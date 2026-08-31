//! Coordinated engine-memory lifecycle and final allocation recovery.
//!
//! Repeated cell transitions can leave native scene, texture, PDD, async, and
//! model-loader ownership under process VAS pressure. This module consumes a
//! proven pressure request through one native Begin/Free/End transaction. It
//! does not run a periodic or unconditional post-load PDD purge.
//!
//! Final allocator failure uses the native stage executor synchronously. Main
//! thread stages 0 through 6 run while IO dequeue, active IO iterations,
//! AI/Havok task groups, renderer, and scene ownership are quiescent. Worker
//! failures retain the native stage-8 publish/wait/retry contract, including
//! Psycho's validated BSTaskManagerThread semaphore guard. A process-wide
//! owner prevents cleanup allocations from recursively entering another
//! recovery transaction.

use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use libc::c_void;

use super::engine::globals;
use super::{allocator, block};

static PRESSURE_REQUEST: AtomicU64 = AtomicU64::new(0);
static PRESSURE_HANDLED: AtomicU64 = AtomicU64::new(0);
static RECOVERY_OWNER_THREAD: AtomicU32 = AtomicU32::new(0);

/// Publish a pressure generation for main-thread native memory reclamation.
pub(crate) fn request_pressure(generation: u64) {
    PRESSURE_REQUEST.fetch_max(generation, Ordering::Release);
}

/// Consume pending pressure reclamation at Phase 10.
///
/// The caller is the established main-thread maintenance hook. Cleanup waits
/// until the native pending-cell handle is quiescent.
pub(crate) fn on_main_thread_frame() {
    if !globals::is_main_thread_by_tid() {
        return;
    }

    let pressure = PRESSURE_REQUEST.load(Ordering::Acquire);
    let pressure_pending = pressure > PRESSURE_HANDLED.load(Ordering::Acquire);
    if !pressure_pending || globals::is_bst_cell_load_pending() {
        return;
    }

    if unsafe { run_native_memory_free("vas-pressure") } {
        PRESSURE_HANDLED.store(pressure, Ordering::Release);
    }
}

/// Recover one final allocator failure through the native retry lifecycle.
///
/// # Safety
/// `size` is the original GameHeap request. The returned pointer has the same
/// ownership and alignment contract as [`allocator::alloc_once`].
pub(crate) unsafe fn recover_allocation(size: usize) -> *mut c_void {
    if !globals::main_thread_id_is_set() {
        return null_mut();
    }

    let thread = libpsycho::os::windows::winapi::get_current_thread_id();
    let owner = RECOVERY_OWNER_THREAD.load(Ordering::Acquire);
    if owner == thread {
        return null_mut();
    }
    if !globals::is_main_thread_by_tid() {
        return unsafe { recover_worker_allocation(size) };
    }
    if RECOVERY_OWNER_THREAD
        .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return null_mut();
    }

    let result = unsafe { recover_main_allocation(size) };
    RECOVERY_OWNER_THREAD.store(0, Ordering::Release);
    result
}

/// Run one externally requested native OOM stage under the same destruction
/// barriers as Psycho's owned retry sequence.
///
/// This covers native GameHeap and HeapCompact callers that reach the shared
/// stage executor independently of gheap allocation. One stage gets one
/// complete barrier transaction because the native caller may stop retrying as
/// soon as its next allocation succeeds.
///
/// # Safety
///
/// The caller must be the main-thread shared OOM-stage hook, and `call` must
/// invoke the captured native stage provider with its original valid ABI and
/// arguments. The native stage may inspect and destroy engine-owned objects.
pub(crate) unsafe fn run_guarded_oom_stage(call: impl FnOnce() -> i32) -> Option<i32> {
    let thread = libpsycho::os::windows::winapi::get_current_thread_id();
    if RECOVERY_OWNER_THREAD
        .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    let result = unsafe { run_guarded_oom_stage_owned(call) };
    RECOVERY_OWNER_THREAD.store(0, Ordering::Release);
    result
}

unsafe fn run_guarded_oom_stage_owned(call: impl FnOnce() -> i32) -> Option<i32> {
    let _io_barrier = unsafe { globals::acquire_io_dequeue_barrier(500)? };
    unsafe { globals::stop_havok_drain() };
    let mut state = unsafe { globals::pre_destruction_setup() };
    let next = call();
    let _ = block::retire_empty_after_engine_cleanup();
    unsafe { globals::post_destruction_restore(&mut state) };
    unsafe { globals::start_havok() };
    Some(next)
}

unsafe fn recover_main_allocation(size: usize) -> *mut c_void {
    let Some(_io_barrier) = (unsafe { globals::acquire_io_dequeue_barrier(500) }) else {
        return null_mut();
    };

    unsafe { globals::stop_havok_drain() };
    let mut state = unsafe { globals::pre_destruction_setup() };
    let mut stage = 0i32;
    let mut result = null_mut();
    while stage <= 6 {
        stage = unsafe { globals::run_original_oom_stage(stage) };
        result = unsafe { allocator::alloc_once(size) };
        if !result.is_null() {
            break;
        }
    }
    let retired = block::retire_empty_after_engine_cleanup();
    if result.is_null() && retired.slots_retired > 0 {
        result = unsafe { allocator::alloc_once(size) };
    }
    unsafe { globals::post_destruction_restore(&mut state) };
    unsafe { globals::start_havok() };

    if retired.slots_retired > 0 {
        log::warn!(
            "[OOM] Native recovery released medium extents: retired={}/{} reserved={}MB committed={}MB failures={}",
            retired.slots_retired,
            retired.eligible_slots,
            retired.reserved_bytes / super::vas::MB,
            retired.committed_bytes / super::vas::MB,
            retired.release_failures,
        );
    }
    result
}

unsafe fn recover_worker_allocation(size: usize) -> *mut c_void {
    let mut stage = 8i32;
    loop {
        let (next, done) = unsafe { globals::run_single_oom_stage(stage) };
        let result = unsafe { allocator::alloc_once(size) };
        if !result.is_null() {
            return result;
        }
        if done || next > 8 {
            return null_mut();
        }
        stage = next;
    }
}

unsafe fn run_native_memory_free(reason: &'static str) -> bool {
    let thread = libpsycho::os::windows::winapi::get_current_thread_id();
    if RECOVERY_OWNER_THREAD
        .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    let result = unsafe { run_native_memory_free_owned(reason) };
    RECOVERY_OWNER_THREAD.store(0, Ordering::Release);
    result
}

unsafe fn run_native_memory_free_owned(reason: &'static str) -> bool {
    // Transition pressure is preventative, not an allocation emergency. Never
    // add a frame hitch waiting for active streaming; preserve the request and
    // retry at a later Phase 10 when all native workers are already idle.
    let Some(_io_barrier) = (unsafe { globals::acquire_io_dequeue_barrier(0) }) else {
        return false;
    };

    unsafe { globals::stop_havok_drain() };
    let mut state = unsafe { globals::pre_destruction_setup() };
    unsafe { globals::deferred_cleanup_small(state[5]) };
    let retired = block::retire_empty_after_engine_cleanup();
    unsafe { globals::post_destruction_restore(&mut state) };
    unsafe { globals::start_havok() };

    log::info!(
        "[MEMORY] Native reclamation complete: reason={} retired={}/{} extents reserved={}MB committed={}MB failures={}",
        reason,
        retired.slots_retired,
        retired.eligible_slots,
        retired.reserved_bytes / super::vas::MB,
        retired.committed_bytes / super::vas::MB,
        retired.release_failures,
    );
    true
}

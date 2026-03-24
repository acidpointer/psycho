//! Hook functions for game heap allocation and main loop integration.
//!
//! Thin wrappers that delegate to Gheap for allocation logic and
//! PressureRelief for between-frame maintenance.

use libc::c_void;

use super::alloc::Gheap;
use super::pressure::PressureRelief;
use super::statics;

// ---- Game heap alloc/free/msize/realloc ----

pub unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { Gheap::alloc(size) }
}

pub unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
    unsafe { Gheap::free(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_msize(
    _this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    unsafe { Gheap::msize(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_realloc(
    _this: *mut c_void,
    ptr: *mut c_void,
    new_size: usize,
) -> *mut c_void {
    unsafe { Gheap::realloc(ptr, new_size) }
}

// ---- Main loop: frame tick + pressure relief ----

pub unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
    if let Ok(original) = statics::MAIN_LOOP_MAINTENANCE_HOOK.original() {
        unsafe { original(this) };
    }

    unsafe { Gheap::on_frame_tick() };
}

// ---- IOManager Phase 3: read lock during IO task dispatch ----

/// IOManager main-thread processing (FUN_00c3dbf0, Phase 3).
/// Holds read lock during the entire call — prevents PDD and quarantine
/// flush from recycling memory while we're dispatching IO task results.
/// This covers the gap where BSTaskManagerThread-completed tasks are
/// read by the main thread via vtable dispatch.
pub unsafe extern "thiscall" fn hook_io_manager_process(this: *mut c_void) {
    super::destruction_guard::read(|| {
        if let Ok(original) = statics::IO_MANAGER_PROCESS_HOOK.original() {
            unsafe { original(this) };
        }
    });
}

// ---- AI thread synchronization ----

use std::cell::Cell;
use super::destruction_guard::ReadGuard;

thread_local! {
    static AI_GUARD: Cell<Option<ReadGuard>> = const { Cell::new(None) };
}

/// Check if AI read guard is currently held (main thread only).
/// Used by OOM recovery to skip game stages that would deadlock.
pub fn is_ai_guard_held() -> bool {
    AI_GUARD.with(|g| {
        // Cell<Option<T>> doesn't have a peek method, but we can
        // take + put back. This is safe since we're single-threaded (main thread).
        let val = g.take();
        let held = val.is_some();
        g.set(val);
        held
    })
}

/// AI_Start: try to acquire read guard. Stored in thread-local.
pub unsafe extern "fastcall" fn hook_ai_thread_start(mgr: *mut c_void) {
    AI_GUARD.set(super::destruction_guard::try_read_guard());

    if let Ok(original) = statics::AI_THREAD_START_HOOK.original() {
        unsafe { original(mgr) };
    }
}

/// AI_Join: drop guard (lock released), then deferred unloading.
pub unsafe extern "fastcall" fn hook_ai_thread_join(mgr: *mut c_void) {
    if let Ok(original) = statics::AI_THREAD_JOIN_HOOK.original() {
        unsafe { original(mgr) };
    }

    AI_GUARD.set(None); // guard dropped, lock released

    if let Some(pr) = PressureRelief::instance() {
        unsafe { pr.run_deferred_unload() };
    }
}

// ---- Per-frame queue drain: boost NiNode drain under pressure ----

/// Extra rounds of FUN_00868850 when under memory pressure.
/// Each round drains 10-20 NiNodes; 19 extra = 200-400 NiNodes/frame total.
const EXTRA_DRAIN_ROUNDS: u32 = 19;

/// NiNode PDD queue (DAT_011de808), count at offset +0x0A (u16).
const NINODE_QUEUE_ADDR: usize = 0x011DE808;
const QUEUE_COUNT_OFFSET: usize = 0x0A;

/// HeapCompact trigger field (heap_singleton + 0x134).
const HEAP_COMPACT_TRIGGER_PTR: usize = 0x011F636C;

/// All PDD queue addresses, count at offset +0x0A (u16) each.
const TEXTURE_QUEUE_ADDR: usize = 0x011DE910;
const ANIM_QUEUE_ADDR: usize = 0x011DE888;
const GENERIC_QUEUE_ADDR: usize = 0x011DE874;
const FORM_QUEUE_ADDR: usize = 0x011DE828;

/// Log queue states every N frames when under pressure (~5s at 60fps).
const DIAG_LOG_INTERVAL: u32 = 300;

thread_local! {
    static DIAG_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Flush quarantine BEFORE PDD runs. At this point:
    // - AI threads idle (joined in Phase 9 of previous frame)
    // - NVSE dispatch completed (after previous inner loop)
    // - IOManager Phase 3 completed (earlier this frame)
    unsafe { Gheap::on_pre_pdd() };

    if let Ok(original) = statics::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        unsafe { original() };

        if let Some(pr) = PressureRelief::instance()
            && pr.is_requested()
        {
            // Periodic diagnostics
            DIAG_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % DIAG_LOG_INTERVAL == 0 {
                    let trigger_val =
                        unsafe { *(HEAP_COMPACT_TRIGGER_PTR as *const u32) };
                    let ninode_q = unsafe {
                        *((NINODE_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let texture_q = unsafe {
                        *((TEXTURE_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let anim_q = unsafe {
                        *((ANIM_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let generic_q = unsafe {
                        *((GENERIC_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let form_q = unsafe {
                        *((FORM_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    log::debug!(
                        "[GHEAP-DEBUG] trigger={} queues: NiNode={} Tex={} Anim={} Gen={} Form={}",
                        trigger_val, ninode_q, texture_q, anim_q, generic_q, form_q
                    );
                }
            });

            // Boosted drain: call original additional times for NiNode queue
            for _ in 0..EXTRA_DRAIN_ROUNDS {
                let count = unsafe {
                    *((NINODE_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                };
                if count == 0 {
                    break;
                }
                unsafe { original() };
            }
        }
    }
}

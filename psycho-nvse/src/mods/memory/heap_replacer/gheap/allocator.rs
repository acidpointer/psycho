//! Game heap allocator: routes alloc/free/realloc/msize through pool + mimalloc.
//!
//! Every thread gets its own thread-local pool (zombie freelist). Freed blocks
//! stay readable until reused by a same-size allocation. This preserves the
//! SBM "freed memory stays readable" contract that the game engine relies on.
//!
//! - Alloc: pool (freelist hit) or mi_malloc (freelist miss).
//! - Free:  pool freelist push (block stays readable).
//! - OOM:   drain own pool + game OOM stages (mutex-protected) + retry.

use libc::c_void;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned, mi_usable_size,
};

use super::engine::{addr, globals};
use super::pool;
use super::statics;
use crate::mods::memory::heap_replacer::heap_validate;

const ALIGN: usize = 16;

/// When true, frees of large blocks (>= SMALL_BLOCK_THRESHOLD) bypass the
/// pool and go directly to mi_free. Small blocks still pool for zombie safety.
///
/// Two sources: `with_large_bypass(f)` (scoped) and `set_loading_bypass` (persistent).
static LARGE_BYPASS: AtomicBool = AtomicBool::new(false);
static LOADING_BYPASS: AtomicBool = AtomicBool::new(false);

pub fn with_large_bypass<R>(f: impl FnOnce() -> R) -> R {
    LARGE_BYPASS.store(true, Ordering::Release);
    let result = f();
    LARGE_BYPASS.store(false, Ordering::Release);
    result
}

pub fn set_loading_bypass(active: bool) {
    LOADING_BYPASS.store(active, Ordering::Release);
}

#[inline]
pub fn is_bypass_active() -> bool {
    LARGE_BYPASS.load(Ordering::Relaxed) || LOADING_BYPASS.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------
// Thread identity
// -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ThreadRole { Unknown = 0, Main = 1, Worker = 2 }

thread_local! {
    static THREAD_ROLE: Cell<ThreadRole> = const { Cell::new(ThreadRole::Unknown) };
}

static POOL_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn is_pool_active() -> bool {
    POOL_ACTIVE.load(Ordering::Acquire)
}

pub fn activate_pool() {
    POOL_ACTIVE.store(true, Ordering::Release);
    log::info!("[POOL] Activated");
}

#[inline]
pub fn is_main_thread() -> bool {
    THREAD_ROLE.with(|r| match r.get() {
        ThreadRole::Main => true,
        ThreadRole::Worker => false,
        ThreadRole::Unknown => {
            let is_main = globals::is_main_thread_by_tid();
            if is_main {
                r.set(ThreadRole::Main);
            } else if is_pool_active() {
                r.set(ThreadRole::Worker);
            }
            is_main
        }
    })
}

// -----------------------------------------------------------------------
// Alloc / Free / Msize / Realloc
// -----------------------------------------------------------------------

/// Allocate `size` bytes. Uses thread-local pool, falls back to mi_malloc.
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    let ptr = if is_pool_active() {
        let (p, _) = unsafe { pool::pool_alloc(size) };
        p
    } else {
        unsafe { mi_malloc_aligned(size, ALIGN) }
    };

    if !ptr.is_null() {
        return ptr;
    }
    unsafe { recover_oom(size) }
}

/// Free a block. Pushes to thread-local pool (zombie-safe).
/// Pre-hook pointers are routed to the original SBM trampoline.
#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        if is_pool_active() {
            // Large bypass (cleanup/loading/OOM): large blocks to mi_free.
            // Small blocks stay in pool as zombies for concurrent IO safety.
            if is_bypass_active() {
                let usable = unsafe { mi_usable_size(ptr as *const c_void) };
                if usable >= pool::SMALL_BLOCK_THRESHOLD {
                    unsafe { libmimalloc::mi_free(ptr) };
                    return;
                }
            }
            unsafe { pool::pool_free(ptr) };
        } else {
            unsafe { libmimalloc::mi_free(ptr) };
        }
        return;
    }

    // Pre-hook pointer: route to original SBM trampoline.
    if let Ok(orig_free) = statics::GHEAP_FREE_HOOK.original() {
        unsafe { orig_free(addr::HEAP_SINGLETON as *mut c_void, ptr) };
        return;
    }

    unsafe { heap_validate::heap_validated_free(ptr) };
}

/// Return usable size of an allocated block.
#[inline]
pub unsafe fn msize(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        return unsafe { mi_usable_size(ptr as *const c_void) };
    }
    if let Ok(orig_msize) = statics::GHEAP_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(addr::HEAP_SINGLETON as *mut c_void, ptr) };
        if size != 0 {
            return size;
        }
    }
    let size = unsafe { heap_validate::heap_validated_size(ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }
    0
}

/// Reallocate a block.
#[inline]
pub unsafe fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { alloc(new_size) };
    }
    if new_size == 0 {
        unsafe { free(ptr) };
        return null_mut();
    }
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
        if !new_ptr.is_null() {
            return new_ptr;
        }
        return unsafe { recover_oom(new_size) };
    }
    let old_size = unsafe { msize(ptr) };
    if old_size == 0 {
        return null_mut();
    }
    let new_ptr = unsafe { alloc(new_size) };
    if !new_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_size),
            );
        }
        unsafe { free(ptr) };
    }
    new_ptr
}

// -----------------------------------------------------------------------
// OOM recovery
// -----------------------------------------------------------------------

// Reentrancy guard. Game cleanup stages allocate small temporaries.
// Without this guard, those allocations failing would recurse into
// the full OOM recovery -- stack overflow or deadlock on PDD lock.
thread_local! {
    static IN_OOM_RECOVERY: Cell<bool> = const { Cell::new(false) };
}

/// OOM recovery matching vanilla FUN_00aa3e40 retry pattern.
///
/// Pattern: **cleanup --> retry --> cleanup --> retry**.
/// Each cleanup step uses HeapManager (mi_collect encapsulated).
/// Large bypass during game stages so large frees --> mi_free,
/// small frees --> pool (zombie safety preserved), then drain catches them.
#[cold]
unsafe fn recover_oom(size: usize) -> *mut c_void {
    // Reentrancy: game cleanup stages may allocate. Don't recurse into
    // the full recovery -- just collect and retry.
    if IN_OOM_RECOVERY.with(|r| r.get()) {
        unsafe { mi_collect(false) };
        return unsafe { mi_malloc_aligned(size, ALIGN) };
    }

    IN_OOM_RECOVERY.with(|r| r.set(true));
    let result = unsafe { do_recover_oom(size) };
    IN_OOM_RECOVERY.with(|r| r.set(false));
    result
}

#[cold]
unsafe fn do_recover_oom(size: usize) -> *mut c_void {
    use super::heap_manager::HeapManager;

    let heap = HeapManager::get();
    let is_main = is_main_thread();
    let commit_entry = heap.commit_mb();

    log::warn!(
        "[OOM] size={} thread={} commit={}MB pool={}MB",
        size, if is_main { "main" } else { "worker" },
        commit_entry, heap.pool_mb(),
    );

    // Worker: signal main thread to drain its pool at Phase 7.
    if !is_main {
        heap.signal_emergency_drain();
    }

    // --- Phase 1: Active cleanup (stages 0-6) ---
    //
    // bypass_all scoped INSIDE run_oom_stage (wraps only the game call).
    // Frees during cleanup --> mi_free (VAS reclaimed).
    // Between stages, bypass OFF -- zombie safety preserved.
    //
    // Stages are idempotent -- PDD queues empty, caches flush once.
    // Stop repeating when a cycle frees < 64KB.
    //
    // Main thread: runs stages locally (including stage 5 cell unload).
    //   No yield -- main IS the thread that runs Phase 6/7.
    // Worker: yields between cycles so main thread processes HeapCompact.
    const MAX_ACTIVE_CYCLES: u32 = 10;

    for cycle in 0..MAX_ACTIVE_CYCLES {
        let commit_before_cycle = heap.commit_bytes();
        let mut stage: i32 = 0;

        loop {
            let (next, _) = unsafe { heap.run_oom_stage(stage, true) };
            stage = next;

            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered: cycle={} size={} commit={}-->{}MB",
                    cycle, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }

            if stage >= 7 { break; }
        }

        let freed_this_cycle = commit_before_cycle
            .saturating_sub(heap.commit_bytes());

        // Workers: signal main thread + yield to let Phase 6/7 run.
        // Main: skip yield -- it IS the Phase 6/7 thread. Yielding
        // achieves nothing and wastes time.
        if !is_main {
            heap.signal_heap_compact(
                super::engine::globals::HeapCompactStage::CellUnload,
            );
            heap.signal_emergency_drain();
            libpsycho::os::windows::winapi::sleep(1);

            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered after yield: cycle={} size={} commit={}-->{}MB",
                    cycle, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }
        }

        // Stages exhausted -- stop repeating no-ops.
        if freed_this_cycle < 64 * 1024 && cycle > 0 {
            log::info!(
                "[OOM] Stages exhausted at cycle {}: commit={}-->{}MB",
                cycle, commit_entry, heap.commit_mb(),
            );
            break;
        }

        if cycle > 0 && cycle.is_multiple_of(5) {
            log::warn!(
                "[OOM] Cycle {}: commit={}-->{}MB pool={}MB",
                cycle, commit_entry, heap.commit_mb(), heap.pool_mb(),
            );
        }
    }

    // --- Phase 2: Wait for main thread cleanup (workers only) ---
    //
    // Workers can't run stage 5 (cell unload, main-thread-only).
    // Signal main thread to run destruction_protocol at each AI_JOIN.
    // Each AI_JOIN (~16ms) unloads 11 cells, freeing ~10-30MB.
    // Re-signal every frame so destruction_protocol runs repeatedly
    // until enough memory is freed.
    if !is_main {
        // Normal gameplay: 2 seconds (main loop runs destruction_protocol).
        // Loading/menu/console: 30 seconds (main loop paused, will resume
        // when player closes menu -- no point going to FATAL).
        let max_wait = if globals::is_loading() { 30_000u32 } else { 2_000u32 };

        for iter in 0..max_wait {
            // Re-signal every ~16ms (once per frame) so main thread
            // runs destruction_protocol at every AI_JOIN when it resumes.
            if iter.is_multiple_of(16) {
                heap.signal_heap_compact(
                    super::engine::globals::HeapCompactStage::CellUnload,
                );
                heap.signal_emergency_drain();
                if let Some(pr) = super::pressure::PressureRelief::instance() {
                    pr.set_deferred_unload();
                }
            }

            libpsycho::os::windows::winapi::sleep(1);

            // Re-check loading state -- if menu closed, switch to short wait.
            if iter == 2000 && !globals::is_loading() {
                break;
            }

            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered during wait: iter={}ms size={} commit={}-->{}MB",
                    iter, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }

            if iter.is_multiple_of(1000) && iter > 0 {
                log::warn!(
                    "[OOM] Waiting: {}ms commit={}-->{}MB pool={}MB loading={}",
                    iter, commit_entry, heap.commit_mb(), heap.pool_mb(),
                    globals::is_loading(),
                );
            }
        }

        log::warn!(
            "[OOM] Wait expired: commit={}-->{}MB pool={}MB",
            commit_entry, heap.commit_mb(), heap.pool_mb(),
        );
    }

    // --- Phase 3: Last resort ---
    //
    // Main thread arrives here fast (no Phase 2 wait). Workers arrive
    // after 3 seconds of waiting. Now we escalate to unsafe operations.
    log::warn!(
        "[OOM] Escalating: commit={}-->{}MB pool={}MB",
        commit_entry, heap.commit_mb(), heap.pool_mb(),
    );

    // Safe drain (>= 1KB only -- no BSTreeNode UAF risk).
    unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
    unsafe { mi_collect(true) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() { return ptr; }

    // Nuclear: drain ALL pool blocks. UAF risk accepted -- crash is
    // the alternative.
    let drained = unsafe { pool::pool_drain_all() };
    let commit_after_drain = heap.commit_mb();
    let freed_mb = commit_entry.saturating_sub(commit_after_drain);
    log::error!(
        "[OOM] Last resort: drain_all={} commit={}-->{}MB freed={}MB",
        drained, commit_entry, commit_after_drain, freed_mb,
    );

    // Only retry if drain freed meaningful amount relative to request.
    // If we freed < requested size, VAS is too fragmented -- retrying
    // with mi_collect(true) just freezes the game for seconds.
    let size_mb = size / 1024 / 1024;
    if freed_mb > size_mb {
        unsafe { mi_collect(true) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Recovered post-drain: commit={}-->{}MB",
                commit_entry, heap.commit_mb(),
            );
            return ptr;
        }
    }

    log::error!(
        "[OOM] FATAL: size={} commit={}MB thread={}",
        size, heap.commit_mb(), if is_main { "main" } else { "worker" },
    );
    null_mut()
}

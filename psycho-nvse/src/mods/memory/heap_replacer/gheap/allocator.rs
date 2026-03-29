//! Game heap allocator: routes alloc/free/realloc/msize through pool + mimalloc.
//!
//! - Main thread alloc: pool (freelist hit) or mi_malloc (freelist miss).
//! - Main thread free:  pool freelist push (never mi_free, block stays readable).
//! - Worker alloc/free: mi_malloc/mi_free directly (thread-local heaps, safe).
//! - Realloc:           mi_realloc_aligned directly (no pool involvement).
//! - Msize:             mi_usable_size for mimalloc pointers.
//!
//! The pool preserves SBM's "freed memory stays readable" contract. Freed
//! blocks sit on per-size-class freelists and are reused by same-size
//! allocations. No quarantine, no GC, no timing tricks.
//!
//! OOM recovery: drain pool freelists + game's OOM stages. Never return NULL.

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

/// Worker threads set this when OOM. Main thread picks it up at Phase 7
/// and runs emergency pool drain + game OOM stages.
pub static EMERGENCY_CLEANUP: AtomicBool = AtomicBool::new(false);

/// When true, main-thread frees of LARGE blocks (>= SMALL_BLOCK_THRESHOLD)
/// bypass the pool and go directly to mi_free. Small blocks still go to pool
/// to preserve the zombie data contract for NiRefObject stale readers.
///
/// Two sources can activate bypass:
/// - `with_large_bypass(f)` — scoped, for cleanup operations
/// - `set_loading_bypass(true)` — persistent during loading phase
static LARGE_BYPASS: AtomicBool = AtomicBool::new(false);
static LOADING_BYPASS: AtomicBool = AtomicBool::new(false);

/// Run `f` with large-block bypass active. Large frees (>=512 bytes)
/// go to mi_free directly during `f`. Small blocks still pool.
/// Bypass is guaranteed to be disabled when `f` returns.
pub fn with_large_bypass<R>(f: impl FnOnce() -> R) -> R {
    log::debug!("[BYPASS] Scoped ON");
    LARGE_BYPASS.store(true, Ordering::Release);
    let result = f();
    LARGE_BYPASS.store(false, Ordering::Release);
    log::debug!("[BYPASS] Scoped OFF");
    result
}

/// Enable/disable persistent loading bypass. Active for the entire
/// loading phase so game's CellTransitionHandler frees reclaim VAS.
pub fn set_loading_bypass(active: bool) {
    log::debug!("[BYPASS] Loading {}", if active { "ON" } else { "OFF" });
    LOADING_BYPASS.store(active, Ordering::Release);
}

/// Whether any bypass is active (scoped or loading).
#[inline]
pub fn is_bypass_active() -> bool {
    LARGE_BYPASS.load(Ordering::Relaxed) || LOADING_BYPASS.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------
// Thread identity
// -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ThreadRole {
    Unknown = 0,
    Main = 1,
    Worker = 2,
}

thread_local! {
    static THREAD_ROLE: Cell<ThreadRole> = const { Cell::new(ThreadRole::Unknown) };
}

static POOL_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether the pool is active (set after first non-loading frame).
pub fn is_pool_active() -> bool {
    POOL_ACTIVE.load(Ordering::Acquire)
}

/// Activate the pool. Called once from Phase 7 on first non-loading frame.
pub fn activate_pool() {
    POOL_ACTIVE.store(true, Ordering::Release);
    log::info!("[POOL] Activated");
}

/// Check if the current thread is the game's main thread.
/// Result is cached in a thread-local after first determination.
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

// Re-entrancy guard for emergency cleanup piggybacking on alloc().
// Prevents infinite recursion since cleanup itself calls alloc/free.
thread_local! {
    static IN_EMERGENCY: Cell<bool> = const { Cell::new(false) };
}

/// Allocate `size` bytes. Main thread uses pool, workers use mi_malloc.
/// On OOM, enters multi-stage recovery. Engine contract: never returns NULL.
///
/// When a worker is stuck in OOM during loading and Phase 7 is dead,
/// the main thread piggybacks emergency cleanup on its own alloc calls.
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    // Main thread piggyback: if a worker signaled EMERGENCY_CLEANUP and
    // Phase 7 isn't running (loading deadlock), run OOM recovery from
    // the main thread's alloc() call.
    //
    // The vanilla game's own GameHeap::Allocate (FUN_00AA3E40) does
    // exactly this — runs OOM stages 0-8 in a do-while retry loop
    // when allocation fails. Running cleanup from the alloc path is
    // the game's intended design, not a hack.
    //
    // We signal HeapCompact stage 4 (PDD purge, skips stage 5 cell
    // unload to avoid loading deadlocks) + drain_large + mi_collect.
    if is_main_thread()
        && globals::is_loading()
        && EMERGENCY_CLEANUP.load(Ordering::Relaxed)
        && !IN_EMERGENCY.with(|e| e.get())
        && EMERGENCY_CLEANUP.swap(false, Ordering::AcqRel) {
            IN_EMERGENCY.with(|e| e.set(true));

            // HeapCompact 0-4: texture flush, geometry, menu, Havok GC, PDD purge.
            // Stage 5 (cell unload) skipped — deadlocks during loading.
            globals::signal_heap_compact(globals::HeapCompactStage::PddPurge);

            // Drain large pool blocks + force segment decommit.
            let drained = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
            unsafe { mi_collect(false) };

            log::warn!(
                "[OOM] Piggyback: HeapCompact 0-4, drained {} large, commit={}MB, pool={}MB",
                drained,
                libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
                pool::pool_held_bytes() / 1024 / 1024,
            );

            IN_EMERGENCY.with(|e| e.set(false));
        }

    let ptr = if is_main_thread() && is_pool_active() {
        let (p, _usable) = unsafe { pool::pool_alloc(size) };
        p
    } else {
        unsafe { mi_malloc_aligned(size, ALIGN) }
    };

    if !ptr.is_null() {
        return ptr;
    }
    unsafe { recover_oom(size) }
}

/// Free a block. Main thread pushes to pool, workers call mi_free.
/// Pre-hook pointers are routed to the original SBM trampoline.
#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        if is_main_thread() && is_pool_active() {
            // Large bypass: during cell unload / OOM recovery, large blocks
            // go directly to mi_free to keep VAS available. Small blocks
            // still go to pool to preserve zombie data for stale readers.
            if is_bypass_active() {
                let usable = unsafe { mi_usable_size(ptr as *const c_void) };
                if usable >= pool::SMALL_BLOCK_THRESHOLD {
                    unsafe { libmimalloc::mi_free(ptr) };
                    return;
                }
            }
            // Pool: block stays on freelist, never mi_free'd.
            unsafe { pool::pool_free(ptr) };
        } else {
            // Worker or pre-activation: mi_free directly.
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
///
/// Pool blocks were individually allocated by mi_malloc (never mi_free'd),
/// so mi_usable_size reads the correct size from mimalloc's page header.
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

/// Reallocate a block. Uses mi_realloc_aligned directly (no pool).
/// Pre-hook pointers: alloc new, copy, free old.
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
        // Direct mi_realloc: may extend in place (no free) or move.
        // If moved, old block goes to mimalloc's freelist (not our pool).
        // This is acceptable: realloc is rare and the old block's data
        // was already copied to the new location.
        let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
        if !new_ptr.is_null() {
            return new_ptr;
        }
        return unsafe { recover_oom(new_size) };
    }
    // Pre-hook pointer: alloc new, copy, free old.
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
// OOM recovery -- engine contract: never return NULL
// -----------------------------------------------------------------------

#[cold]
unsafe fn recover_oom(size: usize) -> *mut c_void {
    let is_main = is_main_thread();

    log::warn!(
        "[OOM] size={}, thread={}, commit={}MB, pool={}MB",
        size,
        if is_main { "main" } else { "worker" },
        libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
    );

    // Stage 1: reclaim thread-local empty pages.
    unsafe { mi_collect(false) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() { return ptr; }

    // Stage 2: drain large pool blocks + collect.
    // Small blocks (<1KB) stay on freelists to prevent UAF from stale readers.
    if is_main {
        let freed = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
        if freed > 0 {
            log::warn!("[OOM] Pool drained {} large blocks", freed);
        }
    }
    unsafe { mi_collect(true) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() {
        log::warn!("[OOM] Recovered via pool drain (size={})", size);
        return ptr;
    }

    // Stage 3: game's OOM stages 0-8.
    if is_main && !globals::is_loading() {
        let ptr = unsafe { globals::run_oom_stages(size) };
        if !ptr.is_null() { return ptr; }
    }

    // Signal main thread for emergency cleanup.
    if !is_main {
        EMERGENCY_CLEANUP.store(true, Ordering::Release);
    }

    // Stage 4: bounded retry.
    let max_retries: u32 = if is_main { 10 } else { 200 };
    for attempt in 0..max_retries {
        libpsycho::os::windows::winapi::sleep(50);
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            if attempt > 0 {
                log::info!("[OOM] Recovered after {} retries (size={})", attempt, size);
            }
            return ptr;
        }
        if attempt == max_retries / 2 {
            if is_main {
                unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
            }
            unsafe { mi_collect(true) };
        }
    }

    // Stage 5: game OOM stages + pool drain.
    if is_main && !globals::is_loading() {
        let ptr = unsafe { globals::run_oom_stages(size) };
        if !ptr.is_null() { return ptr; }
        unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
        unsafe { mi_collect(true) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() { return ptr; }
    }

    // Stage 6: infinite last-resort.
    unsafe { oom_last_resort(size, is_main) }
}

/// Maximum attempts in oom_last_resort before giving up.
/// 100 attempts * 200ms sleep = 20 seconds max.
/// Returning NULL risks a crash, but an infinite hang is worse:
/// no crash dump, no recovery, user must force-kill the process.
const OOM_LAST_RESORT_MAX: u32 = 100;

#[cold]
unsafe fn oom_last_resort(size: usize, is_main: bool) -> *mut c_void {
    log::error!(
        "[OOM] Last resort: size={}, thread={}, commit={}MB",
        size,
        if is_main { "main" } else { "worker" },
        libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
    );

    for attempt in 0..OOM_LAST_RESORT_MAX {
        // Re-signal emergency every iteration — main thread may have
        // consumed the flag but not freed enough on the first try.
        if !is_main {
            EMERGENCY_CLEANUP.store(true, Ordering::Release);
        }

        // Sleep to give main thread time to run Phase 7 and process
        // emergency cleanup (cell unload + PDD pump during loading).
        libpsycho::os::windows::winapi::sleep(50);

        if is_main {
            unsafe { pool::pool_drain_all() };
        }
        unsafe { mi_collect(false) };

        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::warn!("[OOM] Last resort recovered at attempt {} (size={})", attempt, size);
            return ptr;
        }

        if is_main && !globals::is_loading() {
            let ptr = unsafe { globals::run_oom_stages(size) };
            if !ptr.is_null() { return ptr; }
        }

        if attempt % 10 == 0 {
            let info = libmimalloc::process_info::MiMallocProcessInfo::get();
            log::error!(
                "[OOM] Attempt {}/{}: size={}, commit={}MB, pool={}MB, loading={}, bypass={}",
                attempt, OOM_LAST_RESORT_MAX, size,
                info.get_current_commit() / 1024 / 1024,
                pool::pool_held_bytes() / 1024 / 1024,
                globals::is_loading(),
                is_bypass_active(),
            );
        }
    }

    // Exhausted all retries. Return NULL — game will likely crash with
    // a NULL deref, which produces a crash dump and is recoverable via
    // auto-save. This is strictly better than an infinite hang.
    log::error!(
        "[OOM] FATAL: giving up after {} attempts, size={}, commit={}MB. Returning NULL.",
        OOM_LAST_RESORT_MAX,
        size,
        libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
    );
    null_mut()
}

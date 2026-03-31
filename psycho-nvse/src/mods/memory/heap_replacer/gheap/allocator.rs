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

// Thread-local: when true, ALL frees bypass the pool entirely → mi_free.
// Used during OOM recovery so game cleanup frees actually reclaim VAS
// instead of being captured by the pool.
thread_local! {
    static BYPASS_ALL: Cell<bool> = const { Cell::new(false) };
}

pub fn with_large_bypass<R>(f: impl FnOnce() -> R) -> R {
    LARGE_BYPASS.store(true, Ordering::Release);
    let result = f();
    LARGE_BYPASS.store(false, Ordering::Release);
    result
}

pub fn with_bypass_all<R>(f: impl FnOnce() -> R) -> R {
    BYPASS_ALL.with(|b| b.set(true));
    let result = f();
    BYPASS_ALL.with(|b| b.set(false));
    result
}

pub fn set_loading_bypass(active: bool) {
    LOADING_BYPASS.store(active, Ordering::Release);
}

#[inline]
fn is_bypass_all() -> bool {
    BYPASS_ALL.with(|b| b.get())
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
            // Full bypass (OOM recovery): ALL frees go to mi_free.
            if is_bypass_all() {
                unsafe { libmimalloc::mi_free(ptr) };
                return;
            }
            // Large bypass (cleanup/loading): large blocks to mi_free.
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
// the full OOM recovery — stack overflow or deadlock on PDD lock.
thread_local! {
    static IN_OOM_RECOVERY: Cell<bool> = const { Cell::new(false) };
}

/// OOM recovery matching vanilla FUN_00aa3e40 retry pattern.
///
/// Pattern: **cleanup → retry → cleanup → retry**.
/// Each cleanup step uses HeapManager (mi_collect encapsulated).
/// Large bypass during game stages so large frees → mi_free,
/// small frees → pool (zombie safety preserved), then drain catches them.
#[cold]
unsafe fn recover_oom(size: usize) -> *mut c_void {
    // Reentrancy: game cleanup stages may allocate. Don't recurse into
    // the full recovery — just collect and retry.
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

    // Worker: signal main thread to drain its pool at next Phase 7.
    if !is_main {
        heap.signal_emergency_drain();
    }

    // --- Game OOM stages ---
    //
    // bypass_all is scoped INSIDE run_oom_stage (wraps only the game
    // function call). Frees during cleanup → mi_free (VAS reclaimed).
    // Between stages, bypass is OFF — normal pool behavior for any
    // frees from Havok physics on AI workers.
    //
    // Run stages 0-6 in cycles. Stage 7 falls through to stage 8
    // (Sleep(1) × 15000 = 15 second trap) — skip it. Each cycle
    // frees ~1-3MB. We yield briefly between cycles to let the main
    // thread run HeapCompact + background cleanup.
    const MAX_CYCLES: u32 = 50;

    for cycle in 0..MAX_CYCLES {
        // Stages 0-6: real cleanup (texture, geometry, Havok GC, PDD, cell unload).
        let mut stage: i32 = 0;
        loop {
            let (next, _) = unsafe { heap.run_oom_stage(stage) };
            stage = next;

            // Decommit freed pages and retry.
            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered: cycle={} size={} commit={}→{}MB",
                    cycle, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }

            // Stop before stage 7 — it falls through to stage 8's
            // Sleep(1) × 15000 trap which blocks the cycle loop.
            if stage >= 7 { break; }
        }

        // Signal main thread to run HeapCompact (stages 0-6 including
        // cell unload) + drain its pool at Phase 7.
        heap.signal_heap_compact(
            super::engine::globals::HeapCompactStage::CellUnload,
        );
        if !is_main {
            heap.signal_emergency_drain();
        }

        // Yield to let main thread process HeapCompact + Phase 7.
        libpsycho::os::windows::winapi::sleep(1);

        // Retry after yield.
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Recovered after yield: cycle={} size={} commit={}→{}MB",
                cycle, size, commit_entry, heap.commit_mb(),
            );
            return ptr;
        }

        // Log progress every 5 cycles.
        if cycle > 0 && cycle.is_multiple_of(5) {
            log::warn!(
                "[OOM] Cycle {}/{}: commit={}→{}MB pool={}MB",
                cycle, MAX_CYCLES, commit_entry, heap.commit_mb(), heap.pool_mb(),
            );
        }
    }

    // --- All cycles exhausted ---
    log::warn!(
        "[OOM] {} cycles exhausted: commit={}→{}MB pool={}MB",
        MAX_CYCLES, commit_entry, heap.commit_mb(), heap.pool_mb(),
    );

    // Drain pool + aggressive collect as last resort.
    unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() { return ptr; }

    unsafe { mi_collect(true) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() { return ptr; }

    // Nuclear: drain ALL pool blocks including small.
    let drained = unsafe { pool::pool_drain_all() };
    unsafe { mi_collect(false) };
    log::error!(
        "[OOM] Last resort: drain_all={} commit={}→{}MB",
        drained, commit_entry, heap.commit_mb(),
    );
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() { return ptr; }

    log::error!(
        "[OOM] FATAL: size={} commit={}MB thread={}",
        size, heap.commit_mb(), if is_main { "main" } else { "worker" },
    );
    null_mut()
}

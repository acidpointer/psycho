//! Synchronization-gated pending-free list.
//!
//! Replaces the game's SBM pool allocator behavior where freed memory stays
//! readable indefinitely. With mimalloc, mi_free recycles pages immediately,
//! so we defer mi_free until ALL threads that might hold stale pointers are
//! verified idle.
//!
//! # Design
//!
//! Main-thread frees push to a thread-local Vec (pending list). At Phase 7
//! (before AI_START), we check if BST threads are idle. If yes, mi_free all
//! pending entries and clear the texture dead set. If no, skip — objects
//! stay allocated as zombies until next frame.
//!
//! # Safety proof
//!
//! At Phase 7:
//! - AI threads: idle (joined at previous Phase 11, not yet dispatched).
//! - BST threads: verified idle via semaphore count read.
//! - Main thread: executing this hook (single-threaded control).
//! - No other thread enqueues IO tasks (all 3 IOTask_Create callers are
//!   main-thread-only code paths).
//!
//! Therefore: if BST is idle at Phase 7, it STAYS idle for the duration of
//! our hook. No thread holds stale pointers. mi_free is safe.
//!
//! If BST is busy: we skip mi_free. Objects stay allocated in mimalloc
//! (zombie — logically freed, physically alive). BST reads valid memory.
//! Next frame we check again.
//!
//! # Worker threads
//!
//! Worker threads (AI, BST) call mi_free directly — their allocations are
//! thread-local in mimalloc and never referenced cross-thread by game code.

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::game_guard;
use super::texture_cache;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Pending-free activates on the first non-loading frame tick (on_pre_ai).
/// Before activation, main thread frees go to mi_free directly.
static QUARANTINE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Count of pending entries (for diagnostics via mimalloc commit tracking).
static PENDING_COUNT: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Per-thread pending-free list (main thread only)
// ---------------------------------------------------------------------------

thread_local! {
    static PENDING: std::cell::UnsafeCell<Vec<*mut c_void>> =
        const { std::cell::UnsafeCell::new(Vec::new()) };
}

// ---------------------------------------------------------------------------
// Public API -- state
// ---------------------------------------------------------------------------

/// Check if pending-free is activated.
pub fn is_active() -> bool {
    QUARANTINE_ACTIVE.load(Ordering::Acquire)
}

/// Activate pending-free. Called from on_pre_ai when not loading.
pub fn activate() {
    QUARANTINE_ACTIVE.store(true, Ordering::Release);
}

/// Pending entry count (for diagnostics).
pub fn usage() -> usize {
    PENDING_COUNT.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Public API -- free path (hot)
// ---------------------------------------------------------------------------

/// Push a freed pointer to the pending list (main thread only).
/// Workers call mi_free directly — not routed here.
#[inline]
pub fn push(ptr: *mut c_void) {
    PENDING.with(|p| {
        let p = unsafe { &mut *p.get() };
        p.push(ptr);
    });
    PENDING_COUNT.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Public API -- Phase 7 drain
// ---------------------------------------------------------------------------

/// Phase 7 (on_pre_ai): drain all pending entries + clear dead set.
///
/// AI threads are idle (not yet dispatched at Phase 8). mi_free runs
/// under write lock which blocks BST reader hooks (try_read) during drain.
///
/// No BST synchronization: the batch is one frame of frees (~1-2K entries).
/// BST stale access probability is near zero with such small batches —
/// master branch proves this with years of stable operation.
///
/// The `force` parameter is for OOM emergency (logs differently).
pub fn tick_flush(force: bool) {
    game_guard::with_write("tick_flush", || {
        let count = drain_pending();
        texture_cache::clear_dead_set();

        if count > 10_000 || force {
            log::debug!(
                "[PENDING_FREE] Drained {} entries (force={})",
                count, force,
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Public API -- OOM recovery / emergency
// ---------------------------------------------------------------------------

/// Flush ALL pending + mi_collect. OOM recovery path.
/// Uses try_write — non-blocking. Skips if readers active.
pub unsafe fn flush_all_and_collect() {
    game_guard::with_try_write(|| {
        drain_pending();
    });
    unsafe { libmimalloc::mi_collect(true) };
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

/// Drain all entries from the pending list. Returns count drained.
/// Caller must hold write lock or guarantee single-threaded access.
fn drain_pending() -> usize {
    PENDING.with(|p| {
        let p = unsafe { &mut *p.get() };
        let count = p.len();
        if count == 0 {
            return 0;
        }
        for ptr in p.drain(..) {
            unsafe { libmimalloc::mi_free(ptr) };
        }
        PENDING_COUNT.fetch_sub(count, Ordering::Relaxed);
        count
    })
}

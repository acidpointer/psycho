//! Thread synchronization for the game heap replacer.
//!
//! # Architecture
//!
//! Single RwLock protects quarantine drain (mi_free) from concurrent readers.
//!
//! **Writers** (exclusive — quarantine drain):
//! - `tick_flush()` at Phase 7 (before AI_START, microsecond drain)
//! - `run_deferred_unload()` post-AI_JOIN (aggressive collect)
//! - `flush_current_thread()` OOM recovery (try_write, non-blocking)
//!
//! **Readers** (shared — worker thread validation hooks):
//! - `skeleton_update` on AI worker threads (single function call)
//! - `io_task` on BSTaskManagerThread (single function call)
//!
//! # Deadlock-freedom proof
//!
//! 1. **No same-thread read+write**: Main thread NEVER acquires read lock.
//!    Main thread is the only writer. If main held read (IOManager Phase 3)
//!    then tried write (PDD triggers internally) → deadlock. By never giving
//!    main a read lock, this is impossible.
//!
//! 2. **No ABBA with game locks**: Our lock is always outermost. Read locks
//!    wrap original hooked functions which may acquire game locks internally.
//!    No thread acquires QUARANTINE_LOCK while holding a game lock.
//!    Order: QUARANTINE_LOCK > game locks (PDD, process mgr, IO dequeue).
//!
//! 3. **No long-held locks**: Every acquisition is scoped to a single
//!    function call (microseconds). No lock spans frame phases. The failed
//!    "hold read from AI_START to AI_JOIN" design is NOT repeated.
//!
//! 4. **No livelock in OOM**: flush_current_thread uses try_write.
//!    If readers are active, falls through to retry loop with Sleep(1).
//!
//! # Thread safety model
//!
//! | Thread              | Lock role | Protected by                    |
//! |---------------------|-----------|---------------------------------|
//! | Main thread         | WRITER    | Is the drainer (never reads)    |
//! | AI worker #1, #2    | READER    | RwLock + phase ordering         |
//! | BSTaskMgrThread #1,#2 | READER  | RwLock + refcounting + dead set |

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Protects quarantine drain (mi_free) from concurrent readers.
/// NEVER held across frame phases. NEVER held across game function calls
/// on the main thread.
static QUARANTINE_LOCK: RwLock<()> = RwLock::new(());

// Re-export guard type for callers that need to manage lifetime.
pub type WriteGuard = parking_lot::RwLockWriteGuard<'static, ()>;

// ---------------------------------------------------------------------------
// Writer API (main thread quarantine drain)
// ---------------------------------------------------------------------------

/// Acquire write lock (blocking). Use ONLY when AI is known idle:
/// - tick_flush at Phase 7 (before AI_START)
/// - run_deferred_unload after AI_JOIN
///
/// Blocks until all readers (AI hooks, BST hooks) finish their current
/// call. Each reader holds for microseconds, so this never blocks long.
#[inline]
pub fn write_lock() -> WriteGuard {
    QUARANTINE_LOCK.write()
}

/// Try to acquire write lock (non-blocking). Returns None if any reader
/// is active. Use for OOM recovery where blocking could deadlock.
#[inline]
pub fn try_write_lock() -> Option<WriteGuard> {
    QUARANTINE_LOCK.try_write()
}

// ---------------------------------------------------------------------------
// Reader API (worker thread validation hooks)
// ---------------------------------------------------------------------------

/// Try to acquire read lock and execute `f`. Non-blocking: returns None
/// and skips `f` if write lock is held (drain in progress).
///
/// Use ONLY from worker threads (AI workers, BSTaskManagerThread).
/// NEVER use from main thread — main thread is the writer, same-thread
/// read+write would deadlock with parking_lot's writer-priority policy.
///
/// When drain is in progress (write held), skipping the original call
/// is safe: the object is about to be freed anyway. The validation
/// check would either catch the stale data, or the original would
/// operate on soon-to-be-freed memory. Either way, skipping is correct.
#[inline]
pub fn try_read<R>(f: impl FnOnce() -> R) -> Option<R> {
    let _g = QUARANTINE_LOCK.try_read()?;
    Some(f())
}

// ---------------------------------------------------------------------------
// AI active flag (for OOM game-stage decisions, NOT for UAF protection)
// ---------------------------------------------------------------------------

/// True between AI_START and AI_JOIN on the main thread.
///
/// NOT used for UAF protection — the RwLock above handles that.
/// Used ONLY by OOM recovery (alloc.rs) to skip game stages 4-5
/// (FindCellToUnload, process manager lock) which race with AI
/// threads on GAME-INTERNAL state that our RwLock doesn't cover.
static AI_ACTIVE: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn set_ai_active() {
    AI_ACTIVE.store(true, Ordering::Release);
}

#[inline]
pub fn clear_ai_active() {
    AI_ACTIVE.store(false, Ordering::Release);
}

/// Check if AI threads are currently active.
/// Used by OOM recovery to skip unsafe game stages and decide drain strategy.
#[inline]
pub fn is_ai_active() -> bool {
    AI_ACTIVE.load(Ordering::Acquire)
}

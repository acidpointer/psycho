//! Unified game thread synchronization.
//!
//! Single RwLock protects game heap memory during quarantine drain.
//!
//! Writers (main thread): BLOCKING write -- cleanup MUST always run.
//! Readers (worker threads): TRY read -- if cleanup in progress, skip.
//!
//! API uses closure pattern (with_*) to guarantee guard lifetime
//! matches the protected operation exactly.

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use libpsycho::os::windows::winapi::get_current_thread_id;

static GAME_LOCK: RwLock<()> = RwLock::new(());

const DEADLOCK_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Reader API (worker threads: AI, BST, Havok)
// ---------------------------------------------------------------------------

/// Run `f` with quarantine drain protection.
/// Main thread: runs directly (main is the writer, can't race with itself).
/// Worker thread: acquires try_read, skips if drain active.
#[inline]
pub fn with_try_read<R>(f: impl FnOnce() -> R) -> Option<R> {
    if super::allocator::is_main_thread() {
        return Some(f());
    }
    let _guard = GAME_LOCK.try_read()?;
    Some(f())
}

// ---------------------------------------------------------------------------
// Writer API (main thread: quarantine drain)
// ---------------------------------------------------------------------------

/// Blocking write lock, run `f` under exclusive access.
/// Deadlock detection: logs error if not acquired within 5s.
#[inline]
pub fn with_write<R>(caller: &str, f: impl FnOnce() -> R) -> R {
    let _guard = match GAME_LOCK.try_write_for(DEADLOCK_TIMEOUT) {
        Some(guard) => guard,
        None => {
            log::error!(
                "[DEADLOCK] with_write not acquired within {}s: caller={}, thread={}",
                DEADLOCK_TIMEOUT.as_secs(),
                caller,
                get_current_thread_id(),
            );
            GAME_LOCK.write()
        }
    };
    f()
}

/// Try write lock (non-blocking), run `f` if acquired.
/// Returns None if any reader active. Skips cleanup if contended.
#[inline]
#[allow(dead_code)]
pub fn with_try_write<R>(f: impl FnOnce() -> R) -> Option<R> {
    let _guard = GAME_LOCK.try_write()?;
    Some(f())
}

// ---------------------------------------------------------------------------
// AI active flag (for OOM game-stage decisions)
// ---------------------------------------------------------------------------

static AI_ACTIVE: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn set_ai_active() {
    AI_ACTIVE.store(true, Ordering::Release);
}

#[inline]
pub fn clear_ai_active() {
    AI_ACTIVE.store(false, Ordering::Release);
}

#[inline]
pub fn is_ai_active() -> bool {
    AI_ACTIVE.load(Ordering::Acquire)
}

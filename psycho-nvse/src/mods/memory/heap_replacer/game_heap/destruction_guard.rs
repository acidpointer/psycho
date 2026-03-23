//! Heap access guard — RwLock-based synchronization for game heap operations.
//!
//! Two usage patterns:
//!
//! 1. Short scopes (single function): `.read()` / `.write()` / `.try_write()`
//!    with closure. Scope bounded by Rust ownership.
//!
//! 2. Phase-spanning scopes (across hooks): `begin_read_phase()` / `end_read_phase()`
//!    for AI thread window (AI_Start → AI_Join) and BSTaskManagerThread tasks.
//!    These use raw lock operations — caller MUST ensure pairing.
//!
//! Both patterns use the same underlying RwLock. Multiple read locks are
//! allowed concurrently (parking_lot permits nested shared locks).

use parking_lot::RwLock;
use parking_lot::lock_api::RawRwLock as RawRwLockTrait;

/// Global heap access guard.
static HEAP_GUARD: RwLock<()> = RwLock::new(());

// ---------------------------------------------------------------------------
// Short scope API (closure-based, safe)
// ---------------------------------------------------------------------------

/// Execute `f` while holding READ lock. Multiple readers concurrent.
#[inline]
pub fn read<R>(f: impl FnOnce() -> R) -> R {
    let _guard = HEAP_GUARD.read();
    f()
}

/// Execute `f` while holding WRITE lock. Exclusive access.
#[inline]
pub fn write<R>(f: impl FnOnce() -> R) -> R {
    let _guard = HEAP_GUARD.write();
    f()
}

/// Try to execute `f` while holding WRITE lock (non-blocking).
/// Returns None if any readers are active.
#[inline]
pub fn try_write<R>(f: impl FnOnce() -> R) -> Option<R> {
    let _guard = HEAP_GUARD.try_write()?;
    Some(f())
}

// ---------------------------------------------------------------------------
// Phase-spanning API (raw lock, caller ensures pairing)
// ---------------------------------------------------------------------------

/// Acquire shared (read) lock for a long-running phase.
/// Call `end_read_phase()` when the phase ends.
///
/// Used for AI thread window: AI_Start → AI_Join.
/// During this phase, writers (PDD, quarantine flush) wait.
///
/// # Safety
/// Caller MUST call `end_read_phase()` exactly once for each
/// `begin_read_phase()`. Failing to do so permanently blocks writers.
#[inline]
pub unsafe fn begin_read_phase() {
    HEAP_GUARD.raw().lock_shared();
}

/// Release shared (read) lock from a long-running phase.
///
/// # Safety
/// Must be paired with a previous `begin_read_phase()`.
#[inline]
pub unsafe fn end_read_phase() {
    HEAP_GUARD.raw().unlock_shared();
}

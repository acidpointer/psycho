//! Global destruction guard for cross-subsystem synchronization.
//!
//! Lightweight atomic flag that signals "destruction is in progress."
//! Writers (PDD, cell cleanup, quarantine flush) set it before freeing
//! game objects. Readers (skeleton update, queued ref processing,
//! IOManager task dispatch) check it before accessing potentially
//! stale data.
//!
//! This is defense-in-depth: the quarantine timing (flush at Phase 4)
//! handles the common case. The destruction guard catches edge cases
//! where destruction happens outside the normal phase ordering:
//! - HeapCompact running PDD at non-standard times
//! - Cell transition PDD from the outer loop
//! - DeferredCleanupSmall called from the 5 normal PDD callers
//!   at various frame positions

use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag: true when any destruction path is actively freeing
/// game objects. Readers should skip or return safely when this is set.
static DESTRUCTION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Check if destruction is currently in progress.
/// Readers call this before accessing game object data that might
/// be stale. If true, the reader should skip processing.
#[inline]
pub fn is_destruction_active() -> bool {
    DESTRUCTION_ACTIVE.load(Ordering::Acquire)
}

/// RAII guard that sets DESTRUCTION_ACTIVE for its lifetime.
/// Used by destruction paths (PDD hooks, quarantine flush).
pub struct DestructionScope;

impl DestructionScope {
    /// Enter destruction mode. All reader hooks will see the flag.
    #[inline]
    pub fn enter() -> Self {
        DESTRUCTION_ACTIVE.store(true, Ordering::Release);
        DestructionScope
    }
}

impl Drop for DestructionScope {
    #[inline]
    fn drop(&mut self) {
        DESTRUCTION_ACTIVE.store(false, Ordering::Release);
    }
}

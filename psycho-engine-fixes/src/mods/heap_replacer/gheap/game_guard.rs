//! AI and Havok activity state used by cleanup and hang diagnostics.

use std::sync::atomic::{AtomicBool, Ordering};

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

// ---------------------------------------------------------------------------
// Havok physics active flag (for cell unload sync)
// ---------------------------------------------------------------------------

/// Set when hkWorld_Lock is called (physics stepping in progress).
/// Cleared when hkWorld_Unlock is called.
/// Used by cell unload to wait for physics to complete.
static HAVOK_PHYSICS_ACTIVE: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn set_havok_active() {
    HAVOK_PHYSICS_ACTIVE.store(true, Ordering::Release);
}

#[inline]
pub fn clear_havok_active() {
    HAVOK_PHYSICS_ACTIVE.store(false, Ordering::Release);
}

#[inline]
pub fn is_havok_active() -> bool {
    HAVOK_PHYSICS_ACTIVE.load(Ordering::Acquire)
}

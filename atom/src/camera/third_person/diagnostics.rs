//! Bounded third-person execution and ownership diagnostics.
//!
//! Camera and movement hooks only increment fixed atomics. They never format,
//! allocate, lock, or write a log. MCM's requested diagnostics summary copies
//! these counters later, outside every native callback. Saturation prevents a
//! long session from wrapping a real execution count back to zero.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::native::NativeRejection;

static ENABLED: AtomicBool = AtomicBool::new(false);
static HEADING_CALLS: AtomicU32 = AtomicU32::new(0);
static HEADING_CONSUMED: AtomicU32 = AtomicU32::new(0);
static CAMERA_HEADING_CALLS: AtomicU32 = AtomicU32::new(0);
static CAMERA_HEADING_OVERRIDES: AtomicU32 = AtomicU32::new(0);
static FOLLOW_CALLS: AtomicU32 = AtomicU32::new(0);
static FOLLOW_OFFSETS: AtomicU32 = AtomicU32::new(0);
static NONZERO_FOLLOW_OFFSETS: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_SCOPE_CALLS: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_SCOPES_ADMITTED: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_CALLS: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_OVERRIDES: AtomicU32 = AtomicU32::new(0);
static PITCH_HOLDS: AtomicU32 = AtomicU32::new(0);
static HEADING_HOLDS: AtomicU32 = AtomicU32::new(0);
static RECENTER_SUPPRESSIONS: AtomicU32 = AtomicU32::new(0);
static RECENTER_STARTS: AtomicU32 = AtomicU32::new(0);
static OWNED_OBSERVATIONS: AtomicU32 = AtomicU32::new(0);
static OBSERVATIONS: [AtomicU32; NativeRejection::COUNT] =
    [const { AtomicU32::new(0) }; NativeRejection::COUNT];

/// Point-in-time copy of third-person runtime-path counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) heading_calls: u32,
    pub(super) heading_consumed: u32,
    pub(super) camera_heading_calls: u32,
    pub(super) camera_heading_overrides: u32,
    pub(super) follow_calls: u32,
    pub(super) follow_offsets: u32,
    pub(super) nonzero_follow_offsets: u32,
    pub(super) movement_scope_calls: u32,
    pub(super) movement_scopes_admitted: u32,
    pub(super) movement_calls: u32,
    pub(super) movement_overrides: u32,
    pub(super) pitch_holds: u32,
    pub(super) heading_holds: u32,
    pub(super) recenter_suppressions: u32,
    pub(super) recenter_starts: u32,
    pub(super) owned_observations: u32,
    observations: [u32; NativeRejection::COUNT],
}

impl Snapshot {
    pub(super) const fn observations(self, reason: NativeRejection) -> u32 {
        self.observations[reason as usize]
    }
}

pub(super) fn configure(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
}

pub(super) fn reset() {
    for counter in stage_counters() {
        counter.store(0, Ordering::Relaxed);
    }
    for counter in &OBSERVATIONS {
        counter.store(0, Ordering::Relaxed);
    }
}

pub(super) fn mark_heading(consumed: bool) {
    increment(&HEADING_CALLS);
    if consumed {
        increment(&HEADING_CONSUMED);
    }
}

pub(super) fn mark_camera_heading(overridden: bool) {
    increment(&CAMERA_HEADING_CALLS);
    if overridden {
        increment(&CAMERA_HEADING_OVERRIDES);
    }
}

pub(super) fn mark_follow_call() {
    increment(&FOLLOW_CALLS);
}

pub(super) fn mark_follow_offset(offset: super::Vec3) {
    increment(&FOLLOW_OFFSETS);
    if offset.horizontal_length() > 0.000_1 || offset.z.abs() > 0.000_1 {
        increment(&NONZERO_FOLLOW_OFFSETS);
    }
}

pub(super) fn mark_movement_scope(admitted: bool) {
    increment(&MOVEMENT_SCOPE_CALLS);
    if admitted {
        increment(&MOVEMENT_SCOPES_ADMITTED);
    }
}

pub(super) fn mark_movement(applied: bool) {
    increment(&MOVEMENT_CALLS);
    if applied {
        increment(&MOVEMENT_OVERRIDES);
    }
}

pub(super) fn mark_pitch_hold() {
    increment(&PITCH_HOLDS);
}

pub(super) fn mark_heading_hold() {
    increment(&HEADING_HOLDS);
}

pub(super) fn mark_recenter_suppressed() {
    increment(&RECENTER_SUPPRESSIONS);
}

pub(super) fn mark_recenter_started() {
    increment(&RECENTER_STARTS);
}

pub(super) fn mark_observation(reason: NativeRejection, owned: bool) {
    increment(&OBSERVATIONS[reason as usize]);
    if owned {
        increment(&OWNED_OBSERVATIONS);
    }
}

pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        heading_calls: HEADING_CALLS.load(Ordering::Relaxed),
        heading_consumed: HEADING_CONSUMED.load(Ordering::Relaxed),
        camera_heading_calls: CAMERA_HEADING_CALLS.load(Ordering::Relaxed),
        camera_heading_overrides: CAMERA_HEADING_OVERRIDES.load(Ordering::Relaxed),
        follow_calls: FOLLOW_CALLS.load(Ordering::Relaxed),
        follow_offsets: FOLLOW_OFFSETS.load(Ordering::Relaxed),
        nonzero_follow_offsets: NONZERO_FOLLOW_OFFSETS.load(Ordering::Relaxed),
        movement_scope_calls: MOVEMENT_SCOPE_CALLS.load(Ordering::Relaxed),
        movement_scopes_admitted: MOVEMENT_SCOPES_ADMITTED.load(Ordering::Relaxed),
        movement_calls: MOVEMENT_CALLS.load(Ordering::Relaxed),
        movement_overrides: MOVEMENT_OVERRIDES.load(Ordering::Relaxed),
        pitch_holds: PITCH_HOLDS.load(Ordering::Relaxed),
        heading_holds: HEADING_HOLDS.load(Ordering::Relaxed),
        recenter_suppressions: RECENTER_SUPPRESSIONS.load(Ordering::Relaxed),
        recenter_starts: RECENTER_STARTS.load(Ordering::Relaxed),
        owned_observations: OWNED_OBSERVATIONS.load(Ordering::Relaxed),
        observations: load_observations(),
    }
}

fn increment(counter: &AtomicU32) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn stage_counters() -> [&'static AtomicU32; 16] {
    [
        &HEADING_CALLS,
        &HEADING_CONSUMED,
        &CAMERA_HEADING_CALLS,
        &CAMERA_HEADING_OVERRIDES,
        &FOLLOW_CALLS,
        &FOLLOW_OFFSETS,
        &NONZERO_FOLLOW_OFFSETS,
        &MOVEMENT_SCOPE_CALLS,
        &MOVEMENT_SCOPES_ADMITTED,
        &MOVEMENT_CALLS,
        &MOVEMENT_OVERRIDES,
        &PITCH_HOLDS,
        &HEADING_HOLDS,
        &RECENTER_SUPPRESSIONS,
        &RECENTER_STARTS,
        &OWNED_OBSERVATIONS,
    ]
}

fn load_observations() -> [u32; NativeRejection::COUNT] {
    let mut values = [0; NativeRejection::COUNT];
    for (value, counter) in values.iter_mut().zip(&OBSERVATIONS) {
        *value = counter.load(Ordering::Relaxed);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{NativeRejection, configure, mark_observation, reset, snapshot};

    #[test]
    fn collection_is_inert_when_disabled_and_bounded_when_enabled() {
        configure(false);
        reset();
        mark_observation(NativeRejection::Perspective, false);
        assert_eq!(snapshot().observations(NativeRejection::Perspective), 0);

        configure(true);
        mark_observation(NativeRejection::Perspective, false);
        assert_eq!(snapshot().observations(NativeRejection::Perspective), 1);
        configure(false);
    }
}

//! Bounded first-person camera path diagnostics.
//!
//! Native update and render hooks only increment fixed 32-bit atomics. They do
//! not allocate, lock, format, or write logs. A requested MCM diagnostics
//! summary copies the counters later, outside every engine hook. Saturation is
//! deliberate: a long session must not wrap old failures into plausible zeros.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::native::NativeRejection;

static ENABLED: AtomicBool = AtomicBool::new(false);
static UPDATE_CALLS: AtomicU32 = AtomicU32::new(0);
static SAMPLES_ACCEPTED: AtomicU32 = AtomicU32::new(0);
static NON_IDENTITY_FRAMES: AtomicU32 = AtomicU32::new(0);
static WORLD_CALLS: AtomicU32 = AtomicU32::new(0);
static WORLD_ADMITTED: AtomicU32 = AtomicU32::new(0);
static WORLD_POSES: AtomicU32 = AtomicU32::new(0);
static VIEWMODEL_CALLS: AtomicU32 = AtomicU32::new(0);
static VIEWMODEL_POSES: AtomicU32 = AtomicU32::new(0);
static TRANSFORMS_APPLIED: AtomicU32 = AtomicU32::new(0);
static TRANSFORMS_REJECTED: AtomicU32 = AtomicU32::new(0);
static MOTION_BUSY: AtomicU32 = AtomicU32::new(0);
static TOKEN_MISSES: AtomicU32 = AtomicU32::new(0);
static SAMPLE_REJECTIONS: [AtomicU32; NativeRejection::COUNT] =
    [const { AtomicU32::new(0) }; NativeRejection::COUNT];
static RENDER_REJECTIONS: [AtomicU32; NativeRejection::COUNT] =
    [const { AtomicU32::new(0) }; NativeRejection::COUNT];

/// Point-in-time copy of the bounded first-person camera counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) update_calls: u32,
    pub(crate) samples_accepted: u32,
    pub(crate) non_identity_frames: u32,
    pub(crate) world_calls: u32,
    pub(crate) world_admitted: u32,
    pub(crate) world_poses: u32,
    pub(crate) viewmodel_calls: u32,
    pub(crate) viewmodel_poses: u32,
    pub(crate) transforms_applied: u32,
    pub(crate) transforms_rejected: u32,
    pub(crate) motion_busy: u32,
    pub(crate) token_misses: u32,
    sample_rejections: [u32; NativeRejection::COUNT],
    render_rejections: [u32; NativeRejection::COUNT],
}

impl Snapshot {
    /// Return the sample rejection count for one fail-closed native gate.
    pub(crate) const fn sample_rejections(self, reason: NativeRejection) -> u32 {
        self.sample_rejections[reason as usize]
    }

    /// Return the render rejection count for one fail-closed native gate.
    pub(crate) const fn render_rejections(self, reason: NativeRejection) -> u32 {
        self.render_rejections[reason as usize]
    }
}

pub(crate) fn configure(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
}

pub(crate) fn reset() {
    for counter in stage_counters() {
        counter.store(0, Ordering::Relaxed);
    }
    for counter in SAMPLE_REJECTIONS.iter().chain(&RENDER_REJECTIONS) {
        counter.store(0, Ordering::Relaxed);
    }
}

pub(super) fn mark_update_call() {
    increment(&UPDATE_CALLS);
}

pub(super) fn mark_sample_accepted(non_identity: bool) {
    increment(&SAMPLES_ACCEPTED);
    if non_identity {
        increment(&NON_IDENTITY_FRAMES);
    }
}

pub(super) fn mark_sample_rejected(reason: NativeRejection) {
    increment(&SAMPLE_REJECTIONS[reason as usize]);
}

pub(super) fn mark_motion_busy() {
    increment(&MOTION_BUSY);
}

pub(super) fn mark_world_call() {
    increment(&WORLD_CALLS);
}

pub(super) fn mark_world_admitted() {
    increment(&WORLD_ADMITTED);
}

pub(super) fn mark_world_pose() {
    increment(&WORLD_POSES);
}

pub(super) fn mark_render_rejected(reason: NativeRejection) {
    increment(&RENDER_REJECTIONS[reason as usize]);
}

pub(super) fn mark_viewmodel_call() {
    increment(&VIEWMODEL_CALLS);
}

pub(super) fn mark_viewmodel_pose() {
    increment(&VIEWMODEL_POSES);
}

pub(super) fn mark_token_miss() {
    increment(&TOKEN_MISSES);
}

pub(super) fn mark_transform(applied: bool) {
    increment(if applied {
        &TRANSFORMS_APPLIED
    } else {
        &TRANSFORMS_REJECTED
    });
}

pub(crate) fn snapshot() -> Snapshot {
    Snapshot {
        update_calls: UPDATE_CALLS.load(Ordering::Relaxed),
        samples_accepted: SAMPLES_ACCEPTED.load(Ordering::Relaxed),
        non_identity_frames: NON_IDENTITY_FRAMES.load(Ordering::Relaxed),
        world_calls: WORLD_CALLS.load(Ordering::Relaxed),
        world_admitted: WORLD_ADMITTED.load(Ordering::Relaxed),
        world_poses: WORLD_POSES.load(Ordering::Relaxed),
        viewmodel_calls: VIEWMODEL_CALLS.load(Ordering::Relaxed),
        viewmodel_poses: VIEWMODEL_POSES.load(Ordering::Relaxed),
        transforms_applied: TRANSFORMS_APPLIED.load(Ordering::Relaxed),
        transforms_rejected: TRANSFORMS_REJECTED.load(Ordering::Relaxed),
        motion_busy: MOTION_BUSY.load(Ordering::Relaxed),
        token_misses: TOKEN_MISSES.load(Ordering::Relaxed),
        sample_rejections: load_rejections(&SAMPLE_REJECTIONS),
        render_rejections: load_rejections(&RENDER_REJECTIONS),
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

fn stage_counters() -> [&'static AtomicU32; 12] {
    [
        &UPDATE_CALLS,
        &SAMPLES_ACCEPTED,
        &NON_IDENTITY_FRAMES,
        &WORLD_CALLS,
        &WORLD_ADMITTED,
        &WORLD_POSES,
        &VIEWMODEL_CALLS,
        &VIEWMODEL_POSES,
        &TRANSFORMS_APPLIED,
        &TRANSFORMS_REJECTED,
        &MOTION_BUSY,
        &TOKEN_MISSES,
    ]
}

fn load_rejections(
    counters: &[AtomicU32; NativeRejection::COUNT],
) -> [u32; NativeRejection::COUNT] {
    let mut values = [0; NativeRejection::COUNT];
    for (value, counter) in values.iter_mut().zip(counters) {
        *value = counter.load(Ordering::Relaxed);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{NativeRejection, configure, mark_sample_rejected, reset, snapshot};

    #[test]
    fn disabled_collection_is_inert_and_enabled_collection_is_bounded() {
        configure(false);
        reset();
        mark_sample_rejected(NativeRejection::Menu);
        assert_eq!(snapshot().sample_rejections(NativeRejection::Menu), 0);

        configure(true);
        mark_sample_rejected(NativeRejection::Menu);
        assert_eq!(snapshot().sample_rejections(NativeRejection::Menu), 1);
        configure(false);
    }
}

//! Collision-limited third-person presentation translation.
//!
//! FNV's native chase solver remains the sole owner of structural camera
//! distance and its persistent collision history. This module applies Atom's
//! small procedural translation only to the completed native camera position.
//! It owns no engine pointer: the native adapter supplies either a clear short
//! segment or the accepted hit point and camera clearance for one synchronous
//! call. Invalid geometry fails without producing a replacement position.

use core::sync::atomic::{AtomicU32, Ordering};

use super::Vec3;
use super::motion::MAX_TRANSLATION_LENGTH;

/// Result of FNV's short presentation-clearance query.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum CameraMotionClearance {
    /// No accepted obstruction lies on the native-to-presented segment.
    Clear,
    /// The engine returned the nearest accepted point on that segment.
    Hit { position: Vec3, caster_radius: f32 },
}

/// Seconds required to re-expand the applied translation after a clipped frame.
///
/// Clipping toward the native position stays immediate because presenting
/// into geometry is never acceptable. Recovery away from it is rate-limited:
/// when a grazing obstruction clears, an instant full re-application would
/// move the presented camera by up to the whole translation in one frame.
const MOTION_RECOVERY_SECONDS: f32 = 0.12;
/// Upper bound for the observed frame interval used by recovery integration.
const MOTION_RECOVERY_MAX_DT: f32 = 0.1;

static APPLIED_FRACTION: AtomicU32 = AtomicU32::new(1.0_f32.to_bits());
static LAST_RECOVERY_SECONDS: AtomicU32 = AtomicU32::new(0);

/// Discard recovery history at epoch boundaries.
pub(super) fn reset_recovery() {
    APPLIED_FRACTION.store(1.0_f32.to_bits(), Ordering::Relaxed);
    LAST_RECOVERY_SECONDS.store(0, Ordering::Relaxed);
}

/// Pure recovery transition between two applied fractions.
///
/// Clipping toward a smaller allowance is immediate; growth toward a larger
/// allowance integrates over [`MOTION_RECOVERY_SECONDS`] using the observed
/// frame interval, so equivalent time partitions recover equivalently.
/// Invalid intervals hold the previous fraction.
fn next_applied_fraction(previous: f32, allowed: f32, delta_seconds: f32) -> f32 {
    if !previous.is_finite() || allowed < previous {
        return allowed;
    }
    let share = if delta_seconds.is_finite() && delta_seconds > 0.0 {
        delta_seconds.min(MOTION_RECOVERY_MAX_DT) / MOTION_RECOVERY_SECONDS
    } else {
        0.0
    };
    (previous + share).min(allowed)
}

/// Update the stored recovery state for one presented frame.
fn advance_applied_fraction(allowed_fraction: f32, now_seconds: f32) -> f32 {
    let previous = f32::from_bits(APPLIED_FRACTION.load(Ordering::Relaxed));
    let last = f32::from_bits(LAST_RECOVERY_SECONDS.swap(now_seconds.to_bits(), Ordering::Relaxed));
    let delta = if last.is_finite() && last > 0.0 && now_seconds.is_finite() && now_seconds >= last
    {
        now_seconds - last
    } else {
        0.0
    };
    let next = next_applied_fraction(previous, allowed_fraction, delta);
    APPLIED_FRACTION.store(next.to_bits(), Ordering::Relaxed);
    next
}

/// Resolve one bounded procedural offset after native chase collision.
///
/// A hit is shortened by FNV's own camera-caster radius. The engine query owns
/// hit filtering; this function owns only finite arithmetic and segment bounds.
/// Invalid input returns `None` so the callsite can chain the untouched native
/// position.
pub(super) fn resolve_motion_endpoint(
    native_position: Vec3,
    motion: Vec3,
    clearance: CameraMotionClearance,
) -> Option<Vec3> {
    let allowed_fraction = allowed_motion_fraction(native_position, motion, clearance)?;
    apply_motion_fraction(native_position, motion, allowed_fraction)
}

/// [`resolve_motion_endpoint`] with collision-clipped recovery memory.
///
/// Identical geometry result, except that re-expansion after a clipped frame
/// is rate-limited instead of instantaneous. Epoch resets call
/// [`reset_recovery`] so a new ownership start always begins fully applied.
pub(super) fn resolve_motion_endpoint_with_recovery(
    native_position: Vec3,
    motion: Vec3,
    clearance: CameraMotionClearance,
    now_seconds: f32,
) -> Option<Vec3> {
    let allowed_fraction = allowed_motion_fraction(native_position, motion, clearance)?;
    let applied_fraction = advance_applied_fraction(allowed_fraction, now_seconds);
    apply_motion_fraction(native_position, motion, applied_fraction)
}

/// Return the clearance-permitted share of `motion` in `[0, 1]`.
fn allowed_motion_fraction(
    native_position: Vec3,
    motion: Vec3,
    clearance: CameraMotionClearance,
) -> Option<f32> {
    if !native_position.is_finite() || !motion.is_finite() {
        return None;
    }
    let motion_distance = motion.length();
    if !motion_distance.is_finite() || motion_distance > MAX_TRANSLATION_LENGTH {
        return None;
    }
    if motion_distance <= f32::EPSILON {
        return Some(1.0);
    }
    match clearance {
        CameraMotionClearance::Clear => Some(1.0),
        CameraMotionClearance::Hit {
            position,
            caster_radius,
        } => {
            if !position.is_finite() || !caster_radius.is_finite() || caster_radius < 0.0 {
                return None;
            }
            let hit_distance = (position - native_position).length();
            if !hit_distance.is_finite() {
                return None;
            }
            Some((hit_distance - caster_radius).clamp(0.0, motion_distance) / motion_distance)
        }
    }
}

fn apply_motion_fraction(native_position: Vec3, motion: Vec3, fraction: f32) -> Option<Vec3> {
    if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
        return None;
    }
    let resolved = native_position + motion * fraction;
    resolved.is_finite().then_some(resolved)
}

#[cfg(test)]
mod tests {
    use super::{
        CameraMotionClearance, MOTION_RECOVERY_SECONDS, next_applied_fraction,
        resolve_motion_endpoint,
    };
    use crate::camera::third_person::Vec3;

    fn hit(position: Vec3, radius: f32) -> CameraMotionClearance {
        CameraMotionClearance::Hit {
            position,
            caster_radius: radius,
        }
    }

    #[test]
    fn clear_motion_is_applied_after_the_native_position() {
        let native = Vec3::new(10.0, 20.0, 30.0);
        let motion = Vec3::new(1.0, -2.0, 3.0);
        assert_eq!(
            resolve_motion_endpoint(native, motion, CameraMotionClearance::Clear),
            Some(native + motion),
        );
    }

    #[test]
    fn collision_clips_only_the_short_presentation_segment() {
        let native = Vec3::new(10.0, 0.0, 0.0);
        let motion = Vec3::new(6.0, 0.0, 0.0);
        assert_eq!(
            resolve_motion_endpoint(native, motion, hit(Vec3::new(14.0, 0.0, 0.0), 1.5)),
            Some(Vec3::new(12.5, 0.0, 0.0)),
        );
    }

    #[test]
    fn collision_inside_caster_radius_preserves_native_position() {
        let native = Vec3::new(1.0, 2.0, 3.0);
        let motion = Vec3::new(0.0, 5.0, 0.0);
        assert_eq!(
            resolve_motion_endpoint(native, motion, hit(Vec3::new(1.0, 2.5, 3.0), 1.0)),
            Some(native),
        );
    }

    #[test]
    fn invalid_or_unbounded_motion_fails_native() {
        let native = Vec3::new(1.0, 2.0, 3.0);
        assert!(
            resolve_motion_endpoint(
                native,
                Vec3::new(f32::NAN, 0.0, 0.0),
                CameraMotionClearance::Clear,
            )
            .is_none()
        );
        assert!(
            resolve_motion_endpoint(
                native,
                Vec3::new(6.01, 0.0, 0.0),
                CameraMotionClearance::Clear,
            )
            .is_none()
        );
    }

    #[test]
    fn clipping_is_immediate_and_re_expansion_is_rate_limited() {
        // A smaller allowance always applies in the same frame.
        assert_eq!(next_applied_fraction(1.0, 0.5, 1.0 / 60.0), 0.5);
        // Growth integrates over the recovery budget, not one frame.
        let step = MOTION_RECOVERY_SECONDS / 6.0;
        let after_one_step = next_applied_fraction(0.5, 1.0, step);
        assert!((after_one_step - (0.5 + 1.0 / 6.0)).abs() < 0.000_1);
        // Equivalent partitions recover equivalently.
        let two_small =
            next_applied_fraction(next_applied_fraction(0.5, 1.0, step / 2.0), 1.0, step / 2.0);
        assert!((two_small - after_one_step).abs() < 0.000_1);
        // Recovery saturates at the allowance.
        assert_eq!(
            next_applied_fraction(after_one_step, 1.0, MOTION_RECOVERY_SECONDS * 2.0),
            1.0
        );
    }

    #[test]
    fn invalid_intervals_hold_and_non_finite_history_clips() {
        assert_eq!(next_applied_fraction(0.5, 1.0, f32::NAN), 0.5);
        assert_eq!(next_applied_fraction(0.5, 1.0, -1.0), 0.5);
        assert_eq!(next_applied_fraction(0.5, 1.0, 0.0), 0.5);
        // A poisoned fraction recovers to the allowance instead of staying.
        assert_eq!(next_applied_fraction(f32::NAN, 0.75, 1.0), 0.75);
        // Oversized intervals are bounded, never a jump past the allowance.
        assert_eq!(next_applied_fraction(0.5, 0.9, 100.0), 0.9);
    }
}

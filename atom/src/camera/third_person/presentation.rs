//! Collision-limited third-person presentation translation.
//!
//! FNV's native chase solver remains the sole owner of structural camera
//! distance and its persistent collision history. This module applies Atom's
//! small procedural translation only to the completed native camera position.
//! It owns no engine pointer: the native adapter supplies either a clear short
//! segment or the accepted hit point and camera clearance for one synchronous
//! call. Invalid geometry fails without producing a replacement position.

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
    if !native_position.is_finite() || !motion.is_finite() {
        return None;
    }
    let motion_distance = motion.length();
    if !motion_distance.is_finite() || motion_distance > MAX_TRANSLATION_LENGTH {
        return None;
    }
    if motion_distance <= f32::EPSILON {
        return Some(native_position);
    }

    let candidate = native_position + motion;
    if !candidate.is_finite() {
        return None;
    }
    let allowed_distance = match clearance {
        CameraMotionClearance::Clear => motion_distance,
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
            (hit_distance - caster_radius).clamp(0.0, motion_distance)
        }
    };
    let resolved = native_position + motion * (allowed_distance / motion_distance);
    resolved.is_finite().then_some(resolved)
}

#[cfg(test)]
mod tests {
    use super::{CameraMotionClearance, resolve_motion_endpoint};
    use crate::camera::third_person::Vec3;

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
        let clearance = CameraMotionClearance::Hit {
            position: Vec3::new(14.0, 0.0, 0.0),
            caster_radius: 1.5,
        };
        assert_eq!(
            resolve_motion_endpoint(native, motion, clearance),
            Some(Vec3::new(12.5, 0.0, 0.0)),
        );
    }

    #[test]
    fn collision_inside_caster_radius_preserves_native_position() {
        let native = Vec3::new(1.0, 2.0, 3.0);
        let motion = Vec3::new(0.0, 5.0, 0.0);
        let clearance = CameraMotionClearance::Hit {
            position: Vec3::new(1.0, 2.5, 3.0),
            caster_radius: 1.0,
        };
        assert_eq!(
            resolve_motion_endpoint(native, motion, clearance),
            Some(native)
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
}

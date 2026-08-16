//! Third-person reticle and real-muzzle convergence math.
//!
//! Atom keeps FNV's native reticle cast, projectile subtype, collision, range,
//! and impact ownership. This module only derives a muzzle-to-target base
//! angle and reapplies the exact angular spread delta already sampled by the
//! native ranged-fire path.

use super::follow::Vec3;
use super::movement::wrap_angle;

/// Horizontal yaw and vertical pitch in FNV radians.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AimAngles {
    yaw: f32,
    pitch: f32,
}

impl AimAngles {
    /// Construct angles in FNV's yaw/pitch convention.
    pub const fn new(yaw: f32, pitch: f32) -> Self {
        Self { yaw, pitch }
    }

    /// Return horizontal yaw in radians.
    pub const fn yaw(self) -> f32 {
        self.yaw
    }

    /// Return vertical pitch in radians.
    pub const fn pitch(self) -> f32 {
        self.pitch
    }

    /// Return whether both angles are finite.
    pub fn is_finite(self) -> bool {
        self.yaw.is_finite() && self.pitch.is_finite()
    }
}

/// Build the logical view direction used by FNV's native reticle cast.
///
/// FNV uses +Y as yaw zero and negative X rotation for upward pitch.
pub fn view_direction(yaw: f32, pitch: f32) -> Option<Vec3> {
    if !yaw.is_finite() || !pitch.is_finite() {
        return None;
    }
    let (sin_yaw, cos_yaw) = yaw.sin_cos();
    let (sin_pitch, cos_pitch) = pitch.sin_cos();
    Some(Vec3::new(
        sin_yaw * cos_pitch,
        cos_yaw * cos_pitch,
        -sin_pitch,
    ))
}

/// Converge a native shot on a target while preserving sampled spread.
///
/// `native_base` is the projectile-node orientation before spread and
/// `native_final` is the already perturbed launch angle. The returned value
/// applies their wrapped delta around the real muzzle-to-target direction.
/// A degenerate or non-finite geometry returns `None` so the caller can chain
/// the original native launch unchanged.
pub fn converge_angles(
    muzzle: Vec3,
    target: Vec3,
    native_base: AimAngles,
    native_final: AimAngles,
) -> Option<AimAngles> {
    if !muzzle.is_finite()
        || !target.is_finite()
        || !native_base.is_finite()
        || !native_final.is_finite()
    {
        return None;
    }
    let direction = target - muzzle;
    let horizontal = direction.horizontal_length();
    if horizontal <= f32::EPSILON && direction.z.abs() <= f32::EPSILON {
        return None;
    }

    let base_yaw = direction.x.atan2(direction.y);
    let base_pitch = -direction.z.atan2(horizontal);
    let spread_yaw = wrap_angle(native_final.yaw - native_base.yaw);
    let spread_pitch = wrap_angle(native_final.pitch - native_base.pitch);
    Some(AimAngles::new(
        wrap_angle(base_yaw + spread_yaw),
        wrap_angle(base_pitch + spread_pitch),
    ))
}

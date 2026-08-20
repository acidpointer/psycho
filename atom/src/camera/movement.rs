//! Camera-relative movement and authoritative actor-facing math.
//!
//! FNV has already produced an actor-local vector and complete movement flags
//! before this module runs. The native movement wrapper subsequently rotates
//! that vector into world space with the actor's authoritative Z heading.
//! Atom compensates the local vector for the heading that will actually reach
//! that wrapper, preserving magnitude and every unowned flag bit.

use core::f32::consts::{PI, TAU};

use super::follow::Vec3;

/// Facing policy selected by the camera ownership state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FacingPolicy {
    /// Moving actors face world movement while native locomotion flags stay authoritative.
    Explore,
    /// Actors face the logical view and preserve native strafe intent.
    Combat,
}

/// Immutable camera-relative intent awaiting the actor heading used by FNV.
///
/// Preparing intent and resolving it are deliberately separate operations.
/// The native absolute-yaw setter can normalize or reject a requested angle
/// without reporting success. Callers must therefore invoke the setter, read
/// the actor's resulting raw `rotZ`, and pass that observed value to
/// [`MovementIntent::resolve`]. This ordering prevents a second unintended
/// rotation when FNV later transforms the request into world space.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MovementIntent {
    native: Vec3,
    flags: u32,
    view_yaw: f32,
    policy: FacingPolicy,
    native_heading: Option<f32>,
    movement_heading: Option<f32>,
    valid: bool,
}

impl MovementIntent {
    /// Capture one native actor-local request and its logical camera heading.
    pub fn new(native: Vec3, flags: u32, view_yaw: f32, policy: FacingPolicy) -> Self {
        let valid = native.is_finite() && view_yaw.is_finite();
        let native_heading = valid.then(|| local_movement_heading(native)).flatten();
        Self {
            native,
            flags,
            view_yaw,
            policy,
            native_heading,
            movement_heading: native_heading
                .and_then(|_| camera_relative_heading(native, view_yaw)),
            valid,
        }
    }

    /// Capture one request with an already-owned world travel heading.
    ///
    /// This is used while auto-centering: the camera may turn, but the held
    /// local input must continue to produce the world direction latched when
    /// recentering began. Invalid or zero movement remains an unchanged native
    /// request.
    pub fn with_world_heading(
        native: Vec3,
        flags: u32,
        view_yaw: f32,
        policy: FacingPolicy,
        world_heading: f32,
    ) -> Self {
        let valid = native.is_finite() && view_yaw.is_finite() && world_heading.is_finite();
        let native_heading = valid.then(|| local_movement_heading(native)).flatten();
        Self {
            native,
            flags,
            view_yaw,
            policy,
            native_heading,
            movement_heading: native_heading.map(|_| wrap_angle(world_heading)),
            valid,
        }
    }

    /// Return the desired authoritative actor heading, when one exists.
    ///
    /// Explore mode faces nonzero world movement. Combat mode faces the view
    /// even while stationary so firing and blocking do not depend on a prior
    /// movement sample.
    pub const fn facing_target(self) -> Option<f32> {
        if !self.valid {
            return None;
        }
        match self.policy {
            FacingPolicy::Explore => self.movement_heading,
            FacingPolicy::Combat => Some(self.view_yaw),
        }
    }

    /// Return the desired camera-relative world movement heading.
    pub const fn movement_heading(self) -> Option<f32> {
        self.movement_heading
    }

    /// Resolve the actor-local request against the raw yaw FNV will consume.
    ///
    /// `actual_actor_yaw` must be sampled after any requested facing write.
    /// Invalid input returns the original native request unchanged.
    pub fn resolve(self, actual_actor_yaw: f32) -> MovementOutput {
        if !self.valid || !actual_actor_yaw.is_finite() {
            return MovementOutput {
                vector: self.native,
                flags: self.flags,
                movement_heading: None,
            };
        }

        let (Some(native_heading), Some(movement_heading)) =
            (self.native_heading, self.movement_heading)
        else {
            return MovementOutput {
                vector: self.native,
                flags: self.flags,
                movement_heading: None,
            };
        };

        // FNV later applies E(actual_actor_yaw). Applying
        // E(movement_heading - actual_actor_yaw - native_heading) here makes
        // the composition produce the owned world heading. The general form
        // is required while auto-center turns the camera but must not steer a
        // held diagonal input with that changing camera basis.
        let angle = wrap_angle(movement_heading - actual_actor_yaw - native_heading);
        let (sin_angle, cos_angle) = angle.sin_cos();
        let vector = Vec3::new(
            cos_angle.mul_add(self.native.x, sin_angle * self.native.y),
            (-sin_angle).mul_add(self.native.x, cos_angle * self.native.y),
            self.native.z,
        );
        MovementOutput {
            vector,
            // The researched native wrapper copies the complete request flags
            // into its movement objects. They are engine-owned input, not an
            // animation-only field Atom may reinterpret as Actor yaw changes.
            flags: self.flags,
            movement_heading: self.movement_heading,
        }
    }
}

/// Camera-relative movement request produced for FNV's native pipeline.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MovementOutput {
    vector: Vec3,
    flags: u32,
    movement_heading: Option<f32>,
}

impl MovementOutput {
    /// Return the compensated actor-local vector with native magnitude preserved.
    pub const fn vector(self) -> Vec3 {
        self.vector
    }

    /// Return the complete unchanged native movement flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Return the movement heading in radians when horizontal intent exists.
    pub const fn movement_heading(self) -> Option<f32> {
        self.movement_heading
    }
}

/// Return the world heading of camera-relative movement intent.
///
/// FNV's Z matrix maps an actor-local `(x, y)` vector to world space as
/// `(cos(yaw) * x + sin(yaw) * y, -sin(yaw) * x + cos(yaw) * y)`. In
/// particular, local `+Y` is forward and maps to `(sin(yaw), cos(yaw))`.
/// This function applies that exact convention and returns the resulting
/// heading. A zero horizontal vector has no heading.
pub fn camera_relative_heading(native: Vec3, view_yaw: f32) -> Option<f32> {
    if !native.is_finite() || !view_yaw.is_finite() {
        return None;
    }
    if native.horizontal_length() <= f32::EPSILON {
        return None;
    }

    let (sin_yaw, cos_yaw) = view_yaw.sin_cos();
    let world_x = cos_yaw.mul_add(native.x, sin_yaw * native.y);
    let world_y = (-sin_yaw).mul_add(native.x, cos_yaw * native.y);
    Some(wrap_angle(world_x.atan2(world_y)))
}

/// Compensate FNV's actor-local movement for camera-relative world intent.
///
/// `actor_yaw` must be the heading that the caller has already written, or the
/// unchanged native heading when no facing write occurred. The returned local
/// vector makes FNV's later actor-heading transform produce the same world
/// vector as applying `view_yaw` to the original local input. Explore mode
/// preserves the complete native flags in both Explore and Combat.
pub fn remap_movement(
    native: Vec3,
    flags: u32,
    actor_yaw: f32,
    view_yaw: f32,
    policy: FacingPolicy,
) -> MovementOutput {
    MovementIntent::new(native, flags, view_yaw, policy).resolve(actor_yaw)
}

/// Wrap an angle to the half-open interval `[-pi, pi)`.
pub fn wrap_angle(angle: f32) -> f32 {
    if !angle.is_finite() {
        return 0.0;
    }
    (angle + PI).rem_euclid(TAU) - PI
}

fn local_movement_heading(native: Vec3) -> Option<f32> {
    (native.horizontal_length() > f32::EPSILON).then(|| native.x.atan2(native.y))
}

/// Advance a heading with bounded angular speed and acceleration.
///
/// `speed` is the caller-owned current turn rate. The function accelerates
/// toward `max_speed`, brakes when required to avoid overshoot, and always
/// follows the shortest wrapped arc.
pub fn step_heading(
    current: f32,
    target: f32,
    speed: &mut f32,
    max_speed: f32,
    acceleration: f32,
    dt: f32,
) -> f32 {
    if !current.is_finite()
        || !target.is_finite()
        || !speed.is_finite()
        || !max_speed.is_finite()
        || !acceleration.is_finite()
        || max_speed <= 0.0
        || acceleration <= 0.0
        || dt <= 0.0
        || !dt.is_finite()
    {
        *speed = 0.0;
        return if current.is_finite() { current } else { 0.0 };
    }

    let delta = wrap_angle(target - current);
    let distance = delta.abs();
    if distance <= 0.000_01 {
        *speed = 0.0;
        return wrap_angle(target);
    }

    let braking_speed = (2.0 * acceleration * distance).sqrt();
    let desired_speed = max_speed.min(braking_speed);
    *speed = (*speed + acceleration * dt).min(desired_speed);
    let step = (*speed * dt).min(distance);
    wrap_angle(current + delta.signum() * step)
}

//! Camera-relative movement and authoritative actor-facing math.
//!
//! FNV has already produced an actor-local vector and complete movement flags
//! before this module runs. The native movement wrapper subsequently rotates
//! that vector into world space with the actor's authoritative Z heading.
//! Atom compensates the local vector for the heading that will actually reach
//! that wrapper, preserving magnitude and every unowned flag bit.

use core::f32::consts::{PI, TAU};

use super::follow::Vec3;

/// Native low movement-direction bits accepted by FNV's movement request.
pub const DIRECTION_MASK: u32 = 0x0F;
/// Native forward movement bit.
pub const FORWARD: u32 = 0x01;
/// Native backward movement bit.
pub const BACKWARD: u32 = 0x02;
/// Native left movement bit.
pub const LEFT: u32 = 0x04;
/// Native right movement bit.
pub const RIGHT: u32 = 0x08;

const OCTANT_RADIANS: f32 = PI / 4.0;
const HALF_OCTANT_RADIANS: f32 = PI / 8.0;
const SECTOR_HYSTERESIS_RADIANS: f32 = PI / 36.0;

/// Eight-way locomotion direction relative to the actor's current body yaw.
///
/// FNV has no separate diagonal direction bits. Its native keyboard path
/// expresses diagonals by combining one forward/backward bit with one
/// left/right bit, so these values remain compatible with whichever cardinal
/// locomotion assets the active animation provider supplies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocomotionSector {
    /// Forward relative to the actor.
    Forward,
    /// Forward and right relative to the actor.
    ForwardRight,
    /// Right relative to the actor.
    Right,
    /// Backward and right relative to the actor.
    BackwardRight,
    /// Backward relative to the actor.
    Backward,
    /// Backward and left relative to the actor.
    BackwardLeft,
    /// Left relative to the actor.
    Left,
    /// Forward and left relative to the actor.
    ForwardLeft,
}

impl LocomotionSector {
    /// Return the exact native low direction nibble for this sector.
    pub const fn direction_bits(self) -> u32 {
        match self {
            Self::Forward => FORWARD,
            Self::ForwardRight => FORWARD | RIGHT,
            Self::Right => RIGHT,
            Self::BackwardRight => BACKWARD | RIGHT,
            Self::Backward => BACKWARD,
            Self::BackwardLeft => BACKWARD | LEFT,
            Self::Left => LEFT,
            Self::ForwardLeft => FORWARD | LEFT,
        }
    }

    const fn center_radians(self) -> f32 {
        match self {
            Self::Forward => 0.0,
            Self::ForwardRight => OCTANT_RADIANS,
            Self::Right => 2.0 * OCTANT_RADIANS,
            Self::BackwardRight => 3.0 * OCTANT_RADIANS,
            Self::Backward => PI,
            Self::BackwardLeft => -3.0 * OCTANT_RADIANS,
            Self::Left => -2.0 * OCTANT_RADIANS,
            Self::ForwardLeft => -OCTANT_RADIANS,
        }
    }

    fn nearest(actor_local_heading: f32) -> Self {
        match ((actor_local_heading / OCTANT_RADIANS).round() as i32).rem_euclid(8) {
            0 => Self::Forward,
            1 => Self::ForwardRight,
            2 => Self::Right,
            3 => Self::BackwardRight,
            4 => Self::Backward,
            5 => Self::BackwardLeft,
            6 => Self::Left,
            _ => Self::ForwardLeft,
        }
    }

    fn select(actor_local_heading: f32, previous: Option<Self>) -> Self {
        if let Some(previous) = previous {
            // Retaining the current sector for five degrees past the nominal
            // 22.5-degree boundary prevents animation flags from alternating
            // when analog input or bounded actor turning hovers at a seam.
            let distance = wrap_angle(actor_local_heading - previous.center_radians()).abs();
            if distance <= HALF_OCTANT_RADIANS + SECTOR_HYSTERESIS_RADIANS {
                return previous;
            }
        }
        Self::nearest(actor_local_heading)
    }
}

/// Facing policy selected by the camera ownership state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FacingPolicy {
    /// Moving actors face world movement and select actor-local eight-way locomotion.
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
    movement_heading: Option<f32>,
    valid: bool,
}

impl MovementIntent {
    /// Capture one native actor-local request and its logical camera heading.
    pub fn new(native: Vec3, flags: u32, view_yaw: f32, policy: FacingPolicy) -> Self {
        let valid = native.is_finite() && view_yaw.is_finite();
        Self {
            native,
            flags,
            view_yaw,
            policy,
            movement_heading: valid
                .then(|| camera_relative_heading(native, view_yaw))
                .flatten(),
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
        self.resolve_stateful(actual_actor_yaw, None).output
    }

    /// Resolve movement while retaining an optional prior Explore sector.
    ///
    /// The returned sector is `Some` only for finite, nonzero Explore motion.
    /// Passing the preceding result enables boundary hysteresis; callers must
    /// discard it on idle, Combat entry, or any camera-ownership transition.
    /// The movement vector is identical to [`MovementIntent::resolve`].
    pub fn resolve_stateful(
        self,
        actual_actor_yaw: f32,
        previous_sector: Option<LocomotionSector>,
    ) -> MovementResolution {
        if !self.valid || !actual_actor_yaw.is_finite() {
            return MovementResolution {
                output: MovementOutput {
                    vector: self.native,
                    flags: self.flags,
                    movement_heading: None,
                },
                locomotion_sector: None,
            };
        }

        if self.native.horizontal_length() <= f32::EPSILON {
            return MovementResolution {
                output: MovementOutput {
                    vector: self.native,
                    flags: self.flags,
                    movement_heading: None,
                },
                locomotion_sector: None,
            };
        }

        // FNV later applies E(actual_actor_yaw). Applying
        // E(view_yaw - actual_actor_yaw) here makes their composition exactly
        // E(view_yaw), including when the setter normalized or rejected the
        // requested facing angle.
        let angle = self.view_yaw - actual_actor_yaw;
        let (sin_angle, cos_angle) = angle.sin_cos();
        let vector = Vec3::new(
            cos_angle.mul_add(self.native.x, sin_angle * self.native.y),
            (-sin_angle).mul_add(self.native.x, cos_angle * self.native.y),
            self.native.z,
        );
        let locomotion_sector = match self.policy {
            FacingPolicy::Explore => self.movement_heading.map(|heading| {
                LocomotionSector::select(wrap_angle(heading - actual_actor_yaw), previous_sector)
            }),
            FacingPolicy::Combat => None,
        };
        let low = locomotion_sector
            .map(LocomotionSector::direction_bits)
            .unwrap_or(self.flags & DIRECTION_MASK);
        MovementResolution {
            output: MovementOutput {
                vector,
                flags: (self.flags & !DIRECTION_MASK) | low,
                movement_heading: self.movement_heading,
            },
            locomotion_sector,
        }
    }
}

/// Stateful Explore locomotion result paired with its next animation sector.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MovementResolution {
    output: MovementOutput,
    locomotion_sector: Option<LocomotionSector>,
}

impl MovementResolution {
    /// Return the camera-relative request to pass to FNV.
    pub const fn output(self) -> MovementOutput {
        self.output
    }

    /// Return the sector to retain for the next Explore movement sample.
    pub const fn locomotion_sector(self) -> Option<LocomotionSector> {
        self.locomotion_sector
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

    /// Return movement flags with only the proven low nibble remapped.
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
/// maps nonzero motion to the nearest actor-local eight-way sector; Combat
/// mode retains the original low direction nibble for forward/back/strafe
/// animation around the view.
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

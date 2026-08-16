//! Frame-rate-independent follow-camera math.
//!
//! The solver follows the player's logical transform, never an animated
//! skeleton node. Dead/soft zones shape the target, horizontal logical
//! velocity contributes bounded lookahead, and an analytic critically damped
//! spring advances the result without fixed-frame interpolation.

use core::ops::{Add, AddAssign, Mul, Sub};

use super::third_person::ThirdPersonConfig;

const MAX_STEP_SECONDS: f32 = 0.1;
const TELEPORT_DISTANCE: f32 = 512.0;
const VELOCITY_FILTER_RATE: f32 = 8.0;

/// Three-component FNV vector used for world positions and local directions.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C)]
pub struct Vec3 {
    /// X component.
    pub x: f32,
    /// Y component.
    pub y: f32,
    /// Z component.
    pub z: f32,
}

impl Vec3 {
    /// Construct a vector from three components.
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }

    /// Return whether every component is finite.
    pub fn is_finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }

    /// Return the squared Euclidean length.
    pub fn length_squared(self) -> f32 {
        self.x
            .mul_add(self.x, self.y.mul_add(self.y, self.z * self.z))
    }

    /// Return the Euclidean length.
    pub fn length(self) -> f32 {
        self.length_squared().sqrt()
    }

    /// Return a normalized vector, or zero when no finite direction exists.
    pub fn normalized(self) -> Self {
        let length = self.length();
        if length.is_finite() && length > f32::EPSILON {
            self * length.recip()
        } else {
            Self::default()
        }
    }

    /// Return horizontal length in FNV's X/Y plane.
    pub fn horizontal_length(self) -> f32 {
        self.x.hypot(self.y)
    }
}

impl Add for Vec3 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.x + rhs.x, self.y + rhs.y, self.z + rhs.z)
    }
}

impl AddAssign for Vec3 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Vec3 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::new(self.x - rhs.x, self.y - rhs.y, self.z - rhs.z)
    }
}

impl Mul<f32> for Vec3 {
    type Output = Self;

    fn mul(self, rhs: f32) -> Self::Output {
        Self::new(self.x * rhs, self.y * rhs, self.z * rhs)
    }
}

/// One analytic critically damped spring axis.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SpringAxis {
    position: f32,
    velocity: f32,
}

impl SpringAxis {
    /// Construct a spring at rest at `position`.
    pub const fn at(position: f32) -> Self {
        Self {
            position,
            velocity: 0.0,
        }
    }

    /// Return the current position.
    pub const fn position(self) -> f32 {
        self.position
    }

    /// Return the current velocity in units per second.
    pub const fn velocity(self) -> f32 {
        self.velocity
    }

    /// Reset position and discard temporal velocity.
    pub fn reset(&mut self, position: f32) {
        self.position = position;
        self.velocity = 0.0;
    }

    /// Advance exactly over `dt` seconds at decay rate `rate`.
    ///
    /// Invalid values reset to the finite target. This function does not
    /// integrate in fixed substeps, so equivalent time partitions produce the
    /// same analytic solution within floating-point roundoff.
    pub fn advance(&mut self, target: f32, rate: f32, dt: f32) {
        if !target.is_finite()
            || !rate.is_finite()
            || !dt.is_finite()
            || rate <= 0.0
            || dt < 0.0
            || !self.position.is_finite()
            || !self.velocity.is_finite()
        {
            self.reset(if target.is_finite() { target } else { 0.0 });
            return;
        }
        if dt == 0.0 {
            return;
        }

        let error = self.position - target;
        let c = self.velocity + rate * error;
        let decay = (-rate * dt).exp();
        self.position = target + (error + c * dt) * decay;
        self.velocity = (self.velocity - rate * c * dt) * decay;
    }
}

/// Fixed-size follow target and spring state for one ownership epoch.
#[derive(Clone, Copy, Debug)]
pub struct FollowSolver {
    target: Vec3,
    position: Vec3,
    velocity: Vec3,
    filtered_velocity: Vec3,
    last_pivot: Vec3,
    initialized: bool,
}

impl FollowSolver {
    /// Construct an uninitialized solver.
    pub const fn new() -> Self {
        Self {
            target: Vec3::new(0.0, 0.0, 0.0),
            position: Vec3::new(0.0, 0.0, 0.0),
            velocity: Vec3::new(0.0, 0.0, 0.0),
            filtered_velocity: Vec3::new(0.0, 0.0, 0.0),
            last_pivot: Vec3::new(0.0, 0.0, 0.0),
            initialized: false,
        }
    }

    /// Return the current smoothed follow point.
    pub const fn position(self) -> Vec3 {
        self.position
    }

    /// Seed every temporal value from one native logical pivot.
    pub fn reset(&mut self, pivot: Vec3) {
        let pivot = if pivot.is_finite() {
            pivot
        } else {
            Vec3::default()
        };
        self.target = pivot;
        self.position = pivot;
        self.velocity = Vec3::default();
        self.filtered_velocity = Vec3::default();
        self.last_pivot = pivot;
        self.initialized = true;
    }

    /// Advance the follow point from one logical player pivot.
    ///
    /// `view_yaw` is the camera's logical horizontal heading in radians.
    /// Invalid, paused, or teleport-sized input resets immediately so stale
    /// spring energy cannot cross an ownership or world discontinuity.
    pub fn advance(
        &mut self,
        pivot: Vec3,
        view_yaw: f32,
        dt: f32,
        config: ThirdPersonConfig,
    ) -> Vec3 {
        if !self.initialized
            || !pivot.is_finite()
            || !view_yaw.is_finite()
            || !dt.is_finite()
            || dt <= 0.0
            || dt > MAX_STEP_SECONDS
            || (pivot - self.last_pivot).length() > TELEPORT_DISTANCE
        {
            self.reset(pivot);
            return self.position;
        }

        let instantaneous_velocity = (pivot - self.last_pivot) * dt.recip();
        self.last_pivot = pivot;
        let filter_alpha = 1.0 - (-VELOCITY_FILTER_RATE * dt).exp();
        self.filtered_velocity += (instantaneous_velocity - self.filtered_velocity) * filter_alpha;
        self.filtered_velocity.z = 0.0;

        let (sin_yaw, cos_yaw) = view_yaw.sin_cos();
        let right = Vec3::new(cos_yaw, -sin_yaw, 0.0);
        let forward = Vec3::new(sin_yaw, cos_yaw, 0.0);
        let displacement = pivot - self.target;
        let local_right = displacement.x * right.x + displacement.y * right.y;
        let local_depth = displacement.x * forward.x + displacement.y * forward.y;
        let horizontal_zone = config.soft_zone();
        let vertical_zone = horizontal_zone * 1.5;
        self.target += right * zone_correction(local_right, horizontal_zone);
        self.target += forward * zone_correction(local_depth, horizontal_zone);
        self.target.z += zone_correction(displacement.z, vertical_zone);

        let horizontal_velocity =
            Vec3::new(self.filtered_velocity.x, self.filtered_velocity.y, 0.0);
        let speed = horizontal_velocity.horizontal_length();
        let lookahead_distance = (speed * 0.08).min(config.look_ahead());
        let desired = self.target + horizontal_velocity.normalized() * lookahead_distance;

        let horizontal_rate = config.follow_speed();
        self.position.x = spring_step(
            self.position.x,
            &mut self.velocity.x,
            desired.x,
            horizontal_rate,
            dt,
        );
        self.position.y = spring_step(
            self.position.y,
            &mut self.velocity.y,
            desired.y,
            horizontal_rate,
            dt,
        );
        self.position.z = spring_step(
            self.position.z,
            &mut self.velocity.z,
            desired.z,
            horizontal_rate * 0.8,
            dt,
        );
        self.position
    }
}

impl Default for FollowSolver {
    fn default() -> Self {
        Self::new()
    }
}

fn zone_correction(value: f32, soft_radius: f32) -> f32 {
    if soft_radius <= f32::EPSILON {
        return value;
    }
    let dead_radius = soft_radius * 0.35;
    let magnitude = value.abs();
    if magnitude <= dead_radius {
        return 0.0;
    }
    let sign = value.signum();
    if magnitude >= soft_radius {
        return value - sign * soft_radius;
    }
    let t = (magnitude - dead_radius) / (soft_radius - dead_radius);
    let smooth = t * t * (3.0 - 2.0 * t);
    sign * (magnitude - dead_radius) * smooth
}

fn spring_step(position: f32, velocity: &mut f32, target: f32, rate: f32, dt: f32) -> f32 {
    let error = position - target;
    let c = *velocity + rate * error;
    let decay = (-rate * dt).exp();
    *velocity = (*velocity - rate * c * dt) * decay;
    target + (error + c * dt) * decay
}

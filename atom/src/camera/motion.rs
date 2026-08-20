//! Frame-rate-independent first-person motion synthesis.
//!
//! The generator consumes engine time, support-relative velocity, native
//! locomotion state and movement admission, logical look deltas, aiming state,
//! and pointer-free player-shot events. It never reads devices or engine memory
//! itself. Distance advances gait phase only while the native mover has
//! directional locomotion; analytic damping controls envelopes, cadence, and
//! viewmodel inertia; landing is a one-shot air-to-ground event, while ranged
//! fire produces one bounded pitch response. Cadence is analytically filtered
//! and capped before it reaches one smooth footfall waveform. A conservative
//! translation plus sub-degree render rotation forms the world-camera head
//! layer. FNV's native first-person graph remains the sole owner of locomotion
//! cadence for the close-up hands/weapon projection; Atom adds only a
//! non-oscillating movement-weight offset and bounded look inertia there.
//! Authored actions own that relative layer exclusively. Every result is
//! zero-centered and bounded before it can reach a native transform.

use core::f32::consts::PI;
use core::f64::consts::TAU;

use super::{CameraPose, FirstPersonConfig};

const MAX_STEP_SECONDS: f32 = 0.100;
const CAMERA_CUT_RADIANS: f32 = PI / 3.0;
const GAIT_START_RATE: f32 = 10.0;
const GAIT_STOP_RATE: f32 = 7.0;
const GAIT_CADENCE_FILTER_RATE: f32 = 10.0;
const MAX_FULL_STRIDE_HZ: f32 = 1.6;
const AIM_BLEND_RATE: f32 = 14.0;
const ANIMATION_RELEASE_RATE: f32 = 12.0;
const INERTIA_FREQUENCY: f32 = 17.0;
const LOOK_RATE_DEAD_ZONE: f32 = 0.015;
const MAX_YAW_INERTIA: f32 = 0.012;
const MAX_PITCH_INERTIA: f32 = 0.009;
const LANDING_DEAD_ZONE: f32 = 120.0;
const LANDING_SATURATION: f32 = 620.0;
const ENVELOPE_SETTLE_EPSILON: f32 = 1.0e-5;
const SPRING_SETTLE_EPSILON: f32 = 1.0e-6;
const HEAD_GAIT_ROLL_RADIANS: f32 = 0.0065;
const HEAD_GAIT_PITCH_RADIANS: f32 = 0.0045;
const HEAD_IMPULSE_PITCH_RADIANS: f32 = 0.0050;
const MAX_HEAD_PITCH_RADIANS: f32 = 0.0080;
const IMPULSE_SETTLE_RATE: f32 = 9.0;

/// Bounded world and relative-viewmodel bases for one accepted update.
///
/// The public composite accessor preserves the logical head-plus-weapon pose
/// used by pure motion consumers. The frame publisher applies only the
/// relative pose to FNV's separately projected close-up weapon camera; copying
/// the world head layer there visibly amplifies it through viewmodel parallax.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GeneratedMotion {
    world_pose: CameraPose,
    relative_viewmodel_pose: CameraPose,
    head_rotation: [f32; 3],
}

impl GeneratedMotion {
    /// An exact identity result which performs no camera write.
    pub const IDENTITY: Self = Self {
        world_pose: CameraPose::IDENTITY,
        relative_viewmodel_pose: CameraPose::IDENTITY,
        head_rotation: [0.0; 3],
    };

    /// Return the additive world-camera translation base.
    pub const fn world_pose(self) -> CameraPose {
        self.world_pose
    }

    /// Return logical head translation plus additive hands/weapon motion.
    pub const fn viewmodel_pose(self) -> CameraPose {
        let common = self.world_pose.translation();
        let relative = self.relative_viewmodel_pose.translation();
        CameraPose::new(
            [
                common[0] + relative[0],
                common[1] + relative[1],
                common[2] + relative[2],
            ],
            self.relative_viewmodel_pose.rotation(),
        )
    }

    /// Return only motion Atom may add to the close-up weapon projection.
    pub(super) const fn relative_viewmodel_pose(self) -> CameraPose {
        self.relative_viewmodel_pose
    }

    /// Return world render-only `[roll, yaw, pitch]` head rotation.
    ///
    /// The frame publisher composes this onto the world pose only. Keeping it
    /// separate mirrors third-person motion's render layer and prevents the
    /// close-up weapon projection from magnifying it.
    pub(super) const fn head_rotation(self) -> [f32; 3] {
        self.head_rotation
    }
}

/// Native character-controller locomotion classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LocomotionState {
    /// The controller is supported by walkable ground.
    #[default]
    Grounded,
    /// The controller is in its jump transition.
    Jumping,
    /// The controller is unsupported and falling or rising.
    Airborne,
    /// The native state is not suitable for first-person gait.
    Unsupported,
}

/// One immutable input to the first-person motion generator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MotionInput {
    delta_seconds: f32,
    relative_velocity: [f32; 3],
    locomotion: LocomotionState,
    directional_locomotion: bool,
    look_delta: [f32; 2],
    aiming: bool,
    authored_animation: bool,
}

impl MotionInput {
    /// Construct a motion sample.
    ///
    /// Velocity is the controller's support-relative world velocity in game
    /// units per second. `directional_locomotion` reports whether the native
    /// player mover committed a forward, backward, or strafe direction; it is
    /// a gait-admission signal, not a substitute for velocity. Look delta is
    /// `[yaw, pitch]` in radians for this update, after Atom Input and native
    /// heading processing. `aiming` controls precision attenuation;
    /// `authored_animation` grants native animation exclusive ownership of
    /// motion relative to the world presentation.
    pub const fn new(
        delta_seconds: f32,
        relative_velocity: [f32; 3],
        locomotion: LocomotionState,
        directional_locomotion: bool,
        look_delta: [f32; 2],
        aiming: bool,
        authored_animation: bool,
    ) -> Self {
        Self {
            delta_seconds,
            relative_velocity,
            locomotion,
            directional_locomotion,
            look_delta,
            aiming,
            authored_animation,
        }
    }

    /// Return the engine-time step in seconds.
    pub const fn delta_seconds(self) -> f32 {
        self.delta_seconds
    }

    /// Return support-relative world velocity in game units per second.
    pub const fn relative_velocity(self) -> [f32; 3] {
        self.relative_velocity
    }

    /// Return the native locomotion state.
    pub const fn locomotion(self) -> LocomotionState {
        self.locomotion
    }

    /// Return whether native directional locomotion admits gait motion.
    pub const fn directional_locomotion(self) -> bool {
        self.directional_locomotion
    }

    /// Return `[yaw, pitch]` logical look delta in radians.
    pub const fn look_delta(self) -> [f32; 2] {
        self.look_delta
    }

    /// Return whether the native process reports aiming.
    pub const fn aiming(self) -> bool {
        self.aiming
    }

    /// Return whether an authored weapon animation should own presentation.
    pub const fn authored_animation(self) -> bool {
        self.authored_animation
    }

    fn finite(self) -> bool {
        self.delta_seconds.is_finite()
            && self.relative_velocity.into_iter().all(f32::is_finite)
            && self.look_delta.into_iter().all(f32::is_finite)
    }
}

/// Stateful, allocation-free first-person motion generator.
///
/// One instance must be advanced at most once per accepted player update.
/// Render listeners consume its published [`GeneratedMotion`] and never
/// advance it.
#[derive(Clone, Copy, Debug)]
pub struct MotionGenerator {
    gait_phase: f64,
    gait_frequency: f32,
    gait_envelope: f32,
    aim_weight: f32,
    animation_weight: f32,
    yaw_inertia: CriticalSpring,
    pitch_inertia: CriticalSpring,
    was_airborne: bool,
    minimum_air_velocity: f32,
    landing_amplitude: f32,
    landing_age: f32,
    shot_amplitude: f32,
    shot_age: f32,
}

impl MotionGenerator {
    /// Construct a neutral generator with no temporal history.
    pub const fn new() -> Self {
        Self {
            gait_phase: 0.0,
            gait_frequency: 0.0,
            gait_envelope: 0.0,
            aim_weight: 0.0,
            animation_weight: 0.0,
            yaw_inertia: CriticalSpring::new(),
            pitch_inertia: CriticalSpring::new(),
            was_airborne: false,
            minimum_air_velocity: 0.0,
            landing_amplitude: 0.0,
            landing_age: 0.0,
            shot_amplitude: 0.0,
            shot_age: 0.0,
        }
    }

    /// Clear gait, landing, shot, aiming, and look-inertia history.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Start one bounded camera-only response to an authoritative player shot.
    ///
    /// A new event replaces any unfinished response instead of accumulating,
    /// so high-rate fire cannot grow the camera offset without limit. Native
    /// weapon animation, logical aim, and projectile behavior remain separate.
    pub(crate) fn trigger_shot_impulse(&mut self) {
        self.shot_amplitude = 1.0;
        self.shot_age = 0.0;
    }

    /// Advance one native update and return both bounded presentation poses.
    ///
    /// Invalid time, non-finite input, unsupported locomotion, or a disabled
    /// configuration resets temporal state and returns exact identity.
    pub fn update(&mut self, input: MotionInput, config: FirstPersonConfig) -> GeneratedMotion {
        if !config.enabled()
            || (config.camera_motion() == 0.0 && config.weapon_motion() == 0.0)
            || !input.finite()
            || input.delta_seconds <= 0.0
            || input.delta_seconds > MAX_STEP_SECONDS
            || input.locomotion == LocomotionState::Unsupported
        {
            self.reset();
            return GeneratedMotion::IDENTITY;
        }

        let dt = input.delta_seconds;
        let speed = input.relative_velocity[0].hypot(input.relative_velocity[1]);
        let grounded = input.locomotion == LocomotionState::Grounded;
        let gait_admitted = grounded && input.directional_locomotion;
        let gait_target = if gait_admitted {
            smooth01((speed - 4.0) / 90.0)
        } else {
            0.0
        };
        let gait_rate = if gait_target > self.gait_envelope {
            GAIT_START_RATE
        } else {
            GAIT_STOP_RATE
        };
        self.gait_envelope = approach_exponential(self.gait_envelope, gait_target, gait_rate, dt);

        let frequency_target = if gait_admitted && speed > 4.0 {
            // A continuously interpolated stride avoids cadence jumps at an
            // arbitrary walk/run threshold while preserving distance phase.
            // Extreme SpeedMult values and physics spikes are capped at a
            // comfort-safe presentation cadence instead of turning the camera
            // waveform into high-frequency shake.
            let stride_mix = smooth01((speed - 55.0) / 170.0);
            let stride_length = 92.0 + (158.0 - 92.0) * stride_mix;
            (speed / stride_length).min(MAX_FULL_STRIDE_HZ)
        } else {
            0.0
        };
        // Contact resolution can perturb instantaneous controller velocity.
        // Filter the derived cadence rather than phase itself, and integrate
        // the exponential analytically so equal elapsed time produces the
        // same phase at 30, 60, 120, or irregular update partitions.
        let (frequency, stride_cycles) = approach_exponential_integrated(
            self.gait_frequency,
            frequency_target,
            GAIT_CADENCE_FILTER_RATE,
            dt,
        );
        self.gait_frequency = frequency;
        if gait_admitted {
            self.gait_phase = (self.gait_phase + TAU * f64::from(stride_cycles.max(0.0))) % TAU;
        }

        self.update_landing(input.locomotion, input.relative_velocity[2], dt);
        self.update_shot(dt);
        let precision_target = f32::from(input.aiming);
        self.aim_weight =
            approach_exponential(self.aim_weight, precision_target, AIM_BLEND_RATE, dt);
        // Entry is immediate because even one procedurally offset frame can
        // visibly fight recoil, equip, or reload animation. Release is eased
        // so the secondary weapon layer cannot pop back at an authored clip's
        // terminal frame. The common head layer remains independent.
        self.animation_weight = if input.authored_animation {
            1.0
        } else {
            approach_exponential(self.animation_weight, 0.0, ANIMATION_RELEASE_RATE, dt)
        };

        let [yaw_delta, pitch_delta] = input.look_delta;
        let camera_cut =
            yaw_delta.abs() > CAMERA_CUT_RADIANS || pitch_delta.abs() > CAMERA_CUT_RADIANS;
        let (yaw_target, pitch_target) = if input.authored_animation || camera_cut {
            self.yaw_inertia.reset();
            self.pitch_inertia.reset();
            (0.0, 0.0)
        } else {
            let yaw_rate = dead_zone(yaw_delta / dt, LOOK_RATE_DEAD_ZONE);
            let pitch_rate = dead_zone(pitch_delta / dt, LOOK_RATE_DEAD_ZONE);
            (
                (-yaw_rate * 0.018).clamp(-MAX_YAW_INERTIA, MAX_YAW_INERTIA),
                (-pitch_rate * 0.014).clamp(-MAX_PITCH_INERTIA, MAX_PITCH_INERTIA),
            )
        };
        self.yaw_inertia.advance(yaw_target, INERTIA_FREQUENCY, dt);
        self.pitch_inertia
            .advance(pitch_target, INERTIA_FREQUENCY, dt);

        let phase = self.gait_phase as f32;
        let side = phase.sin();
        // One smooth vertical event per footfall is sufficient. The previous
        // fourth harmonic amplified a normal sprint into visible rapid shake
        // even though each individual offset remained numerically small.
        let vertical = (2.0 * phase - PI * 0.5).sin();
        // Squaring the analytic envelope keeps slow movement restrained while
        // preserving full-scale running motion and the exact zero boundary.
        // Cadence still follows distance, so this changes weight, not timing.
        let gait = self.gait_envelope * self.gait_envelope;
        let landing =
            landing_curve(self.landing_amplitude, self.landing_age) * config.landing_motion();
        // A shot begins at its peak and reuses landing's analytic recovery
        // rate. Restarting this monotonic envelope can only restore the bounded
        // peak; it cannot drop the current response or accumulate random shake.
        let shot = shot_curve(self.shot_amplitude, self.shot_age);

        // The native collision helper is a stateful chase-camera transaction,
        // not a reusable first-person clearance query. Positional head motion
        // therefore stays well below one game unit and fore/aft movement
        // remains viewmodel-only. A sub-degree roll/pitch layer supplies the
        // perceptible world motion without adding near-wall translation. It is
        // composed only for world rendering. Applying that same transform to
        // the separately projected close-up weapon camera magnifies its screen
        // displacement, while FNV's weapon graph already supplies locomotion.
        // Aiming removes the world offset immediately; leaving it fades back
        // through the analytic aim envelope. Weapon animation does not remove
        // locomotion from the player's head. Native animation alone owns the
        // weapon's movement relative to that scene motion.
        let world_gain = if input.aiming {
            0.0
        } else {
            config.camera_motion() * (1.0 - self.aim_weight)
        };
        let shot_precision_gain = if input.aiming {
            config.aim_motion()
        } else {
            1.0 + (config.aim_motion() - 1.0) * self.aim_weight
        };
        let shot_gain = config.camera_motion() * shot_precision_gain;
        let world_translation = [
            0.0,
            (vertical * 0.24 * gait + landing * 0.22) * world_gain,
            side * 0.08 * gait * world_gain,
        ];
        let world_rotation = [0.0; 3];
        let head_rotation = [
            -side * HEAD_GAIT_ROLL_RADIANS * gait * world_gain,
            0.0,
            (vertical * HEAD_GAIT_PITCH_RADIANS * gait + landing * HEAD_IMPULSE_PITCH_RADIANS)
                * world_gain
                + shot * HEAD_IMPULSE_PITCH_RADIANS * shot_gain,
        ];

        let Some(world_pose) = bounded_world_pose(world_translation, world_rotation) else {
            self.reset();
            return GeneratedMotion::IDENTITY;
        };
        let Some(head_rotation) = bounded_head_rotation(head_rotation) else {
            self.reset();
            return GeneratedMotion::IDENTITY;
        };

        let viewmodel_precision_gain = 1.0 + (config.aim_motion() - 1.0) * self.aim_weight;
        let viewmodel_gain =
            config.weapon_motion() * viewmodel_precision_gain * (1.0 - self.animation_weight);
        let viewmodel_translation = [
            // Preserve controllable weapon weight without another footstep
            // waveform. This follows only the analytic movement envelope, so
            // it eases once on start/stop instead of oscillating.
            -0.015 * gait * viewmodel_gain,
            0.0,
            self.yaw_inertia.position * 24.0 * viewmodel_gain,
        ];
        let viewmodel_rotation = [
            -self.yaw_inertia.velocity * 0.000_08 * viewmodel_gain,
            self.yaw_inertia.position * viewmodel_gain,
            self.pitch_inertia.position * viewmodel_gain,
        ];
        let Some(relative_viewmodel_pose) =
            bounded_viewmodel_pose(viewmodel_translation, viewmodel_rotation)
        else {
            self.reset();
            return GeneratedMotion::IDENTITY;
        };
        GeneratedMotion {
            world_pose,
            relative_viewmodel_pose,
            head_rotation,
        }
    }

    /// Return the current wrapped full-stride phase in radians.
    pub fn gait_phase(&self) -> f64 {
        self.gait_phase
    }

    fn update_landing(&mut self, state: LocomotionState, vertical_velocity: f32, dt: f32) {
        let airborne = matches!(state, LocomotionState::Jumping | LocomotionState::Airborne);
        if airborne {
            if !self.was_airborne {
                self.minimum_air_velocity = vertical_velocity.min(0.0);
            } else {
                self.minimum_air_velocity = self.minimum_air_velocity.min(vertical_velocity);
            }
        } else if self.was_airborne {
            let downward_speed = -self.minimum_air_velocity;
            let strength = smooth01(
                (downward_speed - LANDING_DEAD_ZONE) / (LANDING_SATURATION - LANDING_DEAD_ZONE),
            );
            if strength > 0.0 {
                self.landing_amplitude = self.landing_amplitude.max(strength);
                self.landing_age = 0.0;
            }
            self.minimum_air_velocity = 0.0;
        }
        self.was_airborne = airborne;
        if self.landing_amplitude > 0.0 {
            self.landing_age += dt;
            if self.landing_age >= 0.8 {
                self.landing_amplitude = 0.0;
                self.landing_age = 0.0;
            }
        }
    }

    fn update_shot(&mut self, dt: f32) {
        if self.shot_amplitude > 0.0 {
            self.shot_age += dt;
            if self.shot_age >= 0.8 {
                self.shot_amplitude = 0.0;
                self.shot_age = 0.0;
            }
        }
    }
}

impl Default for MotionGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
struct CriticalSpring {
    position: f32,
    velocity: f32,
}

impl CriticalSpring {
    const fn new() -> Self {
        Self {
            position: 0.0,
            velocity: 0.0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn advance(&mut self, target: f32, frequency: f32, dt: f32) {
        let error = self.position - target;
        let coefficient = self.velocity + frequency * error;
        let decay = (-frequency * dt).exp();
        self.position = target + (error + coefficient * dt) * decay;
        self.velocity = (self.velocity - frequency * coefficient * dt) * decay;
        if (self.position - target).abs() <= SPRING_SETTLE_EPSILON
            && self.velocity.abs() <= SPRING_SETTLE_EPSILON
        {
            self.position = target;
            self.velocity = 0.0;
        }
    }
}

fn approach_exponential(current: f32, target: f32, rate: f32, dt: f32) -> f32 {
    let next = target + (current - target) * (-rate * dt).exp();
    if (next - target).abs() <= ENVELOPE_SETTLE_EPSILON {
        target
    } else {
        next
    }
}

fn approach_exponential_integrated(current: f32, target: f32, rate: f32, dt: f32) -> (f32, f32) {
    let decay = (-rate * dt).exp();
    let next = target + (current - target) * decay;
    let integral = target * dt + (current - target) * (1.0 - decay) / rate;
    let settled = if (next - target).abs() <= ENVELOPE_SETTLE_EPSILON {
        target
    } else {
        next
    };
    (settled, integral)
}

fn dead_zone(value: f32, threshold: f32) -> f32 {
    if value.abs() <= threshold { 0.0 } else { value }
}

fn smooth01(value: f32) -> f32 {
    let value = value.clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn landing_curve(amplitude: f32, age: f32) -> f32 {
    // The difference of decays begins at zero, compresses once, and returns
    // monotonically from its single trough without an oscillatory bounce.
    -amplitude * 1.55 * ((-IMPULSE_SETTLE_RATE * age).exp() - (-32.0 * age).exp())
}

fn shot_curve(amplitude: f32, age: f32) -> f32 {
    amplitude * (-IMPULSE_SETTLE_RATE * age).exp()
}

fn bounded_world_pose(translation: [f32; 3], rotation: [f32; 3]) -> Option<CameraPose> {
    if !translation.into_iter().chain(rotation).all(f32::is_finite) {
        return None;
    }
    Some(CameraPose::new(
        [
            translation[0].clamp(-0.10, 0.10),
            translation[1].clamp(-0.50, 0.50),
            translation[2].clamp(-0.15, 0.15),
        ],
        [rotation[0].clamp(-0.006, 0.006), 0.0, 0.0],
    ))
}

fn bounded_head_rotation(rotation: [f32; 3]) -> Option<[f32; 3]> {
    rotation.into_iter().all(f32::is_finite).then(|| {
        [
            rotation[0].clamp(-HEAD_GAIT_ROLL_RADIANS, HEAD_GAIT_ROLL_RADIANS),
            0.0,
            rotation[2].clamp(-MAX_HEAD_PITCH_RADIANS, MAX_HEAD_PITCH_RADIANS),
        ]
    })
}

fn bounded_viewmodel_pose(translation: [f32; 3], rotation: [f32; 3]) -> Option<CameraPose> {
    if !translation.into_iter().chain(rotation).all(f32::is_finite) {
        return None;
    }
    Some(CameraPose::new(
        [
            translation[0].clamp(-0.75, 0.75),
            translation[1].clamp(-1.25, 1.25),
            translation[2].clamp(-0.90, 0.90),
        ],
        [
            rotation[0].clamp(-0.006, 0.006),
            rotation[1].clamp(-MAX_YAW_INERTIA, MAX_YAW_INERTIA),
            rotation[2].clamp(-0.012, 0.012),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::{CriticalSpring, HEAD_IMPULSE_PITCH_RADIANS, landing_curve, shot_curve};
    use crate::camera::{FirstPersonConfig, LocomotionState, MotionGenerator, MotionInput};

    #[test]
    fn critical_spring_is_frame_partition_invariant() {
        let mut one = CriticalSpring::new();
        one.advance(1.0, 12.0, 1.0 / 30.0);

        let mut two = CriticalSpring::new();
        two.advance(1.0, 12.0, 1.0 / 60.0);
        two.advance(1.0, 12.0, 1.0 / 60.0);

        assert!((one.position - two.position).abs() < 1.0e-6);
        assert!((one.velocity - two.velocity).abs() < 1.0e-5);
    }

    #[test]
    fn landing_response_has_one_compression_and_returns_toward_zero() {
        let values = [0.0, 0.03, 0.06, 0.12, 0.24, 0.48].map(|age| landing_curve(1.0, age));
        assert_eq!(values[0], 0.0);
        assert!(values[1] < 0.0);
        let minimum = values
            .iter()
            .enumerate()
            .min_by(|left, right| left.1.total_cmp(right.1))
            .map(|(index, _)| index)
            .expect("landing samples");
        assert!(minimum > 0 && minimum < values.len() - 1);
        assert!(values[minimum..].windows(2).all(|pair| pair[1] >= pair[0]));
    }

    #[test]
    fn shot_response_has_one_peak_and_returns_monotonically() {
        let values = [0.0, 0.03, 0.06, 0.12, 0.24, 0.48].map(|age| shot_curve(1.0, age));
        assert_eq!(values[0], 1.0);
        assert!(values.windows(2).all(|pair| pair[1] < pair[0]));
    }

    #[test]
    fn shot_impulse_survives_authored_recoil_is_bounded_and_settles() {
        let config = FirstPersonConfig::from_ini(
            "[FirstPerson]\nbEnabled=1\nfCameraMotion=1\nfWeaponMotion=1\nfAimMotion=0.25\n",
        )
        .expect("valid first-person test config");
        let authored = MotionInput::new(
            1.0 / 60.0,
            [0.0; 3],
            LocomotionState::Grounded,
            false,
            [0.0; 2],
            false,
            true,
        );
        let mut generator = MotionGenerator::new();
        generator.trigger_shot_impulse();
        let fired = generator.update(authored, config);
        assert!(fired.head_rotation()[2] > 0.0);
        assert!(fired.head_rotation()[2] <= HEAD_IMPULSE_PITCH_RADIANS);
        assert!(fired.relative_viewmodel_pose().is_identity());

        let mut settled = fired;
        for _ in 0..60 {
            settled = generator.update(authored, config);
        }
        assert_eq!(settled.head_rotation(), [0.0; 3]);
        assert!(settled.relative_viewmodel_pose().is_identity());
    }

    #[test]
    fn aiming_attenuates_the_shot_listener_without_changing_native_weapon_ownership() {
        let config = FirstPersonConfig::from_ini(
            "[FirstPerson]\nbEnabled=1\nfCameraMotion=1\nfWeaponMotion=1\nfAimMotion=0.25\n",
        )
        .expect("valid first-person test config");
        let sample = |aiming| {
            MotionInput::new(
                1.0 / 60.0,
                [0.0; 3],
                LocomotionState::Grounded,
                false,
                [0.0; 2],
                aiming,
                true,
            )
        };
        let mut hip = MotionGenerator::new();
        hip.trigger_shot_impulse();
        let hip_kick = hip.update(sample(false), config).head_rotation()[2];
        let mut aim = MotionGenerator::new();
        aim.trigger_shot_impulse();
        let aim_kick = aim.update(sample(true), config).head_rotation()[2];

        assert!((aim_kick / hip_kick - config.aim_motion()).abs() < 1.0e-6);
    }

    #[test]
    fn repeated_shots_saturate_and_zero_camera_gain_is_exact_pass_through() {
        let enabled = FirstPersonConfig::from_ini(
            "[FirstPerson]\nbEnabled=1\nfCameraMotion=1\nfWeaponMotion=1\n",
        )
        .expect("valid first-person test config");
        let camera_off = FirstPersonConfig::from_ini(
            "[FirstPerson]\nbEnabled=1\nfCameraMotion=0\nfWeaponMotion=1\n",
        )
        .expect("valid first-person test config");
        let authored = MotionInput::new(
            1.0 / 60.0,
            [0.0; 3],
            LocomotionState::Grounded,
            false,
            [0.0; 2],
            false,
            true,
        );
        let mut burst = MotionGenerator::new();
        burst.trigger_shot_impulse();
        let first = burst.update(authored, enabled).head_rotation()[2];
        let decayed = burst.update(authored, enabled).head_rotation()[2];
        assert!(decayed < first);
        burst.trigger_shot_impulse();
        let restarted = burst.update(authored, enabled).head_rotation()[2];
        assert!(restarted > decayed);
        for _ in 0..120 {
            burst.trigger_shot_impulse();
            let kick = burst.update(authored, enabled).head_rotation()[2];
            assert!(kick > 0.0 && kick <= HEAD_IMPULSE_PITCH_RADIANS);
        }

        let mut disabled = MotionGenerator::new();
        disabled.trigger_shot_impulse();
        let passthrough = disabled.update(authored, camera_off);
        assert_eq!(passthrough.head_rotation(), [0.0; 3]);
        assert!(passthrough.relative_viewmodel_pose().is_identity());
    }
}

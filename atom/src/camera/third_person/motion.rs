//! Deterministic third-person locomotion presentation.
//!
//! The generator derives cadence from support-relative horizontal velocity,
//! integrates phase by travelled distance, and applies analytic attack,
//! release, and landing envelopes. It owns no engine pointer and performs no
//! allocation, synchronization, or diagnostics. Output is restrained
//! translation along camera-right, camera-forward, and world-up plus a
//! sub-degree render-only roll/pitch signal. Effective aiming attenuates both.
//! Translation is bounded and applied only after FNV completes its persistent
//! chase-distance solve, then limited by a separate short native clearance
//! cast. Rotation never changes collision geometry.

use core::f32::consts::PI;
use core::f64::consts::TAU;

use crate::camera::LocomotionState;

use super::{ThirdPersonConfig, Vec3};

const MAX_STEP_SECONDS: f32 = 0.100;
const GAIT_START_RATE: f32 = 8.0;
const GAIT_STOP_RATE: f32 = 6.0;
const CADENCE_FILTER_RATE: f32 = 9.0;
const AIM_RELEASE_RATE: f32 = 10.0;
const MAX_FULL_STRIDE_HZ: f32 = 1.5;
const LANDING_DEAD_ZONE: f32 = 120.0;
const LANDING_SATURATION: f32 = 620.0;
const ENVELOPE_EPSILON: f32 = 1.0e-5;
const GAIT_SIDE_UNITS: f32 = 1.30;
const GAIT_FORE_UNITS: f32 = 0.75;
const GAIT_VERTICAL_UNITS: f32 = 2.10;
const LANDING_VERTICAL_UNITS: f32 = 3.25;
const GAIT_ROLL_RADIANS: f32 = 0.0065;
const GAIT_PITCH_RADIANS: f32 = 0.0045;
const LANDING_PITCH_RADIANS: f32 = 0.0050;
/// Strict Euclidean bound implied by the three component clamps below.
pub(super) const MAX_TRANSLATION_LENGTH: f32 = 6.0;

/// Immutable native observations consumed by one generator step.
#[derive(Clone, Copy, Debug)]
pub(super) struct MotionInput {
    pub(super) velocity: Vec3,
    pub(super) locomotion: LocomotionState,
    pub(super) directional_locomotion: bool,
    pub(super) aiming: bool,
    pub(super) desired_distance: f32,
}

/// Allocation-free temporal state for one owned third-person camera epoch.
#[derive(Clone, Copy, Debug)]
pub(super) struct MotionGenerator {
    gait_phase: f64,
    gait_frequency: f32,
    gait_envelope: f32,
    aim_weight: f32,
    was_airborne: bool,
    minimum_air_velocity: f32,
    landing_amplitude: f32,
    landing_age: f32,
    render_rotation: Vec3,
}

impl MotionGenerator {
    /// Construct a neutral generator without gait or landing history.
    pub(super) const fn new() -> Self {
        Self {
            gait_phase: 0.0,
            gait_frequency: 0.0,
            gait_envelope: 0.0,
            aim_weight: 0.0,
            was_airborne: false,
            minimum_air_velocity: 0.0,
            landing_amplitude: 0.0,
            landing_age: 0.0,
            render_rotation: Vec3::new(0.0, 0.0, 0.0),
        }
    }

    /// Clear every temporal value at an ownership or lifecycle boundary.
    pub(super) fn reset(&mut self) {
        *self = Self::new();
    }

    /// Return render-only local roll/yaw/pitch for the latest accepted step.
    ///
    /// Translation is composed at FNV's final camera-position seam. Rotation is
    /// deferred to the complete render route so clearance cannot erase the
    /// visual gait signal and no camera endpoint is displaced twice.
    pub(super) const fn render_rotation(&self) -> Vec3 {
        self.render_rotation
    }

    /// Advance one accepted input frame and return local side/up translation.
    ///
    /// `input.velocity` is the native controller's support-relative world
    /// velocity. `input.directional_locomotion` is the committed native
    /// movement-word gate; platform and physics velocity alone must not
    /// synthesize footsteps. `input.desired_distance` scales the bounded world
    /// displacement mildly so one preset retains comparable screen-space
    /// weight across zoom levels.
    pub(super) fn update(
        &mut self,
        delta_seconds: f32,
        input: MotionInput,
        config: ThirdPersonConfig,
    ) -> Vec3 {
        if !config.motion_enabled()
            || (config.motion_strength() == 0.0 && config.landing_motion() == 0.0)
            || !delta_seconds.is_finite()
            || delta_seconds <= 0.0
            || !input.velocity.is_finite()
            || !input.desired_distance.is_finite()
            || input.desired_distance <= 0.0
            || input.locomotion == LocomotionState::Unsupported
        {
            self.reset();
            return Vec3::default();
        }

        let dt = delta_seconds.min(MAX_STEP_SECONDS);
        let speed = input.velocity.horizontal_length();
        let grounded = input.locomotion == LocomotionState::Grounded;
        let gait_target = if grounded && input.directional_locomotion {
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

        let frequency_target = if grounded && input.directional_locomotion && speed > 4.0 {
            let stride_mix = smooth01((speed - 55.0) / 170.0);
            let stride_length = 92.0 + (158.0 - 92.0) * stride_mix;
            (speed / stride_length).min(MAX_FULL_STRIDE_HZ)
        } else {
            0.0
        };
        let (frequency, stride_cycles) = approach_exponential_integrated(
            self.gait_frequency,
            frequency_target,
            CADENCE_FILTER_RATE,
            dt,
        );
        self.gait_frequency = frequency;
        if grounded && input.directional_locomotion {
            self.gait_phase = (self.gait_phase + TAU * f64::from(stride_cycles.max(0.0))) % TAU;
        }

        self.update_landing(input.locomotion, input.velocity.z, dt);
        self.aim_weight = if input.aiming {
            1.0
        } else {
            approach_exponential(self.aim_weight, 0.0, AIM_RELEASE_RATE, dt)
        };

        let phase = self.gait_phase as f32;
        let gait = self.gait_envelope * self.gait_envelope;
        let distance_scale = (input.desired_distance / 120.0).clamp(0.75, 2.0);
        let presentation_gain = config.motion_strength() * (1.0 - self.aim_weight);
        let side = phase.sin() * GAIT_SIDE_UNITS * gait * presentation_gain * distance_scale;
        let footfall = (2.0 * phase - PI * 0.5).sin();
        let fore = (2.0 * phase + 0.50).sin();
        let forward = fore * GAIT_FORE_UNITS * gait * presentation_gain * distance_scale;
        let landing = landing_curve(self.landing_amplitude, self.landing_age)
            * config.landing_motion()
            * distance_scale;
        let vertical = footfall * GAIT_VERTICAL_UNITS * gait * presentation_gain * distance_scale
            + landing * LANDING_VERTICAL_UNITS * (1.0 - self.aim_weight);
        let roll = -phase.sin() * GAIT_ROLL_RADIANS * gait * presentation_gain;
        let pitch = footfall * GAIT_PITCH_RADIANS * gait * presentation_gain
            + landing * LANDING_PITCH_RADIANS * (1.0 - self.aim_weight);

        if !side.is_finite()
            || !forward.is_finite()
            || !vertical.is_finite()
            || !roll.is_finite()
            || !pitch.is_finite()
        {
            self.reset();
            return Vec3::default();
        }
        self.render_rotation = Vec3::new(roll, 0.0, pitch);
        Vec3::new(
            side.clamp(-2.75, 2.75),
            forward.clamp(-1.75, 1.75),
            vertical.clamp(-5.0, 5.0),
        )
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
}

fn approach_exponential(current: f32, target: f32, rate: f32, dt: f32) -> f32 {
    let next = target + (current - target) * (-rate * dt).exp();
    if (next - target).abs() <= ENVELOPE_EPSILON {
        target
    } else {
        next
    }
}

fn approach_exponential_integrated(current: f32, target: f32, rate: f32, dt: f32) -> (f32, f32) {
    let decay = (-rate * dt).exp();
    let next = target + (current - target) * decay;
    let integral = target * dt + (current - target) * (1.0 - decay) / rate;
    let settled = if (next - target).abs() <= ENVELOPE_EPSILON {
        target
    } else {
        next
    };
    (settled, integral)
}

fn smooth01(value: f32) -> f32 {
    let value = value.clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn landing_curve(amplitude: f32, age: f32) -> f32 {
    -amplitude * 1.55 * ((-9.0 * age).exp() - (-32.0 * age).exp())
}

#[cfg(test)]
mod tests {
    use super::{MotionGenerator, MotionInput};
    use crate::camera::third_person::Vec3;
    use crate::camera::{LocomotionState, third_person::ThirdPersonConfig};

    const FRAME_SECONDS: f32 = 1.0 / 60.0;

    fn config() -> ThirdPersonConfig {
        ThirdPersonConfig::from_ini(
            "[Camera]\n\
             bMotion=1\n\
             fMotionStrength=0.75\n\
             fLandMotion=0.75\n",
        )
        .expect("valid motion configuration")
    }

    fn walking(aiming: bool) -> MotionInput {
        MotionInput {
            velocity: Vec3::new(0.0, 150.0, 0.0),
            locomotion: LocomotionState::Grounded,
            directional_locomotion: true,
            aiming,
            desired_distance: 170.0,
        }
    }

    #[test]
    fn configured_gait_is_visible_bounded_and_settles_smoothly() {
        let mut generator = MotionGenerator::new();
        let mut maxima = Vec3::default();
        for _ in 0..180 {
            let sample = generator.update(FRAME_SECONDS, walking(false), config());
            maxima.x = maxima.x.max(sample.x.abs());
            maxima.y = maxima.y.max(sample.y.abs());
            maxima.z = maxima.z.max(sample.z.abs());
        }

        assert!(
            maxima.x > 0.75,
            "lateral gait motion is imperceptible: {maxima:?}"
        );
        assert!(
            maxima.y > 0.35,
            "fore/aft gait motion is imperceptible: {maxima:?}"
        );
        assert!(
            maxima.z > 1.0,
            "vertical gait motion is imperceptible: {maxima:?}"
        );
        assert!(maxima.x <= 2.75 && maxima.y <= 1.75 && maxima.z <= 5.0);

        let stopped = MotionInput {
            velocity: Vec3::default(),
            locomotion: LocomotionState::Grounded,
            directional_locomotion: false,
            aiming: false,
            desired_distance: 170.0,
        };
        let first_release = generator.update(FRAME_SECONDS, stopped, config());
        assert!(
            first_release.length() > 0.0,
            "motion must ease out instead of snapping off"
        );
        let mut settled = first_release;
        for _ in 0..240 {
            settled = generator.update(FRAME_SECONDS, stopped, config());
        }
        assert!(
            settled.length() < 0.000_1,
            "stopped motion did not settle: {settled:?}"
        );
    }

    #[test]
    fn aiming_is_an_exact_identity_and_release_eases_back_in() {
        let mut generator = MotionGenerator::new();
        for _ in 0..120 {
            generator.update(FRAME_SECONDS, walking(false), config());
        }

        assert_eq!(
            generator.update(FRAME_SECONDS, walking(true), config()),
            Vec3::default(),
            "aiming must preserve native camera placement exactly",
        );
        let released = generator.update(FRAME_SECONDS, walking(false), config());
        assert!(released.length() > 0.0);
        assert!(released.x.abs() <= 2.75 && released.y.abs() <= 1.75 && released.z.abs() <= 5.0);
    }

    #[test]
    fn gait_end_state_is_stable_across_common_frame_partitions() {
        fn advance(steps: usize, dt: f32) -> Vec3 {
            let mut generator = MotionGenerator::new();
            let mut output = Vec3::default();
            for _ in 0..steps {
                output = generator.update(dt, walking(false), config());
            }
            output
        }

        let at_60_hz = advance(120, 1.0 / 60.0);
        let at_120_hz = advance(240, 1.0 / 120.0);
        assert!((at_60_hz.x - at_120_hz.x).abs() < 0.000_1);
        assert!((at_60_hz.y - at_120_hz.y).abs() < 0.000_1);
        assert!((at_60_hz.z - at_120_hz.z).abs() < 0.000_1);
    }

    #[test]
    fn long_finite_frame_clamps_integration_without_resetting_motion() {
        let mut long_frame = MotionGenerator::new();
        for _ in 0..90 {
            long_frame.update(FRAME_SECONDS, walking(false), config());
        }
        let mut bounded_frame = long_frame;

        let long = long_frame.update(0.25, walking(false), config());
        let bounded = bounded_frame.update(0.1, walking(false), config());
        assert!((long.x - bounded.x).abs() < 0.000_01);
        assert!((long.y - bounded.y).abs() < 0.000_01);
        assert!((long.z - bounded.z).abs() < 0.000_01);
        assert_eq!(
            long_frame.render_rotation(),
            bounded_frame.render_rotation()
        );
    }

    #[test]
    fn landing_emits_one_visible_bounded_compression_then_settles() {
        let mut generator = MotionGenerator::new();
        let airborne = MotionInput {
            velocity: Vec3::new(0.0, 0.0, -500.0),
            locomotion: LocomotionState::Airborne,
            directional_locomotion: false,
            aiming: false,
            desired_distance: 170.0,
        };
        for _ in 0..30 {
            assert_eq!(
                generator.update(FRAME_SECONDS, airborne, config()),
                Vec3::default(),
            );
        }

        let grounded = MotionInput {
            locomotion: LocomotionState::Grounded,
            velocity: Vec3::default(),
            ..airborne
        };
        let first = generator.update(FRAME_SECONDS, grounded, config());
        assert!(
            first.z < -0.5,
            "landing compression is imperceptible: {first:?}"
        );
        assert!(first.z >= -5.0);
        let mut settled = first;
        for _ in 0..90 {
            settled = generator.update(FRAME_SECONDS, grounded, config());
        }
        assert!(
            settled.length() < 0.000_1,
            "landing motion did not settle: {settled:?}"
        );
    }
}

//! Coherent camera-frame publication and single-writer temporal ownership.
//!
//! The complete native UpdateCamera entry is the only motion writer. Its first
//! accepted completion for each Atom Input frame advances the generator;
//! transition and maintenance callers in that same frame are deduplicated.
//! Pointer-free player-shot sequence changes remain pending across a duplicate
//! and are consumed only by the next advancing frame in the same ownership
//! epoch.
//! Render callbacks load a fixed atomic snapshot and never lock or advance
//! time. A nonblocking writer lease prevents recursive chains from creating
//! two mutable references to the generator.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::native::NativeUpdateSample;
use super::{CameraPose, FirstPersonConfig, LocomotionState, MotionGenerator, MotionInput};

const FRAME_WORDS: usize = 14;
const FLAG_VALID: u32 = 1;
const FLAG_AIMING: u32 = 1 << 1;
const LOCOMOTION_SHIFT: u32 = 8;

/// Result of attempting to consume one post-UpdateCamera native sample.
pub(super) enum MotionAdvance {
    /// A new native input epoch produced an immutable presentation frame.
    Published(CameraMotionFrame),
    /// Another UpdateCamera caller completed in the already-consumed epoch.
    Duplicate,
}

/// Immutable motion generated for one accepted native camera update.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CameraMotionFrame {
    epoch: u32,
    valid: bool,
    locomotion: LocomotionState,
    aiming: bool,
    world_pose: CameraPose,
    viewmodel_pose: CameraPose,
}

impl CameraMotionFrame {
    /// Return the wrapping native camera-update epoch.
    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    /// Return whether this frame passed every normal first-person owner gate.
    pub const fn valid(self) -> bool {
        self.valid
    }

    /// Return the native controller locomotion classification.
    pub const fn locomotion(self) -> LocomotionState {
        self.locomotion
    }

    /// Return whether the native process reported aiming for this update.
    pub const fn aiming(self) -> bool {
        self.aiming
    }

    /// Return the additive world-camera pose.
    pub const fn world_pose(self) -> CameraPose {
        self.world_pose
    }

    /// Return the additive hands/weapon camera pose.
    pub const fn viewmodel_pose(self) -> CameraPose {
        self.viewmodel_pose
    }

    fn encode(self) -> [u32; FRAME_WORDS] {
        let locomotion = match self.locomotion {
            LocomotionState::Grounded => 0,
            LocomotionState::Jumping => 1,
            LocomotionState::Airborne => 2,
            LocomotionState::Unsupported => 3,
        };
        let mut words = [0; FRAME_WORDS];
        words[0] = self.epoch;
        words[1] = u32::from(self.valid)
            | (u32::from(self.aiming) << 1)
            | (locomotion << LOCOMOTION_SHIFT);
        encode_pose(self.world_pose, &mut words[2..8]);
        encode_pose(self.viewmodel_pose, &mut words[8..14]);
        words
    }

    fn decode(words: [u32; FRAME_WORDS]) -> Self {
        let locomotion = match (words[1] >> LOCOMOTION_SHIFT) & 0xFF {
            0 => LocomotionState::Grounded,
            1 => LocomotionState::Jumping,
            2 => LocomotionState::Airborne,
            _ => LocomotionState::Unsupported,
        };
        Self {
            epoch: words[0],
            valid: words[1] & FLAG_VALID != 0,
            locomotion,
            aiming: words[1] & FLAG_AIMING != 0,
            world_pose: decode_pose(&words[2..8]),
            viewmodel_pose: decode_pose(&words[8..14]),
        }
    }
}

fn encode_pose(pose: CameraPose, words: &mut [u32]) {
    let [forward, up, right] = pose.translation();
    let [roll, yaw, pitch] = pose.rotation();
    words.copy_from_slice(&[
        forward.to_bits(),
        up.to_bits(),
        right.to_bits(),
        roll.to_bits(),
        yaw.to_bits(),
        pitch.to_bits(),
    ]);
}

fn decode_pose(words: &[u32]) -> CameraPose {
    CameraPose::new(
        [
            f32::from_bits(words[0]),
            f32::from_bits(words[1]),
            f32::from_bits(words[2]),
        ],
        [
            f32::from_bits(words[3]),
            f32::from_bits(words[4]),
            f32::from_bits(words[5]),
        ],
    )
}

/// Fixed atomic store for one complete camera frame.
pub(super) struct FrameStore {
    sequence: AtomicU32,
    words: [AtomicU32; FRAME_WORDS],
}

impl FrameStore {
    pub(super) const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            words: [const { AtomicU32::new(0) }; FRAME_WORDS],
        }
    }

    pub(super) fn publish(&self, frame: CameraMotionFrame) {
        let words = frame.encode();
        self.sequence.fetch_add(1, Ordering::AcqRel);
        for (target, value) in self.words.iter().zip(words) {
            target.store(value, Ordering::Relaxed);
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    pub(super) fn clear(&self) {
        self.publish(CameraMotionFrame::default());
    }

    pub(super) fn load(&self) -> CameraMotionFrame {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let mut words = [0; FRAME_WORDS];
            for (value, source) in words.iter_mut().zip(&self.words) {
                *value = source.load(Ordering::Relaxed);
            }
            if before == self.sequence.load(Ordering::Acquire) {
                return CameraMotionFrame::decode(words);
            }
        }
    }
}

/// Nonblocking owner of the mutable update-thread generator.
pub(super) struct MotionStateCell {
    borrowed: AtomicBool,
    state: UnsafeCell<MotionState>,
}

// `borrowed` is an exclusive lease. Every access to `state` occurs only after
// a successful false->true transition and the release store in Lease::drop
// happens before another acquire. Render callbacks never access the cell.
unsafe impl Sync for MotionStateCell {}

impl MotionStateCell {
    pub(super) const fn new() -> Self {
        Self {
            borrowed: AtomicBool::new(false),
            state: UnsafeCell::new(MotionState::new()),
        }
    }

    pub(super) fn advance(
        &self,
        sample: NativeUpdateSample,
        config: FirstPersonConfig,
        reset_generation: u32,
        shot_sequence: u32,
    ) -> Option<MotionAdvance> {
        let lease = self.try_borrow()?;
        // SAFETY: `lease` owns the only mutable access until it is dropped.
        let state = unsafe { &mut *self.state.get() };
        let frame = state.advance(sample, config, reset_generation, shot_sequence);
        drop(lease);
        Some(frame)
    }

    fn try_borrow(&self) -> Option<MotionStateLease<'_>> {
        self.borrowed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| MotionStateLease { owner: self })
    }
}

struct MotionStateLease<'a> {
    owner: &'a MotionStateCell,
}

impl Drop for MotionStateLease<'_> {
    fn drop(&mut self) {
        self.owner.borrowed.store(false, Ordering::Release);
    }
}

struct MotionState {
    generator: MotionGenerator,
    epoch: u32,
    input_frame_id: u32,
    reset_generation: u32,
    shot_sequence: u32,
    cell: usize,
    previous_angles: [f32; 2],
    acquired: bool,
}

impl MotionState {
    const fn new() -> Self {
        Self {
            generator: MotionGenerator::new(),
            epoch: 0,
            input_frame_id: 0,
            reset_generation: 0,
            shot_sequence: 0,
            cell: 0,
            previous_angles: [0.0; 2],
            acquired: false,
        }
    }

    fn advance(
        &mut self,
        sample: NativeUpdateSample,
        config: FirstPersonConfig,
        reset_generation: u32,
        shot_sequence: u32,
    ) -> MotionAdvance {
        let ownership_changed =
            !self.acquired || self.reset_generation != reset_generation || self.cell != sample.cell;
        if !ownership_changed && self.input_frame_id == sample.input_frame_id {
            // UpdateCamera is also used by transition, screenshot, load, and
            // maintenance routes. The latest Atom Input frame is the stable
            // native main-loop identity shared by those calls, so only its
            // first accepted completion may advance time and gait distance.
            return MotionAdvance::Duplicate;
        }

        self.epoch = self.epoch.wrapping_add(1);
        self.input_frame_id = sample.input_frame_id;
        if ownership_changed {
            self.generator.reset();
            self.reset_generation = reset_generation;
            self.shot_sequence = shot_sequence;
            self.cell = sample.cell;
            self.previous_angles = sample.logical_angles;
            self.acquired = true;
            return MotionAdvance::Published(CameraMotionFrame {
                epoch: self.epoch,
                valid: config.enabled(),
                locomotion: sample.motion.locomotion(),
                aiming: sample.motion.aiming(),
                world_pose: CameraPose::IDENTITY,
                viewmodel_pose: CameraPose::IDENTITY,
            });
        }

        let look_delta = [
            wrapped_angle_delta(sample.logical_angles[0], self.previous_angles[0]),
            wrapped_angle_delta(sample.logical_angles[1], self.previous_angles[1]),
        ];
        self.previous_angles = sample.logical_angles;
        if shot_sequence != self.shot_sequence {
            // The authoritative fire routine may run after an earlier
            // UpdateCamera caller in this same Input epoch. A duplicate leaves
            // the sequence pending; the next advancing first-person sample
            // consumes the whole burst as one bounded presentation impulse.
            self.generator.trigger_shot_impulse();
        }
        self.shot_sequence = shot_sequence;
        let motion = MotionInput::new(
            sample.motion.delta_seconds(),
            sample.motion.relative_velocity(),
            sample.motion.locomotion(),
            sample.motion.directional_locomotion(),
            look_delta,
            sample.motion.aiming(),
            sample.motion.authored_animation(),
        );
        let generated = self.generator.update(motion, config);
        // The head rotation is a world render layer, just like third-person
        // gait rotation. The close-up weapon camera uses a different projection
        // and FNV already animates its graph, so copying either common head
        // translation or rotation there exaggerates the motion on screen.
        // Publish only Atom's non-oscillating weapon-inertia remainder there.
        let head_rotation = generated.head_rotation();
        MotionAdvance::Published(CameraMotionFrame {
            epoch: self.epoch,
            valid: config.enabled(),
            locomotion: motion.locomotion(),
            aiming: motion.aiming(),
            world_pose: add_common_head_rotation(generated.world_pose(), head_rotation),
            viewmodel_pose: generated.relative_viewmodel_pose(),
        })
    }
}

fn add_common_head_rotation(pose: CameraPose, head_rotation: [f32; 3]) -> CameraPose {
    let relative = pose.rotation();
    CameraPose::new(
        pose.translation(),
        [
            relative[0] + head_rotation[0],
            relative[1] + head_rotation[1],
            relative[2] + head_rotation[2],
        ],
    )
}

fn wrapped_angle_delta(current: f32, previous: f32) -> f32 {
    let tau = core::f32::consts::TAU;
    let mut delta = (current - previous) % tau;
    if delta > core::f32::consts::PI {
        delta -= tau;
    } else if delta < -core::f32::consts::PI {
        delta += tau;
    }
    delta
}

#[cfg(test)]
mod tests {
    use super::{MotionAdvance, MotionState, wrapped_angle_delta};
    use crate::camera::native::NativeUpdateSample;
    use crate::camera::{FirstPersonConfig, LocomotionState, MotionInput};

    fn config() -> FirstPersonConfig {
        FirstPersonConfig::from_ini("[FirstPerson]\nbEnabled=1\nfCameraMotion=1\nfWeaponMotion=1\n")
            .expect("valid first-person test config")
    }

    fn sample(input_frame_id: u32) -> NativeUpdateSample {
        NativeUpdateSample {
            input_frame_id,
            cell: 0x10000,
            logical_angles: [0.0; 2],
            motion: MotionInput::new(
                1.0 / 60.0,
                [120.0, 0.0, 0.0],
                LocomotionState::Grounded,
                true,
                [0.0; 2],
                false,
                false,
            ),
        }
    }

    #[test]
    fn logical_heading_wrap_does_not_create_a_camera_cut() {
        let delta =
            wrapped_angle_delta(-core::f32::consts::PI + 0.01, core::f32::consts::PI - 0.01);
        assert!((delta - 0.02).abs() < 1.0e-5);
    }

    #[test]
    fn multiple_update_camera_callers_advance_motion_once_per_input_frame() {
        let mut state = MotionState::new();
        let first = state.advance(sample(41), config(), 0, 0);
        assert!(matches!(first, MotionAdvance::Published(frame) if frame.epoch() == 1));

        let duplicate = state.advance(sample(41), config(), 0, 0);
        assert!(matches!(duplicate, MotionAdvance::Duplicate));

        let next = state.advance(sample(42), config(), 0, 0);
        assert!(matches!(next, MotionAdvance::Published(frame) if frame.epoch() == 2));
    }

    #[test]
    fn ownership_reset_reacquires_even_with_the_same_input_frame() {
        let mut state = MotionState::new();
        let first = state.advance(sample(7), config(), 0, 0);
        assert!(matches!(first, MotionAdvance::Published(frame) if frame.epoch() == 1));

        let reacquired = state.advance(sample(7), config(), 1, 1);
        assert!(matches!(reacquired, MotionAdvance::Published(frame) if frame.epoch() == 2));
    }

    #[test]
    fn shot_events_wait_for_an_advancing_frame_and_do_not_cross_reacquisition() {
        let mut state = MotionState::new();
        let _ = state.advance(sample(11), config(), 0, 4);

        let duplicate = state.advance(sample(11), config(), 0, 5);
        assert!(matches!(duplicate, MotionAdvance::Duplicate));

        let fired = state.advance(sample(12), config(), 0, 5);
        assert!(
            matches!(fired, MotionAdvance::Published(frame) if !frame.world_pose().is_identity())
        );

        let reacquired = state.advance(sample(13), config(), 1, 6);
        assert!(
            matches!(reacquired, MotionAdvance::Published(frame) if frame.world_pose().is_identity())
        );
    }
}

//! ESP-less third-person framing, follow, motion, 360 locomotion, and aim.
//!
//! Atom owns output only in stable normal third person. VATS, POV changes,
//! free camera, menus, disabled controls, furniture, scripted animation,
//! death/ragdoll, loading, missing world state, and explicit external owners
//! revoke the complete output set in the same update. One subsequent stable
//! native frame seeds a new ownership epoch before Atom can write again.
//!
//! Native capabilities are installed in independent transactions from xNVSE
//! `DeferredInit`, and all behavior defaults off. Hook paths retain no engine
//! pointer, allocate no memory, perform no I/O, emit no routine log, and fail
//! to the live chained predecessor if their fixed nonblocking state lease is
//! unavailable.

mod config;
mod diagnostics;
mod hooks;
mod motion;
mod native;
mod ownership;
mod presentation;
mod zoom;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::OnceLock;

use libnvse::api::player_controls::PlayerControlsReader;
use libpsycho::os::windows::winapi::get_current_thread_id;
use thiserror::Error;

use motion::MotionInput;

pub use super::aim::{AimAngles, ViewRay, converge_angles, third_person_view_ray, view_direction};
pub use super::follow::{FollowSolver, SpringAxis, Vec3};
pub use super::movement::{
    FacingPolicy, MovementIntent, MovementOutput, camera_relative_heading, remap_movement,
    step_heading, wrap_angle,
};
pub use config::{ThirdPersonConfig, ThirdPersonConfigError};
pub use ownership::{OwnershipInput, OwnershipMachine, OwnershipState, OwnershipTransition};
pub use zoom::linear_zoom_delta;

use config::ConfigStore;
use motion::MotionGenerator;

const EXTERNAL_OWNER_CAPACITY: usize = 8;
const MAX_DT: f32 = 0.1;
const MAX_VIEW_PITCH: f32 = 1.553_343;
const NATIVE_HANDOFF_SETTLE_SECONDS: f32 = 0.15;
const COMBAT_GRACE_SECONDS: f32 = 0.65;
const COMBAT_RECOVERY_SECONDS: f32 = 0.35;
const HIP_FIRE_HOLD_SECONDS: f32 = 0.80;
const HIP_FIRE_HOLD_MAX_SECONDS: f32 = 1.40;
const HIP_FIRE_CADENCE_MARGIN_SECONDS: f32 = 0.18;
const HIP_FIRE_GRAPH_BRIDGE_SECONDS: f32 = 0.35;
const HIP_FIRE_PROCESS_AIM_SETTLE_SECONDS: f32 = 0.12;
const HIP_FIRE_RELEASE_RETRY_SECONDS: f32 = 0.75;
const TRANSIENT_HEADING_HOLD_SECONDS: f32 = 0.12;
const RECENTER_INPUT_CHANGE_RADIANS: f32 = 0.017_453_293;
const RECENTER_FADE_START: f32 = 1.221_730_5;
const RECENTER_FADE_END: f32 = 1.431_17;
const VIEW_MATCH_EPSILON: f32 = 0.000_1;
const SCOPE_IDLE: u32 = 0;
const SCOPE_PREPARING: u32 = 1;
const SCOPE_ACTIVE: u32 = 2;
const CAMERA_SCOPE_VIEW_ACTIVE: u32 = 1 << 0;
const CAMERA_SCOPE_FOLLOW_ACTIVE: u32 = 1 << 1;
const CAMERA_SCOPE_MOTION_ACTIVE: u32 = 1 << 2;
const CAMERA_SCOPE_RETAINED_VIEW: u32 = 1 << 3;

/// One ownership observation consumed by third-person yaw continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadingContinuityEvent {
    /// Stable normal third person refreshed the durable yaw.
    Stable,
    /// Controls or input context interrupted otherwise valid third person.
    SoftGap,
    /// Another view owner or missing retained identity requires immediate handoff.
    HardOwner,
}

/// Bounded policy for retaining the native camera-only yaw representation.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct HeadingContinuity {
    soft_seconds: f32,
}

impl HeadingContinuity {
    /// Construct a policy with no retained interruption history.
    pub const fn new() -> Self {
        Self { soft_seconds: 0.0 }
    }

    /// Advance one observation and return whether the existing yaw may remain.
    ///
    /// Stable state resets the grace interval. Soft gaps retain yaw for at
    /// most 120 ms. Hard ownership, negative time, or non-finite time revokes
    /// it immediately.
    pub fn advance(&mut self, event: HeadingContinuityEvent, delta_seconds: f32) -> bool {
        if !delta_seconds.is_finite() || delta_seconds < 0.0 {
            self.soft_seconds = 0.0;
            return false;
        }
        match event {
            HeadingContinuityEvent::Stable => {
                self.soft_seconds = 0.0;
                true
            }
            HeadingContinuityEvent::SoftGap => {
                self.soft_seconds = (self.soft_seconds
                    + delta_seconds.min(TRANSIENT_HEADING_HOLD_SECONDS + MAX_DT))
                .min(TRANSIENT_HEADING_HOLD_SECONDS + MAX_DT);
                self.soft_seconds <= TRANSIENT_HEADING_HOLD_SECONDS
            }
            HeadingContinuityEvent::HardOwner => {
                self.soft_seconds = 0.0;
                false
            }
        }
    }
}

/// Presentation lifetime retained around native combat intent.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum CombatPresentationPhase {
    #[default]
    Relaxed,
    Active,
    Grace,
    Recover,
}

/// Fixed-size post-combat posture envelope advanced once per input frame.
///
/// Atom never extends an engine attack action or starts an animation. The
/// envelope owns only camera/facing policy: native combat remains active while
/// firing, a quiet interval absorbs repeated shots, and Explore facing resumes
/// through a bounded recovery weight instead of at the action-end boundary.
#[derive(Clone, Copy, Debug, Default)]
struct CombatPresentation {
    phase: CombatPresentationPhase,
    phase_seconds: f32,
}

/// Debounced ownership of one third-person unaimed-fire pose session.
///
/// Native input and attack actions start or refresh the session. For replaced
/// animation graphs, a changed Attack-family signature may bridge only the
/// first 350 ms after native fire ends; a persistent loop is never activity.
/// A bounded cadence-adaptive quiet interval then spans follow-up shots, after
/// which Atom requests one complete native false-aim reconciliation back to
/// locomotion. The state never drives sequence weights, requests true aim, or
/// restarts an attack animation.
#[derive(Clone, Copy, Debug, Default)]
struct HipFirePresentation {
    active: bool,
    quiet_seconds: f32,
    hold_seconds: f32,
}

/// Identity of one natural hip-fire timeout awaiting native relaxation.
#[derive(Clone, Copy)]
struct HipFireReleaseCommand {
    player: u32,
    frame_id: u32,
    epoch: u32,
}

impl HipFirePresentation {
    const fn new() -> Self {
        Self {
            active: false,
            quiet_seconds: 0.0,
            hold_seconds: HIP_FIRE_HOLD_SECONDS,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn advance(
        &mut self,
        requested: bool,
        presentation_valid: bool,
        delta_seconds: f32,
        frame_advanced: bool,
    ) {
        if !frame_advanced {
            return;
        }
        if !presentation_valid {
            self.reset();
            return;
        }
        if requested {
            if self.active && self.quiet_seconds > 0.0 {
                // Learn the observed gap between authored shots. This keeps a
                // modded burst or low-FPS automatic loop inside one pose epoch
                // without imposing a long release on ordinary weapons.
                let observed_hold = self.quiet_seconds * 2.0 + HIP_FIRE_CADENCE_MARGIN_SECONDS;
                self.hold_seconds = self
                    .hold_seconds
                    .max(observed_hold)
                    .min(HIP_FIRE_HOLD_MAX_SECONDS);
            } else if !self.active {
                self.hold_seconds = HIP_FIRE_HOLD_SECONDS;
            }
            self.active = true;
            self.quiet_seconds = 0.0;
            return;
        }
        if !self.active {
            return;
        }
        let dt = if delta_seconds.is_finite() && delta_seconds > 0.0 {
            delta_seconds.min(MAX_DT)
        } else {
            0.0
        };
        self.quiet_seconds = (self.quiet_seconds + dt).min(self.hold_seconds + MAX_DT);
        if self.quiet_seconds >= self.hold_seconds {
            self.reset();
        }
    }

    const fn active(self) -> bool {
        self.active
    }
}

impl CombatPresentation {
    const fn new() -> Self {
        Self {
            phase: CombatPresentationPhase::Relaxed,
            phase_seconds: 0.0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn advance(
        &mut self,
        requested: bool,
        presentation_valid: bool,
        delta_seconds: f32,
        frame_advanced: bool,
    ) {
        if !presentation_valid {
            self.reset();
            return;
        }
        if requested {
            self.phase = CombatPresentationPhase::Active;
            self.phase_seconds = 0.0;
            return;
        }
        if self.phase == CombatPresentationPhase::Active {
            self.phase = CombatPresentationPhase::Grace;
            self.phase_seconds = 0.0;
            return;
        }
        if !frame_advanced {
            return;
        }
        let dt = if delta_seconds.is_finite() && delta_seconds > 0.0 {
            delta_seconds.min(MAX_DT)
        } else {
            0.0
        };
        match self.phase {
            CombatPresentationPhase::Grace => {
                self.phase_seconds += dt;
                if self.phase_seconds >= COMBAT_GRACE_SECONDS {
                    self.phase = CombatPresentationPhase::Recover;
                    self.phase_seconds -= COMBAT_GRACE_SECONDS;
                }
            }
            CombatPresentationPhase::Recover => {
                self.phase_seconds += dt;
                if self.phase_seconds >= COMBAT_RECOVERY_SECONDS {
                    self.reset();
                }
            }
            CombatPresentationPhase::Relaxed | CombatPresentationPhase::Active => {}
        }
    }

    fn owns_combat_facing(self) -> bool {
        matches!(
            self.phase,
            CombatPresentationPhase::Active | CombatPresentationPhase::Grace
        )
    }

    fn recovering(self) -> bool {
        self.phase == CombatPresentationPhase::Recover
    }

    fn recovery_weight(self) -> f32 {
        if !self.recovering() {
            return 0.0;
        }
        let relaxed = (self.phase_seconds / COMBAT_RECOVERY_SECONDS).clamp(0.0, 1.0);
        let smooth = relaxed * relaxed * (3.0 - 2.0 * relaxed);
        1.0 - smooth
    }
}

/// Native route selected for one final look delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookRoute {
    /// Atom advances the logical camera axis without writing Actor rotation.
    CameraOnly,
    /// The chained native Actor-rotation route remains the sole owner.
    NativeOnly,
    /// Native Actor rotation runs and Atom copies its result afterwards.
    NativeAndSynchronize,
}

/// Select vertical-look ownership from the published camera state.
///
/// Explore free orbit is camera-only. Combat and a current aim request must
/// retain Actor pitch so character presentation, crosshair direction, and
/// gameplay aim remain coupled. Non-owned states always remain native.
pub const fn vertical_look_route(
    ownership: OwnershipState,
    movement_enabled: bool,
    aim_requested: bool,
) -> LookRoute {
    if !movement_enabled {
        return LookRoute::NativeOnly;
    }
    match ownership {
        OwnershipState::Explore if !aim_requested => LookRoute::CameraOnly,
        OwnershipState::Explore | OwnershipState::Combat => LookRoute::NativeAndSynchronize,
        OwnershipState::Native | OwnershipState::Acquire | OwnershipState::Release => {
            LookRoute::NativeOnly
        }
    }
}

/// Select horizontal-look ownership from the published camera state.
///
/// Explore orbit remains camera-only until native aim begins. AIM and Combat
/// must let FNV rotate the Actor because its horizontal look routine derives
/// absolute body yaw from the adjusted camera heading. Atom then adopts that
/// raw Actor result and restores the same camera-only offset invariant.
pub const fn horizontal_look_route(
    ownership: OwnershipState,
    movement_enabled: bool,
    aim_requested: bool,
) -> LookRoute {
    vertical_look_route(ownership, movement_enabled, aim_requested)
}

/// Return the immediate Actor-yaw handoff required by AIM or Combat.
///
/// The target is the existing logical world-view heading. Applying it before
/// native `UpdateCamera`, followed by camera-offset compensation, aligns the
/// character without rotating the view. Camera-only Explore and native-owned
/// epochs never receive an Actor write.
pub fn actor_heading_handoff_target(
    route: LookRoute,
    actor_heading: f32,
    logical_heading: f32,
) -> Option<f32> {
    if route != LookRoute::NativeAndSynchronize
        || !actor_heading.is_finite()
        || !logical_heading.is_finite()
    {
        return None;
    }
    let target = wrap_angle(logical_heading);
    (wrap_angle(target - actor_heading).abs() > VIEW_MATCH_EPSILON).then_some(target)
}

/// Adopt the raw Actor yaw produced by FNV's native horizontal-look setter.
///
/// The setter at `0x00931D30` reads adjusted camera heading, adds the input
/// delta, and publishes the result as absolute Actor yaw. Reading adjusted
/// heading again here would add the old camera offset twice.
pub fn logical_heading_after_native_look(actor_heading: f32) -> Option<f32> {
    actor_heading.is_finite().then(|| wrap_angle(actor_heading))
}

/// Consecutive-normal-state gate for returning from a native camera owner.
///
/// FNV's Pip-Boy close path starts its player animation before clearing the UI
/// owner byte, so one nominally normal sample does not prove that presentation
/// has settled. This fixed, allocation-free timer resets on every interrupted
/// sample and admits Atom only after a short continuous gameplay interval.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeHandoffGuard {
    stable_seconds: f32,
}

impl NativeHandoffGuard {
    /// Construct a handoff that initially leaves camera ownership native.
    pub const fn new() -> Self {
        Self {
            stable_seconds: 0.0,
        }
    }

    /// Discard all accumulated normal-state time.
    pub fn reset(&mut self) {
        self.stable_seconds = 0.0;
    }

    /// Observe one native state and return whether Atom may begin acquisition.
    ///
    /// `normal_state` must already combine every hard owner and world-validity
    /// predicate. Invalid or negative time is fail-native. Zero time preserves
    /// an already-complete handoff but cannot advance an incomplete one.
    pub fn advance(&mut self, normal_state: bool, delta_seconds: f32) -> bool {
        if !normal_state || !delta_seconds.is_finite() || delta_seconds < 0.0 {
            self.reset();
            return false;
        }
        let bounded_delta = if delta_seconds <= MAX_DT {
            delta_seconds
        } else {
            0.0
        };
        self.stable_seconds =
            (self.stable_seconds + bounded_delta).min(NATIVE_HANDOFF_SETTLE_SECONDS);
        self.stable_seconds >= NATIVE_HANDOFF_SETTLE_SECONDS
    }
}

/// Advance finite logical camera pitch within FNV's established view limit.
pub fn advance_logical_pitch(current: f32, delta: f32) -> Option<f32> {
    (current.is_finite() && delta.is_finite())
        .then(|| (current + delta).clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH))
}

/// Advance ownership of Actor rotX and request one neutral handoff to Explore.
///
/// Native aim/Combat pitch may legitimately move the character. The first
/// subsequent camera-only Explore frame requests presentation-pitch cleanup
/// while retaining Atom's logical camera pitch; the caller may apply that
/// cleanup through its active recovery envelope. A nonzero live Actor value
/// keeps requesting cleanup, so an intervening native UI epoch cannot erase
/// the handoff merely by clearing temporal state. Native-owned states never
/// modify engine state.
pub fn advance_actor_pitch_ownership(
    native_pitch_owned: &mut bool,
    route: LookRoute,
    observed_actor_pitch: f32,
) -> bool {
    match route {
        LookRoute::NativeAndSynchronize => {
            *native_pitch_owned = true;
            false
        }
        LookRoute::CameraOnly => {
            let pending_handoff = core::mem::take(native_pitch_owned);
            pending_handoff
                || (observed_actor_pitch.is_finite()
                    && observed_actor_pitch.abs() > VIEW_MATCH_EPSILON)
        }
        LookRoute::NativeOnly => {
            *native_pitch_owned = false;
            false
        }
    }
}

/// Derive the camera-only offset that preserves one logical world heading.
///
/// FNV's adjusted heading is `base + player[0x6E4]`. Actor facing changes
/// during camera-relative locomotion, and native camera helpers can also alter
/// the offset. Removing the observed old offset recovers the current base;
/// adding this returned value makes the next native adjusted heading equal the
/// logical camera heading without feeding locomotion back into the view.
pub fn compensated_camera_heading_offset(
    native_adjusted_heading: f32,
    current_offset: f32,
    logical_heading: f32,
) -> Option<f32> {
    if !native_adjusted_heading.is_finite()
        || !current_offset.is_finite()
        || !logical_heading.is_finite()
    {
        return None;
    }
    let base_heading = wrap_angle(native_adjusted_heading - current_offset);
    Some(wrap_angle(logical_heading - base_heading))
}

/// Select independently safe reticle and projectile-convergence capabilities.
///
/// A native reticle call is sufficient to align crosshair object selection.
/// Projectile convergence additionally requires the native spawn call, but an
/// existing spawn owner must never disable the otherwise independent reticle.
pub const fn reticle_and_convergence_admission(
    reticle_is_native: bool,
    spawn_is_native: bool,
) -> (bool, bool) {
    let reticle_admitted = reticle_is_native;
    let convergence_admitted = reticle_admitted && spawn_is_native;
    (reticle_admitted, convergence_admitted)
}

/// Restrict follow lag to the current three-dimensional view axis.
///
/// The returned displacement may change chase distance but is collinear with
/// the logical view direction, so applying it to FNV's desired camera point
/// cannot steer yaw, pitch, or lateral framing. Invalid input is rejected.
pub fn axial_follow_offset(solved: Vec3, view_yaw: f32, view_pitch: f32) -> Option<Vec3> {
    if !solved.is_finite() {
        return None;
    }
    let view_axis = view_direction(view_yaw, view_pitch)?;
    // Actor Z follows every contour under the capsule. Feeding that vertical
    // movement into chase distance makes holes and small road rocks lengthen
    // the downward camera ray, which turns harmless terrain into repeated
    // native collision contractions. Horizontal locomotion may retain axial
    // follow lag; terrain height must remain native camera translation only.
    let distance = solved.x.mul_add(view_axis.x, solved.y * view_axis.y);
    let projected = view_axis * distance;
    projected.is_finite().then_some(projected)
}

/// Compose follow distance onto FNV's exact native pivot-to-camera ray.
///
/// Shoulder placement and other native camera geometry may make that ray
/// differ slightly from the logical view axis. Reprojecting at the native
/// seam guarantees follow can change only distance. Degenerate geometry, a
/// request that would cross the pivot, or non-finite input returns `None` so
/// the hook can chain the untouched native values.
pub fn compose_follow_camera(desired: Vec3, pivot: Vec3, follow: Vec3) -> Option<Vec3> {
    if !desired.is_finite() || !pivot.is_finite() || !follow.is_finite() {
        return None;
    }
    if follow == Vec3::default() {
        return Some(desired);
    }
    let ray = desired - pivot;
    let native_distance = ray.length();
    if !native_distance.is_finite() || native_distance <= f32::EPSILON {
        return None;
    }
    let direction = ray * native_distance.recip();
    let distance_delta = follow.x.mul_add(
        direction.x,
        follow.y.mul_add(direction.y, follow.z * direction.z),
    );
    if !distance_delta.is_finite() {
        return None;
    }
    if distance_delta.abs() <= 0.000_01 {
        return Some(desired);
    }
    let final_distance = native_distance + distance_delta;
    if !final_distance.is_finite() || final_distance <= f32::EPSILON {
        return None;
    }
    let composed = pivot + direction * final_distance;
    composed.is_finite().then_some(composed)
}

#[inline]
fn camera_motion_to_world(local: Vec3, view_yaw: f32) -> Option<Vec3> {
    if !local.is_finite() || !view_yaw.is_finite() {
        return None;
    }
    let (sin_yaw, cos_yaw) = view_yaw.sin_cos();
    let world = Vec3::new(
        cos_yaw.mul_add(local.x, sin_yaw * local.y),
        (-sin_yaw).mul_add(local.x, cos_yaw * local.y),
        local.z,
    );
    world.is_finite().then_some(world)
}

static CONFIG: ConfigStore = ConfigStore::new();
static CONTROLS: OnceLock<PlayerControlsReader> = OnceLock::new();
static RUNTIME: RuntimeStore = RuntimeStore::new();
static HOOKS_ACTIVE: AtomicBool = AtomicBool::new(false);
static FOLLOW_ACTIVE: AtomicBool = AtomicBool::new(false);
static MOVEMENT_ACTIVE: AtomicBool = AtomicBool::new(false);
static MOTION_GENERATOR_ACTIVE: AtomicBool = AtomicBool::new(false);
static MOTION_POSITION_ACTIVE: AtomicBool = AtomicBool::new(false);
static FRAMING_CONTRACT_ACTIVE: AtomicBool = AtomicBool::new(false);
static FRAMING_DIRTY: AtomicBool = AtomicBool::new(true);
static FRAMING: FramingStore = FramingStore::new();
static ZOOM_ACTIVE: AtomicBool = AtomicBool::new(false);
static RETICLE_ACTIVE: AtomicBool = AtomicBool::new(false);
static CONVERGENCE_ACTIVE: AtomicBool = AtomicBool::new(false);
static HIP_FIRE_POSE_ADMITTED: AtomicBool = AtomicBool::new(false);
// Published only for the active player and consumed at animation-transition
// frequency. Release/acquire ordering prevents a new graph from observing a
// stale player token across a lifecycle or ownership boundary.
static HIP_FIRE_POSE_ACTIVE: AtomicBool = AtomicBool::new(false);
static HIP_FIRE_POSE_PLAYER: AtomicU32 = AtomicU32::new(0);
// The inverse native conversion can yield fractional DirectInput wheel units.
// One f32 bit pattern is sufficient for the bounded [-0.5, 0.5] remainder and is
// lock-free on the supported 32-bit target. Contention fails to native input.
static ZOOM_RESIDUAL: AtomicU32 = AtomicU32::new(0.0_f32.to_bits());
static RESET_REQUESTED: AtomicBool = AtomicBool::new(false);
static RESET_GENERATION: AtomicU32 = AtomicU32::new(0);
// 0 is idle, 1 is being prepared, and 2 is an active UpdateCamera scope.
// Payload publication precedes the release store of 2. The global vtable
// detour additionally checks the owner thread and player, so a compatible
// concurrent caller cannot observe another camera update's logical state.
static CAMERA_SCOPE_STATE: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_COUNTER: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_GENERATION: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_PLAYER: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_THREAD: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_FLAGS: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_HEADING: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_PITCH: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_FOLLOW_X: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_FOLLOW_Y: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_FOLLOW_Z: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_MOTION_X: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_MOTION_Y: AtomicU32 = AtomicU32::new(0);
static CAMERA_SCOPE_MOTION_Z: AtomicU32 = AtomicU32::new(0);
// A persistent logical heading already survives an internal scope miss in
// PlayerCharacter +0x6E4. Pitch has no equivalent native field, so retain one
// last-safe value only for the same player, thread, reset generation, and Atom
// input frame. Native ownership rejection invalidates this snapshot.
static SAFE_PITCH_VALID: AtomicBool = AtomicBool::new(false);
static SAFE_PITCH_PLAYER: AtomicU32 = AtomicU32::new(0);
static SAFE_PITCH_THREAD: AtomicU32 = AtomicU32::new(0);
static SAFE_PITCH_FRAME: AtomicU32 = AtomicU32::new(0);
static SAFE_PITCH_RESET_GENERATION: AtomicU32 = AtomicU32::new(0);
static SAFE_PITCH_VALUE: AtomicU32 = AtomicU32::new(0);
// The native +0x6E4 offset is already the durable yaw representation. This
// token prevents fail-native callbacks from clearing it during an internal
// stable-third-person admission gap of any duration. Only a proven camera
// owner or explicit lifecycle reset invalidates it.
static HEADING_HOLD_PLAYER: AtomicU32 = AtomicU32::new(0);
static HEADING_HOLD_RESET_GENERATION: AtomicU32 = AtomicU32::new(0);
static HEADING_HOLD_YAW: AtomicU32 = AtomicU32::new(0);
static HEADING_HOLD_COMBAT: AtomicBool = AtomicBool::new(false);
// Nonzero only while Atom has published a camera-only +0x6E4 heading offset
// for this exact PlayerCharacter. The marker deliberately survives temporal
// resets: a POV/menu/lifecycle boundary must return the persistent engine
// field to native actor/view coupling before Atom may forget its ownership.
static CAMERA_HEADING_OFFSET_PLAYER: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_SCOPE_STATE: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_SCOPE_COUNTER: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_SCOPE_GENERATION: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_SCOPE_MOVER: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_SCOPE_THREAD: AtomicU32 = AtomicU32::new(0);
static FACING_CALL_ACTIVE: AtomicBool = AtomicBool::new(false);
static EXTERNAL_OWNERS: [AtomicU32; EXTERNAL_OWNER_CAPACITY] =
    [const { AtomicU32::new(0) }; EXTERNAL_OWNER_CAPACITY];

/// Failure to validate or install Atom's third-person system.
#[derive(Debug, Error)]
pub(crate) enum ThirdPersonInstallError {
    /// The fixed FNV data contract was unavailable.
    #[error(transparent)]
    Native(#[from] native::NativeContractError),
    /// Deferred initialization attempted to replace an established reader.
    #[error("third-person control-state reader was already initialized")]
    ReaderAlreadyInitialized,
}

/// Captured predecessor addresses for startup diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThirdPersonHookStatus {
    pub(crate) zoom_predecessor: Option<usize>,
    pub(crate) camera_heading_predecessor: Option<usize>,
    pub(crate) camera_pitch_predecessor: Option<usize>,
    pub(crate) follow_predecessor: Option<usize>,
    pub(crate) motion_position_predecessor: Option<usize>,
    pub(crate) movement_scope_predecessor: Option<usize>,
    pub(crate) player_movement_predecessor: Option<usize>,
    pub(crate) reticle_predecessor: Option<usize>,
    pub(crate) spawn_predecessor: Option<usize>,
    pub(crate) hip_fire_pose_predecessor: Option<usize>,
    pub(crate) reticle_admitted: bool,
    pub(crate) aim_admitted: bool,
    pub(crate) framing_admitted: bool,
    pub(crate) motion_admitted: bool,
    pub(crate) hip_fire_pose_admitted: bool,
}

/// Return one coherent copy of the current MCM-owned settings.
pub fn current_config() -> ThirdPersonConfig {
    CONFIG.load()
}

pub(crate) fn publish_config(config: ThirdPersonConfig) {
    let previous = CONFIG.load();
    CONFIG.publish(config);
    if previous.zoom_step() != config.zoom_step() {
        clear_zoom_residual();
    }
    if previous.follow_enabled() != config.follow_enabled()
        || previous.movement_enabled() != config.movement_enabled()
        || previous.framing_enabled() != config.framing_enabled()
        || previous.motion_enabled() != config.motion_enabled()
    {
        // Enabling is also a discontinuity: a solver that was dormant while
        // another capability owned the epoch must seed from current native
        // state instead of resuming old follow or facing history.
        request_reset();
    }
    FRAMING_DIRTY.store(true, Ordering::Release);
    reconcile_framing();
}

/// Enable or disable fixed third-person runtime-path counters.
pub(crate) fn configure_diagnostics(enabled: bool) {
    diagnostics::configure(enabled);
}

/// Clear third-person counters at the start of a telemetry epoch.
pub(crate) fn reset_diagnostics() {
    diagnostics::reset();
}

/// Write a requested third-person path summary outside native callbacks.
pub(crate) fn log_diagnostics_summary() {
    let snapshot = diagnostics::snapshot();
    let runtime = RUNTIME.with_mut(|state| {
        (
            state.ownership.state(),
            state.ownership.epoch(),
            state.last_frame_id,
        )
    });
    log::info!("[CAMERA_TELEMETRY] Requested third-person path summary");
    log::info!(
        "[CAMERA_TELEMETRY] Third-person look: delta_calls={}, consumed={}, camera_heading_calls={}, overridden={}",
        snapshot.heading_calls,
        snapshot.heading_consumed,
        snapshot.camera_heading_calls,
        snapshot.camera_heading_overrides,
    );
    log::info!(
        "[CAMERA_TELEMETRY] Third-person follow: calls={}, admitted={}, nonzero_offsets={}",
        snapshot.follow_calls,
        snapshot.follow_offsets,
        snapshot.nonzero_follow_offsets,
    );
    log::info!(
        "[CAMERA_TELEMETRY] Native camera collision: samples={}, distance_drops={}, max_contraction={:.3}, max_frame_drop={:.3}, max_unexplained_drop={:.3}",
        snapshot.follow_collision_samples,
        snapshot.follow_distance_drops,
        f32::from_bits(snapshot.max_collision_contraction_bits),
        f32::from_bits(snapshot.max_resolved_distance_drop_bits),
        f32::from_bits(snapshot.max_unexplained_distance_drop_bits),
    );
    log::info!(
        "[CAMERA_TELEMETRY] Third-person movement: scope_calls={}, admitted_scopes={}, wrapper_calls={}, overridden={}",
        snapshot.movement_scope_calls,
        snapshot.movement_scopes_admitted,
        snapshot.movement_calls,
        snapshot.movement_overrides,
    );
    log::info!(
        "[CAMERA_TELEMETRY] Third-person stability: transient_heading_holds={}, internal_pitch_holds={}, vertical_recenter_suppressions={}, recenter_starts={}",
        snapshot.heading_holds,
        snapshot.pitch_holds,
        snapshot.recenter_suppressions,
        snapshot.recenter_starts,
    );
    if let Some((state, epoch, frame_id)) = runtime {
        log::info!(
            "[CAMERA_TELEMETRY] Third-person owner: state={state:?}, epoch={epoch}, frame_id={frame_id}, owned_observations={}",
            snapshot.owned_observations,
        );
    } else {
        log::info!(
            "[CAMERA_TELEMETRY] Third-person owner: state snapshot busy, owned_observations={}",
            snapshot.owned_observations,
        );
    }
    log::info!(
        "[CAMERA_TELEMETRY] Third-person native state accepted: {}",
        snapshot.observations(native::NativeRejection::Accepted),
    );
    for reason in native::NativeRejection::ALL {
        if reason == native::NativeRejection::Accepted {
            continue;
        }
        let count = snapshot.observations(reason);
        if count != 0 {
            log::info!(
                "[CAMERA_TELEMETRY] Third-person rejected by {}: {}",
                reason.label(),
                count,
            );
        }
    }
}

/// Validate shared native state and independently install third-person groups.
pub(crate) fn install_native_system(
    controls: PlayerControlsReader,
) -> Result<ThirdPersonHookStatus, ThirdPersonInstallError> {
    native::validate_data_contract()?;
    CONTROLS
        .set(controls)
        .map_err(|_| ThirdPersonInstallError::ReaderAlreadyInitialized)?;

    let follow_predecessor = match hooks::install_follow() {
        Ok(predecessor) => {
            FOLLOW_ACTIVE.store(true, Ordering::Release);
            Some(predecessor)
        }
        Err(error) => {
            log::warn!(
                "[CAMERA] Third-person follow is unavailable: {error:#}. Camera-relative movement remains independently eligible"
            );
            None
        }
    };
    let movement_predecessors = match hooks::install_movement() {
        Ok(predecessors) => {
            MOVEMENT_ACTIVE.store(true, Ordering::Release);
            Some(predecessors)
        }
        Err(error) => {
            log::warn!(
                "[CAMERA] Camera-relative movement is unavailable: {error:#}. Third-person follow remains independently eligible"
            );
            None
        }
    };
    let aim_predecessors = movement_predecessors.and_then(|_| match hooks::install_aim() {
        Ok(predecessors) => Some(predecessors),
        Err(error) => {
            log::warn!(
                "[AIM] Third-person convergence is unavailable: {error:#}. Native aiming remains active"
            );
            None
        }
    });
    let reticle_admitted = aim_predecessors.is_some_and(|value| value.reticle_admitted);
    let aim_admitted = aim_predecessors.is_some_and(|value| value.aim_admitted);
    RETICLE_ACTIVE.store(reticle_admitted, Ordering::Release);
    CONVERGENCE_ACTIVE.store(aim_admitted, Ordering::Release);
    // Preserve the accepted follow/movement/aim transaction order. Fine zoom
    // is a new independent capability and is appended after those established
    // DeferredInit operations so its failure cannot perturb their admission.
    let zoom_predecessor = match native::validate_zoom_contract() {
        Ok(()) => match hooks::install_zoom() {
            Ok(predecessor) => {
                ZOOM_ACTIVE.store(true, Ordering::Release);
                Some(predecessor)
            }
            Err(error) => {
                log::warn!(
                    "[CAMERA] Fine third-person zoom is unavailable: {error:#}. Native wheel distance remains active"
                );
                None
            }
        },
        Err(error) => {
            log::warn!(
                "[CAMERA] Fine third-person zoom is unavailable: {error:#}. Native wheel distance remains active"
            );
            None
        }
    };
    let motion_admitted = match native::validate_motion_contract() {
        Ok(()) => {
            MOTION_GENERATOR_ACTIVE.store(true, Ordering::Release);
            true
        }
        Err(error) => {
            log::warn!(
                "[CAMERA] Third-person gait motion is unavailable: {error:#}. Follow and movement remain independently available"
            );
            false
        }
    };
    let motion_position_predecessor = if motion_admitted {
        match native::validate_motion_position_contract() {
            Ok(()) => match hooks::install_motion_position() {
                Ok(predecessor) => {
                    MOTION_POSITION_ACTIVE.store(true, Ordering::Release);
                    Some(predecessor)
                }
                Err(error) => {
                    log::warn!(
                        "[CAMERA] Third-person motion translation is unavailable: {error:#}. Render bob remains available"
                    );
                    None
                }
            },
            Err(error) => {
                log::warn!(
                    "[CAMERA] Third-person motion translation is unavailable: {error:#}. Render bob remains available"
                );
                None
            }
        }
    } else {
        None
    };
    let framing_admitted = match native::validate_framing_contract() {
        Ok(()) => {
            FRAMING_CONTRACT_ACTIVE.store(true, Ordering::Release);
            FRAMING_DIRTY.store(true, Ordering::Release);
            reconcile_framing();
            true
        }
        Err(error) => {
            log::warn!(
                "[CAMERA] Third-person framing is unavailable: {error:#}. Native distance and shoulder settings remain active"
            );
            false
        }
    };
    // Append the independent presentation adapter after every established
    // camera transaction. Its LazyLock is first touched here at DeferredInit;
    // it adds no loader-time TLS, worker, import, or parser ownership.
    let hip_fire_pose_predecessor = match native::validate_hip_fire_pose_contract() {
        Ok(()) => match hooks::install_hip_fire_pose() {
            Ok(predecessor) => {
                HIP_FIRE_POSE_ADMITTED.store(true, Ordering::Release);
                Some(predecessor)
            }
            Err(error) => {
                log::warn!(
                    "[AIM] Hip-fire pose smoothing is unavailable: {error:#}. Native animations remain active"
                );
                None
            }
        },
        Err(error) => {
            log::warn!(
                "[AIM] Hip-fire pose smoothing is unavailable: {error:#}. Native animations remain active"
            );
            None
        }
    };
    HOOKS_ACTIVE.store(
        follow_predecessor.is_some()
            || motion_admitted
            || motion_position_predecessor.is_some()
            || movement_predecessors.is_some()
            || hip_fire_pose_predecessor.is_some(),
        Ordering::Release,
    );
    Ok(ThirdPersonHookStatus {
        zoom_predecessor,
        camera_heading_predecessor: movement_predecessors.map(|value| value.camera_heading),
        camera_pitch_predecessor: movement_predecessors.map(|value| value.camera_pitch),
        follow_predecessor,
        motion_position_predecessor,
        movement_scope_predecessor: movement_predecessors.map(|value| value.movement_scope),
        player_movement_predecessor: movement_predecessors.map(|value| value.player_movement),
        reticle_predecessor: aim_predecessors.map(|value| value.reticle),
        spawn_predecessor: aim_predecessors.map(|value| value.spawn),
        hip_fire_pose_predecessor,
        reticle_admitted,
        aim_admitted,
        framing_admitted,
        motion_admitted,
        hip_fire_pose_admitted: hip_fire_pose_predecessor.is_some(),
    })
}

/// Assert or release an explicit external third-person owner.
///
/// `owner_token` must be a stable nonzero identifier selected by the external
/// provider. Up to eight simultaneous owners are tracked without allocation.
/// Repeated assertions are idempotent; releasing an absent token returns
/// `false`. While any token is present, this subsystem performs no follow,
/// movement, facing, zoom conversion, or aim writes. External
/// DLLs should use [`crate::AtomCamera_SetExternalOwner`] to cover both Atom
/// camera systems through the stable C ABI.
pub fn set_external_owner(owner_token: u32, active: bool) -> bool {
    if owner_token == 0 {
        return false;
    }
    let accepted = if active {
        EXTERNAL_OWNERS
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == owner_token)
            || EXTERNAL_OWNERS.iter().any(|slot| {
                slot.compare_exchange(0, owner_token, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            })
    } else {
        let mut found = false;
        for slot in &EXTERNAL_OWNERS {
            if slot
                .compare_exchange(owner_token, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                found = true;
            }
        }
        found
    };
    if accepted {
        FRAMING_DIRTY.store(true, Ordering::Release);
        request_reset();
    }
    accepted
}

/// Remap one live player animation request while a hip-fire session owns it.
///
/// This is called only by the fingerprinted morph-entry detour. Pointer and
/// ADS validation remain in the native boundary; every rejected context keeps
/// the exact requested group and chains its predecessor unchanged.
pub(super) fn remap_hip_fire_animation(anim_data: *mut c_void, group: u16) -> u16 {
    if !HIP_FIRE_POSE_ACTIVE.load(Ordering::Acquire) {
        return group;
    }
    let player = HIP_FIRE_POSE_PLAYER.load(Ordering::Relaxed) as usize as *mut c_void;
    if unsafe { native::hip_fire_anim_data_owned(anim_data, player) } {
        native::hip_fire_animation_group(group, true)
    } else {
        group
    }
}

/// Return the latest bounded third-person render-only gait rotation.
///
/// This composes onto the live predecessor camera, so another camera mod's
/// base transform remains authoritative. A nonblocking runtime lease and a
/// same-frame native ownership recheck make contention or a POV/menu handoff
/// fail to the exact native render.
pub(super) fn render_camera_pose() -> Option<super::CameraPose> {
    if !HOOKS_ACTIVE.load(Ordering::Acquire)
        || !MOTION_GENERATOR_ACTIVE.load(Ordering::Acquire)
        || external_owner_active()
    {
        return None;
    }
    let config = CONFIG.load();
    if !config.motion_enabled() || config.motion_strength() == 0.0 {
        return None;
    }
    let controls = *CONTROLS.get()?;
    let player = native::player();
    if !unsafe { native::render_owner_allows(player, controls) } {
        return None;
    }
    RUNTIME
        .with_mut(|runtime| {
            let current_frame = input_frame_id();
            if !runtime.ownership.state().is_owned()
                || runtime.player != pointer_word(player)
                || current_frame == 0
                || (runtime.last_frame_id != current_frame
                    && runtime.last_frame_id.wrapping_add(1) != current_frame)
                || !runtime.render_motion_rotation.is_finite()
            {
                return None;
            }
            let rotation = runtime.render_motion_rotation;
            Some(super::CameraPose::new(
                [0.0; 3],
                [rotation.x, rotation.y, rotation.z],
            ))
        })
        .flatten()
}

fn publish_hip_fire_pose(player: *mut c_void, active: bool) {
    if active {
        HIP_FIRE_POSE_PLAYER.store(pointer_word(player), Ordering::Relaxed);
        HIP_FIRE_POSE_ACTIVE.store(true, Ordering::Release);
    } else {
        HIP_FIRE_POSE_ACTIVE.store(false, Ordering::Release);
        HIP_FIRE_POSE_PLAYER.store(0, Ordering::Relaxed);
    }
}

/// Invalidate all third-person temporal state at a lifecycle boundary.
pub(crate) fn request_reset() {
    RESET_GENERATION.fetch_add(1, Ordering::AcqRel);
    RESET_REQUESTED.store(true, Ordering::Release);
    invalidate_safe_pitch();
    invalidate_heading_hold();
    clear_camera_scope();
    clear_movement_scope();
    clear_zoom_residual();
    publish_hip_fire_pose(core::ptr::null_mut(), false);
    if RUNTIME.with_mut(RuntimeState::reset).is_some() {
        RESET_REQUESTED.store(false, Ordering::Release);
    }
}

/// Convert one normal third-person wheel read to the configured linear step.
pub(crate) fn refine_zoom_wheel(native_delta: i32) -> i32 {
    if native_delta == 0 || !ZOOM_ACTIVE.load(Ordering::Acquire) {
        return native_delta;
    }
    let Some(controls) = CONTROLS.get().copied() else {
        clear_zoom_residual();
        return native_delta;
    };
    let config = CONFIG.load();
    if !config.enabled() || external_owner_active() {
        clear_zoom_residual();
        return native_delta;
    }

    // This hook owns only the exact axis-3 read in normal UpdateCamera. A
    // fresh observation is still required because a menu, VATS, POV, or
    // loading transition may happen before the ownership machine advances.
    let frame = unsafe { native::observe(core::ptr::null_mut(), controls) };
    if !frame.hard_valid {
        clear_zoom_residual();
        return native_delta;
    }
    if frame.weapon_out
        && (!config.drawn_360() || frame.combat_intent)
        && unsafe { native::fighting_control_disabled(frame.player, controls) }
    {
        clear_zoom_residual();
        return native_delta;
    }
    let Some(sample) = (unsafe { native::zoom_sample(native_delta) }) else {
        clear_zoom_residual();
        return native_delta;
    };

    let residual_bits = ZOOM_RESIDUAL.load(Ordering::Acquire);
    let mut residual = f64::from(f32::from_bits(residual_bits));
    let Some(adjusted) = linear_zoom_delta(
        native_delta,
        sample.desired_distance,
        sample.multiplier,
        config.zoom_step(),
        &mut residual,
    ) else {
        clear_zoom_residual();
        return native_delta;
    };
    if ZOOM_RESIDUAL
        .compare_exchange(
            residual_bits,
            (residual as f32).to_bits(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // A concurrent owner changed the accumulated state. Passing the raw
        // value preserves native behavior without overwriting its progress.
        return native_delta;
    }
    adjusted
}

pub(crate) fn consume_horizontal_heading(player: *mut c_void, delta: f32) -> bool {
    if !HOOKS_ACTIVE.load(Ordering::Acquire)
        || !MOVEMENT_ACTIVE.load(Ordering::Acquire)
        || !delta.is_finite()
    {
        return false;
    }
    let consumed = RUNTIME
        .with_mut(|runtime| {
            let Some((frame, config)) = runtime.refresh(player) else {
                return false;
            };
            let route = horizontal_look_route(
                runtime.ownership.state(),
                config.movement_enabled(),
                runtime.motion_aiming,
            );
            // Follow-only and native-owned modes preserve the complete FNV
            // path. AIM/Combat also stays native so body yaw is authoritative;
            // observe_native_horizontal_heading synchronizes the logical view
            // after the setter has run.
            if route != LookRoute::CameraOnly || frame.player != player {
                return false;
            }
            runtime.view_yaw = wrap_angle(runtime.view_yaw + delta);
            if delta.abs() > 0.000_001 {
                runtime.manual_idle_seconds = 0.0;
                runtime.recenter_speed = 0.0;
                runtime.recenter_intent = None;
            }
            true
        })
        .unwrap_or(false);
    let consumed = consumed || consume_retained_horizontal_heading(player, delta);
    diagnostics::mark_heading(consumed);
    consumed
}

fn consume_retained_horizontal_heading(player: *mut c_void, delta: f32) -> bool {
    if !heading_hold_matches(player) || HEADING_HOLD_COMBAT.load(Ordering::Relaxed) {
        return false;
    }
    let held = f32::from_bits(HEADING_HOLD_YAW.load(Ordering::Relaxed));
    if !held.is_finite() {
        invalidate_heading_hold();
        return false;
    }
    let heading = wrap_angle(held + delta);
    if !unsafe { synchronize_owned_camera_heading(player, heading) } {
        invalidate_heading_hold();
        return false;
    }
    HEADING_HOLD_YAW.store(heading.to_bits(), Ordering::Relaxed);
    let _ = RUNTIME.with_mut(|runtime| {
        if runtime.player == pointer_word(player) {
            runtime.view_yaw = heading;
            if delta.abs() > 0.000_001 {
                runtime.manual_idle_seconds = 0.0;
                runtime.recenter_speed = 0.0;
                runtime.recenter_intent = None;
            }
        }
    });
    true
}

/// Refresh logical heading after native AIM/Combat updates Actor rotZ.
pub(crate) fn observe_native_horizontal_heading(player: *mut c_void) {
    if !HOOKS_ACTIVE.load(Ordering::Acquire) || !MOVEMENT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let logical_heading = RUNTIME
        .with_mut(|runtime| {
            let (frame, config) = runtime.refresh(player)?;
            let route = horizontal_look_route(
                runtime.ownership.state(),
                config.movement_enabled(),
                runtime.motion_aiming,
            );
            if route != LookRoute::NativeAndSynchronize
                || !frame.hard_valid
                || frame.player != player
            {
                return None;
            }
            let heading = logical_heading_after_native_look(frame.actor_yaw)?;
            if wrap_angle(heading - runtime.view_yaw).abs() > 0.000_001 {
                runtime.manual_idle_seconds = 0.0;
                runtime.recenter_speed = 0.0;
                runtime.recenter_intent = None;
            }
            runtime.view_yaw = heading;
            Some(heading)
        })
        .flatten();
    if logical_heading
        .is_some_and(|heading| unsafe { !synchronize_owned_camera_heading(player, heading) })
    {
        request_reset();
    }
}

/// Prepare Atom's persistent camera-only heading for native horizontal look.
///
/// A proven Combat or native-owner call folds the effective adjusted heading
/// into raw Actor yaw and clears `+0x6E4`. An internal fail-native gap retains
/// the offset because it does not transfer ownership of the visible view.
pub(crate) fn prepare_native_horizontal_heading(player: *mut c_void) {
    // A fail-native input callback during an internal third-person admission
    // gap must not turn that gap into a camera-owner transition. Combat still
    // needs the explicit fold because FNV's native look setter begins from the
    // adjusted heading and immediately writes Actor yaw.
    if heading_hold_matches(player) && !HEADING_HOLD_COMBAT.load(Ordering::Relaxed) {
        diagnostics::mark_heading_hold();
        return;
    }
    let _ = release_owned_camera_heading(player);
}

/// Build a stateless camera-relative request during a retained yaw gap.
///
/// Actor facing and temporal animation history remain untouched. The next
/// admitted stateful sample resumes their normal bounded convergence.
pub(crate) fn fallback_movement_override(
    actor: *mut c_void,
    native_movement: Vec3,
    flags: u32,
) -> Option<MovementOutput> {
    if !native_movement.is_finite() || !movement_scope_matches() || !heading_hold_matches(actor) {
        return None;
    }
    let view_yaw = f32::from_bits(HEADING_HOLD_YAW.load(Ordering::Relaxed));
    let actor_yaw = unsafe { native::raw_actor_yaw(actor)? };
    let policy = if HEADING_HOLD_COMBAT.load(Ordering::Relaxed) {
        FacingPolicy::Combat
    } else {
        FacingPolicy::Explore
    };
    if !view_yaw.is_finite() {
        return None;
    }
    let recenter_heading = if policy == FacingPolicy::Explore {
        // A feature-only observation gap may retain an existing recenter
        // transaction, but it cannot mutate or reseed one. If the runtime
        // lease is unavailable, chain native unchanged instead of rebuilding
        // movement from a camera basis that may currently be turning.
        let snapshot = RUNTIME.with_mut(|runtime| {
            if runtime.player != pointer_word(actor) {
                return Err(());
            }
            let local_heading = (native_movement.horizontal_length() > f32::EPSILON)
                .then(|| wrap_angle(native_movement.x.atan2(native_movement.y)));
            Ok(runtime
                .recenter_intent
                .zip(local_heading)
                .filter(|(recenter, local)| recenter.matches(*local))
                .map(|(recenter, _)| recenter.world_travel_heading))
        })?;
        snapshot.ok()?
    } else {
        None
    };
    diagnostics::mark_heading_hold();
    let intent = recenter_heading.map_or_else(
        || MovementIntent::new(native_movement, flags, view_yaw, policy),
        |heading| {
            MovementIntent::with_world_heading(native_movement, flags, view_yaw, policy, heading)
        },
    );
    Some(intent.resolve(actor_yaw))
}

pub(crate) fn consume_vertical_heading(player: *mut c_void, delta: f32) -> bool {
    if !HOOKS_ACTIVE.load(Ordering::Acquire)
        || !MOVEMENT_ACTIVE.load(Ordering::Acquire)
        || !delta.is_finite()
    {
        return false;
    }
    RUNTIME
        .with_mut(|runtime| {
            let Some((frame, config)) = runtime.refresh(player) else {
                return false;
            };
            let route = vertical_look_route(
                runtime.ownership.state(),
                config.movement_enabled(),
                runtime.motion_aiming,
            );
            if route != LookRoute::CameraOnly || frame.player != player {
                return false;
            }
            let Some(pitch) = advance_logical_pitch(runtime.view_pitch, delta) else {
                return false;
            };
            runtime.view_pitch = pitch;
            if delta.abs() > 0.000_001 {
                // Any manual orbit input owns the complete view. Vertical look
                // must cancel a pending horizontal recenter just as yaw does.
                runtime.manual_idle_seconds = 0.0;
                runtime.recenter_speed = 0.0;
                runtime.recenter_intent = None;
            }
            true
        })
        .unwrap_or(false)
}

/// Join free-orbit camera pitch to Actor pitch before native AIM look runs.
///
/// FNV's incremental vertical setter starts from Actor rotX. On the initial
/// sampled AIM frame that value still belongs to Explore while the logical
/// camera may be looking far above or below it. Publishing the logical angle
/// first makes the chained delta operate on the displayed direction instead
/// of snapping the camera back to stale character pitch.
pub(crate) fn prepare_native_vertical_heading(player: *mut c_void) {
    if !HOOKS_ACTIVE.load(Ordering::Acquire) || !MOVEMENT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let target = RUNTIME
        .with_mut(|runtime| {
            let (frame, config) = runtime.refresh(player)?;
            let route = vertical_look_route(
                runtime.ownership.state(),
                config.movement_enabled(),
                runtime.motion_aiming,
            );
            if route != LookRoute::NativeAndSynchronize
                || !frame.hard_valid
                || frame.player != player
                || !runtime.view_pitch.is_finite()
                || (frame.pitch - runtime.view_pitch).abs() <= VIEW_MATCH_EPSILON
            {
                return None;
            }
            Some(runtime.view_pitch)
        })
        .flatten();
    let Some(target) = target else {
        return;
    };
    let actual = unsafe { native::invoke_actor_pitch_setter(player, target) };
    if !actual.is_some_and(|pitch| adopt_owned_actor_pitch(player, pitch)) {
        request_reset();
    }
}

/// Refresh logical pitch after the native Combat route updates Actor rotX.
pub(crate) fn observe_native_vertical_heading(player: *mut c_void) {
    if !HOOKS_ACTIVE.load(Ordering::Acquire) || !MOVEMENT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let _ = RUNTIME.with_mut(|runtime| {
        let Some((frame, config)) = runtime.refresh(player) else {
            return;
        };
        let route = vertical_look_route(
            runtime.ownership.state(),
            config.movement_enabled(),
            runtime.motion_aiming,
        );
        if route == LookRoute::NativeAndSynchronize && frame.hard_valid && frame.player == player {
            let _ =
                advance_actor_pitch_ownership(&mut runtime.native_pitch_owned, route, frame.pitch);
            runtime.view_pitch = frame.pitch.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH);
        }
    });
}

/// Identity token for one complete native `UpdateCamera` invocation.
///
/// The generation prevents an old guard from clearing a newer reentrant
/// scope after a lifecycle reset revoked the old publication.
#[derive(Clone, Copy)]
pub(crate) struct CameraUpdateScope {
    generation: u32,
    player: u32,
    thread: u32,
    motion_sample: Option<super::NativeMotionCarrier>,
}

impl CameraUpdateScope {
    /// Return the already-validated locomotion carrier for post-update reuse.
    pub(crate) const fn motion_sample(self) -> Option<super::NativeMotionCarrier> {
        self.motion_sample
    }
}

/// Prepare and publish one immutable snapshot for a native camera update.
pub(crate) fn enter_camera_update_scope(player: *mut c_void) -> Option<CameraUpdateScope> {
    reconcile_framing();
    if !HOOKS_ACTIVE.load(Ordering::Acquire) || player.is_null() {
        return None;
    }
    let reset_generation = RESET_GENERATION.load(Ordering::Acquire);
    if CAMERA_SCOPE_STATE
        .compare_exchange(
            SCOPE_IDLE,
            SCOPE_PREPARING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return None;
    }
    let generation = CAMERA_SCOPE_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let owner_thread = get_current_thread_id();
    CAMERA_SCOPE_GENERATION.store(generation, Ordering::Relaxed);
    CAMERA_SCOPE_THREAD.store(owner_thread, Ordering::Relaxed);

    let prepared = RUNTIME.with_mut(|runtime| {
        let prepared = runtime.prepare_camera_frame(player);
        (
            prepared,
            runtime.heading_handoff_required,
            runtime.view_pitch,
            runtime.retained_follow_offset,
            runtime.retained_motion_offset,
            runtime.retained_spatial_flags,
        )
    });
    let Some(prepared) = prepared else {
        // RuntimeStore contention is fail-native for this callback, but it
        // does not prove an ownership transition. The current offset remains
        // paired with the still-live logical view until the owner can decide.
        clear_preparing_camera_scope(generation, owner_thread);
        return None;
    };
    let (
        prepared,
        heading_handoff_required,
        retained_pitch,
        retained_follow_offset,
        retained_motion_offset,
        retained_spatial_flags,
    ) = prepared;
    let Some(mut prepared) = prepared else {
        // Feature admission and view ownership are independent. A transient
        // mover, collision, process, or active-3D gap cannot run follow or
        // movement, but the current callback has already proven that no real
        // camera owner took over. Publish the last complete view axes, axial
        // follow input, and post-solve motion so UpdateCamera cannot expose an
        // intervening native pose as a one-frame position or angle snap.
        if heading_handoff_required {
            let _ = release_owned_camera_heading(player);
            invalidate_safe_pitch();
            clear_preparing_camera_scope(generation, owner_thread);
            return None;
        }
        return activate_retained_view_scope(
            player,
            retained_pitch,
            retained_follow_offset,
            retained_motion_offset,
            retained_spatial_flags,
            generation,
            owner_thread,
            reset_generation,
        );
    };
    if let Some(command) = prepared.hip_fire_release {
        // Actor::AimWeapon can reenter Atom's animation detour, so invoke it
        // only after releasing RuntimeStore. Identity and generation checks
        // prevent a queued relaxation from crossing a player, reset, or
        // camera-scope boundary.
        let invoked = pointer_word(player) == command.player
            && RESET_GENERATION.load(Ordering::Acquire) == reset_generation
            && CAMERA_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_PREPARING
            && CAMERA_SCOPE_GENERATION.load(Ordering::Relaxed) == generation
            && CAMERA_SCOPE_THREAD.load(Ordering::Relaxed) == owner_thread
            && unsafe { native::release_hip_fire_pose(player) };
        let _ = RUNTIME.with_mut(|runtime| {
            runtime.complete_hip_fire_release(command, invoked);
        });
    }
    let actor_heading_succeeded = prepared.align_actor_heading.is_none_or(|target| {
        let Some(_facing_scope) = FacingCallScope::enter() else {
            return false;
        };
        if !unsafe { native::invoke_actor_yaw_setter(player, target) } {
            return false;
        }
        unsafe { native::raw_actor_yaw(player) }
            .is_some_and(|actual| wrap_angle(actual - target).abs() <= VIEW_MATCH_EPSILON)
    });
    let actor_pitch_succeeded = prepared.actor_pitch_write.is_none_or(|write| {
        let Some(actual) = (unsafe { native::invoke_actor_pitch_setter(player, write.target) })
        else {
            return false;
        };
        if write.adopt_result {
            prepared.pitch = actual.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH);
            adopt_owned_actor_pitch(player, prepared.pitch)
        } else {
            (actual - write.target).abs() <= VIEW_MATCH_EPSILON
        }
    });
    let view_active = prepared.flags & CAMERA_SCOPE_VIEW_ACTIVE != 0;
    let heading_handoff_succeeded = if view_active {
        unsafe { synchronize_owned_camera_heading(player, prepared.heading) }
    } else {
        release_owned_camera_heading(player)
    };
    let native_writes_succeeded =
        actor_heading_succeeded && actor_pitch_succeeded && heading_handoff_succeeded;
    if !native_writes_succeeded {
        request_reset();
        clear_preparing_camera_scope(generation, owner_thread);
        return None;
    }
    if RESET_GENERATION.load(Ordering::Acquire) != reset_generation
        || CAMERA_SCOPE_STATE.load(Ordering::Acquire) != SCOPE_PREPARING
        || CAMERA_SCOPE_GENERATION.load(Ordering::Relaxed) != generation
        || CAMERA_SCOPE_THREAD.load(Ordering::Relaxed) != owner_thread
    {
        return None;
    }
    CAMERA_SCOPE_PLAYER.store(pointer_word(player), Ordering::Relaxed);
    CAMERA_SCOPE_FLAGS.store(prepared.flags, Ordering::Relaxed);
    CAMERA_SCOPE_HEADING.store(prepared.heading.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_PITCH.store(prepared.pitch.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_X.store(prepared.follow_offset.x.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_Y.store(prepared.follow_offset.y.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_Z.store(prepared.follow_offset.z.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_X.store(prepared.motion_offset.x.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_Y.store(prepared.motion_offset.y.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_Z.store(prepared.motion_offset.z.to_bits(), Ordering::Relaxed);
    let active = CAMERA_SCOPE_STATE
        .compare_exchange(
            SCOPE_PREPARING,
            SCOPE_ACTIVE,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_ok();
    let scope = CameraUpdateScope {
        generation,
        player: pointer_word(player),
        thread: owner_thread,
        motion_sample: prepared.motion_sample,
    };
    if !active || RESET_GENERATION.load(Ordering::Acquire) != reset_generation {
        if active {
            leave_camera_update_scope(scope);
        } else {
            clear_preparing_camera_scope(generation, owner_thread);
        }
        return None;
    }
    if view_active {
        publish_safe_pitch(player, owner_thread, prepared.frame_id, prepared.pitch);
    } else {
        invalidate_safe_pitch();
    }
    Some(scope)
}

/// Release exactly the camera scope represented by `scope`.
pub(crate) fn leave_camera_update_scope(scope: CameraUpdateScope) {
    if CAMERA_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_ACTIVE
        && CAMERA_SCOPE_GENERATION.load(Ordering::Relaxed) == scope.generation
        && CAMERA_SCOPE_PLAYER.load(Ordering::Relaxed) == scope.player
        && CAMERA_SCOPE_THREAD.load(Ordering::Relaxed) == scope.thread
    {
        clear_camera_scope();
    }
}

fn activate_retained_view_scope(
    player: *mut c_void,
    pitch: f32,
    follow_offset: Vec3,
    motion_offset: Vec3,
    spatial_flags: u32,
    generation: u32,
    owner_thread: u32,
    reset_generation: u32,
) -> Option<CameraUpdateScope> {
    let Some(heading) = retained_explore_heading(player) else {
        clear_preparing_camera_scope(generation, owner_thread);
        return None;
    };
    if !pitch.is_finite()
        || !follow_offset.is_finite()
        || !motion_offset.is_finite()
        || !unsafe { synchronize_owned_camera_heading(player, heading) }
        || RESET_GENERATION.load(Ordering::Acquire) != reset_generation
        || CAMERA_SCOPE_STATE.load(Ordering::Acquire) != SCOPE_PREPARING
        || CAMERA_SCOPE_GENERATION.load(Ordering::Relaxed) != generation
        || CAMERA_SCOPE_THREAD.load(Ordering::Relaxed) != owner_thread
    {
        invalidate_heading_hold();
        clear_preparing_camera_scope(generation, owner_thread);
        return None;
    }

    CAMERA_SCOPE_PLAYER.store(pointer_word(player), Ordering::Relaxed);
    CAMERA_SCOPE_FLAGS.store(
        CAMERA_SCOPE_RETAINED_VIEW
            | spatial_flags & (CAMERA_SCOPE_FOLLOW_ACTIVE | CAMERA_SCOPE_MOTION_ACTIVE),
        Ordering::Relaxed,
    );
    CAMERA_SCOPE_HEADING.store(heading.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_PITCH.store(
        pitch.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH).to_bits(),
        Ordering::Relaxed,
    );
    CAMERA_SCOPE_FOLLOW_X.store(follow_offset.x.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_Y.store(follow_offset.y.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_Z.store(follow_offset.z.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_X.store(motion_offset.x.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_Y.store(motion_offset.y.to_bits(), Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_Z.store(motion_offset.z.to_bits(), Ordering::Relaxed);
    let active = CAMERA_SCOPE_STATE
        .compare_exchange(
            SCOPE_PREPARING,
            SCOPE_ACTIVE,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_ok();
    let scope = CameraUpdateScope {
        generation,
        player: pointer_word(player),
        thread: owner_thread,
        motion_sample: None,
    };
    if !active || RESET_GENERATION.load(Ordering::Acquire) != reset_generation {
        if active {
            leave_camera_update_scope(scope);
        } else {
            clear_preparing_camera_scope(generation, owner_thread);
        }
        return None;
    }
    diagnostics::mark_heading_hold();
    Some(scope)
}

/// Return the scoped logical heading for this player and owner thread.
pub(crate) fn scoped_camera_heading(player: *mut c_void) -> Option<f32> {
    if !camera_scope_matches(player)
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed)
            & (CAMERA_SCOPE_VIEW_ACTIVE | CAMERA_SCOPE_RETAINED_VIEW)
            == 0
    {
        return None;
    }
    let heading = f32::from_bits(CAMERA_SCOPE_HEADING.load(Ordering::Relaxed));
    heading.is_finite().then_some(heading)
}

/// Return the scoped logical pitch for this player and owner thread.
pub(crate) fn scoped_camera_pitch(player: *mut c_void) -> Option<f32> {
    if !camera_scope_matches(player)
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed)
            & (CAMERA_SCOPE_VIEW_ACTIVE | CAMERA_SCOPE_RETAINED_VIEW)
            == 0
    {
        return None;
    }
    let pitch = f32::from_bits(CAMERA_SCOPE_PITCH.load(Ordering::Relaxed));
    pitch.is_finite().then_some(pitch)
}

/// Return the last logical pitch only for an internal same-frame scope miss.
///
/// A completed native-owner observation invalidates this snapshot. The strict
/// identity checks prevent an old camera epoch from overriding POV, menu,
/// loading, player, or thread transitions.
pub(crate) fn fallback_camera_pitch(player: *mut c_void) -> Option<f32> {
    if !SAFE_PITCH_VALID.load(Ordering::Acquire)
        || !fallback_pitch_identity_matches(
            CameraSnapshotIdentity {
                player: SAFE_PITCH_PLAYER.load(Ordering::Relaxed),
                thread: SAFE_PITCH_THREAD.load(Ordering::Relaxed),
                frame: SAFE_PITCH_FRAME.load(Ordering::Relaxed),
                generation: SAFE_PITCH_RESET_GENERATION.load(Ordering::Relaxed),
            },
            CameraSnapshotIdentity {
                player: pointer_word(player),
                thread: get_current_thread_id(),
                frame: input_frame_id(),
                generation: RESET_GENERATION.load(Ordering::Acquire),
            },
        )
        || !CONFIG.load().movement_enabled()
    {
        return None;
    }
    let pitch = f32::from_bits(SAFE_PITCH_VALUE.load(Ordering::Relaxed));
    if pitch.is_finite() {
        diagnostics::mark_pitch_hold();
        Some(pitch)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CameraSnapshotIdentity {
    player: u32,
    thread: u32,
    frame: u32,
    generation: u32,
}

fn fallback_pitch_identity_matches(
    published: CameraSnapshotIdentity,
    current: CameraSnapshotIdentity,
) -> bool {
    current.player != 0 && published == current
}

/// Return the scoped axial-follow displacement for the active camera update.
pub(crate) fn scoped_follow_offset(player: *mut c_void) -> Option<Vec3> {
    if !camera_scope_matches(player)
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed) & CAMERA_SCOPE_FOLLOW_ACTIVE == 0
    {
        return None;
    }
    let follow = Vec3::new(
        f32::from_bits(CAMERA_SCOPE_FOLLOW_X.load(Ordering::Relaxed)),
        f32::from_bits(CAMERA_SCOPE_FOLLOW_Y.load(Ordering::Relaxed)),
        f32::from_bits(CAMERA_SCOPE_FOLLOW_Z.load(Ordering::Relaxed)),
    );
    follow.is_finite().then_some(follow)
}

/// Return the scoped post-solve motion displacement for the active update.
pub(crate) fn scoped_motion_offset(player: *mut c_void) -> Option<Vec3> {
    if !MOTION_POSITION_ACTIVE.load(Ordering::Acquire)
        || !camera_scope_matches(player)
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed) & CAMERA_SCOPE_MOTION_ACTIVE == 0
    {
        return None;
    }
    let motion = Vec3::new(
        f32::from_bits(CAMERA_SCOPE_MOTION_X.load(Ordering::Relaxed)),
        f32::from_bits(CAMERA_SCOPE_MOTION_Y.load(Ordering::Relaxed)),
        f32::from_bits(CAMERA_SCOPE_MOTION_Z.load(Ordering::Relaxed)),
    );
    motion.is_finite().then_some(motion)
}

/// Identity token for one native player-mover update invocation.
#[derive(Clone, Copy)]
pub(crate) struct MovementScope {
    generation: u32,
    mover: u32,
    thread: u32,
}

/// Admit one native player-mover call and return its exact identity token.
pub(crate) fn enter_movement_scope(mover: *mut c_void) -> Option<MovementScope> {
    if !HOOKS_ACTIVE.load(Ordering::Acquire)
        || !MOVEMENT_ACTIVE.load(Ordering::Acquire)
        || mover.is_null()
    {
        return None;
    }
    let reset_generation = RESET_GENERATION.load(Ordering::Acquire);
    if MOVEMENT_SCOPE_STATE
        .compare_exchange(
            SCOPE_IDLE,
            SCOPE_PREPARING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return None;
    }
    let generation = MOVEMENT_SCOPE_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let owner_thread = get_current_thread_id();
    let mover_word = pointer_word(mover);
    MOVEMENT_SCOPE_GENERATION.store(generation, Ordering::Relaxed);
    MOVEMENT_SCOPE_MOVER.store(mover_word, Ordering::Relaxed);
    MOVEMENT_SCOPE_THREAD.store(owner_thread, Ordering::Relaxed);

    let player = native::player();
    let admitted = RUNTIME
        .with_mut(|runtime| {
            let Some((frame, config)) = runtime.refresh(player) else {
                return false;
            };
            runtime.ownership.state().is_owned()
                && frame.hard_valid
                && config.movement_enabled()
                && frame.mover == mover
        })
        .unwrap_or(false);
    if !admitted {
        clear_preparing_movement_scope(generation, owner_thread);
        return None;
    }
    let active = MOVEMENT_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_PREPARING
        && MOVEMENT_SCOPE_GENERATION.load(Ordering::Relaxed) == generation
        && MOVEMENT_SCOPE_THREAD.load(Ordering::Relaxed) == owner_thread
        && MOVEMENT_SCOPE_STATE
            .compare_exchange(
                SCOPE_PREPARING,
                SCOPE_ACTIVE,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok();
    let scope = MovementScope {
        generation,
        mover: mover_word,
        thread: owner_thread,
    };
    if !active || RESET_GENERATION.load(Ordering::Acquire) != reset_generation {
        if active {
            clear_movement_scope();
        } else {
            clear_preparing_movement_scope(generation, owner_thread);
        }
        return None;
    }
    Some(scope)
}

/// Release exactly the movement scope represented by `scope`.
pub(crate) fn leave_movement_scope(scope: MovementScope) {
    if MOVEMENT_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_ACTIVE
        && MOVEMENT_SCOPE_GENERATION.load(Ordering::Relaxed) == scope.generation
        && MOVEMENT_SCOPE_MOVER.load(Ordering::Relaxed) == scope.mover
        && MOVEMENT_SCOPE_THREAD.load(Ordering::Relaxed) == scope.thread
    {
        clear_movement_scope();
    }
}

/// Build one complete camera-relative player movement transaction.
///
/// The virtual wrapper receives PlayerMover's finalized vector and complete
/// flags together, before it consumes either. Facing and compensation are
/// therefore derived from the same owned world heading and post-turn yaw,
/// while the complete engine-authored flags pass through unchanged.
pub(crate) fn movement_override(
    actor: *mut c_void,
    native_movement: Vec3,
    flags: u32,
    dt: f32,
) -> Option<MovementOutput> {
    if actor.is_null()
        || !native_movement.is_finite()
        || !dt.is_finite()
        || dt < 0.0
        || !movement_scope_matches()
    {
        return None;
    }
    let prepared = RUNTIME.with_mut(|runtime| {
        let (frame, config) = runtime.refresh(actor)?;
        if !runtime.ownership.state().is_owned()
            || !frame.hard_valid
            || !config.movement_enabled()
            || frame.player != actor
            || pointer_word(frame.mover) != MOVEMENT_SCOPE_MOVER.load(Ordering::Relaxed)
        {
            return None;
        }
        let (policy, recovery_weight) = if runtime.ownership.state() == OwnershipState::Combat {
            runtime.recenter_intent = None;
            (FacingPolicy::Combat, 0.0)
        } else {
            (
                FacingPolicy::Explore,
                runtime.combat_presentation.recovery_weight(),
            )
        };
        let live_intent = MovementIntent::new(native_movement, flags, runtime.view_yaw, policy);
        let live_movement_heading = live_intent.movement_heading();
        let movement_input_heading =
            live_movement_heading.map(|_| wrap_angle(native_movement.x.atan2(native_movement.y)));
        let input_changed = match (runtime.movement_input_heading, movement_input_heading) {
            (Some(previous), Some(current)) => {
                wrap_angle(current - previous).abs() > RECENTER_INPUT_CHANGE_RADIANS
            }
            (None, None) => false,
            _ => true,
        };
        if input_changed {
            runtime.manual_idle_seconds = 0.0;
            runtime.recenter_speed = 0.0;
            runtime.recenter_intent = None;
        }
        runtime.movement_input_heading = movement_input_heading;
        let movement_heading = match (policy, runtime.recenter_intent, movement_input_heading) {
            (FacingPolicy::Explore, Some(recenter), Some(local)) if recenter.matches(local) => {
                Some(recenter.world_travel_heading)
            }
            _ => live_movement_heading,
        };
        let intent = movement_heading.map_or(live_intent, |heading| {
            MovementIntent::with_world_heading(
                native_movement,
                flags,
                runtime.view_yaw,
                policy,
                heading,
            )
        });
        if let Some(heading) = movement_heading {
            runtime.last_movement_heading = heading;
            runtime.last_movement_magnitude = native_movement.horizontal_length();
        } else {
            runtime.last_movement_magnitude = 0.0;
            runtime.recenter_intent = None;
        }
        let facing_target = if recovery_weight > 0.0 {
            movement_heading.map(|heading| {
                wrap_angle(heading + wrap_angle(runtime.view_yaw - heading) * recovery_weight)
            })
        } else {
            intent.facing_target()
        };
        let mut next_turn_speed = runtime.actor_turn_speed;
        let facing = facing_target.map(|target| {
            step_heading(
                frame.actor_yaw,
                target,
                &mut next_turn_speed,
                config.turn_speed_radians(),
                config.turn_speed_radians() * 6.0,
                dt.clamp(0.0, MAX_DT),
            )
        });
        Some(PreparedMovement {
            intent,
            facing,
            logical_heading: runtime.view_yaw,
            next_turn_speed,
            player: runtime.player,
            epoch: runtime.ownership.epoch(),
        })
    })??;
    let actual_actor_yaw =
        apply_movement_heading(actor, prepared.facing, prepared.logical_heading)?;
    let output = prepared.intent.resolve(actual_actor_yaw);
    let _ = RUNTIME.with_mut(|runtime| {
        if runtime.ownership.state().is_owned()
            && runtime.ownership.epoch() == prepared.epoch
            && runtime.player == prepared.player
        {
            runtime.actor_turn_speed = prepared.next_turn_speed;
        }
    });
    Some(output)
}

fn apply_movement_heading(
    actor: *mut c_void,
    facing: Option<f32>,
    logical_heading: f32,
) -> Option<f32> {
    let old_actor_yaw = unsafe { native::raw_actor_yaw(actor) }?;
    let old_camera_offset = unsafe { native::raw_camera_heading_offset(actor) }?;
    let _facing_scope = if facing.is_some() {
        Some(FacingCallScope::enter()?)
    } else {
        None
    };
    if facing.is_some_and(|target| unsafe { !native::invoke_actor_yaw_setter(actor, target) }) {
        return None;
    }
    let actual_actor_yaw = unsafe { native::raw_actor_yaw(actor) };
    if let Some(actual_actor_yaw) = actual_actor_yaw
        && unsafe { synchronize_owned_camera_heading(actor, logical_heading) }
    {
        return Some(actual_actor_yaw);
    }

    // Actor yaw and camera offset form one visible-heading transaction. A
    // partial failure restores both values; only a failed rollback escalates
    // to a lifecycle reset.
    let actor_restored = if facing.is_some() {
        if !unsafe { native::invoke_actor_yaw_setter(actor, old_actor_yaw) } {
            false
        } else {
            unsafe { native::raw_actor_yaw(actor) }.is_some_and(|actual| {
                wrap_angle(actual - old_actor_yaw).abs() <= VIEW_MATCH_EPSILON
            })
        }
    } else {
        true
    };
    let offset_restored = unsafe { native::write_camera_heading_offset(actor, old_camera_offset) };
    if actor_restored && offset_restored {
        record_owned_camera_heading_offset(actor, old_camera_offset);
    } else {
        request_reset();
    }
    None
}

#[derive(Clone, Copy)]
struct PreparedMovement {
    intent: MovementIntent,
    facing: Option<f32>,
    logical_heading: f32,
    next_turn_speed: f32,
    player: u32,
    epoch: u32,
}

struct FacingCallScope;

impl FacingCallScope {
    fn enter() -> Option<Self> {
        FACING_CALL_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for FacingCallScope {
    fn drop(&mut self) {
        FACING_CALL_ACTIVE.store(false, Ordering::Release);
    }
}

/// Portion of a rendered cursor ray inside native player activation reach.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ViewReachInterval {
    entry: f32,
    exit: f32,
}

impl ViewReachInterval {
    /// Return the first nonnegative ray distance inside player reach.
    pub const fn entry(self) -> f32 {
        self.entry
    }

    /// Return the last ray distance inside player reach.
    pub const fn exit(self) -> f32 {
        self.exit
    }

    /// Return whether a native hit distance lies inside player reach.
    pub fn accepts_hit(self, distance: f32) -> bool {
        const REACH_EPSILON: f32 = 0.01;
        distance.is_finite()
            && distance + REACH_EPSILON >= self.entry
            && distance <= self.exit + REACH_EPSILON
    }
}

/// Intersect a unit cursor ray with the native eye-centered activation sphere.
///
/// `None` means the rendered cursor does not enter player reach or any input
/// is invalid. Returned distances are measured from `camera_origin`, so a far
/// third-person camera may cast farther without extending the player's world
/// activation radius.
pub fn view_reach_interval(
    native_eye: Vec3,
    camera_origin: Vec3,
    direction: Vec3,
    reach: f32,
) -> Option<ViewReachInterval> {
    if !native_eye.is_finite()
        || !camera_origin.is_finite()
        || !direction.is_finite()
        || !reach.is_finite()
        || reach <= 0.0
        || (direction.length_squared() - 1.0).abs() > 0.001
    {
        return None;
    }
    let camera_from_eye = camera_origin - native_eye;
    let projection = camera_from_eye.x.mul_add(
        direction.x,
        camera_from_eye
            .y
            .mul_add(direction.y, camera_from_eye.z * direction.z),
    );
    let discriminant = projection.mul_add(
        projection,
        reach.mul_add(reach, -camera_from_eye.length_squared()),
    );
    if !discriminant.is_finite() || discriminant < 0.0 {
        return None;
    }
    let radius = discriminant.sqrt();
    let entry = (-projection - radius).max(0.0);
    let exit = -projection + radius;
    (exit.is_finite() && exit > entry).then_some(ViewReachInterval { entry, exit })
}

/// Exact scalar outputs initialized by FNV ViewCaster on a no-hit result.
pub const fn view_cast_no_hit_outputs() -> (f32, u8) {
    (f32::MAX, 0)
}

/// Immutable view-ray sample paired with one ownership epoch and input frame.
#[derive(Clone, Copy)]
pub(crate) struct ViewCastPrepared {
    origin: Vec3,
    direction: Vec3,
    reach_start: f32,
    reach_end: f32,
}

impl ViewCastPrepared {
    pub(crate) const fn origin(self) -> Vec3 {
        self.origin
    }

    pub(crate) const fn direction(self) -> Vec3 {
        self.direction
    }

    pub(crate) fn cast_distance(self) -> Option<f32> {
        (self.reach_end.is_finite() && self.reach_end > 0.0).then_some(self.reach_end)
    }

    pub(crate) fn accepts_hit(self, distance: f32) -> bool {
        ViewReachInterval {
            entry: self.reach_start,
            exit: self.reach_end,
        }
        .accepts_hit(distance)
    }
}

pub(crate) fn prepare_view_cast(origin: Vec3, max_distance: f32) -> Option<ViewCastPrepared> {
    if !RETICLE_ACTIVE.load(Ordering::Acquire)
        || !origin.is_finite()
        || !max_distance.is_finite()
        || max_distance <= 0.0
    {
        return None;
    }
    let player = native::player();
    RUNTIME.with_mut(|runtime| {
        let (frame, config) = runtime.refresh(player)?;
        if !runtime.ownership.state().is_owned()
            || !frame.hard_valid
            || !runtime_camera_enabled(config)
            || frame.player != player
        {
            return None;
        }
        let camera_origin = unsafe { native::render_camera_origin()? };
        let ray =
            third_person_view_ray(origin, camera_origin, runtime.view_yaw, runtime.view_pitch)?;
        // Preserve native player reach rather than extending it by camera
        // distance. Only the portion of the rendered cursor ray inside the
        // native eye-centered reach sphere may publish a selected reference.
        let direction = ray.direction();
        let interval = view_reach_interval(origin, ray.origin(), direction, max_distance);
        let (reach_start, reach_end) = interval
            .map(|interval| (interval.entry(), interval.exit()))
            .unwrap_or((0.0, 0.0));
        Some(ViewCastPrepared {
            origin: ray.origin(),
            direction,
            reach_start,
            reach_end,
        })
    })?
}

pub(crate) fn prepare_spawn(
    projectile: *mut c_void,
    source: *mut c_void,
    weapon: *mut c_void,
    native_final: AimAngles,
) -> Option<(Vec3, AimAngles)> {
    if !CONVERGENCE_ACTIVE.load(Ordering::Acquire) || source != native::player() {
        return None;
    }

    // Establish current ownership before touching weapon, projectile,
    // skeleton, or node memory. The interaction ViewCaster is deliberately
    // absent: its eye-sphere result is reach-limited and cannot be a ballistic
    // target for a distant shoulder camera.
    let request = RUNTIME.with_mut(|runtime| {
        let (frame, config) = runtime.refresh(source)?;
        if !runtime.ownership.state().is_owned()
            || !frame.hard_valid
            || !config.movement_enabled()
            || frame.player != source
        {
            return None;
        }
        let origin = unsafe { native::render_camera_origin()? };
        let direction = view_direction(runtime.view_yaw, runtime.view_pitch)?;
        Some(CombatAimRequest {
            origin,
            direction,
            player: pointer_word(source),
            frame_id: frame.frame_id,
            epoch: runtime.ownership.epoch(),
            cached: runtime.combat_aim,
        })
    })??;

    let range = unsafe { native::admitted_projectile_range(projectile, weapon)? };
    let (muzzle, native_base) = unsafe { native::real_muzzle(source, weapon)? };
    let distance = if request.cached.matches(request, range) {
        request.cached.distance
    } else {
        let distance = unsafe {
            native::combat_ray_distance(source, request.origin, request.direction, range)?
        };
        let sample = CombatAimSample {
            valid: true,
            origin: request.origin,
            direction: request.direction,
            distance,
            range,
            player: request.player,
            frame_id: request.frame_id,
            epoch: request.epoch,
        };
        // Shotguns and other multi-projectile attacks invoke the launch seam
        // repeatedly in one input frame. Publish the immutable depth after the
        // engine ray returns so every pellet shares one collision query while
        // retaining its independently sampled native spread.
        let _ = RUNTIME.with_mut(|runtime| {
            if runtime.ownership.state().is_owned()
                && runtime.ownership.epoch() == request.epoch
                && runtime.player == request.player
                && runtime.last_frame_id == request.frame_id
            {
                runtime.combat_aim = sample;
            }
        });
        distance
    };
    let ray = ViewRay::from_parts(request.origin, request.direction);
    let target = ray.point_at(distance)?;
    let angles = converge_angles(muzzle, target, native_base, native_final)?;
    Some((muzzle, angles))
}

#[derive(Clone, Copy, Debug, Default)]
struct CombatAimSample {
    valid: bool,
    origin: Vec3,
    direction: Vec3,
    distance: f32,
    range: f32,
    player: u32,
    frame_id: u32,
    epoch: u32,
}

impl CombatAimSample {
    fn matches(self, request: CombatAimRequest, range: f32) -> bool {
        self.valid
            && self.player == request.player
            && self.frame_id == request.frame_id
            && self.epoch == request.epoch
            && self.origin == request.origin
            && self.direction == request.direction
            && self.range.to_bits() == range.to_bits()
            && self.distance.is_finite()
            && (0.0..=range).contains(&self.distance)
    }
}

#[derive(Clone, Copy)]
struct CombatAimRequest {
    origin: Vec3,
    direction: Vec3,
    player: u32,
    frame_id: u32,
    epoch: u32,
    cached: CombatAimSample,
}

struct FramingStore {
    borrowed: AtomicBool,
    state: UnsafeCell<FramingState>,
}

// Framing reconciliation is game-thread work. The lease still makes an
// unexpected overlapping MCM/camera callback fail closed without exposing two
// mutable references to the captured native baseline.
unsafe impl Sync for FramingStore {}

impl FramingStore {
    const fn new() -> Self {
        Self {
            borrowed: AtomicBool::new(false),
            state: UnsafeCell::new(FramingState::new()),
        }
    }

    fn reconcile(&self, config: ThirdPersonConfig, requested: bool) -> Option<bool> {
        self.borrowed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        struct Release<'a>(&'a AtomicBool);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let release = Release(&self.borrowed);
        let result = unsafe { &mut *self.state.get() }.reconcile(config, requested);
        drop(release);
        Some(result)
    }
}

#[derive(Clone, Copy)]
struct FramingState {
    active: bool,
    baseline: native::NativeFraming,
    last_written: native::NativeFraming,
}

impl FramingState {
    const fn new() -> Self {
        let empty = native::NativeFraming {
            minimum_distance: 0.0,
            maximum_distance: 0.0,
            vanity_maximum_distance: 0.0,
            side_offset: 0.0,
            height_offset: 0.0,
        };
        Self {
            active: false,
            baseline: empty,
            last_written: empty,
        }
    }

    fn reconcile(&mut self, config: ThirdPersonConfig, requested: bool) -> bool {
        if !requested {
            if self.active {
                unsafe { native::restore_framing(self.baseline, self.last_written) };
                self.active = false;
            }
            return true;
        }

        let desired = native::NativeFraming {
            minimum_distance: config.minimum_distance(),
            maximum_distance: config.maximum_distance(),
            vanity_maximum_distance: config.maximum_distance(),
            side_offset: config.side_offset(),
            height_offset: config.height_offset(),
        };
        if !self.active {
            let Some(baseline) = (unsafe { native::read_framing() }) else {
                return false;
            };
            if !unsafe { native::write_framing(desired) }
                || !unsafe { native::write_desired_distance(config.start_distance()) }
            {
                unsafe { native::restore_framing(baseline, desired) };
                return false;
            }
            self.baseline = baseline;
            self.last_written = desired;
            self.active = true;
            return true;
        }

        if !unsafe { native::write_framing(desired) } {
            return false;
        }
        self.last_written = desired;
        if let Some(distance) = unsafe { native::desired_distance() } {
            let clamped = distance.clamp(config.minimum_distance(), config.maximum_distance());
            if clamped.to_bits() != distance.to_bits() {
                let _ = unsafe { native::write_desired_distance(clamped) };
            }
        }
        true
    }
}

fn reconcile_framing() {
    if !FRAMING_DIRTY.load(Ordering::Acquire) || !FRAMING_DIRTY.swap(false, Ordering::AcqRel) {
        return;
    }
    if !FRAMING_CONTRACT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let config = CONFIG.load();
    let requested = config.framing_enabled() && !external_owner_active();
    if FRAMING.reconcile(config, requested) != Some(true) {
        FRAMING_DIRTY.store(true, Ordering::Release);
    }
}

struct RuntimeStore {
    borrowed: AtomicBool,
    state: UnsafeCell<RuntimeState>,
}

// `borrowed` is the exclusive lease for `state`. Every read or write follows
// a successful acquire transition and the guard publishes release on return.
// Contention never blocks: the caller chains native behavior instead.
unsafe impl Sync for RuntimeStore {}

impl RuntimeStore {
    const fn new() -> Self {
        Self {
            borrowed: AtomicBool::new(false),
            state: UnsafeCell::new(RuntimeState::new()),
        }
    }

    fn with_mut<R>(&self, operation: impl FnOnce(&mut RuntimeState) -> R) -> Option<R> {
        self.borrowed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        struct Release<'a>(&'a AtomicBool);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let release = Release(&self.borrowed);
        let result = operation(unsafe { &mut *self.state.get() });
        drop(release);
        Some(result)
    }
}

/// One held input direction and the world travel direction it owned when
/// camera recentering began.
#[derive(Clone, Copy, Debug, PartialEq)]
struct RecenterIntent {
    local_input_heading: f32,
    world_travel_heading: f32,
}

impl RecenterIntent {
    fn new(local_input_heading: f32, world_travel_heading: f32) -> Option<Self> {
        (local_input_heading.is_finite() && world_travel_heading.is_finite()).then_some(Self {
            local_input_heading: wrap_angle(local_input_heading),
            world_travel_heading: wrap_angle(world_travel_heading),
        })
    }

    fn matches(self, local_input_heading: f32) -> bool {
        local_input_heading.is_finite()
            && wrap_angle(local_input_heading - self.local_input_heading).abs()
                <= RECENTER_INPUT_CHANGE_RADIANS
    }
}

struct RuntimeState {
    ownership: OwnershipMachine,
    native_handoff: NativeHandoffGuard,
    heading_handoff_required: bool,
    heading_continuity: HeadingContinuity,
    combat_presentation: CombatPresentation,
    hip_fire_presentation: HipFirePresentation,
    hip_fire_pose_published: bool,
    hip_fire_release_pending: bool,
    hip_fire_release_seconds: f32,
    hip_fire_graph_signature: u32,
    hip_fire_graph_bridge_seconds: f32,
    hip_fire_process_aim_seconds: f32,
    hip_fire_process_aim_blocked: bool,
    motion_aiming: bool,
    player: u32,
    cell: u32,
    last_frame_id: u32,
    view_yaw: f32,
    view_pitch: f32,
    follow: FollowSolver,
    motion: MotionGenerator,
    motion_offset: Vec3,
    retained_follow_offset: Vec3,
    retained_motion_offset: Vec3,
    retained_spatial_flags: u32,
    render_motion_rotation: Vec3,
    last_camera_frame: u32,
    manual_idle_seconds: f32,
    recenter_speed: f32,
    recenter_intent: Option<RecenterIntent>,
    movement_input_heading: Option<f32>,
    actor_turn_speed: f32,
    last_movement_heading: f32,
    last_movement_magnitude: f32,
    native_pitch_owned: bool,
    combat_aim: CombatAimSample,
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            ownership: OwnershipMachine::new(),
            native_handoff: NativeHandoffGuard::new(),
            heading_handoff_required: true,
            heading_continuity: HeadingContinuity::new(),
            combat_presentation: CombatPresentation::new(),
            hip_fire_presentation: HipFirePresentation::new(),
            hip_fire_pose_published: false,
            hip_fire_release_pending: false,
            hip_fire_release_seconds: 0.0,
            hip_fire_graph_signature: 0,
            hip_fire_graph_bridge_seconds: HIP_FIRE_GRAPH_BRIDGE_SECONDS + MAX_DT,
            hip_fire_process_aim_seconds: 0.0,
            hip_fire_process_aim_blocked: false,
            motion_aiming: false,
            player: 0,
            cell: 0,
            last_frame_id: 0,
            view_yaw: 0.0,
            view_pitch: 0.0,
            follow: FollowSolver::new(),
            motion: MotionGenerator::new(),
            motion_offset: Vec3::new(0.0, 0.0, 0.0),
            retained_follow_offset: Vec3::new(0.0, 0.0, 0.0),
            retained_motion_offset: Vec3::new(0.0, 0.0, 0.0),
            retained_spatial_flags: 0,
            render_motion_rotation: Vec3::new(0.0, 0.0, 0.0),
            last_camera_frame: 0,
            manual_idle_seconds: 0.0,
            recenter_speed: 0.0,
            recenter_intent: None,
            movement_input_heading: None,
            actor_turn_speed: 0.0,
            last_movement_heading: 0.0,
            last_movement_magnitude: 0.0,
            native_pitch_owned: false,
            combat_aim: CombatAimSample {
                valid: false,
                origin: Vec3::new(0.0, 0.0, 0.0),
                direction: Vec3::new(0.0, 0.0, 0.0),
                distance: 0.0,
                range: 0.0,
                player: 0,
                frame_id: 0,
                epoch: 0,
            },
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn clear_hip_fire_pose(&mut self) {
        self.hip_fire_presentation.reset();
        if self.hip_fire_pose_published {
            publish_hip_fire_pose(core::ptr::null_mut(), false);
            self.hip_fire_pose_published = false;
        }
        self.hip_fire_release_pending = false;
        self.hip_fire_release_seconds = 0.0;
        self.hip_fire_graph_signature = 0;
        self.hip_fire_graph_bridge_seconds = HIP_FIRE_GRAPH_BRIDGE_SECONDS + MAX_DT;
        self.hip_fire_process_aim_seconds = 0.0;
        self.hip_fire_process_aim_blocked = false;
        self.motion_aiming = false;
    }

    fn reconcile_hip_fire_pose(
        &mut self,
        player: *mut c_void,
        requested: bool,
        natural_release: bool,
        release_allowed: bool,
        delta_seconds: f32,
    ) {
        if requested {
            self.hip_fire_release_pending = false;
            self.hip_fire_release_seconds = 0.0;
            if self.hip_fire_pose_published {
                return;
            }

            // Publish before the entry morph so any nested native animation
            // request observes one coherent session. Explicit transitions call
            // the captured predecessor and therefore do not recurse through the
            // Atom detour themselves.
            publish_hip_fire_pose(player, true);
            self.hip_fire_pose_published = true;
            if let native::HipFireTransition::Morph { anim_data, group } =
                unsafe { native::hip_fire_transition_group(player, true) }
            {
                let _ = unsafe { hooks::morph_hip_fire_group(anim_data, group) };
            }
            return;
        }

        if self.hip_fire_pose_published {
            // Stop remapping before any native relaxation. ADS and hard-owner
            // handoffs deliberately do not synthesize a false aim edge; only
            // expiry of Atom's own quiet interval requests reconciliation.
            publish_hip_fire_pose(core::ptr::null_mut(), false);
            self.hip_fire_pose_published = false;
            self.hip_fire_release_pending = natural_release && release_allowed;
            self.hip_fire_release_seconds = 0.0;
        }
        if !release_allowed {
            self.hip_fire_release_pending = false;
            self.hip_fire_release_seconds = 0.0;
        }
        if !self.hip_fire_release_pending {
            return;
        }

        let dt = if delta_seconds.is_finite() && delta_seconds > 0.0 {
            delta_seconds.min(MAX_DT)
        } else {
            0.0
        };
        self.hip_fire_release_seconds =
            (self.hip_fire_release_seconds + dt).min(HIP_FIRE_RELEASE_RETRY_SECONDS + MAX_DT);
        if self.hip_fire_release_seconds >= HIP_FIRE_RELEASE_RETRY_SECONDS {
            self.hip_fire_release_pending = false;
            self.hip_fire_release_seconds = 0.0;
        }
    }

    fn take_hip_fire_release_command(
        &mut self,
        frame: native::NativeFrame,
    ) -> Option<HipFireReleaseCommand> {
        if !self.hip_fire_release_pending {
            return None;
        }
        self.hip_fire_release_pending = false;
        Some(HipFireReleaseCommand {
            player: pointer_word(frame.player),
            frame_id: frame.frame_id,
            epoch: self.ownership.epoch(),
        })
    }

    fn complete_hip_fire_release(&mut self, command: HipFireReleaseCommand, invoked: bool) {
        if self.player == command.player
            && self.last_frame_id == command.frame_id
            && self.ownership.epoch() == command.epoch
        {
            if invoked {
                self.hip_fire_release_seconds = 0.0;
            } else if !self.hip_fire_presentation.active() {
                // A transient native precondition may clear on the next
                // camera frame. Restore the bounded request only while this
                // is still the same completed hip-fire session.
                self.hip_fire_release_pending = true;
            }
        }
    }

    fn clear_temporal(&mut self) {
        clear_zoom_residual();
        self.follow = FollowSolver::new();
        self.heading_continuity = HeadingContinuity::new();
        self.combat_presentation.reset();
        self.clear_hip_fire_pose();
        self.motion.reset();
        self.motion_offset = Vec3::default();
        self.retained_follow_offset = Vec3::default();
        self.retained_motion_offset = Vec3::default();
        self.retained_spatial_flags = 0;
        self.render_motion_rotation = Vec3::default();
        self.last_camera_frame = 0;
        self.manual_idle_seconds = 0.0;
        self.recenter_speed = 0.0;
        self.recenter_intent = None;
        self.movement_input_heading = None;
        self.actor_turn_speed = 0.0;
        self.last_movement_magnitude = 0.0;
        self.native_pitch_owned = false;
        self.combat_aim = CombatAimSample::default();
    }

    fn seed(&mut self, frame: native::NativeFrame) {
        self.player = pointer_word(frame.player);
        self.cell = pointer_word(frame.cell);
        self.view_yaw = frame.camera_heading;
        self.view_pitch = frame.pitch.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH);
        self.follow.reset(frame.pivot);
        self.clear_temporal_after_follow_seed();
    }

    fn clear_temporal_after_follow_seed(&mut self) {
        clear_zoom_residual();
        self.last_camera_frame = 0;
        self.heading_continuity = HeadingContinuity::new();
        self.combat_presentation.reset();
        self.clear_hip_fire_pose();
        self.motion.reset();
        self.motion_offset = Vec3::default();
        self.retained_follow_offset = Vec3::default();
        self.retained_motion_offset = Vec3::default();
        self.retained_spatial_flags = 0;
        self.render_motion_rotation = Vec3::default();
        self.manual_idle_seconds = 0.0;
        self.recenter_speed = 0.0;
        self.recenter_intent = None;
        self.movement_input_heading = None;
        self.actor_turn_speed = 0.0;
        self.last_movement_heading = 0.0;
        self.last_movement_magnitude = 0.0;
        self.native_pitch_owned = false;
        self.combat_aim = CombatAimSample::default();
    }

    fn refresh(
        &mut self,
        expected_player: *mut c_void,
    ) -> Option<(native::NativeFrame, ThirdPersonConfig)> {
        if RESET_REQUESTED.swap(false, Ordering::AcqRel) {
            self.reset();
        }
        let controls = *CONTROLS.get()?;
        let config = CONFIG.load();
        let frame = unsafe { native::observe(expected_player, controls) };
        let external_owner = external_owner_active();
        let native_combat = frame.weapon_out && frame.combat_intent;
        let immediate_combat = frame.weapon_out && (!config.drawn_360() || native_combat);
        let fighting_owner = immediate_combat
            && unsafe { native::fighting_control_disabled(frame.player, controls) };
        let enabled = runtime_camera_enabled(config);
        let frame_advanced = frame.frame_id != self.last_frame_id;
        let presentation_valid = enabled
            && frame.hard_valid
            && frame.stable_third_person
            && frame.world_ready
            && frame.weapon_out
            && !frame.native_owner
            && !external_owner
            && !fighting_owner;
        let ranged_weapon =
            presentation_valid && unsafe { native::hip_fire_weapon_supported(frame.player) };
        let native_hip_fire = frame_advanced && native::hip_fire_requested(frame.combat_intent);
        if frame_advanced {
            if native_hip_fire {
                self.hip_fire_graph_bridge_seconds = 0.0;
            } else {
                self.hip_fire_graph_bridge_seconds = (self.hip_fire_graph_bridge_seconds
                    + bounded_delta(frame.delta_seconds))
                .min(HIP_FIRE_GRAPH_BRIDGE_SECONDS + MAX_DT);
            }
        }
        let graph_bridge_active =
            self.hip_fire_graph_bridge_seconds <= HIP_FIRE_GRAPH_BRIDGE_SECONDS;
        let graph_signature = (frame_advanced
            && ranged_weapon
            && graph_bridge_active
            && (native_hip_fire || self.hip_fire_presentation.active()))
        .then(|| unsafe { native::hip_fire_attack_sequence_signature(frame.player) })
        .flatten();
        let graph_attack_edge = graph_bridge_active
            && graph_signature.is_some_and(|signature| signature != self.hip_fire_graph_signature);
        if let Some(signature) = graph_signature {
            self.hip_fire_graph_signature = signature;
        } else if frame_advanced && self.hip_fire_presentation.active() {
            self.hip_fire_graph_signature = 0;
        }
        // Graph changes can bridge a replacement animation's admission edge,
        // but only close to real input/process fire. The hard time bound also
        // guarantees release if a provider churns sequence objects or slots.
        let hip_fire_activity = ranged_weapon && (native_hip_fire || graph_attack_edge);
        let physical_aim = unsafe { native::player_aim_input_requested(frame.player) };
        let process_aim = unsafe { native::player_process_aiming(frame.player) };
        if frame_advanced {
            if hip_fire_activity || self.hip_fire_presentation.active() {
                // Some animation controllers can retain IsAiming after
                // automatic fire. Quarantine that process bit until it clears
                // or a real aim input proves a new ADS transition.
                self.hip_fire_process_aim_blocked = true;
            } else if !process_aim || physical_aim {
                self.hip_fire_process_aim_blocked = false;
            }
            if !ranged_weapon
                || physical_aim
                || hip_fire_activity
                || self.hip_fire_presentation.active()
                || self.hip_fire_process_aim_blocked
            {
                self.hip_fire_process_aim_seconds = 0.0;
            } else if process_aim {
                let dt = bounded_delta(frame.delta_seconds);
                self.hip_fire_process_aim_seconds = (self.hip_fire_process_aim_seconds + dt)
                    .min(HIP_FIRE_PROCESS_AIM_SETTLE_SECONDS);
            } else {
                self.hip_fire_process_aim_seconds = 0.0;
            }
        }
        let settled_process_aim = process_aim
            && !self.hip_fire_process_aim_blocked
            && !self.hip_fire_presentation.active()
            && !hip_fire_activity
            && self.hip_fire_process_aim_seconds >= HIP_FIRE_PROCESS_AIM_SETTLE_SECONDS;
        self.motion_aiming = physical_aim || settled_process_aim;
        let hip_fire_context_valid = ranged_weapon && !physical_aim && !settled_process_aim;
        let hip_fire_was_active = self.hip_fire_presentation.active();
        self.hip_fire_presentation.advance(
            hip_fire_activity,
            hip_fire_context_valid,
            frame.delta_seconds,
            frame_advanced,
        );
        let natural_hip_fire_release = frame_advanced
            && hip_fire_was_active
            && !self.hip_fire_presentation.active()
            && hip_fire_context_valid
            && presentation_valid
            && !hip_fire_activity;
        // Keep camera-facing Combat active through the complete debounced
        // weapon-ready session. Its grace/fade and recovery may begin only
        // after the posture owner releases, otherwise Explore movement can
        // rotate the body while the graph still visibly presents Combat.
        self.combat_presentation.advance(
            native_combat
                || self.hip_fire_presentation.active()
                || self.hip_fire_release_pending
                || natural_hip_fire_release,
            presentation_valid,
            frame.delta_seconds,
            frame_advanced,
        );
        let combat_presentation = self.combat_presentation;
        let hip_fire_presentation = self.hip_fire_presentation;
        let combat = frame.weapon_out
            && (!config.drawn_360()
                || self.combat_presentation.owns_combat_facing()
                || self.hip_fire_presentation.active()
                || self.hip_fire_release_pending
                || natural_hip_fire_release);
        let player_word = pointer_word(frame.player);
        let observed_cell = pointer_word(frame.cell);
        let proven_view_owner = frame.rejection.owns_heading() || external_owner || fighting_owner;
        // A missing capability pointer is not evidence that another camera
        // owner took the view. Retain the established player/cell epoch while
        // stable third person still identifies the same player. Capability
        // entry points continue to require `frame.hard_valid` independently.
        let retained_view_identity = self.ownership.state().is_owned()
            && player_word != 0
            && self.player == player_word
            && self.cell != 0
            && frame.stable_third_person
            && !proven_view_owner
            && (observed_cell == 0 || observed_cell == self.cell);
        let ownership_cell = if observed_cell != 0 {
            observed_cell
        } else if retained_view_identity {
            self.cell
        } else {
            0
        };
        let ownership_world_ready = frame.world_ready || retained_view_identity;
        let native_state_clear = enabled
            && frame.stable_third_person
            && player_word != 0
            && ownership_cell != 0
            && !proven_view_owner;
        let handoff_delta = if frame_advanced {
            frame.delta_seconds
        } else {
            0.0
        };
        let handoff_ready = self
            .native_handoff
            .advance(native_state_clear, handoff_delta);
        let native_owner = proven_view_owner || !handoff_ready;
        let input = OwnershipInput::new(
            enabled,
            frame.stable_third_person,
            native_owner,
            ownership_world_ready,
            combat,
            ownership_cell,
        );

        if frame.frame_id != self.last_frame_id {
            let transition = self.ownership.advance(input);
            self.last_frame_id = frame.frame_id;
            if transition.begins_acquire() {
                self.seed(frame);
                // Acquisition clears prior temporal state, but the combat
                // edge belongs to this newly seeded epoch and must survive the
                // seed so a fast tap cannot be lost before native admission.
                self.combat_presentation = combat_presentation;
                self.hip_fire_presentation = hip_fire_presentation;
            } else if transition.current() == OwnershipState::Release {
                self.native_handoff.reset();
                self.clear_temporal();
            }
        } else if self.ownership.state().is_owned()
            && (native_owner
                || self.player != player_word
                || (observed_cell != 0 && self.cell != observed_cell))
        {
            // Loading can swap the player or parent cell between native calls
            // that share an input-frame id. Revoke immediately instead of
            // waiting for the next normal classifier advance.
            self.ownership.force_release();
            self.native_handoff.reset();
            self.clear_temporal();
        }
        if frame_advanced {
            let hip_fire_animation_supported = HIP_FIRE_POSE_ADMITTED.load(Ordering::Acquire)
                && unsafe { native::hip_fire_is_animation_supported(frame.player) };
            let hip_fire_pose_requested = self.ownership.state().is_owned()
                && hip_fire_context_valid
                && hip_fire_animation_supported
                && self.hip_fire_presentation.active();
            let hip_fire_release_allowed = self.ownership.state().is_owned()
                && presentation_valid
                && hip_fire_context_valid
                && hip_fire_animation_supported;
            self.reconcile_hip_fire_pose(
                frame.player,
                hip_fire_pose_requested,
                natural_hip_fire_release,
                hip_fire_release_allowed,
                frame.delta_seconds,
            );
        }
        self.update_heading_handoff(
            frame,
            config,
            frame_advanced,
            external_owner || fighting_owner,
            combat,
        );
        diagnostics::mark_observation(
            if external_owner {
                native::NativeRejection::ExternalOwner
            } else if fighting_owner {
                native::NativeRejection::DisabledControls
            } else {
                frame.rejection
            },
            self.ownership.state().is_owned(),
        );
        Some((frame, config))
    }

    fn update_heading_handoff(
        &mut self,
        frame: native::NativeFrame,
        config: ThirdPersonConfig,
        frame_advanced: bool,
        hard_owner: bool,
        combat: bool,
    ) {
        let atom_view_requested =
            config.movement_enabled() && MOVEMENT_ACTIVE.load(Ordering::Acquire);
        // Camera feature admission and camera ownership are different
        // contracts. Rough terrain can temporarily remove the mover,
        // collision owner, controller, or active 3D and must fail that frame's
        // follow/movement work, but none of those gaps transfers visible yaw
        // to another camera. Keep +0x6E4 durable until an explicit native or
        // registered external owner actually takes the view.
        // Never create a retained heading from default RuntimeState data while
        // native acquisition/handoff is still in progress. Internal gaps may
        // continue only a token published by an actually owned Explore or
        // Combat epoch for this same player and reset generation.
        let retained_heading_owned = self.ownership.state().is_owned()
            || (self.player == pointer_word(frame.player) && heading_hold_matches(frame.player));
        let heading_storage_valid = atom_view_requested
            && retained_heading_owned
            && frame.stable_third_person
            && pointer_word(frame.player) != 0
            && self.player == pointer_word(frame.player)
            && frame.camera_heading.is_finite()
            && frame.camera_heading_offset.is_finite()
            && frame.delta_seconds.is_finite()
            && frame.delta_seconds >= 0.0;
        let event = if !heading_storage_valid || hard_owner || frame.rejection.owns_heading() {
            HeadingContinuityEvent::HardOwner
        } else {
            HeadingContinuityEvent::Stable
        };
        let continuity_delta = if frame_advanced {
            frame.delta_seconds
        } else {
            0.0
        };
        self.heading_handoff_required = !self.heading_continuity.advance(event, continuity_delta);

        if self.heading_handoff_required {
            invalidate_heading_hold();
        } else {
            publish_heading_hold(frame.player, self.view_yaw, combat);
        }
    }

    fn prepare_camera_frame(&mut self, player: *mut c_void) -> Option<PreparedCameraFrame> {
        let (frame, config) = self.refresh(player)?;
        if !self.ownership.state().is_owned() || !frame.hard_valid || frame.player != player {
            return None;
        }

        let follow_enabled = config.follow_enabled() && FOLLOW_ACTIVE.load(Ordering::Acquire);
        let movement_enabled = config.movement_enabled() && MOVEMENT_ACTIVE.load(Ordering::Acquire);
        let framing_enabled =
            config.framing_enabled() && FRAMING_CONTRACT_ACTIVE.load(Ordering::Acquire);
        let motion_enabled =
            config.motion_enabled() && MOTION_GENERATOR_ACTIVE.load(Ordering::Acquire);
        let motion_position_enabled =
            motion_enabled && MOTION_POSITION_ACTIVE.load(Ordering::Acquire);
        let hip_fire_release = self.take_hip_fire_release_command(frame);
        if !follow_enabled
            && !movement_enabled
            && !framing_enabled
            && !motion_enabled
            && hip_fire_release.is_none()
        {
            return None;
        }

        let motion_sample = self.advance_camera_temporal(
            frame,
            config,
            follow_enabled,
            movement_enabled,
            motion_enabled,
        );

        let aim_requested = self.motion_aiming;
        let vertical_route =
            vertical_look_route(self.ownership.state(), movement_enabled, aim_requested);
        let neutralize_actor_pitch = advance_actor_pitch_ownership(
            &mut self.native_pitch_owned,
            vertical_route,
            frame.pitch,
        );
        // Releasing combat ownership must never synthesize Actor pitch. FNV's
        // native look route owns the last combat value; Explore only clears it
        // at its existing ownership edge. Interpolating this scalar made the
        // body look down and rotate against the camera after the quiet timer.
        let actor_pitch_write = if neutralize_actor_pitch {
            Some(PreparedActorPitchWrite {
                target: 0.0,
                adopt_result: false,
            })
        } else if vertical_route == LookRoute::NativeAndSynchronize
            && (frame.pitch - self.view_pitch).abs() > VIEW_MATCH_EPSILON
        {
            Some(PreparedActorPitchWrite {
                target: self.view_pitch,
                adopt_result: true,
            })
        } else {
            None
        };
        let horizontal_route =
            horizontal_look_route(self.ownership.state(), movement_enabled, aim_requested);
        let align_actor_heading =
            actor_heading_handoff_target(horizontal_route, frame.actor_yaw, self.view_yaw);

        let follow_offset = if follow_enabled {
            let solved = self.follow.position() - frame.pivot;
            // FNV already translates the camera with the player. Publishing
            // unconstrained world-space spring lag moves the camera sideways
            // when the player strafes, so locomotion visibly steers the view
            // even though logical yaw is unchanged. Restrict follow response
            // to the current view axis: it may vary chase distance but cannot
            // change yaw or pitch. Native collision still receives the exact
            // player pivot and complete desired-camera segment.
            axial_follow_offset(solved, self.view_yaw, self.view_pitch)?
        } else {
            Vec3::default()
        };
        if !self.view_yaw.is_finite()
            || !self.view_pitch.is_finite()
            || !follow_offset.is_finite()
            || !self.motion_offset.is_finite()
        {
            return None;
        }

        let mut flags = 0;
        if movement_enabled {
            flags |= CAMERA_SCOPE_VIEW_ACTIVE;
        }
        if follow_enabled {
            flags |= CAMERA_SCOPE_FOLLOW_ACTIVE;
        }
        if motion_position_enabled {
            flags |= CAMERA_SCOPE_MOTION_ACTIVE;
        }
        // These are the last complete spatial contributions. A feature-only
        // observation gap may reuse axial follow with the next native ray and
        // procedural motion with the next completed native position.
        self.retained_follow_offset = follow_offset;
        self.retained_motion_offset = self.motion_offset;
        self.retained_spatial_flags =
            flags & (CAMERA_SCOPE_FOLLOW_ACTIVE | CAMERA_SCOPE_MOTION_ACTIVE);
        Some(PreparedCameraFrame {
            flags,
            frame_id: frame.frame_id,
            heading: self.view_yaw,
            pitch: self.view_pitch,
            align_actor_heading,
            actor_pitch_write,
            follow_offset,
            motion_offset: self.motion_offset,
            motion_sample,
            hip_fire_release,
        })
    }

    fn advance_camera_temporal(
        &mut self,
        frame: native::NativeFrame,
        config: ThirdPersonConfig,
        follow_enabled: bool,
        movement_enabled: bool,
        motion_enabled: bool,
    ) -> Option<super::NativeMotionCarrier> {
        if self.last_camera_frame == frame.frame_id {
            return None;
        }

        // Follow-only mode leaves native actor/view coupling intact. Copy the
        // current adjusted heading every frame so follow axes never retain the
        // acquisition-time direction after native look.
        if !movement_enabled {
            self.view_yaw = frame.camera_heading;
            self.view_pitch = frame.pitch.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH);
        }

        let dt = bounded_delta(frame.delta_seconds);
        self.manual_idle_seconds = (self.manual_idle_seconds + dt).min(60.0);
        if follow_enabled
            && movement_enabled
            && config.auto_center()
            && self.ownership.state() == OwnershipState::Explore
            && !self.combat_presentation.recovering()
            && self.manual_idle_seconds >= config.center_delay()
            && self.last_movement_magnitude > 0.05
        {
            let recenter_weight = recenter_horizon_weight(self.view_pitch);
            if recenter_weight > 0.0 {
                // Latch input identity and world travel together. Movement
                // then uses the same world heading while this camera turn is
                // active, so a held diagonal cannot be steered by the changing
                // view basis or diverge from Actor facing.
                if self.recenter_intent.is_none()
                    && let Some(local_heading) = self.movement_input_heading
                {
                    self.recenter_intent =
                        RecenterIntent::new(local_heading, self.last_movement_heading);
                    if self.recenter_intent.is_some() {
                        diagnostics::mark_recenter_started();
                    }
                }
                if let Some(recenter) = self.recenter_intent {
                    self.view_yaw = step_heading(
                        self.view_yaw,
                        recenter.world_travel_heading,
                        &mut self.recenter_speed,
                        config.center_speed_radians() * recenter_weight,
                        config.center_speed_radians() * 5.0 * recenter_weight,
                        dt,
                    );
                }
            } else {
                self.recenter_speed = 0.0;
                self.recenter_intent = None;
                // A pole-suppressed view must not accumulate a hidden target
                // and execute it as soon as the player lowers the camera.
                // Returning to an admissible pitch earns a fresh full delay.
                self.manual_idle_seconds = 0.0;
                diagnostics::mark_recenter_suppressed();
            }
        } else {
            self.recenter_speed = 0.0;
            if !config.auto_center()
                || self.ownership.state() != OwnershipState::Explore
                || self.combat_presentation.recovering()
                || self.last_movement_magnitude <= 0.05
            {
                self.recenter_intent = None;
            }
        }

        // Recenter must complete before advancing follow. Both outputs are
        // then copied into one immutable scope publication for every native
        // heading and collision query in this UpdateCamera invocation.
        if follow_enabled {
            self.follow
                .advance(frame.pivot, self.view_yaw, frame.delta_seconds, config);
        }
        let motion_observation =
            motion_enabled.then(|| unsafe { native::motion_sample(frame.player) });
        let mut shared_motion = None;
        if motion_enabled {
            match motion_observation {
                Some(native::MotionObservation::Sample(sample)) => {
                    shared_motion = Some(sample);
                    let Some(distance) = (unsafe { native::desired_distance() }) else {
                        self.last_camera_frame = frame.frame_id;
                        return shared_motion;
                    };
                    if dt <= 0.0 {
                        self.last_camera_frame = frame.frame_id;
                        return shared_motion;
                    }
                    let velocity = sample.relative_velocity();
                    let local = self.motion.update(
                        dt,
                        MotionInput {
                            velocity: Vec3::new(velocity[0], velocity[1], velocity[2]),
                            locomotion: sample.locomotion(),
                            directional_locomotion: sample.directional_locomotion(),
                            // Hip fire and weapon-ready locomotion still need
                            // visible body-coupled motion. Physical ADS owns
                            // suppression immediately; a mod-retained process
                            // aim byte is ignored during the debounced session.
                            aiming: self.motion_aiming,
                            desired_distance: distance,
                        },
                        config,
                    );
                    self.render_motion_rotation = self.motion.render_rotation();
                    self.motion_offset =
                        camera_motion_to_world(local, self.view_yaw).unwrap_or_default();
                }
                Some(native::MotionObservation::Unsupported) => {
                    self.motion.reset();
                    self.motion_offset = Vec3::default();
                    self.render_motion_rotation = Vec3::default();
                }
                Some(native::MotionObservation::Unavailable) | None => {
                    // A missing controller sample is not a camera-owner
                    // transition. Freeze the last finite pose for this one
                    // scope instead of exposing native identity as a snap.
                }
            }
        } else {
            self.motion.reset();
            self.motion_offset = Vec3::default();
            self.render_motion_rotation = Vec3::default();
        }
        self.last_camera_frame = frame.frame_id;
        shared_motion
    }
}

#[derive(Clone, Copy)]
struct PreparedCameraFrame {
    flags: u32,
    frame_id: u32,
    heading: f32,
    pitch: f32,
    align_actor_heading: Option<f32>,
    actor_pitch_write: Option<PreparedActorPitchWrite>,
    follow_offset: Vec3,
    motion_offset: Vec3,
    motion_sample: Option<super::NativeMotionCarrier>,
    hip_fire_release: Option<HipFireReleaseCommand>,
}

#[derive(Clone, Copy)]
struct PreparedActorPitchWrite {
    target: f32,
    adopt_result: bool,
}

fn bounded_delta(dt: f32) -> f32 {
    if dt.is_finite() && dt > 0.0 {
        dt.min(MAX_DT)
    } else {
        0.0
    }
}

fn recenter_horizon_weight(pitch: f32) -> f32 {
    if !pitch.is_finite() {
        return 0.0;
    }
    let weight = ((RECENTER_FADE_END - pitch.abs()) / (RECENTER_FADE_END - RECENTER_FADE_START))
        .clamp(0.0, 1.0);
    weight * weight * (3.0 - 2.0 * weight)
}

fn runtime_camera_enabled(config: ThirdPersonConfig) -> bool {
    (config.follow_enabled() && FOLLOW_ACTIVE.load(Ordering::Acquire))
        || (config.movement_enabled() && MOVEMENT_ACTIVE.load(Ordering::Acquire))
        || (config.framing_enabled() && FRAMING_CONTRACT_ACTIVE.load(Ordering::Acquire))
        || (config.motion_enabled() && MOTION_GENERATOR_ACTIVE.load(Ordering::Acquire))
        || HIP_FIRE_POSE_ADMITTED.load(Ordering::Acquire)
}

fn camera_scope_matches(player: *mut c_void) -> bool {
    CAMERA_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_ACTIVE
        && CAMERA_SCOPE_PLAYER.load(Ordering::Relaxed) == pointer_word(player)
        && CAMERA_SCOPE_THREAD.load(Ordering::Relaxed) == get_current_thread_id()
}

fn clear_camera_scope() {
    let state = CAMERA_SCOPE_STATE.load(Ordering::Acquire);
    if state != SCOPE_ACTIVE {
        // Only the preparation owner may recycle PREPARING. A concurrent reset
        // revokes it through RESET_GENERATION, and the owner performs cleanup
        // before returning. Recycling here could let stale payload overwrite
        // a newer reentrant scope.
        return;
    }
    if CAMERA_SCOPE_STATE
        .compare_exchange(
            SCOPE_ACTIVE,
            SCOPE_PREPARING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    // SCOPE_PREPARING blocks a new publisher while old payload is cleared.
    // The final release store is the only transition that makes the slot
    // available for another complete scope.
    CAMERA_SCOPE_PLAYER.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_THREAD.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_FLAGS.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_HEADING.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_PITCH.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_X.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_Y.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_FOLLOW_Z.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_X.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_Y.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_MOTION_Z.store(0, Ordering::Relaxed);
    CAMERA_SCOPE_STATE.store(SCOPE_IDLE, Ordering::Release);
}

fn clear_preparing_camera_scope(generation: u32, thread: u32) {
    if CAMERA_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_PREPARING
        && CAMERA_SCOPE_GENERATION.load(Ordering::Relaxed) == generation
        && CAMERA_SCOPE_THREAD.load(Ordering::Relaxed) == thread
    {
        CAMERA_SCOPE_PLAYER.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_THREAD.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_FLAGS.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_HEADING.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_PITCH.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_FOLLOW_X.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_FOLLOW_Y.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_FOLLOW_Z.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_MOTION_X.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_MOTION_Y.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_MOTION_Z.store(0, Ordering::Relaxed);
        CAMERA_SCOPE_STATE.store(SCOPE_IDLE, Ordering::Release);
    }
}

fn movement_scope_matches() -> bool {
    MOVEMENT_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_ACTIVE
        && MOVEMENT_SCOPE_THREAD.load(Ordering::Relaxed) == get_current_thread_id()
}

fn clear_movement_scope() {
    let state = MOVEMENT_SCOPE_STATE.load(Ordering::Acquire);
    if state != SCOPE_ACTIVE {
        // See clear_camera_scope: RESET_GENERATION revokes preparation without
        // allowing a second publisher to reuse the slot prematurely.
        return;
    }
    if MOVEMENT_SCOPE_STATE
        .compare_exchange(
            SCOPE_ACTIVE,
            SCOPE_PREPARING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    MOVEMENT_SCOPE_MOVER.store(0, Ordering::Relaxed);
    MOVEMENT_SCOPE_THREAD.store(0, Ordering::Relaxed);
    MOVEMENT_SCOPE_STATE.store(SCOPE_IDLE, Ordering::Release);
}

fn clear_preparing_movement_scope(generation: u32, thread: u32) {
    if MOVEMENT_SCOPE_STATE.load(Ordering::Acquire) == SCOPE_PREPARING
        && MOVEMENT_SCOPE_GENERATION.load(Ordering::Relaxed) == generation
        && MOVEMENT_SCOPE_THREAD.load(Ordering::Relaxed) == thread
    {
        MOVEMENT_SCOPE_MOVER.store(0, Ordering::Relaxed);
        MOVEMENT_SCOPE_THREAD.store(0, Ordering::Relaxed);
        MOVEMENT_SCOPE_STATE.store(SCOPE_IDLE, Ordering::Release);
    }
}

fn external_owner_active() -> bool {
    EXTERNAL_OWNERS
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) != 0)
}

fn publish_safe_pitch(player: *mut c_void, thread: u32, frame_id: u32, pitch: f32) {
    if !pitch.is_finite() {
        invalidate_safe_pitch();
        return;
    }
    SAFE_PITCH_VALID.store(false, Ordering::Release);
    SAFE_PITCH_PLAYER.store(pointer_word(player), Ordering::Relaxed);
    SAFE_PITCH_THREAD.store(thread, Ordering::Relaxed);
    SAFE_PITCH_FRAME.store(frame_id, Ordering::Relaxed);
    SAFE_PITCH_RESET_GENERATION.store(RESET_GENERATION.load(Ordering::Acquire), Ordering::Relaxed);
    SAFE_PITCH_VALUE.store(pitch.to_bits(), Ordering::Relaxed);
    SAFE_PITCH_VALID.store(true, Ordering::Release);
}

fn invalidate_safe_pitch() {
    SAFE_PITCH_VALID.store(false, Ordering::Release);
    SAFE_PITCH_PLAYER.store(0, Ordering::Relaxed);
    SAFE_PITCH_THREAD.store(0, Ordering::Relaxed);
    SAFE_PITCH_FRAME.store(0, Ordering::Relaxed);
    SAFE_PITCH_RESET_GENERATION.store(0, Ordering::Relaxed);
    SAFE_PITCH_VALUE.store(0, Ordering::Relaxed);
}

fn publish_heading_hold(player: *mut c_void, view_yaw: f32, combat: bool) {
    if !view_yaw.is_finite() {
        invalidate_heading_hold();
        return;
    }
    HEADING_HOLD_PLAYER.store(0, Ordering::Release);
    HEADING_HOLD_RESET_GENERATION
        .store(RESET_GENERATION.load(Ordering::Acquire), Ordering::Relaxed);
    HEADING_HOLD_YAW.store(view_yaw.to_bits(), Ordering::Relaxed);
    HEADING_HOLD_COMBAT.store(combat, Ordering::Relaxed);
    HEADING_HOLD_PLAYER.store(pointer_word(player), Ordering::Release);
}

fn invalidate_heading_hold() {
    HEADING_HOLD_PLAYER.store(0, Ordering::Release);
    HEADING_HOLD_RESET_GENERATION.store(0, Ordering::Relaxed);
    HEADING_HOLD_YAW.store(0, Ordering::Relaxed);
    HEADING_HOLD_COMBAT.store(false, Ordering::Relaxed);
}

fn heading_hold_matches(player: *mut c_void) -> bool {
    let player = pointer_word(player);
    if player == 0
        || HEADING_HOLD_PLAYER.load(Ordering::Acquire) != player
        || HEADING_HOLD_RESET_GENERATION.load(Ordering::Relaxed)
            != RESET_GENERATION.load(Ordering::Acquire)
    {
        return false;
    }
    true
}

fn retained_explore_heading(player: *mut c_void) -> Option<f32> {
    if !heading_hold_matches(player) || HEADING_HOLD_COMBAT.load(Ordering::Relaxed) {
        return None;
    }
    let heading = f32::from_bits(HEADING_HOLD_YAW.load(Ordering::Relaxed));
    heading.is_finite().then_some(heading)
}

fn adopt_owned_actor_pitch(player: *mut c_void, pitch: f32) -> bool {
    if !pitch.is_finite() {
        return false;
    }
    RUNTIME
        .with_mut(|runtime| {
            if runtime.player != pointer_word(player) || !runtime.ownership.state().is_owned() {
                return false;
            }
            runtime.view_pitch = pitch.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH);
            true
        })
        .unwrap_or(false)
}

unsafe fn synchronize_owned_camera_heading(player: *mut c_void, logical_heading: f32) -> bool {
    let Some(offset) = (unsafe { native::synchronize_camera_heading(player, logical_heading) })
    else {
        return false;
    };
    record_owned_camera_heading_offset(player, offset);
    true
}

fn record_owned_camera_heading_offset(player: *mut c_void, offset: f32) {
    let player = pointer_word(player);
    if offset.abs() > VIEW_MATCH_EPSILON {
        CAMERA_HEADING_OFFSET_PLAYER.store(player, Ordering::Release);
    } else if CAMERA_HEADING_OFFSET_PLAYER.load(Ordering::Acquire) == player {
        CAMERA_HEADING_OFFSET_PLAYER.store(0, Ordering::Release);
    }
}

fn release_owned_camera_heading(player: *mut c_void) -> bool {
    let player_word = pointer_word(player);
    if player_word == 0 || CAMERA_HEADING_OFFSET_PLAYER.load(Ordering::Acquire) != player_word {
        return true;
    }
    let Some(_facing_scope) = FacingCallScope::enter() else {
        return false;
    };
    if !unsafe { native::fold_camera_heading_offset_into_actor(player) } {
        return false;
    }
    let _ = CAMERA_HEADING_OFFSET_PLAYER.compare_exchange(
        player_word,
        0,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    true
}

fn clear_zoom_residual() {
    ZOOM_RESIDUAL.store(0.0_f32.to_bits(), Ordering::Release);
}

fn input_frame_id() -> u32 {
    crate::input::latest_action_frame().frame_id()
}

fn pointer_word(pointer: *mut c_void) -> u32 {
    pointer as usize as u32
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use super::{
        CameraSnapshotIdentity, OwnershipInput, OwnershipState, RuntimeState, ThirdPersonConfig,
        Vec3, camera_motion_to_world, fallback_pitch_identity_matches, native,
        recenter_horizon_weight,
    };

    fn frame(frame_id: u32, pivot: Vec3, heading: f32, dt: f32) -> native::NativeFrame {
        native::NativeFrame {
            frame_id,
            player: 0x10_0000usize as *mut c_void,
            mover: 0x20_0000usize as *mut c_void,
            cell: 0x30_0000usize as *mut c_void,
            pivot,
            actor_yaw: 0.0,
            camera_heading: heading,
            camera_heading_offset: 0.0,
            pitch: 0.25,
            delta_seconds: dt,
            stable_third_person: true,
            world_ready: true,
            native_owner: false,
            hard_valid: true,
            rejection: native::NativeRejection::Accepted,
            weapon_out: false,
            combat_intent: false,
        }
    }

    fn own_explore(state: &mut RuntimeState) {
        let input = OwnershipInput::new(true, true, false, true, false, 3);
        state.ownership.advance(input);
        state.ownership.advance(input);
        assert_eq!(state.ownership.state(), OwnershipState::Explore);
    }

    #[test]
    fn camera_temporal_state_advances_once_per_input_frame() {
        let config = ThirdPersonConfig::from_ini(
            "[Camera]\n\
             bFollowCamera=1\n\
             fFollowSpeed=7.5\n\
             fSoftZone=0\n\
             fLookAhead=0\n\
             bAutoCenter=1\n\
             fCenterDelay=0\n\
             fCenterSpeed=120\n\
             [Movement]\n\
             b360Movement=1\n",
        )
        .expect("valid camera configuration");
        let mut state = RuntimeState::new();
        own_explore(&mut state);
        state.follow.reset(Vec3::default());
        state.view_yaw = -1.0;
        state.movement_input_heading = Some(0.0);
        state.last_movement_heading = 1.0;
        state.last_movement_magnitude = 1.0;

        let input = frame(7, Vec3::new(0.0, 24.0, 0.0), -2.0, 1.0 / 60.0);
        state.advance_camera_temporal(input, config, true, true, false);
        let first_heading = state.view_yaw;
        let first_follow = state.follow.position();
        assert!(first_heading > -1.0, "recenter must precede publication");
        assert!(first_follow.y > 0.0 && first_follow.y < 24.0);

        state.advance_camera_temporal(input, config, true, true, false);
        assert_eq!(state.view_yaw, first_heading);
        assert_eq!(state.follow.position(), first_follow);
    }

    #[test]
    fn follow_only_refreshes_native_heading_each_frame() {
        let config = ThirdPersonConfig::from_ini("[Camera]\nbFollowCamera=1\n")
            .expect("valid follow-only configuration");
        let mut state = RuntimeState::new();
        own_explore(&mut state);
        state.follow.reset(Vec3::default());
        state.view_yaw = -1.0;

        state.advance_camera_temporal(
            frame(9, Vec3::default(), 0.75, 1.0 / 60.0),
            config,
            true,
            false,
            false,
        );
        assert_eq!(state.view_yaw, 0.75);
    }

    #[test]
    fn skyward_views_disable_movement_recentering_smoothly() {
        assert_eq!(recenter_horizon_weight(0.0), 1.0);
        assert_eq!(recenter_horizon_weight(70.0_f32.to_radians()), 1.0);
        let midpoint = recenter_horizon_weight(76.0_f32.to_radians());
        assert!((midpoint - 0.5).abs() < 0.000_01);
        assert_eq!(recenter_horizon_weight(82.0_f32.to_radians()), 0.0);
        assert_eq!(recenter_horizon_weight(89.0_f32.to_radians()), 0.0);
        assert_eq!(recenter_horizon_weight(f32::NAN), 0.0);
    }

    #[test]
    fn pitch_fallback_is_limited_to_the_exact_player_thread_frame_and_epoch() {
        let identity = CameraSnapshotIdentity {
            player: 0x10_0000,
            thread: 7,
            frame: 42,
            generation: 3,
        };
        assert!(fallback_pitch_identity_matches(identity, identity));
        for (field, changed) in [
            CameraSnapshotIdentity {
                player: identity.player + 1,
                ..identity
            },
            CameraSnapshotIdentity {
                thread: identity.thread + 1,
                ..identity
            },
            CameraSnapshotIdentity {
                frame: identity.frame + 1,
                ..identity
            },
            CameraSnapshotIdentity {
                generation: identity.generation + 1,
                ..identity
            },
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                !fallback_pitch_identity_matches(identity, changed),
                "identity field {field} admitted a stale pitch"
            );
        }
        let null_player = CameraSnapshotIdentity {
            player: 0,
            ..identity
        };
        assert!(!fallback_pitch_identity_matches(null_player, null_player));
    }

    #[test]
    fn local_motion_uses_camera_right_forward_and_world_up() {
        let local = Vec3::new(1.0, 2.0, 3.0);
        assert_eq!(camera_motion_to_world(local, 0.0), Some(local));
        let quarter_turn = camera_motion_to_world(local, core::f32::consts::FRAC_PI_2)
            .expect("finite camera basis");
        assert!((quarter_turn.x - 2.0).abs() < 0.000_01);
        assert!((quarter_turn.y + 1.0).abs() < 0.000_01);
        assert_eq!(quarter_turn.z, 3.0);

        assert!(camera_motion_to_world(local, f32::NAN).is_none());
    }
}

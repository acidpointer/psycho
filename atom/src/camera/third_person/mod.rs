//! ESP-less third-person follow, 360 locomotion, fine zoom, and aim convergence.
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
mod native;
mod ownership;
mod zoom;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::OnceLock;

use libnvse::api::player_controls::PlayerControlsReader;
use libpsycho::os::windows::winapi::get_current_thread_id;
use thiserror::Error;

pub use super::aim::{AimAngles, ViewRay, converge_angles, third_person_view_ray, view_direction};
pub use super::follow::{FollowSolver, SpringAxis, Vec3};
pub use super::movement::{
    FacingPolicy, LocomotionSector, MovementIntent, MovementOutput, MovementResolution,
    camera_relative_heading, remap_movement, step_heading, wrap_angle,
};
pub use config::{ThirdPersonConfig, ThirdPersonConfigError};
pub use ownership::{OwnershipInput, OwnershipMachine, OwnershipState, OwnershipTransition};
pub use zoom::linear_zoom_delta;

use config::ConfigStore;

const EXTERNAL_OWNER_CAPACITY: usize = 8;
const MAX_DT: f32 = 0.1;
const MAX_VIEW_PITCH: f32 = 1.553_343;
const NATIVE_HANDOFF_SETTLE_SECONDS: f32 = 0.15;
const RECENTER_INPUT_CHANGE_RADIANS: f32 = 0.017_453_293;
const VIEW_MATCH_EPSILON: f32 = 0.000_1;
const SCOPE_IDLE: u32 = 0;
const SCOPE_PREPARING: u32 = 1;
const SCOPE_ACTIVE: u32 = 2;
const CAMERA_SCOPE_VIEW_ACTIVE: u32 = 1 << 0;
const CAMERA_SCOPE_FOLLOW_ACTIVE: u32 = 1 << 1;

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
/// Explore free orbit is camera-only. Combat and a live native aim state must
/// retain Actor pitch so character presentation, crosshair direction, and
/// gameplay aim remain coupled. Non-owned states always remain native.
pub const fn vertical_look_route(
    ownership: OwnershipState,
    movement_enabled: bool,
    native_aiming: bool,
) -> LookRoute {
    if !movement_enabled {
        return LookRoute::NativeOnly;
    }
    match ownership {
        OwnershipState::Explore if !native_aiming => LookRoute::CameraOnly,
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
    native_aiming: bool,
) -> LookRoute {
    vertical_look_route(ownership, movement_enabled, native_aiming)
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
/// subsequent camera-only Explore frame must clear that presentation pitch
/// exactly once while retaining Atom's logical camera pitch. A nonzero live
/// Actor value also requests cleanup, so an intervening native UI epoch cannot
/// erase the handoff merely by clearing temporal state. Native-owned states
/// never modify engine state.
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
    let distance = solved.x.mul_add(
        view_axis.x,
        solved.y.mul_add(view_axis.y, solved.z * view_axis.z),
    );
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

static CONFIG: ConfigStore = ConfigStore::new();
static CONTROLS: OnceLock<PlayerControlsReader> = OnceLock::new();
static RUNTIME: RuntimeStore = RuntimeStore::new();
static HOOKS_ACTIVE: AtomicBool = AtomicBool::new(false);
static FOLLOW_ACTIVE: AtomicBool = AtomicBool::new(false);
static MOVEMENT_ACTIVE: AtomicBool = AtomicBool::new(false);
static ZOOM_ACTIVE: AtomicBool = AtomicBool::new(false);
static RETICLE_ACTIVE: AtomicBool = AtomicBool::new(false);
static CONVERGENCE_ACTIVE: AtomicBool = AtomicBool::new(false);
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
    pub(crate) movement_scope_predecessor: Option<usize>,
    pub(crate) movement_request_predecessor: Option<usize>,
    pub(crate) reticle_predecessor: Option<usize>,
    pub(crate) spawn_predecessor: Option<usize>,
    pub(crate) reticle_admitted: bool,
    pub(crate) aim_admitted: bool,
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
    {
        // Enabling is also a discontinuity: a solver that was dormant while
        // another capability owned the epoch must seed from current native
        // state instead of resuming old follow or facing history.
        request_reset();
    }
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
        "[CAMERA_TELEMETRY] Third-person movement: scope_calls={}, admitted_scopes={}, request_calls={}, overridden={}",
        snapshot.movement_scope_calls,
        snapshot.movement_scopes_admitted,
        snapshot.movement_calls,
        snapshot.movement_overrides,
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
    HOOKS_ACTIVE.store(
        follow_predecessor.is_some() || movement_predecessors.is_some(),
        Ordering::Release,
    );
    Ok(ThirdPersonHookStatus {
        zoom_predecessor,
        camera_heading_predecessor: movement_predecessors.map(|value| value.camera_heading),
        camera_pitch_predecessor: movement_predecessors.map(|value| value.camera_pitch),
        follow_predecessor,
        movement_scope_predecessor: movement_predecessors.map(|value| value.movement_scope),
        movement_request_predecessor: movement_predecessors.map(|value| value.movement_request),
        reticle_predecessor: aim_predecessors.map(|value| value.reticle),
        spawn_predecessor: aim_predecessors.map(|value| value.spawn),
        reticle_admitted,
        aim_admitted,
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
        request_reset();
    }
    accepted
}

/// Invalidate all third-person temporal state at a lifecycle boundary.
pub(crate) fn request_reset() {
    RESET_GENERATION.fetch_add(1, Ordering::AcqRel);
    RESET_REQUESTED.store(true, Ordering::Release);
    clear_camera_scope();
    clear_movement_scope();
    clear_zoom_residual();
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
    if combat_requested(frame, config)
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
                unsafe { native::player_is_aiming(player) },
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
                runtime.recenter_target = None;
            }
            true
        })
        .unwrap_or(false);
    diagnostics::mark_heading(consumed);
    consumed
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
                unsafe { native::player_is_aiming(player) },
            );
            if route != LookRoute::NativeAndSynchronize || frame.player != player {
                return None;
            }
            let heading = logical_heading_after_native_look(frame.actor_yaw)?;
            if wrap_angle(heading - runtime.view_yaw).abs() > 0.000_001 {
                runtime.manual_idle_seconds = 0.0;
                runtime.recenter_speed = 0.0;
                runtime.recenter_target = None;
            }
            runtime.view_yaw = heading;
            Some(heading)
        })
        .flatten();
    if logical_heading
        .is_some_and(|heading| unsafe { !native::synchronize_camera_heading(player, heading) })
    {
        request_reset();
    }
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
                unsafe { native::player_is_aiming(player) },
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
                runtime.recenter_target = None;
            }
            true
        })
        .unwrap_or(false)
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
            unsafe { native::player_is_aiming(player) },
        );
        if route == LookRoute::NativeAndSynchronize && frame.player == player {
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
}

/// Prepare and publish one immutable snapshot for a native camera update.
pub(crate) fn enter_camera_update_scope(player: *mut c_void) -> Option<CameraUpdateScope> {
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

    let prepared = RUNTIME
        .with_mut(|runtime| runtime.prepare_camera_frame(player))
        .flatten();
    let Some(prepared) = prepared else {
        clear_preparing_camera_scope(generation, owner_thread);
        return None;
    };
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
    let native_writes_succeeded = actor_heading_succeeded
        && unsafe { native::synchronize_camera_heading(player, prepared.heading) }
        && (!prepared.neutralize_actor_pitch || unsafe { native::neutralize_actor_pitch(player) });
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
    };
    if !active || RESET_GENERATION.load(Ordering::Acquire) != reset_generation {
        if active {
            leave_camera_update_scope(scope);
        } else {
            clear_preparing_camera_scope(generation, owner_thread);
        }
        return None;
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

/// Return the scoped logical heading for this player and owner thread.
pub(crate) fn scoped_camera_heading(player: *mut c_void) -> Option<f32> {
    if !camera_scope_matches(player)
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed) & CAMERA_SCOPE_VIEW_ACTIVE == 0
    {
        return None;
    }
    let heading = f32::from_bits(CAMERA_SCOPE_HEADING.load(Ordering::Relaxed));
    heading.is_finite().then_some(heading)
}

/// Return the scoped logical pitch for this player and owner thread.
pub(crate) fn scoped_camera_pitch(player: *mut c_void) -> Option<f32> {
    if !camera_scope_matches(player)
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed) & CAMERA_SCOPE_VIEW_ACTIVE == 0
    {
        return None;
    }
    let pitch = f32::from_bits(CAMERA_SCOPE_PITCH.load(Ordering::Relaxed));
    pitch.is_finite().then_some(pitch)
}

/// Return the scoped follow displacement for this player and owner thread.
pub(crate) fn scoped_follow_offset(player: *mut c_void) -> Option<Vec3> {
    if !camera_scope_matches(player)
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed) & CAMERA_SCOPE_FOLLOW_ACTIVE == 0
    {
        return None;
    }
    let offset = Vec3::new(
        f32::from_bits(CAMERA_SCOPE_FOLLOW_X.load(Ordering::Relaxed)),
        f32::from_bits(CAMERA_SCOPE_FOLLOW_Y.load(Ordering::Relaxed)),
        f32::from_bits(CAMERA_SCOPE_FOLLOW_Z.load(Ordering::Relaxed)),
    );
    offset.is_finite().then_some(offset)
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
    let player = native::player();
    let admitted = RUNTIME
        .with_mut(|runtime| {
            let Some((frame, config)) = runtime.refresh(player) else {
                return false;
            };
            runtime.ownership.state().is_owned()
                && config.movement_enabled()
                && frame.mover == mover
        })
        .unwrap_or(false);
    if !admitted
        || MOVEMENT_SCOPE_STATE
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
    let mover = pointer_word(mover);
    MOVEMENT_SCOPE_GENERATION.store(generation, Ordering::Relaxed);
    MOVEMENT_SCOPE_MOVER.store(mover, Ordering::Relaxed);
    MOVEMENT_SCOPE_THREAD.store(owner_thread, Ordering::Relaxed);
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
        mover,
        thread: owner_thread,
    };
    if !active || RESET_GENERATION.load(Ordering::Acquire) != reset_generation {
        if active {
            leave_movement_scope(scope);
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

/// Build one camera-relative movement request for the scoped live player.
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
            || !config.movement_enabled()
            || frame.player != actor
            || pointer_word(frame.mover) != MOVEMENT_SCOPE_MOVER.load(Ordering::Relaxed)
        {
            return None;
        }
        let (policy, previous_sector) = if runtime.ownership.state() == OwnershipState::Combat {
            // Combat owns a different animation vocabulary: native strafe
            // bits remain authoritative and no Explore sector may leak back
            // across the ownership transition.
            runtime.locomotion_sector = None;
            runtime.recenter_target = None;
            (FacingPolicy::Combat, None)
        } else {
            (FacingPolicy::Explore, runtime.locomotion_sector)
        };
        let intent = MovementIntent::new(native_movement, flags, runtime.view_yaw, policy);
        let movement_heading = intent.movement_heading();
        let movement_input_heading =
            movement_heading.map(|_| wrap_angle(native_movement.x.atan2(native_movement.y)));
        let input_changed = match (runtime.movement_input_heading, movement_input_heading) {
            (Some(previous), Some(current)) => {
                wrap_angle(current - previous).abs() > RECENTER_INPUT_CHANGE_RADIANS
            }
            (None, None) => false,
            _ => true,
        };
        if input_changed {
            // A fresh or changed direction gets its own delay and fixed
            // world-space recenter target. Without this reset, entering a
            // lateral direction after an idle interval can turn immediately.
            runtime.manual_idle_seconds = 0.0;
            runtime.recenter_speed = 0.0;
            runtime.recenter_target = None;
        }
        runtime.movement_input_heading = movement_input_heading;
        if let Some(heading) = movement_heading {
            runtime.last_movement_heading = heading;
            runtime.last_movement_magnitude = native_movement.horizontal_length();
        } else {
            runtime.last_movement_magnitude = 0.0;
            runtime.recenter_target = None;
        }
        let facing = intent.facing_target().map(|target| {
            step_heading(
                frame.actor_yaw,
                target,
                &mut runtime.actor_turn_speed,
                config.turn_speed_radians(),
                config.turn_speed_radians() * 6.0,
                dt.clamp(0.0, MAX_DT),
            )
        });
        Some(PreparedMovement {
            intent,
            facing,
            previous_sector,
            logical_heading: runtime.view_yaw,
            player: runtime.player,
            epoch: runtime.ownership.epoch(),
        })
    })??;

    if let Some(facing) = prepared.facing {
        let _facing_scope = FacingCallScope::enter()?;
        let invoked = unsafe { native::invoke_actor_yaw_setter(actor, facing) };
        if !invoked {
            request_reset();
            return None;
        }
    }
    // The setter is void and may reject or normalize the request. Only raw
    // rotZ observed after the call is the heading 0x0092F260 will use.
    let Some(actual_actor_yaw) = (unsafe { native::raw_actor_yaw(actor) }) else {
        request_reset();
        return None;
    };
    if !unsafe { native::synchronize_camera_heading(actor, prepared.logical_heading) } {
        request_reset();
        return None;
    }
    let resolution = prepared
        .intent
        .resolve_stateful(actual_actor_yaw, prepared.previous_sector);
    let next_sector = resolution.locomotion_sector();

    // The yaw setter is an engine call and must run outside RuntimeStore's
    // nonblocking lease. Publish animation history afterwards only if the
    // same player and ownership epoch still exist. Failure to reacquire the
    // lease affects hysteresis only; the already-valid movement request must
    // still reach native code.
    let _ = RUNTIME.with_mut(|runtime| {
        if runtime.ownership.state().is_owned()
            && runtime.ownership.epoch() == prepared.epoch
            && runtime.player == prepared.player
        {
            runtime.locomotion_sector = next_sector;
        }
    });
    Some(resolution.output())
}

#[derive(Clone, Copy)]
struct PreparedMovement {
    intent: MovementIntent,
    facing: Option<f32>,
    previous_sector: Option<LocomotionSector>,
    logical_heading: f32,
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

/// Immutable view-ray sample paired with one ownership epoch and input frame.
#[derive(Clone, Copy)]
pub(crate) struct ViewCastPrepared {
    origin: Vec3,
    direction: Vec3,
    max_distance: f32,
    player: u32,
    frame_id: u32,
    epoch: u32,
}

impl ViewCastPrepared {
    pub(crate) const fn origin(self) -> Vec3 {
        self.origin
    }

    pub(crate) const fn direction(self) -> Vec3 {
        self.direction
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
            || !config.movement_enabled()
            || frame.player != player
        {
            return None;
        }
        let camera_origin = unsafe { native::render_camera_origin()? };
        let ray =
            third_person_view_ray(origin, camera_origin, runtime.view_yaw, runtime.view_pitch)?;
        Some(ViewCastPrepared {
            origin: ray.origin(),
            direction: ray.direction(),
            max_distance,
            player: pointer_word(player),
            frame_id: input_frame_id(),
            epoch: runtime.ownership.epoch(),
        })
    })?
}

pub(crate) fn finish_view_cast(prepared: ViewCastPrepared, distance: f32) {
    let _ = RUNTIME.with_mut(|runtime| {
        if runtime.ownership.state().is_owned()
            && runtime.ownership.epoch() == prepared.epoch
            && runtime.player == prepared.player
        {
            let distance =
                if distance.is_finite() && distance >= 0.0 && distance <= prepared.max_distance {
                    distance
                } else {
                    prepared.max_distance
                };
            runtime.aim_sample = AimSample {
                valid: true,
                origin: prepared.origin,
                direction: prepared.direction,
                distance,
                player: prepared.player,
                frame_id: prepared.frame_id,
                epoch: prepared.epoch,
            };
        }
    });
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

    // Establish a current ownership/view sample before touching weapon,
    // projectile, skeleton, or node memory. This makes every native-owner
    // transition a strict fail-native boundary for the deeper ABI reads.
    let prepared = RUNTIME.with_mut(|runtime| {
        let (frame, config) = runtime.refresh(source)?;
        if !runtime.ownership.state().is_owned()
            || !config.movement_enabled()
            || frame.player != source
            || !runtime.aim_sample.valid
            || runtime.aim_sample.player != pointer_word(source)
            || runtime.aim_sample.epoch != runtime.ownership.epoch()
            || runtime.aim_sample.frame_id != input_frame_id()
        {
            return None;
        }
        let direction = view_direction(runtime.view_yaw, runtime.view_pitch)?;
        if (direction - runtime.aim_sample.direction).length() > VIEW_MATCH_EPSILON {
            return None;
        }
        Some(runtime.aim_sample)
    })??;

    let range = unsafe { native::admitted_projectile_range(projectile, weapon)? };
    let (muzzle, native_base) = unsafe { native::real_muzzle(source, weapon)? };
    let distance = prepared.distance.min(range);
    let ray = ViewRay::from_parts(prepared.origin, prepared.direction);
    let target = ray.point_at(distance)?;
    let angles = converge_angles(muzzle, target, native_base, native_final)?;
    Some((muzzle, angles))
}

#[derive(Clone, Copy, Debug, Default)]
struct AimSample {
    valid: bool,
    origin: Vec3,
    direction: Vec3,
    distance: f32,
    player: u32,
    frame_id: u32,
    epoch: u32,
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

struct RuntimeState {
    ownership: OwnershipMachine,
    native_handoff: NativeHandoffGuard,
    player: u32,
    cell: u32,
    last_frame_id: u32,
    view_yaw: f32,
    view_pitch: f32,
    follow: FollowSolver,
    last_camera_frame: u32,
    manual_idle_seconds: f32,
    recenter_speed: f32,
    recenter_target: Option<f32>,
    movement_input_heading: Option<f32>,
    actor_turn_speed: f32,
    last_movement_heading: f32,
    last_movement_magnitude: f32,
    locomotion_sector: Option<LocomotionSector>,
    native_pitch_owned: bool,
    aim_sample: AimSample,
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            ownership: OwnershipMachine::new(),
            native_handoff: NativeHandoffGuard::new(),
            player: 0,
            cell: 0,
            last_frame_id: 0,
            view_yaw: 0.0,
            view_pitch: 0.0,
            follow: FollowSolver::new(),
            last_camera_frame: 0,
            manual_idle_seconds: 0.0,
            recenter_speed: 0.0,
            recenter_target: None,
            movement_input_heading: None,
            actor_turn_speed: 0.0,
            last_movement_heading: 0.0,
            last_movement_magnitude: 0.0,
            locomotion_sector: None,
            native_pitch_owned: false,
            aim_sample: AimSample {
                valid: false,
                origin: Vec3::new(0.0, 0.0, 0.0),
                direction: Vec3::new(0.0, 0.0, 0.0),
                distance: 0.0,
                player: 0,
                frame_id: 0,
                epoch: 0,
            },
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn clear_temporal(&mut self) {
        clear_zoom_residual();
        self.follow = FollowSolver::new();
        self.last_camera_frame = 0;
        self.manual_idle_seconds = 0.0;
        self.recenter_speed = 0.0;
        self.recenter_target = None;
        self.movement_input_heading = None;
        self.actor_turn_speed = 0.0;
        self.last_movement_magnitude = 0.0;
        self.locomotion_sector = None;
        self.native_pitch_owned = false;
        self.aim_sample = AimSample::default();
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
        self.manual_idle_seconds = 0.0;
        self.recenter_speed = 0.0;
        self.recenter_target = None;
        self.movement_input_heading = None;
        self.actor_turn_speed = 0.0;
        self.last_movement_heading = 0.0;
        self.last_movement_magnitude = 0.0;
        self.locomotion_sector = None;
        self.native_pitch_owned = false;
        self.aim_sample = AimSample::default();
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
        let combat = combat_requested(frame, config);
        let fighting_owner =
            combat && unsafe { native::fighting_control_disabled(frame.player, controls) };
        let enabled = (config.follow_enabled() && FOLLOW_ACTIVE.load(Ordering::Acquire))
            || (config.movement_enabled() && MOVEMENT_ACTIVE.load(Ordering::Acquire));
        let frame_advanced = frame.frame_id != self.last_frame_id;
        let native_state_clear = enabled && frame.hard_valid && !external_owner && !fighting_owner;
        let handoff_delta = if frame_advanced {
            frame.delta_seconds
        } else {
            0.0
        };
        let handoff_ready = self
            .native_handoff
            .advance(native_state_clear, handoff_delta);
        let native_owner = frame.native_owner || external_owner || fighting_owner || !handoff_ready;
        let input = OwnershipInput::new(
            enabled,
            frame.stable_third_person,
            native_owner,
            frame.world_ready,
            combat,
            pointer_word(frame.cell),
        );

        if frame.frame_id != self.last_frame_id {
            let transition = self.ownership.advance(input);
            self.last_frame_id = frame.frame_id;
            if transition.begins_acquire() {
                self.seed(frame);
            } else if transition.current() == OwnershipState::Release {
                self.native_handoff.reset();
                self.clear_temporal();
            }
        } else if self.ownership.state().is_owned()
            && (!frame.hard_valid
                || native_owner
                || self.player != pointer_word(frame.player)
                || self.cell != pointer_word(frame.cell))
        {
            // Loading can swap the player or parent cell between native calls
            // that share an input-frame id. Revoke immediately instead of
            // waiting for the next normal classifier advance.
            self.ownership.force_release();
            self.native_handoff.reset();
            self.clear_temporal();
        }
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

    fn prepare_camera_frame(&mut self, player: *mut c_void) -> Option<PreparedCameraFrame> {
        let (frame, config) = self.refresh(player)?;
        if !self.ownership.state().is_owned() || frame.player != player {
            return None;
        }

        let follow_enabled = config.follow_enabled() && FOLLOW_ACTIVE.load(Ordering::Acquire);
        let movement_enabled = config.movement_enabled() && MOVEMENT_ACTIVE.load(Ordering::Acquire);
        if !follow_enabled && !movement_enabled {
            return None;
        }

        self.advance_camera_temporal(frame, config, follow_enabled, movement_enabled);

        let native_aiming = unsafe { native::player_is_aiming(player) };
        let vertical_route =
            vertical_look_route(self.ownership.state(), movement_enabled, native_aiming);
        let neutralize_actor_pitch = advance_actor_pitch_ownership(
            &mut self.native_pitch_owned,
            vertical_route,
            frame.pitch,
        );
        let horizontal_route =
            horizontal_look_route(self.ownership.state(), movement_enabled, native_aiming);
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
        if !self.view_yaw.is_finite() || !self.view_pitch.is_finite() || !follow_offset.is_finite()
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
        Some(PreparedCameraFrame {
            flags,
            heading: self.view_yaw,
            pitch: self.view_pitch,
            align_actor_heading,
            neutralize_actor_pitch,
            follow_offset,
        })
    }

    fn advance_camera_temporal(
        &mut self,
        frame: native::NativeFrame,
        config: ThirdPersonConfig,
        follow_enabled: bool,
        movement_enabled: bool,
    ) {
        if self.last_camera_frame == frame.frame_id {
            return;
        }

        // Follow-only mode leaves native actor/view coupling intact. Copy the
        // current adjusted heading every frame so follow axes never retain the
        // acquisition-time direction after native look.
        if !movement_enabled {
            self.view_yaw = frame.camera_heading;
            self.view_pitch = frame.pitch.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH);
        }

        let dt = validated_delta(frame.delta_seconds);
        self.manual_idle_seconds = (self.manual_idle_seconds + dt).min(60.0);
        if follow_enabled
            && movement_enabled
            && config.auto_center()
            && self.ownership.state() == OwnershipState::Explore
            && self.manual_idle_seconds >= config.center_delay()
            && self.last_movement_magnitude > 0.05
        {
            // Camera-relative intent changes as the camera turns. Latch one
            // world-space target for the current input direction so recenter
            // cannot chase a lateral/back target around the player forever.
            let target = *self
                .recenter_target
                .get_or_insert(self.last_movement_heading);
            self.view_yaw = step_heading(
                self.view_yaw,
                target,
                &mut self.recenter_speed,
                config.center_speed_radians(),
                config.center_speed_radians() * 5.0,
                dt,
            );
        } else {
            self.recenter_speed = 0.0;
            if !config.auto_center()
                || self.ownership.state() != OwnershipState::Explore
                || self.last_movement_magnitude <= 0.05
            {
                self.recenter_target = None;
            }
        }

        // Recenter must complete before advancing follow. Both outputs are
        // then copied into one immutable scope publication for every native
        // heading and collision query in this UpdateCamera invocation.
        if follow_enabled {
            self.follow.advance(frame.pivot, self.view_yaw, dt, config);
        }
        self.last_camera_frame = frame.frame_id;
    }
}

#[derive(Clone, Copy)]
struct PreparedCameraFrame {
    flags: u32,
    heading: f32,
    pitch: f32,
    align_actor_heading: Option<f32>,
    neutralize_actor_pitch: bool,
    follow_offset: Vec3,
}

fn validated_delta(dt: f32) -> f32 {
    if dt.is_finite() && dt > 0.0 && dt <= MAX_DT {
        dt
    } else {
        // Zero reaches FollowSolver's reset boundary. Substituting a nominal
        // frame after pause or a discontinuity would preserve stale spring
        // energy and make camera motion depend on callback count.
        0.0
    }
}

fn combat_requested(frame: native::NativeFrame, config: ThirdPersonConfig) -> bool {
    frame.weapon_out && (!config.drawn_360() || frame.combat_intent)
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

    use super::{OwnershipInput, OwnershipState, RuntimeState, ThirdPersonConfig, Vec3, native};

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
        state.last_movement_heading = 1.0;
        state.last_movement_magnitude = 1.0;

        let input = frame(7, Vec3::new(0.0, 24.0, 0.0), -2.0, 1.0 / 60.0);
        state.advance_camera_temporal(input, config, true, true);
        let first_heading = state.view_yaw;
        let first_follow = state.follow.position();
        assert!(first_heading > -1.0, "recenter must precede publication");
        assert!(first_follow.y > 0.0 && first_follow.y < 24.0);

        state.advance_camera_temporal(input, config, true, true);
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
        );
        assert_eq!(state.view_yaw, 0.75);
    }
}

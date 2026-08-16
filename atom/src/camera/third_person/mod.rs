//! ESP-less third-person follow, 360 locomotion, and aim convergence.
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

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::OnceLock;

use libnvse::api::player_controls::PlayerControlsReader;
use libpsycho::os::windows::winapi::get_current_thread_id;
use thiserror::Error;

pub use super::aim::{AimAngles, converge_angles, view_direction};
pub use super::follow::{FollowSolver, SpringAxis, Vec3};
pub use super::movement::{
    FacingPolicy, MovementIntent, MovementOutput, camera_relative_heading, remap_movement,
    step_heading, wrap_angle,
};
pub use config::{ThirdPersonConfig, ThirdPersonConfigError};
pub use ownership::{OwnershipInput, OwnershipMachine, OwnershipState, OwnershipTransition};

use config::ConfigStore;

const EXTERNAL_OWNER_CAPACITY: usize = 8;
const MAX_DT: f32 = 0.1;
const MAX_VIEW_PITCH: f32 = 1.553_343;
const VIEW_MATCH_EPSILON: f32 = 0.000_1;
const SCOPE_IDLE: u32 = 0;
const SCOPE_PREPARING: u32 = 1;
const SCOPE_ACTIVE: u32 = 2;
const CAMERA_SCOPE_HEADING_ACTIVE: u32 = 1 << 0;
const CAMERA_SCOPE_FOLLOW_ACTIVE: u32 = 1 << 1;

static CONFIG: ConfigStore = ConfigStore::new();
static CONTROLS: OnceLock<PlayerControlsReader> = OnceLock::new();
static RUNTIME: RuntimeStore = RuntimeStore::new();
static HOOKS_ACTIVE: AtomicBool = AtomicBool::new(false);
static FOLLOW_ACTIVE: AtomicBool = AtomicBool::new(false);
static MOVEMENT_ACTIVE: AtomicBool = AtomicBool::new(false);
static AIM_ACTIVE: AtomicBool = AtomicBool::new(false);
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
    pub(crate) camera_heading_predecessor: Option<usize>,
    pub(crate) follow_predecessor: Option<usize>,
    pub(crate) movement_scope_predecessor: Option<usize>,
    pub(crate) movement_request_predecessor: Option<usize>,
    pub(crate) reticle_predecessor: Option<usize>,
    pub(crate) spawn_predecessor: Option<usize>,
    pub(crate) aim_admitted: bool,
}

/// Return one coherent copy of the current MCM-owned settings.
pub fn current_config() -> ThirdPersonConfig {
    CONFIG.load()
}

pub(crate) fn publish_config(config: ThirdPersonConfig) {
    let previous = CONFIG.load();
    CONFIG.publish(config);
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
    let aim_admitted = aim_predecessors.is_some_and(|value| value.aim_admitted);
    AIM_ACTIVE.store(aim_admitted, Ordering::Release);
    HOOKS_ACTIVE.store(
        follow_predecessor.is_some() || movement_predecessors.is_some(),
        Ordering::Release,
    );
    Ok(ThirdPersonHookStatus {
        camera_heading_predecessor: movement_predecessors.map(|value| value.camera_heading),
        follow_predecessor,
        movement_scope_predecessor: movement_predecessors.map(|value| value.movement_scope),
        movement_request_predecessor: movement_predecessors.map(|value| value.movement_request),
        reticle_predecessor: aim_predecessors.map(|value| value.reticle),
        spawn_predecessor: aim_predecessors.map(|value| value.spawn),
        aim_admitted,
    })
}

/// Assert or release an explicit external third-person owner.
///
/// `owner_token` must be a stable nonzero identifier selected by the external
/// provider. Up to eight simultaneous owners are tracked without allocation.
/// Repeated assertions are idempotent; releasing an absent token returns
/// `false`. While any token is present, this subsystem performs no follow,
/// movement, facing, or aim writes. External
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
    if RUNTIME.with_mut(RuntimeState::reset).is_some() {
        RESET_REQUESTED.store(false, Ordering::Release);
    }
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
            // Follow-only mode deliberately keeps vanilla look/facing coupled.
            // Free orbit is admitted only when the complete movement/facing
            // seam is active, avoiding a camera that can outrun gameplay yaw.
            if !runtime.ownership.state().is_owned()
                || !config.movement_enabled()
                || frame.player != player
            {
                return false;
            }
            runtime.view_yaw = wrap_angle(runtime.view_yaw + delta);
            if delta.abs() > 0.000_001 {
                runtime.manual_idle_seconds = 0.0;
                runtime.recenter_speed = 0.0;
            }
            true
        })
        .unwrap_or(false);
    diagnostics::mark_heading(consumed);
    consumed
}

pub(crate) fn observe_vertical_heading(player: *mut c_void) {
    if !HOOKS_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let _ = RUNTIME.with_mut(|runtime| {
        let Some((frame, _)) = runtime.refresh(player) else {
            return;
        };
        if runtime.ownership.state().is_owned() {
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
        || CAMERA_SCOPE_FLAGS.load(Ordering::Relaxed) & CAMERA_SCOPE_HEADING_ACTIVE == 0
    {
        return None;
    }
    let heading = f32::from_bits(CAMERA_SCOPE_HEADING.load(Ordering::Relaxed));
    heading.is_finite().then_some(heading)
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
        let policy = if runtime.ownership.state() == OwnershipState::Combat {
            FacingPolicy::Combat
        } else {
            FacingPolicy::Explore
        };
        let intent = MovementIntent::new(native_movement, flags, runtime.view_yaw, policy);
        let movement_heading = intent.movement_heading();
        if let Some(heading) = movement_heading {
            runtime.last_movement_heading = heading;
            runtime.last_movement_magnitude = native_movement.horizontal_length();
        } else {
            runtime.last_movement_magnitude = 0.0;
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
        Some((intent, facing))
    })??;

    if let Some(facing) = prepared.1 {
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
    Some(prepared.0.resolve(actual_actor_yaw))
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
    if !AIM_ACTIVE.load(Ordering::Acquire)
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
        let direction = view_direction(runtime.view_yaw, runtime.view_pitch)?;
        Some(ViewCastPrepared {
            origin,
            direction,
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
    if !AIM_ACTIVE.load(Ordering::Acquire) || source != native::player() {
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
    let target = prepared.origin + prepared.direction * distance;
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
    player: u32,
    cell: u32,
    last_frame_id: u32,
    view_yaw: f32,
    view_pitch: f32,
    follow: FollowSolver,
    last_camera_frame: u32,
    manual_idle_seconds: f32,
    recenter_speed: f32,
    actor_turn_speed: f32,
    last_movement_heading: f32,
    last_movement_magnitude: f32,
    aim_sample: AimSample,
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            ownership: OwnershipMachine::new(),
            player: 0,
            cell: 0,
            last_frame_id: 0,
            view_yaw: 0.0,
            view_pitch: 0.0,
            follow: FollowSolver::new(),
            last_camera_frame: 0,
            manual_idle_seconds: 0.0,
            recenter_speed: 0.0,
            actor_turn_speed: 0.0,
            last_movement_heading: 0.0,
            last_movement_magnitude: 0.0,
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
        self.follow = FollowSolver::new();
        self.last_camera_frame = 0;
        self.manual_idle_seconds = 0.0;
        self.recenter_speed = 0.0;
        self.actor_turn_speed = 0.0;
        self.last_movement_magnitude = 0.0;
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
        self.last_camera_frame = 0;
        self.manual_idle_seconds = 0.0;
        self.recenter_speed = 0.0;
        self.actor_turn_speed = 0.0;
        self.last_movement_heading = 0.0;
        self.last_movement_magnitude = 0.0;
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
        let external_owner = EXTERNAL_OWNERS
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) != 0);
        let combat = frame.weapon_out && (!config.drawn_360() || frame.combat_intent);
        let enabled = (config.follow_enabled() && FOLLOW_ACTIVE.load(Ordering::Acquire))
            || (config.movement_enabled() && MOVEMENT_ACTIVE.load(Ordering::Acquire));
        let input = OwnershipInput::new(
            enabled,
            frame.stable_third_person,
            frame.native_owner || external_owner,
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
                self.clear_temporal();
            }
        } else if self.ownership.state().is_owned()
            && (!frame.hard_valid
                || external_owner
                || self.player != pointer_word(frame.player)
                || self.cell != pointer_word(frame.cell))
        {
            // Loading can swap the player or parent cell between native calls
            // that share an input-frame id. Revoke immediately instead of
            // waiting for the next normal classifier advance.
            self.ownership.force_release();
            self.clear_temporal();
        }
        diagnostics::mark_observation(
            if external_owner {
                native::NativeRejection::ExternalOwner
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

        let follow_offset = if follow_enabled {
            self.follow.position() - frame.pivot
        } else {
            Vec3::default()
        };
        if !self.view_yaw.is_finite() || !follow_offset.is_finite() {
            return None;
        }

        let mut flags = 0;
        if movement_enabled {
            flags |= CAMERA_SCOPE_HEADING_ACTIVE;
        }
        if follow_enabled {
            flags |= CAMERA_SCOPE_FOLLOW_ACTIVE;
        }
        Some(PreparedCameraFrame {
            flags,
            heading: self.view_yaw,
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
        }
        self.view_pitch = frame.pitch.clamp(-MAX_VIEW_PITCH, MAX_VIEW_PITCH);

        let dt = validated_delta(frame.delta_seconds);
        self.manual_idle_seconds = (self.manual_idle_seconds + dt).min(60.0);
        if follow_enabled
            && movement_enabled
            && config.auto_center()
            && self.ownership.state() == OwnershipState::Explore
            && self.manual_idle_seconds >= config.center_delay()
            && self.last_movement_magnitude > 0.05
        {
            self.view_yaw = step_heading(
                self.view_yaw,
                self.last_movement_heading,
                &mut self.recenter_speed,
                config.center_speed_radians(),
                config.center_speed_radians() * 5.0,
                dt,
            );
        } else {
            self.recenter_speed = 0.0;
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

//! First- and third-person camera ownership for Atom.
//!
//! The first-person path is a render-scoped presentation wrapper. The
//! [`third_person`] path separately owns follow, camera-relative locomotion,
//! actor facing, and aim convergence only during explicit normal-third-person
//! epochs. Both paths share lifecycle reset and external-owner routing here.
//!
//! Native FNV remains authoritative for candidate filtering, activation,
//! projectile behavior, camera selection, and iron-sight setup. In an owned
//! third-person epoch Atom supplies the logical camera ray to FNV's existing
//! reticle cast so the native selected reference matches the rendered view.
//! Atom samples one accepted post-`UpdateCamera` state, generates a bounded
//! immutable pose pair, and applies the world pose around one complete native
//! render route so sky preparation, world rendering, first-person rendering,
//! and image-space effects observe one camera. A nested viewmodel scope adds
//! weapon-relative motion only while no authored animation owns it. The exact
//! native transforms are restored before the route returns. Stable world motion
//! is constrained to bounded translation. Third person may add sub-degree
//! render-scoped roll/pitch after chase collision; aiming suppresses it.

mod aim;
mod config;
mod diagnostics;
mod follow;
mod hooks;
mod motion;
mod movement;
mod native;
mod pose;
mod state;

pub mod third_person;

pub use config::{FirstPersonConfig, FirstPersonConfigError};
pub use motion::{GeneratedMotion, LocomotionState, MotionGenerator, MotionInput};
pub use pose::{CameraPose, CameraTransform, compose_transform};
pub use state::CameraMotionFrame;

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::OnceLock;

use libnvse::api::player_controls::{ControlFlags, DisabledCheck, PlayerControlsReader};
use thiserror::Error;

use config::ConfigStore;
use state::{FrameStore, MotionAdvance, MotionStateCell};

static CONFIG: ConfigStore = ConfigStore::new();
static FRAMES: FrameStore = FrameStore::new();
static MOTION: MotionStateCell = MotionStateCell::new();
static RESET_GENERATION: AtomicU32 = AtomicU32::new(0);
static RENDER_TOKEN: RenderTokenStore = RenderTokenStore::new();
static EXTERNAL_OWNER: AtomicU32 = AtomicU32::new(0);
static PLAYER_CONTROLS: OnceLock<PlayerControlsReader> = OnceLock::new();
static FIRST_PERSON_ACTIVE: AtomicBool = AtomicBool::new(false);

const CAMERA_CONTROL_MASK: ControlFlags = ControlFlags::from_bits_retain(
    ControlFlags::MOVEMENT.bits()
        | ControlFlags::LOOKING.bits()
        | ControlFlags::PIPBOY.bits()
        | ControlFlags::FIGHTING.bits()
        | ControlFlags::POV.bits()
        | ControlFlags::AIMING_OR_BLOCKING.bits(),
);

/// Failure to admit Atom's fixed first-person camera wrapper.
#[derive(Debug, Error)]
pub(crate) enum FirstPersonInstallError {
    #[error(transparent)]
    Native(#[from] native::NativeContractError),
    #[error(transparent)]
    Hook(#[from] hooks::HookInstallError),
}

/// Current predecessor addresses captured for startup diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FirstPersonHookStatus {
    pub(crate) route_a: usize,
    pub(crate) route_b: usize,
    pub(crate) first_person_special: usize,
    pub(crate) first_person_a: usize,
    pub(crate) first_person_b: usize,
}

/// Captured predecessor for the shared complete camera-update wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharedCameraHookStatus {
    pub(crate) update_entry: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(super) enum RenderRoute {
    A = 1,
    B = 2,
}

/// Pointer-free locomotion carrier shared by both camera presentation paths.
///
/// Third-person motion samples this before native camera construction. The
/// complete UpdateCamera wrapper may reuse that same value for the subsequent
/// first-person update, avoiding a second Havok controller lock in one call.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct NativeMotionCarrier {
    relative_velocity: [f32; 3],
    locomotion: LocomotionState,
    directional_locomotion: bool,
}

impl NativeMotionCarrier {
    pub(super) const fn new(
        relative_velocity: [f32; 3],
        locomotion: LocomotionState,
        directional_locomotion: bool,
    ) -> Self {
        Self {
            relative_velocity,
            locomotion,
            directional_locomotion,
        }
    }

    pub(super) const fn relative_velocity(self) -> [f32; 3] {
        self.relative_velocity
    }

    pub(super) const fn locomotion(self) -> LocomotionState {
        self.locomotion
    }

    pub(super) const fn directional_locomotion(self) -> bool {
        self.directional_locomotion
    }
}

/// Single-consumer route token joining one world call to its immediate
/// first-person continuation.
struct RenderTokenStore {
    epoch: AtomicU32,
    route: AtomicU32,
}

impl RenderTokenStore {
    const fn new() -> Self {
        Self {
            epoch: AtomicU32::new(0),
            route: AtomicU32::new(0),
        }
    }

    fn publish(&self, epoch: u32, route: RenderRoute) {
        self.epoch.store(epoch, Ordering::Relaxed);
        self.route.store(route as u32, Ordering::Release);
    }

    fn consume(&self, route: RenderRoute) -> Option<u32> {
        let published_route = self.route.swap(0, Ordering::AcqRel);
        (published_route == route as u32).then(|| self.epoch.load(Ordering::Acquire))
    }

    fn invalidate(&self) {
        self.route.store(0, Ordering::Release);
    }
}

/// Return one coherent copy of the current MCM-owned camera configuration.
pub fn current_config() -> FirstPersonConfig {
    CONFIG.load()
}

/// Return the latest immutable post-UpdateCamera motion frame.
pub fn latest_motion_frame() -> CameraMotionFrame {
    FRAMES.load()
}

pub(crate) fn publish_config(config: FirstPersonConfig) {
    let previous = CONFIG.load();
    CONFIG.publish(config);
    if config != previous {
        clear_state();
    }
}

/// Install the shared camera-update entry required by both camera systems.
pub(crate) fn install_shared_update_entry(
    player_controls: PlayerControlsReader,
) -> Result<SharedCameraHookStatus, FirstPersonInstallError> {
    let _ = PLAYER_CONTROLS.set(player_controls);
    native::validate_update_camera_contract()?;
    Ok(SharedCameraHookStatus {
        update_entry: hooks::install_update_entry()?,
    })
}

/// Install the first-person-only render capability group.
///
/// The runtime calls this once from xNVSE's first post-Deferred main-loop
/// boundary. Installing after the complete DeferredInit listener walk is what
/// makes this wrapper outermost around compatible graphics predecessors which
/// own pre-render and post-render camera/depth work at the same callsites.
pub(crate) fn install_first_person_system() -> Result<FirstPersonHookStatus, FirstPersonInstallError>
{
    native::validate_contract()?;
    let predecessors = hooks::install_render_hooks()?;
    let status = FirstPersonHookStatus {
        route_a: predecessors.route_a,
        route_b: predecessors.route_b,
        first_person_special: predecessors.first_person_special,
        first_person_a: predecessors.first_person_a,
        first_person_b: predecessors.first_person_b,
    };
    FIRST_PERSON_ACTIVE.store(true, Ordering::Release);
    Ok(status)
}

/// Invalidate every temporal value and pending render pair.
pub(crate) fn clear_state() {
    RESET_GENERATION.fetch_add(1, Ordering::AcqRel);
    FRAMES.clear();
    invalidate_render_token();
}

/// Enable or disable bounded runtime-path collection with Atom telemetry.
pub(crate) fn configure_diagnostics(enabled: bool) {
    diagnostics::configure(enabled);
    third_person::configure_diagnostics(enabled);
}

/// Clear first-person path counters at the start of a telemetry epoch.
pub(crate) fn reset_diagnostics() {
    diagnostics::reset();
    third_person::reset_diagnostics();
}

/// Write the requested first-person path summary outside every native hook.
pub(crate) fn log_diagnostics_summary() {
    let snapshot = diagnostics::snapshot();
    let frame = FRAMES.load();
    let controls = PLAYER_CONTROLS
        .get()
        .map(|reader| {
            reader
                .get_disabled_flags(DisabledCheck::ByAnyModOrVanilla)
                .bits()
        })
        .unwrap_or_default();

    log::info!("[CAMERA_TELEMETRY] -------------------------------------------------------");
    log::info!("[CAMERA_TELEMETRY] Requested first-person path summary");
    log::info!(
        "[CAMERA_TELEMETRY] Update: calls={}, accepted={}, non_identity={}, motion_busy={}",
        snapshot.update_calls,
        snapshot.samples_accepted,
        snapshot.non_identity_frames,
        snapshot.motion_busy,
    );
    log::info!(
        "[CAMERA_TELEMETRY] Render: world_calls={}, admitted={}, head_poses={}, viewmodel_calls={}, weapon_poses={}, applied={}, rejected={}, token_misses={}",
        snapshot.world_calls,
        snapshot.world_admitted,
        snapshot.world_poses,
        snapshot.viewmodel_calls,
        snapshot.viewmodel_poses,
        snapshot.transforms_applied,
        snapshot.transforms_rejected,
        snapshot.token_misses,
    );
    log::info!(
        "[CAMERA_TELEMETRY] Latest frame: epoch={}, valid={}, head_motion={}, weapon_motion={}, combined_disabled_controls=0x{controls:04X}",
        frame.epoch(),
        frame.valid(),
        !frame.world_pose().is_identity(),
        !frame.viewmodel_pose().is_identity(),
    );
    for reason in native::NativeRejection::ALL {
        let sample = snapshot.sample_rejections(reason);
        let render = snapshot.render_rejections(reason);
        if sample != 0 || render != 0 {
            log::info!(
                "[CAMERA_TELEMETRY] Rejected by {}: sample={}, render={}",
                reason.label(),
                sample,
                render,
            );
        }
    }
    third_person::log_diagnostics_summary();
    log::info!("[CAMERA_TELEMETRY] -------------------------------------------------------");
}

/// Request a reset from an xNVSE lifecycle boundary.
pub(crate) fn request_reset() {
    clear_state();
    third_person::request_reset();
}

/// Expire a world-to-viewmodel pair at the presentation boundary.
pub(crate) fn finish_frame() {
    invalidate_render_token();
}

/// Publish or release an external native camera owner.
///
/// A nonzero owner token acquires the single capability slot. A different
/// owner cannot release or replace it accidentally. Every transition clears
/// pending motion before another render can be admitted.
pub(crate) fn set_external_owner(owner_token: u32, active: bool) -> bool {
    if owner_token == 0 {
        return false;
    }
    let result = if active {
        EXTERNAL_OWNER.compare_exchange(0, owner_token, Ordering::AcqRel, Ordering::Acquire)
    } else {
        EXTERNAL_OWNER.compare_exchange(owner_token, 0, Ordering::AcqRel, Ordering::Acquire)
    };
    let first_person_accepted = match result {
        Ok(_) => {
            clear_state();
            true
        }
        Err(current) => active && current == owner_token,
    };
    if !first_person_accepted {
        return false;
    }

    if third_person::set_external_owner(owner_token, active) {
        return true;
    }

    // External ownership covers the complete camera output set. If one side
    // cannot publish the transition, restore the first-person slot rather
    // than exposing split ownership to the provider.
    if active {
        let _ =
            EXTERNAL_OWNER.compare_exchange(owner_token, 0, Ordering::AcqRel, Ordering::Acquire);
    } else {
        let _ =
            EXTERNAL_OWNER.compare_exchange(0, owner_token, Ordering::AcqRel, Ordering::Acquire);
    }
    false
}

/// Route final horizontal look to the active third-person ownership epoch.
pub(crate) fn consume_horizontal_heading(player: *mut c_void, heading: f32) -> bool {
    third_person::consume_horizontal_heading(player, heading)
}

/// Refresh third-person AIM/Combat yaw after the native Actor route runs.
pub(crate) fn observe_native_horizontal_heading(player: *mut c_void) {
    third_person::observe_native_horizontal_heading(player);
}

/// Rejoin an Atom-owned third-person yaw offset before native look executes.
pub(crate) fn prepare_native_horizontal_heading(player: *mut c_void) {
    third_person::prepare_native_horizontal_heading(player);
}

/// Route final vertical look to the active third-person ownership epoch.
pub(crate) fn consume_vertical_heading(player: *mut c_void, heading: f32) -> bool {
    third_person::consume_vertical_heading(player, heading)
}

/// Align an owned third-person camera pitch before native AIM look executes.
pub(crate) fn prepare_native_vertical_heading(player: *mut c_void) {
    third_person::prepare_native_vertical_heading(player);
}

/// Refresh third-person Combat pitch after the native Actor route runs.
pub(crate) fn observe_native_vertical_heading(player: *mut c_void) {
    third_person::observe_native_vertical_heading(player);
}

/// Advance the generator after the chained native UpdateCamera returns.
///
/// # Safety
///
/// `player` must be the receiver supplied to the researched UpdateCamera entry.
pub(super) unsafe fn sample_after_update(
    player: *mut c_void,
    shared_motion: Option<NativeMotionCarrier>,
) {
    if !FIRST_PERSON_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    diagnostics::mark_update_call();
    let config = CONFIG.load();
    if !config.enabled() {
        FRAMES.clear();
        invalidate_render_token();
        return;
    }
    let sample = match unsafe { native::sample_after_update(player, shared_motion) } {
        Ok(sample) => sample,
        Err(reason) => {
            diagnostics::mark_sample_rejected(reason);
            clear_state();
            return;
        }
    };
    let generation = RESET_GENERATION.load(Ordering::Acquire);
    let Some(advance) = MOTION.advance(sample, config, generation) else {
        diagnostics::mark_motion_busy();
        clear_state();
        return;
    };
    let MotionAdvance::Published(frame) = advance else {
        // Any completed native camera rebuild invalidates a pending render
        // pair, but a duplicate caller must not erase the latest immutable
        // pose or integrate the same engine-time delta twice.
        invalidate_render_token();
        return;
    };
    diagnostics::mark_sample_accepted(
        !frame.world_pose().is_identity() || !frame.viewmodel_pose().is_identity(),
    );
    FRAMES.publish(frame);
    invalidate_render_token();
}

/// Admit one main world route and publish its immediate viewmodel token.
///
/// # Safety
///
/// The caller must be inside one of the researched main world callsites.
pub(super) unsafe fn begin_world_render(route: RenderRoute) -> Option<CameraMotionFrame> {
    diagnostics::mark_world_call();
    if !CONFIG.load().enabled() {
        invalidate_render_token();
        return None;
    }
    if let Err(reason) = unsafe { native::render_owner_allows() } {
        diagnostics::mark_render_rejected(reason);
        invalidate_render_token();
        return None;
    }
    let frame = FRAMES.load();
    if !frame.valid() || frame.epoch() == 0 {
        invalidate_render_token();
        return None;
    }
    // Render rate and native player-update rate are independent. Reusing the
    // latest immutable motion frame is required when more than one presented
    // frame consumes the same update; route-scoped single consumption below
    // still prevents a pose from escaping into an unrelated first-person call.
    RENDER_TOKEN.publish(frame.epoch(), route);
    diagnostics::mark_world_admitted();
    Some(frame)
}

/// Consume the only route/epoch token allowed to pose the viewmodel camera.
///
/// # Safety
///
/// The caller must be inside the paired researched RenderFirstPerson callsite.
pub(super) unsafe fn consume_viewmodel_render(route: RenderRoute) -> Option<CameraPose> {
    diagnostics::mark_viewmodel_call();
    let Some(token_epoch) = RENDER_TOKEN.consume(route) else {
        diagnostics::mark_token_miss();
        return None;
    };
    if !CONFIG.load().enabled() {
        diagnostics::mark_token_miss();
        return None;
    }
    if let Err(reason) = unsafe { native::render_owner_allows() } {
        diagnostics::mark_render_rejected(reason);
        return None;
    }
    let frame = FRAMES.load();
    if !frame.valid() || frame.epoch() != token_epoch {
        diagnostics::mark_token_miss();
        return None;
    }
    let pose = frame.viewmodel_pose();
    if !pose.is_identity() {
        diagnostics::mark_viewmodel_pose();
    }
    Some(pose)
}

pub(super) fn invalidate_render_token() {
    RENDER_TOKEN.invalidate();
}

pub(super) fn native_owners_allow_camera() -> bool {
    if EXTERNAL_OWNER.load(Ordering::Acquire) != 0 {
        return false;
    }
    PLAYER_CONTROLS.get().is_some_and(|reader| {
        !reader.any_disabled(DisabledCheck::ByAnyModOrVanilla, CAMERA_CONTROL_MASK)
    })
}

#[cfg(test)]
mod render_token_tests {
    use super::{RenderRoute, RenderTokenStore};

    #[test]
    fn route_token_is_single_consumer_and_route_exact() {
        let store = RenderTokenStore::new();
        store.publish(17, RenderRoute::A);
        assert_eq!(store.consume(RenderRoute::B), None);
        assert_eq!(store.consume(RenderRoute::A), None);

        store.publish(23, RenderRoute::B);
        assert_eq!(store.consume(RenderRoute::B), Some(23));
        assert_eq!(store.consume(RenderRoute::B), None);
    }

    #[test]
    fn invalidation_cannot_leak_an_outer_route_token() {
        let store = RenderTokenStore::new();
        store.publish(41, RenderRoute::A);
        store.invalidate();
        assert_eq!(store.consume(RenderRoute::A), None);
    }
}

#[cfg(test)]
mod tests {
    use super::{RenderRoute, RenderTokenStore};

    #[test]
    fn one_update_epoch_can_pair_multiple_presented_renders() {
        let token = RenderTokenStore::new();

        token.publish(17, RenderRoute::A);
        assert_eq!(token.consume(RenderRoute::A), Some(17));
        assert_eq!(token.consume(RenderRoute::A), None);

        // Presentation may outpace UpdateCamera. A new world call must be
        // able to publish the same immutable epoch for its own paired draw.
        token.publish(17, RenderRoute::A);
        assert_eq!(token.consume(RenderRoute::A), Some(17));
    }

    #[test]
    fn route_mismatch_consumes_the_token_without_cross_route_leakage() {
        let token = RenderTokenStore::new();
        token.publish(23, RenderRoute::A);

        assert_eq!(token.consume(RenderRoute::B), None);
        assert_eq!(token.consume(RenderRoute::A), None);
    }
}

//! Native camera base-FOV ownership.
//!
//! FNV already owns the complete FOV pipeline: `PlayerCharacter::UpdateFOV`
//! derives the live player fields from the `fDefault*` GameSettings, and
//! `PlayerCharacter::UpdateCamera` feeds them to `BSSceneGraph::SetCameraFOV`
//! and its aspect companion. The configured Atom targets are therefore applied
//! to the native bases, not to individual writer arguments:
//!
//! - world / first-person world: `fDefaultWorldFOV` and player `+0x670`;
//! - viewmodel / first-person field: `fDefault1stPersonFOV` and player `+0x674`;
//! - stable third person: `fOverShoulderFOV` and player `+0x678`;
//! - Pip-Boy / terminal: `fPipboy1stPersonFOV`;
//! - presentation: terminal projection scale, global iron-sight base and
//!   transition speed, dialogue zoom/delay, scope scissor, and near distance.
//!
//! Keeping the native bases authoritative means the engine's own ADS, scope,
//! VATS, kill-camera, Pip-Boy, 3D-UI projection, and world-to-screen caches all
//! observe one coherent value. Atom installs no writer detours and never
//! changes the angle a native caller passes to `SetCameraFOV`.
//!
//! The bases are restored when the configuration returns to native or the
//! capability is released. A normal-frame edge check reapplies them after
//! native special-camera/menu/VATS transitions and after an external reset.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use thiserror::Error;

use super::fov::{self, CameraFovConfig};
use super::native::{self, CameraPov, NativeRejection};

/// Failure to admit Atom's native FOV bases.
#[derive(Debug, Error)]
pub(crate) enum FovHookError {
    #[error(transparent)]
    Native(#[from] native::NativeContractError),
}

/// Captured native addresses for startup diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FovHookStatus {
    pub(super) world_setter: usize,
    pub(super) fov_aspect: usize,
}

/// Resolved native bases for one configuration snapshot.
#[derive(Clone, Copy, Debug, PartialEq)]
struct FovBases {
    world: f32,
    first_person: f32,
    over_shoulder: f32,
    pipboy: f32,
}

/// Resolved additional FOV/zoom controls.
#[derive(Clone, Copy, Debug, PartialEq)]
struct FovDetailBases {
    terminal: f32,
    iron_sight_fov: f32,
    iron_sight_speed: f32,
    dialog_zoom_in: f32,
    dialog_zoom_out: f32,
    dialog_delay: f32,
    scope_scissor: f32,
    near_distance: f32,
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static APPLIED: AtomicBool = AtomicBool::new(false);
static REAPPLY: AtomicBool = AtomicBool::new(false);
static SETTINGS_CAPTURED: AtomicBool = AtomicBool::new(false);
static ORIGINAL_SETTINGS: [AtomicU32; 4] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static ORIGINAL_DETAIL: [AtomicU32; 8] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static ORIGINAL_PLAYER: [AtomicU32; 3] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
static PLAYER_CAPTURED: AtomicBool = AtomicBool::new(false);
static LAST_OWNED_POV: AtomicU32 = AtomicU32::new(0);
static WAS_NON_OWNED: AtomicBool = AtomicBool::new(false);
static APPLY_TRACE: AtomicBool = AtomicBool::new(false);

/// Install native FOV base ownership.
///
/// No code is patched. The four `fDefault*` bases and the live player fields
/// are captured and the configured snapshot is applied through the native
/// camera writer pair.
pub(super) fn install_native_system() -> Result<FovHookStatus, FovHookError> {
    native::validate_fov_contract()?;
    ACTIVE.store(true, Ordering::Release);
    REAPPLY.store(true, Ordering::Release);
    APPLY_TRACE.store(false, Ordering::Release);
    apply_config();
    Ok(FovHookStatus {
        world_setter: native::SET_WORLD_FOV,
        fov_aspect: native::SET_FOV_ASPECT,
    })
}

/// Apply a newly published configuration or a lifecycle reset.
pub(super) fn reset_trace() {
    LAST_OWNED_POV.store(0, Ordering::Release);
    WAS_NON_OWNED.store(false, Ordering::Release);
    REAPPLY.store(true, Ordering::Release);
    APPLY_TRACE.store(false, Ordering::Release);
    if ACTIVE.load(Ordering::Acquire) {
        apply_config();
    }
}

/// Reapply the native bases after an update edge.
///
/// Called once after the native `UpdateCamera` completes. It only writes on a
/// configuration publication, a return to normal ownership, a POV change, or a
/// detected external reset of the native bases.
pub(super) fn after_update(player: *mut core::ffi::c_void) {
    if !ACTIVE.load(Ordering::Acquire) {
        return;
    }
    if !fov::configured() {
        if APPLIED.swap(false, Ordering::AcqRel) {
            restore_originals();
        }
        return;
    }
    let mode = match unsafe { native::fov_owner_pov(player) } {
        Ok(CameraPov::First) => 1_u32,
        Ok(CameraPov::Third) => 2_u32,
        Err(
            NativeRejection::Vats
            | NativeRejection::SpecialCamera
            | NativeRejection::FlyCamera
            | NativeRejection::Dead
            | NativeRejection::Menu
            | NativeRejection::PovTransitionA
            | NativeRejection::PovTransitionB,
        ) => {
            LAST_OWNED_POV.store(0, Ordering::Release);
            WAS_NON_OWNED.store(true, Ordering::Release);
            return;
        }
        Err(_) => return,
    };
    let last = LAST_OWNED_POV.swap(mode, Ordering::AcqRel);
    let returned = WAS_NON_OWNED.swap(false, Ordering::AcqRel);
    let pov_changed = last != 0 && last != mode;
    let forced = REAPPLY.swap(false, Ordering::AcqRel);
    if forced || returned || pov_changed {
        apply_bases(true);
        return;
    }
    // A special camera, menu, VATS, or another owner can reset the native
    // bases. Detect that only in stable gameplay and repair it once.
    let Some(originals) = load_original_settings() else {
        return;
    };
    let Some(plan) = resolve_bases(fov::current_config(), originals) else {
        return;
    };
    let Some(detail_originals) = load_original_detail() else {
        return;
    };
    let Some(details) = resolve_detail(fov::current_config(), detail_originals) else {
        return;
    };
    let Some(current) = (unsafe { native::native_fov_settings() }) else {
        return;
    };
    let Some(current_detail) = (unsafe { native::native_fov_detail_settings() }) else {
        return;
    };
    if bases_differ(current, plan) || detail_differs(current_detail, details) {
        apply_bases(true);
    }
}

fn detail_differs(current: [f32; 8], plan: FovDetailBases) -> bool {
    let plan = [
        plan.terminal,
        plan.iron_sight_fov,
        plan.iron_sight_speed,
        plan.dialog_zoom_in,
        plan.dialog_zoom_out,
        plan.dialog_delay,
        plan.scope_scissor,
        plan.near_distance,
    ];
    current
        .into_iter()
        .zip(plan)
        .any(|(live, target)| (live - target).abs() > 0.0001)
}

/// Apply the configuration immediately when possible.
fn apply_config() {
    if !ACTIVE.load(Ordering::Acquire) {
        return;
    }
    if !fov::configured() {
        if APPLIED.swap(false, Ordering::AcqRel) {
            restore_originals();
        }
        return;
    }
    // Capture and write only from stable normal gameplay. Deferring the first
    // application preserves the loaded game's original player fields instead
    // of capturing main-menu or transition values.
    if unsafe { native::fov_pov() }.is_none() {
        REAPPLY.store(true, Ordering::Release);
        return;
    }
    apply_bases(true);
}

/// Capture the engine's native bases and detail settings once.
fn capture_settings_originals() -> bool {
    if SETTINGS_CAPTURED.load(Ordering::Acquire) {
        return true;
    }
    let Some(bases) = (unsafe { native::native_fov_settings() }) else {
        return false;
    };
    if bases
        .into_iter()
        .any(|value| !value.is_finite() || !(1.0..179.0).contains(&value))
    {
        return false;
    }
    let Some(details) = (unsafe { native::native_fov_detail_settings() }) else {
        return false;
    };
    if resolve_detail(CameraFovConfig::default(), details).is_none() {
        return false;
    }
    for (slot, value) in ORIGINAL_SETTINGS.iter().zip(bases) {
        slot.store(value.to_bits(), Ordering::Release);
    }
    for (slot, value) in ORIGINAL_DETAIL.iter().zip(details) {
        slot.store(value.to_bits(), Ordering::Release);
    }
    SETTINGS_CAPTURED.store(true, Ordering::Release);
    true
}

/// Resolve and write one configuration snapshot.
///
/// `camera_ready` is true only on a stable normal-gameplay update. During a
/// menu/special camera the bases and player fields are prepared, but the
/// camera write is deferred to the first normal update.
fn apply_bases(camera_ready: bool) {
    if !capture_settings_originals() {
        REAPPLY.store(true, Ordering::Release);
        return;
    }
    let Some(originals) = load_original_settings() else {
        return;
    };
    let Some(plan) = resolve_bases(fov::current_config(), originals) else {
        return;
    };
    let Some(detail_originals) = load_original_detail() else {
        return;
    };
    let Some(details) = resolve_detail(fov::current_config(), detail_originals) else {
        return;
    };
    // The player fields must be captured from the engine's original bases
    // before any new setting can seed them. If the player is not ready yet,
    // leave the settings untouched and retry on the first normal update.
    if !capture_player_originals() {
        REAPPLY.store(true, Ordering::Release);
        return;
    }
    let detail_values = [
        details.terminal,
        details.iron_sight_fov,
        details.iron_sight_speed,
        details.dialog_zoom_in,
        details.dialog_zoom_out,
        details.dialog_delay,
        details.scope_scissor,
        details.near_distance,
    ];
    if !unsafe {
        native::write_native_fov_settings(
            plan.world,
            plan.first_person,
            plan.over_shoulder,
            plan.pipboy,
        )
    } || !unsafe { native::write_native_fov_detail_settings(detail_values) }
    {
        return;
    }
    unsafe {
        native::write_native_player_fov(plan.world, plan.first_person, plan.over_shoulder);
    }
    APPLIED.store(true, Ordering::Release);
    if !APPLY_TRACE.swap(true, Ordering::AcqRel) {
        log::info!(
            "[CAMERA_FOV] Native bases applied: world={:.0} first_person={:.0} over_shoulder={:.0} pipboy={:.0} terminal={:.2} iron_fov={:.0} iron_speed={:.2} dialog={:.2}/{:.2}/{:.2} scissor={:.2} near={:.1}",
            plan.world,
            plan.first_person,
            plan.over_shoulder,
            plan.pipboy,
            details.terminal,
            details.iron_sight_fov,
            details.iron_sight_speed,
            details.dialog_zoom_in,
            details.dialog_zoom_out,
            details.dialog_delay,
            details.scope_scissor,
            details.near_distance,
        );
    }
    if camera_ready || unsafe { native::fov_pov() }.is_some() {
        let lens = match unsafe { native::fov_pov() } {
            Some(CameraPov::Third) => plan.over_shoulder,
            _ => plan.world,
        };
        unsafe { native::apply_world_camera_fov(lens) };
    }
}

/// Restore every captured native base and the current camera lens.
fn restore_originals() {
    if !SETTINGS_CAPTURED.load(Ordering::Acquire) {
        return;
    }
    let Some(originals) = load_original_settings() else {
        return;
    };
    let Some(details) = load_original_detail() else {
        return;
    };
    unsafe {
        native::write_native_fov_settings(originals[0], originals[1], originals[2], originals[3]);
        native::write_native_fov_detail_settings(details);
        if PLAYER_CAPTURED.load(Ordering::Acquire) {
            native::write_native_player_fov(
                f32::from_bits(ORIGINAL_PLAYER[0].load(Ordering::Acquire)),
                f32::from_bits(ORIGINAL_PLAYER[1].load(Ordering::Acquire)),
                f32::from_bits(ORIGINAL_PLAYER[2].load(Ordering::Acquire)),
            );
        }
        let lens = match native::fov_pov() {
            Some(CameraPov::Third) => originals[2],
            _ => originals[0],
        };
        native::apply_world_camera_fov(lens);
    }
    log::info!(
        "[CAMERA_FOV] Native bases restored: world={:.0} first_person={:.0} over_shoulder={:.0} pipboy={:.0}",
        originals[0],
        originals[1],
        originals[2],
        originals[3],
    );
    LAST_OWNED_POV.store(0, Ordering::Release);
    WAS_NON_OWNED.store(false, Ordering::Release);
}

/// Capture the live player FOV fields once, before the first Atom write.
fn capture_player_originals() -> bool {
    if PLAYER_CAPTURED.load(Ordering::Acquire) {
        return true;
    }
    let Some(fields) = (unsafe { native::native_player_fov() }) else {
        return false;
    };
    if fields
        .into_iter()
        .any(|value| !value.is_finite() || !(1.0..179.0).contains(&value))
    {
        return false;
    }
    for (slot, value) in ORIGINAL_PLAYER.iter().zip(fields) {
        slot.store(value.to_bits(), Ordering::Release);
    }
    PLAYER_CAPTURED.store(true, Ordering::Release);
    true
}

fn load_original_settings() -> Option<[f32; 4]> {
    let mut values = [0.0_f32; 4];
    for (value, slot) in values.iter_mut().zip(ORIGINAL_SETTINGS.iter()) {
        *value = f32::from_bits(slot.load(Ordering::Acquire));
        if !value.is_finite() || !(1.0..179.0).contains(value) {
            return None;
        }
    }
    Some(values)
}

/// Resolve the four configured targets against the captured native bases.
fn resolve_bases(config: CameraFovConfig, originals: [f32; 4]) -> Option<FovBases> {
    let world = if config.first_person() != 0.0 {
        config.first_person()
    } else {
        originals[0]
    };
    let first_person = if config.viewmodel() != 0.0 {
        config.viewmodel()
    } else if config.first_person() != 0.0 {
        config.first_person()
    } else {
        originals[1]
    };
    let over_shoulder = if config.third_person() != 0.0 {
        config.third_person()
    } else {
        originals[2]
    };
    let pipboy = if config.pipboy() != 0.0 {
        config.pipboy()
    } else {
        originals[3]
    };
    let bases = FovBases {
        world,
        first_person,
        over_shoulder,
        pipboy,
    };
    [world, first_person, over_shoulder, pipboy]
        .into_iter()
        .all(|value| value.is_finite() && (1.0..179.0).contains(&value))
        .then_some(bases)
}

fn load_original_detail() -> Option<[f32; 8]> {
    let mut values = [0.0_f32; 8];
    for (value, slot) in values.iter_mut().zip(ORIGINAL_DETAIL.iter()) {
        *value = f32::from_bits(slot.load(Ordering::Acquire));
        if !value.is_finite() {
            return None;
        }
    }
    Some(values)
}

/// Resolve the additional controls against the captured native values.
fn resolve_detail(config: CameraFovConfig, originals: [f32; 8]) -> Option<FovDetailBases> {
    let details = FovDetailBases {
        terminal: if config.terminal() != 0.0 {
            config.terminal()
        } else {
            originals[0]
        },
        iron_sight_fov: if config.iron_sight_fov() != 0.0 {
            config.iron_sight_fov()
        } else {
            originals[1]
        },
        iron_sight_speed: if config.iron_sight_speed() != 0.0 {
            config.iron_sight_speed()
        } else {
            originals[2]
        },
        dialog_zoom_in: if config.dialog_zoom_in() != 0.0 {
            config.dialog_zoom_in()
        } else {
            originals[3]
        },
        dialog_zoom_out: if config.dialog_zoom_out() != 0.0 {
            config.dialog_zoom_out()
        } else {
            originals[4]
        },
        dialog_delay: if config.dialog_delay() != 0.0 {
            config.dialog_delay()
        } else {
            originals[5]
        },
        scope_scissor: if config.scope_scissor() != 0.0 {
            config.scope_scissor()
        } else {
            originals[6]
        },
        near_distance: if config.near_distance() != 0.0 {
            config.near_distance()
        } else {
            originals[7]
        },
    };
    let values = [
        details.terminal,
        details.iron_sight_fov,
        details.iron_sight_speed,
        details.dialog_zoom_in,
        details.dialog_zoom_out,
        details.dialog_delay,
        details.scope_scissor,
        details.near_distance,
    ];
    let ranges = [
        (0.0, 1.0),
        (0.0, 179.0),
        (0.0, 10.0),
        (0.0, 30.0),
        (0.0, 30.0),
        (0.0, 30.0),
        (0.0, 1.0),
        (0.0, 1000.0),
    ];
    if values
        .into_iter()
        .zip(ranges)
        .any(|(value, (minimum, maximum))| {
            !value.is_finite() || !(minimum..=maximum).contains(&value)
        })
    {
        return None;
    }
    Some(details)
}

fn bases_differ(current: [f32; 4], plan: FovBases) -> bool {
    let plan = [
        plan.world,
        plan.first_person,
        plan.over_shoulder,
        plan.pipboy,
    ];
    current
        .into_iter()
        .zip(plan)
        .any(|(live, target)| (live - target).abs() > 0.01)
}

#[cfg(test)]
mod tests {
    use super::{FovBases, FovDetailBases, resolve_bases, resolve_detail};
    use crate::camera::CameraFovConfig;

    const ORIGINALS: [f32; 4] = [75.0, 55.0, 55.0, 47.0];
    const DETAIL_ORIGINALS: [f32; 8] = [0.15, 50.0, 0.25, 1.5, 0.5, 2.0, 0.3, 5.0];

    #[test]
    fn zero_targets_keep_original_bases() {
        let config = CameraFovConfig::from_ini("").expect("empty config");
        assert_eq!(
            resolve_bases(config, ORIGINALS),
            Some(FovBases {
                world: 75.0,
                first_person: 55.0,
                over_shoulder: 55.0,
                pipboy: 47.0,
            })
        );
    }

    #[test]
    fn zero_viewmodel_follows_first_person_and_zero_fields_stay_native() {
        let config =
            CameraFovConfig::from_ini("[Fov]\nfFirstPerson=110\nfThirdPerson=105\nfPipboy=60\n")
                .expect("valid config");
        assert_eq!(
            resolve_bases(config, ORIGINALS),
            Some(FovBases {
                world: 110.0,
                first_person: 110.0,
                over_shoulder: 105.0,
                pipboy: 60.0,
            })
        );
    }

    #[test]
    fn independent_viewmodel_and_native_fields_are_resolved() {
        let config = CameraFovConfig::from_ini("[Fov]\nfViewmodel=90\n").expect("valid config");
        assert_eq!(
            resolve_bases(config, ORIGINALS),
            Some(FovBases {
                world: 75.0,
                first_person: 90.0,
                over_shoulder: 55.0,
                pipboy: 47.0,
            })
        );
    }

    #[test]
    fn invalid_original_bases_are_rejected() {
        assert_eq!(resolve_bases(CameraFovConfig::default(), [0.0; 4]), None);
    }

    #[test]
    fn zero_detail_targets_keep_every_native_value() {
        let config = CameraFovConfig::from_ini("").expect("empty config");
        assert_eq!(
            resolve_detail(config, DETAIL_ORIGINALS),
            Some(FovDetailBases {
                terminal: 0.15,
                iron_sight_fov: 50.0,
                iron_sight_speed: 0.25,
                dialog_zoom_in: 1.5,
                dialog_zoom_out: 0.5,
                dialog_delay: 2.0,
                scope_scissor: 0.3,
                near_distance: 5.0,
            })
        );
    }

    #[test]
    fn independent_detail_targets_are_resolved() {
        let config = CameraFovConfig::from_ini(
            "[Fov]\nfTerminal=0.25\nfIronSightFov=67\nfIronSightSpeed=0.1\n\
             fDialogZoomIn=1.0\nfDialogZoomOut=0.25\nfDialogDelay=1.5\n\
             fScopeScissor=0.2\nfNearDistance=10\n",
        )
        .expect("valid detail config");
        assert_eq!(
            resolve_detail(config, DETAIL_ORIGINALS),
            Some(FovDetailBases {
                terminal: 0.25,
                iron_sight_fov: 67.0,
                iron_sight_speed: 0.1,
                dialog_zoom_in: 1.0,
                dialog_zoom_out: 0.25,
                dialog_delay: 1.5,
                scope_scissor: 0.2,
                near_distance: 10.0,
            })
        );
    }
}

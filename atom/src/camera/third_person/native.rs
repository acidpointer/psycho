//! Audited Fallout: New Vegas 1.4.0.525 third-person native contract.
//!
//! The plugin query rejects other runtime versions and `DeferredInit`
//! validates fixed globals and helper prologues before any hook is enabled.
//! Native callbacks copy only the fields needed for their current call; no
//! engine pointer is retained across an update, load, or ownership epoch.

use core::ffi::c_void;
use core::mem::size_of;

use libnvse::api::player_controls::{ControlFlags, DisabledCheck, PlayerControlsReader};
use libpsycho::os::windows::memory::{MemoryError, read_bytes, validate_memory_range};
use thiserror::Error;

use crate::camera::LocomotionState;
use crate::input::{ActionContext, ActionId, latest_action_frame};

use super::super::NativeMotionCarrier;
use super::{AimAngles, Vec3};

const PLAYER_PTR: usize = 0x011D_EA3C;
const TES_PTR: usize = 0x011D_EA10;
const OS_GLOBALS_PTR: usize = 0x011D_EA0C;
const INTERFACE_MANAGER_PTR: usize = 0x011D_8A80;
const SPECIAL_CAMERA_STATE: usize = 0x011E_07B8;
const NATIVE_CAMERA: usize = 0x011E_0C20;
const DESIRED_THIRD_PERSON_DISTANCE: usize = 0x011E_0B5C;
const VATS_CAMERA_DATA: usize = 0x011F_2250;
const TIME_GLOBAL: usize = 0x011F_6394;

const VANITY_WHEEL_IN_SETTING: usize = 0x011C_DC98;
const VANITY_WHEEL_OUT_SETTING: usize = 0x011C_D2AC;
const VANITY_WHEEL_MIN_SETTING: usize = 0x011C_DA94;
const VANITY_WHEEL_MAX_SETTING: usize = 0x011C_DE14;
const CHASE_CAMERA_MAX_SETTING: usize = 0x011C_D568;
const OVER_SHOULDER_X_SETTING: usize = 0x011C_DC5C;
const OVER_SHOULDER_Z_SETTING: usize = 0x011C_DC44;
const FLOAT_SETTING_VALUE: usize = 0x04;

const PLAYER_PARENT_CELL: usize = 0x040;
const PLAYER_PROCESS: usize = 0x068;
const PLAYER_LIFE_STATE: usize = 0x108;
const PLAYER_MOVER: usize = 0x190;
const PLAYER_MOVER_FLAGS: usize = 0x094;
const MOVEMENT_DIRECTION_MASK: u32 = 0x0F;
const PLAYER_COLLISION_OWNER: usize = 0x21C;
const PLAYER_ROTATION_X: usize = 0x024;
const PLAYER_ROTATION_Z: usize = 0x02C;
const PLAYER_POSITION: usize = 0x030;
const PLAYER_POV_READY: usize = 0x64A;
const PLAYER_ACTIVE_PERSPECTIVE: usize = 0x64B;
const PLAYER_THIRD_PERSON: usize = 0x64C;
const PLAYER_DISABLED_CONTROLS: usize = 0x680;
const PLAYER_CAMERA_HEADING_OFFSET: usize = 0x6E4;

const OS_GLOBALS_FLY_CAMERA: usize = 0x006;
const INTERFACE_MANAGER_ACTIVE: usize = 0x000;
const INTERFACE_MANAGER_MODE: usize = 0x00C;
const GAMEPLAY_INTERFACE_MODE: u32 = 1;
const VATS_MODE: usize = 0x008;
const TIME_SECONDS_PASSED: usize = 0x00C;

const PROCESS_CURRENT_ACTION_VTBL: usize = 0x3E4;
const PROCESS_IS_AIMING_VTBL: usize = 0x404;
const PROCESS_KNOCKED_STATE_VTBL: usize = 0x40C;
const PROCESS_WEAPON_OUT_VTBL: usize = 0x454;
const PROCESS_FURNITURE_STATE_VTBL: usize = 0x4BC;
const PROCESS_WEAPON_INFO: usize = 0x114;
const PROCESS_ANIM_DATA: usize = 0x1C0;
const WEAPON_INFO_WEAPON: usize = 0x08;
const ACTOR_ADJUSTED_HEADING_VTBL: usize = 0x2BC;
const ACTOR_SET_YAW_VTBL: usize = 0x2C4;

const ACTIVE_3D: usize = 0x0095_0BE0;
const WEAPON_PROJECTILE_NODE: usize = 0x0052_5700;
const MATRIX_TO_ANGLES: usize = 0x00A5_9400;
const STOP_ANIMATION_SEQUENCE_TYPE: usize = 0x0049_94F0;
const ACTOR_SET_PITCH: usize = 0x0093_1D90;
const GET_CHARACTER_CONTROLLER: usize = 0x0093_06D0;
const GET_CONTROLLER_STATE: usize = 0x005C_0880;
const GET_SUPPORT_RELATIVE_VELOCITY: usize = 0x0081_2B00;
const PICK_DATA_CONSTRUCTOR: usize = 0x004A_3C20;
const PICK_DATA_SET_FROM: usize = 0x004A_3DA0;
const PICK_DATA_SET_TO: usize = 0x004A_3EB0;
const TES_PICK_OBJECT: usize = 0x0045_8420;
const PLAYER_COLLISION_FILTER: usize = 0x0093_1ED0;

const WEAPON_TYPE: usize = 0x0F4;
const WEAPON_FLAGS_2: usize = 0x12C;
const WEAPON_NO_THIRD_PERSON_IS_ANIMS: u32 = 0x0000_0100;
const ANIM_DATA_ACTOR: usize = 0x004;
const ANIM_DATA_SEQUENCES: usize = 0x0E0;
const ANIM_SEQUENCE_COUNT: usize = 8;
const ANIM_SEQUENCE_STATE: usize = 0x044;
const ANIM_SEQUENCE_GROUP: usize = 0x068;
const ANIM_GROUP_CODE: usize = 0x008;
const PROJECTILE_TYPE_FLAGS: usize = 0x060;
const PROJECTILE_RANGE: usize = 0x06C;
const PROJECTILE_TYPE_MASK: u32 = 0x001F_0000;
const MISSILE_PROJECTILE: u32 = 0x0001_0000;
const NIAVOBJECT_WORLD_ROTATION: usize = 0x068;
const NIAVOBJECT_LOCAL_TRANSLATION: usize = 0x058;
const NIAVOBJECT_WORLD_POSITION: usize = 0x08C;
const PICK_DATA_FILTER: usize = 0x024;
const PICK_DATA_HIT_FRACTION: usize = 0x040;
const PICK_DATA_FAILED: usize = 0x0AC;
const PICK_DATA_SIZE: usize = 0x0B0;
const PROJECTILE_COLLISION_LAYER: u32 = 6;
const MIN_ENGINE_POINTER: usize = 0x1_0000;
// HighProcess::AnimAction values which keep a native attack authored after
// the input edge. The range covers firearm/melee follow-through and both
// thrown-weapon phases without treating reload or unrelated actions as fire.
const ATTACK_ACTION: i16 = 2;
const ATTACK_FOLLOW_THROUGH_ACTION: i16 = 3;
const ATTACK_LATENCY_ACTION: i16 = 4;
const ATTACK_THROW_ATTACH_ACTION: i16 = 5;
const ATTACK_THROW_RELEASE_ACTION: i16 = 6;
const SCRIPTED_ACTION_A: i16 = 0x0D;
const SCRIPTED_ACTION_B: i16 = 0x0E;
const VANILLA_CAMERA_DISABLED_MASK: u8 = 0x17;
const VANILLA_FIGHTING_DISABLED: u8 = 0x08;

type Active3dFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type ProcessActionFn = unsafe extern "thiscall" fn(*mut c_void) -> i16;
type ProcessBoolFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;
type ProcessStateFn = unsafe extern "thiscall" fn(*mut c_void) -> i32;
type ActorAdjustedHeadingFn = unsafe extern "thiscall" fn(*mut c_void, u8) -> f32;
type ActorSetYawFn = unsafe extern "thiscall" fn(*mut c_void, f32);
type ActorSetPitchFn = unsafe extern "thiscall" fn(*mut c_void, f32);
type GetCharacterControllerFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type GetControllerStateFn = unsafe extern "thiscall" fn(*mut c_void) -> u32;
type GetRelativeVelocityFn = unsafe extern "thiscall" fn(*mut c_void, *mut NativePoint3);
type PickDataConstructorFn =
    unsafe extern "thiscall" fn(*mut NativePickData) -> *mut NativePickData;
type PickDataPointFn = unsafe extern "thiscall" fn(*mut NativePickData, *const Vec3);
type PlayerCollisionFilterFn = unsafe extern "thiscall" fn(*mut c_void, *mut u32) -> *mut u32;
type TesPickObjectFn = unsafe extern "thiscall" fn(*mut c_void, *mut NativePickData) -> *mut c_void;
type ProjectileNodeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> *mut c_void;
type MatrixAnglesFn =
    unsafe extern "thiscall" fn(*const [[f32; 3]; 3], *mut f32, *mut f32, *mut f32) -> u8;
type StopAnimationSequenceTypeFn = unsafe extern "thiscall" fn(*mut c_void, u32, u8);

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct NativePoint3 {
    x: f32,
    y: f32,
    z: f32,
}

/// Stack-owned FNV `bhkPickData` used by one synchronous world ray.
///
/// The engine constructor initializes its input/output bases and collector
/// pointers. The type is opaque here because Atom needs only the researched
/// collision filter, hit fraction, and failure fields.
#[repr(C, align(16))]
struct NativePickData {
    bytes: [u8; PICK_DATA_SIZE],
}

/// Native distance and shoulder values owned as one framing profile.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeFraming {
    pub(super) minimum_distance: f32,
    pub(super) maximum_distance: f32,
    pub(super) vanity_maximum_distance: f32,
    pub(super) side_offset: f32,
    pub(super) height_offset: f32,
}

impl NativeFraming {
    pub(super) fn is_finite(self) -> bool {
        [
            self.minimum_distance,
            self.maximum_distance,
            self.vanity_maximum_distance,
            self.side_offset,
            self.height_offset,
        ]
        .into_iter()
        .all(f32::is_finite)
    }
}

/// Native values copied for one third-person ownership decision.
#[derive(Clone, Copy, Debug)]
pub(super) struct NativeFrame {
    pub(super) frame_id: u32,
    pub(super) player: *mut c_void,
    pub(super) mover: *mut c_void,
    pub(super) cell: *mut c_void,
    pub(super) pivot: Vec3,
    pub(super) actor_yaw: f32,
    pub(super) camera_heading: f32,
    pub(super) camera_heading_offset: f32,
    pub(super) pitch: f32,
    pub(super) delta_seconds: f32,
    pub(super) stable_third_person: bool,
    pub(super) world_ready: bool,
    pub(super) native_owner: bool,
    pub(super) hard_valid: bool,
    pub(super) rejection: NativeRejection,
    pub(super) weapon_out: bool,
    pub(super) combat_intent: bool,
}

/// Live inputs consumed by FNV's native wheel-distance calculation.
#[derive(Clone, Copy, Debug)]
pub(super) struct NativeZoomSample {
    pub(super) desired_distance: f32,
    pub(super) multiplier: f32,
}

/// First fail-closed reason attached to one native ownership observation.
///
/// Diagnostics retain only bounded counters for these values. The enum never
/// crosses Atom's ABI and does not retain any engine pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(super) enum NativeRejection {
    Accepted,
    InvalidPlayer,
    PlayerMismatch,
    MissingActionFrame,
    Perspective,
    MissingMover,
    MissingCell,
    MissingProcess,
    MissingCollision,
    MissingActive3d,
    DisabledControls,
    FlyCamera,
    Vats,
    Menu,
    SpecialCamera,
    Dead,
    Knocked,
    Furniture,
    ScriptedAction,
    ActionContext,
    InvalidValues,
    ExternalOwner,
}

impl NativeRejection {
    pub(super) const COUNT: usize = 22;
    pub(super) const ALL: [Self; Self::COUNT] = [
        Self::Accepted,
        Self::InvalidPlayer,
        Self::PlayerMismatch,
        Self::MissingActionFrame,
        Self::Perspective,
        Self::MissingMover,
        Self::MissingCell,
        Self::MissingProcess,
        Self::MissingCollision,
        Self::MissingActive3d,
        Self::DisabledControls,
        Self::FlyCamera,
        Self::Vats,
        Self::Menu,
        Self::SpecialCamera,
        Self::Dead,
        Self::Knocked,
        Self::Furniture,
        Self::ScriptedAction,
        Self::ActionContext,
        Self::InvalidValues,
        Self::ExternalOwner,
    ];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted native state",
            Self::InvalidPlayer => "invalid player",
            Self::PlayerMismatch => "player ownership mismatch",
            Self::MissingActionFrame => "missing action frame",
            Self::Perspective => "POV transition",
            Self::MissingMover => "missing player mover",
            Self::MissingCell => "missing cell",
            Self::MissingProcess => "missing process",
            Self::MissingCollision => "missing collision owner",
            Self::MissingActive3d => "missing active 3D",
            Self::DisabledControls => "disabled controls",
            Self::FlyCamera => "free camera",
            Self::Vats => "VATS",
            Self::Menu => "menu mode",
            Self::SpecialCamera => "special camera",
            Self::Dead => "dead player",
            Self::Knocked => "knocked state",
            Self::Furniture => "furniture",
            Self::ScriptedAction => "scripted action",
            Self::ActionContext => "non-gameplay action context",
            Self::InvalidValues => "invalid sampled values",
            Self::ExternalOwner => "external camera owner",
        }
    }
}

/// Failure to admit the fixed third-person native contract.
#[derive(Debug, Error)]
pub(crate) enum NativeContractError {
    /// A required native data or function range is unavailable.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// A supported-runtime helper differs from the researched executable.
    #[error("third-person native fingerprint mismatch at 0x{address:08X}")]
    FingerprintMismatch { address: usize },
}

pub(super) fn validate_data_contract() -> Result<(), NativeContractError> {
    for (address, length) in [
        (PLAYER_PTR, size_of::<*mut c_void>()),
        (OS_GLOBALS_PTR, size_of::<*mut c_void>()),
        (INTERFACE_MANAGER_PTR, size_of::<*mut c_void>()),
        (SPECIAL_CAMERA_STATE, size_of::<u8>()),
        (
            NATIVE_CAMERA + NIAVOBJECT_LOCAL_TRANSLATION,
            size_of::<Vec3>(),
        ),
        (VATS_CAMERA_DATA + VATS_MODE, size_of::<u32>()),
        (TIME_GLOBAL + TIME_SECONDS_PASSED, size_of::<f32>()),
    ] {
        validate_memory_range(address as *const c_void, length)?;
    }
    let fingerprints: &[(usize, &[u8])] = &[
        (ACTIVE_3D, &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC]),
        (
            WEAPON_PROJECTILE_NODE,
            &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x89, 0x4D, 0xF4],
        ),
        (
            MATRIX_TO_ANGLES,
            &[0x51, 0x56, 0x8B, 0xF1, 0xD9, 0x46, 0x1C],
        ),
        (
            ACTOR_SET_PITCH,
            &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x89, 0x4D, 0xF4],
        ),
    ];
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(NativeContractError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

/// Validate the independently installed normal-third-person wheel contract.
pub(super) fn validate_zoom_contract() -> Result<(), NativeContractError> {
    for (address, length) in [
        (DESIRED_THIRD_PERSON_DISTANCE, size_of::<f32>()),
        (
            VANITY_WHEEL_IN_SETTING + FLOAT_SETTING_VALUE,
            size_of::<f32>(),
        ),
        (
            VANITY_WHEEL_OUT_SETTING + FLOAT_SETTING_VALUE,
            size_of::<f32>(),
        ),
    ] {
        validate_memory_range(address as *const c_void, length)?;
    }
    Ok(())
}

/// Validate writable native settings used by Atom's opt-in framing owner.
pub(super) fn validate_framing_contract() -> Result<(), NativeContractError> {
    for address in [
        DESIRED_THIRD_PERSON_DISTANCE,
        VANITY_WHEEL_MIN_SETTING + FLOAT_SETTING_VALUE,
        VANITY_WHEEL_MAX_SETTING + FLOAT_SETTING_VALUE,
        CHASE_CAMERA_MAX_SETTING + FLOAT_SETTING_VALUE,
        OVER_SHOULDER_X_SETTING + FLOAT_SETTING_VALUE,
        OVER_SHOULDER_Z_SETTING + FLOAT_SETTING_VALUE,
    ] {
        validate_memory_range(address as *const c_void, size_of::<f32>())?;
    }
    Ok(())
}

/// Validate the character-controller functions used only by camera motion.
pub(super) fn validate_motion_contract() -> Result<(), NativeContractError> {
    validate_memory_range(
        DESIRED_THIRD_PERSON_DISTANCE as *const c_void,
        size_of::<f32>(),
    )?;
    let fingerprints: &[(usize, &[u8])] = &[
        (
            GET_CHARACTER_CONTROLLER,
            &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC],
        ),
        (
            GET_CONTROLLER_STATE,
            &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC],
        ),
        (
            GET_SUPPORT_RELATIVE_VELOCITY,
            &[0x53, 0x8B, 0xDC, 0x51, 0x83, 0xE4, 0xF0, 0x83, 0xC4, 0x04],
        ),
    ];
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(NativeContractError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

/// Validate FNV's native upper-body stop/fade owner used at hip-fire release.
pub(super) fn validate_hip_fire_pose_contract() -> Result<(), NativeContractError> {
    // The entry is intentionally not fingerprinted: compatible animation
    // plugins commonly install a complete JMP there before Atom reaches
    // DeferredInit. Immutable instructions inside the original body prove the
    // native stop/type lookup and epilogue while leaving the entry chainable.
    let fingerprints: &[(usize, &[u8])] = &[
        (
            STOP_ANIMATION_SEQUENCE_TYPE + 0x61,
            &[
                0x8B, 0x45, 0xE8, 0x8B, 0x4D, 0xDC, 0x8B, 0x94, 0x81, 0xE0, 0x00, 0x00, 0x00, 0x89,
                0x55,
            ],
        ),
        (
            STOP_ANIMATION_SEQUENCE_TYPE + 0x2AC,
            &[0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00],
        ),
    ];
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(NativeContractError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

/// Validate the synchronous projectile-layer ray used only by convergence.
///
/// This contract is independent of the interaction ViewCaster. A failure may
/// disable projectile convergence without taking camera-correct object
/// selection away from the user.
pub(super) fn validate_combat_ray_contract() -> Result<(), NativeContractError> {
    validate_memory_range(TES_PTR as *const c_void, size_of::<*mut c_void>())?;
    let fingerprints: &[(usize, &[u8])] = &[
        (
            PICK_DATA_CONSTRUCTOR,
            &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC],
        ),
        (
            PICK_DATA_SET_FROM,
            &[0x53, 0x8B, 0xDC, 0x51, 0x83, 0xE4, 0xF0, 0x83, 0xC4, 0x04],
        ),
        (
            PICK_DATA_SET_TO,
            &[0x53, 0x8B, 0xDC, 0x51, 0x83, 0xE4, 0xF0, 0x83, 0xC4, 0x04],
        ),
        (
            TES_PICK_OBJECT,
            &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x6A, 0x01],
        ),
        (
            PLAYER_COLLISION_FILTER,
            &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x18, 0x89, 0x4D, 0xEC],
        ),
    ];
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(NativeContractError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

/// Copy the currently active native framing profile.
///
/// # Safety
///
/// [`validate_framing_contract`] must have succeeded during `DeferredInit`.
pub(super) unsafe fn read_framing() -> Option<NativeFraming> {
    let values = NativeFraming {
        minimum_distance: unsafe {
            read_f32_volatile(VANITY_WHEEL_MIN_SETTING + FLOAT_SETTING_VALUE)
        },
        maximum_distance: unsafe {
            read_f32_volatile(CHASE_CAMERA_MAX_SETTING + FLOAT_SETTING_VALUE)
        },
        vanity_maximum_distance: unsafe {
            read_f32_volatile(VANITY_WHEEL_MAX_SETTING + FLOAT_SETTING_VALUE)
        },
        side_offset: unsafe { read_f32_volatile(OVER_SHOULDER_X_SETTING + FLOAT_SETTING_VALUE) },
        height_offset: unsafe { read_f32_volatile(OVER_SHOULDER_Z_SETTING + FLOAT_SETTING_VALUE) },
    };
    values.is_finite().then_some(values)
}

/// Publish one complete native framing profile.
///
/// # Safety
///
/// [`validate_framing_contract`] must have succeeded and the caller must run
/// on FNV's game thread at `DeferredInit` or an MCM/camera update boundary.
pub(super) unsafe fn write_framing(values: NativeFraming) -> bool {
    if !values.is_finite() {
        return false;
    }
    unsafe {
        write_f32_volatile(
            VANITY_WHEEL_MIN_SETTING + FLOAT_SETTING_VALUE,
            values.minimum_distance,
        );
        write_f32_volatile(
            CHASE_CAMERA_MAX_SETTING + FLOAT_SETTING_VALUE,
            values.maximum_distance,
        );
        write_f32_volatile(
            VANITY_WHEEL_MAX_SETTING + FLOAT_SETTING_VALUE,
            values.vanity_maximum_distance,
        );
        write_f32_volatile(
            OVER_SHOULDER_X_SETTING + FLOAT_SETTING_VALUE,
            values.side_offset,
        );
        write_f32_volatile(
            OVER_SHOULDER_Z_SETTING + FLOAT_SETTING_VALUE,
            values.height_offset,
        );
    }
    true
}

/// Restore only framing values which still match Atom's last publication.
///
/// # Safety
///
/// The framing contract and game-thread requirements of [`write_framing`]
/// apply. Per-field comparison prevents overwriting a newer native owner.
pub(super) unsafe fn restore_framing(baseline: NativeFraming, owned: NativeFraming) {
    for (address, baseline_value, owned_value) in [
        (
            VANITY_WHEEL_MIN_SETTING + FLOAT_SETTING_VALUE,
            baseline.minimum_distance,
            owned.minimum_distance,
        ),
        (
            CHASE_CAMERA_MAX_SETTING + FLOAT_SETTING_VALUE,
            baseline.maximum_distance,
            owned.maximum_distance,
        ),
        (
            VANITY_WHEEL_MAX_SETTING + FLOAT_SETTING_VALUE,
            baseline.vanity_maximum_distance,
            owned.vanity_maximum_distance,
        ),
        (
            OVER_SHOULDER_X_SETTING + FLOAT_SETTING_VALUE,
            baseline.side_offset,
            owned.side_offset,
        ),
        (
            OVER_SHOULDER_Z_SETTING + FLOAT_SETTING_VALUE,
            baseline.height_offset,
            owned.height_offset,
        ),
    ] {
        if let Some(restored) = framing_restoration_value(
            unsafe { read_f32_volatile(address) },
            baseline_value,
            owned_value,
        ) {
            unsafe { write_f32_volatile(address, restored) };
        }
    }
}

fn framing_restoration_value(current: f32, baseline: f32, owned: f32) -> Option<f32> {
    (current.to_bits() == owned.to_bits()).then_some(baseline)
}

/// Read the collision-independent native desired chase distance.
///
/// # Safety
///
/// Either the framing, zoom, or motion contract must have validated this
/// fixed global before use.
pub(super) unsafe fn desired_distance() -> Option<f32> {
    let value = unsafe { read_f32_volatile(DESIRED_THIRD_PERSON_DISTANCE) };
    (value.is_finite() && value > 0.0).then_some(value)
}

/// Set the collision-independent native desired chase distance.
///
/// # Safety
///
/// [`validate_framing_contract`] must have succeeded and the caller must run
/// at the documented game-thread framing boundary.
pub(super) unsafe fn write_desired_distance(value: f32) -> bool {
    if !value.is_finite() || value <= 0.0 {
        return false;
    }
    unsafe { write_f32_volatile(DESIRED_THIRD_PERSON_DISTANCE, value) };
    true
}

/// Copy native controller velocity and support state for camera motion.
///
/// # Safety
///
/// [`validate_motion_contract`] must have succeeded and `player` must be the
/// receiver of the active researched `UpdateCamera` callback.
pub(super) unsafe fn motion_sample(player: *mut c_void) -> Option<NativeMotionCarrier> {
    if !is_engine_pointer(player) {
        return None;
    }
    let mover = unsafe { read_ptr(player.cast(), PLAYER_MOVER) };
    if !is_engine_pointer(mover) {
        return None;
    }
    let directional_locomotion =
        unsafe { read_u32(mover.cast(), PLAYER_MOVER_FLAGS) } & MOVEMENT_DIRECTION_MASK != 0;
    let controller = unsafe { get_character_controller()(player) };
    if !is_engine_pointer(controller) {
        return None;
    }
    let locomotion = match unsafe { get_controller_state()(controller) } {
        0 => LocomotionState::Grounded,
        1 => LocomotionState::Jumping,
        2 => LocomotionState::Airborne,
        _ => LocomotionState::Unsupported,
    };
    if locomotion == LocomotionState::Unsupported {
        return None;
    }
    let mut velocity = NativePoint3::default();
    unsafe { get_relative_velocity()(controller, &mut velocity) };
    let velocity = Vec3::new(velocity.x, velocity.y, velocity.z);
    velocity.is_finite().then_some(NativeMotionCarrier::new(
        [velocity.x, velocity.y, velocity.z],
        locomotion,
        directional_locomotion,
    ))
}

/// Read the desired distance and direction-specific multiplier for one wheel sample.
///
/// The desired value at `0x011E0B5C` is intentionally distinct from realized
/// distance `0x011E0768`: native collision is allowed to contract the latter
/// and later recover toward the former. Rebasing fine zoom on realized distance
/// would destroy that recovery history near walls.
///
/// # Safety
///
/// [`validate_zoom_contract`] must have succeeded during `DeferredInit` and
/// this function may be called only from the fingerprinted player-camera wheel
/// callsite.
pub(super) unsafe fn zoom_sample(raw_delta: i32) -> Option<NativeZoomSample> {
    if raw_delta == 0 {
        return None;
    }
    let setting = if raw_delta > 0 {
        VANITY_WHEEL_IN_SETTING
    } else {
        VANITY_WHEEL_OUT_SETTING
    };
    let desired_distance = unsafe { read_f32_volatile(DESIRED_THIRD_PERSON_DISTANCE) };
    let multiplier = unsafe { read_f32_volatile(setting + FLOAT_SETTING_VALUE) };
    (desired_distance.is_finite()
        && desired_distance > 0.0
        && multiplier.is_finite()
        && multiplier > 0.0)
        .then_some(NativeZoomSample {
            desired_distance,
            multiplier,
        })
}

pub(super) fn player() -> *mut c_void {
    unsafe { core::ptr::read_volatile(PLAYER_PTR as *const *mut c_void) }
}

/// Recheck cheap third-person ownership predicates before a render-scoped pose.
///
/// The update callback already performs the full process/action classification.
/// Render may run at a different rate, so this seam repeats pointer, POV,
/// control, menu, VATS, and camera-owner checks without another controller
/// lock or animation-graph traversal.
///
/// # Safety
///
/// The caller must be inside a researched complete world-render route.
pub(super) unsafe fn render_owner_allows(
    expected_player: *mut c_void,
    controls: PlayerControlsReader,
) -> bool {
    let player = self::player();
    if !is_engine_pointer(player) || player != expected_player {
        return false;
    }
    let stable_third_person = unsafe {
        read_u8(player.cast(), PLAYER_POV_READY) != 0
            && read_u8(player.cast(), PLAYER_ACTIVE_PERSPECTIVE) != 0
            && read_u8(player.cast(), PLAYER_THIRD_PERSON) != 0
    };
    if !stable_third_person
        || unsafe { read_u8(player.cast(), PLAYER_LIFE_STATE) } != 0
        || !is_engine_pointer(unsafe { read_ptr(player.cast(), PLAYER_PROCESS) })
        || !is_engine_pointer(unsafe { read_ptr(player.cast(), PLAYER_PARENT_CELL) })
        || !is_engine_pointer(unsafe { read_ptr(player.cast(), PLAYER_MOVER) })
        || !is_engine_pointer(unsafe { read_ptr(player.cast(), PLAYER_COLLISION_OWNER) })
    {
        return false;
    }
    let camera_controls =
        ControlFlags::MOVEMENT | ControlFlags::LOOKING | ControlFlags::PIPBOY | ControlFlags::POV;
    if controls.any_disabled(DisabledCheck::ByAnyModOrVanilla, camera_controls)
        || unsafe { read_u8(player.cast(), PLAYER_DISABLED_CONTROLS) }
            & VANILLA_CAMERA_DISABLED_MASK
            != 0
        || unsafe { read_u32(VATS_CAMERA_DATA as *const u8, VATS_MODE) } != 0
        || unsafe { read_u8(SPECIAL_CAMERA_STATE as *const u8, 0) } != 0
        || unsafe { menu_mode_active() }
        || latest_action_frame().context() != ActionContext::Gameplay
    {
        return false;
    }
    let os_globals = unsafe { read_global_ptr(OS_GLOBALS_PTR) };
    is_engine_pointer(os_globals)
        && unsafe { read_u8(os_globals.cast(), OS_GLOBALS_FLY_CAMERA) } == 0
}

/// Copy all ownership predicates for the current call.
///
/// # Safety
///
/// `expected_player` must be null or the receiver supplied by the current
/// researched player callsite. No pointer returned in the frame may be used
/// after the surrounding native callback returns.
pub(super) unsafe fn observe(
    expected_player: *mut c_void,
    controls: PlayerControlsReader,
) -> NativeFrame {
    let actions = latest_action_frame();
    let attack = actions.action(ActionId::Use);
    let block = actions.action(ActionId::Block);
    let ready = actions.action(ActionId::ReadyItem);
    let live_player = player();
    let mut frame = NativeFrame {
        frame_id: actions.frame_id(),
        player: live_player,
        mover: core::ptr::null_mut(),
        cell: core::ptr::null_mut(),
        pivot: Vec3::default(),
        actor_yaw: 0.0,
        camera_heading: 0.0,
        camera_heading_offset: 0.0,
        pitch: 0.0,
        delta_seconds: 0.0,
        stable_third_person: false,
        world_ready: false,
        native_owner: true,
        hard_valid: false,
        rejection: NativeRejection::InvalidPlayer,
        weapon_out: false,
        // Buffered presses must enter Combat even when a fast tap is no
        // longer physically down by the time this camera observation runs.
        combat_intent: attack.down()
            || attack.pressed()
            || block.down()
            || block.pressed()
            || ready.down()
            || ready.pressed(),
    };
    if !is_engine_pointer(live_player) {
        return frame;
    }
    if !expected_player.is_null() && expected_player != live_player {
        frame.rejection = NativeRejection::PlayerMismatch;
        return frame;
    }
    if actions.frame_id() == 0 {
        frame.rejection = NativeRejection::MissingActionFrame;
        return frame;
    }

    frame.mover = unsafe { read_ptr(live_player.cast(), PLAYER_MOVER) };
    frame.cell = unsafe { read_ptr(live_player.cast(), PLAYER_PARENT_CELL) };
    let process = unsafe { read_ptr(live_player.cast(), PLAYER_PROCESS) };
    let collision = unsafe { read_ptr(live_player.cast(), PLAYER_COLLISION_OWNER) };
    let active_3d = unsafe { active_3d()(live_player) };
    frame.stable_third_person = unsafe {
        read_u8(live_player.cast(), PLAYER_POV_READY) != 0
            && read_u8(live_player.cast(), PLAYER_ACTIVE_PERSPECTIVE) != 0
            && read_u8(live_player.cast(), PLAYER_THIRD_PERSON) != 0
    };
    frame.world_ready = is_engine_pointer(frame.mover)
        && is_engine_pointer(frame.cell)
        && is_engine_pointer(process)
        && is_engine_pointer(collision)
        && is_engine_pointer(active_3d);
    frame.pivot = unsafe { read_vec3(live_player.cast(), PLAYER_POSITION) };
    // The movement request special-cases the player and builds its world
    // matrix from raw rotZ. UpdateCamera instead calls virtual +0x2BC, whose
    // PlayerCharacter implementation adds the camera-only +0x6E4 heading
    // offset. Keeping both values prevents camera compensation from being
    // fed back into the actor-space movement transform.
    frame.actor_yaw = unsafe { read_f32(live_player.cast(), PLAYER_ROTATION_Z) };
    frame.camera_heading =
        unsafe { actor_adjusted_heading(live_player).unwrap_or(frame.actor_yaw) };
    frame.camera_heading_offset =
        unsafe { read_f32(live_player.cast(), PLAYER_CAMERA_HEADING_OFFSET) };
    // UpdateCamera obtains pitch from 0x00931D70, which reads Actor rotX at
    // +0x24. Virtual +0x2BC is adjusted horizontal heading, not pitch.
    frame.pitch = unsafe { read_f32(live_player.cast(), PLAYER_ROTATION_X) };
    frame.delta_seconds = unsafe { read_f32(TIME_GLOBAL as *const u8, TIME_SECONDS_PASSED) };

    let process_observation = if is_engine_pointer(process) {
        unsafe { observe_process(process) }
    } else {
        None
    };
    if let Some(observation) = process_observation {
        frame.weapon_out = observation.state.weapon_out;
        // The input edge covers entry before native attack admission. Once
        // admitted, the process action owns the complete authored lifetime so
        // button release cannot return the actor to Explore before firing.
        frame.combat_intent |= observation.attack_active;
    }
    let process_state = process_observation.map(|observation| observation.state);

    let camera_controls =
        ControlFlags::MOVEMENT | ControlFlags::LOOKING | ControlFlags::PIPBOY | ControlFlags::POV;
    let vanilla_disabled = unsafe { read_u8(live_player.cast(), PLAYER_DISABLED_CONTROLS) };
    let controls_owned = controls.any_disabled(DisabledCheck::ByAnyModOrVanilla, camera_controls)
        || vanilla_disabled & VANILLA_CAMERA_DISABLED_MASK != 0;
    let os_globals = unsafe { read_global_ptr(OS_GLOBALS_PTR) };
    let fly_camera = is_engine_pointer(os_globals)
        && unsafe { read_u8(os_globals.cast(), OS_GLOBALS_FLY_CAMERA) } != 0;
    let vats = unsafe { read_u32(VATS_CAMERA_DATA as *const u8, VATS_MODE) } != 0;
    let menu = unsafe { menu_mode_active() };
    let special_camera = unsafe { read_u8(SPECIAL_CAMERA_STATE as *const u8, 0) } != 0;
    let dead = unsafe { read_u8(live_player.cast(), PLAYER_LIFE_STATE) } != 0;
    let context_owned = actions.context() != ActionContext::Gameplay;
    let values_valid = frame.pivot.is_finite()
        && frame.actor_yaw.is_finite()
        && frame.camera_heading.is_finite()
        && frame.camera_heading_offset.is_finite()
        && frame.pitch.is_finite()
        && frame.delta_seconds.is_finite();
    frame.rejection = classify_rejection(
        frame.stable_third_person,
        frame.mover,
        frame.cell,
        process,
        collision,
        active_3d,
        controls_owned,
        fly_camera,
        vats,
        menu,
        special_camera,
        dead,
        process_state,
        context_owned,
        values_valid,
    );
    frame.native_owner = frame.rejection != NativeRejection::Accepted;
    frame.hard_valid =
        frame.stable_third_person && frame.world_ready && !frame.native_owner && values_valid;
    frame
}

#[allow(clippy::too_many_arguments)]
fn classify_rejection(
    stable_third_person: bool,
    mover: *mut c_void,
    cell: *mut c_void,
    process: *mut c_void,
    collision: *mut c_void,
    active_3d: *mut c_void,
    controls_owned: bool,
    fly_camera: bool,
    vats: bool,
    menu: bool,
    special_camera: bool,
    dead: bool,
    process_state: Option<ProcessState>,
    context_owned: bool,
    values_valid: bool,
) -> NativeRejection {
    if !stable_third_person {
        return NativeRejection::Perspective;
    }
    for (pointer, rejection) in [
        (mover, NativeRejection::MissingMover),
        (cell, NativeRejection::MissingCell),
        (process, NativeRejection::MissingProcess),
        (collision, NativeRejection::MissingCollision),
        (active_3d, NativeRejection::MissingActive3d),
    ] {
        if !is_engine_pointer(pointer) {
            return rejection;
        }
    }
    if controls_owned {
        return NativeRejection::DisabledControls;
    }
    if fly_camera {
        return NativeRejection::FlyCamera;
    }
    if vats {
        return NativeRejection::Vats;
    }
    if menu {
        return NativeRejection::Menu;
    }
    if special_camera {
        return NativeRejection::SpecialCamera;
    }
    if dead {
        return NativeRejection::Dead;
    }
    let Some(process_state) = process_state else {
        return NativeRejection::MissingProcess;
    };
    // Actor +0x0AC is the allocation owner for bhkRagdollController and may
    // remain non-null in ordinary gameplay. The process virtual is the live
    // state boundary used by gameplay and is therefore the safe admission
    // predicate for knockdown/ragdoll ownership.
    if process_state.knocked != 0 {
        return NativeRejection::Knocked;
    }
    if process_state.furniture != 0 {
        return NativeRejection::Furniture;
    }
    if process_state.scripted {
        return NativeRejection::ScriptedAction;
    }
    if context_owned {
        return NativeRejection::ActionContext;
    }
    if !values_valid {
        return NativeRejection::InvalidValues;
    }
    NativeRejection::Accepted
}

#[derive(Clone, Copy)]
struct ProcessState {
    knocked: i32,
    furniture: i32,
    scripted: bool,
    weapon_out: bool,
}

#[derive(Clone, Copy)]
struct ProcessObservation {
    state: ProcessState,
    attack_active: bool,
}

unsafe fn observe_process(process: *mut c_void) -> Option<ProcessObservation> {
    let action: ProcessActionFn = unsafe { read_virtual(process, PROCESS_CURRENT_ACTION_VTBL)? };
    let knocked: ProcessStateFn = unsafe { read_virtual(process, PROCESS_KNOCKED_STATE_VTBL)? };
    let furniture: ProcessStateFn = unsafe { read_virtual(process, PROCESS_FURNITURE_STATE_VTBL)? };
    let weapon_out: ProcessBoolFn = unsafe { read_virtual(process, PROCESS_WEAPON_OUT_VTBL)? };
    // Resolving the aiming slot as part of the contract ensures a process
    // implementation incomplete for combat cannot accidentally be admitted.
    let _: ProcessBoolFn = unsafe { read_virtual(process, PROCESS_IS_AIMING_VTBL)? };
    let action = unsafe { action(process) };
    Some(ProcessObservation {
        state: ProcessState {
            knocked: unsafe { knocked(process) },
            furniture: unsafe { furniture(process) },
            scripted: matches!(action, SCRIPTED_ACTION_A | SCRIPTED_ACTION_B),
            weapon_out: unsafe { weapon_out(process) != 0 },
        },
        attack_active: matches!(
            action,
            ATTACK_ACTION
                | ATTACK_FOLLOW_THROUGH_ACTION
                | ATTACK_LATENCY_ACTION
                | ATTACK_THROW_ATTACH_ACTION
                | ATTACK_THROW_RELEASE_ACTION
        ),
    })
}

/// Return whether the current player update has requested native aim/block.
///
/// `PlayerCharacter::Update` calls camera helper `0x009445B0` at `0x0093F8D9`
/// before it queries action 6 at `0x00941F4F` and `0x00941F5F`. The process
/// virtual therefore cannot expose the initial stationary AIM sample in time
/// for the look and camera seams. Atom's post-sample action frame closes that
/// entry edge; the process state keeps ownership after the input consumer has
/// established aim and through its native transition timing.
pub(super) unsafe fn player_aim_input_requested(player: *mut c_void) -> bool {
    if !is_engine_pointer(player) || player != self::player() {
        return false;
    }
    let actions = latest_action_frame();
    if actions.frame_id() != 0 && actions.context() == ActionContext::Gameplay {
        let block = actions.action(ActionId::Block);
        if block.down() || block.pressed() {
            return true;
        }
    }
    false
}

/// Return the process' native ADS state independently from physical input.
///
/// Some animation/controller mods transiently retain this byte after unaimed
/// automatic fire. Hip-fire admission therefore observes it separately and
/// treats physical aim as the immediate ownership boundary.
pub(super) unsafe fn player_process_aiming(player: *mut c_void) -> bool {
    if !is_engine_pointer(player) || player != self::player() {
        return false;
    }
    let process = unsafe { read_ptr(player.cast(), PLAYER_PROCESS) };
    if !is_engine_pointer(process) {
        return false;
    }
    let Some(weapon_out) =
        (unsafe { read_virtual::<ProcessBoolFn>(process, PROCESS_WEAPON_OUT_VTBL) })
    else {
        return false;
    };
    let Some(aiming) = (unsafe { read_virtual::<ProcessBoolFn>(process, PROCESS_IS_AIMING_VTBL) })
    else {
        return false;
    };
    unsafe { weapon_out(process) != 0 && aiming(process) != 0 }
}

/// Return whether the current action sample represents unaimed fire intent.
///
/// `combat_intent` already retains FNV's authored attack actions after the
/// input edge. Block and ready-item inputs are removed explicitly so they can
/// keep camera-facing combat without opening a hip-fire animation session.
pub(super) fn hip_fire_requested(combat_intent: bool) -> bool {
    let actions = latest_action_frame();
    if actions.frame_id() == 0 || actions.context() != ActionContext::Gameplay {
        return false;
    }
    let attack = actions.action(ActionId::Use);
    if attack.down() || attack.pressed() {
        return true;
    }
    let block = actions.action(ActionId::Block);
    let ready = actions.action(ActionId::ReadyItem);
    combat_intent && !(block.down() || block.pressed() || ready.down() || ready.pressed())
}

/// Return whether the live player has a supported ranged weapon equipped.
///
/// The current process owns the effective `WeaponInfo`; reading the linked
/// weapon avoids base-inventory guesses and admits every vanilla or mod-added
/// pistol, rifle, automatic, energy weapon, handle weapon, and launcher.
///
/// # Safety
///
/// `player` must be the live player from the current native callback. No
/// pointer read here may be retained after the callback returns.
pub(super) unsafe fn hip_fire_weapon_supported(player: *mut c_void) -> bool {
    if !is_engine_pointer(player) || player != self::player() {
        return false;
    }
    let process = unsafe { read_ptr(player.cast(), PLAYER_PROCESS) };
    if !is_engine_pointer(process) {
        return false;
    }
    unsafe { process_has_supported_ranged_weapon(process) }
}

/// Return whether the equipped weapon advertises third-person IS animations.
///
/// `No3rdPersonISAnims` is an explicit engine/mod capability boundary. Atom
/// retains camera-facing hip-fire for such weapons but leaves their animation
/// graph untouched instead of forcing a missing paired group.
pub(super) unsafe fn hip_fire_is_animation_supported(player: *mut c_void) -> bool {
    if !is_engine_pointer(player) || player != self::player() {
        return false;
    }
    let process = unsafe { read_ptr(player.cast(), PLAYER_PROCESS) };
    let Some(weapon) = is_engine_pointer(process)
        .then(|| unsafe { process_weapon(process) })
        .flatten()
    else {
        return false;
    };
    (unsafe { read_u32(weapon.cast(), WEAPON_FLAGS_2) } & WEAPON_NO_THIRD_PERSON_IS_ANIMS) == 0
}

/// Return whether an authored third-person attack sequence is still active.
///
/// This graph observation complements native input/process actions for kNVSE
/// animation replacements whose authored lifetime can outlast either signal.
pub(super) unsafe fn hip_fire_attack_sequence_active(player: *mut c_void) -> bool {
    let Some(anim_data) = (unsafe { player_anim_data(player) }) else {
        return false;
    };
    (0..ANIM_SEQUENCE_COUNT).any(|index| unsafe {
        active_sequence_group(anim_data, index).is_some_and(is_attack_group)
    })
}

/// Admit one player animation request for Atom's active hip-fire session.
///
/// The entry hook supplies the live `AnimData` receiver. Matching it against
/// the player's current process prevents an NPC, first-person graph, stale
/// graph, melee weapon, or native ADS transition from being remapped.
///
/// # Safety
///
/// `anim_data` must be the receiver of the active, fingerprinted animation
/// morph entry. `player` must be the Atom-published live player token.
pub(super) unsafe fn hip_fire_anim_data_owned(anim_data: *mut c_void, player: *mut c_void) -> bool {
    if !is_engine_pointer(anim_data)
        || !is_engine_pointer(player)
        || player != self::player()
        || unsafe { read_ptr(anim_data.cast(), ANIM_DATA_ACTOR) } != player
    {
        return false;
    }
    let stable_third_person = unsafe {
        read_u8(player.cast(), PLAYER_POV_READY) != 0
            && read_u8(player.cast(), PLAYER_ACTIVE_PERSPECTIVE) != 0
            && read_u8(player.cast(), PLAYER_THIRD_PERSON) != 0
    };
    if !stable_third_person {
        return false;
    }
    let process = unsafe { read_ptr(player.cast(), PLAYER_PROCESS) };
    if !is_engine_pointer(process)
        || unsafe { read_ptr(process.cast(), PROCESS_ANIM_DATA) } != anim_data
        || !unsafe { process_has_supported_ranged_weapon(process) }
        || !unsafe { hip_fire_is_animation_supported(player) }
    {
        return false;
    }
    let Some(weapon_out) =
        (unsafe { read_virtual::<ProcessBoolFn>(process, PROCESS_WEAPON_OUT_VTBL) })
    else {
        return false;
    };
    unsafe { weapon_out(process) != 0 }
}

/// Resolution of one explicit hip-fire pose transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HipFireTransition {
    /// The live graph cannot currently expose a supported posture sequence.
    Unavailable,
    /// A supported posture sequence already uses the requested family.
    Settled,
    /// FNV must morph the live third-person graph to `group`.
    Morph { anim_data: *mut c_void, group: u16 },
}

/// Resolution of one native hip-fire posture release request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HipFireRelease {
    /// The live graph cannot currently expose a supported posture sequence.
    Unavailable,
    /// No supported Aim-family sequence remains to release.
    Settled,
    /// FNV accepted one native stop/fade request for the upper-body sequence type.
    Requested,
}

/// Select the current weapon-posture group for one smooth pose transition.
///
/// The returned receiver and group are valid only for the surrounding camera
/// callback. Calling FNV's captured morph predecessor preserves its normal
/// transition and kNVSE's internal custom-path/blend chain.
///
/// # Safety
///
/// `player` must be the live player from the current camera callback.
pub(super) unsafe fn hip_fire_transition_group(
    player: *mut c_void,
    ready: bool,
) -> HipFireTransition {
    if !is_engine_pointer(player) || player != self::player() {
        return HipFireTransition::Unavailable;
    }
    let process = unsafe { read_ptr(player.cast(), PLAYER_PROCESS) };
    let anim_data = if is_engine_pointer(process) {
        unsafe { read_ptr(process.cast(), PROCESS_ANIM_DATA) }
    } else {
        core::ptr::null_mut()
    };
    if !unsafe { hip_fire_anim_data_owned(anim_data, player) } {
        return HipFireTransition::Unavailable;
    }
    let mut desired_seen = false;
    for index in 0..ANIM_SEQUENCE_COUNT {
        let Some(current) = (unsafe { active_sequence_group(anim_data, index) }) else {
            continue;
        };
        let current = u16::from(current);
        // Explicit session entry/exit owns posture only. Attack groups remain
        // event-driven through the morph detour; replaying one here can restart
        // or visibly jitter an authored firing action.
        if !(17..=22).contains(&(current as u8)) {
            continue;
        }
        let requested = hip_fire_animation_group(current, ready);
        if requested != current {
            return HipFireTransition::Morph {
                anim_data,
                group: requested,
            };
        }
        desired_seen = true;
    }
    if desired_seen {
        HipFireTransition::Settled
    } else {
        HipFireTransition::Unavailable
    }
}

/// Ask FNV to fade the live unaimed-fire upper-body posture back to locomotion.
///
/// Aim and AimIS are variants of native sequence type 4; AimUp/AimISUp and
/// AimDown/AimISDown use types 5 and 6. FNV's type-4 stop owner releases all
/// three together with the graph's authored fade and process callbacks. A
/// morph from AimIS to Aim would retain combat posture and is not a release.
///
/// # Safety
///
/// [`validate_hip_fire_pose_contract`] must have succeeded during
/// `DeferredInit`, and `player` must be live for the surrounding camera call.
pub(super) unsafe fn release_hip_fire_pose(player: *mut c_void) -> HipFireRelease {
    if !is_engine_pointer(player) || player != self::player() {
        return HipFireRelease::Unavailable;
    }
    let process = unsafe { read_ptr(player.cast(), PLAYER_PROCESS) };
    let anim_data = if is_engine_pointer(process) {
        unsafe { read_ptr(process.cast(), PROCESS_ANIM_DATA) }
    } else {
        core::ptr::null_mut()
    };
    if !unsafe { hip_fire_anim_data_owned(anim_data, player) } {
        return HipFireRelease::Unavailable;
    }

    let mut aim_family_visible = false;
    for index in 0..ANIM_SEQUENCE_COUNT {
        let Some(group) = (unsafe { active_sequence_group(anim_data, index) }) else {
            continue;
        };
        if (17..=22).contains(&group) {
            aim_family_visible = true;
            break;
        }
    }
    if !aim_family_visible {
        return HipFireRelease::Settled;
    }

    unsafe { stop_animation_sequence_type()(anim_data, 4, 0) };
    HipFireRelease::Requested
}

/// Map paired third-person Aim/Attack groups without changing their variant.
///
/// High bits are retained for compatible animation resolvers. Each supported
/// family is authored as normal/up/down followed by IS normal/up/down; groups
/// without that exact structure pass through unchanged.
pub(super) fn hip_fire_animation_group(group: u16, ready: bool) -> u16 {
    let base = (group & 0x00FF) as u8;
    let family_start = if (17..=22).contains(&base) {
        Some(17)
    } else if (26..=91).contains(&base) {
        Some(26)
    } else if (102..=167).contains(&base) {
        Some(102)
    } else {
        None
    };
    let Some(family_start) = family_start else {
        return group;
    };
    let lane = base.wrapping_sub(family_start) % 6;
    let mapped = match (ready, lane) {
        (true, 0..=2) => base + 3,
        (false, 3..=5) => base - 3,
        _ => base,
    };
    (group & 0xFF00) | u16::from(mapped)
}

unsafe fn process_has_supported_ranged_weapon(process: *mut c_void) -> bool {
    unsafe { process_weapon(process) }
        .is_some_and(|weapon| matches!(unsafe { read_u8(weapon.cast(), WEAPON_TYPE) }, 3..=9))
}

unsafe fn process_weapon(process: *mut c_void) -> Option<*mut c_void> {
    let weapon_info = unsafe { read_ptr(process.cast(), PROCESS_WEAPON_INFO) };
    if !is_engine_pointer(weapon_info) {
        return None;
    }
    let weapon = unsafe { read_ptr(weapon_info.cast(), WEAPON_INFO_WEAPON) };
    if !is_engine_pointer(weapon) {
        return None;
    }
    Some(weapon)
}

unsafe fn player_anim_data(player: *mut c_void) -> Option<*mut c_void> {
    if !is_engine_pointer(player) || player != self::player() {
        return None;
    }
    let process = unsafe { read_ptr(player.cast(), PLAYER_PROCESS) };
    if !is_engine_pointer(process) {
        return None;
    }
    let anim_data = unsafe { read_ptr(process.cast(), PROCESS_ANIM_DATA) };
    is_engine_pointer(anim_data).then_some(anim_data)
}

unsafe fn active_sequence_group(anim_data: *mut c_void, index: usize) -> Option<u8> {
    let sequence = unsafe {
        read_ptr(
            anim_data.cast(),
            ANIM_DATA_SEQUENCES + index * size_of::<*mut c_void>(),
        )
    };
    if !is_engine_pointer(sequence) {
        return None;
    }
    // NiControllerSequence states 1..=6 are live graph participants. Dead and
    // inactive slots must not keep a session alive or be selected for morph.
    if !(1..=6).contains(&unsafe { read_u32(sequence.cast(), ANIM_SEQUENCE_STATE) }) {
        return None;
    }
    let anim_group = unsafe { read_ptr(sequence.cast(), ANIM_SEQUENCE_GROUP) };
    is_engine_pointer(anim_group).then(|| unsafe { read_u8(anim_group.cast(), ANIM_GROUP_CODE) })
}

fn is_attack_group(group: u8) -> bool {
    (26..=91).contains(&group) || (102..=167).contains(&group)
}

/// Return whether combat camera ownership is blocked by fighting controls.
///
/// This separate Combat-only query prevents an Explore camera from yielding
/// merely because a mod disabled attacks. The player pointer must be the live
/// receiver admitted by [`observe`] in the same native callback.
pub(super) unsafe fn fighting_control_disabled(
    player: *mut c_void,
    controls: PlayerControlsReader,
) -> bool {
    if !is_engine_pointer(player) || player != self::player() {
        return true;
    }
    controls.any_disabled(DisabledCheck::ByAnyModOrVanilla, ControlFlags::FIGHTING)
        || unsafe { read_u8(player.cast(), PLAYER_DISABLED_CONTROLS) } & VANILLA_FIGHTING_DISABLED
            != 0
}

/// Invoke the live authoritative player-yaw setter.
///
/// The native ABI returns no success value and its wrapper may reject the
/// request for current actor state. A `true` result means only that a valid
/// live virtual function was invoked. Callers must sample [`raw_actor_yaw`]
/// afterwards before compensating movement.
pub(super) unsafe fn invoke_actor_yaw_setter(actor: *mut c_void, yaw: f32) -> bool {
    if !is_engine_pointer(actor) || !yaw.is_finite() || actor != player() {
        return false;
    }
    let Some(function) = (unsafe { read_virtual::<ActorSetYawFn>(actor, ACTOR_SET_YAW_VTBL) })
    else {
        return false;
    };
    unsafe { function(actor, yaw) };
    true
}

/// Read the raw Actor `rotZ` consumed by the native player movement request.
///
/// # Safety
///
/// `actor` must be the live player supplied by the current scoped movement
/// call. The returned value is copied and no engine pointer is retained.
pub(super) unsafe fn raw_actor_yaw(actor: *mut c_void) -> Option<f32> {
    if !is_engine_pointer(actor) || actor != player() {
        return None;
    }
    let yaw = unsafe { read_f32(actor.cast(), PLAYER_ROTATION_Z) };
    yaw.is_finite().then_some(yaw)
}

/// Publish Atom's compensated camera-only heading offset.
///
/// FNV itself reads and writes PlayerCharacter `+0x6E4` as a scalar camera
/// offset. `offset` must have been derived from a same-callback native heading
/// observation and the logical view heading. No transform or pointer is kept.
pub(super) unsafe fn write_camera_heading_offset(player: *mut c_void, offset: f32) -> bool {
    if !is_engine_pointer(player) || player != self::player() || !offset.is_finite() {
        return false;
    }
    unsafe {
        core::ptr::write_unaligned(
            player
                .cast::<u8>()
                .add(PLAYER_CAMERA_HEADING_OFFSET)
                .cast::<f32>(),
            offset,
        );
    }
    true
}

/// Reestablish Atom's world-view heading after an authoritative actor turn.
///
/// The movement path calls the native yaw setter outside the camera update,
/// so its base-heading change would immediately leak into every consumer of
/// PlayerCharacter's adjusted heading unless `+0x6E4` is compensated in the
/// same scoped movement callback.
pub(super) unsafe fn synchronize_camera_heading(
    player: *mut c_void,
    logical_heading: f32,
) -> Option<f32> {
    if !is_engine_pointer(player) || player != self::player() || !logical_heading.is_finite() {
        return None;
    }
    let current_offset = unsafe { read_f32(player.cast(), PLAYER_CAMERA_HEADING_OFFSET) };
    let native_adjusted = unsafe { actor_adjusted_heading(player) }?;
    let offset =
        super::compensated_camera_heading_offset(native_adjusted, current_offset, logical_heading)?;
    unsafe { write_camera_heading_offset(player, offset) }.then_some(offset)
}

/// Fold Atom's camera-only yaw offset into native Actor facing.
///
/// The effective world heading is sampled first, then published through the
/// authoritative Actor yaw setter before `+0x6E4` is cleared. This preserves
/// the visible heading while rejoining the raw actor, movement, first-person,
/// and native-look axes. A rejected setter leaves the old offset untouched.
///
/// # Safety
///
/// `player` must be the live PlayerCharacter supplied by the current native
/// look, UpdateCamera, or scoped movement callback on the game thread. The
/// fixed fields and virtual slots must have passed deferred contract checks.
pub(super) unsafe fn fold_camera_heading_offset_into_actor(player: *mut c_void) -> bool {
    if !is_engine_pointer(player) || player != self::player() {
        return false;
    }
    let old_raw = unsafe { read_f32(player.cast(), PLAYER_ROTATION_Z) };
    let old_offset = unsafe { read_f32(player.cast(), PLAYER_CAMERA_HEADING_OFFSET) };
    let Some(adjusted) = (unsafe { actor_adjusted_heading(player) }) else {
        return false;
    };
    if !old_raw.is_finite() || !old_offset.is_finite() || !adjusted.is_finite() {
        return false;
    }
    if old_offset.abs() <= super::VIEW_MATCH_EPSILON {
        return unsafe { write_camera_heading_offset(player, 0.0) };
    }
    if !unsafe { invoke_actor_yaw_setter(player, adjusted) } {
        return false;
    }
    let set_raw = unsafe { read_f32(player.cast(), PLAYER_ROTATION_Z) };
    if !set_raw.is_finite()
        || super::wrap_angle(set_raw - adjusted).abs() > super::VIEW_MATCH_EPSILON
    {
        let _ = unsafe { invoke_actor_yaw_setter(player, old_raw) };
        return false;
    }
    if !unsafe { write_camera_heading_offset(player, 0.0) } {
        let _ = unsafe { invoke_actor_yaw_setter(player, old_raw) };
        return false;
    }
    (unsafe { actor_adjusted_heading(player) }).is_some_and(|heading| {
        super::wrap_angle(heading - adjusted).abs() <= super::VIEW_MATCH_EPSILON
    })
}

/// Publish absolute Actor rotX through FNV's authoritative clamping route.
///
/// The returned value is the live post-setter pitch. FNV may clamp the request,
/// so callers that are joining camera and Actor ownership must adopt this
/// result rather than assume the requested angle reached native state.
///
/// # Safety
///
/// `player` must be the live PlayerCharacter supplied by the current native
/// look or UpdateCamera callback on the game thread. The fixed function and
/// player fields must have passed deferred contract checks.
pub(super) unsafe fn invoke_actor_pitch_setter(player: *mut c_void, pitch: f32) -> Option<f32> {
    if !is_engine_pointer(player) || player != self::player() || !pitch.is_finite() {
        return None;
    }
    let setter: ActorSetPitchFn = unsafe { core::mem::transmute(ACTOR_SET_PITCH) };
    unsafe { setter(player, pitch) };
    let pitch = unsafe { read_f32(player.cast(), PLAYER_ROTATION_X) };
    pitch.is_finite().then_some(pitch)
}

/// Read the final camera position committed by PlayerCharacter::UpdateCamera.
///
/// The reticle wrapper runs later in the native UI update. `0x0094BB61` has
/// already copied the completed position to the persistent camera object's
/// local translation, so this is the exact origin represented on screen.
pub(super) unsafe fn render_camera_origin() -> Option<Vec3> {
    let origin = unsafe {
        core::ptr::read_unaligned((NATIVE_CAMERA + NIAVOBJECT_LOCAL_TRANSLATION) as *const Vec3)
    };
    origin.is_finite().then_some(origin)
}

/// Return the first projectile-layer collision distance along a camera ray.
///
/// The ray uses the live player's collision group with the layer replaced by
/// FNV's projectile layer. This matches native group exclusion, so the camera
/// ray cannot select the firing player's own controller or biped. A clear ray
/// returns `maximum_distance`; any malformed native output fails closed.
///
/// # Safety
///
/// [`validate_combat_ray_contract`] must have succeeded. `player` must be the
/// current live player supplied by the admitted projectile spawn callback,
/// and the call must run synchronously on the game thread.
pub(super) unsafe fn combat_ray_distance(
    player: *mut c_void,
    origin: Vec3,
    direction: Vec3,
    maximum_distance: f32,
) -> Option<f32> {
    if player != self::player()
        || !is_engine_pointer(player)
        || !origin.is_finite()
        || !direction.is_finite()
        || !maximum_distance.is_finite()
        || maximum_distance <= 0.0
    {
        return None;
    }
    let endpoint = origin + direction * maximum_distance;
    if !endpoint.is_finite() {
        return None;
    }

    let tes = unsafe { read_global_ptr(TES_PTR) };
    if !is_engine_pointer(tes) {
        return None;
    }
    let mut player_filter = 0_u32;
    let returned_filter = unsafe { player_collision_filter()(player, &mut player_filter) };
    if returned_filter != &mut player_filter {
        return None;
    }

    let mut pick = NativePickData {
        bytes: [0; PICK_DATA_SIZE],
    };
    if unsafe { pick_data_constructor()(&mut pick) } != &mut pick {
        return None;
    }
    unsafe {
        pick_data_set_from()(&mut pick, &origin);
        pick_data_set_to()(&mut pick, &endpoint);
    }
    // Native CFilter stores its collision layer in the low seven bits and
    // its actor collision group in the high word. Projectile queries keep the
    // player's group, discard unrelated flags, and substitute layer six.
    let projectile_filter = (player_filter & 0xFFFF_0000) | PROJECTILE_COLLISION_LAYER;
    unsafe {
        pick.bytes
            .as_mut_ptr()
            .add(PICK_DATA_FILTER)
            .cast::<u32>()
            .write_unaligned(projectile_filter);
    }

    let _ = unsafe { tes_pick_object()(tes, &mut pick) };
    let failed = unsafe { pick.bytes.as_ptr().add(PICK_DATA_FAILED).read() } != 0;
    let fraction = unsafe {
        pick.bytes
            .as_ptr()
            .add(PICK_DATA_HIT_FRACTION)
            .cast::<f32>()
            .read_unaligned()
    };
    if failed || !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
        return None;
    }
    Some(maximum_distance * fraction)
}

/// Return the range of an admitted standard ranged projectile.
///
/// # Safety
///
/// Both pointers must be the live values supplied by the native spawn call.
pub(super) unsafe fn admitted_projectile_range(
    projectile: *mut c_void,
    weapon: *mut c_void,
) -> Option<f32> {
    if !is_engine_pointer(projectile) || !is_engine_pointer(weapon) {
        return None;
    }
    let weapon_type = unsafe { read_u8(weapon.cast(), WEAPON_TYPE) };
    if !(3..=9).contains(&weapon_type) {
        return None;
    }
    let type_flags = unsafe { read_u32(projectile.cast(), PROJECTILE_TYPE_FLAGS) };
    if type_flags & PROJECTILE_TYPE_MASK != MISSILE_PROJECTILE {
        return None;
    }
    let range = unsafe { read_f32(projectile.cast(), PROJECTILE_RANGE) };
    (range.is_finite() && range > 0.0).then_some(range)
}

/// Resolve the real projectile node and its unspread native angles.
///
/// # Safety
///
/// `source` and `weapon` must be live values from the current native spawn
/// call, and `source` must be the current player.
pub(super) unsafe fn real_muzzle(
    source: *mut c_void,
    weapon: *mut c_void,
) -> Option<(Vec3, AimAngles)> {
    if source != player() || !is_engine_pointer(source) || !is_engine_pointer(weapon) {
        return None;
    }
    let skeleton = unsafe { active_3d()(source) };
    if !is_engine_pointer(skeleton) {
        return None;
    }
    let node = unsafe { projectile_node()(weapon, skeleton) };
    if !is_engine_pointer(node) {
        return None;
    }
    let position = unsafe { read_vec3(node.cast(), NIAVOBJECT_WORLD_POSITION) };
    if !position.is_finite() {
        return None;
    }
    let matrix =
        unsafe { node.cast::<u8>().add(NIAVOBJECT_WORLD_ROTATION) }.cast::<[[f32; 3]; 3]>();
    let mut pitch = 0.0;
    let mut yaw = 0.0;
    let mut roll = 0.0;
    if unsafe { matrix_to_angles()(matrix, &mut pitch, &mut yaw, &mut roll) } == 0 {
        return None;
    }
    let angles = AimAngles::new(yaw, pitch);
    angles.is_finite().then_some((position, angles))
}

unsafe fn actor_adjusted_heading(actor: *mut c_void) -> Option<f32> {
    let function: ActorAdjustedHeadingFn =
        unsafe { read_virtual(actor, ACTOR_ADJUSTED_HEADING_VTBL)? };
    Some(unsafe { function(actor, 0) })
}

fn active_3d() -> Active3dFn {
    unsafe { core::mem::transmute(ACTIVE_3D) }
}

fn projectile_node() -> ProjectileNodeFn {
    unsafe { core::mem::transmute(WEAPON_PROJECTILE_NODE) }
}

fn matrix_to_angles() -> MatrixAnglesFn {
    unsafe { core::mem::transmute(MATRIX_TO_ANGLES) }
}

fn stop_animation_sequence_type() -> StopAnimationSequenceTypeFn {
    unsafe { core::mem::transmute(STOP_ANIMATION_SEQUENCE_TYPE) }
}

fn get_character_controller() -> GetCharacterControllerFn {
    unsafe { core::mem::transmute(GET_CHARACTER_CONTROLLER) }
}

fn get_controller_state() -> GetControllerStateFn {
    unsafe { core::mem::transmute(GET_CONTROLLER_STATE) }
}

fn get_relative_velocity() -> GetRelativeVelocityFn {
    unsafe { core::mem::transmute(GET_SUPPORT_RELATIVE_VELOCITY) }
}

fn pick_data_constructor() -> PickDataConstructorFn {
    unsafe { core::mem::transmute(PICK_DATA_CONSTRUCTOR) }
}

fn pick_data_set_from() -> PickDataPointFn {
    unsafe { core::mem::transmute(PICK_DATA_SET_FROM) }
}

fn pick_data_set_to() -> PickDataPointFn {
    unsafe { core::mem::transmute(PICK_DATA_SET_TO) }
}

fn player_collision_filter() -> PlayerCollisionFilterFn {
    unsafe { core::mem::transmute(PLAYER_COLLISION_FILTER) }
}

fn tes_pick_object() -> TesPickObjectFn {
    unsafe { core::mem::transmute(TES_PICK_OBJECT) }
}

unsafe fn read_global_ptr(address: usize) -> *mut c_void {
    unsafe { core::ptr::read_volatile(address as *const *mut c_void) }
}

unsafe fn read_f32_volatile(address: usize) -> f32 {
    unsafe { core::ptr::read_volatile(address as *const f32) }
}

unsafe fn write_f32_volatile(address: usize, value: f32) {
    unsafe { core::ptr::write_volatile(address as *mut f32, value) };
}

/// Reproduce FNV's side-effect-free `MenuMode` ownership predicate.
///
/// The native helper entry is mutable by `DeferredInit`, while its complete
/// policy is the stable InterfaceManager capability below. Reading that state
/// neither executes nor inspects an unknown provider's replacement code.
unsafe fn menu_mode_active() -> bool {
    let manager = unsafe { read_global_ptr(INTERFACE_MANAGER_PTR) };
    is_engine_pointer(manager)
        && menu_mode_from_fields(
            unsafe { read_u8(manager.cast(), INTERFACE_MANAGER_ACTIVE) },
            unsafe { read_u32(manager.cast(), INTERFACE_MANAGER_MODE) },
        )
}

const fn menu_mode_from_fields(active: u8, mode: u32) -> bool {
    active != 0 && mode != GAMEPLAY_INTERFACE_MODE
}

unsafe fn read_ptr(base: *const u8, offset: usize) -> *mut c_void {
    if !is_engine_pointer(base.cast_mut().cast()) {
        return core::ptr::null_mut();
    }
    unsafe { core::ptr::read_unaligned(base.add(offset).cast::<*mut c_void>()) }
}

unsafe fn read_u8(base: *const u8, offset: usize) -> u8 {
    unsafe { core::ptr::read_unaligned(base.add(offset)) }
}

unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(base.add(offset).cast::<u32>()) }
}

unsafe fn read_f32(base: *const u8, offset: usize) -> f32 {
    unsafe { core::ptr::read_unaligned(base.add(offset).cast::<f32>()) }
}

unsafe fn read_vec3(base: *const u8, offset: usize) -> Vec3 {
    unsafe { core::ptr::read_unaligned(base.add(offset).cast::<Vec3>()) }
}

unsafe fn read_virtual<T: Copy>(owner: *mut c_void, offset: usize) -> Option<T> {
    if !is_engine_pointer(owner) {
        return None;
    }
    let vtable = unsafe { core::ptr::read_unaligned(owner.cast::<*const u8>()) };
    if !is_engine_pointer(vtable.cast_mut().cast()) {
        return None;
    }
    let function = unsafe { core::ptr::read_unaligned(vtable.add(offset).cast::<usize>()) };
    if function < MIN_ENGINE_POINTER {
        return None;
    }
    Some(unsafe { core::mem::transmute_copy(&function) })
}

fn is_engine_pointer(pointer: *mut c_void) -> bool {
    pointer as usize >= MIN_ENGINE_POINTER
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use super::{
        NativeRejection, ProcessState, classify_rejection, framing_restoration_value,
        menu_mode_from_fields,
    };

    #[test]
    fn framing_release_restores_only_values_still_owned_by_atom() {
        assert_eq!(framing_restoration_value(240.0, 120.0, 240.0), Some(120.0));
        assert_eq!(
            framing_restoration_value(300.0, 120.0, 240.0),
            None,
            "a newer native or mod owner must not be overwritten",
        );
        assert_eq!(
            framing_restoration_value(-0.0, 10.0, 0.0),
            None,
            "ownership comparison is bit-exact",
        );
    }

    #[test]
    fn menu_ownership_matches_the_native_interface_manager_policy() {
        assert!(!menu_mode_from_fields(0, 0));
        assert!(!menu_mode_from_fields(1, 1));
        assert!(menu_mode_from_fields(1, 0));
        assert!(menu_mode_from_fields(1, 2));
    }

    #[test]
    fn normal_body_state_is_not_mistaken_for_an_active_ragdoll() {
        let pointer = 0x1_0000_usize as *mut c_void;
        let process = ProcessState {
            knocked: 0,
            furniture: 0,
            scripted: false,
            weapon_out: false,
        };
        assert_eq!(
            classify_rejection(
                true,
                pointer,
                pointer,
                pointer,
                pointer,
                pointer,
                false,
                false,
                false,
                false,
                false,
                false,
                Some(process),
                false,
                true,
            ),
            NativeRejection::Accepted,
        );

        assert_eq!(
            classify_rejection(
                true,
                pointer,
                pointer,
                pointer,
                pointer,
                pointer,
                false,
                false,
                false,
                false,
                false,
                false,
                Some(ProcessState {
                    knocked: 1,
                    ..process
                }),
                false,
                true,
            ),
            NativeRejection::Knocked,
        );
    }
}

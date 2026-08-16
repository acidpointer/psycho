//! Fallout: New Vegas 1.4.0.525 first-person native contract.
//!
//! Fixed addresses are admitted only after plugin query rejects other runtime
//! versions and `DeferredInit` validates immutable function/data ranges. The
//! update sampler runs after native `PlayerCharacter::UpdateCamera`; render
//! access occurs only inside the proven world and first-person call chains.
//! World motion recenters the finite Sky and Weather roots as one scoped
//! transaction. Viewmodel motion uses the engine-corroborated origin rebase so
//! sub-unit offsets do not quantize at large world coordinates. No engine
//! pointer or temporary transform is retained beyond one callback.

use core::ffi::c_void;
use core::mem::size_of;

use libpsycho::os::windows::memory::{MemoryError, read_bytes, validate_memory_range};
use thiserror::Error;

use crate::input::{ActionContext, latest_action_frame};

use super::{
    CameraPose, CameraTransform, LocomotionState, MotionInput, compose_transform,
    native_owners_allow_camera,
};

const PLAYER_PTR: usize = 0x011D_EA3C;
const OS_GLOBALS_PTR: usize = 0x011D_EA0C;
const INTERFACE_MANAGER_PTR: usize = 0x011D_8A80;
const CAMERA_1ST_PTR: usize = 0x011E_07D0;
const SPECIAL_CAMERA_STATE: usize = 0x011E_07B8;
// UpdateCamera stores virtual +0x2BC (adjusted horizontal heading) first,
// then stores Actor rotX from 0x00931D70. The corresponding globals are
// consumed by the native Z- and X-rotation matrix builders, respectively.
const LOGICAL_YAW: usize = 0x011E_076C;
const LOGICAL_PITCH: usize = 0x011E_0764;
const WORLD_SCENE_GRAPH_PTR: usize = 0x011D_EB7C;
// Render preparation names these two NiNode roots "Sky" and "Weather" and
// recenters both from the world camera's local translation before every main
// world draw. A render-only camera translation must keep them centered or the
// finite sky dome exposes the camera offset as foreground motion.
const SKY_ROOT_PTR: usize = 0x011D_EB34;
const WEATHER_ROOT_PTR: usize = 0x011D_EDA4;
const VATS_CAMERA_DATA: usize = 0x011F_2250;
const TIME_GLOBAL: usize = 0x011F_6394;

const PLAYER_PARENT_CELL: usize = 0x40;
const PLAYER_PROCESS: usize = 0x68;
const PLAYER_LIFE_STATE: usize = 0x108;
const PLAYER_COLLISION_OWNER: usize = 0x21C;
const PLAYER_POV_TRANSITION_A: usize = 0x64A;
const PLAYER_POV_TRANSITION_B: usize = 0x64B;
const PLAYER_THIRD_PERSON: usize = 0x64C;
const PLAYER_NATIVE_UPDATE_OWNER: usize = 0x64F;
const PLAYER_DISABLED_CONTROLS: usize = 0x680;
const PLAYER_FIRST_PERSON_3D: usize = 0x694;

const OS_GLOBALS_FLY_CAMERA: usize = 0x06;
const OS_GLOBALS_FIRST_PERSON_CAMERA: usize = 0xA0;
const SCENE_GRAPH_CAMERA: usize = 0xAC;
const INTERFACE_MANAGER_ACTIVE: usize = 0x00;
const INTERFACE_MANAGER_MODE: usize = 0x0C;
const GAMEPLAY_INTERFACE_MODE: u32 = 1;
const VATS_MODE: usize = 0x08;
const TIME_SECONDS_PASSED: usize = 0x0C;

const PROCESS_CURRENT_ACTION_VTBL: usize = 0x3E4;
const PROCESS_IS_AIMING_VTBL: usize = 0x404;
const PROCESS_KNOCKED_STATE_VTBL: usize = 0x40C;
const PROCESS_FURNITURE_STATE_VTBL: usize = 0x4BC;

const NIAVOBJECT_LOCAL_ROTATION: usize = 0x34;
const NIAVOBJECT_LOCAL_TRANSLATION: usize = 0x58;
const NIAVOBJECT_WORLD_ROTATION: usize = 0x68;
const NIAVOBJECT_WORLD_TRANSLATION: usize = 0x8C;
const MIN_ENGINE_POINTER: usize = 0x1_0000;

const GET_CHARACTER_CONTROLLER: usize = 0x0093_06D0;
const GET_CONTROLLER_STATE: usize = 0x005C_0880;
const GET_SUPPORT_RELATIVE_VELOCITY: usize = 0x0081_2B00;
const FIRST_PERSON_ANIMATION_BLOCKED: usize = 0x008A_8870;
const UPDATE_NIAVOBJECT: usize = 0x00A5_9C60;

// The entry itself is deliberately omitted: another camera plugin may already
// own a compatible entry trampoline by DeferredInit. These immutable interior
// stores and the sole epilogue prove that the chained body is still the
// supported UpdateCamera implementation with thiscall stack cleanup.
const UPDATE_CAMERA_INTERIOR_FINGERPRINTS: &[(usize, &[u8])] = &[
    (0x0094_AE6A, &[0x89, 0x8D, 0xEC, 0xFB, 0xFF, 0xFF]),
    (0x0094_AE88, &[0xD9, 0x1D, 0x6C, 0x07, 0x1E, 0x01]),
    (0x0094_AE99, &[0xD9, 0x1D, 0x64, 0x07, 0x1E, 0x01]),
    (
        0x0094_C366,
        &[
            0x8B, 0x4D, 0xF4, 0x64, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x59, 0x5F, 0x5E, 0x8B,
            0xE5, 0x5D, 0xC2, 0x08, 0x00,
        ],
    ),
];

const DISABLED_CONTROL_MASK: u8 = 0x1F;
const SCRIPTED_ACTION_A: i16 = 0x0D;
const SCRIPTED_ACTION_B: i16 = 0x0E;

type GetCharacterControllerFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type GetControllerStateFn = unsafe extern "thiscall" fn(*mut c_void) -> u32;
type GetRelativeVelocityFn = unsafe extern "thiscall" fn(*mut c_void, *mut NativePoint3);
type AnimationBlockedFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;
type ProcessActionFn = unsafe extern "thiscall" fn(*mut c_void) -> i16;
type ProcessBoolFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;
type ProcessStateFn = unsafe extern "thiscall" fn(*mut c_void) -> i32;
type UpdateNiAvObjectFn = unsafe extern "thiscall" fn(*mut c_void, *const NativeUpdateData);
type GraphUpdater = unsafe fn(*mut u8);

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct NativePoint3 {
    x: f32,
    y: f32,
    z: f32,
}

/// Minimal `NiUpdateData` value used by FNV's own render-root update path.
///
/// `0x0043D410` proves the first nine bytes: time at `+0`, two caller flags at
/// `+4/+5`, and three zeroed bytes at `+6..+8`. The trailing padding is never
/// read, but explicit initialization prevents indeterminate bytes from crossing
/// the native boundary.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct NativeUpdateData {
    time: f32,
    update_controllers: u8,
    multithreaded: u8,
    flags: [u8; 3],
    padding: [u8; 3],
}

/// Native values copied after one accepted `UpdateCamera` call.
#[derive(Clone, Copy, Debug)]
pub(super) struct NativeUpdateSample {
    pub(super) input_frame_id: u32,
    pub(super) cell: usize,
    pub(super) logical_angles: [f32; 2],
    pub(super) motion: MotionInput,
}

/// Bounded reason a live update or render remained under native ownership.
///
/// Variant order is stable within one DLL build because diagnostics index a
/// fixed atomic array with the discriminant. The values are never persisted or
/// exposed across the plugin ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(super) enum NativeRejection {
    CombinedControls,
    InvalidPlayer,
    PlayerMismatch,
    PovTransitionA,
    PovTransitionB,
    ThirdPerson,
    NativeUpdateOwner,
    Dead,
    VanillaControls,
    Process,
    Cell,
    Collision,
    FirstPerson3d,
    Camera1st,
    SpecialCamera,
    Vats,
    Menu,
    OsGlobals,
    FlyCamera,
    FirstPersonCamera,
    SceneGraph,
    WorldCamera,
    ActionFrame,
    ActionContext,
    ProcessContract,
    ScriptedAction,
    Furniture,
    Knocked,
    Controller,
    Locomotion,
    InvalidValues,
}

impl NativeRejection {
    pub(super) const COUNT: usize = 31;
    pub(super) const ALL: [Self; Self::COUNT] = [
        Self::CombinedControls,
        Self::InvalidPlayer,
        Self::PlayerMismatch,
        Self::PovTransitionA,
        Self::PovTransitionB,
        Self::ThirdPerson,
        Self::NativeUpdateOwner,
        Self::Dead,
        Self::VanillaControls,
        Self::Process,
        Self::Cell,
        Self::Collision,
        Self::FirstPerson3d,
        Self::Camera1st,
        Self::SpecialCamera,
        Self::Vats,
        Self::Menu,
        Self::OsGlobals,
        Self::FlyCamera,
        Self::FirstPersonCamera,
        Self::SceneGraph,
        Self::WorldCamera,
        Self::ActionFrame,
        Self::ActionContext,
        Self::ProcessContract,
        Self::ScriptedAction,
        Self::Furniture,
        Self::Knocked,
        Self::Controller,
        Self::Locomotion,
        Self::InvalidValues,
    ];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::CombinedControls => "combined disabled controls",
            Self::InvalidPlayer => "invalid player",
            Self::PlayerMismatch => "player ownership mismatch",
            Self::PovTransitionA => "POV transition A",
            Self::PovTransitionB => "POV transition B",
            Self::ThirdPerson => "third person",
            Self::NativeUpdateOwner => "native special update",
            Self::Dead => "dead player",
            Self::VanillaControls => "vanilla disabled controls",
            Self::Process => "missing process",
            Self::Cell => "missing cell",
            Self::Collision => "missing collision owner",
            Self::FirstPerson3d => "missing first-person 3D",
            Self::Camera1st => "missing Camera1st",
            Self::SpecialCamera => "special camera",
            Self::Vats => "VATS",
            Self::Menu => "menu mode",
            Self::OsGlobals => "missing OSGlobals",
            Self::FlyCamera => "free camera",
            Self::FirstPersonCamera => "missing first-person render camera",
            Self::SceneGraph => "missing world scene graph",
            Self::WorldCamera => "missing world camera",
            Self::ActionFrame => "missing action frame",
            Self::ActionContext => "non-gameplay action context",
            Self::ProcessContract => "process virtual contract",
            Self::ScriptedAction => "scripted action",
            Self::Furniture => "furniture",
            Self::Knocked => "knocked state",
            Self::Controller => "missing character controller",
            Self::Locomotion => "unsupported locomotion",
            Self::InvalidValues => "invalid sampled values",
        }
    }
}

/// Failure to admit the fixed first-person native contract.
#[derive(Debug, Error)]
pub(crate) enum NativeContractError {
    /// A proven native range is not readable in this process.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// A supported-runtime function prologue differs from the researched EXE.
    #[error("first-person native fingerprint mismatch at 0x{address:08X}")]
    FingerprintMismatch { address: usize },
}

/// Validate the shared complete UpdateCamera body and ABI at `DeferredInit`.
///
/// This contract is intentionally independent from first-person render state
/// so third-person ownership is not lost when an unrelated render capability
/// is unavailable.
pub(super) fn validate_update_camera_contract() -> Result<(), NativeContractError> {
    for &(address, expected) in UPDATE_CAMERA_INTERIOR_FINGERPRINTS {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(NativeContractError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

/// Validate fixed first-person global slots and helper functions.
pub(super) fn validate_contract() -> Result<(), NativeContractError> {
    validate_update_camera_contract()?;
    for address in [
        PLAYER_PTR,
        OS_GLOBALS_PTR,
        INTERFACE_MANAGER_PTR,
        CAMERA_1ST_PTR,
        WORLD_SCENE_GRAPH_PTR,
        SKY_ROOT_PTR,
        WEATHER_ROOT_PTR,
    ] {
        validate_memory_range(address as *const c_void, size_of::<*mut c_void>())?;
    }
    for address in [
        SPECIAL_CAMERA_STATE,
        LOGICAL_YAW,
        LOGICAL_PITCH,
        VATS_CAMERA_DATA + VATS_MODE,
        TIME_GLOBAL + TIME_SECONDS_PASSED,
    ] {
        validate_memory_range(address as *const c_void, size_of::<f32>())?;
    }

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
        (
            FIRST_PERSON_ANIMATION_BLOCKED,
            &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x89, 0x4D, 0xF8],
        ),
        (
            UPDATE_NIAVOBJECT,
            &[0x56, 0x8B, 0xF1, 0x8B, 0x4C, 0x24, 0x08, 0x8B, 0x06],
        ),
    ];
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(NativeContractError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

/// Copy one post-camera-update sample without retaining engine pointers.
///
/// # Safety
///
/// `player` must be the live receiver passed to the researched UpdateCamera
/// entry, and its chained native predecessor must already have returned.
pub(super) unsafe fn sample_after_update(
    player: *mut c_void,
) -> Result<NativeUpdateSample, NativeRejection> {
    unsafe { hard_owner_allows(player)? };
    let action_frame = latest_action_frame();
    if action_frame.frame_id() == 0 {
        return Err(NativeRejection::ActionFrame);
    }
    if action_frame.context() != ActionContext::Gameplay {
        return Err(NativeRejection::ActionContext);
    }

    let process =
        unsafe { read_ptr(player.cast::<u8>(), PLAYER_PROCESS) }.ok_or(NativeRejection::Process)?;
    let current_action = unsafe {
        let function: ProcessActionFn = read_virtual(process, PROCESS_CURRENT_ACTION_VTBL)
            .ok_or(NativeRejection::ProcessContract)?;
        function(process)
    };
    if matches!(current_action, SCRIPTED_ACTION_A | SCRIPTED_ACTION_B) {
        return Err(NativeRejection::ScriptedAction);
    }
    let furniture_state = unsafe {
        let function: ProcessStateFn = read_virtual(process, PROCESS_FURNITURE_STATE_VTBL)
            .ok_or(NativeRejection::ProcessContract)?;
        function(process)
    };
    let knocked_state = unsafe {
        let function: ProcessStateFn = read_virtual(process, PROCESS_KNOCKED_STATE_VTBL)
            .ok_or(NativeRejection::ProcessContract)?;
        function(process)
    };
    if furniture_state != 0 {
        return Err(NativeRejection::Furniture);
    }
    if knocked_state != 0 {
        return Err(NativeRejection::Knocked);
    }
    let aiming = unsafe {
        let function: ProcessBoolFn = read_virtual(process, PROCESS_IS_AIMING_VTBL)
            .ok_or(NativeRejection::ProcessContract)?;
        function(process) != 0
    };

    let controller = unsafe { get_character_controller()(player) };
    if !is_engine_pointer(controller) {
        return Err(NativeRejection::Controller);
    }
    let locomotion = match unsafe { get_controller_state()(controller) } {
        0 => LocomotionState::Grounded,
        1 => LocomotionState::Jumping,
        2 => LocomotionState::Airborne,
        _ => LocomotionState::Unsupported,
    };
    if locomotion == LocomotionState::Unsupported {
        return Err(NativeRejection::Locomotion);
    }
    let mut velocity = NativePoint3::default();
    unsafe { get_relative_velocity()(controller, &mut velocity) };

    let delta_seconds = unsafe { read_value::<f32>(TIME_GLOBAL as *const u8, TIME_SECONDS_PASSED) };
    let yaw = unsafe { core::ptr::read_unaligned(LOGICAL_YAW as *const f32) };
    let pitch = unsafe { core::ptr::read_unaligned(LOGICAL_PITCH as *const f32) };
    let animation_blocked = unsafe { first_person_animation_blocked()(player) != 0 };
    let cell = unsafe { read_ptr(player.cast::<u8>(), PLAYER_PARENT_CELL) }
        .ok_or(NativeRejection::Cell)? as usize;
    let values = [
        delta_seconds,
        yaw,
        pitch,
        velocity.x,
        velocity.y,
        velocity.z,
    ];
    if cell < MIN_ENGINE_POINTER || !values.into_iter().all(f32::is_finite) {
        return Err(NativeRejection::InvalidValues);
    }

    Ok(NativeUpdateSample {
        input_frame_id: action_frame.frame_id(),
        cell,
        logical_angles: [yaw, pitch],
        motion: MotionInput::new(
            delta_seconds,
            [velocity.x, velocity.y, velocity.z],
            locomotion,
            [0.0; 2],
            aiming,
            animation_blocked,
        ),
    })
}

/// Recheck same-update native camera ownership before a render write.
///
/// # Safety
///
/// The caller must be inside a researched main render callsite.
pub(super) unsafe fn render_owner_allows() -> Result<(), NativeRejection> {
    let player = unsafe { read_global_ptr(PLAYER_PTR) };
    unsafe { hard_owner_allows(player)? };
    if latest_action_frame().context() != ActionContext::Gameplay {
        return Err(NativeRejection::ActionContext);
    }
    Ok(())
}

/// Apply a pose to the persistent world camera for one scoped call.
///
/// # Safety
///
/// The caller must be inside one of the two researched main world render calls.
pub(super) unsafe fn pose_world_camera(pose: CameraPose) -> Option<WorldTransformGuard> {
    let scene_graph = unsafe { read_global_ptr(WORLD_SCENE_GRAPH_PTR) };
    let camera = unsafe { read_ptr(scene_graph.cast::<u8>(), SCENE_GRAPH_CAMERA)? };
    let sky = unsafe { read_global_ptr(SKY_ROOT_PTR) };
    let weather = unsafe { read_global_ptr(WEATHER_ROOT_PTR) };
    if !is_engine_pointer(sky) || !is_engine_pointer(weather) {
        return None;
    }
    unsafe {
        WorldTransformGuard::apply_with_updater(
            camera.cast::<u8>(),
            sky.cast::<u8>(),
            weather.cast::<u8>(),
            pose,
            update_native_graph,
        )
    }
}

/// Apply a pose to OSGlobals' separately rendered first-person camera.
///
/// # Safety
///
/// The caller must be inside a paired researched RenderFirstPerson call after
/// native first-person/iron-sight setup has completed.
pub(super) unsafe fn pose_first_person_camera(pose: CameraPose) -> Option<ViewmodelTransformGuard> {
    let os_globals = unsafe { read_global_ptr(OS_GLOBALS_PTR) };
    let camera = unsafe { read_ptr(os_globals.cast::<u8>(), OS_GLOBALS_FIRST_PERSON_CAMERA)? };
    let player = unsafe { read_global_ptr(PLAYER_PTR) };
    let root = unsafe { read_ptr(player.cast::<u8>(), PLAYER_FIRST_PERSON_3D)? };
    unsafe {
        ViewmodelTransformGuard::apply_with_updater(
            camera.cast::<u8>(),
            root.cast::<u8>(),
            pose,
            update_native_graph,
        )
    }
}

/// Scoped world-camera pose with coherent finite-sky centering.
///
/// FNV centers the `Sky` and `Weather` roots from the camera before Atom's
/// world callsite. Moving only the camera makes both roots visibly jump by the
/// inverse offset. This guard temporarily gives both roots the posed camera's
/// local position, updates their cached descendant transforms through the same
/// native helper used by `0x00872B00`, then restores all three owners.
#[must_use = "dropping the guard restores the camera and infinite-scene roots"]
pub(super) struct WorldTransformGuard {
    camera: *mut u8,
    original_camera: CameraTransform,
    sky: GraphTransformSnapshot,
    weather: GraphTransformSnapshot,
    update: GraphUpdater,
}

impl WorldTransformGuard {
    unsafe fn apply_with_updater(
        camera: *mut u8,
        sky: *mut u8,
        weather: *mut u8,
        pose: CameraPose,
        update: GraphUpdater,
    ) -> Option<Self> {
        if !is_engine_pointer(camera.cast())
            || !is_engine_pointer(sky.cast())
            || !is_engine_pointer(weather.cast())
            || pose.is_identity()
        {
            return None;
        }
        let original_camera = unsafe { read_transform(camera)? };
        let local_camera = unsafe { read_local_transform(camera)? };
        let composed_camera = compose_transform(original_camera, pose)?;
        let centered_translation = compose_transform(local_camera, pose)?.translation;
        let sky = unsafe { GraphTransformSnapshot::capture(sky)? };
        let weather = unsafe { GraphTransformSnapshot::capture(weather)? };

        // Resolve every pointer and finite value before the first write. From
        // here onward the operations are infallible native stores/updates, so
        // a partial render transaction cannot escape through an Option path.
        unsafe {
            write_transform(camera, composed_camera);
            sky.write_local_translation(centered_translation);
            update(sky.object);
            weather.write_local_translation(centered_translation);
            update(weather.object);
        }
        Some(Self {
            camera,
            original_camera,
            sky,
            weather,
            update,
        })
    }
}

impl Drop for WorldTransformGuard {
    fn drop(&mut self) {
        // Restore roots through their normal recursive update so cached child
        // transforms cannot retain Atom's temporary center after the draw.
        unsafe {
            self.sky.restore(self.update);
            self.weather.restore(self.update);
            write_transform(self.camera, self.original_camera);
        }
    }
}

/// Scoped first-person render pose in an origin-relative coordinate frame.
///
/// Fallout stores both the viewmodel root and its camera in absolute `f32`
/// world coordinates. Sub-unit procedural motion therefore quantizes into
/// visible steps in large TTW worldspaces. FNV renders first-person geometry
/// before its later root-update call, so the complete render call can safely
/// rebase both values near zero, apply the additive pose there, then restore
/// the exact native values. An existing viewmodel-shake owner that already
/// supplied a zero root is detected naturally and remains authoritative.
#[must_use = "dropping the guard restores the viewmodel root and camera"]
pub(super) struct ViewmodelTransformGuard {
    camera: *mut u8,
    original_camera: CameraTransform,
    root: Option<GraphTransformSnapshot>,
    update: GraphUpdater,
}

impl ViewmodelTransformGuard {
    unsafe fn apply_with_updater(
        camera: *mut u8,
        root: *mut u8,
        pose: CameraPose,
        update: GraphUpdater,
    ) -> Option<Self> {
        if !is_engine_pointer(camera.cast())
            || !is_engine_pointer(root.cast())
            || pose.is_identity()
        {
            return None;
        }
        let original_camera = unsafe { read_transform(camera)? };
        let root_snapshot = unsafe { GraphTransformSnapshot::capture(root)? };
        let already_rebased = root_snapshot.local.translation == [0.0; 3]
            && root_snapshot.world.translation == [0.0; 3];

        let base_camera = if already_rebased {
            original_camera
        } else {
            let mut rebased_camera = original_camera;
            for axis in 0..3 {
                rebased_camera.translation[axis] -= root_snapshot.world.translation[axis];
            }
            rebased_camera
        };
        if !base_camera.is_finite() {
            return None;
        }
        let composed = compose_transform(base_camera, pose)?;
        // No fallible operation is allowed after the first native write. The
        // first-person player node is a render root; zeroing both transforms
        // is the executable-corroborated ViewModel Shake Fix transaction.
        unsafe {
            if !already_rebased {
                write_translation(root, NIAVOBJECT_LOCAL_TRANSLATION, [0.0; 3]);
                write_translation(root, NIAVOBJECT_WORLD_TRANSLATION, [0.0; 3]);
                update(root);
            }
            write_transform(camera, composed);
        }
        Some(Self {
            camera,
            original_camera,
            root: (!already_rebased).then_some(root_snapshot),
            update,
        })
    }
}

impl Drop for ViewmodelTransformGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(root) = self.root {
                root.restore(self.update);
            }
            write_transform(self.camera, self.original_camera);
        }
    }
}

#[derive(Clone, Copy)]
struct GraphTransformSnapshot {
    object: *mut u8,
    local: CameraTransform,
    world: CameraTransform,
}

impl GraphTransformSnapshot {
    unsafe fn capture(object: *mut u8) -> Option<Self> {
        Some(Self {
            object,
            local: unsafe { read_local_transform(object)? },
            world: unsafe { read_transform(object)? },
        })
    }

    unsafe fn write_local_translation(self, translation: [f32; 3]) {
        unsafe { write_translation(self.object, NIAVOBJECT_LOCAL_TRANSLATION, translation) };
    }

    unsafe fn restore(self, update: GraphUpdater) {
        unsafe {
            write_local_transform(self.object, self.local);
            write_transform(self.object, self.world);
            update(self.object);
            // The recursive update is required for descendants. Reapply the
            // root snapshots afterward so the externally owned root itself is
            // bit-exact even if native multiplication rounded a component.
            write_local_transform(self.object, self.local);
            write_transform(self.object, self.world);
        }
    }
}

unsafe fn hard_owner_allows(player: *mut c_void) -> Result<(), NativeRejection> {
    if !native_owners_allow_camera() {
        return Err(NativeRejection::CombinedControls);
    }
    if !is_engine_pointer(player) {
        return Err(NativeRejection::InvalidPlayer);
    }
    if unsafe { read_global_ptr(PLAYER_PTR) } != player {
        return Err(NativeRejection::PlayerMismatch);
    }
    if unsafe { read_u8(player.cast(), PLAYER_POV_TRANSITION_A) } != 0 {
        return Err(NativeRejection::PovTransitionA);
    }
    if unsafe { read_u8(player.cast(), PLAYER_POV_TRANSITION_B) } != 0 {
        return Err(NativeRejection::PovTransitionB);
    }
    if unsafe { read_u8(player.cast(), PLAYER_THIRD_PERSON) } != 0 {
        return Err(NativeRejection::ThirdPerson);
    }
    if unsafe { read_u8(player.cast(), PLAYER_NATIVE_UPDATE_OWNER) } != 0 {
        return Err(NativeRejection::NativeUpdateOwner);
    }
    if unsafe { read_u8(player.cast(), PLAYER_LIFE_STATE) } != 0 {
        return Err(NativeRejection::Dead);
    }
    if unsafe { read_u8(player.cast(), PLAYER_DISABLED_CONTROLS) } & DISABLED_CONTROL_MASK != 0 {
        return Err(NativeRejection::VanillaControls);
    }
    // Actor +0x0AC owns a process-lifetime bhkRagdollController allocation;
    // it is commonly non-null while the actor is alive and upright. Active
    // knockdown is checked through the process GetKnockedState virtual in the
    // post-update sample below. Treating allocation as state would reject
    // every normal camera frame on runtimes that eagerly create the controller.
    if unsafe { read_ptr(player.cast(), PLAYER_PROCESS) }.is_none() {
        return Err(NativeRejection::Process);
    }
    if unsafe { read_ptr(player.cast(), PLAYER_PARENT_CELL) }.is_none() {
        return Err(NativeRejection::Cell);
    }
    if unsafe { read_ptr(player.cast(), PLAYER_COLLISION_OWNER) }.is_none() {
        return Err(NativeRejection::Collision);
    }
    if unsafe { read_ptr(player.cast(), PLAYER_FIRST_PERSON_3D) }.is_none() {
        return Err(NativeRejection::FirstPerson3d);
    }
    if unsafe { read_global_ptr(CAMERA_1ST_PTR) }.is_null() {
        return Err(NativeRejection::Camera1st);
    }
    if unsafe { read_u8(SPECIAL_CAMERA_STATE as *const u8, 0) } != 0 {
        return Err(NativeRejection::SpecialCamera);
    }
    if unsafe { core::ptr::read_unaligned((VATS_CAMERA_DATA + VATS_MODE) as *const u32) } != 0 {
        return Err(NativeRejection::Vats);
    }
    if unsafe { menu_mode_active() } {
        return Err(NativeRejection::Menu);
    }
    let os_globals = unsafe { read_global_ptr(OS_GLOBALS_PTR) };
    if !is_engine_pointer(os_globals) {
        return Err(NativeRejection::OsGlobals);
    }
    if unsafe { read_u8(os_globals.cast(), OS_GLOBALS_FLY_CAMERA) } != 0 {
        return Err(NativeRejection::FlyCamera);
    }
    if unsafe { read_ptr(os_globals.cast(), OS_GLOBALS_FIRST_PERSON_CAMERA) }.is_none() {
        return Err(NativeRejection::FirstPersonCamera);
    }
    let scene_graph = unsafe { read_global_ptr(WORLD_SCENE_GRAPH_PTR) };
    if !is_engine_pointer(scene_graph) {
        return Err(NativeRejection::SceneGraph);
    }
    if unsafe { read_ptr(scene_graph.cast(), SCENE_GRAPH_CAMERA) }.is_none() {
        return Err(NativeRejection::WorldCamera);
    }
    Ok(())
}

unsafe fn read_transform(camera: *mut u8) -> Option<CameraTransform> {
    let rotation = unsafe {
        core::ptr::read_unaligned(
            camera
                .add(NIAVOBJECT_WORLD_ROTATION)
                .cast::<[[f32; 3]; 3]>(),
        )
    };
    let translation = unsafe {
        core::ptr::read_unaligned(camera.add(NIAVOBJECT_WORLD_TRANSLATION).cast::<[f32; 3]>())
    };
    let transform = CameraTransform::new(rotation, translation);
    transform.is_finite().then_some(transform)
}

unsafe fn read_local_transform(object: *mut u8) -> Option<CameraTransform> {
    let rotation = unsafe {
        core::ptr::read_unaligned(
            object
                .add(NIAVOBJECT_LOCAL_ROTATION)
                .cast::<[[f32; 3]; 3]>(),
        )
    };
    let translation = unsafe { read_translation(object, NIAVOBJECT_LOCAL_TRANSLATION)? };
    let transform = CameraTransform::new(rotation, translation);
    transform.is_finite().then_some(transform)
}

unsafe fn write_transform(camera: *mut u8, transform: CameraTransform) {
    unsafe {
        core::ptr::write_unaligned(
            camera
                .add(NIAVOBJECT_WORLD_ROTATION)
                .cast::<[[f32; 3]; 3]>(),
            transform.rotation,
        );
        core::ptr::write_unaligned(
            camera.add(NIAVOBJECT_WORLD_TRANSLATION).cast::<[f32; 3]>(),
            transform.translation,
        );
    }
}

unsafe fn write_local_transform(object: *mut u8, transform: CameraTransform) {
    unsafe {
        core::ptr::write_unaligned(
            object
                .add(NIAVOBJECT_LOCAL_ROTATION)
                .cast::<[[f32; 3]; 3]>(),
            transform.rotation,
        );
        write_translation(object, NIAVOBJECT_LOCAL_TRANSLATION, transform.translation);
    }
}

unsafe fn read_translation(object: *mut u8, offset: usize) -> Option<[f32; 3]> {
    let translation = unsafe { core::ptr::read_unaligned(object.add(offset).cast::<[f32; 3]>()) };
    translation
        .into_iter()
        .all(f32::is_finite)
        .then_some(translation)
}

unsafe fn write_translation(object: *mut u8, offset: usize, translation: [f32; 3]) {
    unsafe { core::ptr::write_unaligned(object.add(offset).cast::<[f32; 3]>(), translation) };
}

unsafe fn update_native_graph(object: *mut u8) {
    let update = NativeUpdateData::default();
    unsafe { update_niavobject()(object.cast(), &update) };
}

unsafe fn read_global_ptr(address: usize) -> *mut c_void {
    unsafe { core::ptr::read_volatile(address as *const *mut c_void) }
}

/// Reproduce FNV's `MenuMode` ownership predicate from its live manager.
///
/// The helper entry has 55 native callers and may already be detoured by
/// `DeferredInit`, so its vanilla prologue is not an ownership invariant. The
/// researched body adds no policy beyond these two manager fields.
unsafe fn menu_mode_active() -> bool {
    let manager = unsafe { read_global_ptr(INTERFACE_MANAGER_PTR) };
    is_engine_pointer(manager)
        && menu_mode_from_fields(
            unsafe { read_u8(manager.cast(), INTERFACE_MANAGER_ACTIVE) },
            unsafe { read_value::<u32>(manager.cast(), INTERFACE_MANAGER_MODE) },
        )
}

const fn menu_mode_from_fields(active: u8, mode: u32) -> bool {
    active != 0 && mode != GAMEPLAY_INTERFACE_MODE
}

unsafe fn read_ptr(base: *const u8, offset: usize) -> Option<*mut c_void> {
    if !is_engine_pointer(base.cast_mut().cast()) {
        return None;
    }
    let value = unsafe { read_raw_ptr(base, offset) };
    is_engine_pointer(value).then_some(value)
}

unsafe fn read_raw_ptr(base: *const u8, offset: usize) -> *mut c_void {
    unsafe { core::ptr::read_unaligned(base.add(offset).cast::<*mut c_void>()) }
}

unsafe fn read_u8(base: *const u8, offset: usize) -> u8 {
    unsafe { core::ptr::read_unaligned(base.add(offset)) }
}

unsafe fn read_value<T: Copy>(base: *const u8, offset: usize) -> T {
    unsafe { core::ptr::read_unaligned(base.add(offset).cast::<T>()) }
}

unsafe fn read_virtual<T: Copy>(owner: *mut c_void, offset: usize) -> Option<T> {
    if !is_engine_pointer(owner) {
        return None;
    }
    let vtable = unsafe { core::ptr::read_unaligned(owner.cast::<*mut u8>()) };
    if !is_engine_pointer(vtable.cast()) {
        return None;
    }
    let function = unsafe { core::ptr::read_unaligned(vtable.add(offset).cast::<usize>()) };
    if function < MIN_ENGINE_POINTER || size_of::<T>() != size_of::<usize>() {
        return None;
    }
    // Every caller chooses an exact x86 ABI type whose pointer size is checked
    // above. Copying pointer bits avoids an unconstrained generic transmute.
    Some(unsafe { core::ptr::read_unaligned((&function as *const usize).cast::<T>()) })
}

fn is_engine_pointer(pointer: *mut c_void) -> bool {
    pointer as usize >= MIN_ENGINE_POINTER
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

fn first_person_animation_blocked() -> AnimationBlockedFn {
    unsafe { core::mem::transmute(FIRST_PERSON_ANIMATION_BLOCKED) }
}

fn update_niavobject() -> UpdateNiAvObjectFn {
    unsafe { core::mem::transmute(UPDATE_NIAVOBJECT) }
}

#[cfg(test)]
mod tests {
    use super::{
        CameraPose, CameraTransform, NIAVOBJECT_LOCAL_TRANSLATION, NIAVOBJECT_WORLD_ROTATION,
        NIAVOBJECT_WORLD_TRANSLATION, NativeUpdateData, ViewmodelTransformGuard,
        WorldTransformGuard, menu_mode_from_fields, read_local_transform, read_transform,
        write_local_transform, write_transform,
    };

    const IDENTITY_ROTATION: [[f32; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];

    unsafe fn propagate_local_transform(object: *mut u8) {
        let local = unsafe { read_local_transform(object) }.expect("finite local transform");
        unsafe { write_transform(object, local) };
    }

    unsafe fn reject_unowned_graph_update(_object: *mut u8) {
        panic!("an existing origin-rebase owner must keep root update ownership");
    }

    #[test]
    fn menu_ownership_matches_the_native_interface_manager_policy() {
        assert!(!menu_mode_from_fields(0, 0));
        assert!(!menu_mode_from_fields(1, 1));
        assert!(menu_mode_from_fields(1, 0));
        assert!(menu_mode_from_fields(1, 2));
        assert_eq!(core::mem::size_of::<NativeUpdateData>(), 12);
    }

    #[test]
    fn scoped_world_pose_recenters_sky_and_restores_every_owner() {
        let mut camera_object = [0u8; 0xA0];
        let mut sky_object = [0u8; 0xA0];
        let mut weather_object = [0u8; 0xA0];
        let camera = camera_object.as_mut_ptr();
        let sky = sky_object.as_mut_ptr();
        let weather = weather_object.as_mut_ptr();
        let original = CameraTransform::new(
            [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]],
            [12_345.25, -98_765.5, 432.125],
        );
        let local = CameraTransform::new(original.rotation, original.translation);
        let sky_original = CameraTransform::new(IDENTITY_ROTATION, original.translation);
        let weather_original = CameraTransform::new(IDENTITY_ROTATION, original.translation);
        unsafe {
            write_transform(camera, original);
            write_local_transform(camera, local);
            write_local_transform(sky, sky_original);
            write_transform(sky, sky_original);
            write_local_transform(weather, weather_original);
            write_transform(weather, weather_original);
        }

        {
            let guard = unsafe {
                WorldTransformGuard::apply_with_updater(
                    camera,
                    sky,
                    weather,
                    CameraPose::new([0.25, -0.5, 0.75], [0.002, -0.004, 0.006]),
                    propagate_local_transform,
                )
            }
            .expect("finite scoped pose");
            let posed = unsafe { read_transform(camera) }.expect("posed transform");
            assert_ne!(posed, original);
            let posed_local = unsafe { read_local_transform(camera) }.expect("local camera");
            assert_eq!(
                unsafe { read_local_transform(sky) }
                    .expect("posed sky")
                    .translation,
                super::compose_transform(
                    posed_local,
                    CameraPose::new([0.25, -0.5, 0.75], [0.002, -0.004, 0.006]),
                )
                .expect("finite local pose")
                .translation,
            );
            assert_eq!(
                unsafe { read_local_transform(weather) }
                    .expect("posed weather")
                    .translation,
                unsafe { read_local_transform(sky) }
                    .expect("posed sky")
                    .translation,
            );
            assert_eq!(
                unsafe { read_transform(sky) }
                    .expect("updated sky")
                    .translation,
                unsafe { read_transform(weather) }
                    .expect("updated weather")
                    .translation,
            );
            drop(guard);
        }

        assert_eq!(unsafe { read_transform(camera) }, Some(original));
        assert_eq!(unsafe { read_local_transform(sky) }, Some(sky_original));
        assert_eq!(unsafe { read_transform(sky) }, Some(sky_original));
        assert_eq!(
            unsafe { read_local_transform(weather) },
            Some(weather_original)
        );
        assert_eq!(unsafe { read_transform(weather) }, Some(weather_original));
        // The researched fields are adjacent but not represented by a Rust
        // engine struct; this assertion also protects their exact offsets.
        assert_eq!(
            NIAVOBJECT_WORLD_TRANSLATION - NIAVOBJECT_WORLD_ROTATION,
            0x24
        );
    }

    #[test]
    fn viewmodel_pose_rebases_large_world_coordinates_and_restores_on_unwind() {
        let mut camera_object = [0u8; 0xA0];
        let mut root_object = [0u8; 0xA0];
        let camera = camera_object.as_mut_ptr();
        let root = root_object.as_mut_ptr();
        let root_transform =
            CameraTransform::new(IDENTITY_ROTATION, [1_250_000.0, -875_000.0, 64_000.0]);
        let original =
            CameraTransform::new(IDENTITY_ROTATION, [1_250_001.3, -874_999.5, 64_000.75]);
        unsafe {
            write_local_transform(root, root_transform);
            write_transform(root, root_transform);
            write_transform(camera, original);
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = unsafe {
                ViewmodelTransformGuard::apply_with_updater(
                    camera,
                    root,
                    CameraPose::new([0.25, 0.50, 0.75], [0.001, 0.002, 0.003]),
                    propagate_local_transform,
                )
            }
            .expect("finite scoped pose");
            let rebased = unsafe { read_transform(camera) }.expect("rebased camera");
            assert!(
                rebased
                    .translation
                    .into_iter()
                    .all(|value| value.abs() < 4.0)
            );
            assert_eq!(
                unsafe { read_local_transform(root) }
                    .expect("rebased root")
                    .translation,
                [0.0; 3],
            );
            panic!("injected render-wrapper unwind");
        }));

        assert!(result.is_err());
        assert_eq!(unsafe { read_transform(camera) }, Some(original));
        assert_eq!(unsafe { read_local_transform(root) }, Some(root_transform));
        assert_eq!(unsafe { read_transform(root) }, Some(root_transform));
        assert_eq!(NIAVOBJECT_LOCAL_TRANSLATION, 0x58);
    }

    #[test]
    fn viewmodel_pose_preserves_an_existing_origin_rebase_owner() {
        let mut camera_object = [0u8; 0xA0];
        let mut root_object = [0u8; 0xA0];
        let camera = camera_object.as_mut_ptr();
        let root = root_object.as_mut_ptr();
        let root_transform = CameraTransform::new(IDENTITY_ROTATION, [0.0; 3]);
        let original = CameraTransform::new(IDENTITY_ROTATION, [1.25, 0.5, 0.75]);
        unsafe {
            write_local_transform(root, root_transform);
            write_transform(root, root_transform);
            write_transform(camera, original);
        }

        {
            let _guard = unsafe {
                ViewmodelTransformGuard::apply_with_updater(
                    camera,
                    root,
                    CameraPose::new([0.25, 0.50, 0.75], [0.001, 0.002, 0.003]),
                    reject_unowned_graph_update,
                )
            }
            .expect("finite scoped pose");
            assert_ne!(unsafe { read_transform(camera) }, Some(original));
            assert_eq!(unsafe { read_local_transform(root) }, Some(root_transform));
            assert_eq!(unsafe { read_transform(root) }, Some(root_transform));
        }

        assert_eq!(unsafe { read_transform(camera) }, Some(original));
        assert_eq!(unsafe { read_local_transform(root) }, Some(root_transform));
        assert_eq!(unsafe { read_transform(root) }, Some(root_transform));
    }
}

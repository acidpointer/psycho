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

use crate::input::{ActionContext, ActionId, latest_action_frame};

use super::{AimAngles, Vec3};

const PLAYER_PTR: usize = 0x011D_EA3C;
const OS_GLOBALS_PTR: usize = 0x011D_EA0C;
const INTERFACE_MANAGER_PTR: usize = 0x011D_8A80;
const SPECIAL_CAMERA_STATE: usize = 0x011E_07B8;
const VATS_CAMERA_DATA: usize = 0x011F_2250;
const TIME_GLOBAL: usize = 0x011F_6394;

const PLAYER_PARENT_CELL: usize = 0x040;
const PLAYER_PROCESS: usize = 0x068;
const PLAYER_LIFE_STATE: usize = 0x108;
const PLAYER_MOVER: usize = 0x190;
const PLAYER_COLLISION_OWNER: usize = 0x21C;
const PLAYER_ROTATION_X: usize = 0x024;
const PLAYER_ROTATION_Z: usize = 0x02C;
const PLAYER_POSITION: usize = 0x030;
const PLAYER_POV_READY: usize = 0x64A;
const PLAYER_ACTIVE_PERSPECTIVE: usize = 0x64B;
const PLAYER_THIRD_PERSON: usize = 0x64C;
const PLAYER_DISABLED_CONTROLS: usize = 0x680;

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
const ACTOR_ADJUSTED_HEADING_VTBL: usize = 0x2BC;
const ACTOR_SET_YAW_VTBL: usize = 0x2C4;

const ACTIVE_3D: usize = 0x0095_0BE0;
const WEAPON_PROJECTILE_NODE: usize = 0x0052_5700;
const MATRIX_TO_ANGLES: usize = 0x00A5_9400;

const WEAPON_TYPE: usize = 0x0F4;
const PROJECTILE_TYPE_FLAGS: usize = 0x060;
const PROJECTILE_RANGE: usize = 0x06C;
const PROJECTILE_TYPE_MASK: u32 = 0x001F_0000;
const MISSILE_PROJECTILE: u32 = 0x0001_0000;
const NIAVOBJECT_WORLD_ROTATION: usize = 0x068;
const NIAVOBJECT_WORLD_POSITION: usize = 0x08C;
const MIN_ENGINE_POINTER: usize = 0x1_0000;
const SCRIPTED_ACTION_A: i16 = 0x0D;
const SCRIPTED_ACTION_B: i16 = 0x0E;
const VANILLA_DISABLED_MASK: u8 = 0x1F;

type Active3dFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type ProcessActionFn = unsafe extern "thiscall" fn(*mut c_void) -> i16;
type ProcessBoolFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;
type ProcessStateFn = unsafe extern "thiscall" fn(*mut c_void) -> i32;
type ActorAdjustedHeadingFn = unsafe extern "thiscall" fn(*mut c_void, u8) -> f32;
type ActorSetYawFn = unsafe extern "thiscall" fn(*mut c_void, f32);
type ProjectileNodeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> *mut c_void;
type MatrixAnglesFn =
    unsafe extern "thiscall" fn(*const [[f32; 3]; 3], *mut f32, *mut f32, *mut f32) -> u8;

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
    ];
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(NativeContractError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

pub(super) fn player() -> *mut c_void {
    unsafe { core::ptr::read_volatile(PLAYER_PTR as *const *mut c_void) }
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
    let live_player = player();
    let mut frame = NativeFrame {
        frame_id: actions.frame_id(),
        player: live_player,
        mover: core::ptr::null_mut(),
        cell: core::ptr::null_mut(),
        pivot: Vec3::default(),
        actor_yaw: 0.0,
        camera_heading: 0.0,
        pitch: 0.0,
        delta_seconds: 0.0,
        stable_third_person: false,
        world_ready: false,
        native_owner: true,
        hard_valid: false,
        rejection: NativeRejection::InvalidPlayer,
        weapon_out: false,
        combat_intent: actions.action(ActionId::Use).down()
            || actions.action(ActionId::Block).down()
            || actions.action(ActionId::ReadyItem).down(),
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
    // UpdateCamera obtains pitch from 0x00931D70, which reads Actor rotX at
    // +0x24. Virtual +0x2BC is adjusted horizontal heading, not pitch.
    frame.pitch = unsafe { read_f32(live_player.cast(), PLAYER_ROTATION_X) };
    frame.delta_seconds = unsafe { read_f32(TIME_GLOBAL as *const u8, TIME_SECONDS_PASSED) };

    let process_state = if is_engine_pointer(process) {
        unsafe { observe_process(process) }
    } else {
        None
    };
    if let Some(state) = process_state {
        frame.weapon_out = state.weapon_out;
    }

    let relevant_controls = ControlFlags::MOVEMENT
        | ControlFlags::LOOKING
        | ControlFlags::PIPBOY
        | ControlFlags::FIGHTING
        | ControlFlags::POV;
    let controls_owned = controls.any_disabled(DisabledCheck::ByAnyModOrVanilla, relevant_controls)
        || unsafe { read_u8(live_player.cast(), PLAYER_DISABLED_CONTROLS) } & VANILLA_DISABLED_MASK
            != 0;
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

unsafe fn observe_process(process: *mut c_void) -> Option<ProcessState> {
    let action: ProcessActionFn = unsafe { read_virtual(process, PROCESS_CURRENT_ACTION_VTBL)? };
    let knocked: ProcessStateFn = unsafe { read_virtual(process, PROCESS_KNOCKED_STATE_VTBL)? };
    let furniture: ProcessStateFn = unsafe { read_virtual(process, PROCESS_FURNITURE_STATE_VTBL)? };
    let weapon_out: ProcessBoolFn = unsafe { read_virtual(process, PROCESS_WEAPON_OUT_VTBL)? };
    // Resolving the aiming slot as part of the contract ensures a process
    // implementation incomplete for combat cannot accidentally be admitted.
    let _: ProcessBoolFn = unsafe { read_virtual(process, PROCESS_IS_AIMING_VTBL)? };
    let action = unsafe { action(process) };
    Some(ProcessState {
        knocked: unsafe { knocked(process) },
        furniture: unsafe { furniture(process) },
        scripted: matches!(action, SCRIPTED_ACTION_A | SCRIPTED_ACTION_B),
        weapon_out: unsafe { weapon_out(process) != 0 },
    })
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

unsafe fn read_global_ptr(address: usize) -> *mut c_void {
    unsafe { core::ptr::read_volatile(address as *const *mut c_void) }
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

    use super::{NativeRejection, ProcessState, classify_rejection, menu_mode_from_fields};

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

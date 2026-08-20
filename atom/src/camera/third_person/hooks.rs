//! Deferred, ownership-aware third-person native hooks.
//!
//! Immutable instructions around each mutable call displacement prove the
//! supported FNV semantic context. Direct-call hooks capture the live target
//! as a typed predecessor so compatible earlier owners remain in the chain.
//! Follow and movement/facing are independent rollback-capable transactions.
//! A compatible owner at one seam therefore disables only that capability,
//! never the other. Object selection through the native reticle cast is
//! independently useful and safe to admit. Optional projectile convergence
//! joins it only when the spawn call still targets vanilla, because an
//! uncoordinated launch transformation cannot compose safely. The hip-fire
//! pose adapter is a separate chained animation-entry capability and changes
//! only paired group IDs for the admitted live player.

use core::ffi::c_void;
use std::sync::LazyLock;

use libpsycho::os::windows::{
    hook::{
        callsite::{Rel32CallHookContainer, Rel32CallHookError},
        inline::{errors::InlineHookError, inlinehook::InlineHookContainer},
        pointer::{PointerSlotHookContainer, PointerSlotHookError},
        transaction::ModificationTransaction,
    },
    memory::{MemoryError, read_bytes},
};
use thiserror::Error;

use super::{AimAngles, Vec3};

const PLAYER_HEADING_SLOT: usize = 0x0108_ACF8;
const CAMERA_PITCH_CALLSITE: usize = 0x0094_AE94;
const ZOOM_CALLSITE: usize = 0x0094_59BB;
const FOLLOW_CALLSITE: usize = 0x0094_B7D2;
const MOVEMENT_SCOPE_ENTRY: usize = 0x009E_9E50;
const PLAYER_MOVEMENT_SLOT: usize = 0x0108_AC8C;
const RETICLE_CALLSITE: usize = 0x0070_C130;
const SPAWN_CALLSITE: usize = 0x0052_45BD;
const MORPH_GROUP_ENTRY: usize = 0x0049_48C0;

const NATIVE_PLAYER_HEADING: usize = 0x0095_3F20;
const NATIVE_PLAYER_PITCH: usize = 0x0093_1D70;
const NATIVE_MOUSE_GETTER: usize = 0x00A2_39E0;
const NATIVE_FOLLOW: usize = 0x0094_A0C0;
const NATIVE_PLAYER_MOVEMENT: usize = 0x008A_62B0;
const NATIVE_RETICLE: usize = 0x0063_1D60;
const NATIVE_SPAWN: usize = 0x009B_CA60;

type PlayerHeadingFn = unsafe extern "thiscall" fn(*mut c_void, u8) -> f32;
type PlayerPitchFn = unsafe extern "thiscall" fn(*mut c_void) -> f32;
type MouseGetterFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> i32;
type FollowFn = unsafe extern "thiscall" fn(*mut c_void, *mut Vec3, *const Vec3, u8);
type PlayerMoverUpdateFn = unsafe extern "thiscall" fn(*mut c_void, f32);
type PlayerMovementFn =
    unsafe extern "thiscall" fn(*mut c_void, f32, *mut Vec3, u32) -> *mut c_void;
type ViewCasterFn = unsafe extern "thiscall" fn(
    *mut c_void,
    *mut Vec3,
    *mut Vec3,
    f32,
    *mut f32,
    *mut u8,
) -> *mut c_void;
type SpawnFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    Vec3,
    f32,
    f32,
    *mut c_void,
    *mut c_void,
    u32,
    u32,
    f32,
    f32,
    *mut c_void,
) -> *mut c_void;
type MorphGroupFn = unsafe extern "thiscall" fn(*mut c_void, u16, i32) -> *mut c_void;

static CAMERA_HEADING_HOOK: PointerSlotHookContainer<PlayerHeadingFn> =
    PointerSlotHookContainer::new();
static CAMERA_PITCH_HOOK: Rel32CallHookContainer<PlayerPitchFn> = Rel32CallHookContainer::new();
static ZOOM_HOOK: Rel32CallHookContainer<MouseGetterFn> = Rel32CallHookContainer::new();
static FOLLOW_HOOK: Rel32CallHookContainer<FollowFn> = Rel32CallHookContainer::new();
static MOVEMENT_SCOPE_HOOK: LazyLock<InlineHookContainer<PlayerMoverUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
static PLAYER_MOVEMENT_HOOK: PointerSlotHookContainer<PlayerMovementFn> =
    PointerSlotHookContainer::new();
static RETICLE_HOOK: Rel32CallHookContainer<ViewCasterFn> = Rel32CallHookContainer::new();
static SPAWN_HOOK: Rel32CallHookContainer<SpawnFn> = Rel32CallHookContainer::new();
static HIP_FIRE_POSE_HOOK: LazyLock<InlineHookContainer<MorphGroupFn>> =
    LazyLock::new(InlineHookContainer::new);

const MOVEMENT_FINGERPRINTS: &[(usize, &[u8])] = &[
    (
        0x0094_AE70,
        &[
            0x6A, 0x00, 0x8B, 0x85, 0xEC, 0xFB, 0xFF, 0xFF, 0x8B, 0x10, 0x8B, 0x8D, 0xEC, 0xFB,
            0xFF, 0xFF, 0x8B, 0x82, 0xBC, 0x02, 0x00, 0x00, 0xFF, 0xD0,
        ],
    ),
    (
        0x0094_AE88,
        &[
            0xD9, 0x1D, 0x6C, 0x07, 0x1E, 0x01, 0x8B, 0x8D, 0xEC, 0xFB, 0xFF, 0xFF,
        ],
    ),
    (0x0094_AE99, &[0xD9, 0x1D, 0x64, 0x07, 0x1E, 0x01]),
    (
        0x0094_B434,
        &[
            0x6A, 0x00, 0x8B, 0x8D, 0xEC, 0xFB, 0xFF, 0xFF, 0x8B, 0x11, 0x8B, 0x8D, 0xEC, 0xFB,
            0xFF, 0xFF, 0x8B, 0x82, 0xBC, 0x02, 0x00, 0x00, 0xFF, 0xD0,
        ],
    ),
    // The entry may already contain a compatible chained JMP. Fingerprint
    // immutable body and epilogue instructions instead of mutable entry bytes.
    (
        0x009E_9E59,
        &[0x56, 0x89, 0x4D, 0xA8, 0xA1, 0x6C, 0x42, 0x1F, 0x01],
    ),
    (0x009E_A2E2, &[0x5E, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00]),
    (0x009E_A207, &[0x8B, 0x0D, 0x3C, 0xEA, 0x1D, 0x01]),
    (
        0x009E_A212,
        &[
            0x50, 0x8D, 0x4D, 0xF0, 0x51, 0x51, 0xD9, 0x45, 0x08, 0xD9, 0x1C, 0x24, 0x8B, 0x15,
            0x3C, 0xEA, 0x1D, 0x01,
        ],
    ),
    (
        0x008A_6327,
        &[
            0x8B, 0x4D, 0x10, 0x51, 0x8B, 0x55, 0x0C, 0x52, 0x51, 0xD9, 0x45, 0x08, 0xD9, 0x1C,
            0x24, 0x8B, 0x4D, 0xAC,
        ],
    ),
    (0x008A_633E, &[0x89, 0x45, 0xE8, 0x83, 0x7D, 0xE8, 0x00]),
];

const FOLLOW_FINGERPRINTS: &[(usize, &[u8])] = &[
    (
        0x0094_B7B9,
        &[
            0x0F, 0xB6, 0x55, 0x08, 0x52, 0x8D, 0x85, 0xC8, 0xFE, 0xFF, 0xFF, 0x50, 0x8D, 0x8D,
            0xD4, 0xFE, 0xFF, 0xFF, 0x51, 0x8B, 0x8D, 0xEC, 0xFB, 0xFF, 0xFF,
        ],
    ),
    (0x0094_B7D7, &[0x8D, 0x95, 0xAC, 0xFE, 0xFF, 0xFF, 0x52]),
];

const ZOOM_FINGERPRINTS: &[(usize, &[u8])] = &[
    (
        0x0094_59B3,
        &[0x6A, 0x03, 0x8B, 0x8D, 0xD4, 0xFE, 0xFF, 0xFF],
    ),
    (0x0094_59C0, &[0x89, 0x85, 0xD0, 0xFE, 0xFF, 0xFF]),
];

const AIM_FINGERPRINTS: &[(usize, &[u8])] = &[
    (
        0x0070_C119,
        &[
            0xD9, 0x1C, 0x24, 0x8D, 0x55, 0x84, 0x52, 0x8D, 0x45, 0x90, 0x50, 0x8B, 0x8D, 0x98,
            0xFE, 0xFF, 0xFF, 0x8B, 0x89, 0x3C, 0x01, 0x00, 0x00,
        ],
    ),
    (
        0x0070_C135,
        &[
            0x89, 0x85, 0x7C, 0xFF, 0xFF, 0xFF, 0xC6, 0x85, 0x27, 0xFF, 0xFF, 0xFF, 0x01,
        ],
    ),
    (
        0x0052_45A1,
        &[
            0x51, 0x8B, 0x55, 0x90, 0x52, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x8D, 0x48, 0xFE, 0xFF,
            0xFF, 0x51, 0x8B, 0x8D, 0xC8, 0xFD, 0xFF, 0xFF,
        ],
    ),
    (0x0052_45BC, &[0x50]),
    (
        0x0052_45C2,
        &[0x83, 0xC4, 0x40, 0x89, 0x85, 0x58, 0xFE, 0xFF, 0xFF],
    ),
];

// Compatible animation plugins may already own the mutable function entry.
// Fingerprint immutable original-body instructions so InlineHook can chain a
// complete entry JMP while Atom still rejects an unsupported executable.
const HIP_FIRE_POSE_FINGERPRINTS: &[(usize, &[u8])] = &[
    (
        MORPH_GROUP_ENTRY + 0x09,
        &[0x0F, 0xB7, 0x45, 0x08, 0x3D, 0xFF, 0x00, 0x00, 0x00],
    ),
    (
        MORPH_GROUP_ENTRY + 0xCE,
        &[0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00],
    ),
];

/// Failure to validate or install the required third-person hook group.
#[derive(Debug, Error)]
pub(crate) enum HookInstallError {
    /// Reading a required caller fingerprint failed.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// A required caller differs from the supported executable.
    #[error("third-person caller fingerprint mismatch at 0x{address:08X}")]
    FingerprintMismatch { address: usize },
    /// A required direct call could not be captured or enabled.
    #[error(transparent)]
    Callsite(#[from] Rel32CallHookError),
    /// The PlayerCharacter adjusted-heading vtable slot could not be chained.
    #[error(transparent)]
    Pointer(#[from] PointerSlotHookError),
    /// A required native function entry could not be chained.
    #[error(transparent)]
    Inline(#[from] InlineHookError),
}

/// Captured live targets for the inseparable movement/facing capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MovementPredecessors {
    pub(super) camera_heading: usize,
    pub(super) camera_pitch: usize,
    pub(super) movement_scope: usize,
    pub(super) player_movement: usize,
}

/// Captured live targets and independent reticle/convergence admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AimPredecessors {
    pub(super) reticle: usize,
    pub(super) spawn: usize,
    pub(super) reticle_admitted: bool,
    pub(super) aim_admitted: bool,
}

/// Install linear wheel-distance conversion at the normal camera read only.
pub(super) fn install_zoom() -> Result<usize, HookInstallError> {
    validate_fingerprints(ZOOM_FINGERPRINTS)?;
    unsafe {
        ZOOM_HOOK.init(
            "Atom third-person fine zoom",
            ZOOM_CALLSITE as *mut c_void,
            zoom_detour,
        )?;
    }
    let predecessor = ZOOM_HOOK.predecessor_address()?;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&ZOOM_HOOK)?;
    transaction.commit();
    Ok(predecessor)
}

/// Install the native-collision follow capability independently.
pub(super) fn install_follow() -> Result<usize, HookInstallError> {
    validate_fingerprints(FOLLOW_FINGERPRINTS)?;
    unsafe {
        FOLLOW_HOOK.init(
            "Atom third-person collision input",
            FOLLOW_CALLSITE as *mut c_void,
            follow_detour,
        )?;
    }
    let predecessor = FOLLOW_HOOK.predecessor_address()?;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&FOLLOW_HOOK)?;
    transaction.commit();
    Ok(predecessor)
}

/// Install logical view axes, mover scope, and request as one capability.
pub(super) fn install_movement() -> Result<MovementPredecessors, HookInstallError> {
    validate_fingerprints(MOVEMENT_FINGERPRINTS)?;
    unsafe {
        CAMERA_HEADING_HOOK.init(
            "Atom third-person adjusted heading",
            PLAYER_HEADING_SLOT as *mut *mut c_void,
            camera_heading_detour,
        )?;
        CAMERA_PITCH_HOOK.init(
            "Atom third-person camera pitch",
            CAMERA_PITCH_CALLSITE as *mut c_void,
            camera_pitch_detour,
        )?;
        MOVEMENT_SCOPE_HOOK.init(
            "Atom player movement scope",
            MOVEMENT_SCOPE_ENTRY as *mut c_void,
            movement_scope_detour,
        )?;
        PLAYER_MOVEMENT_HOOK.init(
            "Atom complete player movement",
            PLAYER_MOVEMENT_SLOT as *mut *mut c_void,
            player_movement_detour,
        )?;
    }

    let predecessors = MovementPredecessors {
        camera_heading: CAMERA_HEADING_HOOK.predecessor_address()?,
        camera_pitch: CAMERA_PITCH_HOOK.predecessor_address()?,
        movement_scope: MOVEMENT_SCOPE_HOOK.original()? as *const () as usize,
        player_movement: PLAYER_MOVEMENT_HOOK.predecessor_address()?,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_pointer(&CAMERA_HEADING_HOOK)?;
    transaction.enable_callsite(&CAMERA_PITCH_HOOK)?;
    transaction.enable_inline(&MOVEMENT_SCOPE_HOOK)?;
    transaction.enable_pointer(&PLAYER_MOVEMENT_HOOK)?;
    transaction.commit();
    Ok(predecessors)
}

/// Admit camera-correct object selection, then optional projectile convergence.
pub(super) fn install_aim() -> Result<AimPredecessors, HookInstallError> {
    validate_fingerprints(AIM_FINGERPRINTS)?;
    let combat_ray_admitted = match super::native::validate_combat_ray_contract() {
        Ok(()) => true,
        Err(error) => {
            log::warn!(
                "[AIM] Muzzle convergence is unavailable: {error:#}. Camera-correct interaction remains available"
            );
            false
        }
    };
    unsafe {
        RETICLE_HOOK.init(
            "Atom third-person reticle ray",
            RETICLE_CALLSITE as *mut c_void,
            reticle_detour,
        )?;
        SPAWN_HOOK.init(
            "Atom third-person muzzle convergence",
            SPAWN_CALLSITE as *mut c_void,
            spawn_detour,
        )?;
    }
    let predecessors = AimPredecessors {
        reticle: RETICLE_HOOK.predecessor_address()?,
        spawn: SPAWN_HOOK.predecessor_address()?,
        reticle_admitted: false,
        aim_admitted: false,
    };
    let (reticle_admitted, native_spawn_admitted) = super::reticle_and_convergence_admission(
        predecessors.reticle == NATIVE_RETICLE,
        predecessors.spawn == NATIVE_SPAWN,
    );
    let aim_admitted = native_spawn_admitted && combat_ray_admitted;
    if !reticle_admitted {
        return Ok(predecessors);
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&RETICLE_HOOK)?;
    if aim_admitted {
        transaction.enable_callsite(&SPAWN_HOOK)?;
    }
    transaction.commit();
    Ok(AimPredecessors {
        reticle_admitted,
        aim_admitted,
        ..predecessors
    })
}

/// Install the ranged hip-fire animation-group adapter independently.
///
/// FNV's morph entry remains the transition owner. The detour changes only a
/// paired group ID and calls the captured predecessor once, leaving kNVSE's
/// internal sequence lookup and transition hooks in their established chain.
pub(super) fn install_hip_fire_pose() -> Result<usize, HookInstallError> {
    validate_fingerprints(HIP_FIRE_POSE_FINGERPRINTS)?;
    unsafe {
        HIP_FIRE_POSE_HOOK.init(
            "Atom third-person hip-fire pose",
            MORPH_GROUP_ENTRY as *mut c_void,
            hip_fire_pose_detour,
        )?;
    }
    let predecessor = HIP_FIRE_POSE_HOOK.original()? as *const () as usize;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&HIP_FIRE_POSE_HOOK)?;
    transaction.commit();
    Ok(predecessor)
}

/// Request one native crossfade through the already captured morph chain.
///
/// # Safety
///
/// `anim_data` and `group` must be the synchronous values selected from the
/// live player graph by `native::hip_fire_transition_group`.
pub(super) unsafe fn morph_hip_fire_group(anim_data: *mut c_void, group: u16) -> bool {
    let Ok(predecessor) = HIP_FIRE_POSE_HOOK.original() else {
        return false;
    };
    !unsafe { predecessor(anim_data, group, -1) }.is_null()
}

fn validate_fingerprints(fingerprints: &[(usize, &[u8])]) -> Result<(), HookInstallError> {
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(HookInstallError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

unsafe extern "thiscall" fn zoom_detour(owner: *mut c_void, axis: u32) -> i32 {
    let predecessor = ZOOM_HOOK
        .original()
        .unwrap_or_else(|_| native_mouse_getter());
    let native_delta = unsafe { predecessor(owner, axis) };
    if axis == 3 {
        super::refine_zoom_wheel(native_delta)
    } else {
        native_delta
    }
}

unsafe extern "thiscall" fn hip_fire_pose_detour(
    anim_data: *mut c_void,
    group: u16,
    sequence_type: i32,
) -> *mut c_void {
    let Ok(predecessor) = HIP_FIRE_POSE_HOOK.original() else {
        return core::ptr::null_mut();
    };
    let group = super::remap_hip_fire_animation(anim_data, group);
    unsafe { predecessor(anim_data, group, sequence_type) }
}

unsafe extern "thiscall" fn camera_heading_detour(player: *mut c_void, adjusted: u8) -> f32 {
    let predecessor = CAMERA_HEADING_HOOK
        .original()
        .unwrap_or_else(|_| native_player_heading());
    let native = unsafe { predecessor(player, adjusted) };
    let overridden = super::scoped_camera_heading(player);
    super::diagnostics::mark_camera_heading(overridden.is_some());
    overridden.unwrap_or(native)
}

unsafe extern "thiscall" fn camera_pitch_detour(player: *mut c_void) -> f32 {
    let predecessor = CAMERA_PITCH_HOOK
        .original()
        .unwrap_or_else(|_| native_player_pitch());
    let native = unsafe { predecessor(player) };
    super::scoped_camera_pitch(player)
        .or_else(|| super::fallback_camera_pitch(player))
        .unwrap_or(native)
}

unsafe extern "thiscall" fn follow_detour(
    player: *mut c_void,
    desired: *mut Vec3,
    pivot: *const Vec3,
    mode: u8,
) {
    super::diagnostics::mark_follow_call();
    let predecessor = FOLLOW_HOOK.original().unwrap_or_else(|_| native_follow());
    let Some((desired_value, pivot_value)) =
        (unsafe { desired.as_ref() }).zip(unsafe { pivot.as_ref() })
    else {
        unsafe { predecessor(player, desired, pivot, mode) };
        return;
    };
    if !desired_value.is_finite() || !pivot_value.is_finite() {
        unsafe { predecessor(player, desired, pivot, mode) };
        return;
    }
    let Some((follow_offset, motion_offset)) = super::scoped_camera_offsets(player) else {
        unsafe { predecessor(player, desired, pivot, mode) };
        return;
    };
    super::diagnostics::mark_follow_offset(follow_offset + motion_offset);

    let Some(followed) = super::compose_follow_camera(*desired_value, *pivot_value, follow_offset)
    else {
        unsafe { predecessor(player, desired, pivot, mode) };
        return;
    };
    let Some(composed) = super::compose_motion_camera(followed, motion_offset) else {
        unsafe { predecessor(player, desired, pivot, mode) };
        return;
    };

    // Keep FNV's player-root pivot exact. Moving it changes the collision set
    // and makes the camera react to shoulder-height clutter and actors.
    let mut adjusted_desired = composed;
    unsafe { predecessor(player, &mut adjusted_desired, pivot, mode) };
    unsafe { desired.write(adjusted_desired) };
}

unsafe extern "thiscall" fn movement_scope_detour(mover: *mut c_void, dt: f32) {
    let predecessor = MOVEMENT_SCOPE_HOOK
        .original()
        .unwrap_or_else(|_| native_movement_scope());
    let guard = MovementScopeGuard::enter(mover);
    super::diagnostics::mark_movement_scope(guard.active());
    unsafe { predecessor(mover, dt) };
    drop(guard);
}

struct MovementScopeGuard {
    scope: Option<super::MovementScope>,
}

impl MovementScopeGuard {
    fn enter(mover: *mut c_void) -> Self {
        Self {
            scope: super::enter_movement_scope(mover),
        }
    }

    fn active(&self) -> bool {
        self.scope.is_some()
    }
}

impl Drop for MovementScopeGuard {
    fn drop(&mut self) {
        if let Some(scope) = self.scope.take() {
            super::leave_movement_scope(scope);
        }
    }
}

unsafe extern "thiscall" fn player_movement_detour(
    actor: *mut c_void,
    dt: f32,
    movement: *mut Vec3,
    flags: u32,
) -> *mut c_void {
    let predecessor = PLAYER_MOVEMENT_HOOK
        .original()
        .unwrap_or_else(|_| native_player_movement());
    let Some(native) = (unsafe { movement.as_ref() }) else {
        super::diagnostics::mark_movement(false);
        return unsafe { predecessor(actor, dt, movement, flags) };
    };
    let Some(output) = super::movement_override(actor, *native, flags, dt) else {
        if let Some(output) = super::fallback_movement_override(actor, *native, flags) {
            super::diagnostics::mark_movement(true);
            let mut transformed = output.vector();
            return unsafe { predecessor(actor, dt, &mut transformed, output.flags()) };
        }
        super::diagnostics::mark_movement(false);
        // A movement miss is not a camera-owner transition. Chaining native
        // unchanged must not fold or clear Atom's persistent view heading.
        return unsafe { predecessor(actor, dt, movement, flags) };
    };
    super::diagnostics::mark_movement(true);
    let mut transformed = output.vector();
    unsafe { predecessor(actor, dt, &mut transformed, output.flags()) }
}

unsafe extern "thiscall" fn reticle_detour(
    caster: *mut c_void,
    origin: *mut Vec3,
    direction: *mut Vec3,
    max_distance: f32,
    out_distance: *mut f32,
    out_alternate_hit: *mut u8,
) -> *mut c_void {
    let predecessor = RETICLE_HOOK.original().unwrap_or_else(|_| native_reticle());
    let Some((origin_value, direction_value)) =
        (unsafe { origin.as_ref() }).zip(unsafe { direction.as_ref() })
    else {
        return unsafe {
            predecessor(
                caster,
                origin,
                direction,
                max_distance,
                out_distance,
                out_alternate_hit,
            )
        };
    };
    if !direction_value.is_finite() {
        return unsafe {
            predecessor(
                caster,
                origin,
                direction,
                max_distance,
                out_distance,
                out_alternate_hit,
            )
        };
    }
    if out_distance.is_null() || out_alternate_hit.is_null() {
        return unsafe {
            predecessor(
                caster,
                origin,
                direction,
                max_distance,
                out_distance,
                out_alternate_hit,
            )
        };
    }
    let Some(prepared) = super::prepare_view_cast(*origin_value, max_distance) else {
        return unsafe {
            predecessor(
                caster,
                origin,
                direction,
                max_distance,
                out_distance,
                out_alternate_hit,
            )
        };
    };
    // The exact native caller reuses these stack locals after ViewCaster to
    // publish InterfaceManager's crosshair world point. Passing temporaries
    // corrects collision selection only; it leaves actor/weapon aim and any
    // compatible downstream convergence owner on the old vanilla ray. Keep
    // the corrected values in the caller-owned locals for that whole chain.
    unsafe {
        origin.write(prepared.origin());
        direction.write(prepared.direction());
    }
    let Some(cast_distance) = prepared.cast_distance() else {
        unsafe { clear_view_cast_outputs(out_distance, out_alternate_hit) };
        return core::ptr::null_mut();
    };
    let mut selected = unsafe {
        predecessor(
            caster,
            origin,
            direction,
            cast_distance,
            out_distance,
            out_alternate_hit,
        )
    };
    let distance = unsafe { out_distance.as_ref() }.copied();
    let accepted_distance =
        distance.filter(|value| !selected.is_null() && prepared.accepts_hit(*value));
    if !selected.is_null() && accepted_distance.is_none() {
        // Match ViewCaster's researched no-hit outputs exactly. An object or
        // obstruction between the remote camera and the player's native
        // reach sphere may block the cursor ray, but it is never activatable.
        unsafe { clear_view_cast_outputs(out_distance, out_alternate_hit) };
        selected = core::ptr::null_mut();
    }
    selected
}

/// Publish the exact no-hit values initialized by FNV ViewCaster 0x00631D60.
///
/// # Safety
///
/// Both pointers must be the non-null caller-owned outputs from the admitted
/// InterfaceManager callsite.
unsafe fn clear_view_cast_outputs(out_distance: *mut f32, out_alternate_hit: *mut u8) {
    let (distance, alternate) = super::view_cast_no_hit_outputs();
    unsafe {
        out_distance.write(distance);
        out_alternate_hit.write(alternate);
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn spawn_detour(
    projectile: *mut c_void,
    source: *mut c_void,
    controller: *mut c_void,
    weapon: *mut c_void,
    position: Vec3,
    rotation_z: f32,
    rotation_x: f32,
    opaque: *mut c_void,
    live_target: *mut c_void,
    always_hit: u32,
    ignore_gravity: u32,
    angular_z: f32,
    angular_x: f32,
    cell: *mut c_void,
) -> *mut c_void {
    let predecessor = SPAWN_HOOK.original().unwrap_or_else(|_| native_spawn());
    let prepared = super::prepare_spawn(
        projectile,
        source,
        weapon,
        AimAngles::new(rotation_z, rotation_x),
    );
    let (position, rotation_z, rotation_x) = prepared
        .map(|(muzzle, angles)| (muzzle, angles.yaw(), angles.pitch()))
        .unwrap_or((position, rotation_z, rotation_x));
    unsafe {
        predecessor(
            projectile,
            source,
            controller,
            weapon,
            position,
            rotation_z,
            rotation_x,
            opaque,
            live_target,
            always_hit,
            ignore_gravity,
            angular_z,
            angular_x,
            cell,
        )
    }
}

fn native_player_heading() -> PlayerHeadingFn {
    unsafe { core::mem::transmute(NATIVE_PLAYER_HEADING) }
}

fn native_player_pitch() -> PlayerPitchFn {
    unsafe { core::mem::transmute(NATIVE_PLAYER_PITCH) }
}

fn native_mouse_getter() -> MouseGetterFn {
    unsafe { core::mem::transmute(NATIVE_MOUSE_GETTER) }
}

fn native_follow() -> FollowFn {
    unsafe { core::mem::transmute(NATIVE_FOLLOW) }
}

fn native_movement_scope() -> PlayerMoverUpdateFn {
    unsafe { core::mem::transmute(MOVEMENT_SCOPE_ENTRY) }
}

fn native_player_movement() -> PlayerMovementFn {
    unsafe { core::mem::transmute(NATIVE_PLAYER_MOVEMENT) }
}

fn native_reticle() -> ViewCasterFn {
    unsafe { core::mem::transmute(NATIVE_RETICLE) }
}

fn native_spawn() -> SpawnFn {
    unsafe { core::mem::transmute(NATIVE_SPAWN) }
}

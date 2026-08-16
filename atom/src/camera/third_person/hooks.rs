//! Deferred, ownership-aware third-person native hooks.
//!
//! Immutable instructions around each mutable call displacement prove the
//! supported FNV semantic context. Direct-call hooks capture the live target
//! as a typed predecessor so compatible earlier owners remain in the chain.
//! Follow and movement/facing are independent rollback-capable transactions.
//! A compatible owner at one seam therefore disables only that capability,
//! never the other. The two aim callsites are enabled only as an inseparable
//! pair, only after movement admission, and only when both still target
//! vanilla because an uncoordinated convergence owner cannot compose safely.

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
const FOLLOW_CALLSITE: usize = 0x0094_B7D2;
const MOVEMENT_SCOPE_ENTRY: usize = 0x009E_9E50;
const MOVEMENT_REQUEST_CALLSITE: usize = 0x008A_6339;
const RETICLE_CALLSITE: usize = 0x0070_C130;
const SPAWN_CALLSITE: usize = 0x0052_45BD;

const NATIVE_PLAYER_HEADING: usize = 0x0095_3F20;
const NATIVE_FOLLOW: usize = 0x0094_A0C0;
const NATIVE_MOVEMENT_REQUEST: usize = 0x0092_F260;
const NATIVE_RETICLE: usize = 0x0063_1D60;
const NATIVE_SPAWN: usize = 0x009B_CA60;

type PlayerHeadingFn = unsafe extern "thiscall" fn(*mut c_void, u8) -> f32;
type FollowFn = unsafe extern "thiscall" fn(*mut c_void, *mut Vec3, *const Vec3, u8);
type PlayerMoverUpdateFn = unsafe extern "thiscall" fn(*mut c_void, f32);
type MovementRequestFn =
    unsafe extern "thiscall" fn(*mut c_void, f32, *mut Vec3, u32) -> *mut c_void;
type ViewCasterFn = unsafe extern "thiscall" fn(
    *mut c_void,
    *const Vec3,
    *const Vec3,
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

static CAMERA_HEADING_HOOK: PointerSlotHookContainer<PlayerHeadingFn> =
    PointerSlotHookContainer::new();
static FOLLOW_HOOK: Rel32CallHookContainer<FollowFn> = Rel32CallHookContainer::new();
static MOVEMENT_SCOPE_HOOK: LazyLock<InlineHookContainer<PlayerMoverUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
static MOVEMENT_REQUEST_HOOK: Rel32CallHookContainer<MovementRequestFn> =
    Rel32CallHookContainer::new();
static RETICLE_HOOK: Rel32CallHookContainer<ViewCasterFn> = Rel32CallHookContainer::new();
static SPAWN_HOOK: Rel32CallHookContainer<SpawnFn> = Rel32CallHookContainer::new();

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
    (
        MOVEMENT_SCOPE_ENTRY,
        &[
            0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, 0x56, 0x89, 0x4D, 0xA8,
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
    /// The scoped PlayerMover entry could not be chained.
    #[error(transparent)]
    Inline(#[from] InlineHookError),
}

/// Captured live targets for the inseparable movement/facing capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MovementPredecessors {
    pub(super) camera_heading: usize,
    pub(super) movement_scope: usize,
    pub(super) movement_request: usize,
}

/// Captured live targets and admission result for the paired aim capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AimPredecessors {
    pub(super) reticle: usize,
    pub(super) spawn: usize,
    pub(super) aim_admitted: bool,
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

/// Install adjusted heading, mover scope, and request as one capability.
pub(super) fn install_movement() -> Result<MovementPredecessors, HookInstallError> {
    validate_fingerprints(MOVEMENT_FINGERPRINTS)?;
    unsafe {
        CAMERA_HEADING_HOOK.init(
            "Atom third-person adjusted heading",
            PLAYER_HEADING_SLOT as *mut *mut c_void,
            camera_heading_detour,
        )?;
        MOVEMENT_SCOPE_HOOK.init(
            "Atom player movement scope",
            MOVEMENT_SCOPE_ENTRY as *mut c_void,
            movement_scope_detour,
        )?;
        MOVEMENT_REQUEST_HOOK.init(
            "Atom camera-relative movement request",
            MOVEMENT_REQUEST_CALLSITE as *mut c_void,
            movement_request_detour,
        )?;
    }

    let predecessors = MovementPredecessors {
        camera_heading: CAMERA_HEADING_HOOK.predecessor_address()?,
        movement_scope: MOVEMENT_SCOPE_HOOK.original()? as *const () as usize,
        movement_request: MOVEMENT_REQUEST_HOOK.predecessor_address()?,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_pointer(&CAMERA_HEADING_HOOK)?;
    transaction.enable_inline(&MOVEMENT_SCOPE_HOOK)?;
    transaction.enable_callsite(&MOVEMENT_REQUEST_HOOK)?;
    transaction.commit();
    Ok(predecessors)
}

/// Admit reticle and projectile convergence only as one vanilla-owned pair.
pub(super) fn install_aim() -> Result<AimPredecessors, HookInstallError> {
    validate_fingerprints(AIM_FINGERPRINTS)?;
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
        aim_admitted: false,
    };
    if predecessors.reticle != NATIVE_RETICLE || predecessors.spawn != NATIVE_SPAWN {
        return Ok(predecessors);
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&RETICLE_HOOK)?;
    transaction.enable_callsite(&SPAWN_HOOK)?;
    transaction.commit();
    Ok(AimPredecessors {
        aim_admitted: true,
        ..predecessors
    })
}

fn validate_fingerprints(fingerprints: &[(usize, &[u8])]) -> Result<(), HookInstallError> {
    for &(address, expected) in fingerprints {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(HookInstallError::FingerprintMismatch { address });
        }
    }
    Ok(())
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
    let Some(offset) = super::scoped_follow_offset(player) else {
        unsafe { predecessor(player, desired, pivot, mode) };
        return;
    };
    super::diagnostics::mark_follow_offset(offset);

    // The pivot is the player's logical position and the origin of FNV's
    // clearance ray. Keep it exact so native collision still covers the full
    // player-to-camera segment; compose follow displacement only into the
    // already-built shoulder/distance endpoint that native resolves in place.
    let mut adjusted_desired = *desired_value + offset;
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

unsafe extern "thiscall" fn movement_request_detour(
    actor: *mut c_void,
    dt: f32,
    movement: *mut Vec3,
    flags: u32,
) -> *mut c_void {
    let predecessor = MOVEMENT_REQUEST_HOOK
        .original()
        .unwrap_or_else(|_| native_movement_request());
    let Some(native) = (unsafe { movement.as_ref() }) else {
        super::diagnostics::mark_movement(false);
        return unsafe { predecessor(actor, dt, movement, flags) };
    };
    let Some(output) = super::movement_override(actor, *native, flags, dt) else {
        super::diagnostics::mark_movement(false);
        return unsafe { predecessor(actor, dt, movement, flags) };
    };
    super::diagnostics::mark_movement(true);
    let mut transformed = output.vector();
    unsafe { predecessor(actor, dt, &mut transformed, output.flags()) }
}

unsafe extern "thiscall" fn reticle_detour(
    caster: *mut c_void,
    origin: *const Vec3,
    direction: *const Vec3,
    max_distance: f32,
    out_distance: *mut f32,
    out_alternate_hit: *mut u8,
) -> *mut c_void {
    let predecessor = RETICLE_HOOK.original().unwrap_or_else(|_| native_reticle());
    let Some(origin_value) = (unsafe { origin.as_ref() }) else {
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
    let selected = unsafe {
        predecessor(
            caster,
            &prepared.origin(),
            &prepared.direction(),
            max_distance,
            out_distance,
            out_alternate_hit,
        )
    };
    if let Some(distance) = unsafe { out_distance.as_ref() } {
        super::finish_view_cast(prepared, *distance);
    }
    selected
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

fn native_follow() -> FollowFn {
    unsafe { core::mem::transmute(NATIVE_FOLLOW) }
}

fn native_movement_scope() -> PlayerMoverUpdateFn {
    unsafe { core::mem::transmute(MOVEMENT_SCOPE_ENTRY) }
}

fn native_movement_request() -> MovementRequestFn {
    unsafe { core::mem::transmute(NATIVE_MOVEMENT_REQUEST) }
}

fn native_reticle() -> ViewCasterFn {
    unsafe { core::mem::transmute(NATIVE_RETICLE) }
}

fn native_spawn() -> SpawnFn {
    unsafe { core::mem::transmute(NATIVE_SPAWN) }
}

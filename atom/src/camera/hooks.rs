//! Deferred first-person camera entry and render-call hooks.
//!
//! `PlayerCharacter::UpdateCamera` has eleven native callers, including three
//! mutually exclusive routes in the main player update. Atom wraps the live
//! function entry so every caller completes through one typed predecessor and
//! sampling always occurs after native camera construction. The same complete
//! entry scope lets third person substitute adjusted horizontal heading for
//! every native caller instead of assuming one player-update callsite is live.
//! predecessor per caller. The shared entry and the five first-person render
//! callsites are separate capabilities: third-person ownership needs only the
//! entry scope, while the render hooks are admitted together in their own
//! rollback-capable transaction. A rejected first-person render contract can
//! therefore never suppress an otherwise valid third-person camera system.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

use libpsycho::os::windows::hook::{
    callsite::{Rel32CallHookContainer, Rel32CallHookError},
    inline::{errors::InlineHookError, inlinehook::InlineHookContainer},
    transaction::ModificationTransaction,
};
use thiserror::Error;

use super::{
    RenderRoute, begin_world_render, consume_viewmodel_render, diagnostics,
    invalidate_render_token, native, sample_after_update,
};

const UPDATE_CAMERA_ENTRY: usize = 0x0094_AE40;
const WORLD_CALL_A: usize = 0x0087_0AE8;
const WORLD_CALL_B: usize = 0x0087_0E18;
const FIRST_PERSON_CALL_SPECIAL: usize = 0x0087_093D;
const FIRST_PERSON_CALL_A: usize = 0x0087_0B21;
const FIRST_PERSON_CALL_B: usize = 0x0087_0F74;

const RENDER_WORLD_NATIVE: usize = 0x0087_3200;
const RENDER_FIRST_PERSON_NATIVE: usize = 0x0087_5110;

type UpdateCameraFn = unsafe extern "thiscall" fn(*mut c_void, u8, u8);
type RenderWorldFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8, u8, u8);
type RenderFirstPersonFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void);

static UPDATE_CAMERA_HOOK: LazyLock<InlineHookContainer<UpdateCameraFn>> =
    LazyLock::new(InlineHookContainer::new);
static WORLD_HOOK_A: Rel32CallHookContainer<RenderWorldFn> = Rel32CallHookContainer::new();
static WORLD_HOOK_B: Rel32CallHookContainer<RenderWorldFn> = Rel32CallHookContainer::new();
static FIRST_PERSON_HOOK_SPECIAL: Rel32CallHookContainer<RenderFirstPersonFn> =
    Rel32CallHookContainer::new();
static FIRST_PERSON_HOOK_A: Rel32CallHookContainer<RenderFirstPersonFn> =
    Rel32CallHookContainer::new();
static FIRST_PERSON_HOOK_B: Rel32CallHookContainer<RenderFirstPersonFn> =
    Rel32CallHookContainer::new();

static WORLD_CALL_ACTIVE: AtomicBool = AtomicBool::new(false);
static FIRST_PERSON_CALL_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Failure to validate or transactionally install the camera wrapper.
#[derive(Debug, Error)]
pub(crate) enum HookInstallError {
    /// The complete UpdateCamera entry could not be chained.
    #[error(transparent)]
    Inline(#[from] InlineHookError),
    /// A direct call could not be captured, chained, enabled, or rolled back.
    #[error(transparent)]
    Callsite(#[from] Rel32CallHookError),
}

/// Live first-person render targets captured from each native caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RenderHookPredecessors {
    pub(crate) world_a: usize,
    pub(crate) world_b: usize,
    pub(crate) first_person_special: usize,
    pub(crate) first_person_a: usize,
    pub(crate) first_person_b: usize,
}

/// Install the complete `PlayerCharacter::UpdateCamera` entry wrapper.
pub(crate) fn install_update_entry() -> Result<usize, HookInstallError> {
    unsafe {
        UPDATE_CAMERA_HOOK.init(
            "Atom complete post-UpdateCamera sample",
            UPDATE_CAMERA_ENTRY as *mut c_void,
            update_camera_detour,
        )?;
    }
    let predecessor = UPDATE_CAMERA_HOOK.original()? as usize;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&UPDATE_CAMERA_HOOK)?;
    transaction.commit();
    Ok(predecessor)
}

/// Install the inseparable first-person world/viewmodel render group.
pub(crate) fn install_render_hooks() -> Result<RenderHookPredecessors, HookInstallError> {
    unsafe {
        WORLD_HOOK_A.init(
            "Atom first-person world route A",
            WORLD_CALL_A as *mut c_void,
            world_a_detour,
        )?;
        WORLD_HOOK_B.init(
            "Atom first-person world route B",
            WORLD_CALL_B as *mut c_void,
            world_b_detour,
        )?;
        FIRST_PERSON_HOOK_SPECIAL.init(
            "Atom special first-person pass-through",
            FIRST_PERSON_CALL_SPECIAL as *mut c_void,
            first_person_special_detour,
        )?;
        FIRST_PERSON_HOOK_A.init(
            "Atom first-person viewmodel route A",
            FIRST_PERSON_CALL_A as *mut c_void,
            first_person_a_detour,
        )?;
        FIRST_PERSON_HOOK_B.init(
            "Atom first-person viewmodel route B",
            FIRST_PERSON_CALL_B as *mut c_void,
            first_person_b_detour,
        )?;
    }

    let predecessors = RenderHookPredecessors {
        world_a: WORLD_HOOK_A.predecessor_address()?,
        world_b: WORLD_HOOK_B.predecessor_address()?,
        first_person_special: FIRST_PERSON_HOOK_SPECIAL.predecessor_address()?,
        first_person_a: FIRST_PERSON_HOOK_A.predecessor_address()?,
        first_person_b: FIRST_PERSON_HOOK_B.predecessor_address()?,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&WORLD_HOOK_A)?;
    transaction.enable_callsite(&WORLD_HOOK_B)?;
    transaction.enable_callsite(&FIRST_PERSON_HOOK_SPECIAL)?;
    transaction.enable_callsite(&FIRST_PERSON_HOOK_A)?;
    transaction.enable_callsite(&FIRST_PERSON_HOOK_B)?;
    transaction.commit();
    Ok(predecessors)
}

unsafe extern "thiscall" fn update_camera_detour(player: *mut c_void, first: u8, second: u8) {
    // Initialization publishes the trampoline before the transaction can
    // write the entry jump. If that invariant is ever broken, returning is
    // safer than jumping back to the now-detoured entry and recursing until
    // stack exhaustion.
    let Ok(predecessor) = UPDATE_CAMERA_HOOK.original() else {
        return;
    };
    let third_person_scope = ThirdPersonCameraScope::enter(player);
    unsafe { predecessor(player, first, second) };
    // Scope only native construction. Post-update sampling must observe the
    // completed native state without extending the heading substitution into
    // unrelated Atom work.
    drop(third_person_scope);
    unsafe { sample_after_update(player) };
}

struct ThirdPersonCameraScope {
    scope: Option<super::third_person::CameraUpdateScope>,
}

impl ThirdPersonCameraScope {
    fn enter(player: *mut c_void) -> Self {
        Self {
            scope: super::third_person::enter_camera_update_scope(player),
        }
    }
}

impl Drop for ThirdPersonCameraScope {
    fn drop(&mut self) {
        if let Some(scope) = self.scope.take() {
            super::third_person::leave_camera_update_scope(scope);
        }
    }
}

unsafe extern "thiscall" fn world_a_detour(
    main: *mut c_void,
    scene: *mut c_void,
    render_first_person: u8,
    scene_phase: u8,
    flags: u8,
) {
    let predecessor = WORLD_HOOK_A
        .original()
        .unwrap_or_else(|_| native_render_world());
    unsafe {
        world_body(
            predecessor,
            RenderRoute::A,
            main,
            scene,
            render_first_person,
            scene_phase,
            flags,
        )
    };
}

unsafe extern "thiscall" fn world_b_detour(
    main: *mut c_void,
    scene: *mut c_void,
    render_first_person: u8,
    scene_phase: u8,
    flags: u8,
) {
    let predecessor = WORLD_HOOK_B
        .original()
        .unwrap_or_else(|_| native_render_world());
    unsafe {
        world_body(
            predecessor,
            RenderRoute::B,
            main,
            scene,
            render_first_person,
            scene_phase,
            flags,
        )
    };
}

#[allow(clippy::too_many_arguments)]
unsafe fn world_body(
    predecessor: RenderWorldFn,
    route: RenderRoute,
    main: *mut c_void,
    scene: *mut c_void,
    render_first_person: u8,
    scene_phase: u8,
    flags: u8,
) {
    let Some(_scope) = CallScope::enter(&WORLD_CALL_ACTIVE) else {
        unsafe { predecessor(main, scene, render_first_person, scene_phase, flags) };
        return;
    };

    let frame = unsafe { begin_world_render(route) };
    let world_pose = frame.map(|value| value.world_pose());
    let guard = match world_pose.filter(|pose| !pose.is_identity()) {
        Some(pose) => {
            diagnostics::mark_world_pose();
            let guard = unsafe { native::pose_world_camera(pose) };
            diagnostics::mark_transform(guard.is_some());
            if guard.is_none() {
                invalidate_render_token();
            }
            guard
        }
        None => None,
    };
    unsafe { predecessor(main, scene, render_first_person, scene_phase, flags) };
    drop(guard);
}

unsafe extern "thiscall" fn first_person_special_detour(
    main: *mut c_void,
    renderer: *mut c_void,
    geometry: *mut c_void,
    sky_sun: *mut c_void,
    rendered_texture: *mut c_void,
) {
    invalidate_render_token();
    let predecessor = FIRST_PERSON_HOOK_SPECIAL
        .original()
        .unwrap_or_else(|_| native_render_first_person());
    unsafe { predecessor(main, renderer, geometry, sky_sun, rendered_texture) };
}

unsafe extern "thiscall" fn first_person_a_detour(
    main: *mut c_void,
    renderer: *mut c_void,
    geometry: *mut c_void,
    sky_sun: *mut c_void,
    rendered_texture: *mut c_void,
) {
    let predecessor = FIRST_PERSON_HOOK_A
        .original()
        .unwrap_or_else(|_| native_render_first_person());
    unsafe {
        first_person_body(
            predecessor,
            RenderRoute::A,
            main,
            renderer,
            geometry,
            sky_sun,
            rendered_texture,
        )
    };
}

unsafe extern "thiscall" fn first_person_b_detour(
    main: *mut c_void,
    renderer: *mut c_void,
    geometry: *mut c_void,
    sky_sun: *mut c_void,
    rendered_texture: *mut c_void,
) {
    let predecessor = FIRST_PERSON_HOOK_B
        .original()
        .unwrap_or_else(|_| native_render_first_person());
    unsafe {
        first_person_body(
            predecessor,
            RenderRoute::B,
            main,
            renderer,
            geometry,
            sky_sun,
            rendered_texture,
        )
    };
}

#[allow(clippy::too_many_arguments)]
unsafe fn first_person_body(
    predecessor: RenderFirstPersonFn,
    route: RenderRoute,
    main: *mut c_void,
    renderer: *mut c_void,
    geometry: *mut c_void,
    sky_sun: *mut c_void,
    rendered_texture: *mut c_void,
) {
    let Some(_scope) = CallScope::enter(&FIRST_PERSON_CALL_ACTIVE) else {
        invalidate_render_token();
        unsafe { predecessor(main, renderer, geometry, sky_sun, rendered_texture) };
        return;
    };

    let pose = unsafe { consume_viewmodel_render(route) };
    let guard = pose.filter(|value| !value.is_identity()).and_then(|value| {
        let guard = unsafe { native::pose_first_person_camera(value) };
        diagnostics::mark_transform(guard.is_some());
        guard
    });
    unsafe { predecessor(main, renderer, geometry, sky_sun, rendered_texture) };
    drop(guard);
}

struct CallScope<'a> {
    active: &'a AtomicBool,
}

impl<'a> CallScope<'a> {
    fn enter(active: &'a AtomicBool) -> Option<Self> {
        active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self { active })
    }
}

impl Drop for CallScope<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

fn native_render_world() -> RenderWorldFn {
    unsafe { core::mem::transmute(RENDER_WORLD_NATIVE) }
}

fn native_render_first_person() -> RenderFirstPersonFn {
    unsafe { core::mem::transmute(RENDER_FIRST_PERSON_NATIVE) }
}

//! Deferred first-person camera entry and render-call hooks.
//!
//! `PlayerCharacter::UpdateCamera` has eleven native callers, including three
//! mutually exclusive routes in the main player update. Atom wraps the live
//! function entry so every caller completes through one typed predecessor and
//! sampling always occurs after native camera construction. The same complete
//! entry scope lets third person substitute adjusted horizontal heading for
//! every native caller instead of assuming one player-update callsite is live.
//! The shared entry and the five first-person render callsites are separate
//! capabilities, and every render callsite captures its own typed predecessor.
//! Third-person ownership needs only the entry scope, while the render hooks
//! are admitted together in their own rollback-capable transaction at the first
//! post-Deferred main-loop boundary. That later boundary captures deferred
//! graphics wrappers as predecessors. The two outer route hooks apply the world
//! pose before native Sky/Weather preparation and keep it through final image
//! space; the three inner first-person hooks retain exact viewmodel ownership.
//! A rejected first-person render contract can therefore never suppress an
//! otherwise valid third-person camera system.

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
// Main::Render selects these two complete routes. Their exact thiscall ABI and
// `ret 8` epilogues are established in fnv_first_person_camera_contract.txt.
// Hooking here is essential: both route bodies call 0x00872B00, which centers
// Sky and Weather from the camera, before their RenderWorld calls.
const RENDER_ROUTE_CALL_A: usize = 0x0087_074B;
const RENDER_ROUTE_CALL_B: usize = 0x0087_075E;
const FIRST_PERSON_CALL_SPECIAL: usize = 0x0087_093D;
const FIRST_PERSON_CALL_A: usize = 0x0087_0B21;
const FIRST_PERSON_CALL_B: usize = 0x0087_0F74;

type UpdateCameraFn = unsafe extern "thiscall" fn(*mut c_void, u8, u8);
type RenderRouteFn = unsafe extern "thiscall" fn(*mut c_void, u32, u8);
type RenderFirstPersonFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void);

static UPDATE_CAMERA_HOOK: LazyLock<InlineHookContainer<UpdateCameraFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_ROUTE_HOOK_A: Rel32CallHookContainer<RenderRouteFn> = Rel32CallHookContainer::new();
static RENDER_ROUTE_HOOK_B: Rel32CallHookContainer<RenderRouteFn> = Rel32CallHookContainer::new();
static FIRST_PERSON_HOOK_SPECIAL: Rel32CallHookContainer<RenderFirstPersonFn> =
    Rel32CallHookContainer::new();
static FIRST_PERSON_HOOK_A: Rel32CallHookContainer<RenderFirstPersonFn> =
    Rel32CallHookContainer::new();
static FIRST_PERSON_HOOK_B: Rel32CallHookContainer<RenderFirstPersonFn> =
    Rel32CallHookContainer::new();

static RENDER_ROUTE_CALL_ACTIVE: AtomicBool = AtomicBool::new(false);
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
    pub(crate) route_a: usize,
    pub(crate) route_b: usize,
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
///
/// The caller must use a quiescent post-Deferred boundary. Enabling a direct
/// five-byte call is not atomic, and capturing before all deferred graphics
/// owners would invert the required camera/depth nesting.
pub(crate) fn install_render_hooks() -> Result<RenderHookPredecessors, HookInstallError> {
    unsafe {
        RENDER_ROUTE_HOOK_A.init(
            "Atom complete first-person render route A",
            RENDER_ROUTE_CALL_A as *mut c_void,
            render_route_a_detour,
        )?;
        RENDER_ROUTE_HOOK_B.init(
            "Atom complete first-person render route B",
            RENDER_ROUTE_CALL_B as *mut c_void,
            render_route_b_detour,
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
        route_a: RENDER_ROUTE_HOOK_A.predecessor_address()?,
        route_b: RENDER_ROUTE_HOOK_B.predecessor_address()?,
        first_person_special: FIRST_PERSON_HOOK_SPECIAL.predecessor_address()?,
        first_person_a: FIRST_PERSON_HOOK_A.predecessor_address()?,
        first_person_b: FIRST_PERSON_HOOK_B.predecessor_address()?,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&RENDER_ROUTE_HOOK_A)?;
    transaction.enable_callsite(&RENDER_ROUTE_HOOK_B)?;
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

unsafe extern "thiscall" fn render_route_a_detour(
    main: *mut c_void,
    render_target: u32,
    flags: u8,
) {
    let Ok(predecessor) = RENDER_ROUTE_HOOK_A.original() else {
        invalidate_render_token();
        return;
    };
    unsafe { render_route_body(predecessor, RenderRoute::A, main, render_target, flags) };
}

unsafe extern "thiscall" fn render_route_b_detour(
    main: *mut c_void,
    render_target: u32,
    flags: u8,
) {
    let Ok(predecessor) = RENDER_ROUTE_HOOK_B.original() else {
        invalidate_render_token();
        return;
    };
    unsafe { render_route_body(predecessor, RenderRoute::B, main, render_target, flags) };
}

unsafe fn render_route_body(
    predecessor: RenderRouteFn,
    route: RenderRoute,
    main: *mut c_void,
    render_target: u32,
    flags: u8,
) {
    let Some(_scope) = CallScope::enter(&RENDER_ROUTE_CALL_ACTIVE) else {
        // A nested route cannot safely consume the outer route's viewmodel
        // token. Keep all native rendering but fail the paired Atom pose closed.
        invalidate_render_token();
        unsafe { predecessor(main, render_target, flags) };
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
    unsafe { predecessor(main, render_target, flags) };
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
    let Ok(predecessor) = FIRST_PERSON_HOOK_SPECIAL.original() else {
        return;
    };
    unsafe { predecessor(main, renderer, geometry, sky_sun, rendered_texture) };
}

unsafe extern "thiscall" fn first_person_a_detour(
    main: *mut c_void,
    renderer: *mut c_void,
    geometry: *mut c_void,
    sky_sun: *mut c_void,
    rendered_texture: *mut c_void,
) {
    let Ok(predecessor) = FIRST_PERSON_HOOK_A.original() else {
        invalidate_render_token();
        return;
    };
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
    let Ok(predecessor) = FIRST_PERSON_HOOK_B.original() else {
        invalidate_render_token();
        return;
    };
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

#[cfg(test)]
mod tests {
    use super::{RenderFirstPersonFn, RenderRouteFn, render_route_a_detour, render_route_b_detour};

    #[test]
    fn detours_preserve_the_executable_proven_x86_abis() {
        let _: RenderRouteFn = render_route_a_detour;
        let _: RenderRouteFn = render_route_b_detour;
        let _: RenderFirstPersonFn = super::first_person_a_detour;
        let _: RenderFirstPersonFn = super::first_person_b_detour;
        let _: RenderFirstPersonFn = super::first_person_special_detour;
    }
}

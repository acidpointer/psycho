//! Deferred ownership of the native camera FOV writers.
//!
//! `BSSceneGraph::SetCameraFOV @ 0x00C52020` consumes the degree value produced
//! by `PlayerCharacter::UpdateCamera`, writes the live `SceneGraph+0xBC` scalar
//! and the world NiCamera frustum, and refreshes the `+0x110` FOV ratio. Native
//! 3D UI projection derives its matching compensation through `0x00B54000`.
//! Atom wraps both writers so one tangent ratio scales the rendered camera and
//! its UI compensation together. The separately rendered hands/weapon camera
//! copies the world frustum at `0x008752F2`; one direct-call owner applies the
//! independent viewmodel ratio there. A third-person render route guard and the
//! Pip-Boy/terminal callsites own the remaining presentation seams.
//!
//! Every wrapper is a bounded read-and-chain. A missing owner, invalid setting,
//! native special camera state, or native pass-through request calls the
//! captured predecessor with the original value. No wrapper allocates, blocks,
//! parses configuration, or retains an engine pointer.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::LazyLock;

use libpsycho::os::windows::hook::{
    callsite::{Rel32CallHookContainer, Rel32CallHookError},
    inline::{errors::InlineHookError, inlinehook::InlineHookContainer},
    transaction::ModificationTransaction,
};
use libpsycho::os::windows::winapi::get_tick_count;
use thiserror::Error;

use super::fov::{self, NativeFrustum, fov_scale, scale_fov_degrees, scale_frustum};
use super::native::{self, CameraPov, NativeRejection, PlayerFovField};
use crate::integrity;

const FIRST_PERSON_FRUSTUM_COPY: usize = 0x0087_52F2;
const THIRD_PERSON_ROUTE_CALL: usize = 0x0087_0730;
const PIPBOY_FOV_CALLS: [usize; 2] = [0x0095_8F91, 0x0095_C895];
const PIPBOY_OPEN_SETUP: usize = 0x007F_7F40;

type SetWorldFovFn = unsafe extern "thiscall" fn(*mut c_void, f32, u8, *mut c_void, u8);
type SetFovAspectFn = unsafe extern "cdecl" fn(f32);
type SetFrustumFn = unsafe extern "thiscall" fn(*mut c_void, *const NativeFrustum);
type ThirdPersonRouteFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32);
type PipBoyFovFn = unsafe extern "thiscall" fn(*mut c_void, f32) -> f32;
type PipBoyOpenSetupFn = unsafe extern "thiscall" fn(*mut c_void);

static SET_WORLD_FOV_HOOK: LazyLock<InlineHookContainer<SetWorldFovFn>> =
    LazyLock::new(InlineHookContainer::new);
static SET_FOV_ASPECT_HOOK: LazyLock<InlineHookContainer<SetFovAspectFn>> =
    LazyLock::new(InlineHookContainer::new);
static FIRST_PERSON_FRUSTUM_HOOK: Rel32CallHookContainer<SetFrustumFn> =
    Rel32CallHookContainer::new();
static THIRD_PERSON_ROUTE_HOOK: Rel32CallHookContainer<ThirdPersonRouteFn> =
    Rel32CallHookContainer::new();
static PIPBOY_FOV_HOOK_A: Rel32CallHookContainer<PipBoyFovFn> = Rel32CallHookContainer::new();
static PIPBOY_FOV_HOOK_B: Rel32CallHookContainer<PipBoyFovFn> = Rel32CallHookContainer::new();
static PIPBOY_OPEN_HOOK: LazyLock<InlineHookContainer<PipBoyOpenSetupFn>> =
    LazyLock::new(InlineHookContainer::new);
static WORLD_FOV_ACTIVE: AtomicBool = AtomicBool::new(false);
static FOV_TRACE_MASK: AtomicU32 = AtomicU32::new(0);
// Last coherent player POV. Menus and transitions do not expose a stable
// triplet, so the FOV owner holds this presentation instead of reverting.
static LAST_POV: AtomicU8 = AtomicU8::new(1);
// The native Pip-Boy setter writes its selected argument back into the shared
// FOV field. Retain the pre-selection value so disabling the feature or changing
// the target can leave the field in native state instead of pinning the old
// target.
static PIPBOY_ACTIVE: AtomicBool = AtomicBool::new(false);
static PIPBOY_CALL_ACTIVE: AtomicBool = AtomicBool::new(false);
static PIPBOY_LAST_NATIVE: AtomicU32 = AtomicU32::new(0);
static PIPBOY_LAST_SELECTED: AtomicU32 = AtomicU32::new(0);
// The manager byte clears after scheduling the visual close. Keep the Pip-Boy
// lens for the same bounded return interval Atom already uses for native
// camera reacquisition after this edge.
const PIPBOY_CLOSE_TAIL_MILLIS: u32 = 150;
const PIPBOY_OPEN_TAIL_MILLIS: u32 = 150;
static PIPBOY_LATCH_WAS_ACTIVE: AtomicBool = AtomicBool::new(false);
static PIPBOY_CLOSE_TAIL_ACTIVE: AtomicBool = AtomicBool::new(false);
static PIPBOY_CLOSE_UNTIL: AtomicU32 = AtomicU32::new(0);
static PIPBOY_OPEN_TAIL_ACTIVE: AtomicBool = AtomicBool::new(false);
static PIPBOY_OPEN_UNTIL: AtomicU32 = AtomicU32::new(0);
// Tracks entry into an authored special/VATS/death camera so the first normal
// writer after it can be identified in bounded diagnostics.
static SPECIAL_CAMERA_WAS_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Failure to admit Atom's native FOV writers.
#[derive(Debug, Error)]
pub(crate) enum FovHookError {
    #[error(transparent)]
    Native(#[from] native::NativeContractError),
    #[error(transparent)]
    Inline(#[from] InlineHookError),
    #[error(transparent)]
    Callsite(#[from] Rel32CallHookError),
    #[error("world camera FOV owners are inactive")]
    WorldFovInactive,
}

/// Captured predecessors for startup diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FovHookStatus {
    pub(super) world_setter: usize,
    pub(super) fov_aspect: usize,
}

/// Install both world-camera FOV writers as one rollback-capable capability.
///
/// They must be admitted together: scaling the camera without the matching 3D
/// UI compensation would make native projection disagree with the rendered
/// frustum.
pub(super) fn install_native_system() -> Result<FovHookStatus, FovHookError> {
    native::validate_fov_contract()?;
    unsafe {
        SET_WORLD_FOV_HOOK.init(
            "Atom world camera FOV",
            native::SET_WORLD_FOV as *mut c_void,
            set_world_fov_detour,
        )?;
        SET_FOV_ASPECT_HOOK.init(
            "Atom FOV aspect compensation",
            native::SET_FOV_ASPECT as *mut c_void,
            set_fov_aspect_detour,
        )?;
    }
    let status = FovHookStatus {
        world_setter: SET_WORLD_FOV_HOOK.original()? as usize,
        fov_aspect: SET_FOV_ASPECT_HOOK.original()? as usize,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&SET_WORLD_FOV_HOOK)?;
    transaction.enable_inline(&SET_FOV_ASPECT_HOOK)?;
    transaction.commit();
    WORLD_FOV_ACTIVE.store(true, Ordering::Release);
    integrity::register_inline("Atom world camera FOV", &SET_WORLD_FOV_HOOK);
    integrity::register_inline("Atom FOV aspect compensation", &SET_FOV_ASPECT_HOOK);
    Ok(status)
}

/// Install the direct-call owner for the viewmodel frustum copy.
///
/// This runs at the first post-Deferred main-loop boundary with the rest of the
/// first-person render group. Failure leaves world FOV and every other Atom
/// camera capability active while the viewmodel retains its native FOV.
pub(super) fn install_viewmodel_frustum(world_fov_active: bool) -> Result<usize, FovHookError> {
    if !world_fov_active {
        return Err(FovHookError::WorldFovInactive);
    }
    unsafe {
        FIRST_PERSON_FRUSTUM_HOOK.init(
            "Atom viewmodel FOV frustum",
            FIRST_PERSON_FRUSTUM_COPY as *mut c_void,
            viewmodel_frustum_detour,
        )?;
    }
    let predecessor = FIRST_PERSON_FRUSTUM_HOOK.predecessor_address()?;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&FIRST_PERSON_FRUSTUM_HOOK)?;
    transaction.commit();
    Ok(predecessor)
}

/// Return whether both world-camera FOV writers are active.
pub(super) fn world_fov_active() -> bool {
    WORLD_FOV_ACTIVE.load(Ordering::Acquire)
}

/// Clear one-shot FOV trace latches after a configuration publication.
pub(super) fn reset_trace() {
    FOV_TRACE_MASK.store(0, Ordering::Release);
    native::reset_fov_bases();
    LAST_POV.store(1, Ordering::Release);
    SPECIAL_CAMERA_WAS_ACTIVE.store(false, Ordering::Release);
    if !unsafe { native::pipboy_presentation_active() }
        && !PIPBOY_OPEN_TAIL_ACTIVE.load(Ordering::Acquire)
        && !PIPBOY_CLOSE_TAIL_ACTIVE.load(Ordering::Acquire)
    {
        PIPBOY_LATCH_WAS_ACTIVE.store(false, Ordering::Release);
    }
}

/// Return whether the Pip-Boy lens owns the current frame.
///
/// The native latch covers open and the close function itself. The manager
/// byte is cleared after the close animation is scheduled, so a bounded tail
/// covers the visible return without leaving Pip-Boy FOV active in gameplay.
fn pipboy_fov_presentation_active() -> bool {
    let active = unsafe { native::pipboy_presentation_active() };
    if active {
        PIPBOY_OPEN_TAIL_ACTIVE.store(false, Ordering::Release);
        PIPBOY_OPEN_UNTIL.store(0, Ordering::Release);
        PIPBOY_LATCH_WAS_ACTIVE.store(true, Ordering::Release);
        PIPBOY_CLOSE_TAIL_ACTIVE.store(false, Ordering::Release);
        PIPBOY_CLOSE_UNTIL.store(0, Ordering::Release);
        return true;
    }
    if PIPBOY_OPEN_TAIL_ACTIVE.load(Ordering::Acquire) {
        let until = PIPBOY_OPEN_UNTIL.load(Ordering::Acquire);
        if (get_tick_count().wrapping_sub(until) as i32) < 0 {
            return true;
        }
        PIPBOY_OPEN_TAIL_ACTIVE.store(false, Ordering::Release);
        PIPBOY_OPEN_UNTIL.store(0, Ordering::Release);
    }
    if PIPBOY_LATCH_WAS_ACTIVE.swap(false, Ordering::AcqRel) {
        let until = get_tick_count().wrapping_add(PIPBOY_CLOSE_TAIL_MILLIS);
        PIPBOY_CLOSE_UNTIL.store(until, Ordering::Release);
        PIPBOY_CLOSE_TAIL_ACTIVE.store(true, Ordering::Release);
        trace_once(
            TRACE_PIPBOY_CLOSE_LATCH,
            format_args!(
                "[CAMERA_FOV] Pip-Boy close latch engaged: tail={:.2}s",
                f64::from(PIPBOY_CLOSE_TAIL_MILLIS) / 1000.0
            ),
        );
        return true;
    }
    if !PIPBOY_CLOSE_TAIL_ACTIVE.load(Ordering::Acquire) {
        return false;
    }
    let until = PIPBOY_CLOSE_UNTIL.load(Ordering::Acquire);
    let now = get_tick_count();
    if (now.wrapping_sub(until) as i32) < 0 {
        true
    } else {
        PIPBOY_CLOSE_TAIL_ACTIVE.store(false, Ordering::Release);
        PIPBOY_CLOSE_UNTIL.store(0, Ordering::Release);
        false
    }
}

/// Install the render-route fallback used by the normal third-person world
/// draw.
///
/// This route is separate from Atom's first-person world callsites. The guard
/// compares the live scene graph FOV with the expected third-person value and
/// is an exact no-op when the native writer wrappers already applied it.
pub(super) fn install_third_person_route() -> Result<usize, FovHookError> {
    unsafe {
        THIRD_PERSON_ROUTE_HOOK.init(
            "Atom third-person FOV render route",
            THIRD_PERSON_ROUTE_CALL as *mut c_void,
            third_person_route_detour,
        )?;
    }
    let predecessor = THIRD_PERSON_ROUTE_HOOK.predecessor_address()?;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&THIRD_PERSON_ROUTE_HOOK)?;
    transaction.commit();
    Ok(predecessor)
}

/// Install the Pip-Boy/terminal FOV argument owners.
///
/// These are the two proven `PlayerCharacter::SetPipBoyFOV` callers. Owning the
/// argument here is precise: the shared `+0x65C` field is also used by
/// temporary gameplay FOVs, so a field-wide rule would corrupt scopes.
pub(super) fn install_pipboy_fov() -> Result<(usize, usize), FovHookError> {
    unsafe {
        PIPBOY_FOV_HOOK_A.init(
            "Atom Pip-Boy FOV A",
            PIPBOY_FOV_CALLS[0] as *mut c_void,
            pipboy_fov_detour_a,
        )?;
        PIPBOY_FOV_HOOK_B.init(
            "Atom Pip-Boy FOV B",
            PIPBOY_FOV_CALLS[1] as *mut c_void,
            pipboy_fov_detour_b,
        )?;
    }
    let predecessors = (
        PIPBOY_FOV_HOOK_A.predecessor_address()?,
        PIPBOY_FOV_HOOK_B.predecessor_address()?,
    );
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&PIPBOY_FOV_HOOK_A)?;
    transaction.enable_callsite(&PIPBOY_FOV_HOOK_B)?;
    transaction.commit();
    Ok(predecessors)
}

/// Install the pre-open latch at the start of the Pip-Boy animation setup.
///
/// `0x7F7F40` runs before `0x011DB378` is set at `0x7F8065`. Without this
/// leading edge the first open-animation frames still use the native FOV.
pub(super) fn install_pipboy_open_setup() -> Result<usize, FovHookError> {
    unsafe {
        PIPBOY_OPEN_HOOK.init(
            "Atom Pip-Boy open setup",
            PIPBOY_OPEN_SETUP as *mut c_void,
            pipboy_open_setup_detour,
        )?;
    }
    let predecessor = PIPBOY_OPEN_HOOK.original()? as usize;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&PIPBOY_OPEN_HOOK)?;
    transaction.commit();
    integrity::register_inline("Atom Pip-Boy open setup", &PIPBOY_OPEN_HOOK);
    Ok(predecessor)
}

unsafe extern "thiscall" fn set_world_fov_detour(
    scene_graph: *mut c_void,
    fov: f32,
    second: u8,
    camera: *mut c_void,
    fourth: u8,
) {
    let Ok(predecessor) = SET_WORLD_FOV_HOOK.original() else {
        return;
    };
    if !fov::configured() {
        unsafe { predecessor(scene_graph, fov, second, camera, fourth) };
        return;
    }
    // The dedicated Pip-Boy latch owns its target. Other menus do not inherit
    // it; they use the active POV target through the world scaling path below.
    if pipboy_fov_presentation_active() {
        let target = fov::current_config().pipboy();
        let fov = scaled_menu_pipboy_fov(fov);
        unsafe { predecessor(scene_graph, fov, second, camera, fourth) };
        trace_pipboy_lens(TRACE_PIPBOY_LENS, target);
        return;
    }
    if PIPBOY_CALL_ACTIVE.load(Ordering::Acquire) {
        unsafe { predecessor(scene_graph, fov, second, camera, fourth) };
        return;
    }
    let world_target = camera.is_null() || unsafe { native::world_camera() } == Some(camera);
    let reapply = world_target
        && second != 0
        && unsafe { native::scene_graph_fov(scene_graph) }
            .is_some_and(|current| current.to_bits() == fov.to_bits());
    let fov = if world_target && unsafe { native::is_world_scene_graph(scene_graph) } {
        if reapply {
            scaled_world_fov_reapply(fov)
        } else {
            scaled_world_fov(fov)
        }
    } else {
        fov
    };
    unsafe { predecessor(scene_graph, fov, second, camera, fourth) };
}

unsafe extern "cdecl" fn set_fov_aspect_detour(fov: f32) {
    let Ok(predecessor) = SET_FOV_ASPECT_HOOK.original() else {
        return;
    };
    if !fov::configured() {
        unsafe { predecessor(fov) };
        return;
    }
    if pipboy_fov_presentation_active() {
        unsafe { predecessor(scaled_menu_pipboy_fov(fov)) };
        return;
    }
    if PIPBOY_CALL_ACTIVE.load(Ordering::Acquire) {
        unsafe { predecessor(fov) };
        return;
    }
    unsafe { predecessor(scaled_world_fov(fov)) };
}

unsafe extern "thiscall" fn pipboy_fov_detour_a(player: *mut c_void, fov: f32) -> f32 {
    let Ok(predecessor) = PIPBOY_FOV_HOOK_A.original() else {
        return fov;
    };
    PIPBOY_CALL_ACTIVE.store(true, Ordering::Release);
    let result = unsafe { predecessor(player, scaled_pipboy_fov(fov)) };
    PIPBOY_CALL_ACTIVE.store(false, Ordering::Release);
    result
}

unsafe extern "thiscall" fn pipboy_open_setup_detour(player: *mut c_void) {
    let Ok(predecessor) = PIPBOY_OPEN_HOOK.original() else {
        return;
    };
    PIPBOY_OPEN_UNTIL.store(
        get_tick_count().wrapping_add(PIPBOY_OPEN_TAIL_MILLIS),
        Ordering::Release,
    );
    PIPBOY_OPEN_TAIL_ACTIVE.store(true, Ordering::Release);
    trace_once(
        TRACE_PIPBOY_OPEN_LATCH,
        format_args!(
            "[CAMERA_FOV] Pip-Boy open latch engaged: tail={:.2}s",
            f64::from(PIPBOY_OPEN_TAIL_MILLIS) / 1000.0
        ),
    );
    let target = fov::current_config().pipboy();
    if target != 0.0 {
        let _ = set_world_fov_absolute(target);
        trace_pipboy_lens(TRACE_PIPBOY_OPEN_LENS, target);
    }
    unsafe { predecessor(player) };
}

unsafe extern "thiscall" fn pipboy_fov_detour_b(player: *mut c_void, fov: f32) -> f32 {
    let Ok(predecessor) = PIPBOY_FOV_HOOK_B.original() else {
        return fov;
    };
    PIPBOY_CALL_ACTIVE.store(true, Ordering::Release);
    let result = unsafe { predecessor(player, scaled_pipboy_fov(fov)) };
    PIPBOY_CALL_ACTIVE.store(false, Ordering::Release);
    result
}

unsafe extern "thiscall" fn third_person_route_detour(
    main: *mut c_void,
    first: *mut c_void,
    second: u32,
) {
    let Ok(predecessor) = THIRD_PERSON_ROUTE_HOOK.original() else {
        return;
    };
    let guard = unsafe { enforce_render_fov() };
    unsafe { predecessor(main, first, second) };
    drop(guard);
}

unsafe extern "thiscall" fn viewmodel_frustum_detour(
    camera: *mut c_void,
    source: *const NativeFrustum,
) {
    let Ok(predecessor) = FIRST_PERSON_FRUSTUM_HOOK.original() else {
        return;
    };
    let first_person_camera = unsafe { native::first_person_camera() };
    let Some(scale) = viewmodel_scale() else {
        unsafe { predecessor(camera, source) };
        return;
    };
    if first_person_camera != Some(camera) || source.is_null() || scale == 1.0 {
        unsafe { predecessor(camera, source) };
        return;
    }
    let Some(scaled) = scale_frustum(unsafe { read_frustum(source) }, scale) else {
        unsafe { predecessor(camera, source) };
        return;
    };
    unsafe { predecessor(camera, &scaled) };
}

/// Read only the native `NiFrustum` prefix consumed by `0x00A6FAF0`.
///
/// The trailing three bytes are not part of the field setter's contract. Keep
/// them explicit and zeroed instead of copying arbitrary adjacent camera data.
unsafe fn read_frustum(source: *const NativeFrustum) -> NativeFrustum {
    let base = source.cast::<u8>();
    let read_f32 = |offset: usize| unsafe { base.add(offset).cast::<f32>().read_unaligned() };
    NativeFrustum {
        left: read_f32(0x00),
        right: read_f32(0x04),
        top: read_f32(0x08),
        bottom: read_f32(0x0C),
        near: read_f32(0x10),
        far: read_f32(0x14),
        orthographic: unsafe { base.add(0x18).read() },
        reserved: [0; 3],
    }
}

/// How the current presentation consumes the configured world FOV.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorldFovMode {
    /// Normal gameplay: preserve the live field's native relative zoom.
    Relative(CameraPov, u32),
    /// Authored camera: apply the player's ratio without replacing its angle.
    Special(CameraPov, u32),
    /// Menu or POV transition: force the last coherent target.
    Absolute(u32),
    /// No owned presentation.
    Native,
}

fn remember_pov(pov: CameraPov) {
    LAST_POV.store(
        match pov {
            CameraPov::First => 1,
            CameraPov::Third => 2,
        },
        Ordering::Release,
    );
}

fn last_pov() -> CameraPov {
    if LAST_POV.load(Ordering::Acquire) == 2 {
        CameraPov::Third
    } else {
        CameraPov::First
    }
}

fn target_bits(target: f32) -> u32 {
    target.to_bits()
}

fn target_value(bits: u32) -> f32 {
    f32::from_bits(bits)
}

/// Learn one native hip-fire field value and report the first stable update.
fn observe_base(field: PlayerFovField, value: f32) {
    let before = native::observed_fov_base(field);
    native::observe_fov_base(field, value);
    let after = native::observed_fov_base(field);
    if after > before {
        let mask = match field {
            PlayerFovField::World => TRACE_BASE_WORLD,
            PlayerFovField::FirstPerson => TRACE_BASE_FIRST,
            PlayerFovField::OverShoulder => TRACE_BASE_SHOULDER,
            PlayerFovField::Other => return,
        };
        trace_once(
            mask,
            format_args!(
                "[CAMERA_FOV] Hip-fire base observed: field={field:?} value={after:.2} previous={before:.2}"
            ),
        );
    }
}

fn world_fov_mode() -> WorldFovMode {
    let Some(player) = (unsafe { native::player() }) else {
        return WorldFovMode::Native;
    };
    let config = fov::current_config();
    match unsafe { native::fov_owner_pov(player) } {
        Ok(pov) => {
            remember_pov(pov);
            let target = config.world_target(pov == CameraPov::First);
            if SPECIAL_CAMERA_WAS_ACTIVE.swap(false, Ordering::AcqRel) {
                trace_once(
                    TRACE_SPECIAL_EXIT,
                    format_args!(
                        "[CAMERA_FOV] Special camera exited; normal lens resumes: pov={pov:?} target={target:.2}"
                    ),
                );
                if target != 0.0 {
                    // The authored camera may have left the scene graph at its
                    // own angle and the aspect owner at a different one. Force
                    // the configured hip-fire lens for the first post-scene
                    // frame; the next normal writer refines any ADS angle.
                    let _ = set_world_fov_absolute(target);
                }
            }
            if target == 0.0 {
                WorldFovMode::Native
            } else {
                WorldFovMode::Relative(pov, target_bits(target))
            }
        }
        Err(NativeRejection::Menu) => {
            // Menus may keep a coherent POV triplet. Prefer the live byte
            // state; fall back to the last coherent POV during loading/main
            // menu frames where the triplet is not usable.
            let pov = unsafe { native::current_pov() }.unwrap_or_else(last_pov);
            remember_pov(pov);
            let target = config.world_target(pov == CameraPov::First);
            if target == 0.0 {
                WorldFovMode::Native
            } else {
                WorldFovMode::Absolute(target_bits(target))
            }
        }
        Err(NativeRejection::PovTransitionA) | Err(NativeRejection::PovTransitionB) => {
            let pov = last_pov();
            let target = config.world_target(pov == CameraPov::First);
            if target == 0.0 {
                WorldFovMode::Native
            } else {
                WorldFovMode::Absolute(target_bits(target))
            }
        }
        Err(NativeRejection::Vats) => special_fov_mode(config, "vats", TRACE_SPECIAL_VATS),
        Err(NativeRejection::SpecialCamera) => {
            special_fov_mode(config, "special", TRACE_SPECIAL_SPECIAL)
        }
        Err(NativeRejection::FlyCamera) => special_fov_mode(config, "fly", TRACE_SPECIAL_FLY),
        Err(NativeRejection::Dead) => special_fov_mode(config, "dead", TRACE_SPECIAL_DEAD),
        Err(_) => WorldFovMode::Native,
    }
}

/// Keep an authored camera's angle while applying the player's relative lens.
fn special_fov_mode(config: fov::CameraFovConfig, label: &'static str, mask: u32) -> WorldFovMode {
    SPECIAL_CAMERA_WAS_ACTIVE.store(true, Ordering::Release);
    let pov = last_pov();
    let target = config.world_target(pov == CameraPov::First);
    if target == 0.0 {
        return WorldFovMode::Native;
    }
    trace_once(
        mask,
        format_args!(
            "[CAMERA_FOV] Special camera FOV policy: kind={label} pov={pov:?} target={target:.2} (relative scale on the authored angle)"
        ),
    );
    WorldFovMode::Special(pov, target_bits(target))
}

/// Apply the active mode's base-FOV ratio to one live native angle.
fn scaled_world_fov(fov: f32) -> f32 {
    match world_fov_mode() {
        WorldFovMode::Native => fov,
        WorldFovMode::Absolute(bits) => {
            let target = target_value(bits);
            trace_once(
                TRACE_SETTER_ABSOLUTE,
                format_args!(
                    "[CAMERA_FOV] Menu/transition FOV forced: live={fov:.2} target={target:.2}"
                ),
            );
            target
        }
        WorldFovMode::Relative(pov, bits) => {
            scale_field_world_fov(fov, pov, target_value(bits), true)
        }
        WorldFovMode::Special(pov, bits) => {
            scale_field_world_fov(fov, pov, target_value(bits), false)
        }
    }
}

/// Scale one native writer argument by the owning field's stable base.
///
/// Normal gameplay learns the hip-fire value; an authored special camera keeps
/// its angle but still receives the player's relative lens ratio.
fn scale_field_world_fov(fov: f32, pov: CameraPov, target: f32, observe: bool) -> f32 {
    let field = unsafe { native::player_fov_field(pov, fov) };
    if observe {
        observe_base(field, fov);
    }
    let Some(base) = (unsafe { native::base_fov_for_field(pov, field) }) else {
        return fov;
    };
    let Some(scale) = fov_scale(target, base) else {
        return fov;
    };
    let scaled = scale_fov_degrees(fov, scale).unwrap_or(fov);
    trace_once(
        if pov == CameraPov::First {
            TRACE_SETTER_FIRST
        } else {
            TRACE_SETTER_THIRD
        },
        format_args!(
            "[CAMERA_FOV] {pov:?} writer applied: field={field:?} live={fov:.2} base={base:.2} target={target:.2} result={scaled:.2}"
        ),
    );
    scaled
}

/// Resolve a force-flagged re-application of the scene graph's own scalar.
///
/// Re-application is idempotent for an unchanged target, but a changed target
/// or a disable request must not be skipped. The current scalar is the base, so
/// a target change maps directly to the new angle; disabling restores the live
/// player field.
fn scaled_world_fov_reapply(fov: f32) -> f32 {
    match world_fov_mode() {
        WorldFovMode::Native => {
            let pov = unsafe { native::player() }
                .and_then(|player| unsafe { native::fov_owner_pov(player) }.ok())
                .unwrap_or_else(last_pov);
            unsafe { native::player_fov(pov) }.unwrap_or(fov)
        }
        WorldFovMode::Absolute(bits) => target_value(bits),
        WorldFovMode::Relative(_, bits) => reapply_world_fov(fov, target_value(bits), None),
        // A special camera's force-flagged scalar is already authored or already
        // carries the player's ratio. Replacing it with the world target here
        // would destroy VATS/kill-camera framing and can double-scale after the
        // scene. The next normal writer restores the configured lens.
        WorldFovMode::Special(_, _) => fov,
    }
}

fn reapply_world_fov(fov: f32, target: f32, native: Option<f32>) -> f32 {
    if target == 0.0 {
        return native.filter(|value| value.is_finite()).unwrap_or(fov);
    }
    fov_scale(target, fov)
        .and_then(|scale| scale_fov_degrees(fov, scale))
        .unwrap_or(fov)
}

/// Report the world and first-person camera lens after a Pip-Boy ownership
/// write. This distinguishes an incomplete scalar write from a separate screen
/// camera that does not consume the world lens.
fn trace_pipboy_lens(mask: u32, target: f32) {
    trace_once(
        mask,
        format_args!(
            "[CAMERA_FOV] Pip-Boy lens: world={:.2} first_camera={:.2} target={target:.2}",
            unsafe { native::world_scene_graph() }
                .and_then(|scene_graph| unsafe { native::scene_graph_fov(scene_graph) })
                .unwrap_or(f32::NAN),
            unsafe { native::first_person_camera() }
                .and_then(camera_vertical_fov)
                .unwrap_or(f32::NAN),
        ),
    );
}

fn camera_vertical_fov(camera: *mut c_void) -> Option<f32> {
    let frustum = unsafe { native::read_frustum(camera) }?;
    frustum_vertical_fov(&frustum)
}

fn frustum_vertical_fov(frustum: &NativeFrustum) -> Option<f32> {
    if frustum.orthographic != 0 {
        return None;
    }
    let half = (frustum.top - frustum.bottom) * 0.5;
    (half > 0.0).then(|| (half.atan() * 2.0).to_degrees())
}

/// Apply the Pip-Boy target to the camera fields used by the Pip-Boy open and
/// close animation.
///
/// The caller has already admitted the native presentation latch or its
/// bounded close tail, so any finite live angle belongs to that camera.
fn scaled_menu_pipboy_fov(fov: f32) -> f32 {
    let config = fov::current_config();
    let target = config.pipboy();
    if target == 0.0 {
        return fov;
    }
    if let Some(fields) = unsafe { native::fov_fields() } {
        trace_once(
            TRACE_PIPBOY_OBSERVE,
            format_args!(
                "[CAMERA_FOV] Menu FOV observed: call={fov:.2} pipboy_field={:.2} first_field={:.2} world_field={:.2} shoulder_field={:.2} target={target:.2}",
                fields[0], fields[1], fields[2], fields[3]
            ),
        );
    }
    let Some(scale) = fov_scale(target, fov) else {
        return fov;
    };
    let scaled = scale_fov_degrees(fov, scale).unwrap_or(fov);
    let closing = !unsafe { native::menu_open() };
    trace_once(
        if closing {
            TRACE_PIPBOY_CLOSE
        } else {
            TRACE_PIPBOY_MENU
        },
        format_args!(
            "[CAMERA_FOV] Pip-Boy {} FOV applied: native={fov:.2} target={target:.2} result={scaled:.2}",
            if closing { "close" } else { "menu" }
        ),
    );
    scaled
}

/// Scale the argument of one proven Pip-Boy/terminal camera call.
///
/// The callsite itself identifies the owner, so no menu-wide field heuristic is
/// needed. The native setter writes the selected value back into the shared
/// field; the retained pre-selection value makes target changes and disabling
/// the feature return to native instead of pinning the previous target.
fn scaled_pipboy_fov(fov: f32) -> f32 {
    let config = fov::current_config();
    let active = PIPBOY_ACTIVE.load(Ordering::Acquire);
    let last_native = f32::from_bits(PIPBOY_LAST_NATIVE.load(Ordering::Acquire));
    let last_selected = f32::from_bits(PIPBOY_LAST_SELECTED.load(Ordering::Acquire));
    let selection = select_pipboy_fov(config.pipboy(), fov, active, last_native, last_selected);
    PIPBOY_LAST_NATIVE.store(selection.native.to_bits(), Ordering::Release);
    PIPBOY_LAST_SELECTED.store(selection.selected.to_bits(), Ordering::Release);
    PIPBOY_ACTIVE.store(selection.active, Ordering::Release);
    if selection.active && selection.selected.to_bits() != fov.to_bits() {
        trace_once(
            TRACE_PIPBOY,
            format_args!(
                "[CAMERA_FOV] Pip-Boy FOV applied: native={:.2} target={:.2} result={:.2}",
                selection.native,
                config.pipboy(),
                selection.selected
            ),
        );
    }
    selection.selected
}

/// Pure Pip-Boy selection state.
///
/// `selected` is what the native setter should store; `native` retains the
/// pre-selection value used to restore or rebase a later call.
#[derive(Clone, Copy, Debug, PartialEq)]
struct PipBoySelection {
    selected: f32,
    native: f32,
    active: bool,
}

fn select_pipboy_fov(
    target: f32,
    fov: f32,
    active: bool,
    last_native: f32,
    last_selected: f32,
) -> PipBoySelection {
    let current_is_selected =
        active && last_selected.is_finite() && fov.to_bits() == last_selected.to_bits();
    if target == 0.0 {
        let selected = if current_is_selected && last_native.is_finite() {
            last_native
        } else {
            fov
        };
        return PipBoySelection {
            selected,
            native: last_native,
            active: false,
        };
    }
    let base = if current_is_selected && last_native.is_finite() {
        last_native
    } else {
        fov
    };
    let selected = fov_scale(target, base)
        .and_then(|scale| scale_fov_degrees(base, scale))
        .unwrap_or(fov);
    PipBoySelection {
        selected,
        native: base,
        active: selected.to_bits() != fov.to_bits() || active,
    }
}

/// Render-scoped third-person FOV correction for the normal world route.
///
/// The native writer wrappers already scale the scene graph FOV. This guard is
/// an idempotent safety net for the separate third-person route: it compares
/// the live scene graph scalar with the expected value for the player's current
/// third-person base and only writes when they differ. A no-op leaves the
/// native writer's exact state untouched.
pub(super) unsafe fn enforce_render_fov() -> Option<WorldFovGuard> {
    if pipboy_fov_presentation_active() {
        let target = fov::current_config().pipboy();
        if target == 0.0 {
            return None;
        }
        return apply_world_fov(target, true);
    }
    match world_fov_mode() {
        WorldFovMode::Native | WorldFovMode::Special(_, _) => None,
        WorldFovMode::Absolute(bits) => apply_world_fov(target_value(bits), true),
        WorldFovMode::Relative(pov, bits) => {
            let target = target_value(bits);
            let live = unsafe { native::player_fov(pov) }?;
            let field = match pov {
                CameraPov::First => native::PlayerFovField::World,
                CameraPov::Third => native::PlayerFovField::OverShoulder,
            };
            observe_base(field, live);
            let base = unsafe { native::base_fov_for_field(pov, field) }?;
            let expected = scale_fov_degrees(live, fov_scale(target, base)?)?;
            apply_world_fov(expected, false)
        }
    }
}

fn apply_world_fov(expected: f32, absolute: bool) -> Option<WorldFovGuard> {
    let scene_graph = unsafe { native::world_scene_graph() }?;
    let camera = unsafe { native::world_camera() }?;
    let current = unsafe { native::scene_graph_fov(scene_graph) }?;
    if (current - expected).abs() <= 0.01 {
        return None;
    }
    let original = unsafe { native::read_frustum(camera) }?;
    let current_half = current.to_radians() * 0.5;
    let ratio = (expected.to_radians() * 0.5).tan() / current_half.tan();
    let scaled = scale_frustum(original, ratio)?;
    unsafe {
        native::write_frustum_extents(camera, scaled);
        native::write_scene_graph_fov(scene_graph, expected);
    }
    trace_once(
        if absolute {
            TRACE_RENDER_ABSOLUTE
        } else {
            TRACE_RENDER_RELATIVE
        },
        format_args!(
            "[CAMERA_FOV] Render FOV enforced: mode={} native={current:.2} expected={expected:.2}",
            if absolute { "absolute" } else { "relative" }
        ),
    );
    Some(WorldFovGuard {
        scene_graph,
        camera,
        original,
        original_fov: current,
    })
}

/// Persistently apply one absolute FOV at a presentation transition.
///
/// Used by the Pip-Boy open setup so the first rendered animation frame already
/// has the selected lens, before the next camera update or render guard runs.
fn set_world_fov_absolute(target: f32) -> bool {
    if target == 0.0 {
        return false;
    }
    let Some(scene_graph) = (unsafe { native::world_scene_graph() }) else {
        return false;
    };
    if unsafe { native::world_camera() }.is_none() {
        return false;
    }
    // Prefer the captured native setter: it also refreshes `+0x110` and the
    // frustum with the engine's exact aspect/clamp behavior.
    if let Ok(setter) = SET_WORLD_FOV_HOOK.original() {
        unsafe { setter(scene_graph, target, 0, core::ptr::null_mut(), 0) };
        if let Ok(aspect) = SET_FOV_ASPECT_HOOK.original() {
            unsafe { aspect(target) };
        }
        return true;
    }
    let Some(camera) = (unsafe { native::world_camera() }) else {
        return false;
    };
    let Some(current) = (unsafe { native::scene_graph_fov(scene_graph) }) else {
        return false;
    };
    if (current - target).abs() <= 0.01 {
        return true;
    }
    let Some(original) = (unsafe { native::read_frustum(camera) }) else {
        return false;
    };
    let current_half = current.to_radians() * 0.5;
    let ratio = (target.to_radians() * 0.5).tan() / current_half.tan();
    let Some(scaled) = scale_frustum(original, ratio) else {
        return false;
    };
    unsafe {
        native::write_frustum_extents(camera, scaled);
        native::write_scene_graph_fov(scene_graph, target);
    }
    if let Ok(aspect) = SET_FOV_ASPECT_HOOK.original() {
        unsafe { aspect(target) };
    }
    true
}

/// Restore the exact scene graph FOV and angular extents after one route.
#[must_use = "dropping the guard restores the scene graph FOV"]
pub(super) struct WorldFovGuard {
    scene_graph: *mut c_void,
    camera: *mut c_void,
    original: NativeFrustum,
    original_fov: f32,
}

impl Drop for WorldFovGuard {
    fn drop(&mut self) {
        unsafe {
            native::write_frustum_extents(self.camera, self.original);
            native::write_scene_graph_fov(self.scene_graph, self.original_fov);
        }
    }
}

const TRACE_RENDER_ABSOLUTE: u32 = 1 << 0;
const TRACE_PIPBOY: u32 = 1 << 1;
const TRACE_SETTER_FIRST: u32 = 1 << 2;
const TRACE_SETTER_THIRD: u32 = 1 << 3;
const TRACE_RENDER_RELATIVE: u32 = 1 << 4;
const TRACE_PIPBOY_MENU: u32 = 1 << 5;
const TRACE_PIPBOY_CLOSE: u32 = 1 << 6;
const TRACE_PIPBOY_OBSERVE: u32 = 1 << 7;
const TRACE_PIPBOY_CLOSE_LATCH: u32 = 1 << 8;
const TRACE_PIPBOY_OPEN_LATCH: u32 = 1 << 9;
const TRACE_SETTER_ABSOLUTE: u32 = 1 << 10;
const TRACE_BASE_WORLD: u32 = 1 << 11;
const TRACE_BASE_FIRST: u32 = 1 << 12;
const TRACE_BASE_SHOULDER: u32 = 1 << 13;
const TRACE_SPECIAL_EXIT: u32 = 1 << 15;
const TRACE_PIPBOY_LENS: u32 = 1 << 16;
const TRACE_PIPBOY_OPEN_LENS: u32 = 1 << 17;
const TRACE_SPECIAL_VATS: u32 = 1 << 18;
const TRACE_SPECIAL_SPECIAL: u32 = 1 << 19;
const TRACE_SPECIAL_FLY: u32 = 1 << 20;
const TRACE_SPECIAL_DEAD: u32 = 1 << 21;

fn trace_once(mask: u32, message: core::fmt::Arguments<'_>) {
    if FOV_TRACE_MASK.fetch_or(mask, Ordering::AcqRel) & mask == 0 {
        log::info!("{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::{PipBoySelection, reapply_world_fov, select_pipboy_fov};

    fn selected(value: f32, native: f32, active: bool) -> PipBoySelection {
        PipBoySelection {
            selected: value,
            native,
            active,
        }
    }

    #[test]
    fn reapply_tracks_target_changes_and_restores_native() {
        // Already at the target.
        assert!((reapply_world_fov(90.0, 90.0, None) - 90.0).abs() < 1.0e-4);
        // Target changed from the current scalar.
        assert!((reapply_world_fov(90.0, 100.0, None) - 100.0).abs() < 1.0e-4);
        // Disable restores the live player field.
        assert_eq!(reapply_world_fov(100.0, 0.0, Some(55.0)), 55.0);
        // Missing native state falls back to the current scalar.
        assert_eq!(reapply_world_fov(100.0, 0.0, None), 100.0);
    }

    #[test]
    fn pipboy_selection_is_idempotent_and_rebases_target_changes() {
        let first = select_pipboy_fov(90.0, 75.0, false, 0.0, 0.0);
        assert_eq!(first.selected, 90.0);
        assert_eq!(first.native, 75.0);
        assert!(first.active);

        let repeat = select_pipboy_fov(90.0, 90.0, true, first.native, first.selected);
        assert_eq!(repeat, selected(90.0, 75.0, true));

        let changed = select_pipboy_fov(100.0, 90.0, true, repeat.native, repeat.selected);
        assert!((changed.selected - 100.0).abs() < 1.0e-4);
        assert_eq!(changed.native, 75.0);
        assert!(changed.active);
    }

    #[test]
    fn pipboy_disable_restores_the_pre_selection_value() {
        let disabled = select_pipboy_fov(0.0, 90.0, true, 75.0, 90.0);
        assert_eq!(disabled, selected(75.0, 75.0, false));

        // A native value written by the game after the feature was disabled is
        // preserved rather than replaced by a stale target.
        let native = select_pipboy_fov(0.0, 68.0, false, 75.0, 90.0);
        assert_eq!(native, selected(68.0, 75.0, false));
    }

    #[test]
    fn pipboy_target_is_absolute_from_the_native_value() {
        let selection = select_pipboy_fov(70.0, 55.0, false, 0.0, 0.0);
        assert!((selection.selected - 70.0).abs() < 1.0e-4);
        assert_eq!(selection.native, 55.0);
    }
}

/// Return the additional frustum ratio needed for the viewmodel camera.
///
/// The source frustum already includes the world first-person ratio when the
/// world writers are active. Dividing the absolute viewmodel tangent ratio by
/// that ratio leaves `1.0` (an exact pass-through) for `Viewmodel FOV = 0` and
/// yields the requested absolute base FOV otherwise.
fn viewmodel_scale() -> Option<f32> {
    if !fov::configured() || pipboy_fov_presentation_active() {
        return None;
    }
    let config = fov::current_config();
    let pov = unsafe { native::fov_pov() }.unwrap_or_else(last_pov);
    if pov != CameraPov::First {
        return None;
    }
    let base = unsafe { native::base_fov(CameraPov::First) }?;
    let first_scale = if world_fov_active() {
        fov_scale(config.first_person(), base)?
    } else {
        1.0
    };
    let viewmodel_scale = if config.viewmodel() == 0.0 {
        first_scale
    } else {
        fov_scale(config.viewmodel(), base)?
    };
    let additional = viewmodel_scale / first_scale;
    (additional.is_finite() && additional > 0.0).then_some(additional)
}

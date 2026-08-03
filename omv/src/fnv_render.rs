//! Native Fallout New Vegas render-stage boundaries used by OMV.
//!
//! World-scene entry establishes the destination shared-depth identity,
//! pre-alpha performs the provider-owned world capture, and post-world
//! publication marks externally produced depth as observable. Their
//! trampolines are prepared at DeferredInit, but the native entry jumps are
//! physically detached when neither OMV visuals nor the OMV shared-depth
//! service needs them. Render callbacks are nonblocking and never substitute
//! one provider for another. When the selected provider exposes world depth
//! but no first-person mask, AO is composed on the completed world target
//! immediately after `RenderWorldSceneGraph`; hands and weapons later
//! overwrite AO naturally without reactivating OMV depth capture.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::{Result, anyhow};
use libpsycho::ffi::fnptr::Function;
use libpsycho::os::windows::{directx9::Device9Ref, hook::inline::inlinehook::InlineHookContainer};

const PROCESS_IMAGE_SPACE_SHADERS_ADDR: usize = 0x00B55AC0;
const SET_WATER_SHADER_UNDERWATER_ADDR: usize = 0x004E2120;
const RENDER_WORLD_SCENE_GRAPH_ADDR: usize = 0x00873200;
const RENDER_FIRST_PERSON_ADDR: usize = 0x00875110;
const RENDER_PRE_DEPTH_GROUPS_ADDR: usize = 0x00B65AE0;
const IMAGE_SPACE_MANAGER_PTR_ADDR: usize = 0x011F91AC;
const IMAGE_SPACE_EFFECTS_OFFSET: usize = 0x08;
const IMAGE_SPACE_LAST_EFFECT_ID_OFFSET: usize = 0x1EC;
const IMAGE_SPACE_DOF_EFFECT_ID: usize = 4;
const IMAGE_SPACE_EFFECT_IS_ACTIVE_VTBL_OFFSET: usize = 0x18;
const WORLD_SCENE_GRAPH_PHASE: u8 = 0;

const MAX_HOOK_ERROR_LOGS: u32 = 8;
const MAX_DEPTH_CAPTURE_LOGS: u32 = 16;
const MAX_DEPTH_CAPTURE_SKIP_LOGS: u32 = 16;
const MAX_SHADER_APPLY_LOGS: u32 = 16;

type ProcessImageSpaceShadersFn = unsafe extern "cdecl" fn(*mut c_void, *mut c_void, *mut c_void);
type SetWaterShaderUnderwaterFn = unsafe extern "thiscall" fn(*mut c_void, u8);
type RenderWorldSceneGraphFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8, u8, u8);
type RenderFirstPersonFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void);
type RenderPreDepthGroupsFn = unsafe extern "cdecl" fn(*mut c_void);
type ImageSpaceEffectIsActiveFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;

static PROCESS_IMAGE_SPACE_SHADERS_HOOK: LazyLock<InlineHookContainer<ProcessImageSpaceShadersFn>> =
    LazyLock::new(InlineHookContainer::new);
static SET_WATER_SHADER_UNDERWATER_HOOK: LazyLock<InlineHookContainer<SetWaterShaderUnderwaterFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_WORLD_SCENE_GRAPH_HOOK: LazyLock<InlineHookContainer<RenderWorldSceneGraphFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_FIRST_PERSON_HOOK: LazyLock<InlineHookContainer<RenderFirstPersonFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_PRE_DEPTH_GROUPS_HOOK: LazyLock<InlineHookContainer<RenderPreDepthGroupsFn>> =
    LazyLock::new(InlineHookContainer::new);

static HOOK_ERROR_LOGS: AtomicU32 = AtomicU32::new(0);
static UNDERWATER_PUBLICATION_HOOK_READY: AtomicBool = AtomicBool::new(false);
static WORLD_SCENE_HOOK_READY: AtomicBool = AtomicBool::new(false);
static PRE_ALPHA_HOOK_READY: AtomicBool = AtomicBool::new(false);
static DEPTH_STAGE_HOOK_MASK: AtomicU8 = AtomicU8::new(0);
static DEPTH_CAPTURE_LOGS: AtomicU32 = AtomicU32::new(0);
static DEPTH_CAPTURE_SKIP_LOGS: AtomicU32 = AtomicU32::new(0);
static SHADER_APPLY_LOGS: AtomicU32 = AtomicU32::new(0);
static PRE_ALPHA_WORLD_TARGET: AtomicUsize = AtomicUsize::new(0);
static PRE_ALPHA_WORLD_ARMED: AtomicBool = AtomicBool::new(false);

/// Install every native scene boundary required by live provider switching.
pub(crate) fn install_scene_boundary_hook() {
    install_process_image_space_shaders_hook();
    install_set_water_shader_underwater_hook();
    install_render_world_scene_graph_hook();
    install_render_first_person_hook();
    install_render_pre_depth_groups_hook();
    publish_depth_stage_hook_states(depth_stage_hook_states());
}

/// Return whether native underwater classification can be published safely.
pub(crate) fn underwater_publication_hook_ready() -> bool {
    UNDERWATER_PUBLICATION_HOOK_READY.load(Ordering::Acquire)
}

/// Return whether both boundaries required by shared-depth service are prepared.
///
/// Prepared hooks retain callable trampolines while their native entry jumps
/// are detached, allowing a later Present-boundary switch to reattach them.
pub(crate) fn shared_depth_service_ready() -> bool {
    shared_depth_service_hooks_ready(
        WORLD_SCENE_HOOK_READY.load(Ordering::Acquire),
        PRE_ALPHA_HOOK_READY.load(Ordering::Acquire),
    )
}

fn shared_depth_service_hooks_ready(world_scene: bool, pre_alpha: bool) -> bool {
    world_scene && pre_alpha
}

#[derive(Clone, Copy)]
struct DepthStageHookStates {
    underwater: bool,
    world: bool,
    first_person: bool,
    pre_alpha: bool,
}

impl DepthStageHookStates {
    const ALL_MASK: u8 = 0b1111;

    fn all_active(self) -> bool {
        self.underwater && self.world && self.first_person && self.pre_alpha
    }

    fn mask(self) -> u8 {
        u8::from(self.underwater)
            | (u8::from(self.world) << 1)
            | (u8::from(self.first_person) << 2)
            | (u8::from(self.pre_alpha) << 3)
    }
}

fn depth_stage_hook_states() -> DepthStageHookStates {
    DepthStageHookStates {
        underwater: SET_WATER_SHADER_UNDERWATER_HOOK.is_enabled(),
        world: RENDER_WORLD_SCENE_GRAPH_HOOK.is_enabled(),
        first_person: RENDER_FIRST_PERSON_HOOK.is_enabled(),
        pre_alpha: RENDER_PRE_DEPTH_GROUPS_HOOK.is_enabled(),
    }
}

fn publish_depth_stage_hook_states(states: DepthStageHookStates) {
    DEPTH_STAGE_HOOK_MASK.store(states.mask(), Ordering::Release);
}

fn set_inline_hook_state<T: Function>(
    hook: &InlineHookContainer<T>,
    active: bool,
    label: &'static str,
) -> Result<()> {
    if hook.is_enabled() == active {
        return Ok(());
    }
    let result = if active {
        hook.enable()
    } else {
        hook.disable()
    };
    result.map_err(|err| {
        anyhow!(
            "{label} could not be {}: {err}",
            if active { "attached" } else { "detached" }
        )
    })
}

fn restore_depth_stage_hook_states(states: DepthStageHookStates) {
    // Best-effort rollback uses dependency order: restore metadata/pre-alpha
    // boundaries before the outer world wrapper when attaching, and restore
    // the outer wrapper first when detaching. Every failure is visible; a
    // partial executable patch state must never be silently reported ready.
    for result in [
        set_inline_hook_state(
            &SET_WATER_SHADER_UNDERWATER_HOOK,
            states.underwater,
            "underwater publication hook",
        ),
        set_inline_hook_state(
            &RENDER_PRE_DEPTH_GROUPS_HOOK,
            states.pre_alpha,
            "pre-alpha hook",
        ),
        set_inline_hook_state(
            &RENDER_FIRST_PERSON_HOOK,
            states.first_person,
            "first-person hook",
        ),
        set_inline_hook_state(
            &RENDER_WORLD_SCENE_GRAPH_HOOK,
            states.world,
            "world-scene hook",
        ),
    ] {
        if let Err(err) = result {
            log::error!("[FNV] Depth-stage hook rollback failed: {err:#}");
        }
    }
    let restored = depth_stage_hook_states();
    publish_depth_stage_hook_states(restored);
    if restored.mask() != states.mask() {
        log::error!(
            "[FNV] Depth-stage hook rollback left a partial state: underwater={}, world={}, first_person={}, pre_alpha={}",
            restored.underwater,
            restored.world,
            restored.first_person,
            restored.pre_alpha,
        );
    }
}

/// Physically attach or detach OMV's native depth-stage inline hooks.
///
/// Callers must use xNVSE DeferredInit or OMV's `Present` detour. Those are
/// quiescent boundaries for the serialized FNV render functions whose entry
/// bytes are restored here. Detachment removes OMV's jumps from underwater,
/// world, first-person, and pre-alpha entry points; it is not a branch inside
/// resident detours.
pub(crate) fn set_depth_stage_hooks_active(active: bool) -> Result<()> {
    let previous = depth_stage_hook_states();
    if previous.all_active() == active
        && [
            previous.underwater,
            previous.world,
            previous.first_person,
            previous.pre_alpha,
        ]
        .into_iter()
        .all(|state| state == active)
    {
        publish_depth_stage_hook_states(previous);
        return Ok(());
    }

    let transition = if active {
        set_inline_hook_state(
            &SET_WATER_SHADER_UNDERWATER_HOOK,
            true,
            "underwater publication hook",
        )
        .and_then(|_| set_inline_hook_state(&RENDER_PRE_DEPTH_GROUPS_HOOK, true, "pre-alpha hook"))
        .and_then(|_| set_inline_hook_state(&RENDER_FIRST_PERSON_HOOK, true, "first-person hook"))
        // Publish the outer world wrapper last so a frame cannot enter before
        // every boundary it depends on is callable.
        .and_then(|_| {
            set_inline_hook_state(&RENDER_WORLD_SCENE_GRAPH_HOOK, true, "world-scene hook")
        })
    } else {
        // Remove the outer wrapper first. Even if a later restoration fails,
        // native rendering cannot newly enter a partially detached OMV chain.
        set_inline_hook_state(&RENDER_WORLD_SCENE_GRAPH_HOOK, false, "world-scene hook")
            .and_then(|_| {
                set_inline_hook_state(&RENDER_FIRST_PERSON_HOOK, false, "first-person hook")
            })
            .and_then(|_| {
                set_inline_hook_state(&RENDER_PRE_DEPTH_GROUPS_HOOK, false, "pre-alpha hook")
            })
            .and_then(|_| {
                set_inline_hook_state(
                    &SET_WATER_SHADER_UNDERWATER_HOOK,
                    false,
                    "underwater publication hook",
                )
            })
    };

    if let Err(err) = transition {
        restore_depth_stage_hook_states(previous);
        return Err(err);
    }
    publish_depth_stage_hook_states(depth_stage_hook_states());
    log::info!(
        "[FNV] Depth-stage hooks physically {}",
        if active { "attached" } else { "detached" }
    );
    Ok(())
}

/// Reconcile native depth-stage hooks with current producer/visual ownership.
pub(crate) fn reconcile_depth_stage_hooks() -> Result<()> {
    let required = depth_stage_hooks_required(
        crate::runtime::needs_fnv_scene_hooks(),
        crate::fnv_world_pipeline::needs_scene_hooks(),
        crate::backend::needs_shared_pre_alpha_depth(),
    );
    set_depth_stage_hooks_active(required)
}

/// Return whether native depth-stage entries currently point at OMV.
pub(crate) fn depth_stage_hooks_active() -> bool {
    DEPTH_STAGE_HOOK_MASK.load(Ordering::Acquire) == DepthStageHookStates::ALL_MASK
}

/// Return an exact diagnostic label for native depth-stage entry ownership.
pub(crate) fn depth_stage_hooks_status_label() -> &'static str {
    match DEPTH_STAGE_HOOK_MASK.load(Ordering::Acquire) {
        0 => "detached",
        DepthStageHookStates::ALL_MASK => "attached",
        _ => "partial",
    }
}

fn install_process_image_space_shaders_hook() {
    if PROCESS_IMAGE_SPACE_SHADERS_HOOK.is_initialized() {
        enable_prepared_scene_hook(
            &PROCESS_IMAGE_SPACE_SHADERS_HOOK,
            "ProcessImageSpaceShaders",
        );
        return;
    }
    match unsafe {
        PROCESS_IMAGE_SPACE_SHADERS_HOOK.init(
            "FNV ProcessImageSpaceShaders",
            PROCESS_IMAGE_SPACE_SHADERS_ADDR as *mut c_void,
            hook_process_image_space_shaders,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[FNV] ProcessImageSpaceShaders hook skipped at 0x{PROCESS_IMAGE_SPACE_SHADERS_ADDR:08X}: {err}"
            );
            return;
        }
    }

    match PROCESS_IMAGE_SPACE_SHADERS_HOOK.enable() {
        Ok(()) => {
            log::info!(
                "[FNV] ProcessImageSpaceShaders hook installed at 0x{PROCESS_IMAGE_SPACE_SHADERS_ADDR:08X}"
            )
        }
        Err(err) => {
            log::warn!(
                "[FNV] ProcessImageSpaceShaders hook skipped at 0x{PROCESS_IMAGE_SPACE_SHADERS_ADDR:08X}: {err}"
            )
        }
    }
}

fn install_set_water_shader_underwater_hook() {
    UNDERWATER_PUBLICATION_HOOK_READY.store(false, Ordering::Release);
    if SET_WATER_SHADER_UNDERWATER_HOOK.is_initialized() {
        let ready = enable_prepared_scene_hook(
            &SET_WATER_SHADER_UNDERWATER_HOOK,
            "SetWaterShaderUnderwater",
        );
        UNDERWATER_PUBLICATION_HOOK_READY.store(ready, Ordering::Release);
        return;
    }
    match unsafe {
        SET_WATER_SHADER_UNDERWATER_HOOK.init(
            "FNV SetWaterShaderUnderwater",
            SET_WATER_SHADER_UNDERWATER_ADDR as *mut c_void,
            hook_set_water_shader_underwater,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[FNV] Underwater publication hook skipped at 0x{SET_WATER_SHADER_UNDERWATER_ADDR:08X}: {err}"
            );
            return;
        }
    }

    match SET_WATER_SHADER_UNDERWATER_HOOK.enable() {
        Ok(()) => {
            UNDERWATER_PUBLICATION_HOOK_READY.store(true, Ordering::Release);
            log::info!(
                "[FNV] Underwater publication hook installed at 0x{SET_WATER_SHADER_UNDERWATER_ADDR:08X}"
            );
        }
        Err(err) => {
            log::warn!(
                "[FNV] Underwater publication hook skipped at 0x{SET_WATER_SHADER_UNDERWATER_ADDR:08X}: {err}"
            );
        }
    }
}

fn install_render_world_scene_graph_hook() {
    WORLD_SCENE_HOOK_READY.store(false, Ordering::Release);
    if RENDER_WORLD_SCENE_GRAPH_HOOK.is_initialized() {
        let ready =
            enable_prepared_scene_hook(&RENDER_WORLD_SCENE_GRAPH_HOOK, "RenderWorldSceneGraph");
        WORLD_SCENE_HOOK_READY.store(ready, Ordering::Release);
        return;
    }
    match unsafe {
        RENDER_WORLD_SCENE_GRAPH_HOOK.init(
            "FNV RenderWorldSceneGraph",
            RENDER_WORLD_SCENE_GRAPH_ADDR as *mut c_void,
            hook_render_world_scene_graph,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[FNV] RenderWorldSceneGraph hook skipped at 0x{RENDER_WORLD_SCENE_GRAPH_ADDR:08X}: {err}"
            );
            return;
        }
    }

    match RENDER_WORLD_SCENE_GRAPH_HOOK.enable() {
        Ok(()) => {
            WORLD_SCENE_HOOK_READY.store(true, Ordering::Release);
            log::info!(
                "[FNV] RenderWorldSceneGraph hook installed at 0x{RENDER_WORLD_SCENE_GRAPH_ADDR:08X}"
            )
        }
        Err(err) => {
            log::warn!(
                "[FNV] RenderWorldSceneGraph hook skipped at 0x{RENDER_WORLD_SCENE_GRAPH_ADDR:08X}: {err}"
            )
        }
    }
}

fn install_render_first_person_hook() {
    if RENDER_FIRST_PERSON_HOOK.is_initialized() {
        enable_prepared_scene_hook(&RENDER_FIRST_PERSON_HOOK, "RenderFirstPerson");
        return;
    }
    match unsafe {
        RENDER_FIRST_PERSON_HOOK.init(
            "FNV RenderFirstPerson",
            RENDER_FIRST_PERSON_ADDR as *mut c_void,
            hook_render_first_person,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[FNV] RenderFirstPerson hook skipped at 0x{RENDER_FIRST_PERSON_ADDR:08X}: {err}"
            );
            return;
        }
    }

    match RENDER_FIRST_PERSON_HOOK.enable() {
        Ok(()) => {
            log::info!("[FNV] RenderFirstPerson hook installed at 0x{RENDER_FIRST_PERSON_ADDR:08X}")
        }
        Err(err) => {
            log::warn!(
                "[FNV] RenderFirstPerson hook skipped at 0x{RENDER_FIRST_PERSON_ADDR:08X}: {err}"
            )
        }
    }
}

fn install_render_pre_depth_groups_hook() {
    PRE_ALPHA_HOOK_READY.store(false, Ordering::Release);
    if RENDER_PRE_DEPTH_GROUPS_HOOK.is_initialized() {
        let ready =
            enable_prepared_scene_hook(&RENDER_PRE_DEPTH_GROUPS_HOOK, "RenderPreDepthGroups");
        PRE_ALPHA_HOOK_READY.store(ready, Ordering::Release);
        return;
    }
    match unsafe {
        RENDER_PRE_DEPTH_GROUPS_HOOK.init(
            "FNV RenderPreDepthGroups",
            RENDER_PRE_DEPTH_GROUPS_ADDR as *mut c_void,
            hook_render_pre_depth_groups,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[FNV] Pre-alpha atmosphere hook skipped at 0x{RENDER_PRE_DEPTH_GROUPS_ADDR:08X}: {err}"
            );
            return;
        }
    }

    match RENDER_PRE_DEPTH_GROUPS_HOOK.enable() {
        Ok(()) => {
            PRE_ALPHA_HOOK_READY.store(true, Ordering::Release);
            log::info!(
                "[FNV] Pre-alpha atmosphere hook installed at 0x{RENDER_PRE_DEPTH_GROUPS_ADDR:08X}"
            );
        }
        Err(err) => log::warn!(
            "[FNV] Pre-alpha atmosphere hook skipped at 0x{RENDER_PRE_DEPTH_GROUPS_ADDR:08X}: {err}"
        ),
    }
}

/// Re-enable a prepared scene hook during a DeferredInit retry.
///
/// Hook containers intentionally reject a second `init`. Retrying therefore
/// reuses the existing trampoline and only restores the entry jump when a
/// previous startup attempt left it detached.
fn enable_prepared_scene_hook<T: Function>(
    hook: &InlineHookContainer<T>,
    label: &'static str,
) -> bool {
    if hook.is_enabled() {
        return true;
    }
    match hook.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[FNV] Prepared {label} hook could not be re-enabled: {err}");
            false
        }
    }
}

unsafe extern "cdecl" fn hook_process_image_space_shaders(
    renderer: *mut c_void,
    rendered_texture_1: *mut c_void,
    rendered_texture_2: *mut c_void,
) {
    let Ok(original) = PROCESS_IMAGE_SPACE_SHADERS_HOOK.original() else {
        log_hook_error("[FNV] Missing original ProcessImageSpaceShaders function");
        return;
    };
    if !crate::runtime::effects_enabled() {
        unsafe { original(renderer, rendered_texture_1, rendered_texture_2) };
        return;
    }

    unsafe {
        let outer_image_space_call = rendered_texture_2.is_null();
        let native_dof_active =
            if outer_image_space_call && crate::runtime::needs_native_dof_query() {
                native_dof_active().unwrap_or(true)
            } else {
                false
            };

        run_image_space_phase_order(
            outer_image_space_call,
            || {
                crate::fnv_world_pipeline::close_deadline(rendered_texture_1);
                apply_scene_pre_image_space(
                    "FNV before vanilla image-space shaders",
                    rendered_texture_1,
                );
            },
            || original(renderer, rendered_texture_1, rendered_texture_2),
            || apply_scene_post_image_space("FNV after image-space shaders", native_dof_active),
            || apply_final_image_space("FNV final image-space"),
        );
    }
}

#[inline]
fn run_image_space_phase_order(
    outer_image_space_call: bool,
    scene_pre: impl FnOnce(),
    original: impl FnOnce(),
    scene_post: impl FnOnce(),
    final_image: impl FnOnce(),
) {
    if outer_image_space_call {
        scene_pre();
    }
    original();
    if outer_image_space_call {
        scene_post();
        final_image();
    }
}

unsafe extern "thiscall" fn hook_set_water_shader_underwater(
    water_shader_state: *mut c_void,
    underwater: u8,
) {
    let Ok(original) = SET_WATER_SHADER_UNDERWATER_HOOK.original() else {
        log_hook_error("[FNV] Missing original SetWaterShaderUnderwater function");
        return;
    };

    unsafe { original(water_shader_state, underwater) };
    crate::backend::publish_fnv_underwater_classification(underwater != 0);
}

unsafe fn native_dof_active() -> Option<bool> {
    let manager = unsafe { *(IMAGE_SPACE_MANAGER_PTR_ADDR as *const *mut u8) };
    if manager.is_null() {
        return None;
    }

    let last_effect_id = unsafe { *(manager.add(IMAGE_SPACE_LAST_EFFECT_ID_OFFSET).cast::<i32>()) };
    if last_effect_id < IMAGE_SPACE_DOF_EFFECT_ID as i32 {
        return Some(false);
    }

    let effects = unsafe {
        *(manager
            .add(IMAGE_SPACE_EFFECTS_OFFSET)
            .cast::<*mut *mut c_void>())
    };
    if effects.is_null() {
        return None;
    }

    let effect = unsafe { *effects.add(IMAGE_SPACE_DOF_EFFECT_ID) };
    if effect.is_null() {
        return Some(false);
    }

    let vtable = unsafe { *(effect.cast::<*const u8>()) };
    if vtable.is_null() {
        return None;
    }

    let function_address = unsafe {
        *(vtable
            .add(IMAGE_SPACE_EFFECT_IS_ACTIVE_VTBL_OFFSET)
            .cast::<usize>())
    };
    if function_address == 0 {
        return None;
    }

    let is_active: ImageSpaceEffectIsActiveFn = unsafe { std::mem::transmute(function_address) };
    Some(unsafe { is_active(effect) != 0 })
}

unsafe extern "thiscall" fn hook_render_world_scene_graph(
    main: *mut c_void,
    scene_graph: *mut c_void,
    render_first_person: u8,
    scene_graph_phase: u8,
    render_flags: u8,
) {
    let Ok(original) = RENDER_WORLD_SCENE_GRAPH_HOOK.original() else {
        log_hook_error("[FNV] Missing original RenderWorldSceneGraph function");
        return;
    };
    if !depth_stage_hooks_required(
        crate::runtime::needs_fnv_scene_hooks(),
        crate::fnv_world_pipeline::needs_scene_hooks(),
        crate::backend::needs_shared_pre_alpha_depth(),
    ) {
        unsafe {
            original(
                main,
                scene_graph,
                render_first_person,
                scene_graph_phase,
                render_flags,
            )
        };
        return;
    }

    unsafe {
        let world_scene_graph = scene_graph_phase == WORLD_SCENE_GRAPH_PHASE;
        // The first stack argument is not the SceneGraph held in the function's
        // internal [EBP-0x24] local. Camera access must use the world global.
        let camera_jitter = world_scene_graph
            .then(|| begin_temporal_aa_jitter())
            .flatten();
        let pre_alpha_target = world_scene_graph
            .then(current_render_target)
            .flatten()
            .filter(|_| {
                crate::fnv_world_pipeline::needs_atmosphere()
                    || crate::backend::needs_shared_pre_alpha_depth()
            })
            .unwrap_or(0);
        PRE_ALPHA_WORLD_TARGET.store(pre_alpha_target, Ordering::Release);
        PRE_ALPHA_WORLD_ARMED.store(pre_alpha_target != 0, Ordering::Release);
        original(
            main,
            scene_graph,
            render_first_person,
            scene_graph_phase,
            render_flags,
        );
        PRE_ALPHA_WORLD_ARMED.store(false, Ordering::Release);
        PRE_ALPHA_WORLD_TARGET.store(0, Ordering::Release);

        // Ghidra callsites prove the third stack argument is the scene phase:
        // 0x00870AE8 pushes 1, 0x00870E18 pushes 0. The second u8 is not the
        // world/first-person discriminator.
        if world_scene_graph {
            drop(camera_jitter);
            if let Some(device_ptr) = crate::backend::d3d_device_ptr() {
                // Depth Resolve's post-water texture is fresh only after the
                // original world renderer returns. Publishing the borrowed
                // snapshot here lets the external provider feed OMV without
                // issuing another physical resolve.
                crate::backend::publish_external_depth_after_world(
                    device_ptr,
                    crate::hooks::render_epoch(),
                );
                if crate::fnv_world_pipeline::needs_depth(crate::backend::DepthResolveSlot::World) {
                    crate::fnv_world_pipeline::apply_primary(device_ptr);
                } else {
                    capture_depth(
                        crate::backend::DepthResolveSlot::World,
                        None,
                        "FNV after world scene graph",
                    );
                }
                if crate::runtime::needs_fnv_world_color_capture() {
                    crate::runtime::capture_fnv_world_color(device_ptr);
                }
                if crate::backend::active_depth_provider()
                    == crate::backend::DepthProvider::DepthResolve
                {
                    // RT0 still owns the completed world here. Do not move
                    // this draw to RenderFirstPerson entry: that function has
                    // not yet activated its BSRenderedTexture argument, and
                    // manually binding it violated the engine target lifetime.
                    crate::runtime::apply_fnv_ao_after_world(device_ptr);
                }
            }
        } else {
            log_depth_capture_skip(
                crate::backend::DepthResolveSlot::World,
                "FNV after world scene graph",
                "non-world scene graph phase",
            );
        }
    }
}

fn depth_stage_hooks_required(
    scene_inputs: bool,
    world_pipeline: bool,
    shared_depth_service: bool,
) -> bool {
    // Published consumer requirements, rather than the global master switch,
    // decide whether OMV needs these entry points. When OMV is the selected
    // physical producer, the separate shared service still requires one
    // pre-alpha refresh even if every OMV effect is disabled.
    scene_inputs || world_pipeline || shared_depth_service
}

unsafe extern "cdecl" fn hook_render_pre_depth_groups(accumulator: *mut c_void) {
    let Ok(original) = RENDER_PRE_DEPTH_GROUPS_HOOK.original() else {
        log_hook_error("[FNV] Missing original RenderPreDepthGroups function");
        return;
    };
    unsafe { original(accumulator) };

    if !PRE_ALPHA_WORLD_ARMED.load(Ordering::Acquire) {
        return;
    }
    let expected_target = PRE_ALPHA_WORLD_TARGET.load(Ordering::Acquire);
    if expected_target == 0 || current_render_target() != Some(expected_target) {
        return;
    }
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    if crate::backend::needs_shared_pre_alpha_depth()
        && !crate::fnv_world_pipeline::needs_atmosphere()
    {
        unsafe { capture_shared_pre_alpha_depth(device_ptr) };
    } else {
        unsafe { crate::fnv_world_pipeline::apply_before_alpha(device_ptr) };
    }
}

unsafe fn capture_shared_pre_alpha_depth(device_ptr: *mut c_void) {
    // Depth Resolve consumers such as Vanilla Plus Particles sample the
    // shared texture during native alpha rendering even when OMV's master
    // effects are disabled. In OMV-provider mode one pre-alpha capture keeps
    // that service fresh while the external pre/post markers are suppressed.
    let _ = unsafe {
        crate::backend::resolve_scene_depth(
            crate::backend::DepthProvider::FalloutNewVegas,
            device_ptr,
            None,
            crate::backend::DepthResolveSlot::World,
            crate::backend::DepthResolveStage::PreAlphaWorld,
            None,
            "OMV shared pre-alpha depth service",
            crate::hooks::render_epoch(),
        )
    };
}

fn current_render_target() -> Option<usize> {
    let device_ptr = crate::backend::d3d_device_ptr()?;
    let device = unsafe { Device9Ref::from_raw_void(device_ptr) }?;
    device
        .render_target(0)
        .ok()
        .map(|surface| surface.as_raw() as usize)
}

unsafe fn begin_temporal_aa_jitter() -> Option<crate::backend::WorldCameraJitter> {
    if !crate::fnv_world_pipeline::needs_temporal_aa() {
        return None;
    }

    let device_ptr = crate::backend::d3d_device_ptr()?;
    let device = unsafe { Device9Ref::from_raw_void(device_ptr) }?;
    let render_target = device.render_target(0).ok()?;
    let desc = render_target.desc().ok()?;
    unsafe {
        crate::fnv_world_pipeline::begin_temporal_aa_jitter(
            device_ptr,
            render_target.as_raw() as usize,
            crate::effects::temporal_aa::TargetDescription::from(&desc),
        )
    }
}

unsafe extern "thiscall" fn hook_render_first_person(
    main: *mut c_void,
    renderer: *mut c_void,
    geo: *mut c_void,
    sky_sun: *mut c_void,
    rendered_texture: *mut c_void,
) {
    let Ok(original) = RENDER_FIRST_PERSON_HOOK.original() else {
        log_hook_error("[FNV] Missing original RenderFirstPerson function");
        return;
    };
    if !crate::runtime::effects_enabled() {
        unsafe { original(main, renderer, geo, sky_sun, rendered_texture) };
        return;
    }

    unsafe {
        if let Some(device_ptr) = crate::backend::d3d_device_ptr() {
            crate::fnv_world_pipeline::retry_before_first_person(device_ptr, rendered_texture);
        }
        original(main, renderer, geo, sky_sun, rendered_texture);
        crate::backend::publish_fnv_first_person_rendered();
        capture_depth(
            crate::backend::DepthResolveSlot::FirstPerson,
            Some(rendered_texture),
            "FNV after first-person depth",
        );
    }
}

unsafe fn capture_depth(
    slot: crate::backend::DepthResolveSlot,
    source_rendered_texture: Option<*mut c_void>,
    reason: &'static str,
) {
    if !crate::runtime::needs_fnv_depth_capture(slot)
        && !crate::fnv_world_pipeline::needs_depth(slot)
    {
        log_depth_capture_skip(slot, reason, "runtime not ready or no scene inputs needed");
        return;
    }

    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        log_depth_capture_skip(slot, reason, "missing D3D device");
        return;
    };

    let depth_provider = crate::backend::active_depth_provider();
    match unsafe {
        crate::backend::resolve_scene_depth(
            depth_provider,
            device_ptr,
            source_rendered_texture,
            slot,
            match slot {
                crate::backend::DepthResolveSlot::World => {
                    crate::backend::DepthResolveStage::CoherentWorld
                }
                crate::backend::DepthResolveSlot::FirstPerson => {
                    crate::backend::DepthResolveStage::FirstPerson
                }
            },
            None,
            reason,
            crate::hooks::render_epoch(),
        )
    } {
        crate::backend::DepthResolveOutcome::Resolved { .. } => log_depth_capture(slot, reason),
        crate::backend::DepthResolveOutcome::Busy => {
            log_depth_capture_skip(slot, reason, "depth owner busy")
        }
        crate::backend::DepthResolveOutcome::Rejected => {}
    }
}

unsafe fn apply_final_image_space(reason: &'static str) {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    log_shader_apply(reason);
    unsafe {
        crate::runtime::apply_fnv_final_image_space(device_ptr);
    }
}

unsafe fn apply_scene_pre_image_space(reason: &'static str, source_rendered_texture: *mut c_void) {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    log_shader_apply(reason);
    unsafe {
        crate::runtime::apply_fnv_scene_pre_image_space(device_ptr, source_rendered_texture);
    }
}

unsafe fn apply_scene_post_image_space(reason: &'static str, native_dof_active: bool) {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    log_shader_apply(reason);
    unsafe {
        crate::runtime::apply_fnv_scene_post_image_space(device_ptr, native_dof_active);
    }
}

fn log_hook_error(message: &'static str) {
    if HOOK_ERROR_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_HOOK_ERROR_LOGS {
        log::warn!("{message}");
    }
}

fn log_depth_capture(slot: crate::backend::DepthResolveSlot, reason: &'static str) {
    if DEPTH_CAPTURE_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_DEPTH_CAPTURE_LOGS {
        log::debug!(
            "[FNV] Depth capture trigger: slot={}, reason={reason}",
            slot.label()
        );
    }
}

fn log_depth_capture_skip(
    slot: crate::backend::DepthResolveSlot,
    reason: &'static str,
    cause: &'static str,
) {
    if DEPTH_CAPTURE_SKIP_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_DEPTH_CAPTURE_SKIP_LOGS {
        log::debug!(
            "[FNV] Depth capture skipped: slot={}, reason={reason}, cause={cause}",
            slot.label()
        );
    }
}

fn log_shader_apply(reason: &'static str) {
    if SHADER_APPLY_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_SHADER_APPLY_LOGS {
        log::debug!("[FNV] Screen-space shader trigger: {reason}");
    }
}

#[cfg(test)]
mod final_color_phase_contract_tests {
    use std::{cell::RefCell, mem::size_of};

    use super::{
        PROCESS_IMAGE_SPACE_SHADERS_ADDR, ProcessImageSpaceShadersFn, depth_stage_hooks_required,
        run_image_space_phase_order, shared_depth_service_hooks_ready,
    };

    #[test]
    fn supported_engine_entry_and_callback_abi_are_exact() {
        assert_eq!(PROCESS_IMAGE_SPACE_SHADERS_ADDR, 0x00B5_5AC0);
        assert_eq!(size_of::<ProcessImageSpaceShadersFn>(), 4);
    }

    #[test]
    fn outer_image_space_orders_grade_after_vanilla_and_nested_calls_do_not_grade() {
        let events = RefCell::new(Vec::new());
        run_image_space_phase_order(
            true,
            || events.borrow_mut().push("scene_pre"),
            || events.borrow_mut().push("vanilla"),
            || events.borrow_mut().push("scene_post"),
            || events.borrow_mut().push("final_color"),
        );
        assert_eq!(
            events.into_inner(),
            ["scene_pre", "vanilla", "scene_post", "final_color"]
        );

        let events = RefCell::new(Vec::new());
        run_image_space_phase_order(
            false,
            || events.borrow_mut().push("scene_pre"),
            || events.borrow_mut().push("vanilla"),
            || events.borrow_mut().push("scene_post"),
            || events.borrow_mut().push("final_color"),
        );
        assert_eq!(events.into_inner(), ["vanilla"]);
    }

    #[test]
    fn world_only_ao_uses_the_active_post_world_target_before_first_person() {
        let source = include_str!("fnv_render.rs");
        let world_body = source
            .split_once("unsafe extern \"thiscall\" fn hook_render_world_scene_graph")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn depth_stage_hooks_required"))
            .map(|(body, _)| body)
            .expect("RenderWorldSceneGraph detour");
        let publish = world_body
            .find("publish_external_depth_after_world")
            .expect("external world-depth publication");
        let world_color = world_body[publish..]
            .find("capture_fnv_world_color")
            .map(|offset| publish + offset)
            .expect("world-color capture");
        let world_ao = world_body[world_color..]
            .find("apply_fnv_ao_after_world")
            .map(|offset| world_color + offset)
            .expect("world-only AO boundary");

        // AO must draw while the completed world surface is still RT0. The
        // BSRenderedTexture argument is not activated by the engine until
        // inside RenderFirstPerson, so pre-binding it here is not equivalent.
        assert!(publish < world_color);
        assert!(world_color < world_ao);

        let first_person_body = source
            .split_once("unsafe extern \"thiscall\" fn hook_render_first_person")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nunsafe fn capture_depth"))
            .map(|(body, _)| body)
            .expect("RenderFirstPerson detour");
        let world_retry = first_person_body
            .find("retry_before_first_person")
            .expect("world-pipeline retry");
        let original = first_person_body[world_retry..]
            .find("original(main, renderer, geo, sky_sun, rendered_texture)")
            .map(|offset| world_retry + offset)
            .expect("native first-person draw");
        let publish = first_person_body[original..]
            .find("publish_fnv_first_person_rendered")
            .map(|offset| original + offset)
            .expect("first-person publication");
        let capture = first_person_body[publish..]
            .find("capture_depth(")
            .map(|offset| publish + offset)
            .expect("OMV-provider first-person capture");

        assert!(!first_person_body.contains("apply_fnv_ao"));
        assert!(world_retry < original);
        assert!(original < publish);
        assert!(publish < capture);
    }

    #[test]
    fn disabled_master_bypasses_visual_hooks_but_not_the_shared_depth_service() {
        let source = include_str!("fnv_render.rs");
        for (detour, first_effect_work) in [
            (
                "unsafe extern \"cdecl\" fn hook_process_image_space_shaders",
                "run_image_space_phase_order(",
            ),
            (
                "unsafe extern \"thiscall\" fn hook_render_first_person",
                "fn capture_depth(",
            ),
        ] {
            let prefix = source
                .split_once(detour)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once(first_effect_work))
                .map(|(prefix, _)| prefix)
                .expect("scene hook master gate");
            assert!(prefix.contains("if !crate::runtime::effects_enabled()"));
            assert!(prefix.contains("original("));
        }

        assert!(!depth_stage_hooks_required(false, false, false));
        assert!(depth_stage_hooks_required(true, false, false));
        assert!(depth_stage_hooks_required(false, true, false));
        assert!(depth_stage_hooks_required(false, false, true));
    }

    #[test]
    fn shared_service_capture_is_owned_by_omv_and_does_not_select_a_hybrid_provider() {
        let source = include_str!("fnv_render.rs");
        let body = source
            .split_once("unsafe fn capture_shared_pre_alpha_depth")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("fn current_render_target()"))
            .map(|(body, _)| body)
            .expect("shared pre-alpha capture body");
        assert!(body.contains("DepthProvider::FalloutNewVegas"));
        assert!(!body.contains("active_depth_provider"));
    }

    #[test]
    fn exclusive_service_requires_both_native_scene_boundaries() {
        assert!(shared_depth_service_hooks_ready(true, true));
        assert!(!shared_depth_service_hooks_ready(true, false));
        assert!(!shared_depth_service_hooks_ready(false, true));
        assert!(!shared_depth_service_hooks_ready(false, false));
    }

    #[test]
    fn inactive_external_policy_reaches_physical_depth_stage_detachment() {
        assert!(!depth_stage_hooks_required(false, false, false));

        let source = include_str!("fnv_render.rs");
        let body = source
            .split_once("pub(crate) fn reconcile_depth_stage_hooks")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn depth_stage_hooks_active"))
            .map(|(body, _)| body)
            .expect("depth-stage reconciliation body");
        assert!(body.contains("depth_stage_hooks_required("));
        assert!(body.contains("set_depth_stage_hooks_active(required)"));

        let transition = source
            .split_once("pub(crate) fn set_depth_stage_hooks_active")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn reconcile_depth_stage_hooks"))
            .map(|(body, _)| body)
            .expect("physical depth-stage transition body");
        for hook in [
            "SET_WATER_SHADER_UNDERWATER_HOOK",
            "RENDER_WORLD_SCENE_GRAPH_HOOK",
            "RENDER_FIRST_PERSON_HOOK",
            "RENDER_PRE_DEPTH_GROUPS_HOOK",
        ] {
            assert!(transition.contains(hook));
        }
        assert!(transition.contains("set_inline_hook_state"));
        assert!(transition.contains("false"));
    }
}

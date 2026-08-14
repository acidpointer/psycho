//! Native Fallout New Vegas render-stage boundaries used by OMV.
//!
//! World-scene entry establishes the destination identity, pre-alpha captures
//! depth only for an admitted immediate consumer, and post-world publication
//! exposes either OMV or externally produced world depth. Their trampolines
//! are prepared and enabled as one DeferredInit transaction, then remain
//! resident until process exit. Runtime settings only change passive consumer
//! gates inside the detours; they never rewrite executable entry bytes while
//! the renderer is live. Render callbacks are nonblocking and never substitute
//! one provider for another. When the selected provider exposes world depth
//! but no first-person mask, AO is composed on the completed world target
//! immediately after `RenderWorldSceneGraph`; hands and weapons later
//! overwrite AO naturally without reactivating OMV depth capture.
//!
//! First-person motion blur uses the same engine ownership interval but runs
//! after all other post-world owners. A busy primary call may publish one exact
//! epoch/RT0 retry for `RenderFirstPerson` entry. The detour validates both the
//! still-bound RT0 and the rendered-texture argument, retries coherent world
//! depth only when absent, then closes the deadline before entering native
//! first-person rendering. It never moves missed first-person work into the
//! later image-space hooks.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::{Result, anyhow};
use libpsycho::ffi::fnptr::Function;
use libpsycho::os::windows::{
    directx9::Device9Ref, hook::inline::inlinehook::InlineHookContainer,
    memory::validate_memory_range,
};

const PROCESS_IMAGE_SPACE_SHADERS_ADDR: usize = 0x00B55AC0;
const SET_WATER_SHADER_UNDERWATER_ADDR: usize = 0x004E2120;
const RENDER_WORLD_SCENE_GRAPH_ADDR: usize = 0x00873200;
const RENDER_FIRST_PERSON_ADDR: usize = 0x00875110;
const RENDER_PRE_DEPTH_GROUPS_ADDR: usize = 0x00B65AE0;
const PROCESS_IMAGE_SPACE_SHADERS_PROLOGUE: &[u8] = &[0x8B, 0x54, 0x24, 0x04, 0x56];
const SET_WATER_SHADER_UNDERWATER_PROLOGUE: &[u8] = &[0x55, 0x8B, 0xEC, 0x51, 0x89];
const RENDER_WORLD_SCENE_GRAPH_PROLOGUE: &[u8] = &[0x55, 0x8B, 0xEC, 0x6A, 0xFF];
const RENDER_FIRST_PERSON_PROLOGUE: &[u8] = &[0x55, 0x8B, 0xEC, 0x6A, 0xFF];
const RENDER_PRE_DEPTH_GROUPS_PROLOGUE: &[u8] = &[0x56, 0x8B, 0x74, 0x24, 0x08];
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
///
/// All trampolines are prepared before the first executable entry is changed.
/// If a mandatory enable fails, only entries acquired by this attempt are
/// restored in reverse order and readiness remains unpublished.
pub(crate) fn install_scene_boundary_hook() -> Result<()> {
    prepare_process_image_space_shaders_hook()?;
    prepare_set_water_shader_underwater_hook()?;
    prepare_render_world_scene_graph_hook()?;
    prepare_render_first_person_hook()?;
    prepare_render_pre_depth_groups_hook()?;

    let mut enabled_image_space = false;
    let mut enabled_underwater = false;
    let mut enabled_pre_alpha = false;
    let mut enabled_first_person = false;
    let mut enabled_world = false;
    let transaction = (|| -> Result<()> {
        enabled_image_space = enable_prepared_scene_hook(
            &PROCESS_IMAGE_SPACE_SHADERS_HOOK,
            "ProcessImageSpaceShaders",
        )?;
        enabled_underwater = enable_prepared_scene_hook(
            &SET_WATER_SHADER_UNDERWATER_HOOK,
            "SetWaterShaderUnderwater",
        )?;
        enabled_pre_alpha =
            enable_prepared_scene_hook(&RENDER_PRE_DEPTH_GROUPS_HOOK, "RenderPreDepthGroups")?;
        enabled_first_person =
            enable_prepared_scene_hook(&RENDER_FIRST_PERSON_HOOK, "RenderFirstPerson")?;
        // The outer world entry is published last, after every inner boundary
        // on which its producer transaction depends is callable.
        enabled_world =
            enable_prepared_scene_hook(&RENDER_WORLD_SCENE_GRAPH_HOOK, "RenderWorldSceneGraph")?;
        Ok(())
    })();
    if let Err(error) = transaction {
        rollback_scene_hook(
            &RENDER_WORLD_SCENE_GRAPH_HOOK,
            enabled_world,
            "RenderWorldSceneGraph",
        );
        rollback_scene_hook(
            &RENDER_FIRST_PERSON_HOOK,
            enabled_first_person,
            "RenderFirstPerson",
        );
        rollback_scene_hook(
            &RENDER_PRE_DEPTH_GROUPS_HOOK,
            enabled_pre_alpha,
            "RenderPreDepthGroups",
        );
        rollback_scene_hook(
            &SET_WATER_SHADER_UNDERWATER_HOOK,
            enabled_underwater,
            "SetWaterShaderUnderwater",
        );
        rollback_scene_hook(
            &PROCESS_IMAGE_SPACE_SHADERS_HOOK,
            enabled_image_space,
            "ProcessImageSpaceShaders",
        );
        UNDERWATER_PUBLICATION_HOOK_READY.store(false, Ordering::Release);
        WORLD_SCENE_HOOK_READY.store(false, Ordering::Release);
        PRE_ALPHA_HOOK_READY.store(false, Ordering::Release);
        publish_depth_stage_hook_states(depth_stage_hook_states());
        return Err(error);
    }

    let states = depth_stage_hook_states();
    let ready = PROCESS_IMAGE_SPACE_SHADERS_HOOK.is_enabled() && states.all_active();
    UNDERWATER_PUBLICATION_HOOK_READY.store(states.underwater, Ordering::Release);
    WORLD_SCENE_HOOK_READY.store(states.world, Ordering::Release);
    PRE_ALPHA_HOOK_READY.store(states.pre_alpha, Ordering::Release);
    publish_depth_stage_hook_states(states);
    if !ready {
        anyhow::bail!("one or more resident FNV scene hooks are not active");
    }
    log::info!("[FNV] Resident scene-boundary hook transaction installed");
    Ok(())
}

/// Return whether native underwater classification can be published safely.
pub(crate) fn underwater_publication_hook_ready() -> bool {
    UNDERWATER_PUBLICATION_HOOK_READY.load(Ordering::Acquire)
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

/// Return an exact diagnostic label for native depth-stage entry ownership.
pub(crate) fn depth_stage_hooks_status_label() -> &'static str {
    match DEPTH_STAGE_HOOK_MASK.load(Ordering::Acquire) {
        0 => "detached",
        DepthStageHookStates::ALL_MASK => "attached",
        _ => "partial",
    }
}

fn prepare_process_image_space_shaders_hook() -> Result<()> {
    if PROCESS_IMAGE_SPACE_SHADERS_HOOK.is_initialized() {
        return Ok(());
    }
    validate_vanilla_scene_entry(
        PROCESS_IMAGE_SPACE_SHADERS_ADDR,
        PROCESS_IMAGE_SPACE_SHADERS_PROLOGUE,
        "ProcessImageSpaceShaders",
    )?;
    unsafe {
        PROCESS_IMAGE_SPACE_SHADERS_HOOK.init(
            "FNV ProcessImageSpaceShaders",
            PROCESS_IMAGE_SPACE_SHADERS_ADDR as *mut c_void,
            hook_process_image_space_shaders,
        )
    }
    .map_err(|err| {
        anyhow!(
            "ProcessImageSpaceShaders hook preparation at 0x{PROCESS_IMAGE_SPACE_SHADERS_ADDR:08X} failed: {err}"
        )
    })
}

fn prepare_set_water_shader_underwater_hook() -> Result<()> {
    if SET_WATER_SHADER_UNDERWATER_HOOK.is_initialized() {
        return Ok(());
    }
    validate_vanilla_scene_entry(
        SET_WATER_SHADER_UNDERWATER_ADDR,
        SET_WATER_SHADER_UNDERWATER_PROLOGUE,
        "SetWaterShaderUnderwater",
    )?;
    unsafe {
        SET_WATER_SHADER_UNDERWATER_HOOK.init(
            "FNV SetWaterShaderUnderwater",
            SET_WATER_SHADER_UNDERWATER_ADDR as *mut c_void,
            hook_set_water_shader_underwater,
        )
    }
    .map_err(|err| {
        anyhow!(
            "SetWaterShaderUnderwater hook preparation at 0x{SET_WATER_SHADER_UNDERWATER_ADDR:08X} failed: {err}"
        )
    })
}

fn prepare_render_world_scene_graph_hook() -> Result<()> {
    if RENDER_WORLD_SCENE_GRAPH_HOOK.is_initialized() {
        return Ok(());
    }
    validate_vanilla_scene_entry(
        RENDER_WORLD_SCENE_GRAPH_ADDR,
        RENDER_WORLD_SCENE_GRAPH_PROLOGUE,
        "RenderWorldSceneGraph",
    )?;
    unsafe {
        RENDER_WORLD_SCENE_GRAPH_HOOK.init(
            "FNV RenderWorldSceneGraph",
            RENDER_WORLD_SCENE_GRAPH_ADDR as *mut c_void,
            hook_render_world_scene_graph,
        )
    }
    .map_err(|err| {
        anyhow!(
            "RenderWorldSceneGraph hook preparation at 0x{RENDER_WORLD_SCENE_GRAPH_ADDR:08X} failed: {err}"
        )
    })
}

fn prepare_render_first_person_hook() -> Result<()> {
    if RENDER_FIRST_PERSON_HOOK.is_initialized() {
        return Ok(());
    }
    validate_vanilla_scene_entry(
        RENDER_FIRST_PERSON_ADDR,
        RENDER_FIRST_PERSON_PROLOGUE,
        "RenderFirstPerson",
    )?;
    unsafe {
        RENDER_FIRST_PERSON_HOOK.init(
            "FNV RenderFirstPerson",
            RENDER_FIRST_PERSON_ADDR as *mut c_void,
            hook_render_first_person,
        )
    }
    .map_err(|err| {
        anyhow!(
            "RenderFirstPerson hook preparation at 0x{RENDER_FIRST_PERSON_ADDR:08X} failed: {err}"
        )
    })
}

fn prepare_render_pre_depth_groups_hook() -> Result<()> {
    if RENDER_PRE_DEPTH_GROUPS_HOOK.is_initialized() {
        return Ok(());
    }
    validate_vanilla_scene_entry(
        RENDER_PRE_DEPTH_GROUPS_ADDR,
        RENDER_PRE_DEPTH_GROUPS_PROLOGUE,
        "RenderPreDepthGroups",
    )?;
    unsafe {
        RENDER_PRE_DEPTH_GROUPS_HOOK.init(
            "FNV RenderPreDepthGroups",
            RENDER_PRE_DEPTH_GROUPS_ADDR as *mut c_void,
            hook_render_pre_depth_groups,
        )
    }
    .map_err(|err| {
        anyhow!(
            "RenderPreDepthGroups hook preparation at 0x{RENDER_PRE_DEPTH_GROUPS_ADDR:08X} failed: {err}"
        )
    })
}

fn validate_vanilla_scene_entry(
    address: usize,
    expected: &[u8],
    label: &'static str,
) -> Result<()> {
    validate_memory_range(address as *const c_void, expected.len())
        .map_err(|error| anyhow!("could not read {label} entry at 0x{address:08X}: {error}"))?;
    let observed = unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) };
    if observed != expected {
        return Err(anyhow!(
            "{label} entry at 0x{address:08X} has unsupported ownership or executable bytes"
        ));
    }
    Ok(())
}

/// Re-enable a prepared scene hook during a DeferredInit retry.
///
/// Hook containers intentionally reject a second `init`. Retrying therefore
/// reuses the existing trampoline and only restores the entry jump when a
/// previous startup attempt left it detached.
fn enable_prepared_scene_hook<T: Function>(
    hook: &InlineHookContainer<T>,
    label: &'static str,
) -> Result<bool> {
    if hook.is_enabled() {
        return Ok(false);
    }
    match hook.enable() {
        Ok(()) => Ok(true),
        Err(err) => {
            // Page-protection restoration can fail after the entry JMP was
            // written. InlineHook publishes that real ownership; remove it
            // immediately so the caller's reverse rollback starts from the
            // last fully completed member.
            if hook.is_enabled()
                && let Err(rollback_err) = hook.disable()
            {
                log::error!(
                    "[FNV] {label} hook became active during failed enable and immediate rollback failed: {rollback_err}"
                );
            }
            Err(anyhow!("prepared {label} hook could not be enabled: {err}"))
        }
    }
}

fn rollback_scene_hook<T: Function>(
    hook: &InlineHookContainer<T>,
    enabled_by_attempt: bool,
    label: &'static str,
) {
    if enabled_by_attempt && let Err(err) = hook.disable() {
        log::error!("[FNV] {label} hook rollback failed: {err}");
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
        crate::effects::shadows::needs_scene_hooks(),
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
                crate::effects::shadows::needs_pre_alpha()
                    || crate::fnv_world_pipeline::needs_atmosphere()
            })
            .unwrap_or(0);
        let shadow_world_context = (world_scene_graph && pre_alpha_target != 0)
            .then(|| begin_shadow_world_context(pre_alpha_target))
            .flatten();
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
        if let Some(context) = shadow_world_context {
            crate::effects::shadows::end_world_context(context);
        }

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
                // First-person motion blur must consume the final world color
                // after every world owner above, especially early AO. Native
                // RenderFirstPerson then supplies the exact foreground mask.
                crate::runtime::apply_fnv_motion_blur_after_world(device_ptr);
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

fn depth_stage_hooks_required(scene_inputs: bool, world_pipeline: bool, shadows: bool) -> bool {
    // Published consumer requirements, rather than the global master switch,
    // decide whether OMV needs these entry points.
    scene_inputs || world_pipeline || shadows
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
    // The engine's BSRenderedTexture owner is authoritative only at this
    // opaque-world boundary. An outer-entry context may legitimately be
    // unavailable while the manager is still switching targets, so establish
    // a nested exact receiver context here and restore any outer context after
    // both pre-alpha consumers finish.
    let shadow_receiver_context = unsafe { begin_shadow_world_context(expected_target) };
    // Opaque world shadows are the bottom-most world-space effect. Native
    // alpha, atmosphere/fog, TAA, AO, motion blur, and image-space work all
    // execute later and therefore remain visually on top of the shadowed
    // scene instead of being multiplied by it.
    run_pre_alpha_world_effects(
        || unsafe { crate::effects::shadows::apply_before_alpha(device_ptr) },
        || unsafe { crate::fnv_world_pipeline::apply_before_alpha(device_ptr) },
    );
    if let Some(context) = shadow_receiver_context {
        crate::effects::shadows::end_world_context(context);
    }
}

/// Execute opaque-world consumers in their physical composition order.
///
/// Shadows attenuate only surface radiance. Atmosphere then adds fog and
/// volumetric scattering over that surface. Keeping the order in an
/// executable helper lets tests reject the visually invalid inverse order
/// without inspecting Rust source text.
#[inline]
fn run_pre_alpha_world_effects(
    mut apply_surface_shadows: impl FnMut(),
    mut apply_atmosphere: impl FnMut(),
) {
    apply_surface_shadows();
    apply_atmosphere();
}

fn current_render_target() -> Option<usize> {
    let device_ptr = crate::backend::d3d_device_ptr()?;
    let device = unsafe { Device9Ref::from_raw_void(device_ptr) }?;
    device
        .render_target(0)
        .ok()
        .map(|surface| surface.as_raw() as usize)
}

unsafe fn begin_shadow_world_context(
    color_surface: usize,
) -> Option<crate::effects::shadows::WorldContextGuard> {
    if !crate::effects::shadows::needs_pre_alpha() {
        return None;
    }
    let device_ptr = crate::backend::d3d_device_ptr()?;
    let device = unsafe { Device9Ref::from_raw_void(device_ptr) }?;
    let target = device.render_target(0).ok()?;
    if target.as_raw() as usize != color_surface {
        return None;
    }
    let desc = target.desc().ok()?;
    let rendered_texture = unsafe { crate::backend::current_fnv_world_rendered_texture()? };
    // The BSRenderedTexture may expose a resolved color alias rather than the
    // exact COM surface currently bound as RT0. The outer hook already proved
    // the active RT0 identity; requiring pointer equality with that alias
    // rejects a valid world owner. Depth ownership is validated independently
    // against this rendered texture at consumption.
    let depth_surface =
        unsafe { crate::backend::rendered_texture_depth_surface(rendered_texture)? as usize };
    let native_camera =
        unsafe { crate::backend::fnv_world_camera_frame_fast(desc.Width, desc.Height) }
            .filter(|camera| camera.available && camera.world_transform.available)?;
    let generation_camera =
        crate::fnv_world_pipeline::shadow_generation_camera(native_camera).unwrap_or(native_camera);
    let depth_camera = crate::fnv_world_pipeline::shadow_depth_camera(
        color_surface,
        crate::effects::temporal_aa::TargetDescription::from(&desc),
        native_camera,
    )
    .unwrap_or(native_camera);
    if !generation_camera.available
        || !generation_camera.world_transform.available
        || !depth_camera.available
        || !depth_camera.world_transform.available
    {
        return None;
    }
    crate::effects::shadows::begin_world_context(
        color_surface,
        depth_surface,
        rendered_texture as usize,
        generation_camera,
        depth_camera,
    )
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
        crate::runtime::close_fnv_motion_blur_deadline();
        unsafe { original(main, renderer, geo, sky_sun, rendered_texture) };
        return;
    }

    unsafe {
        if let Some(device_ptr) = crate::backend::d3d_device_ptr() {
            crate::fnv_world_pipeline::retry_before_first_person(device_ptr, rendered_texture);
            if crate::runtime::fnv_motion_blur_retry_matches(device_ptr, rendered_texture) {
                if crate::runtime::fnv_motion_blur_retry_needs_world_depth() {
                    // The motion-blur producer can lose its post-world
                    // try-lock even when no focused world pass was pending.
                    // Reuse the ordinary coherent-world capture; its epoch and
                    // stage cache prevents a duplicate physical depth copy.
                    capture_depth(
                        crate::backend::DepthResolveSlot::World,
                        None,
                        "FNV before first-person motion blur retry",
                    );
                }
                crate::runtime::retry_fnv_motion_blur_before_first_person(
                    device_ptr,
                    rendered_texture,
                );
            }
        }
        // This is the hard ownership deadline. No miss may be carried into
        // scene post after native hands/weapons enter the color target.
        crate::runtime::close_fnv_motion_blur_deadline();
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
        run_image_space_phase_order, run_pre_alpha_world_effects,
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
    fn post_world_effects_finish_in_order_before_native_first_person() {
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
        let motion_blur = world_body[world_ao..]
            .find("apply_fnv_motion_blur_after_world")
            .map(|offset| world_ao + offset)
            .expect("first-person motion-blur boundary");

        // AO must draw while the completed world surface is still RT0. The
        // BSRenderedTexture argument is not activated by the engine until
        // inside RenderFirstPerson, so pre-binding it here is not equivalent.
        assert!(publish < world_color);
        assert!(world_color < world_ao);
        assert!(world_ao < motion_blur);

        let first_person_body = source
            .split_once("unsafe extern \"thiscall\" fn hook_render_first_person")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nunsafe fn capture_depth"))
            .map(|(body, _)| body)
            .expect("RenderFirstPerson detour");
        let world_retry = first_person_body
            .find("retry_before_first_person")
            .expect("world-pipeline retry");
        let motion_blur_retry = first_person_body[world_retry..]
            .find("retry_fnv_motion_blur_before_first_person")
            .map(|offset| world_retry + offset)
            .expect("motion-blur retry");
        let deadline = first_person_body[motion_blur_retry..]
            .find("close_fnv_motion_blur_deadline")
            .map(|offset| motion_blur_retry + offset)
            .expect("motion-blur deadline");
        let original = first_person_body[deadline..]
            .find("original(main, renderer, geo, sky_sun, rendered_texture)")
            .map(|offset| deadline + offset)
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
        assert!(world_retry < motion_blur_retry);
        assert!(motion_blur_retry < deadline);
        assert!(deadline < original);
        assert!(original < publish);
        assert!(publish < capture);
    }

    #[test]
    fn disabled_master_bypasses_visual_scene_hooks() {
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
    fn world_shadows_compose_at_the_opaque_pre_alpha_boundary_before_atmosphere() {
        let phase = core::cell::Cell::new(0_u8);
        run_pre_alpha_world_effects(
            || {
                assert_eq!(phase.get(), 0);
                phase.set(1);
            },
            || {
                assert_eq!(phase.get(), 1);
                phase.set(2);
            },
        );
        assert_eq!(phase.get(), 2);
    }

    #[test]
    fn runtime_policy_cannot_rewrite_resident_depth_stage_hooks() {
        assert!(!depth_stage_hooks_required(false, false, false));

        let source = include_str!("fnv_render.rs");
        let live_toggle = ["set_depth_stage_hooks", "_active"].concat();
        let reconciliation = ["reconcile_depth_stage", "_hooks"].concat();
        assert!(!source.contains(&live_toggle));
        assert!(!source.contains(&reconciliation));

        let install = source
            .split_once("pub(crate) fn install_scene_boundary_hook")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn underwater_publication_hook_ready"))
            .map(|(body, _)| body)
            .expect("resident scene hook transaction");
        assert!(install.contains("prepare_render_world_scene_graph_hook"));
        assert!(install.contains("rollback_scene_hook"));
    }
}

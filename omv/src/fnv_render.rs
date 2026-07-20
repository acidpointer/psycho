//! FalloutNV render-stage hooks.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

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
static DEPTH_CAPTURE_LOGS: AtomicU32 = AtomicU32::new(0);
static DEPTH_CAPTURE_SKIP_LOGS: AtomicU32 = AtomicU32::new(0);
static SHADER_APPLY_LOGS: AtomicU32 = AtomicU32::new(0);
static PRE_ALPHA_WORLD_TARGET: AtomicUsize = AtomicUsize::new(0);
static PRE_ALPHA_WORLD_ARMED: AtomicBool = AtomicBool::new(false);

pub(crate) fn install_scene_boundary_hook() {
    install_process_image_space_shaders_hook();
    install_set_water_shader_underwater_hook();
    install_render_world_scene_graph_hook();
    install_render_first_person_hook();
    install_render_pre_depth_groups_hook();
}

pub(crate) fn underwater_publication_hook_ready() -> bool {
    UNDERWATER_PUBLICATION_HOOK_READY.load(Ordering::Acquire)
}

fn install_process_image_space_shaders_hook() {
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
        Ok(()) => log::info!(
            "[FNV] Pre-alpha atmosphere hook installed at 0x{RENDER_PRE_DEPTH_GROUPS_ADDR:08X}"
        ),
        Err(err) => log::warn!(
            "[FNV] Pre-alpha atmosphere hook skipped at 0x{RENDER_PRE_DEPTH_GROUPS_ADDR:08X}: {err}"
        ),
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
            .filter(|_| crate::fnv_world_pipeline::needs_atmosphere())
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
    unsafe { crate::fnv_world_pipeline::apply_before_alpha(device_ptr) };
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
    let jitter = unsafe {
        crate::fnv_world_pipeline::begin_temporal_aa_jitter(
            device_ptr,
            crate::effects::temporal_aa::TargetDescription::from(&desc),
        )?
    };
    unsafe { crate::backend::jitter_fnv_world_camera(jitter, desc.Width, desc.Height) }
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

    let depth_provider = crate::backend::DepthProvider::FalloutNewVegas;
    match unsafe {
        crate::backend::resolve_scene_depth(
            depth_provider,
            device_ptr,
            source_rendered_texture,
            slot,
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
        PROCESS_IMAGE_SPACE_SHADERS_ADDR, ProcessImageSpaceShadersFn, run_image_space_phase_order,
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
}

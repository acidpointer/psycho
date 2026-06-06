//! FalloutNV render-stage hooks.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicU32, Ordering},
    },
};

use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

const PROCESS_IMAGE_SPACE_SHADERS_ADDR: usize = 0x00B55AC0;
const RENDER_WORLD_SCENE_GRAPH_ADDR: usize = 0x00873200;
const RENDER_FIRST_PERSON_ADDR: usize = 0x00875110;

const MAX_HOOK_ERROR_LOGS: u32 = 8;
const MAX_DEPTH_CAPTURE_LOGS: u32 = 16;
const MAX_FINAL_APPLY_LOGS: u32 = 16;

type ProcessImageSpaceShadersFn = unsafe extern "cdecl" fn(*mut c_void, *mut c_void, *mut c_void);
type RenderWorldSceneGraphFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8, u8, u8);
type RenderFirstPersonFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void);

static PROCESS_IMAGE_SPACE_SHADERS_HOOK: LazyLock<InlineHookContainer<ProcessImageSpaceShadersFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_WORLD_SCENE_GRAPH_HOOK: LazyLock<InlineHookContainer<RenderWorldSceneGraphFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_FIRST_PERSON_HOOK: LazyLock<InlineHookContainer<RenderFirstPersonFn>> =
    LazyLock::new(InlineHookContainer::new);

static HOOK_ERROR_LOGS: AtomicU32 = AtomicU32::new(0);
static DEPTH_CAPTURE_LOGS: AtomicU32 = AtomicU32::new(0);
static FINAL_APPLY_LOGS: AtomicU32 = AtomicU32::new(0);

pub(crate) fn install_scene_boundary_hook() {
    install_process_image_space_shaders_hook();
    install_render_world_scene_graph_hook();
    install_render_first_person_hook();
}

fn install_process_image_space_shaders_hook() {
    match PROCESS_IMAGE_SPACE_SHADERS_HOOK.init(
        "FNV ProcessImageSpaceShaders",
        PROCESS_IMAGE_SPACE_SHADERS_ADDR as *mut c_void,
        hook_process_image_space_shaders,
    ) {
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

fn install_render_world_scene_graph_hook() {
    match RENDER_WORLD_SCENE_GRAPH_HOOK.init(
        "FNV RenderWorldSceneGraph",
        RENDER_WORLD_SCENE_GRAPH_ADDR as *mut c_void,
        hook_render_world_scene_graph,
    ) {
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
    match RENDER_FIRST_PERSON_HOOK.init(
        "FNV RenderFirstPerson",
        RENDER_FIRST_PERSON_ADDR as *mut c_void,
        hook_render_first_person,
    ) {
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
        original(renderer, rendered_texture_1, rendered_texture_2);
        if rendered_texture_2.is_null() {
            apply_final_image_space("FNV after image-space shaders");
        }
    }
}

unsafe extern "thiscall" fn hook_render_world_scene_graph(
    main: *mut c_void,
    sky_sun: *mut c_void,
    is_first_person: u8,
    wireframe: u8,
    arg4: u8,
) {
    let Ok(original) = RENDER_WORLD_SCENE_GRAPH_HOOK.original() else {
        log_hook_error("[FNV] Missing original RenderWorldSceneGraph function");
        return;
    };

    unsafe {
        original(main, sky_sun, is_first_person, wireframe, arg4);
        capture_depth(
            crate::backend::DepthResolveSlot::World,
            "FNV after world scene graph",
        );
        capture_world_color();
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

    unsafe {
        original(main, renderer, geo, sky_sun, rendered_texture);
        capture_depth(
            crate::backend::DepthResolveSlot::FirstPerson,
            "FNV after first-person depth",
        );
    }
}

unsafe fn capture_depth(slot: crate::backend::DepthResolveSlot, reason: &'static str) {
    if !crate::runtime::needs_fnv_depth_capture() {
        return;
    }

    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    let depth_provider = crate::backend::DepthProvider::FalloutNewVegas;
    if unsafe { crate::backend::resolve_scene_depth(depth_provider, device_ptr, slot, reason) } {
        log_depth_capture(slot, reason);
    }
}

unsafe fn capture_world_color() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    unsafe {
        crate::runtime::capture_fnv_world_color(device_ptr);
    }
}

unsafe fn apply_final_image_space(reason: &'static str) {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    log_final_apply(reason);
    unsafe {
        crate::runtime::apply_fnv_scene_frame(device_ptr);
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

fn log_final_apply(reason: &'static str) {
    if FINAL_APPLY_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_FINAL_APPLY_LOGS {
        log::debug!("[FNV] Screen-space shader trigger: {reason}");
    }
}

//! FalloutNV render-stage hooks.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicU32, Ordering},
    },
};

use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer, memory::read_bytes, winapi::patch_bytes,
};

const PROCESS_IMAGE_SPACE_SHADERS_ADDR: usize = 0x00B55AC0;
const RENDER_WORLD_SCENE_GRAPH_ADDR: usize = 0x00873200;
const RENDER_FIRST_PERSON_ADDR: usize = 0x00875110;
const FIRST_PERSON_SETUP_AFTER_DEPTH_CLEAR_ADDR: usize = 0x00874C10;
const FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR: usize = 0x008751C0;

const MAX_HOOK_ERROR_LOGS: u32 = 8;
const MAX_DEPTH_CAPTURE_LOGS: u32 = 16;
const MAX_FINAL_APPLY_LOGS: u32 = 16;

const FIRST_PERSON_CLEAR_MODE_DISABLED: u32 = 0;
const FIRST_PERSON_CLEAR_MODE_OWNED: u32 = 1;
const FIRST_PERSON_CLEAR_MODE_EXTERNAL_NEUTRALIZED: u32 = 2;

type ProcessImageSpaceShadersFn = unsafe extern "cdecl" fn(*mut c_void, *mut c_void, *mut c_void);
type RenderWorldSceneGraphFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8, u8, u8);
type RenderFirstPersonFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void);
type FirstPersonSetupFn = unsafe extern "thiscall" fn(*mut c_void);

static PROCESS_IMAGE_SPACE_SHADERS_HOOK: LazyLock<InlineHookContainer<ProcessImageSpaceShadersFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_WORLD_SCENE_GRAPH_HOOK: LazyLock<InlineHookContainer<RenderWorldSceneGraphFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_FIRST_PERSON_HOOK: LazyLock<InlineHookContainer<RenderFirstPersonFn>> =
    LazyLock::new(InlineHookContainer::new);

static FIRST_PERSON_CLEAR_MODE: AtomicU32 = AtomicU32::new(FIRST_PERSON_CLEAR_MODE_DISABLED);
static HOOK_ERROR_LOGS: AtomicU32 = AtomicU32::new(0);
static FIRST_PERSON_CLEAR_PATCH_LOGS: AtomicU32 = AtomicU32::new(0);
static DEPTH_CAPTURE_LOGS: AtomicU32 = AtomicU32::new(0);
static FINAL_APPLY_LOGS: AtomicU32 = AtomicU32::new(0);

pub(crate) fn install_scene_boundary_hook() {
    inspect_first_person_depth_clear();
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

fn inspect_first_person_depth_clear() {
    let bytes = match read_bytes(FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR as *const c_void, 1) {
        Ok(bytes) => bytes,
        Err(err) => {
            log_first_person_clear_patch_failure(err);
            return;
        }
    };

    let Some(current) = bytes.first().copied() else {
        log::warn!(
            "[FNV] First-person depth clear patch skipped at 0x{FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR:08X}: empty read"
        );
        return;
    };

    if current == 0 {
        FIRST_PERSON_CLEAR_MODE.store(
            FIRST_PERSON_CLEAR_MODE_EXTERNAL_NEUTRALIZED,
            Ordering::Release,
        );
        log::info!(
            "[FNV] First-person depth clear already neutralized by existing code at 0x{FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR:08X}"
        );
        return;
    }

    if current != 4 {
        log::warn!(
            "[FNV] First-person depth clear patch skipped at 0x{FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR:08X}: unexpected byte 0x{current:02X}"
        );
        return;
    }

    FIRST_PERSON_CLEAR_MODE.store(FIRST_PERSON_CLEAR_MODE_OWNED, Ordering::Release);
    log::info!(
        "[FNV] First-person depth clear will be neutralized only during FNV depth captures at 0x{FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR:08X}"
    );
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
        if is_first_person == 0 {
            capture_depth("FNV after world scene graph");
        }
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
        let clear_mode = FIRST_PERSON_CLEAR_MODE.load(Ordering::Acquire);
        if clear_mode == FIRST_PERSON_CLEAR_MODE_DISABLED {
            original(main, renderer, geo, sky_sun, rendered_texture);
            return;
        }

        if !crate::runtime::needs_fnv_depth_capture() {
            if clear_mode == FIRST_PERSON_CLEAR_MODE_OWNED {
                let _ = set_first_person_depth_clear_arg(4);
            }
            original(main, renderer, geo, sky_sun, rendered_texture);
            return;
        }

        if clear_mode == FIRST_PERSON_CLEAR_MODE_OWNED {
            if !set_first_person_depth_clear_arg(0) {
                original(main, renderer, geo, sky_sun, rendered_texture);
                return;
            }
        }

        original(main, renderer, geo, sky_sun, rendered_texture);

        capture_depth("FNV after first-person depth");
        clear_depth_for_first_person_redraw();
        setup_first_person_after_depth_clear(main);
        original(main, renderer, geo, sky_sun, rendered_texture);

        if clear_mode == FIRST_PERSON_CLEAR_MODE_OWNED {
            let _ = set_first_person_depth_clear_arg(4);
        }
    }
}

unsafe fn set_first_person_depth_clear_arg(value: u8) -> bool {
    match unsafe { patch_bytes(FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR as *mut c_void, &[value]) } {
        Ok(()) => true,
        Err(err) => {
            log_first_person_clear_patch_failure(err);
            false
        }
    }
}

unsafe fn capture_depth(reason: &'static str) {
    if !crate::runtime::needs_fnv_depth_capture() {
        return;
    }

    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    let depth_provider = crate::backend::DepthProvider::FalloutNewVegas;
    if unsafe { crate::backend::resolve_scene_depth(depth_provider, device_ptr, reason) } {
        log_depth_capture(reason);
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

unsafe fn clear_depth_for_first_person_redraw() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };

    let Some(device) =
        (unsafe { libpsycho::os::windows::directx9::Device9Ref::from_raw_void(device_ptr) })
    else {
        return;
    };

    if let Err(err) = device.clear_zbuffer() {
        log::warn!("[FNV] First-person depth redraw clear failed: {err}");
    }
}

unsafe fn setup_first_person_after_depth_clear(main: *mut c_void) {
    if main.is_null() {
        return;
    }

    let setup: FirstPersonSetupFn =
        unsafe { core::mem::transmute(FIRST_PERSON_SETUP_AFTER_DEPTH_CLEAR_ADDR as *const ()) };
    unsafe {
        setup(main);
    }
}

fn log_hook_error(message: &'static str) {
    if HOOK_ERROR_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_HOOK_ERROR_LOGS {
        log::warn!("{message}");
    }
}

fn log_first_person_clear_patch_failure(err: impl core::fmt::Display) {
    if FIRST_PERSON_CLEAR_PATCH_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_HOOK_ERROR_LOGS {
        log::warn!(
            "[FNV] First-person depth clear patch skipped at 0x{FIRST_PERSON_DEPTH_CLEAR_ARG_ADDR:08X}: {err}"
        );
    }
}

fn log_depth_capture(reason: &'static str) {
    if DEPTH_CAPTURE_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_DEPTH_CAPTURE_LOGS {
        log::debug!("[FNV] Depth capture trigger: {reason}");
    }
}

fn log_final_apply(reason: &'static str) {
    if FINAL_APPLY_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_FINAL_APPLY_LOGS {
        log::debug!("[FNV] Screen-space shader trigger: {reason}");
    }
}

//! Engine-owned render lifecycle hooks for OMV.
//!
//! OMV never rewrites the live `IDirect3DDevice9` vtable. Driver-owned COM
//! entries are shared by the game, compatibility layers, overlays, and vendor
//! runtimes; replacing them made every native draw and presentation traverse
//! OMV and created an especially expensive ownership conflict on NVIDIA.
//!
//! Fallout New Vegas already provides the three serialized boundaries OMV
//! needs:
//!
//! - `NiDX9Renderer::DisplayScene` brackets the engine's presentation work;
//! - `NiDX9Renderer::Recreate` owns device-loss/reset notification ordering;
//! - the common `NiDX9Shader` draw method brackets shader-backed native draws.
//!
//! These entry hooks patch game code once at `DeferredInit`, retain stable
//! trampolines, and stay resident. Runtime feature switches are cheap atomic
//! gates inside OMV; they never mutate driver-owned state or executable bytes
//! from a render callback. The separate Win32 WndProc hook remains necessary
//! for menu input and is unrelated to D3D device ownership.

use core::ffi::c_void;
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use crate::{
    backend,
    effects::{pbr, sky},
    runtime,
};
use anyhow::{Context, Result};
use libpsycho::os::windows::{
    directx9::Device9Ref,
    hook::inline::inlinehook::InlineHookContainer,
    winapi::{call_window_proc_a, set_window_long_a},
};

// Addresses and ABIs are for FalloutNV.exe 1.4.0.525, SHA-256
// 42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c.
// `DisplayScene` returns AL=1 after draining the renderer's display queue.
const DISPLAY_SCENE_ADDR: usize = 0x00E7_5000;
// `Recreate` returns 0 on failure, 1 for recovery parameters, and 2 for the
// caller-requested parameters. Both reset attempts and engine notifications
// are inside this function, so OMV releases resources before entering it.
const RECREATE_ADDR: usize = 0x00E7_3EB0;
// PPLighting and Sky shader vtables both publish this method at slot +0x6C.
// It is after the engine selected a shader/pass and immediately surrounds the
// native draw, which is the ownership boundary required by PBR and sky.
const COMMON_SHADER_DRAW_ADDR: usize = 0x00E8_12F0;
const NIDX9_RENDERER_DEVICE_OFFSET: usize = 0x288;
const GWL_WNDPROC: i32 = -4;
const MAX_HOOK_ERROR_LOGS: u32 = 8;

type DisplaySceneFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;
type RecreateFn = unsafe extern "thiscall" fn(*mut c_void, u32, u32) -> u32;
type CommonShaderDrawFn =
    unsafe extern "thiscall" fn(*mut c_void, usize, usize, usize, usize) -> usize;

static DISPLAY_SCENE_HOOK: LazyLock<InlineHookContainer<DisplaySceneFn>> =
    LazyLock::new(InlineHookContainer::new);
static RECREATE_HOOK: LazyLock<InlineHookContainer<RecreateFn>> =
    LazyLock::new(InlineHookContainer::new);
static COMMON_SHADER_DRAW_HOOK: LazyLock<InlineHookContainer<CommonShaderDrawFn>> =
    LazyLock::new(InlineHookContainer::new);

static ENGINE_HOOKS_READY: AtomicBool = AtomicBool::new(false);
static RENDER_EPOCH: AtomicU32 = AtomicU32::new(1);
static HOOK_ERROR_LOGS: AtomicU32 = AtomicU32::new(0);
static ORIGINAL_WNDPROC: AtomicUsize = AtomicUsize::new(0);
static WNDPROC_HWND: AtomicUsize = AtomicUsize::new(0);

/// Return the current serialized render epoch.
pub(crate) fn render_epoch() -> u32 {
    RENDER_EPOCH.load(Ordering::Acquire)
}

fn advance_render_epoch(epoch: &AtomicU32) {
    epoch.fetch_add(1, Ordering::AcqRel);
}

/// Install OMV's engine-owned presentation, reset, and native-draw hooks.
///
/// This must run from xNVSE `DeferredInit`, after the executable image is
/// stable and before render callbacks can publish OMV work. Repeated calls are
/// retry-safe: prepared trampolines are reused and only missing entry jumps
/// are enabled.
pub(crate) fn install_engine_hooks() -> Result<()> {
    prepare_display_scene_hook()?;
    prepare_recreate_hook()?;
    prepare_common_shader_draw_hook()?;

    enable_prepared_hook(&DISPLAY_SCENE_HOOK, "NiDX9Renderer::DisplayScene")?;
    enable_prepared_hook(&RECREATE_HOOK, "NiDX9Renderer::Recreate")?;
    enable_prepared_hook(&COMMON_SHADER_DRAW_HOOK, "common NiDX9Shader draw")?;

    let ready = DISPLAY_SCENE_HOOK.is_enabled()
        && RECREATE_HOOK.is_enabled()
        && COMMON_SHADER_DRAW_HOOK.is_enabled();
    ENGINE_HOOKS_READY.store(ready, Ordering::Release);
    pbr::set_draw_boundary_ready(ready);
    sky::set_draw_boundary_ready(ready);
    if !ready {
        anyhow::bail!("one or more engine render hooks are not active");
    }

    if let Some(device_ptr) = backend::d3d_device_ptr()
        && let Some(device) = unsafe { Device9Ref::from_raw_void(device_ptr) }
    {
        log_presentation_profile(&device, "engine-hook-install");
    }
    log::info!(
        "[HOOKS] Engine-owned DisplayScene, Recreate, and common shader draw hooks installed"
    );
    Ok(())
}

fn prepare_display_scene_hook() -> Result<()> {
    if DISPLAY_SCENE_HOOK.is_initialized() {
        return Ok(());
    }
    unsafe {
        DISPLAY_SCENE_HOOK.init(
            "FNV NiDX9Renderer::DisplayScene",
            DISPLAY_SCENE_ADDR as *mut c_void,
            display_scene_detour,
        )
    }
    .context("could not prepare NiDX9Renderer::DisplayScene hook")
}

fn prepare_recreate_hook() -> Result<()> {
    if RECREATE_HOOK.is_initialized() {
        return Ok(());
    }
    unsafe {
        RECREATE_HOOK.init(
            "FNV NiDX9Renderer::Recreate",
            RECREATE_ADDR as *mut c_void,
            recreate_detour,
        )
    }
    .context("could not prepare NiDX9Renderer::Recreate hook")
}

fn prepare_common_shader_draw_hook() -> Result<()> {
    if COMMON_SHADER_DRAW_HOOK.is_initialized() {
        return Ok(());
    }
    unsafe {
        COMMON_SHADER_DRAW_HOOK.init(
            "FNV common NiDX9Shader draw",
            COMMON_SHADER_DRAW_ADDR as *mut c_void,
            common_shader_draw_detour,
        )
    }
    .context("could not prepare common NiDX9Shader draw hook")
}

fn enable_prepared_hook<T: libpsycho::ffi::fnptr::Function>(
    hook: &InlineHookContainer<T>,
    label: &'static str,
) -> Result<()> {
    if hook.is_enabled() {
        return Ok(());
    }
    hook.enable()
        .with_context(|| format!("could not enable {label} hook"))
}

/// Return a stable diagnostic label for native draw ownership.
pub(crate) fn draw_interposition_status_label() -> &'static str {
    if ENGINE_HOOKS_READY.load(Ordering::Acquire) {
        "engine-owned"
    } else {
        "unavailable"
    }
}

/// Install the Win32 menu-input hook for the active game window.
pub(crate) fn install_window_proc(hwnd: *mut c_void) -> Result<()> {
    if hwnd.is_null() {
        anyhow::bail!("null HWND");
    }

    let installed_hwnd = WNDPROC_HWND.load(Ordering::Acquire);
    if installed_hwnd == hwnd as usize {
        return Ok(());
    }
    if installed_hwnd != 0 {
        anyhow::bail!("WndProc hook already installed for another HWND");
    }

    let previous = set_window_long_a(
        hwnd,
        GWL_WNDPROC,
        wndproc_detour as *const () as usize as i32,
    );
    if previous == 0 {
        anyhow::bail!("SetWindowLongA(GWL_WNDPROC) returned null previous WndProc");
    }

    ORIGINAL_WNDPROC.store(previous as usize, Ordering::Release);
    WNDPROC_HWND.store(hwnd as usize, Ordering::Release);
    log::info!("[HOOKS] Win32 WndProc hook installed");
    Ok(())
}

unsafe extern "thiscall" fn display_scene_detour(renderer: *mut c_void) -> u8 {
    let Ok(original) = DISPLAY_SCENE_HOOK.original() else {
        log_hook_error("[HOOKS] Missing original NiDX9Renderer::DisplayScene function");
        return 0;
    };
    let render_epoch = render_epoch();
    if let Some(device_ptr) = unsafe { renderer_device(renderer) }
        && runtime::present_services_required()
    {
        pbr::finish_draw_batches();
        sky::finish_direct_draw();
        sky::service_present_frame();
        unsafe { runtime::apply_present_frame(device_ptr, core::ptr::null_mut()) };
    }
    let present_started_at = runtime::present_frame_started_at();
    let result = unsafe { original(renderer) };
    unsafe { runtime::finish_present_frame(render_epoch, present_started_at, result != 0) };
    crate::fnv_world_pipeline::finish_present(render_epoch);
    advance_render_epoch(&RENDER_EPOCH);
    result
}

unsafe extern "thiscall" fn recreate_detour(
    renderer: *mut c_void,
    request_a: u32,
    request_b: u32,
) -> u32 {
    let Ok(original) = RECREATE_HOOK.original() else {
        log_hook_error("[HOOKS] Missing original NiDX9Renderer::Recreate function");
        return 0;
    };
    let Some(device_ptr) = (unsafe { renderer_device(renderer) }) else {
        return unsafe { original(renderer, request_a, request_b) };
    };
    if !unsafe { runtime::try_release_device_resources(device_ptr) } {
        // Recreate's native failure value is zero. Returning an HRESULT here
        // would violate the engine ABI and could make the caller treat a busy
        // OMV resource owner as a successful reset mode.
        return 0;
    }
    pbr::reset_runtime_state();
    sky::reset_runtime_state();
    let result = unsafe { original(renderer, request_a, request_b) };
    if result != 0
        && let Some(active_device) = unsafe { renderer_device(renderer) }
        && let Some(device) = unsafe { Device9Ref::from_raw_void(active_device) }
    {
        log_presentation_profile(&device, "engine-recreate");
    }
    result
}

unsafe extern "thiscall" fn common_shader_draw_detour(
    shader: *mut c_void,
    argument_a: usize,
    argument_b: usize,
    argument_c: usize,
    result_cookie: usize,
) -> usize {
    let Ok(original) = COMMON_SHADER_DRAW_HOOK.original() else {
        log_hook_error("[HOOKS] Missing original common NiDX9Shader draw function");
        return result_cookie;
    };
    if !runtime::effects_enabled() {
        return unsafe { original(shader, argument_a, argument_b, argument_c, result_cookie) };
    }

    let pbr_draw = pbr::prepare_direct_draw();
    let sky_draw = sky::prepare_direct_draw();
    let result = unsafe { original(shader, argument_a, argument_b, argument_c, result_cookie) };
    if sky_draw {
        sky::finish_direct_draw();
    }
    pbr::finish_direct_draw(pbr_draw);
    result
}

/// Read the device owned by this exact renderer invocation.
///
/// Using the receiver avoids racing a singleton publication during Recreate.
/// The executable layout proves the device pointer at `NiDX9Renderer+0x288`;
/// `Device9Ref` performs the COM-interface validation before any method call.
unsafe fn renderer_device(renderer: *mut c_void) -> Option<*mut c_void> {
    if renderer.is_null() {
        return None;
    }
    let device = unsafe {
        *(renderer
            .byte_add(NIDX9_RENDERER_DEVICE_OFFSET)
            .cast::<*mut c_void>())
    };
    unsafe { Device9Ref::from_raw_void(device) }.map(|validated| validated.as_raw())
}

fn log_presentation_profile(device: &Device9Ref<'_>, boundary: &'static str) {
    let Ok(parameters) = device.presentation_parameters() else {
        log::warn!("[D3D] Could not query presentation parameters at {boundary}");
        return;
    };
    log::info!(
        "[D3D] Presentation at {}: mode={}, backbuffer={}x{} format={} count={} msaa={}/quality={} swap={} refresh_hz={} interval=0x{:08X} available_texture_mem_mib={}",
        boundary,
        if parameters.Windowed.as_bool() {
            "windowed"
        } else {
            "fullscreen"
        },
        parameters.BackBufferWidth,
        parameters.BackBufferHeight,
        parameters.BackBufferFormat.0,
        parameters.BackBufferCount,
        parameters.MultiSampleType.0,
        parameters.MultiSampleQuality,
        parameters.SwapEffect.0,
        parameters.FullScreen_RefreshRateInHz,
        parameters.PresentationInterval,
        device.available_texture_mem() / (1024 * 1024),
    );
}

fn log_hook_error(message: &'static str) {
    if HOOK_ERROR_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_HOOK_ERROR_LOGS {
        log::warn!("{message}");
    }
}

unsafe extern "system" fn wndproc_detour(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    if let Some(result) = runtime::handle_window_message(hwnd, msg, wparam, lparam) {
        return result;
    }
    unsafe { call_original_wndproc(hwnd, msg, wparam, lparam) }
}

unsafe fn call_original_wndproc(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    let original = ORIGINAL_WNDPROC.load(Ordering::Acquire);
    if original == 0 {
        return 0;
    }
    unsafe { call_window_proc_a(original as *mut c_void, hwnd, msg, wparam, lparam) }
}

#[cfg(test)]
mod tests {
    use super::advance_render_epoch;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn presentation_epoch_advances_without_runtime_ownership() {
        let epoch = AtomicU32::new(41);
        advance_render_epoch(&epoch);
        assert_eq!(epoch.load(Ordering::Acquire), 42);
    }

    #[test]
    fn d3d_lifecycle_never_mutates_a_live_device_vtable() {
        let source = include_str!("hooks.rs");
        let vmt_hook = ["Vmt", "Hook"].concat();
        let device_vtable_constant = ["DEVICE9_", "VTBL_"].concat();
        let device_present = ["IDirect3DDevice9", "::Present"].concat();
        let device_reset = ["IDirect3DDevice9", "::Reset"].concat();
        assert!(!source.contains(&vmt_hook));
        assert!(!source.contains(&device_vtable_constant));
        assert!(!source.contains(&device_present));
        assert!(!source.contains(&device_reset));
        assert!(source.contains("DISPLAY_SCENE_ADDR"));
        assert!(source.contains("RECREATE_ADDR"));
        assert!(source.contains("COMMON_SHADER_DRAW_ADDR"));
    }

    #[test]
    fn display_scene_services_omv_before_engine_presentation() {
        let source = include_str!("hooks.rs");
        let body = source
            .split_once("unsafe extern \"thiscall\" fn display_scene_detour")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("unsafe extern \"thiscall\" fn recreate_detour"))
            .map(|(body, _)| body)
            .expect("DisplayScene detour body");
        let apply = body
            .find("runtime::apply_present_frame")
            .expect("OMV presentation service");
        let native = body
            .find("original(renderer)")
            .expect("engine presentation");
        let finish = body
            .find("runtime::finish_present_frame")
            .expect("OMV presentation completion");
        assert!(apply < native);
        assert!(native < finish);
    }

    #[test]
    fn common_engine_draw_closes_replacement_scopes_after_native_draw() {
        let source = include_str!("hooks.rs");
        let body = source
            .split_once("unsafe extern \"thiscall\" fn common_shader_draw_detour")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("unsafe fn renderer_device"))
            .map(|(body, _)| body)
            .expect("common shader draw body");
        let prepare = body
            .find("pbr::prepare_direct_draw")
            .expect("PBR preparation");
        let native = body[prepare..]
            .find("original(shader")
            .map(|offset| prepare + offset)
            .expect("native draw");
        let finish = body.find("pbr::finish_direct_draw").expect("PBR cleanup");
        assert!(prepare < native);
        assert!(native < finish);
    }
}

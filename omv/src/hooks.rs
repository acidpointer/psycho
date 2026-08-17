//! Engine-owned render lifecycle hooks for OMV.
//!
//! OMV never rewrites the live `IDirect3DDevice9` vtable. Driver-owned COM
//! entries are shared by the game, compatibility layers, overlays, and vendor
//! runtimes; replacing them made every native draw and presentation traverse
//! OMV and created an especially expensive ownership conflict on NVIDIA.
//!
//! Fallout New Vegas and xNVSE provide the serialized boundaries OMV needs:
//!
//! - xNVSE `OnFramePresent` runs immediately before final presentation;
//! - the proven `NiDX9Renderer::Recreate` caller owns device-loss/reset order;
//! - live renderer vtable slots for `RenderTriShape` and `RenderTriStrips` own
//!   the actual primitive submissions used by PPLighting and native sky.
//!
//! `NiD3DShader::SetupGeometry @ 0x00E812F0` is deliberately not hooked. It
//! binds streams and indices through D3D9 but returns before the geometry
//! virtual dispatch reaches the renderer methods containing `DrawPrimitive`
//! and `DrawIndexedPrimitive`. Treating it as a draw caused OMV to restore a
//! rejected/replacement pair before the primitive that consumed it.
//!
//! OMV chains the predecessor present in each proven caller or live engine
//! dispatch slot at `DeferredInit`; it no longer claims the shared function
//! entries. Runtime feature switches are cheap atomic gates and never mutate
//! driver-owned state or executable bytes from a render callback. The separate
//! Win32 WndProc hook remains necessary for menu input and is unrelated to D3D
//! device ownership.

use core::{ffi::c_void, mem::size_of};
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
    hook::{
        callsite::Rel32CallHookContainer, pointer::PointerSlotHookContainer,
        transaction::ModificationTransaction,
    },
    memory::validate_memory_range,
    winapi::{call_window_proc_a, set_window_long_a},
};

// Addresses and ABIs are for FalloutNV.exe 1.4.0.525, SHA-256
// 42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c.
// `Recreate` returns 0 on failure, 1 for recovery parameters, and 2 for the
// caller-requested parameters. Both reset attempts and engine notifications
// are inside this function. OMV redirects its one proven direct caller rather
// than claiming the shared implementation at 0x00E73EB0.
const RECREATE_CALL_ADDR: usize = 0x004D_C41F;
// NiTriShape::RenderImmediate dispatches here through NiDX9Renderer vtable
// slot +0x1B4. The function owns every direct DrawPrimitive/DIP for the shape.
const RENDER_TRI_SHAPE_VTABLE_OFFSET: usize = 0x1B4;
// NiTriStrips::RenderImmediate dispatches here through renderer slot +0x1B8.
const RENDER_TRI_STRIPS_VTABLE_OFFSET: usize = 0x1B8;
const NIDX9_RENDERER_DEVICE_OFFSET: usize = 0x288;
const GWL_WNDPROC: i32 = -4;
const MAX_HOOK_ERROR_LOGS: u32 = 8;

type RecreateFn = unsafe extern "thiscall" fn(*mut c_void, u32, u32) -> u32;
type RenderGeometryFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

static RECREATE_HOOK: LazyLock<Rel32CallHookContainer<RecreateFn>> =
    LazyLock::new(Rel32CallHookContainer::new);
static RENDER_TRI_SHAPE_HOOK: LazyLock<PointerSlotHookContainer<RenderGeometryFn>> =
    LazyLock::new(PointerSlotHookContainer::new);
static RENDER_TRI_STRIPS_HOOK: LazyLock<PointerSlotHookContainer<RenderGeometryFn>> =
    LazyLock::new(PointerSlotHookContainer::new);

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

/// Install OMV's reset caller and optional native-draw dispatch slots.
///
/// Presentation is owned by the already-registered xNVSE `OnFramePresent`
/// listener. Reset is essential and therefore fails installation if its unique
/// caller cannot be chained. Geometry is an independent optional capability:
/// a conflict disables PBR/sky draw replacement without suppressing the rest
/// of OMV's screen-space pipeline.
pub(crate) fn install_engine_hooks() -> Result<()> {
    prepare_recreate_hook()?;
    if !RECREATE_HOOK.is_enabled() {
        let mut reset_transaction = ModificationTransaction::new();
        reset_transaction
            .enable_callsite(&RECREATE_HOOK)
            .context("could not chain the NiDX9Renderer::Recreate caller")?;
        reset_transaction.commit();
    }

    let geometry_ready = install_geometry_slots();
    ENGINE_HOOKS_READY.store(geometry_ready, Ordering::Release);
    pbr::set_draw_boundary_ready(geometry_ready);
    sky::set_draw_boundary_ready(geometry_ready);

    if let Some(device_ptr) = backend::d3d_device_ptr()
        && let Some(device) = unsafe { Device9Ref::from_raw_void(device_ptr) }
    {
        log_presentation_profile(&device, "engine-hook-install");
    }
    log::info!("[HOOKS] Recreate direct caller chained");
    if geometry_ready {
        log::info!("[HOOKS] Live RenderTriShape/RenderTriStrips vtable slots chained");
    } else {
        log::warn!(
            "[HOOKS] Geometry dispatch unavailable; PBR and native-sky draw replacement remain disabled"
        );
    }
    Ok(())
}

fn prepare_recreate_hook() -> Result<()> {
    if RECREATE_HOOK.is_initialized() {
        return Ok(());
    }
    unsafe {
        RECREATE_HOOK.init(
            "FNV NiDX9Renderer::Recreate caller",
            RECREATE_CALL_ADDR as *mut c_void,
            recreate_detour,
        )
    }
    .context("could not prepare the NiDX9Renderer::Recreate direct caller")
}

fn install_geometry_slots() -> bool {
    if RENDER_TRI_SHAPE_HOOK.is_enabled() && RENDER_TRI_STRIPS_HOOK.is_enabled() {
        return true;
    }
    if let Err(error) = prepare_geometry_slots() {
        log::warn!("[HOOKS] Geometry slot preflight failed: {error:#}");
        return false;
    }

    let mut transaction = ModificationTransaction::new();
    if let Err(error) = transaction.enable_pointer(&RENDER_TRI_SHAPE_HOOK) {
        log::warn!("[HOOKS] RenderTriShape slot activation failed: {error}");
        return false;
    }
    if let Err(error) = transaction.enable_pointer(&RENDER_TRI_STRIPS_HOOK) {
        log::warn!("[HOOKS] RenderTriStrips slot activation failed: {error}");
        return false;
    }
    transaction.commit();
    true
}

fn prepare_geometry_slots() -> Result<()> {
    let renderer = backend::renderer_ptr().map_err(anyhow::Error::msg)?;
    let vtable = read_non_null_pointer(renderer.cast_const(), "NiDX9Renderer vtable")?;

    if !RENDER_TRI_SHAPE_HOOK.is_initialized() {
        let slot = vtable_slot(vtable, RENDER_TRI_SHAPE_VTABLE_OFFSET, "RenderTriShape")?;
        unsafe {
            RENDER_TRI_SHAPE_HOOK.init(
                "FNV NiDX9Renderer::RenderTriShape slot",
                slot,
                render_tri_shape_detour,
            )
        }
        .context("could not prepare RenderTriShape vtable slot")?;
    }
    if !RENDER_TRI_STRIPS_HOOK.is_initialized() {
        let slot = vtable_slot(vtable, RENDER_TRI_STRIPS_VTABLE_OFFSET, "RenderTriStrips")?;
        unsafe {
            RENDER_TRI_STRIPS_HOOK.init(
                "FNV NiDX9Renderer::RenderTriStrips slot",
                slot,
                render_tri_strips_detour,
            )
        }
        .context("could not prepare RenderTriStrips vtable slot")?;
    }
    Ok(())
}

fn vtable_slot(
    vtable: *mut c_void,
    offset: usize,
    label: &'static str,
) -> Result<*mut *mut c_void> {
    let address = (vtable as usize)
        .checked_add(offset)
        .with_context(|| format!("{label} vtable slot address overflowed"))?;
    let slot = address as *mut *mut c_void;
    validate_memory_range(slot.cast(), size_of::<*mut c_void>())
        .with_context(|| format!("could not read {label} vtable slot at 0x{address:08X}"))?;
    Ok(slot)
}

fn read_non_null_pointer(address: *const c_void, label: &'static str) -> Result<*mut c_void> {
    validate_memory_range(address, size_of::<*mut c_void>())
        .with_context(|| format!("could not read {label} at {address:p}"))?;
    let value = unsafe { address.cast::<*mut c_void>().read() };
    if value.is_null() {
        anyhow::bail!("{label} is null");
    }
    Ok(value)
}

/// Return a stable diagnostic label for native draw ownership.
pub(crate) fn draw_interposition_status_label() -> &'static str {
    if ENGINE_HOOKS_READY.load(Ordering::Acquire) {
        "engine-owned"
    } else {
        "unavailable"
    }
}

/// Read-only ownership evidence for the diagnostics UI and DeferredInit log.
///
/// Captured addresses explain which predecessor OMV chains, but no rendering
/// decision depends on an address or its containing module.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EngineHookInteropStatus {
    pub(crate) reset_ready: bool,
    pub(crate) reset_predecessor: Option<usize>,
    pub(crate) geometry_ready: bool,
    pub(crate) geometry_predecessors: [Option<usize>; 2],
}

pub(crate) fn interoperability_status() -> EngineHookInteropStatus {
    EngineHookInteropStatus {
        reset_ready: RECREATE_HOOK.is_enabled(),
        reset_predecessor: RECREATE_HOOK.predecessor_address().ok(),
        geometry_ready: ENGINE_HOOKS_READY.load(Ordering::Acquire),
        geometry_predecessors: [
            RENDER_TRI_SHAPE_HOOK.predecessor_address().ok(),
            RENDER_TRI_STRIPS_HOOK.predecessor_address().ok(),
        ],
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

/// Service OMV at xNVSE's engine-owned final-presentation boundary.
///
/// `OnFramePresent` does not expose the later D3D present result. Reaching the
/// callback is therefore recorded as a continuous presentation boundary, not
/// as proof that a driver call succeeded. This retains frame/epoch ordering
/// without interposing either DisplayScene or the device's `Present` slot.
pub(crate) fn on_frame_present(loading_screen: bool) {
    if !crate::startup::deferred_graphics_ready() {
        return;
    }

    let render_epoch = render_epoch();
    let present_started_at = runtime::present_frame_started_at();
    if backend::d3d_device_ptr().is_none()
        && let Err(reason) = backend::publish_initial_d3d_device()
    {
        log_hook_error("[HOOKS] OnFramePresent could not republish the renderer device");
        log::debug!("[HOOKS] Renderer-device republish reason: {reason}");
    }
    // These are idempotent atomic fast paths when no draw is outstanding.
    // Closing them before optional services prevents a skipped UI/effect frame
    // from carrying replacement ownership into the engine's final display.
    pbr::finish_draw_batches();
    sky::finish_direct_draw();
    if let Some(device_ptr) = backend::d3d_device_ptr()
        && runtime::present_services_required()
    {
        sky::service_present_frame();
        unsafe { runtime::apply_present_frame(device_ptr, core::ptr::null_mut(), loading_screen) };
    }
    unsafe { runtime::finish_present_frame(render_epoch, present_started_at) };
    crate::fnv_world_pipeline::finish_present(render_epoch);
    if crate::graphics_diagnostics::seal_frame(render_epoch) {
        crate::graphics_diagnostics::log_latest_sample();
    }
    advance_render_epoch(&RENDER_EPOCH);
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
    if !crate::effects::shadows::reset_runtime_state()
        || !pbr::reset_runtime_state()
        || !sky::reset_runtime_state()
    {
        // Recreate's caller understands zero as a retryable failure. Every
        // owner that did reset can rebuild lazily on the next successful
        // lifecycle attempt; no still-owned default-pool object crosses reset.
        return 0;
    }
    if backend::clear_d3d_device().is_err() {
        // Recreate's caller already understands zero as a retryable failure.
        // Do not enter native reset while OMV still owns a device reference.
        return 0;
    }
    let result = unsafe { original(renderer, request_a, request_b) };
    if result != 0
        && let Some(active_device) = unsafe { renderer_device(renderer) }
    {
        if unsafe { backend::publish_d3d_device(active_device) }.is_ok()
            && let Some(device) = unsafe { Device9Ref::from_raw_void(active_device) }
        {
            log_presentation_profile(&device, "engine-recreate");
        }
    }
    result
}

unsafe extern "thiscall" fn render_tri_shape_detour(renderer: *mut c_void, geometry: *mut c_void) {
    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::TriShapeSubmission, 1);
    let _span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::TriShapeSubmission,
    );
    unsafe { render_geometry(&RENDER_TRI_SHAPE_HOOK, renderer, geometry, "RenderTriShape") };
}

unsafe extern "thiscall" fn render_tri_strips_detour(renderer: *mut c_void, geometry: *mut c_void) {
    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::TriStripsSubmission, 1);
    let _span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::TriStripsSubmission,
    );
    unsafe {
        render_geometry(
            &RENDER_TRI_STRIPS_HOOK,
            renderer,
            geometry,
            "RenderTriStrips",
        )
    };
}

/// Bracket one geometry renderer entry that owns the consuming primitives.
///
/// Native `SetShaders` and `SetupGeometry` have already run when this entry is
/// reached. The predecessor may submit several skin partitions, but every
/// primitive shares this geometry, sampler set, shader pair, and constant
/// block. One scope therefore preserves exact coverage without interposing the
/// driver-owned D3D9 vtable for each individual DIP.
unsafe fn render_geometry(
    hook: &PointerSlotHookContainer<RenderGeometryFn>,
    renderer: *mut c_void,
    geometry: *mut c_void,
    label: &'static str,
) {
    let Ok(original) = hook.original() else {
        log_hook_error(match label {
            "RenderTriShape" => "[HOOKS] Missing original RenderTriShape function",
            _ => "[HOOKS] Missing original RenderTriStrips function",
        });
        return;
    };
    if !runtime::effects_enabled() {
        unsafe { original(renderer, geometry) };
        return;
    }

    // UpdateConstants publishes the exact geometry that owns a sky pair. Give
    // that draw exclusive shader ownership; a stale sky callback must neither
    // consume an unrelated PBR draw nor overwrite its engine-owned pair.
    let sky_draw = sky::prepare_direct_draw(geometry);
    let pbr_draw = (!sky_draw)
        .then(|| pbr::prepare_direct_draw(geometry))
        .unwrap_or_default();
    unsafe { original(renderer, geometry) };
    if sky_draw {
        sky::finish_direct_draw();
    }
    pbr::finish_direct_draw(pbr_draw);
}

/// Submit one shadow-pass triangle geometry through the original renderer.
///
/// The normal OMV geometry detours are intentionally bypassed: PBR and sky
/// replacements describe the main color pass and must not overwrite the
/// shadow producer's dedicated shaders. The returned `false` means the
/// corresponding resident hook has no valid trampoline, in which case the
/// caller must abort replacement production and restore D3D state.
///
/// # Safety
///
/// `renderer` and `geometry` must be the live engine objects for the current
/// serialized render transaction. The caller must have bound valid shadow
/// shaders, constants, streams, indices, and declaration/FVF.
pub(crate) unsafe fn submit_shadow_geometry(
    renderer: *mut c_void,
    geometry: *mut c_void,
    strips: bool,
) -> bool {
    let hook = if strips {
        &RENDER_TRI_STRIPS_HOOK
    } else {
        &RENDER_TRI_SHAPE_HOOK
    };
    let Ok(original) = hook.original() else {
        return false;
    };
    unsafe { original(renderer, geometry) };
    true
}

/// Read the device owned by this exact renderer invocation.
///
/// Using the receiver avoids racing a singleton publication during Recreate.
/// The executable layout proves the device pointer at `NiDX9Renderer+0x288`;
/// `Device9Ref` supplies a typed non-owning borrow after the null check. Full
/// COM identity validation and retention occur only when lifecycle publication
/// observes a changed pointer.
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
    use super::{
        RecreateFn, RenderGeometryFn, advance_render_epoch, recreate_detour,
        render_tri_shape_detour, render_tri_strips_detour,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn presentation_epoch_advances_without_runtime_ownership() {
        let epoch = AtomicU32::new(41);
        advance_render_epoch(&epoch);
        assert_eq!(epoch.load(Ordering::Acquire), 42);
    }

    #[test]
    fn renderer_detours_use_the_executable_proven_x86_abis() {
        let _: RecreateFn = recreate_detour;
        let _: RenderGeometryFn = render_tri_shape_detour;
        let _: RenderGeometryFn = render_tri_strips_detour;
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
        assert!(!source.contains(&["DISPLAY_SCENE_", "ADDR"].concat()));
        assert!(source.contains("RECREATE_CALL_ADDR"));
        assert!(source.contains("RENDER_TRI_SHAPE_VTABLE_OFFSET"));
        assert!(source.contains("RENDER_TRI_STRIPS_VTABLE_OFFSET"));
        assert!(source.contains("Rel32CallHookContainer<RecreateFn>"));
        assert!(source.contains("PointerSlotHookContainer<RenderGeometryFn>"));
        assert!(!source.contains(&["0x00E7_", "5000"].concat()));
        assert!(!source.contains(&["0x00E7_", "3EB0"].concat()));
        assert!(!source.contains(&["0x00E7_", "45A0"].concat()));
        assert!(!source.contains(&["0x00E7_", "4840"].concat()));
        let obsolete_draw_owner = ["COMMON_SHADER", "_DRAW_ADDR"].concat();
        assert!(!source.contains(&obsolete_draw_owner));
    }

    #[test]
    fn frame_present_services_omv_and_completes_the_epoch() {
        let source = include_str!("hooks.rs");
        let body = source
            .split_once("pub(crate) fn on_frame_present")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("unsafe extern \"thiscall\" fn recreate_detour"))
            .map(|(body, _)| body)
            .expect("OnFramePresent body");
        let arrival = body
            .find("runtime::present_frame_started_at")
            .expect("presentation timing arrival");
        let apply = body
            .find("runtime::apply_present_frame")
            .expect("OMV presentation service");
        let finish = body
            .find("runtime::finish_present_frame")
            .expect("OMV presentation completion");
        let epoch = body.find("advance_render_epoch").expect("epoch completion");
        assert!(arrival < apply);
        assert!(apply < finish);
        assert!(finish < epoch);
        assert!(!body.contains("original(renderer)"));
    }

    #[test]
    fn recreate_releases_before_invoking_its_exact_predecessor() {
        let source = include_str!("hooks.rs");
        let body = source
            .split_once("unsafe extern \"thiscall\" fn recreate_detour")
            .and_then(|(_, tail)| {
                tail.split_once("unsafe extern \"thiscall\" fn render_tri_shape_detour")
            })
            .map(|(body, _)| body)
            .expect("Recreate caller wrapper");
        let release = body
            .find("runtime::try_release_device_resources")
            .expect("resource release");
        let native = body[release..]
            .find("original(renderer, request_a, request_b)")
            .map(|offset| release + offset)
            .expect("captured predecessor after resource release");
        let republish = body
            .find("backend::publish_d3d_device")
            .expect("device republish");
        assert!(release < native);
        assert!(native < republish);
    }

    #[test]
    fn renderer_geometry_draw_closes_replacement_scopes_after_native_submission() {
        let source = include_str!("hooks.rs");
        let body = source
            .split_once("unsafe fn render_geometry")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("unsafe fn renderer_device"))
            .map(|(body, _)| body)
            .expect("renderer geometry body");
        let prepare = body
            .find("pbr::prepare_direct_draw")
            .expect("PBR preparation");
        let native = body[prepare..]
            .find("original(renderer, geometry)")
            .map(|offset| prepare + offset)
            .expect("native geometry submission");
        let finish = body.find("pbr::finish_direct_draw").expect("PBR cleanup");
        assert!(prepare < native);
        assert!(native < finish);
    }
}

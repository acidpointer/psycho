//! Direct3D9 device-hook lifecycle for OMV.
//!
//! `Present` owns menu/config publication, `Reset` invalidates device
//! resources, and the optional draw hooks provide the exact native-draw
//! boundary required by PBR and sky replacement. The draw detours are prepared
//! once but physically detached when neither native replacement is enabled.
//! This matters on drivers where even a passive vtable detour on every draw is
//! measurable; the master switch therefore restores the original DP/DIP
//! entries instead of merely taking a cheap branch inside OMV.
//!
//! `SetRenderState` is prepared only when a compatible Depth Resolve is
//! present. Its vtable entry points at OMV only while OMV owns physical RESZ
//! production; selecting the external provider restores the original device
//! method. While attached, the detour distinguishes OMV's armed marker from
//! the external plugin's duplicate markers against the exact shared texture
//! identity. All live transitions occur at DeferredInit or Present, the
//! serialized render-thread boundaries where no hooked device call can be in
//! flight.

use std::{
    mem::size_of,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use crate::{
    backend,
    effects::{pbr, sky},
    runtime,
};
use anyhow::{Context, Result};
use core::ffi::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    hook::traits::Hook,
    os::windows::{
        directx9::{
            D3D_DEVICE_LOST_CODE, D3D_FAILURE_CODE, D3DRESZ_POINT_SIZE, D3DRS_POINTSIZE,
            DEVICE9_VTBL_PRESENT, DEVICE9_VTBL_RESET, DEVICE9_VTBL_SET_RENDER_STATE, Device9Ref,
        },
        hook::vmt::vmthook::VmtHook,
        winapi::{Rect, call_window_proc_a, set_window_long_a},
    },
};
use parking_lot::Mutex;

type PresentFn = unsafe extern "system" fn(
    *mut c_void,
    *const Rect,
    *const Rect,
    *mut c_void,
    *const c_void,
) -> i32;
type ResetFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
type SetRenderStateFn = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;
type DrawPrimitiveFn = unsafe extern "system" fn(*mut c_void, u32, u32, u32) -> i32;
type DrawIndexedPrimitiveFn =
    unsafe extern "system" fn(*mut c_void, u32, i32, u32, u32, u32, u32) -> i32;

const PRESENT_INDEX: usize = DEVICE9_VTBL_PRESENT / size_of::<*mut c_void>();
const RESET_INDEX: usize = DEVICE9_VTBL_RESET / size_of::<*mut c_void>();
const SET_RENDER_STATE_INDEX: usize = DEVICE9_VTBL_SET_RENDER_STATE / size_of::<*mut c_void>();
const DRAW_PRIMITIVE_INDEX: usize =
    libpsycho::os::windows::directx9::DEVICE9_VTBL_DRAW_PRIMITIVE / size_of::<*mut c_void>();
const DRAW_INDEXED_PRIMITIVE_INDEX: usize =
    libpsycho::os::windows::directx9::DEVICE9_VTBL_DRAW_INDEXED_PRIMITIVE
        / size_of::<*mut c_void>();
const INSTALL_POLL_MS: u64 = 50;
const INSTALL_LOG_EVERY_POLLS: u32 = 200;
const GWL_WNDPROC: i32 = -4;

static INSTALL_WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static RESZ_INTERPOSITION_READY: AtomicBool = AtomicBool::new(false);
static RESZ_INTERPOSITION_ACTIVE: AtomicBool = AtomicBool::new(false);
static DRAW_INTERPOSITION_READY: AtomicBool = AtomicBool::new(false);
static DRAW_INTERPOSITION_ACTIVE: AtomicBool = AtomicBool::new(false);
static RENDER_EPOCH: AtomicU32 = AtomicU32::new(1);
static ORIGINAL_PRESENT: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_RESET: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_SET_RENDER_STATE: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_DRAW_PRIMITIVE: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_DRAW_INDEXED_PRIMITIVE: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_WNDPROC: AtomicUsize = AtomicUsize::new(0);
static WNDPROC_HWND: AtomicUsize = AtomicUsize::new(0);
static DEVICE_HOOKS: LazyLock<Mutex<DeviceHooks>> =
    LazyLock::new(|| Mutex::new(DeviceHooks::default()));

#[derive(Default)]
struct DeviceHooks {
    present: Option<VmtHook<PresentFn>>,
    reset: Option<VmtHook<ResetFn>>,
    set_render_state: Option<VmtHook<SetRenderStateFn>>,
    draw_primitive: Option<VmtHook<DrawPrimitiveFn>>,
    draw_indexed_primitive: Option<VmtHook<DrawIndexedPrimitiveFn>>,
}

pub(crate) fn render_epoch() -> u32 {
    RENDER_EPOCH.load(Ordering::Acquire)
}

fn advance_render_epoch(epoch: &AtomicU32) {
    epoch.fetch_add(1, Ordering::AcqRel);
}

pub(crate) fn start_install_worker() -> Result<()> {
    if INSTALL_WORKER_STARTED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    thread::Builder::new()
        .name("omv-d3d-hook".to_owned())
        .spawn(install_worker)
        .context("failed to start Direct3D hook worker")?;

    Ok(())
}

/// Install all device hooks immediately when DeferredInit already has a device.
///
/// This synchronous path closes the ownership window for the OMV provider:
/// scene hooks must not suppress Depth Resolve conceptually until the exact
/// RESZ marker can be intercepted physically.
pub(crate) fn install_current_device_hooks() -> Result<()> {
    let device_ptr =
        backend::d3d_device_ptr().context("D3D9 device is unavailable during DeferredInit")?;
    install_device_hooks(device_ptr)
}

/// Return whether the optional RESZ hook object and original entry are prepared.
pub(crate) fn resz_interposition_ready() -> bool {
    RESZ_INTERPOSITION_READY.load(Ordering::Acquire)
}

/// Physically attach or detach the optional RESZ device-vtable detour.
///
/// The caller must use a quiescent render boundary. OMV calls this only from
/// DeferredInit or its `Present` detour, where Fallout New Vegas cannot be
/// executing `SetRenderState` on the serialized D3D9 render thread. Detaching
/// restores the original vtable entry; it is not an inactive branch inside
/// OMV's detour.
pub(crate) fn set_resz_interposition_active(active: bool) -> Result<(), &'static str> {
    let Some(hooks) = DEVICE_HOOKS.try_lock() else {
        return Err("RESZ hook owner is busy");
    };
    let Some(hook) = hooks.set_render_state.as_ref() else {
        return Err("RESZ interposition hook is not installed");
    };
    if hook.is_enabled() == active {
        RESZ_INTERPOSITION_ACTIVE.store(active, Ordering::Release);
        return Ok(());
    }
    let result = if active {
        hook.enable()
    } else {
        hook.disable()
    };
    if let Err(err) = result {
        log::warn!(
            "[HOOKS] Could not {} RESZ interposition: {err}",
            if active { "attach" } else { "detach" }
        );
        return Err("RESZ interposition transition failed");
    }
    RESZ_INTERPOSITION_ACTIVE.store(active, Ordering::Release);
    log::info!(
        "[HOOKS] RESZ interposition physically {}",
        if active { "attached" } else { "detached" }
    );
    Ok(())
}

/// Return whether the device currently points at OMV's RESZ detour.
pub(crate) fn resz_interposition_active() -> bool {
    RESZ_INTERPOSITION_ACTIVE.load(Ordering::Acquire)
}

/// Physically attach or detach the paired DP/DIP device-vtable detours.
///
/// Both entries form one ownership contract. A partial transition is rolled
/// back before returning an error so PBR and sky never observe a boundary that
/// covers only one primitive family. The caller must invoke this only at the
/// quiescent DeferredInit or Present boundary described by this module.
pub(crate) fn set_draw_interposition_active(active: bool) -> Result<(), &'static str> {
    let Some(hooks) = DEVICE_HOOKS.try_lock() else {
        return Err("draw hook owner is busy");
    };
    transition_draw_interposition(&hooks, active)
}

/// Return a stable diagnostic label for physical DP/DIP ownership.
pub(crate) fn draw_interposition_status_label() -> &'static str {
    if DRAW_INTERPOSITION_ACTIVE.load(Ordering::Acquire) {
        "attached"
    } else if DRAW_INTERPOSITION_READY.load(Ordering::Acquire) {
        "prepared-detached"
    } else {
        "unavailable"
    }
}

fn transition_draw_interposition(hooks: &DeviceHooks, active: bool) -> Result<(), &'static str> {
    let Some(draw) = hooks.draw_primitive.as_ref() else {
        return Err("DrawPrimitive hook is not installed");
    };
    let Some(draw_indexed) = hooks.draw_indexed_primitive.as_ref() else {
        return Err("DrawIndexedPrimitive hook is not installed");
    };
    if draw.is_enabled() == active && draw_indexed.is_enabled() == active {
        publish_draw_interposition(active);
        return Ok(());
    }

    // Enabling DP first and disabling DIP first makes rollback symmetrical:
    // the second operation either completes the pair or restores the first.
    let result = if active {
        draw.enable().and_then(|()| {
            draw_indexed.enable().inspect_err(|_| {
                let _ = draw.disable();
            })
        })
    } else {
        draw_indexed.disable().and_then(|()| {
            draw.disable().inspect_err(|_| {
                let _ = draw_indexed.enable();
            })
        })
    };
    if let Err(err) = result {
        log::warn!(
            "[HOOKS] Could not {} native draw interposition: {err}",
            if active { "attach" } else { "detach" }
        );
        return Err("native draw interposition transition failed");
    }

    publish_draw_interposition(active);
    log::info!(
        "[HOOKS] Native DP/DIP interposition physically {}",
        if active { "attached" } else { "detached" }
    );
    Ok(())
}

fn publish_draw_interposition(active: bool) {
    DRAW_INTERPOSITION_ACTIVE.store(active, Ordering::Release);
    pbr::set_draw_boundary_ready(active);
    sky::set_draw_boundary_ready(active);
}

fn install_worker() {
    let mut polls = 0u32;
    let mut failed_polls = 0u32;

    loop {
        if let Some(device_ptr) = backend::d3d_device_ptr() {
            match install_device_hooks(device_ptr) {
                Ok(()) => {
                    log::info!("[HOOKS] Direct3D9 device hooks installed");
                    return;
                }
                Err(err) => {
                    if failed_polls == 0 || failed_polls % INSTALL_LOG_EVERY_POLLS == 0 {
                        log::warn!("[HOOKS] Direct3D9 hook install failed: {err:#}");
                    }
                    failed_polls = failed_polls.wrapping_add(1);
                }
            }
        } else if polls == 0 || polls % INSTALL_LOG_EVERY_POLLS == 0 {
            log::info!("[HOOKS] Waiting for Direct3D9 device");
        }

        polls = polls.wrapping_add(1);
        thread::sleep(Duration::from_millis(INSTALL_POLL_MS));
    }
}

fn install_device_hooks(device_ptr: *mut c_void) -> Result<()> {
    let mut hooks = DEVICE_HOOKS.lock();
    let needs_resz_interposition = backend::depth_resolve_interposition_required();
    let activate_resz_interposition = resz_interposition_required_for_provider(
        needs_resz_interposition,
        backend::active_depth_provider(),
    );
    let activate_draw_interposition = runtime::draw_interposition_required();
    if hooks.present.is_some()
        && hooks.reset.is_some()
        && (!needs_resz_interposition || hooks.set_render_state.is_some())
        && hooks.draw_primitive.is_some()
        && hooks.draw_indexed_primitive.is_some()
    {
        transition_draw_interposition(&hooks, activate_draw_interposition)
            .map_err(anyhow::Error::msg)?;
        return Ok(());
    }

    let present_hook = unsafe {
        VmtHook::new(
            "IDirect3DDevice9::Present",
            device_ptr,
            PRESENT_INDEX,
            present_detour as PresentFn,
        )
    }?;
    let reset_hook = unsafe {
        VmtHook::new(
            "IDirect3DDevice9::Reset",
            device_ptr,
            RESET_INDEX,
            reset_detour as ResetFn,
        )
    }?;
    let set_render_state_hook = if needs_resz_interposition {
        Some(unsafe {
            VmtHook::new(
                "IDirect3DDevice9::SetRenderState",
                device_ptr,
                SET_RENDER_STATE_INDEX,
                set_render_state_detour as SetRenderStateFn,
            )
        }?)
    } else {
        None
    };
    let draw_primitive_hook = unsafe {
        VmtHook::new(
            "IDirect3DDevice9::DrawPrimitive",
            device_ptr,
            DRAW_PRIMITIVE_INDEX,
            draw_primitive_detour as DrawPrimitiveFn,
        )
    }?;
    let draw_indexed_primitive_hook = unsafe {
        VmtHook::new(
            "IDirect3DDevice9::DrawIndexedPrimitive",
            device_ptr,
            DRAW_INDEXED_PRIMITIVE_INDEX,
            draw_indexed_primitive_detour as DrawIndexedPrimitiveFn,
        )
    }?;

    let original_present = present_hook.original();
    let original_reset = reset_hook.original();
    let original_draw_primitive = draw_primitive_hook.original();
    let original_draw_indexed_primitive = draw_indexed_primitive_hook.original();
    ORIGINAL_PRESENT.store(original_present as usize, Ordering::Release);
    ORIGINAL_RESET.store(original_reset as usize, Ordering::Release);
    if let Some(set_render_state_hook) = set_render_state_hook.as_ref() {
        ORIGINAL_SET_RENDER_STATE
            .store(set_render_state_hook.original() as usize, Ordering::Release);
    }
    ORIGINAL_DRAW_PRIMITIVE.store(original_draw_primitive as usize, Ordering::Release);
    ORIGINAL_DRAW_INDEXED_PRIMITIVE
        .store(original_draw_indexed_primitive as usize, Ordering::Release);

    macro_rules! disable_all_pending {
        () => {{
            let _ = reset_hook.disable();
            let _ = present_hook.disable();
            let _ = draw_indexed_primitive_hook.disable();
            let _ = draw_primitive_hook.disable();
            if let Some(set_render_state_hook) = set_render_state_hook.as_ref()
                && set_render_state_hook.is_enabled()
            {
                let _ = set_render_state_hook.disable();
            }
        }};
    }

    macro_rules! enable_pending {
        ($hook:expr, $name:literal) => {
            if let Err(err) = $hook.enable() {
                disable_all_pending!();
                clear_originals();
                anyhow::bail!("{} hook enable failed: {err}", $name);
            }
        };
    }

    if activate_draw_interposition {
        enable_pending!(draw_primitive_hook, "DrawPrimitive");
        enable_pending!(draw_indexed_primitive_hook, "DrawIndexedPrimitive");
    }
    if activate_resz_interposition
        && let Some(set_render_state_hook) = set_render_state_hook.as_ref()
    {
        enable_pending!(set_render_state_hook, "SetRenderState");
    }
    enable_pending!(reset_hook, "Reset");
    enable_pending!(present_hook, "Present");

    hooks.present = Some(present_hook);
    hooks.reset = Some(reset_hook);
    hooks.set_render_state = set_render_state_hook;
    hooks.draw_primitive = Some(draw_primitive_hook);
    hooks.draw_indexed_primitive = Some(draw_indexed_primitive_hook);
    RESZ_INTERPOSITION_READY.store(needs_resz_interposition, Ordering::Release);
    RESZ_INTERPOSITION_ACTIVE.store(activate_resz_interposition, Ordering::Release);
    DRAW_INTERPOSITION_READY.store(true, Ordering::Release);
    publish_draw_interposition(activate_draw_interposition);
    log::info!(
        "[HOOKS] Native DP/DIP interposition prepared; state={}",
        draw_interposition_status_label()
    );
    if let Some(device) = unsafe { Device9Ref::from_raw_void(device_ptr) } {
        log_presentation_profile(&device, "hook-install");
    }
    Ok(())
}

fn resz_interposition_required_for_provider(
    depth_resolve_present: bool,
    provider: backend::DepthProvider,
) -> bool {
    depth_resolve_present && provider == backend::DepthProvider::FalloutNewVegas
}

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

unsafe extern "system" fn present_detour(
    device_ptr: *mut c_void,
    source_rect: *const Rect,
    dest_rect: *const Rect,
    dest_window: *mut c_void,
    dirty_region: *const c_void,
) -> i32 {
    unsafe {
        let render_epoch = render_epoch();
        if runtime::present_services_required() {
            pbr::finish_draw_batches();
            sky::finish_direct_draw();
            sky::service_present_frame();
            runtime::apply_present_frame(device_ptr, dest_window);
        }
        let present_started_at = runtime::present_frame_started_at();
        let result = call_original_present(
            device_ptr,
            source_rect,
            dest_rect,
            dest_window,
            dirty_region,
        );
        runtime::finish_present_frame(render_epoch, present_started_at, present_succeeded(result));
        crate::fnv_world_pipeline::finish_present(render_epoch);
        advance_render_epoch(&RENDER_EPOCH);
        result
    }
}

fn present_succeeded(result: i32) -> bool {
    result >= 0
}

#[cfg(test)]
mod tests {
    use super::{
        advance_render_epoch, is_resz_marker, present_succeeded,
        resz_interposition_required_for_provider,
    };
    use crate::backend::DepthProvider;
    use libpsycho::os::windows::directx9::{
        D3D_DEVICE_LOST_CODE, D3D_FAILURE_CODE, D3DRESZ_POINT_SIZE, D3DRS_POINTSIZE, D3DRS_ZENABLE,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn present_epoch_advances_without_runtime_ownership() {
        let epoch = AtomicU32::new(41);
        advance_render_epoch(&epoch);
        assert_eq!(epoch.load(Ordering::Acquire), 42);
    }

    #[test]
    fn only_successful_present_results_are_timing_samples() {
        assert!(present_succeeded(0));
        assert!(present_succeeded(1));
        assert!(!present_succeeded(D3D_DEVICE_LOST_CODE));
        assert!(!present_succeeded(D3D_FAILURE_CODE));
    }

    #[test]
    fn resz_interposition_matches_only_the_exact_d3d9_marker() {
        assert!(is_resz_marker(D3DRS_POINTSIZE.0 as u32, D3DRESZ_POINT_SIZE));
        assert!(!is_resz_marker(D3DRS_ZENABLE.0 as u32, D3DRESZ_POINT_SIZE));
        assert!(!is_resz_marker(D3DRS_POINTSIZE.0 as u32, 0));
    }

    #[test]
    fn resz_interposition_is_physically_requested_only_for_the_omv_provider() {
        assert!(resz_interposition_required_for_provider(
            true,
            DepthProvider::FalloutNewVegas
        ));
        assert!(!resz_interposition_required_for_provider(
            true,
            DepthProvider::DepthResolve
        ));
        assert!(!resz_interposition_required_for_provider(
            true,
            DepthProvider::None
        ));
        assert!(!resz_interposition_required_for_provider(
            false,
            DepthProvider::FalloutNewVegas
        ));
    }

    #[test]
    fn resz_provider_transition_writes_the_vtable_in_both_directions() {
        let source = include_str!("hooks.rs");
        let transition = source
            .split_once("pub(crate) fn set_resz_interposition_active")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn resz_interposition_active"))
            .map(|(body, _)| body)
            .expect("RESZ physical transition body");
        assert!(transition.contains("hook.enable()"));
        assert!(transition.contains("hook.disable()"));
        assert!(transition.contains("hook.is_enabled()"));
    }

    #[test]
    fn native_draw_transition_is_physical_and_pair_atomic() {
        let source = include_str!("hooks.rs");
        let transition = source
            .split_once("fn transition_draw_interposition")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("fn publish_draw_interposition"))
            .map(|(body, _)| body)
            .expect("draw interposition transition");

        assert!(transition.contains("draw.enable()"));
        assert!(transition.contains("draw_indexed.enable()"));
        assert!(transition.contains("draw.disable()"));
        assert!(transition.contains("draw_indexed.disable()"));
        assert!(
            transition.contains("let _ = draw.disable()"),
            "failed pair attachment must roll back DP"
        );
        assert!(
            transition.contains("let _ = draw_indexed.enable()"),
            "failed pair detachment must roll back DIP"
        );
    }

    #[test]
    fn present_hot_path_never_services_logging_telemetry() {
        let source = include_str!("hooks.rs");
        let start = source
            .find("unsafe extern \"system\" fn present_detour")
            .expect("present detour");
        let end = source[start..]
            .find("#[cfg(test)]")
            .map(|offset| start + offset)
            .expect("present detour test boundary");
        let present_path = &source[start..end];

        assert!(!present_path.contains("service_lock_telemetry"));
        assert!(!present_path.contains("log::"));
    }

    #[test]
    fn frame_timestamp_is_captured_before_native_present() {
        let source = include_str!("hooks.rs");
        let start = source
            .find("unsafe extern \"system\" fn present_detour")
            .expect("present detour");
        let end = source[start..]
            .find("fn present_succeeded")
            .map(|offset| start + offset)
            .expect("present detour boundary");
        let present_path = &source[start..end];

        let timestamp = present_path
            .find("runtime::present_frame_started_at()")
            .expect("present-start timestamp");
        let native_present = present_path
            .find("call_original_present(")
            .expect("native Present call");
        let finish = present_path
            .find("runtime::finish_present_frame(")
            .expect("frame timing consumer");
        assert!(timestamp < native_present);
        assert!(native_present < finish);
    }

    #[test]
    fn disabled_master_bypasses_all_draw_boundary_effect_work() {
        let source = include_str!("hooks.rs");
        for detour in [
            "unsafe extern \"system\" fn draw_primitive_detour",
            "unsafe extern \"system\" fn draw_indexed_primitive_detour",
        ] {
            let body = source
                .split_once(detour)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once("pbr::prepare_direct_draw()"))
                .map(|(prefix, _)| prefix)
                .expect("draw detour master gate");
            assert!(body.contains("if !runtime::effects_enabled()"));
            assert!(body.contains("call_original_draw"));
        }
    }

    #[test]
    fn pbr_draw_scope_is_closed_after_each_native_draw() {
        let source = include_str!("hooks.rs");
        for (detour, boundary) in [
            (
                "unsafe extern \"system\" fn draw_primitive_detour",
                "unsafe extern \"system\" fn draw_indexed_primitive_detour",
            ),
            (
                "unsafe extern \"system\" fn draw_indexed_primitive_detour",
                "unsafe fn call_original_present",
            ),
        ] {
            let body = source
                .split_once(detour)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once(boundary))
                .map(|(body, _)| body)
                .expect("draw detour body");
            let prepare = body
                .find("let pbr_draw = pbr::prepare_direct_draw()")
                .expect("PBR draw preparation");
            let native_draw = body[prepare..]
                .find("call_original_draw")
                .map(|offset| prepare + offset)
                .expect("native draw");
            let finish = body
                .find("pbr::finish_direct_draw(pbr_draw)")
                .expect("PBR draw cleanup");

            assert!(prepare < native_draw);
            assert!(native_draw < finish);
        }
    }
}

unsafe extern "system" fn reset_detour(device_ptr: *mut c_void, params: *mut c_void) -> i32 {
    unsafe {
        if !runtime::try_release_device_resources(device_ptr) {
            return D3D_DEVICE_LOST_CODE;
        }
        pbr::reset_runtime_state();
        sky::reset_runtime_state();
        let result = call_original_reset(device_ptr, params);
        if present_succeeded(result)
            && let Some(device) = Device9Ref::from_raw_void(device_ptr)
        {
            log_presentation_profile(&device, "device-reset");
        }
        result
    }
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

unsafe extern "system" fn set_render_state_detour(
    device_ptr: *mut c_void,
    state: u32,
    value: u32,
) -> i32 {
    if is_resz_marker(state, value)
        && let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) })
    {
        let bound_texture = device.texture_raw(0).map_or(0, |texture| texture as usize);
        if backend::suppress_resz_marker(bound_texture) {
            // SetRenderState returns HRESULT. Suppressing the inactive
            // provider's marker must look successful so Depth Resolve can
            // finish restoring its own state without entering an error path.
            return 0;
        }
    }
    unsafe { call_original_set_render_state(device_ptr, state, value) }
}

fn is_resz_marker(state: u32, value: u32) -> bool {
    state == D3DRS_POINTSIZE.0 as u32 && value == D3DRESZ_POINT_SIZE
}

unsafe extern "system" fn draw_primitive_detour(
    device_ptr: *mut c_void,
    primitive_type: u32,
    start_vertex: u32,
    primitive_count: u32,
) -> i32 {
    if !runtime::effects_enabled() {
        return unsafe {
            call_original_draw_primitive(device_ptr, primitive_type, start_vertex, primitive_count)
        };
    }
    let pbr_draw = pbr::prepare_direct_draw();
    let sky_draw = sky::prepare_direct_draw();
    let result = unsafe {
        call_original_draw_primitive(device_ptr, primitive_type, start_vertex, primitive_count)
    };
    if sky_draw {
        sky::finish_direct_draw();
    }
    pbr::finish_direct_draw(pbr_draw);
    result
}

unsafe extern "system" fn draw_indexed_primitive_detour(
    device_ptr: *mut c_void,
    primitive_type: u32,
    base_vertex_index: i32,
    min_vertex_index: u32,
    vertex_count: u32,
    start_index: u32,
    primitive_count: u32,
) -> i32 {
    if !runtime::effects_enabled() {
        return unsafe {
            call_original_draw_indexed_primitive(
                device_ptr,
                primitive_type,
                base_vertex_index,
                min_vertex_index,
                vertex_count,
                start_index,
                primitive_count,
            )
        };
    }
    let pbr_draw = pbr::prepare_direct_draw();
    let sky_draw = sky::prepare_direct_draw();
    let result = unsafe {
        call_original_draw_indexed_primitive(
            device_ptr,
            primitive_type,
            base_vertex_index,
            min_vertex_index,
            vertex_count,
            start_index,
            primitive_count,
        )
    };
    if sky_draw {
        sky::finish_direct_draw();
    }
    pbr::finish_direct_draw(pbr_draw);
    result
}

unsafe fn call_original_present(
    device_ptr: *mut c_void,
    source_rect: *const Rect,
    dest_rect: *const Rect,
    dest_window: *mut c_void,
    dirty_region: *const c_void,
) -> i32 {
    let original = ORIGINAL_PRESENT.load(Ordering::Acquire);
    if original == 0 {
        return D3D_FAILURE_CODE;
    }

    let Ok(original) = (unsafe { FnPtr::<PresentFn>::from_raw(original as *mut c_void) }) else {
        return D3D_FAILURE_CODE;
    };
    let original = original.as_fn();
    unsafe {
        original(
            device_ptr,
            source_rect,
            dest_rect,
            dest_window,
            dirty_region,
        )
    }
}

unsafe fn call_original_reset(device_ptr: *mut c_void, params: *mut c_void) -> i32 {
    let original = ORIGINAL_RESET.load(Ordering::Acquire);
    if original == 0 {
        return D3D_FAILURE_CODE;
    }

    let Ok(original) = (unsafe { FnPtr::<ResetFn>::from_raw(original as *mut c_void) }) else {
        return D3D_FAILURE_CODE;
    };
    unsafe { original.as_fn()(device_ptr, params) }
}

unsafe fn call_original_set_render_state(device_ptr: *mut c_void, state: u32, value: u32) -> i32 {
    let original = ORIGINAL_SET_RENDER_STATE.load(Ordering::Acquire);
    if original == 0 {
        return D3D_FAILURE_CODE;
    }
    let Ok(original) = (unsafe { FnPtr::<SetRenderStateFn>::from_raw(original as *mut c_void) })
    else {
        return D3D_FAILURE_CODE;
    };
    unsafe { original.as_fn()(device_ptr, state, value) }
}

unsafe fn call_original_draw_primitive(
    device_ptr: *mut c_void,
    primitive_type: u32,
    start_vertex: u32,
    primitive_count: u32,
) -> i32 {
    let original = ORIGINAL_DRAW_PRIMITIVE.load(Ordering::Acquire);
    if original == 0 {
        return D3D_FAILURE_CODE;
    }
    let Ok(original) = (unsafe { FnPtr::<DrawPrimitiveFn>::from_raw(original as *mut c_void) })
    else {
        return D3D_FAILURE_CODE;
    };
    unsafe { original.as_fn()(device_ptr, primitive_type, start_vertex, primitive_count) }
}

#[allow(clippy::too_many_arguments)]
unsafe fn call_original_draw_indexed_primitive(
    device_ptr: *mut c_void,
    primitive_type: u32,
    base_vertex_index: i32,
    min_vertex_index: u32,
    vertex_count: u32,
    start_index: u32,
    primitive_count: u32,
) -> i32 {
    let original = ORIGINAL_DRAW_INDEXED_PRIMITIVE.load(Ordering::Acquire);
    if original == 0 {
        return D3D_FAILURE_CODE;
    }
    let Ok(original) =
        (unsafe { FnPtr::<DrawIndexedPrimitiveFn>::from_raw(original as *mut c_void) })
    else {
        return D3D_FAILURE_CODE;
    };
    unsafe {
        original.as_fn()(
            device_ptr,
            primitive_type,
            base_vertex_index,
            min_vertex_index,
            vertex_count,
            start_index,
            primitive_count,
        )
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

fn clear_originals() {
    ORIGINAL_PRESENT.store(0, Ordering::Release);
    ORIGINAL_RESET.store(0, Ordering::Release);
    ORIGINAL_SET_RENDER_STATE.store(0, Ordering::Release);
    ORIGINAL_DRAW_PRIMITIVE.store(0, Ordering::Release);
    ORIGINAL_DRAW_INDEXED_PRIMITIVE.store(0, Ordering::Release);
    RESZ_INTERPOSITION_READY.store(false, Ordering::Release);
    RESZ_INTERPOSITION_ACTIVE.store(false, Ordering::Release);
    DRAW_INTERPOSITION_READY.store(false, Ordering::Release);
    publish_draw_interposition(false);
}

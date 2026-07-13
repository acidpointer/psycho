//! Direct3D hook installation.

use std::{
    mem::size_of,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use core::ffi::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    hook::traits::Hook,
    os::windows::{
        directx9::{DEVICE9_VTBL_PRESENT, DEVICE9_VTBL_RESET},
        hook::vmt::vmthook::VmtHook,
        winapi::{call_window_proc_a, set_window_long_a},
    },
};
use parking_lot::Mutex;
use windows::Win32::{
    Foundation::{E_FAIL, HWND, RECT},
    Graphics::{Direct3D9::D3DPRESENT_PARAMETERS, Gdi::RGNDATA},
};
use windows::core::HRESULT;

use crate::{backend, effects::pbr, runtime};

type PresentFn = unsafe extern "system" fn(
    *mut c_void,
    *const RECT,
    *const RECT,
    HWND,
    *const RGNDATA,
) -> HRESULT;
type ResetFn = unsafe extern "system" fn(*mut c_void, *mut D3DPRESENT_PARAMETERS) -> HRESULT;

const PRESENT_INDEX: usize = DEVICE9_VTBL_PRESENT / size_of::<*mut c_void>();
const RESET_INDEX: usize = DEVICE9_VTBL_RESET / size_of::<*mut c_void>();
const INSTALL_POLL_MS: u64 = 50;
const INSTALL_LOG_EVERY_POLLS: u32 = 200;
const GWL_WNDPROC: i32 = -4;

static INSTALL_WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static ORIGINAL_PRESENT: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_RESET: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_WNDPROC: AtomicUsize = AtomicUsize::new(0);
static WNDPROC_HWND: AtomicUsize = AtomicUsize::new(0);
static DEVICE_HOOKS: LazyLock<Mutex<DeviceHooks>> =
    LazyLock::new(|| Mutex::new(DeviceHooks::default()));

#[derive(Default)]
struct DeviceHooks {
    present: Option<VmtHook<PresentFn>>,
    reset: Option<VmtHook<ResetFn>>,
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

fn install_worker() {
    let mut polls = 0u32;
    let mut failed_polls = 0u32;

    loop {
        if let Some(device_ptr) = backend::d3d_device_ptr() {
            match install_device_hooks(device_ptr) {
                Ok(()) => {
                    log::info!("[HOOKS] Direct3D9 shader hooks installed");
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
    if hooks.present.is_some() && hooks.reset.is_some() {
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

    let original_present = present_hook.original();
    let original_reset = reset_hook.original();
    ORIGINAL_PRESENT.store(original_present as usize, Ordering::Release);
    ORIGINAL_RESET.store(original_reset as usize, Ordering::Release);

    macro_rules! disable_all_pending {
        () => {{
            let _ = reset_hook.disable();
            let _ = present_hook.disable();
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

    enable_pending!(reset_hook, "Reset");
    enable_pending!(present_hook, "Present");

    hooks.present = Some(present_hook);
    hooks.reset = Some(reset_hook);
    Ok(())
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
    source_rect: *const RECT,
    dest_rect: *const RECT,
    dest_window: HWND,
    dirty_region: *const RGNDATA,
) -> HRESULT {
    unsafe {
        runtime::apply_present_frame(device_ptr, dest_window.0);
        let result = call_original_present(
            device_ptr,
            source_rect,
            dest_rect,
            dest_window,
            dirty_region,
        );
        runtime::finish_present_frame(device_ptr);
        result
    }
}

unsafe extern "system" fn reset_detour(
    device_ptr: *mut c_void,
    params: *mut D3DPRESENT_PARAMETERS,
) -> HRESULT {
    unsafe {
        runtime::release_device_resources(device_ptr);
        backend::reset_depth_resources();
        pbr::reset_runtime_state();
        call_original_reset(device_ptr, params)
    }
}

unsafe fn call_original_present(
    device_ptr: *mut c_void,
    source_rect: *const RECT,
    dest_rect: *const RECT,
    dest_window: HWND,
    dirty_region: *const RGNDATA,
) -> HRESULT {
    let original = ORIGINAL_PRESENT.load(Ordering::Acquire);
    if original == 0 {
        return E_FAIL;
    }

    let Ok(original) = (unsafe { FnPtr::<PresentFn>::from_raw(original as *mut c_void) }) else {
        return E_FAIL;
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

unsafe fn call_original_reset(
    device_ptr: *mut c_void,
    params: *mut D3DPRESENT_PARAMETERS,
) -> HRESULT {
    let original = ORIGINAL_RESET.load(Ordering::Acquire);
    if original == 0 {
        return E_FAIL;
    }

    let Ok(original) = (unsafe { FnPtr::<ResetFn>::from_raw(original as *mut c_void) }) else {
        return E_FAIL;
    };
    unsafe { original.as_fn()(device_ptr, params) }
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
}

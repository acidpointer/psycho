//! Process-lifetime hooks needed by the helper-owned dashboard.

use std::{
    mem::size_of,
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::Result;
use core::ffi::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    hook::traits::Hook,
    os::windows::{
        directx9::DEVICE9_VTBL_RESET,
        hook::vmt::vmthook::VmtHook,
        winapi::{call_window_proc_a, set_window_long_a},
    },
};
use parking_lot::Mutex;

use crate::dashboard;

const GWL_WNDPROC: i32 = -4;
const RESET_INDEX: usize = DEVICE9_VTBL_RESET / size_of::<*mut c_void>();

type ResetFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;

static ORIGINAL_RESET: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_WNDPROC: AtomicUsize = AtomicUsize::new(0);
static WNDPROC_HWND: AtomicUsize = AtomicUsize::new(0);
static RESET_HOOK: LazyLock<Mutex<Option<VmtHook<ResetFn>>>> = LazyLock::new(|| Mutex::new(None));

pub(crate) fn window_proc_installed() -> bool {
    WNDPROC_HWND.load(Ordering::Acquire) != 0
}

pub(crate) fn ensure_window_proc(hwnd: *mut c_void) -> Result<()> {
    if hwnd.is_null() {
        anyhow::bail!("null dashboard HWND");
    }
    let installed = WNDPROC_HWND.load(Ordering::Acquire);
    if installed == hwnd as usize {
        return Ok(());
    }
    if installed != 0 {
        anyhow::bail!("dashboard WndProc already belongs to another HWND");
    }

    let previous = set_window_long_a(
        hwnd,
        GWL_WNDPROC,
        wndproc_detour as *const () as usize as i32,
    );
    if previous == 0 {
        anyhow::bail!("SetWindowLongA(GWL_WNDPROC) returned no predecessor");
    }
    ORIGINAL_WNDPROC.store(previous as usize, Ordering::Release);
    WNDPROC_HWND.store(hwnd as usize, Ordering::Release);
    log::info!("[DASHBOARD] Win32 input bridge installed");
    Ok(())
}

pub(crate) fn ensure_reset_hook(device: *mut c_void) -> Result<()> {
    let mut slot = RESET_HOOK.lock();
    if slot.is_some() {
        return Ok(());
    }

    let hook = unsafe {
        VmtHook::new(
            "dashboard IDirect3DDevice9::Reset",
            device,
            RESET_INDEX,
            reset_detour as ResetFn,
        )
    }?;
    ORIGINAL_RESET.store(hook.original() as usize, Ordering::Release);
    hook.enable()?;
    *slot = Some(hook);
    log::info!("[DASHBOARD] Direct3D9 reset bridge installed");
    Ok(())
}

unsafe extern "system" fn reset_detour(device: *mut c_void, params: *mut c_void) -> i32 {
    dashboard::before_device_reset(device);
    let result = unsafe { call_original_reset(device, params) };
    dashboard::after_device_reset(device, result >= 0);
    result
}

unsafe fn call_original_reset(device: *mut c_void, params: *mut c_void) -> i32 {
    let original = ORIGINAL_RESET.load(Ordering::Acquire);
    let Ok(original) = (unsafe { FnPtr::<ResetFn>::from_raw(original as *mut c_void) }) else {
        return -1;
    };
    unsafe { original.as_fn()(device, params) }
}

unsafe extern "system" fn wndproc_detour(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    if let Some(result) = dashboard::handle_window_message(hwnd, msg, wparam, lparam) {
        return result;
    }

    let original = ORIGINAL_WNDPROC.load(Ordering::Acquire);
    if original == 0 {
        return 0;
    }
    unsafe { call_window_proc_a(original as *mut c_void, hwnd, msg, wparam, lparam) }
}

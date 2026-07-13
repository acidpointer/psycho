//! Forwarded `dinput8.dll` exports.
//!
//! Mod initialization is independent of forwarding. Proxy exports never start
//! or wait for the loader, so a caller holding loader lock cannot deadlock with
//! Syringe's mod-loading path.

use core::ffi::c_void;
use core::mem::transmute;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::win32::{self, HInstance, HModule};

const E_FAIL: i32 = 0x8000_4005u32 as i32;

// Cached handle to the real System32 dinput8.dll. We load by absolute system
// directory path so forwarding never resolves back to this proxy.
static REAL_DINPUT8: AtomicUsize = AtomicUsize::new(0);

type DirectInput8CreateFn =
    unsafe extern "system" fn(HInstance, u32, *const c_void, *mut *mut c_void, *mut c_void) -> i32;
type DllCanUnloadNowFn = unsafe extern "system" fn() -> i32;
type DllGetClassObjectFn =
    unsafe extern "system" fn(*const c_void, *const c_void, *mut *mut c_void) -> i32;
type DllRegisterServerFn = unsafe extern "system" fn() -> i32;

pub unsafe fn direct_input8_create(
    instance: HInstance,
    version: u32,
    riidltf: *const c_void,
    out: *mut *mut c_void,
    outer: *mut c_void,
) -> i32 {
    let proc = real_proc(b"DirectInput8Create\0");
    if proc.is_null() {
        return E_FAIL;
    }

    let f: DirectInput8CreateFn = unsafe { transmute(proc) };
    unsafe { f(instance, version, riidltf, out, outer) }
}

pub unsafe fn dll_can_unload_now() -> i32 {
    let proc = real_proc(b"DllCanUnloadNow\0");
    if proc.is_null() {
        return E_FAIL;
    }

    let f: DllCanUnloadNowFn = unsafe { transmute(proc) };
    unsafe { f() }
}

pub unsafe fn dll_get_class_object(
    clsid: *const c_void,
    iid: *const c_void,
    out: *mut *mut c_void,
) -> i32 {
    let proc = real_proc(b"DllGetClassObject\0");
    if proc.is_null() {
        return E_FAIL;
    }

    let f: DllGetClassObjectFn = unsafe { transmute(proc) };
    unsafe { f(clsid, iid, out) }
}

pub unsafe fn dll_register_server() -> i32 {
    let proc = real_proc(b"DllRegisterServer\0");
    if proc.is_null() {
        return E_FAIL;
    }

    let f: DllRegisterServerFn = unsafe { transmute(proc) };
    unsafe { f() }
}

pub unsafe fn dll_unregister_server() -> i32 {
    let proc = real_proc(b"DllUnregisterServer\0");
    if proc.is_null() {
        return E_FAIL;
    }

    let f: DllRegisterServerFn = unsafe { transmute(proc) };
    unsafe { f() }
}

/// Load and cache the real system DLL before invoking mod callbacks.
/// Proxy exports retain lazy loading as their normal compatibility fallback.
pub fn preload() {
    let _ = real_dinput8();
}

fn real_proc(name: &[u8]) -> *mut c_void {
    let module = real_dinput8();
    if module.is_null() {
        return null_mut();
    }

    win32::get_proc_address(module, name)
}

fn real_dinput8() -> HModule {
    let current = REAL_DINPUT8.load(Ordering::Acquire);
    if current != 0 {
        return current as HModule;
    }

    let loaded = load_real_dinput8();
    if loaded.is_null() {
        return null_mut();
    }

    match REAL_DINPUT8.compare_exchange(0, loaded as usize, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => loaded,
        Err(existing) => existing as HModule,
    }
}

fn load_real_dinput8() -> HModule {
    let mut path = win32::system_directory();
    if path.is_empty() || !path.append_component_ascii("dinput8.dll") {
        return null_mut();
    }

    win32::load_library(&path)
}

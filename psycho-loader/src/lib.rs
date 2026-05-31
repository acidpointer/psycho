#![no_std]
#![allow(non_snake_case)]

//! Minimal `dinput8.dll` proxy and root `mods/*.dll` loader.
//!
//! This crate deliberately stays tiny: no allocator, no logging, no
//! `libpsycho`, and no game-specific knowledge. Its only job is to load
//! root-level early DLLs before later plugin loaders run and then
//! forward the standard dinput8 exports to the real system DLL.
//!
//! Loader-lock rule: loader-lock callbacks must not call `LoadLibraryW` for
//! mods. `DllMain` and the TLS callback both run the same tiny attach path:
//! record our module handle, disable thread notifications, and start a worker
//! thread. The exported dinput8 functions also call `ensure_loaded` as a
//! fallback so early DirectInput callers cannot outrun the worker thread.

mod dinput8;
mod mods;
mod wide_path;
mod win32;

use core::ffi::c_void;
use core::panic::PanicInfo;

use win32::HInstance;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Stable `no_std` cdylib builds for MinGW still reference this personality
// symbol in some configurations even with `panic = "abort"`.
#[unsafe(export_name = "rust_eh_personality")]
extern "C" fn loader_rust_eh_personality() {}

#[used]
#[unsafe(link_section = ".CRT$XLB")]
static TLS_CALLBACK: unsafe extern "system" fn(HInstance, u32, *mut c_void) = tls_callback;

unsafe extern "system" fn tls_callback(instance: HInstance, reason: u32, _reserved: *mut c_void) {
    unsafe { process_attach(instance, reason) };
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    instance: HInstance,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    unsafe { process_attach(instance, reason) };
    1
}

unsafe fn process_attach(instance: HInstance, reason: u32) {
    if reason != win32::DLL_PROCESS_ATTACH {
        return;
    }

    mods::remember_loader_module(instance);

    if !instance.is_null() {
        win32::disable_thread_library_calls(instance);
    }

    mods::start_loader_thread();
}

// The .def file exports the normal dinput8 surface. Each exported function
// delegates to `dinput8.rs`, which keeps real-system-DLL loading in one place.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DirectInput8Create(
    instance: HInstance,
    version: u32,
    riidltf: *const c_void,
    out: *mut *mut c_void,
    outer: *mut c_void,
) -> i32 {
    unsafe { dinput8::direct_input8_create(instance, version, riidltf, out, outer) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllCanUnloadNow() -> i32 {
    unsafe { dinput8::dll_can_unload_now() }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const c_void,
    iid: *const c_void,
    out: *mut *mut c_void,
) -> i32 {
    unsafe { dinput8::dll_get_class_object(clsid, iid, out) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllRegisterServer() -> i32 {
    unsafe { dinput8::dll_register_server() }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllUnregisterServer() -> i32 {
    unsafe { dinput8::dll_unregister_server() }
}

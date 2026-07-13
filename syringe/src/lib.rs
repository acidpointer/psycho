#![no_std]
#![allow(non_snake_case)]

//! Minimal `dinput8.dll` proxy and root `syringe/*.dll` loader.
//!
//! This crate deliberately stays tiny: no allocator, no logging, no
//! `libpsycho`, and no game-specific knowledge. Its only job is to load
//! root-level early DLLs before later plugin loaders run and then
//! forward the standard dinput8 exports to the real system DLL.
//!
//! Loader-lock rule: loader-lock callbacks never load mods. `DllMain` installs
//! a main-executable startup barrier; its callback initializes mods after
//! loader lock is released. A non-blocking worker is installed from process
//! attach only when the barrier cannot be installed. Proxy exports never start
//! or wait for mod loading.

#[cfg(not(all(target_os = "windows", target_arch = "x86")))]
compile_error!("syringe must be built for 32-bit Windows (i686-pc-windows-gnu)");

mod dinput8;
mod mods;
mod startup_barrier;
mod wide_path;
mod win32;

use core::ffi::c_void;
use core::panic::PanicInfo;

use win32::HInstance;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Keep the MinGW DllMain entrypoint link-visible without making it a PE export.
// `#[no_mangle]` would force DllMain into the proxy export table.
core::arch::global_asm!(
    ".globl _DllMain@12",
    "_DllMain@12:",
    "jmp {dll_main}",
    dll_main = sym dll_main_impl,
);

// Stable `no_std` cdylib builds for MinGW still reference this personality
// symbol in some configurations even with `panic = "abort"`.
core::arch::global_asm!(
    ".globl _rust_eh_personality",
    "_rust_eh_personality:",
    "ret"
);

/// Windows loader entrypoint.
///
/// # Safety
/// Called by the Windows loader with process-attach/detach arguments. The
/// pointers and reason code must come from the loader.
unsafe extern "system" fn dll_main_impl(
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

    if !startup_barrier::install() {
        mods::start_loader_thread();
    }
}

// The .def file exports the normal dinput8 surface. Each exported function
// delegates to `dinput8.rs`, which keeps real-system-DLL loading in one place.
/// Forward `DirectInput8Create` to the real system `dinput8.dll`.
///
/// # Safety
/// Arguments must satisfy the Win32 `DirectInput8Create` contract.
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

/// Forward `DllCanUnloadNow` to the real system `dinput8.dll`.
///
/// # Safety
/// Called by COM using the standard DLL export contract.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllCanUnloadNow() -> i32 {
    unsafe { dinput8::dll_can_unload_now() }
}

/// Forward `DllGetClassObject` to the real system `dinput8.dll`.
///
/// # Safety
/// Arguments must satisfy the Win32 `DllGetClassObject` contract.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const c_void,
    iid: *const c_void,
    out: *mut *mut c_void,
) -> i32 {
    unsafe { dinput8::dll_get_class_object(clsid, iid, out) }
}

/// Forward `DllRegisterServer` to the real system `dinput8.dll`.
///
/// # Safety
/// Called by COM registration tooling using the standard DLL export contract.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllRegisterServer() -> i32 {
    unsafe { dinput8::dll_register_server() }
}

/// Forward `DllUnregisterServer` to the real system `dinput8.dll`.
///
/// # Safety
/// Called by COM registration tooling using the standard DLL export contract.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllUnregisterServer() -> i32 {
    unsafe { dinput8::dll_unregister_server() }
}

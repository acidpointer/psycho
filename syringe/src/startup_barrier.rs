//! Post-loader-lock initialization barrier.
//!
//! The PE32 MSVC CRT calls `GetStartupInfoA` before global constructors.
//! Hooking the main-executable IAT during process attach gives Syringe a
//! deterministic callback outside loader lock. xNVSE installs its hook later,
//! performs its preload work, and then calls the saved IAT function; that
//! normal chain reaches this barrier only after xNVSE preload completes.

use core::ffi::c_void;
use core::mem::transmute;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{mods, win32};

static ORIGINAL_GET_STARTUP_INFO_A: AtomicUsize = AtomicUsize::new(0);

type GetStartupInfoAFn = unsafe extern "system" fn(*mut c_void);

/// Install the executable IAT barrier during process attach.
///
/// Returning `false` leaves startup to the non-blocking worker fallback. At
/// this point the executable entrypoint has not run, so no application thread
/// can observe the IAT slot before the saved predecessor is published.
pub fn install() -> bool {
    let module = win32::process_module();
    let Some(slot) = (unsafe { find_import(module, b"kernel32.dll\0", b"GetStartupInfoA\0") })
    else {
        return false;
    };
    let Some(original) = (unsafe {
        win32::replace_iat_pointer(slot, get_startup_info_a_hook as *const () as usize)
    }) else {
        return false;
    };
    ORIGINAL_GET_STARTUP_INFO_A.store(original, Ordering::Release);
    true
}

unsafe extern "system" fn get_startup_info_a_hook(info: *mut c_void) {
    mods::load_mods_at_pre_crt_barrier();
    let original = ORIGINAL_GET_STARTUP_INFO_A.load(Ordering::Acquire);
    if original != 0 {
        let function: GetStartupInfoAFn = unsafe { transmute(original) };
        unsafe { function(info) };
    }
}

unsafe fn find_import(module: win32::HModule, dll: &[u8], function: &[u8]) -> Option<*mut usize> {
    if module.is_null() {
        return None;
    }
    let base = module as usize;
    if unsafe { read_u16(base)? } != 0x5A4D {
        return None;
    }
    let pe_offset = unsafe { read_u32(base.checked_add(0x3C)?)? } as usize;
    let nt = base.checked_add(pe_offset)?;
    if unsafe { read_u32(nt)? } != 0x0000_4550 {
        return None;
    }
    let optional = nt.checked_add(24)?;
    if unsafe { read_u16(optional)? } != 0x010B {
        return None;
    }
    let import_rva = unsafe { read_u32(optional.checked_add(104)?)? } as usize;
    if import_rva == 0 {
        return None;
    }
    let mut descriptor = base.checked_add(import_rva)?;
    loop {
        let original_thunk = unsafe { read_u32(descriptor)? } as usize;
        let name_rva = unsafe { read_u32(descriptor.checked_add(12)?)? } as usize;
        let first_thunk = unsafe { read_u32(descriptor.checked_add(16)?)? } as usize;
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            return None;
        }
        if unsafe { ascii_eq_ignore_case(base.checked_add(name_rva)?, dll) } {
            // OriginalFirstThunk is optional in PE32, but FirstThunk contains
            // resolved function pointers by the time DllMain runs. It cannot
            // safely be reinterpreted as name RVAs. Without the untouched
            // lookup table we cannot identify this import by name, so use the
            // worker fallback instead of reading an arbitrary address.
            if original_thunk == 0 || first_thunk == 0 {
                return None;
            }
            let mut lookup = base.checked_add(original_thunk)?;
            let mut iat = base.checked_add(first_thunk)?;
            loop {
                let entry = unsafe { read_u32(lookup)? };
                if entry == 0 {
                    return None;
                }
                if entry & 0x8000_0000 == 0 {
                    let import_name = base.checked_add(entry as usize)?.checked_add(2)?;
                    if unsafe { ascii_eq(import_name, function) } {
                        return Some(iat as *mut usize);
                    }
                }
                lookup = lookup.checked_add(4)?;
                iat = iat.checked_add(4)?;
            }
        }
        descriptor = descriptor.checked_add(20)?;
    }
}

unsafe fn read_u16(address: usize) -> Option<u16> {
    if address == 0 {
        None
    } else {
        Some(unsafe { core::ptr::read_unaligned(address as *const u16) })
    }
}

unsafe fn read_u32(address: usize) -> Option<u32> {
    if address == 0 {
        None
    } else {
        Some(unsafe { core::ptr::read_unaligned(address as *const u32) })
    }
}

unsafe fn ascii_eq(address: usize, expected: &[u8]) -> bool {
    let mut index = 0usize;
    while index < expected.len() {
        let actual = unsafe { core::ptr::read((address + index) as *const u8) };
        if actual != expected[index] {
            return false;
        }
        if actual == 0 {
            return true;
        }
        index += 1;
    }
    false
}

unsafe fn ascii_eq_ignore_case(address: usize, expected: &[u8]) -> bool {
    let mut index = 0usize;
    while index < expected.len() {
        let actual = unsafe { core::ptr::read((address + index) as *const u8) };
        let wanted = expected[index];
        if !actual.eq_ignore_ascii_case(&wanted) {
            return false;
        }
        if actual == 0 {
            return true;
        }
        index += 1;
    }
    false
}

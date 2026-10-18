//! Volatile engine-memory readers used by the occlusion-plane runtime.
//!
//! Every helper performs one aligned volatile read or write. Callers are
//! responsible for null checks, lifetime and the main-thread boundary. The
//! engine is 32-bit, so pointers and `usize` are the same width.

use core::ffi::c_void;

/// Read one pointer at an absolute address.
pub(super) unsafe fn read_ptr(address: usize) -> *mut c_void {
    unsafe { core::ptr::read_volatile(address as *const *mut c_void) }
}

/// Read one pointer at `base + offset`.
pub(super) unsafe fn read_ptr_at(base: *mut c_void, offset: usize) -> *mut c_void {
    unsafe { core::ptr::read_volatile((base as *const u8).add(offset) as *const *mut c_void) }
}

/// Write one pointer at `base + offset`.
pub(super) unsafe fn write_ptr_at(base: *mut c_void, offset: usize, value: *mut c_void) {
    unsafe {
        core::ptr::write_volatile((base as *mut u8).add(offset) as *mut *mut c_void, value);
    }
}

/// Read one `u8` at `base + offset`.
pub(super) unsafe fn read_u8_at(base: *mut c_void, offset: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base as *const u8).add(offset)) }
}

/// Write one `u8` at `base + offset`.
pub(super) unsafe fn write_u8_at(base: *mut c_void, offset: usize, value: u8) {
    unsafe {
        core::ptr::write_volatile((base as *mut u8).add(offset), value);
    }
}

/// Read one `u16` at `base + offset`.
pub(super) unsafe fn read_u16_at(base: *mut c_void, offset: usize) -> u16 {
    unsafe { core::ptr::read_volatile((base as *const u8).add(offset) as *const u16) }
}

/// Read one `u32` at `base + offset`.
pub(super) unsafe fn read_u32_at(base: *mut c_void, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base as *const u8).add(offset) as *const u32) }
}

/// Write one `u32` at `base + offset`.
pub(super) unsafe fn write_u32_at(base: *mut c_void, offset: usize, value: u32) {
    unsafe {
        core::ptr::write_volatile((base as *mut u8).add(offset) as *mut u32, value);
    }
}

/// Read one `f32` at `base + offset`.
pub(super) unsafe fn read_f32_at(base: *mut c_void, offset: usize) -> f32 {
    unsafe { core::ptr::read_volatile((base as *const u8).add(offset) as *const f32) }
}

/// Read one `i32` at `base + offset`.
pub(super) unsafe fn read_i32_at(base: *mut c_void, offset: usize) -> i32 {
    unsafe { core::ptr::read_volatile((base as *const u8).add(offset) as *const i32) }
}

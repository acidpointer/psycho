//! IO task release hook: prevents double-release crashes on recycled memory.
//!
//! FUN_0044dd60 does DecRef at this+8. If result == 0, calls vtable[0](1)
//! (destructor). When the IO completion queue holds a stale pointer to a
//! freed task, the memory is recycled by mimalloc. DecRef on recycled memory
//! can return 0 if +8 happened to contain 1, triggering the destructor on
//! garbage data.
//!
//! Fix: validate the object before calling original. Check vtable pointer
//! is in .rdata range (valid game object) and refcount > 0.

use libc::c_void;

use super::statics;

/// Game module .rdata range for vtable validation.
const RDATA_START: usize = 0x01000000;
const RDATA_END: usize = 0x01300000;

pub unsafe extern "fastcall" fn hook_task_release(this: *mut c_void) {
    if this.is_null() {
        return;
    }

    // Validate: vtable pointer must be in .rdata section
    let vtable = unsafe { *(this as *const usize) };
    if !(RDATA_START..RDATA_END).contains(&vtable) {
        return;
    }

    // Validate: refcount at +8 must be > 0
    let refcount = unsafe {
        std::ptr::read_volatile((this as *const u8).add(8) as *const i32)
    };
    if refcount <= 0 {
        return;
    }

    if let Ok(original) = statics::TASK_RELEASE_HOOK.original() {
        unsafe { original(this) };
    }
}

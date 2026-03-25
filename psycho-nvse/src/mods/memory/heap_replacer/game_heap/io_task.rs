//! IO task release hook (FUN_0044dd60).
//!
//! Validates vtable pointer and refcount before calling the original DecRef.
//! with_try_read handles main/worker distinction internally.

use libc::c_void;

use super::engine::addr;
use super::game_guard;
use super::statics;

pub unsafe extern "fastcall" fn hook_task_release(this: *mut c_void) {
    if this.is_null() {
        return;
    }

    game_guard::with_try_read(|| {
        unsafe { validate_and_release(this) };
    });
}

unsafe fn validate_and_release(this: *mut c_void) {
    let vtable = unsafe { *(this as *const usize) };
    if !(addr::RDATA_START..addr::RDATA_END).contains(&vtable) {
        return;
    }

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

//! IO task release hook (FUN_0044dd60).
//!
//! Full read lock during original call. Internal GameHeap::Free calls
//! go to quarantine via try_write (non-blocking, no deadlock).
//! Quarantine flushes after read lock is released.

use libc::c_void;

use super::destruction_guard;
use super::statics;

const RDATA_START: usize = 0x01000000;
const RDATA_END: usize = 0x01300000;

pub unsafe extern "fastcall" fn hook_task_release(this: *mut c_void) {
    if this.is_null() {
        return;
    }

    destruction_guard::read(|| {
        let vtable = unsafe { *(this as *const usize) };
        if !(RDATA_START..RDATA_END).contains(&vtable) {
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
    });
}

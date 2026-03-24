//! IO task release hook (FUN_0044dd60).
//!
//! Validates vtable pointer and refcount before calling the original
//! DecRef. With mimalloc, freed task memory can be recycled immediately,
//! so stale task pointers may have garbage vtable/refcount. Read lock
//! prevents concurrent quarantine drain during validation + original call.
//!
//! Called from BSTaskManagerThread (continuous) and main thread Phase 3.
//! Read lock: short-scoped (single function call, microseconds).
//!
//! NOTE: When called from main thread (Phase 3), we must NOT acquire
//! read lock — main thread is the writer, same-thread read+write deadlocks.
//! Main thread path skips the lock (it can't race with itself).

use libc::c_void;

use super::destruction_guard;
use super::statics;

const RDATA_START: usize = 0x01000000;
const RDATA_END: usize = 0x01300000;

pub unsafe extern "fastcall" fn hook_task_release(this: *mut c_void) {
    if this.is_null() {
        return;
    }

    if super::delayed_free::is_main_thread() {
        // Main thread: no read lock (writer thread, would deadlock).
        // Safe: main thread can't race with its own drain.
        unsafe { validate_and_release(this) };
    } else {
        // Worker thread (BSTaskManagerThread): read lock protects against
        // concurrent quarantine drain. try_read: if drain in progress,
        // skip release (task will be leaked but avoids crash).
        destruction_guard::try_read(|| {
            unsafe { validate_and_release(this) };
        });
    }
}

unsafe fn validate_and_release(this: *mut c_void) {
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
}

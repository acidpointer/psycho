//! Queued reference processing hook (FUN_0056f700).
//!
//! Full read lock during original call. Internal frees go to quarantine
//! via try_write (non-blocking). Flushed after read lock released.

use libc::c_void;

use super::destruction_guard;
use super::statics;

const TESFORM_FLAGS_OFFSET: usize = 0x08;
const FLAG_HAVOK_DEATH: u32 = 0x10000;

pub unsafe extern "fastcall" fn hook_queued_ref_process(refr: *mut c_void) {
    if refr.is_null() {
        return;
    }

    destruction_guard::read(|| {
        let flags = unsafe { *((refr as *const u8).add(TESFORM_FLAGS_OFFSET) as *const u32) };
        if flags & FLAG_HAVOK_DEATH != 0 {
            return;
        }

        if let Ok(original) = statics::QUEUED_REF_PROCESS_HOOK.original() {
            unsafe { original(refr) };
        }
    });
}

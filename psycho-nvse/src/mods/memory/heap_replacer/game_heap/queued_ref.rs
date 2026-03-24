//! Queued reference processing hook (FUN_0056f700).
//!
//! Skips processing for characters with HAVOK_DEATH flag (0x10000).
//! After ragdoll death, the Havok allocator frees bone/physics data
//! but the game still queues a reference update. The original function
//! would read freed Havok memory → crash.
//!
//! Called from main thread during per-frame processing.
//! NO read lock: main thread is the writer, can't race with itself.

use libc::c_void;

use super::statics;

const TESFORM_FLAGS_OFFSET: usize = 0x08;
const FLAG_HAVOK_DEATH: u32 = 0x10000;

pub unsafe extern "fastcall" fn hook_queued_ref_process(refr: *mut c_void) {
    if refr.is_null() {
        return;
    }

    let flags = unsafe { *((refr as *const u8).add(TESFORM_FLAGS_OFFSET) as *const u32) };
    if flags & FLAG_HAVOK_DEATH != 0 {
        return;
    }

    if let Ok(original) = statics::QUEUED_REF_PROCESS_HOOK.original() {
        unsafe { original(refr) };
    }
}

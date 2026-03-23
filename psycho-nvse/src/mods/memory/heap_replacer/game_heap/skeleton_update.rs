//! Skeleton update validation hook (FUN_00c79680).
//!
//! Validates ragdoll bone array pointer before access.
//! Holds heap read lock during the original call to prevent
//! concurrent memory recycling by worker threads.

use libc::c_void;

use super::destruction_guard;
use super::statics;

const BONE_ARRAY_OFFSET: usize = 0xA4;
const MIN_VALID_PTR: usize = 0x10000;

pub unsafe extern "fastcall" fn hook_skeleton_update(ragdoll: *mut c_void) {
    if ragdoll.is_null() {
        return;
    }

    destruction_guard::read(|| {
        let bone_array = unsafe {
            std::ptr::read_volatile(
                (ragdoll as *const u8).add(BONE_ARRAY_OFFSET) as *const usize,
            )
        };

        if bone_array < MIN_VALID_PTR {
            return;
        }

        if let Ok(original) = statics::SKELETON_UPDATE_HOOK.original() {
            unsafe { original(ragdoll) };
        }
    });
}

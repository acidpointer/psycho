//! Skeleton update validation hook (FUN_00c79680).
//!
//! Validates ragdoll bone array pointer before access. With mimalloc,
//! freed ragdoll memory can be recycled, so bone_array may point to
//! garbage. Read lock prevents concurrent quarantine drain (mi_free)
//! during the original call.
//!
//! Called from AI worker threads during physics update.
//! Read lock: short-scoped (single function call, microseconds).

use libc::c_void;

use super::destruction_guard;
use super::statics;

const BONE_ARRAY_OFFSET: usize = 0xA4;
const MIN_VALID_PTR: usize = 0x10000;

pub unsafe extern "fastcall" fn hook_skeleton_update(ragdoll: *mut c_void) {
    if ragdoll.is_null() {
        return;
    }

    // Read lock: blocks quarantine drain while we validate + call original.
    // try_read: if write lock held (drain in progress), skip this update
    // rather than block an AI thread (would delay AI_JOIN → frame stall).
    destruction_guard::try_read(|| {
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

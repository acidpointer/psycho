// Skeleton update validation hook (FUN_00c79680).
//
// Called from AI worker threads during physics update.
// Always worker thread — with_try_read, skip if drain active.

use libc::c_void;

use super::engine::addr;
use super::game_guard;
use super::statics;

pub unsafe extern "fastcall" fn hook_skeleton_update(ragdoll: *mut c_void) {
    if ragdoll.is_null() {
        return;
    }

    game_guard::with_try_read(|| {
        let vtable = unsafe { *(ragdoll as *const usize) };
        if !(addr::RDATA_START..addr::RDATA_END).contains(&vtable) {
            return;
        }

        let bone_array = unsafe {
            std::ptr::read_volatile(
                (ragdoll as *const u8).add(addr::RAGDOLL_BONE_ARRAY_OFFSET) as *const usize,
            )
        };
        if bone_array < addr::MIN_VALID_PTR {
            return;
        }

        if let Ok(original) = statics::SKELETON_UPDATE_HOOK.original() {
            unsafe { original(ragdoll) };
        }
    });
}

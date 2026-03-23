//! Skeleton update validation hook.
//!
//! FUN_00c79680 (963 bytes, fastcall) updates a ragdoll controller's
//! skeleton bone transforms. It reads the bone array pointer at
//! ragdoll+0xa4. If the ragdoll controller was freed and recycled by
//! mimalloc, this pointer is garbage (typically 0 or small value),
//! causing a crash at 0x00A6DF48 reading address 0x34.
//!
//! This is a timing/synchronization issue: ragdoll controllers can be
//! freed at any time (normal refcount decrement, PDD, cell transition),
//! but QueuedCharacter processing reads them later via IOManager Phase 3.
//! With SBM, freed memory stayed readable as zombies. With mimalloc,
//! it's recycled immediately.
//!
//! Fix: validate the bone array pointer before the original function
//! reads it. If it's NULL or clearly invalid (< 0x10000), skip the update.

use libc::c_void;

use super::destruction_guard;
use super::statics;

/// Offset of the bone array pointer within the ragdoll controller.
/// FUN_00c79680 reads *(param_1 + 0xa4) as the bone array base.
const BONE_ARRAY_OFFSET: usize = 0xA4;

/// Minimum valid pointer value. Anything below this is clearly
/// freed/recycled memory (NULL, small mimalloc metadata values, etc.).
const MIN_VALID_PTR: usize = 0x10000;

/// Hook for FUN_00c79680 (skeleton update, fastcall, param_1 in ECX).
/// Validates the ragdoll's bone array pointer before calling original.
pub unsafe extern "fastcall" fn hook_skeleton_update(ragdoll: *mut c_void) {
    if ragdoll.is_null() {
        return;
    }

    // Defense-in-depth: skip if destruction is actively freeing objects.
    if destruction_guard::is_destruction_active() {
        return;
    }

    // Validate bone array pointer at ragdoll+0xa4.
    // If the ragdoll was freed and recycled, this field contains
    // garbage (0, small values, or mimalloc metadata).
    let bone_array_ptr_addr = unsafe { (ragdoll as *const u8).add(BONE_ARRAY_OFFSET) } as *const usize;
    let bone_array = unsafe { std::ptr::read_volatile(bone_array_ptr_addr) };

    if bone_array < MIN_VALID_PTR {
        // Bone array is NULL or invalid — ragdoll was freed.
        // Skip skeleton update to prevent crash.
        return;
    }

    if let Ok(original) = statics::SKELETON_UPDATE_HOOK.original() {
        unsafe { original(ragdoll) };
    }
}

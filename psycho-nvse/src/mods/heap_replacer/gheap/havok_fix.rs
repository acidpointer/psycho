//! Havok vanilla-bug shims.
//!
//! `FUN_00CFFA00` (hkpEntity::fireAddedToWorldCallbacks) is called by
//! `hkpWorld::addEntityBatch` (FUN_00C94BD0) once per slot in the array
//! produced by `hkp3AxisSweep::addObjectBatch`. The broadphase result
//! array is allowed to contain NULL slots -- there is a dedicated
//! compactor (FUN_00D00370) that removes NULLs from other world-owned
//! arrays precisely because null slots are a normal outcome. The outer
//! loop in `addEntityBatch` forgets to filter, and the very first
//! instruction of `FUN_00CFFA00` is:
//!
//!     MOV EBX, dword ptr [EAX + 0x214]   ; EAX = entity
//!
//! so a NULL slot reaches instruction zero and faults reading `[0x214]`.
//! Vanilla almost never hits it -- gheap's different allocation layout
//! and timing make the sparse outcome reproducible on AI Linear Task
//! Thread 2 within minutes of stress flight. See
//! analysis/ghidra/output/crash/crash_cffa08_dataflow.txt.
//!
//! The fix: inline-hook `FUN_00CFFA00` entry and bail out when the entity
//! is NULL. One `test/jz` on the hot path, no behavioral change otherwise.

use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;

use super::statics;

/// Counts how many times we skipped a NULL entity. Referenced by the log
/// threshold below -- a nonzero value means the vanilla bug is firing.
static NULL_SKIPS: AtomicU64 = AtomicU64::new(0);

/// Detour for `FUN_00CFFA00`. Skips the call entirely when the game passes
/// a NULL entity pointer; otherwise tail-calls the original trampoline.
pub unsafe extern "C" fn hook_havok_entity_post_add(entity: *mut c_void) {
    if entity.is_null() {
        let n = NULL_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
        // Log at power-of-two boundaries so a misbehaving session that
        // fires thousands of times per frame does not flood the log.
        if n == 1 || n.is_power_of_two() {
            log::warn!(
                "[HAVOK] FUN_00CFFA00 NULL entity skipped (total={}). \
                 hkp3AxisSweep::addObjectBatch produced a sparse result.",
                n,
            );
        }
        return;
    }

    match statics::HAVOK_ENTITY_POST_ADD_HOOK.original() {
        Ok(original) => unsafe { original(entity) },
        Err(e) => {
            log::error!("[HAVOK] FUN_00CFFA00 original trampoline missing: {:?}", e);
        }
    }
}

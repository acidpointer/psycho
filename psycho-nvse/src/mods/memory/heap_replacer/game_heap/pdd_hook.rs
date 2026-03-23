//! PDD (ProcessDeferredDestruction) hook.
//!
//! Wraps the core destruction function with heap write lock.
//! Readers (skeleton_update, queued_ref, io_task) hold read lock
//! and will wait until PDD finishes before accessing game objects.

use libc::c_void;

use super::destruction_guard;
use super::statics;

pub unsafe extern "C" fn hook_pdd(try_lock: u8) {
    destruction_guard::write(|| {
        if let Ok(original) = statics::PDD_HOOK.original() {
            unsafe { original(try_lock) };
        }
    });
}

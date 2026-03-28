//! PDD (ProcessDeferredDestruction) hook.
//!
//! Pass-through. Gen queue deadlock is prevented by the quarantine's
//! demand-driven drain (real_commit threshold). Quarantine stays full
//! during normal gameplay -- Gen destructors access readable zombie
//! memory instead of garbage. No infinite loops.

use super::statics;

pub unsafe extern "C" fn hook_pdd(try_lock: u8) {
    if let Ok(original) = statics::PDD_HOOK.original() {
        unsafe { original(try_lock) };
    }
}

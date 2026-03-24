//! PDD (ProcessDeferredDestruction) hook.
//!
//! Pass-through. The game's own PDD lock (DAT_011de8e0) serializes
//! destruction. Quarantine provides UAF protection.

use super::statics;

pub unsafe extern "C" fn hook_pdd(try_lock: u8) {
    if let Ok(original) = statics::PDD_HOOK.original() {
        unsafe { original(try_lock) };
    }
}

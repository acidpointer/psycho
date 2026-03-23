//! PDD (ProcessDeferredDestruction) hook.
//!
//! FUN_00868d70 is the core destruction function called by ALL paths:
//! - 5 normal PDD callers (FUN_004556d0, FUN_005b6cd0, FUN_008782b0,
//!   FUN_0093cdf0, FUN_0093d500) via DeferredCleanupSmall
//! - CellTransitionHandler (FUN_008774a0)
//! - HeapCompact stages (FUN_00866a90)
//! - Per-frame drain (FUN_00868850) internal calls
//!
//! We wrap it with the destruction guard so ALL reader hooks know
//! when destruction is actively running, regardless of which caller
//! triggered it.

use libc::c_void;

use super::destruction_guard::DestructionScope;
use super::statics;

/// Hook for FUN_00868d70 (PDD, cdecl, param = try_lock flag).
/// Sets DESTRUCTION_ACTIVE for the duration of the original call.
pub unsafe extern "C" fn hook_pdd(try_lock: u8) {
    let _guard = DestructionScope::enter();

    if let Ok(original) = statics::PDD_HOOK.original() {
        unsafe { original(try_lock) };
    }
}

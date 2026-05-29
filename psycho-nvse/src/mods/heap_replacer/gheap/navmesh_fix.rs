//! Pathfinding/navmesh defensive shims.
//!
//! Stress testing under full gheap exposed a tasklet crash at
//! `0x0069083A`, inside `FUN_00690830`:
//!
//!     CMP dword ptr [EAX + 0x1c], 0
//!
//! The crash register state had `ECX=EAX=4`, so the pathfinding helper
//! received a small sentinel value where it expected a NavMeshInfo-like
//! object pointer. The immediate value is not gheap-owned memory
//! (`pool=false block=false mi=false` in crash_diag); gheap pressure
//! appears to expose a vanilla path/navmesh contract break.
//!
//! Returning a null identity is the least invasive repair. Known callers
//! either pass the helper result through the game's RTTI/dynamic-cast
//! helper, which already returns null for null input, or explicitly
//! branch on a zero result.

use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;

use super::statics;

static SMALL_PTR_SKIPS: AtomicU64 = AtomicU64::new(0);

const LOW_POINTER_LIMIT: usize = 0x10000;

/// Detour for `FUN_00690830`.
///
/// Valid game pointers are never in the first 64 KB of address space.
/// Treating null/low values as "identity unavailable" avoids the
/// tasklet crash without changing behavior for valid NavMeshInfo data.
pub unsafe extern "fastcall" fn hook_navmesh_name_helper(info: *mut c_void) -> *mut c_void {
    let addr = info as usize;
    if addr < LOW_POINTER_LIMIT {
        log_small_pointer_skip(addr);
        return core::ptr::null_mut();
    }

    match statics::NAVMESH_NAME_HELPER_HOOK.original() {
        Ok(original) => unsafe { original(info) },
        Err(e) => {
            log::error!(
                "[NAVMESH] FUN_00690830 original trampoline missing: {:?}",
                e
            );
            core::ptr::null_mut()
        }
    }
}

fn log_small_pointer_skip(addr: usize) {
    let n = SMALL_PTR_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[NAVMESH] low endpoint pointer skipped: ptr=0x{:08X}, total={}. \
             Treating path identity as unavailable.",
            addr,
            n,
        );
    }
}

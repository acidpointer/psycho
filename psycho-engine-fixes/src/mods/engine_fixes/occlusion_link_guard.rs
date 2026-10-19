//! Reject unreadable native occlusion-plane inputs before compound construction.
//!
//! Six game-owned callers share the thiscall(context, plane), RET 4 contract.
//! Their void builder already permits no contribution. Guarded copies admit the
//! source's complete 0xFC-byte range and its selected linked plane's range before
//! any builder output changes. Unselected links are not dereferenced. Readable
//! inputs reach the captured provider once; rejection contributes nothing and
//! leaves engine objects and ownership intact.
//!
//! Installation is transactional at quiescent pre-CRT startup. Predecessors are
//! published before activation; an unadmitted rollback survivor forwards directly.
//! No pointer escapes its call. Admission uses one stack buffer and at most two
//! guarded copies, without allocation, locks or routine logging. Copies prove
//! readability only: readable stale objects and post-copy invalidation retain the
//! native provider's lifetime/threading preconditions. Gameplay cost is unmeasured.
//! See docs/crash_20261018_occlusion_link_plan.md for proof and qualification.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use anyhow::{Context, Result, ensure};
use libpsycho::os::windows::{
    guarded_memory::{prepare_current_process_memory_reader, read_current_process_memory},
    hook::{callsite::Rel32CallHookContainer, transaction::ModificationTransaction},
    winapi::{get_last_error_code, set_last_error},
};

type Builder = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

const PLANE_SIZE: usize = 0xFC;
const LINK_OFFSET: usize = 0xEC;
const LINK_COUNT: usize = 4;
// C35980 prefers axis 0/2; C47D3A..C47DBE selects one occupied slot on that axis.
const LINK_ORDER: [usize; LINK_COUNT] = [0, 2, 1, 3];
const CALL_COUNT: usize = 6;

struct Callsite {
    address: usize,
    before: &'static [u8],
    after: &'static [u8],
    detour: Builder,
}

// Complete argument setup and three following instructions. The intervening
// E8 target remains dynamic: capture the installed provider, not a code allowlist.
const CALLS: [Callsite; CALL_COUNT] = [
    Callsite {
        address: 0x00B5F285,
        before: &[0x56, 0x8D, 0x8D, 0x38, 0x01, 0x00, 0x00],
        after: &[0x3B, 0xFB, 0x75, 0xA9, 0x80, 0x7C, 0x24, 0x17, 0x00],
        detour: build::<0>,
    },
    Callsite {
        address: 0x00B5F353,
        before: &[0x57, 0x8B, 0xCD],
        after: &[0x85, 0xF6, 0x75, 0xB7, 0x84, 0xDB],
        detour: build::<1>,
    },
    Callsite {
        address: 0x00B5F5BB,
        before: &[0x55, 0x8B, 0xCB],
        after: &[0x85, 0xF6, 0x75, 0xDC, 0x8B, 0x6C, 0x24, 0x18],
        detour: build::<2>,
    },
    Callsite {
        address: 0x00B5F6D3,
        before: &[0x55, 0x8B, 0xCB],
        after: &[0x85, 0xF6, 0x75, 0xD8, 0x85, 0xFF],
        detour: build::<3>,
    },
    Callsite {
        address: 0x00B5F822,
        before: &[0x55, 0x8D, 0x8B, 0x38, 0x01, 0x00, 0x00],
        after: &[0x85, 0xF6, 0x75, 0xD8, 0x8B, 0x5C, 0x24, 0x18],
        detour: build::<4>,
    },
    Callsite {
        address: 0x00B5F8EF,
        before: &[0x55, 0x8D, 0x8B, 0x38, 0x01, 0x00, 0x00],
        after: &[0x85, 0xF6, 0x75, 0xD8, 0x8B, 0x5C, 0x24, 0x18],
        detour: build::<5>,
    },
];

static HOOKS: [Rel32CallHookContainer<Builder>; CALL_COUNT] =
    [const { Rel32CallHookContainer::new() }; CALL_COUNT];
static PROVIDERS: [AtomicPtr<c_void>; CALL_COUNT] =
    [const { AtomicPtr::new(std::ptr::null_mut()) }; CALL_COUNT];
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REJECTION_REPORTED: AtomicBool = AtomicBool::new(false);

/// Guard all proven native callers without modifying the shared builder.
///
/// Exact caller context establishes the void thiscall ABI and ignored return.
/// Every predecessor is published before the first code write. Installation
/// failure rolls back owned calls; any surviving unadmitted bridge forwards.
pub(super) fn install() -> Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "occlusion-link installation requires the quiescent pre-CRT boundary"
    );
    prepare_current_process_memory_reader()?;
    for site in &CALLS {
        verify_context(site)?;
    }
    for (index, site) in CALLS.iter().enumerate() {
        // SAFETY: Verified game-owned argument setup and continuation prove
        // thiscall(context, plane), RET 4. The container captures the live E8.
        unsafe {
            HOOKS[index].init(
                "occlusion_link_guard",
                site.address as *mut c_void,
                site.detour,
            )
        }
        .with_context(|| format!("occlusion-link caller 0x{:08X}", site.address))?;
        PROVIDERS[index].store(HOOKS[index].original()? as *mut c_void, Ordering::Release);
    }
    let mut transaction = ModificationTransaction::new();
    for hook in &HOOKS {
        transaction.enable_callsite(hook)?;
    }
    transaction.commit();
    ADMITTED.store(true, Ordering::Release);
    log::info!("[OCCLUSION_LINK] Unreadable plane guard active at native compound callers");
    Ok(())
}

fn verify_context(site: &Callsite) -> Result<()> {
    // The longest audited prefix/suffix are seven and nine bytes respectively.
    let mut before = [0; 7];
    let mut after = [0; 9];
    read_current_process_memory(
        site.address - site.before.len(),
        &mut before[..site.before.len()],
    )?;
    read_current_process_memory(site.address + 5, &mut after[..site.after.len()])?;
    ensure!(
        &before[..site.before.len()] == site.before && &after[..site.after.len()] == site.after,
        "occlusion-link caller context mismatch at 0x{:08X}",
        site.address
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Rejection {
    address: usize,
    link: Option<usize>,
}

/// Admit complete object ranges without directly dereferencing engine storage.
/// Snapshots are discarded before forwarding; no object identity is inferred.
fn validate_planes(source: usize) -> std::result::Result<(), Rejection> {
    let mut snapshot = [0; PLANE_SIZE];
    if !copy_plane(source, &mut snapshot) {
        return Err(Rejection {
            address: source,
            link: None,
        });
    }
    for index in LINK_ORDER {
        let offset = LINK_OFFSET + index * 4;
        let target = u32::from_le_bytes([
            snapshot[offset],
            snapshot[offset + 1],
            snapshot[offset + 2],
            snapshot[offset + 3],
        ]) as usize;
        if target != 0 {
            // Only the selected target is consumed, including the repeated
            // axis-1 lookup at C486CF. Do not reject unreadable unused links or
            // fall back when the selected target is unreadable. Selection is
            // complete before reusing the source snapshot as the target buffer.
            return if copy_plane(target, &mut snapshot) {
                Ok(())
            } else {
                Err(Rejection {
                    address: target,
                    link: Some(index),
                })
            };
        }
    }
    Ok(())
}

fn copy_plane(address: usize, snapshot: &mut [u8; PLANE_SIZE]) -> bool {
    address.checked_add(PLANE_SIZE - 1).is_some()
        && read_current_process_memory(address, snapshot).is_ok()
}

/// The index is fixed by CALLS; each predecessor survives any failed rollback.
unsafe extern "thiscall" fn build<const INDEX: usize>(context: *mut c_void, plane: *mut c_void) {
    // SAFETY: Each of the six installed monomorphizations has its own captured
    // provider with this exact ABI, published before its caller is redirected.
    unsafe { dispatch(context, plane, PROVIDERS[INDEX].load(Ordering::Acquire)) };
}

unsafe fn dispatch(context: *mut c_void, plane: *mut c_void, provider: *mut c_void) {
    if ADMITTED.load(Ordering::Acquire) {
        let last_error = get_last_error_code();
        let result = validate_planes(plane as usize);
        if let Err(rejection) = result {
            report_rejection(plane, rejection);
            set_last_error(last_error);
            return;
        }
        set_last_error(last_error);
    }
    // SAFETY: Captured provider is non-null before code publication, including
    // unadmitted rollback survivors. Readable inputs retain native lifetime and
    // threading requirements; forward the original pointers exactly once.
    let original: Builder = unsafe { std::mem::transmute(provider) };
    unsafe { original(context, plane) };
}

#[cold]
fn report_rejection(source: *mut c_void, rejection: Rejection) {
    if !REJECTION_REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "[OCCLUSION_LINK] Cannot read plane range; source={source:p}, \
             rejected=0x{:08X}, link={:?}; this clipping contribution is omitted",
            rejection.address,
            rejection.link,
        );
    }
}

#[cfg(test)]
mod tests;

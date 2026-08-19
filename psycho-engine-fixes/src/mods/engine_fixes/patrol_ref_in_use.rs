//! `ExtraPatrolRefInUseData` actor FormID containment.
//!
//! Patrol markers retain only the occupying actor's FormID at extra-data
//! offset `+0x0C`. Actor destruction releases that ID for reuse, so a later
//! lookup can legitimately return another live `TESForm`. Vanilla's validator
//! calls a `TESObjectREFR`-only virtual slot before its later actor-type gate;
//! the reported AI-thread crash resolved the stale ID to a `CombatController`
//! and dispatched through data beyond that shorter vtable.
//!
//! This module redirects only the audited loaded-form lookup in that validator.
//! Character and Creature references pass through unchanged. Any other form or
//! identity mismatch is returned as NULL, which preserves the validator's own
//! recovery path: it clears the stale saved ID and treats the marker as
//! available. Psycho never mutates the extra list or changes global FormID
//! resolution. The extra has no generation token, so reuse by another actor of
//! the same subtype remains indistinguishable from the original owner.
//!
//! Installation is attempted only when the default-on
//! `engine_fixes.patrol_owner_form_id_guard` setting admits it, and preserves
//! an ABI-compatible direct-call predecessor. The valid runtime path performs
//! no allocation, locking, OS query, or logging. It relies on the surrounding
//! native AI evaluation keeping a non-NULL result readable as a `TESForm` for
//! this synchronous call; the resolver itself does not pin the object. The
//! guard inspects only the base type and FormID fields on the valid path.

use std::{
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use anyhow::{Context, ensure};
use libc::c_void;
use libpsycho::{ffi::fnptr::FnPtr, os::windows::winapi::virtual_query};

use crate::mods::diagnostics;

use super::patching;

const PATROL_OWNER_RESOLVE_CALL_ADDR: usize = 0x0043_7ADD;
const LOADED_FORM_RESOLVER_ADDR: usize = 0x0048_39C0;

const TES_FORM_TYPE_OFFSET: usize = 0x04;
const TES_FORM_REF_ID_OFFSET: usize = 0x0C;
const TES_FORM_LAST_READ_OFFSET: usize = 0x0F;
const CHARACTER_FORM_TYPE: u8 = 0x3B;
const CREATURE_FORM_TYPE: u8 = 0x3C;
const LOW_POINTER_LIMIT: usize = 0x1_0000;
const DETAILED_LOG_LIMIT: u64 = 16;

// These fixed bytes prove the saved-ID source, the unsafe virtual-call order,
// and the native NULL repair. The chainable CALL displacement is excluded.
const CALL_SITE_PREFIX_ADDR: usize = 0x0043_7AD6;
const CALL_SITE_PREFIX: &[u8] = &[0x8B, 0x55, 0xF4, 0x8B, 0x42, 0x0C, 0x50];
const CALL_SITE_SUFFIX_ADDR: usize = 0x0043_7AE2;
const CALL_SITE_SUFFIX: &[u8] = &[
    0x83, 0xC4, 0x04, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x00, 0x74, 0x28, 0x6A, 0x00, 0x8B, 0x4D,
    0xFC, 0x8B, 0x11, 0x8B, 0x4D, 0xFC, 0x8B, 0x82, 0x2C, 0x02, 0x00, 0x00, 0xFF, 0xD0, 0x0F, 0xB6,
    0xC8, 0x85, 0xC9, 0x75, 0x0F,
];
const NULL_REPAIR_ADDR: usize = 0x0043_7B16;
const NULL_REPAIR_BYTES: &[u8] = &[
    0x8B, 0x45, 0xF4, 0xC7, 0x40, 0x0C, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x01, 0xEB, 0x66,
];

type LoadedFormResolverFn = unsafe extern "C" fn(u32) -> *mut c_void;

static RESOLVER_PREDECESSOR: AtomicUsize = AtomicUsize::new(LOADED_FORM_RESOLVER_ADDR);
static REJECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static PREDECESSOR_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug)]
struct FormIdentity {
    vtable: usize,
    type_id: u8,
    ref_id: u32,
}

#[derive(Clone, Copy, Debug)]
struct Rejection {
    reason: &'static str,
    identity: Option<FormIdentity>,
}

/// Install the patrol-owner lookup guard while preserving a direct-call owner.
///
/// This must run once on the pregame startup thread, before AI work can enter
/// the audited callsite. It verifies the surrounding validator and native NULL
/// repair, publishes the captured ABI-compatible predecessor, and redirects
/// only the direct resolver call.
///
/// # Errors
///
/// Returns an error when the executable fingerprint, predecessor, or callsite
/// patch is unsafe. Preparation failures leave the callsite unchanged.
pub(super) fn install() -> anyhow::Result<()> {
    unsafe { patching::verify_bytes(CALL_SITE_PREFIX_ADDR, CALL_SITE_PREFIX) }
        .context("verify ExtraPatrolRefInUseData resolver prefix")?;
    unsafe { patching::verify_bytes(CALL_SITE_SUFFIX_ADDR, CALL_SITE_SUFFIX) }
        .context("verify ExtraPatrolRefInUseData resolver suffix")?;
    unsafe { patching::verify_bytes(NULL_REPAIR_ADDR, NULL_REPAIR_BYTES) }
        .context("verify ExtraPatrolRefInUseData NULL repair")?;

    let predecessor = unsafe { patching::relative_call_target(PATROL_OWNER_RESOLVE_CALL_ADDR) }
        .context("read ExtraPatrolRefInUseData resolver call")?;
    let replacement = resolve_patrol_actor_checked as *mut c_void;
    if predecessor == replacement as usize {
        INSTALLED.store(true, Ordering::Release);
        log::info!("[AI_PATROL] Patrol owner FormID guard active");
        return Ok(());
    }
    ensure!(
        is_executable(predecessor),
        "patrol owner resolver target 0x{predecessor:08X} is not executable"
    );

    // Startup has not admitted game work yet. Publish the predecessor before
    // the callsite so no caller can observe the wrapper without its chain.
    RESOLVER_PREDECESSOR.store(predecessor, Ordering::Release);
    let displaced =
        unsafe { patching::redirect_relative_call(PATROL_OWNER_RESOLVE_CALL_ADDR, replacement) }
            .context("redirect ExtraPatrolRefInUseData resolver call")?;
    if displaced != predecessor {
        let actual_chain = select_safe_chain(displaced, replacement as usize);
        RESOLVER_PREDECESSOR.store(actual_chain, Ordering::Release);
        log::warn!(
            "[AI_PATROL] Resolver changed during installation; chaining actual target 0x{actual_chain:08X}"
        );
    }

    INSTALLED.store(true, Ordering::Release);
    log::info!("[AI_PATROL] Patrol owner FormID guard active");
    Ok(())
}

/// Whether the audited patrol-owner resolver call was redirected successfully.
pub(super) fn is_installed() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

fn select_safe_chain(displaced: usize, replacement: usize) -> usize {
    if displaced != replacement && is_executable(displaced) {
        displaced
    } else {
        LOADED_FORM_RESOLVER_ADDR
    }
}

/// Resolve one saved patrol-owner FormID and admit only live actor references.
///
/// # Safety
///
/// This function is entered only from the audited cdecl call at `0x00437ADD`.
/// The captured predecessor must preserve the exact `u32 -> TESForm*` ABI. A
/// non-NULL result must remain readable while the surrounding native AI
/// evaluation and this wrapper synchronously inspect its `TESForm` base.
unsafe extern "C" fn resolve_patrol_actor_checked(saved_ref: u32) -> *mut c_void {
    let mut target = RESOLVER_PREDECESSOR.load(Ordering::Acquire);
    if target < LOW_POINTER_LIMIT || target == resolve_patrol_actor_checked as *const () as usize {
        log_predecessor_fallback_once();
        target = LOADED_FORM_RESOLVER_ADDR;
    }

    let resolve = unsafe { FnPtr::<LoadedFormResolverFn>::from_address_unchecked(target) }.as_fn();
    let candidate = unsafe { resolve(saved_ref) };
    if candidate.is_null() {
        return candidate;
    }

    match unsafe { inspect_patrol_actor(candidate, saved_ref) } {
        Ok(()) => candidate,
        Err(rejection) => {
            log_rejection(saved_ref, candidate, rejection);
            ptr::null_mut()
        }
    }
}

/// Validate the base identity needed before vanilla's actor-only dispatch.
///
/// # Safety
///
/// `candidate` must be a non-NULL result from the captured loaded-form
/// resolver and remain readable through `TESForm` offset `+0x0F` for this
/// synchronous inspection.
unsafe fn inspect_patrol_actor(candidate: *mut c_void, saved_ref: u32) -> Result<(), Rejection> {
    let address = candidate as usize;
    if address < LOW_POINTER_LIMIT {
        return Err(Rejection {
            reason: "low-pointer",
            identity: None,
        });
    }
    if address & 3 != 0 {
        return Err(Rejection {
            reason: "unaligned-pointer",
            identity: None,
        });
    }
    if address.checked_add(TES_FORM_LAST_READ_OFFSET).is_none() {
        return Err(Rejection {
            reason: "pointer-overflow",
            identity: None,
        });
    }

    // SAFETY: The caller provides the lifetime contract above. Unaligned reads
    // keep this boundary exact without asserting stronger Rust alignment.
    let type_id = unsafe { ptr::read_unaligned((address + TES_FORM_TYPE_OFFSET) as *const u8) };
    let ref_id = unsafe { ptr::read_unaligned((address + TES_FORM_REF_ID_OFFSET) as *const u32) };
    let reason = if !matches!(type_id, CHARACTER_FORM_TYPE | CREATURE_FORM_TYPE) {
        Some("wrong-form-type")
    } else if ref_id != saved_ref {
        Some("form-id-mismatch")
    } else {
        None
    };

    let Some(reason) = reason else {
        return Ok(());
    };

    // The vtable is diagnostic-only and is intentionally absent from the
    // valid AI-worker path.
    let vtable = unsafe { ptr::read_unaligned(address as *const u32) as usize };
    Err(Rejection {
        reason,
        identity: Some(FormIdentity {
            vtable,
            type_id,
            ref_id,
        }),
    })
}

#[cold]
#[inline(never)]
fn log_predecessor_fallback_once() {
    if !PREDECESSOR_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!("[AI_PATROL] Resolver predecessor unavailable; using native resolver");
    }
}

#[cold]
#[inline(never)]
fn log_rejection(saved_ref: u32, candidate: *mut c_void, rejection: Rejection) {
    let total = REJECTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if total > DETAILED_LOG_LIMIT && !diagnostics::should_log_power_of_two(total) {
        return;
    }

    if let Some(identity) = rejection.identity {
        log::warn!(
            "[AI_PATROL] Rejected invalid patrol owner: reason={} saved_id={saved_ref:08X} form={candidate:p} type={:02X} resolved_id={:08X} vtable=0x{:08X} total={total}; vanilla will clear the stale ID",
            rejection.reason,
            identity.type_id,
            identity.ref_id,
            identity.vtable,
        );
    } else {
        log::warn!(
            "[AI_PATROL] Rejected invalid patrol owner: reason={} saved_id={saved_ref:08X} form={candidate:p} total={total}; vanilla will clear the stale ID",
            rejection.reason,
        );
    }
}

fn is_executable(address: usize) -> bool {
    if address < LOW_POINTER_LIMIT {
        return false;
    }
    virtual_query(address as *mut c_void).is_ok_and(|info| info.is_executable())
}

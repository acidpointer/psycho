//! Keep NULL stored string keys out of the native model-cache comparison.
//!
//! Native LockFreeStringMap/LockFreeCaseInsensitiveStringMap ordering consumes
//! the key snapshot supplied by either native search template. Returning false
//! advances the existing cursor and hazard publication to the next entry; it
//! does not report a whole-map miss, remove a node, or change a model reference.
//! Non-NULL keys chain the provider captured at the shared ordering entry.
//!
//! One entry hook is prepared and activated at quiescent pre-CRT core startup.
//! Admission follows transaction commit. An unadmitted rollback survivor chains
//! its original provider, whose trampoline remains live for process lifetime.
//! Traversal fingerprints reject an unsupported consumer before activation.
//! This module owns no native map, node, string, lock, or allocation. It does
//! not validate non-NULL lifetimes or identify the writer of an invalid key.
//! Valid calls allocate, lock, log, and count nothing; the first rejected key
//! emits one recoverable warning through the core logger.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicPtr, Ordering},
    },
};

use anyhow::Result;
use libpsycho::os::windows::hook::{
    inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction,
};

// Both native consumers read AL. Preserve the captured provider's byte result
// rather than imposing Rust bool's canonical-value contract on another provider.
type OrderingFn = unsafe extern "thiscall" fn(*mut c_void, *const u8, *const u8) -> u8;
static ORDERING_HOOK: LazyLock<InlineHookContainer<OrderingFn>> =
    LazyLock::new(InlineHookContainer::new);
static PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REJECTION_REPORTED: AtomicBool = AtomicBool::new(false);

/// Install NULL-key rejection at the shared native string ordering entry.
///
/// Requires the supported executable and quiescent pre-CRT startup. Both
/// native search templates must retain their proven false/advance contract.
/// The installed entry provider is captured unchanged, including an earlier
/// hook. Preparation/fingerprint/activation errors leave admission false;
/// any rollback survivor forwards through the process-lifetime trampoline.
/// Successful installation is idempotent. No native cache state is edited.
pub(super) fn install() -> Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    // These templates share string predicates with other map specializations.
    // Guard the string provider, not a generic key: zero is valid for some
    // integer/pointer maps. Neither shared traversal nor its cleanup is patched.
    for (arguments, advance, restart) in [
        (0x666404, 0x666442, 0x6664CA),
        (0x529194, 0x5291D2, 0x52925A),
    ] {
        // SAFETY: Fixed, readable ranges in the supported main executable.
        // The argument snapshots, predicate slots, false branch, and native
        // cursor/hazard stores are verified before any entry write occurs.
        unsafe {
            super::patching::verify_bytes(arguments, ARGUMENTS_AND_PREDICATES)?;
            super::patching::verify_bytes(advance, &[0x8B, 0x4D, 0xE4, 0x83, 0xC1, 0x14])?;
            super::patching::verify_bytes(advance + 11, ADVANCE_STORES)?;
            super::patching::verify_bytes(advance + 44, &[0xEB, 0x5A])?;
            super::patching::verify_bytes(restart, RESTART_STORES)?;
        }
    }
    // SAFETY: Binary-proven thiscall(map, stored_key, query) -> AL, RET 8 at
    // 0x4496D0. Installation captures the provider already present at that
    // boundary without inspecting modules, vtables, or allocator ownership.
    unsafe {
        ORDERING_HOOK.init(
            "model_cache_null_stored_key",
            0x4496D0 as *mut c_void,
            ordering,
        )?;
    }
    PROVIDER.store(ORDERING_HOOK.original()? as *mut c_void, Ordering::Release);
    let mut tx = ModificationTransaction::new();
    tx.enable_inline(&ORDERING_HOOK)?;
    tx.commit();
    ADMITTED.store(true, Ordering::Release);
    log::info!("[MODEL_CACHE] Shared string-key NULL rejection active");
    Ok(())
}

// The relative CALLs differ between templates, so verify the invariant stores
// separately. Each predicate uses the same saved key; rejection also prevents
// the following equality predicate from consuming that NULL snapshot.
const ARGUMENTS_AND_PREDICATES: &[u8] = &[
    0x8B, 0x45, 0x0C, 0x50, 0x8B, 0x4D, 0xEC, 0x51, 0x8B, 0x55, 0xE4, 0x8B, 0x02, 0x8B, 0x4D, 0xE4,
    0x8B, 0x09, 0x8B, 0x10, 0x8B, 0x42, 0x34, 0xFF, 0xD0, 0x0F, 0xB6, 0xC8, 0x85, 0xC9, 0x74, 0x1E,
    0x8B, 0x55, 0x0C, 0x52, 0x8B, 0x45, 0xEC, 0x50, 0x8B, 0x4D, 0xE4, 0x8B, 0x11, 0x8B, 0x45, 0xE4,
    0x8B, 0x08, 0x8B, 0x12, 0x8B, 0x42, 0x38, 0xFF, 0xD0, 0xE9, 0xC3, 0, 0, 0,
];
const ADVANCE_STORES: &[u8] = &[0x83, 0xC0, 0x08, 0x8B, 0x4D, 0xE4, 0x89, 0x41, 0x10];
const RESTART_STORES: &[u8] = &[
    0x8B, 0x55, 0xE4, 0x8B, 0x42, 0x18, 0x8B, 0x4D, 0xE4, 0x89, 0x41, 0x14,
];

/// Compare through the captured provider, or skip a NULL stored key.
///
/// Safety: for non-NULL keys, map and both NUL-terminated strings must satisfy
/// the captured provider's original lifetime/threading contract. A rejected
/// key causes no access to map, query, node, string bytes, or reference counts.
/// Installation publishes the provider before exposing this function; it is
/// never cleared or reclaimed while a detour can remain callable.
unsafe extern "thiscall" fn ordering(
    map: *mut c_void,
    stored_key: *const u8,
    query: *const u8,
) -> u8 {
    if stored_key.is_null() && ADMITTED.load(Ordering::Acquire) {
        if !REJECTION_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("[MODEL_CACHE] NULL stored string key skipped; native search continues");
        }
        return 0;
    }
    // SAFETY: install publishes a non-NULL, exactly typed captured trampoline
    // before activation. It and the DLL live for process lifetime, including
    // unadmitted rollback survivors. All arguments pass through unchanged.
    let original: OrderingFn = unsafe { std::mem::transmute(PROVIDER.load(Ordering::Acquire)) };
    unsafe { original(map, stored_key, query) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_detour_rejects_null_stored_key_without_a_provider() {
        // Execute the shipped rejection boundary itself. No native cache or
        // comparator is mocked: rejection must not call any provider or read
        // the opaque receiver/query. No other test installs this engine hook.
        struct RestoreAdmission;
        impl Drop for RestoreAdmission {
            fn drop(&mut self) {
                ADMITTED.store(false, Ordering::Release);
                REJECTION_REPORTED.store(false, Ordering::Relaxed);
            }
        }
        let _restore = RestoreAdmission;
        ADMITTED.store(true, Ordering::Release);
        // SAFETY: the admitted NULL-key branch inspects no pointed-to storage.
        assert_eq!(
            unsafe { ordering(std::ptr::null_mut(), std::ptr::null(), c"".as_ptr().cast()) },
            0
        );
        // Repeated rejection must retain the same native false result after
        // the one-time warning has already been emitted.
        assert_eq!(
            unsafe { ordering(std::ptr::null_mut(), std::ptr::null(), c"".as_ptr().cast()) },
            0
        );
    }
}

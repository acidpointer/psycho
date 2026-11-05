//! Publish found-radio references only after native load fixup or empty reset.
//!
//! Native 0x008368B0 stores FormIDs in the list returned by 0x0079C080.
//! Only 0x00836AF0 converts them to borrowed TESObjectREFR pointers. A rejected
//! changed-form load can skip that conversion. All audited accessor consumers
//! tolerate NULL, so the accessor withholds the unresolved representation.
//! Valid, published lists reach the captured provider unchanged.
//!
//! Three game-owned cdecl CALLs bracket deserialization, fixup, and world reset.
//! Only fixup/reset completion republishes the list; deserialization return
//! deliberately does not. Reset is a world-lifecycle boundary, not an object
//! destructor hook. No engine memory, ownership, reference counts, allocator
//! metadata, or provider DLL is inspected or changed. Native writers remain
//! serialized by the engine's world-load lifecycle; readers observe an atomic
//! publication gate, not a new lifetime lock for pointers they already hold.
//!
//! Preparation/activation shares the save-integrity pre-CRT transaction. Until
//! commit, a rollback survivor only forwards. Runtime work is constant, with no
//! allocation, list traversal, OS probe, TLS, or lock. The first withheld query
//! per unavailable interval is logged with LastError preserved.
//! See docs/save_integrity.md for binary proof, exception, and remaining limits.

use std::{
    ffi::c_void,
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    hook::{
        callsite::Rel32CallHookContainer, inline::inlinehook::InlineHookContainer,
        transaction::ModificationTransaction,
    },
    winapi::{get_last_error_code, set_last_error},
};

use super::patching;

type RadioDataFn = unsafe extern "C" fn(*mut c_void);
type RadioResetFn = unsafe extern "C" fn();
type FoundReferencesFn = unsafe extern "C" fn() -> *mut c_void;

const DESERIALIZE_CALL: usize = 0x0084_BF3B;
const FIXUP_CALL: usize = 0x0084_C0B3;
const RESET_CALL: usize = 0x0086_B7A4;
const FOUND_REFERENCES: usize = 0x0079_C080;
const FOUND_REFERENCES_BYTES: [u8; 10] =
    [0x55, 0x8B, 0xEC, 0xB8, 0x9C, 0xD5, 0x1D, 0x01, 0x5D, 0xC3];

static DESERIALIZE: Rel32CallHookContainer<RadioDataFn> = Rel32CallHookContainer::new();
static FIXUP: Rel32CallHookContainer<RadioDataFn> = Rel32CallHookContainer::new();
static RESET: Rel32CallHookContainer<RadioResetFn> = Rel32CallHookContainer::new();
static ACCESSOR: LazyLock<InlineHookContainer<FoundReferencesFn>> =
    LazyLock::new(InlineHookContainer::new);
static ADMITTED: AtomicBool = AtomicBool::new(false);
static UNRESOLVED: AtomicBool = AtomicBool::new(false);
static REPORTED: AtomicBool = AtomicBool::new(false);

/// Capture providers without writing code or changing list publication.
pub(super) fn prepare() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "radio load publication requires the quiescent pre-CRT boundary"
    );
    // SAFETY: Fixed, mapped supported-executable instruction ranges. These
    // exact setup/continuation fingerprints prove cdecl arguments and cleanup;
    // the containers capture current CALL targets without provider allowlists.
    unsafe {
        patching::verify_bytes(DESERIALIZE_CALL - 4, &[0x8B, 0x45, 0x0C, 0x50])?;
        patching::verify_bytes(
            DESERIALIZE_CALL + 5,
            &[0x83, 0xC4, 0x04, 0xB0, 0x01, 0xEB, 0x35],
        )?;
        patching::verify_bytes(FIXUP_CALL - 4, &[0x8B, 0x55, 0x0C, 0x52])?;
        patching::verify_bytes(FIXUP_CALL + 5, &[0x83, 0xC4, 0x04, 0xB0, 0x01, 0xEB, 0x1B])?;
        // Adjacent no-argument calls retain their own mutable providers.
        patching::verify_bytes(RESET_CALL - 5, &[0xE8])?;
        patching::verify_bytes(RESET_CALL + 5, &[0xE8])?;
        patching::verify_bytes(RESET_CALL + 10, &[0xE8])?;
        patching::verify_bytes(RESET_CALL + 15, &[0xE8])?;
        patching::verify_bytes(
            RESET_CALL + 20,
            &[
                0x89, 0x85, 0x9C, 0xFC, 0xFF, 0xFF, 0x8B, 0x8D, 0x9C, 0xFC, 0xFF, 0xFF,
            ],
        )?;
        // Native UI caller: no arguments, EAX pointer result, NULL skips its
        // complete loop. This also anchors the shared entry's ABI when an
        // existing rel32 entry redirect must remain in the provider chain.
        patching::verify_bytes(0x0079_BF02, &[0xFF, 0xD2])?;
        patching::verify_bytes(0x0079_BF04, &[0xE8])?;
        patching::verify_bytes(0x0079_BF09, &[0x89, 0x45, 0xE8, 0xEB, 0x0B])?;
        patching::verify_bytes(
            0x0079_BF19,
            &[0x83, 0x7D, 0xE8, 0x00, 0x0F, 0x84, 0xF1, 0x00, 0x00, 0x00],
        )?;
        let entry = std::slice::from_raw_parts(FOUND_REFERENCES as *const u8, 10);
        ensure!(
            entry == FOUND_REFERENCES_BYTES || entry[0] == 0xE9,
            "unrecognized found-radio accessor entry"
        );

        DESERIALIZE.init(
            "radio_load_deserialize_publication",
            DESERIALIZE_CALL as *mut c_void,
            deserialize,
        )?;
        FIXUP.init(
            "radio_load_fixup_publication",
            FIXUP_CALL as *mut c_void,
            fixup,
        )?;
        RESET.init(
            "radio_load_reset_publication",
            RESET_CALL as *mut c_void,
            reset,
        )?;
        // The inline trampoline preserves either the verified native body or
        // a current entry JMP. Its target is never inspected or modified.
        ACCESSOR.init(
            "radio_found_references_publication",
            FOUND_REFERENCES as *mut c_void,
            found_references,
        )?;
    }
    Ok(())
}

/// Activate the complete support graph inside its caller's rollback owner.
pub(super) fn enable(transaction: &mut ModificationTransaction) -> Result<()> {
    transaction.enable_callsite(&DESERIALIZE)?;
    transaction.enable_callsite(&FIXUP)?;
    transaction.enable_callsite(&RESET)?;
    transaction.enable_inline(&ACCESSOR)?;
    Ok(())
}

/// Admit phase tracking only after the complete save-integrity commit.
pub(super) fn admit() {
    ADMITTED.store(true, Ordering::Release);
}

fn begin_unresolved() {
    REPORTED.store(false, Ordering::Relaxed);
    UNRESOLVED.store(true, Ordering::Release);
}

fn publish_resolved() {
    UNRESOLVED.store(false, Ordering::Release);
}

unsafe extern "C" fn deserialize(context: *mut c_void) {
    let Ok(original) = DESERIALIZE.original() else {
        // An enabled hook always has a captured predecessor. Missing support
        // must leave the accessor closed rather than publish unknown data.
        begin_unresolved();
        log::error!("[RADIO_LOAD] Deserialization predecessor unavailable");
        return;
    };
    if ADMITTED.load(Ordering::Acquire) {
        begin_unresolved();
    }
    // SAFETY: The exact caller owns context through the synchronous cdecl call.
    unsafe { original(context) };
    // Return is not publication: payloads remain FormIDs until native fixup.
}

unsafe extern "C" fn fixup(context: *mut c_void) {
    let Ok(original) = FIXUP.original() else {
        begin_unresolved();
        log::error!("[RADIO_LOAD] Fixup predecessor unavailable");
        return;
    };
    let admitted = ADMITTED.load(Ordering::Acquire);
    if admitted {
        begin_unresolved();
    }
    // SAFETY: This native owner converts or removes every serialized identity
    // before returning. The captured provider retains the same lifecycle ABI.
    unsafe { original(context) };
    if admitted {
        publish_resolved();
    }
}

unsafe extern "C" fn reset() {
    let Ok(original) = RESET.original() else {
        begin_unresolved();
        log::error!("[RADIO_LOAD] Reset predecessor unavailable");
        return;
    };
    let admitted = ADMITTED.load(Ordering::Acquire);
    if admitted {
        begin_unresolved();
    }
    // SAFETY: The sole native world-reset caller owns this no-argument call.
    // Native reset clears the found list before return; Psycho changes no node.
    unsafe { original() };
    if admitted {
        publish_resolved();
    }
}

unsafe extern "C" fn found_references() -> *mut c_void {
    if ADMITTED.load(Ordering::Acquire) && UNRESOLVED.load(Ordering::Acquire) {
        if !REPORTED.swap(true, Ordering::Relaxed) {
            let last_error = get_last_error_code();
            log::warn!(
                "[RADIO_LOAD] Withheld unresolved radio references; waiting for native load fixup or world reset"
            );
            set_last_error(last_error);
        }
        return ptr::null_mut();
    }
    // SAFETY: The verified shared accessor has no arguments and returns the
    // provider's borrowed list pointer. Admission never retains or changes it.
    match ACCESSOR.original() {
        Ok(original) => unsafe { original() },
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests;

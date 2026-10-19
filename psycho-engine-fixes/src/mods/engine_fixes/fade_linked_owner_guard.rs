//! Contain unreadable BSFadeNode linked owners at the actor-alpha callsite.
//!
//! Installation belongs to quiescent pre-CRT core startup. The process-lifetime
//! hook captures the existing helper, retaining its current callback provider.
//! Admission follows transaction commit; an unadmitted rollback survivor chains
//! the retained helper unchanged. No node, owner, vtable, or reference is owned
//! or modified here. Readable inputs retain the helper's lifetime/threading
//! contract: guarded copies do not pin objects or prevent later invalidation.
//!
//! Admission copies one or three four-byte ranges through the existing Win32
//! guarded reader. It checks only the prefix consumed by the native type test,
//! without calling that test or inspecting actor-only state. Failure returns
//! the native neutral alpha, 1.0. Valid calls allocate, lock, log, and count
//! nothing; the first rejection emits one warning. Actual API cost is unmeasured.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    guarded_memory::{prepare_current_process_memory_reader, read_current_process_memory},
    hook::{callsite::Rel32CallHookContainer, transaction::ModificationTransaction},
    winapi::{get_last_error_code, set_last_error},
};

type AlphaFn = unsafe extern "thiscall" fn(*mut c_void) -> f32;

const CALLSITE: usize = 0x00B4E772;
const OWNER_OFFSET: usize = 0xCC;
const TYPE_SLOT_OFFSET: usize = 0x100;
const CALL_INPUT: &[u8] = &[
    0x8B, 0x0D, 0x38, 0x91, 0x1F, 0x01, 0x89, 0x8E, 0xC8, 0x00, 0x00, 0x00, 0x8B, 0xCE,
];
const CALL_OUTPUT: &[u8] = &[0xD9, 0x5C, 0x24, 0x18];

static ALPHA_HOOK: Rel32CallHookContainer<AlphaFn> = Rel32CallHookContainer::new();
static PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REJECTION_REPORTED: AtomicBool = AtomicBool::new(false);

/// Guard the supported fade consumer without changing its installed provider.
///
/// Requires the supported executable and quiescent pre-CRT startup. Fixed
/// input/output instructions must match before activating the five-byte CALL.
/// The live E8 callee is captured without constraining its target address.
/// Successful installation is idempotent. Preparation/activation failures keep
/// admission false, and a rollback survivor retains its callable predecessor.
pub(super) fn install() -> Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    prepare_current_process_memory_reader()?;
    let mut input = [0u8; CALL_INPUT.len()];
    let mut output = [0u8; CALL_OUTPUT.len()];
    read_current_process_memory(CALLSITE - input.len(), &mut input)?;
    read_current_process_memory(CALLSITE + 5, &mut output)?;
    ensure!(
        input == CALL_INPUT && output == CALL_OUTPUT,
        "fade alpha caller context mismatch at 0x{CALLSITE:08X}: input={input:02X?}, output={output:02X?}"
    );
    // SAFETY: The guarded copies verify the complete supported caller context.
    // The container validates/captures the intervening E8 before any code write.
    unsafe {
        // Binary-proven thiscall(node in ECX) -> x87 ST(0), no stack arguments.
        // Only this native caller is changed; callback registration stays live.
        ALPHA_HOOK.init("fade_linked_owner_guard", CALLSITE as *mut c_void, alpha)?;
    }
    PROVIDER.store(ALPHA_HOOK.original()? as *mut c_void, Ordering::Release);
    let mut tx = ModificationTransaction::new();
    tx.enable_callsite(&ALPHA_HOOK)?;
    tx.commit();
    ADMITTED.store(true, Ordering::Release);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rejection {
    OwnerSlot,
    OwnerVtable,
    TypeSlot,
}

impl Rejection {
    fn label(self) -> &'static str {
        match self {
            Self::OwnerSlot => "unreadable node owner slot",
            Self::OwnerVtable => "unreadable or NULL owner vtable",
            Self::TypeSlot => "unreadable owner type slot",
        }
    }
}

/// Copy only the prefix required before the provider's owner type test.
fn validate_owner_prefix(node: usize) -> Result<(), Rejection> {
    let owner = node
        .checked_add(OWNER_OFFSET)
        .and_then(read_word)
        .ok_or(Rejection::OwnerSlot)?;
    if owner == 0 {
        return Ok(());
    }
    let vtable = read_word(owner as usize)
        .filter(|&value| value != 0)
        .ok_or(Rejection::OwnerVtable)?;
    (vtable as usize)
        .checked_add(TYPE_SLOT_OFFSET)
        .and_then(read_word)
        .ok_or(Rejection::TypeSlot)?;
    Ok(())
}

/// Snapshot a complete 32-bit word without directly dereferencing foreign data.
fn read_word(address: usize) -> Option<u32> {
    address.checked_add(3)?;
    let mut bytes = [0u8; 4];
    read_current_process_memory(address, &mut bytes).ok()?;
    Some(u32::from_ne_bytes(bytes))
}

/// Forward readable inputs, or bypass only the unsafe owner-alpha lookup.
///
/// Safety: admitted inputs must retain the captured helper's original native
/// lifetime/threading contract after the copies. Installation publishes its
/// exactly typed, non-NULL predecessor before exposing this detour, and never
/// clears it while a detour, including a rollback survivor, can be called.
unsafe extern "thiscall" fn alpha(node: *mut c_void) -> f32 {
    if ADMITTED.load(Ordering::Acquire) {
        let last_error = get_last_error_code();
        let result = validate_owner_prefix(node as usize);
        if let Err(rejection) = result {
            if !REJECTION_REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "[FADE_OWNER] {}; node={node:p}; neutral alpha used without changing the linked owner",
                    rejection.label()
                );
            }
            set_last_error(last_error);
            return 1.0;
        }
        // Preserve the provider's input thread state, but do not overwrite
        // last-error changes that the provider itself may make afterward.
        set_last_error(last_error);
    }
    // SAFETY: install publishes this correctly typed process-lifetime callee
    // before the code write. Forward the original node exactly once and leave
    // the provider's result and side effects unchanged.
    let original: AlphaFn = unsafe { std::mem::transmute(PROVIDER.load(Ordering::Acquire)) };
    unsafe { original(node) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpsycho::os::windows::winapi::{
        native_system_layout, virtual_make_noaccess, virtual_release, virtual_reserve_commit,
    };

    /// Real OS-owned storage with a readable page followed by an unreadable one.
    struct Pages {
        base: *mut c_void,
        page_size: usize,
    }

    impl Pages {
        fn new() -> Self {
            let page_size = native_system_layout().page_size as usize;
            // SAFETY: Own the complete reservation until Drop; no aliasing
            // references or native objects are created in these test pages.
            let base = unsafe { virtual_reserve_commit(None, page_size * 2) };
            assert!(!base.is_null());
            let pages = Self { base, page_size };
            // SAFETY: The second page is within our live reservation.
            unsafe { virtual_make_noaccess(pages.unreadable() as *mut c_void, page_size) }
                .expect("protect the owned second page");
            pages
        }

        fn unreadable(&self) -> usize {
            self.base as usize + self.page_size
        }
    }

    impl Drop for Pages {
        fn drop(&mut self) {
            // SAFETY: This is the reservation base and all reads have ended.
            unsafe { virtual_release(self.base) }.expect("release the owned pages");
        }
    }

    fn node_prefix(owner: usize) -> [u8; OWNER_OFFSET + 4] {
        let mut bytes = [0; OWNER_OFFSET + 4];
        bytes[OWNER_OFFSET..].copy_from_slice(&(owner as u32).to_ne_bytes());
        bytes
    }

    #[test]
    fn production_admission_reads_only_the_required_prefix() {
        let pages = Pages::new();
        // The required four-byte type slot ends at the readable page boundary.
        // The unused actor-only +0x420 slot lies in the unreadable next page.
        let vtable = (pages.unreadable() - 4 - TYPE_SLOT_OFFSET) as u32;
        let node = node_prefix(std::ptr::addr_of!(vtable) as usize);
        assert_eq!(validate_owner_prefix(node.as_ptr() as usize), Ok(()));
        let null_owner = node_prefix(0);
        assert_eq!(validate_owner_prefix(null_owner.as_ptr() as usize), Ok(()));

        let unreadable_owner = node_prefix(pages.unreadable());
        assert_eq!(
            validate_owner_prefix(unreadable_owner.as_ptr() as usize),
            Err(Rejection::OwnerVtable)
        );
        let null_vtable = 0u32;
        let owner = node_prefix(std::ptr::addr_of!(null_vtable) as usize);
        assert_eq!(
            validate_owner_prefix(owner.as_ptr() as usize),
            Err(Rejection::OwnerVtable)
        );
    }

    #[test]
    fn production_detour_rejects_inaccessible_reads_without_a_provider() {
        // Execute the shipped detour and actual OS reader, with no mock helper
        // or reconstructed game callback. The supplied crash remains the game
        // failure; these checks support its defensive candidate only.
        struct RestoreAdmission;
        impl Drop for RestoreAdmission {
            fn drop(&mut self) {
                ADMITTED.store(false, Ordering::Release);
                REJECTION_REPORTED.store(false, Ordering::Relaxed);
            }
        }
        let pages = Pages::new();
        let vtable = (pages.unreadable() - TYPE_SLOT_OFFSET) as u32;
        let node = node_prefix(std::ptr::addr_of!(vtable) as usize);
        let partial_owner = node_prefix(pages.unreadable() - 2);
        let partial_type_vtable = (pages.unreadable() - 2 - TYPE_SLOT_OFFSET) as u32;
        let partial_type = node_prefix(std::ptr::addr_of!(partial_type_vtable) as usize);
        let overflowing_owner = node_prefix(usize::MAX - 2);
        let overflowing_type_vtable = u32::MAX - 0xFF;
        let overflowing_type = node_prefix(std::ptr::addr_of!(overflowing_type_vtable) as usize);
        let overflowing_type_end_vtable = u32::MAX - 0x102;
        let overflowing_type_end =
            node_prefix(std::ptr::addr_of!(overflowing_type_end_vtable) as usize);
        let inputs = [
            (node.as_ptr() as usize, Rejection::TypeSlot),
            (pages.unreadable() - OWNER_OFFSET, Rejection::OwnerSlot),
            (pages.unreadable() - 2 - OWNER_OFFSET, Rejection::OwnerSlot),
            (partial_owner.as_ptr() as usize, Rejection::OwnerVtable),
            (partial_type.as_ptr() as usize, Rejection::TypeSlot),
            (usize::MAX - 2, Rejection::OwnerSlot),
            (overflowing_owner.as_ptr() as usize, Rejection::OwnerVtable),
            (overflowing_type.as_ptr() as usize, Rejection::TypeSlot),
            (overflowing_type_end.as_ptr() as usize, Rejection::TypeSlot),
            (node.as_ptr() as usize, Rejection::TypeSlot),
        ];
        let _restore = RestoreAdmission;
        ADMITTED.store(true, Ordering::Release);
        for (address, expected) in inputs {
            assert_eq!(validate_owner_prefix(address), Err(expected));
            set_last_error(0x12345678);
            // SAFETY: These inputs must be rejected without any native helper
            // invocation or direct dereference. PROVIDER is intentionally NULL.
            assert_eq!(unsafe { alpha(address as *mut c_void) }, 1.0);
            assert_eq!(get_last_error_code(), 0x12345678);
        }
        // Rejection must leave the original node link and owner word intact.
        assert_eq!(
            read_word(node.as_ptr() as usize + OWNER_OFFSET),
            Some(std::ptr::addr_of!(vtable) as u32)
        );
        assert_eq!(read_word(std::ptr::addr_of!(vtable) as usize), Some(vtable));
        assert_eq!(read_word(usize::MAX - 2), None);
    }
}

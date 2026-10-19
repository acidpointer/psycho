//! Contain unreadable scene-owner base forms at the native physics lookup.
//!
//! The pre-CRT installer owns one process-lifetime callsite, not the shared
//! lookup entry. Readable inputs chain its live provider unchanged. Admission
//! walks the native parent/type-accessor contract without changing any node,
//! owner, reference count, or provider. Native type accessors are non-mutating
//! thiscall queries; their node and code lifetime must cover both this query
//! and the retained lookup. Snapshots do not pin objects or repair a race.
//!
//! Failure returns the existing NULL result supported by all discovered native
//! helper callers. See docs/crash_20261020_corvega_exit_scene_owner_plan.md.
//! Work is linear in visited parents with constant stack storage and no depth
//! limit. Cycle detection prevents an unbounded admission walk. Guarded reads
//! and executable-page queries add unmeasured OS cost; valid calls allocate,
//! lock, log, and count nothing. Only the first rejection emits a warning.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    guarded_memory::{prepare_current_process_memory_reader, read_current_process_memory},
    hook::{callsite::Rel32CallHookContainer, transaction::ModificationTransaction},
    winapi::{get_last_error_code, set_last_error, virtual_query},
};

type LookupFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FadeQueryFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;

const CALLSITE: usize = 0x0062B50C;
const CALL_INPUT: &[u8] = &[0x83, 0x7D, 0xF8, 0x00, 0x74, 0x0F, 0x8B, 0x4D, 0xF8, 0x51];
const CALL_OUTPUT: &[u8] = &[0x83, 0xC4, 0x04, 0x89, 0x45, 0xFC];
const PLAYER_SLOT: usize = 0x011DEA3C;
const PLAYER_NODE_OFFSET: usize = 0x694;
const FADE_QUERY_SLOT: usize = 0x10;
const PARENT_OFFSET: usize = 0x18;
const OWNER_OFFSET: usize = 0xCC;
const BASE_OFFSET: usize = 0x20;
const FORM_TYPE_OFFSET: usize = 4;
const AMMO_TYPE: u8 = 0x29;

static LOOKUP_HOOK: Rel32CallHookContainer<LookupFn> = Rel32CallHookContainer::new();
static PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REJECTION_REPORTED: AtomicBool = AtomicBool::new(false);

/// Install the cdecl scene lookup guard at quiescent pre-CRT startup.
///
/// Fixed caller context must match the supported executable. The complete live
/// E8 is captured and ownership-checked by the container, including rollback.
/// The predecessor remains published even if activation leaves a rollback
/// survivor. Admission is enabled only after transaction commit.
pub(super) fn install() -> Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    prepare_current_process_memory_reader()?;
    let mut input = [0; CALL_INPUT.len()];
    let mut output = [0; CALL_OUTPUT.len()];
    read_current_process_memory(CALLSITE - input.len(), &mut input)?;
    read_current_process_memory(CALLSITE + 5, &mut output)?;
    ensure!(
        input == CALL_INPUT && output == CALL_OUTPUT,
        "scene reference caller context mismatch at 0x{CALLSITE:08X}: input={input:02X?}, output={output:02X?}"
    );
    // SAFETY: Binary-proven cdecl(scene on stack) -> pointer in EAX, plain ret.
    // The guarded caller context qualifies the seam; the container captures
    // the live provider without classifying its code or module ownership.
    unsafe {
        LOOKUP_HOOK.init(
            "scene_reference_owner_guard",
            CALLSITE as *mut c_void,
            lookup,
        )?;
    }
    PROVIDER.store(LOOKUP_HOOK.original()? as *mut c_void, Ordering::Release);
    let mut tx = ModificationTransaction::new();
    tx.enable_callsite(&LOOKUP_HOOK)?;
    tx.commit();
    ADMITTED.store(true, Ordering::Release);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rejection {
    PlayerNode,
    TypeQuery,
    OwnerSlot,
    BaseSlot,
    BaseType,
    Parent,
    ParentCycle,
}

impl Rejection {
    fn label(self) -> &'static str {
        match self {
            Self::PlayerNode => "unreadable player scene link",
            Self::TypeQuery => "unreadable or non-executable fade query",
            Self::OwnerSlot => "unreadable fade owner slot",
            Self::BaseSlot => "unreadable owner base-form slot",
            Self::BaseType => "unreadable base-form type",
            Self::Parent => "unreadable scene parent",
            Self::ParentCycle => "cyclic scene parent chain",
        }
    }
}

/// Copy a complete range, rejecting address wrap before entering Win32.
fn read<const N: usize>(address: usize) -> Option<[u8; N]> {
    address.checked_add(N.checked_sub(1)?)?;
    let mut bytes = [0; N];
    read_current_process_memory(address, &mut bytes).ok()?;
    Some(bytes)
}

fn word_at(address: usize, offset: usize) -> Option<usize> {
    let bytes = read::<4>(address.checked_add(offset)?)?;
    Some(u32::from_le_bytes(bytes) as usize)
}

/// Check exactly the base-form reads shared by vanilla and optimized lookup.
///
/// NULL base forms are accepted: native lookup returns that owner unchanged.
/// Ammo requests parent resolution; other readable types end the search.
fn owner_is_ammo(owner: usize) -> Result<bool, Rejection> {
    let base = word_at(owner, BASE_OFFSET).ok_or(Rejection::BaseSlot)?;
    if base == 0 {
        return Ok(false);
    }
    let address = base
        .checked_add(FORM_TYPE_OFFSET)
        .ok_or(Rejection::BaseType)?;
    let [kind] = read::<1>(address).ok_or(Rejection::BaseType)?;
    Ok(kind == AMMO_TYPE)
}

/// Admit only the reads the native lookup reaches before returning an owner.
///
/// Safety: nodes and live virtual +0x10 accessors retain the native lookup's
/// non-mutating thiscall contract and lifetime. Page checks can reject missing
/// memory/code, but cannot establish identity of readable corrupt pointers.
unsafe fn validate_chain(mut node: usize) -> Result<(), Rejection> {
    if node == 0 {
        return Ok(());
    }
    let player = word_at(PLAYER_SLOT, 0).ok_or(Rejection::PlayerNode)?;
    let player_node = if player == 0 {
        0
    } else {
        word_at(player, PLAYER_NODE_OFFSET).ok_or(Rejection::PlayerNode)?
    };
    let mut checkpoint = node;
    let mut power = 1usize;
    let mut span = 0usize;
    while node != 0 {
        if node == player_node {
            return Ok(());
        }
        let vtable = word_at(node, 0).ok_or(Rejection::TypeQuery)?;
        let query = word_at(vtable, FADE_QUERY_SLOT).ok_or(Rejection::TypeQuery)?;
        if !virtual_query(query as *mut c_void).is_ok_and(|page| page.is_executable()) {
            return Err(Rejection::TypeQuery);
        }
        // SAFETY: Query uses the exact live slot, ECX and return ABI consumed
        // by native lookup. Its non-mutating type-accessor contract is required
        // of the original provider too; the checks do not prove object life.
        let query: FadeQueryFn = unsafe { std::mem::transmute(query) };
        let fade = unsafe { query(node as *mut c_void) } as usize;
        if fade != 0 {
            let owner = word_at(fade, OWNER_OFFSET).ok_or(Rejection::OwnerSlot)?;
            if owner != 0 && !owner_is_ammo(owner)? {
                return Ok(());
            }
        }
        node = word_at(node, PARENT_OFFSET).ok_or(Rejection::Parent)?;
        // Brent's detector uses only already-visited pointers. It performs no
        // second traversal or extra virtual calls and imposes no depth budget.
        if node != 0 && node == checkpoint {
            return Err(Rejection::ParentCycle);
        }
        span = span.checked_add(1).ok_or(Rejection::ParentCycle)?;
        if span == power {
            checkpoint = node;
            power = power.checked_mul(2).ok_or(Rejection::ParentCycle)?;
            span = 0;
        }
    }
    Ok(())
}

/// Reject inaccessible input before entering the captured reference provider.
///
/// Safety: installation publishes the process-lifetime, correctly typed
/// predecessor before activating the callsite. Readable inputs keep its native
/// lifetime/virtual-query requirements; admission neither retains nor mutates.
unsafe extern "C" fn lookup(node: *mut c_void) -> *mut c_void {
    if ADMITTED.load(Ordering::Acquire) {
        let last_error = get_last_error_code();
        // SAFETY: The detour inherits the live native scene-lookup contract.
        let result = unsafe { validate_chain(node as usize) };
        if let Err(reason) = result {
            if !REJECTION_REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "[SCENE_OWNER] {}; node={node:p}; lookup returned no reference",
                    reason.label()
                );
            }
            set_last_error(last_error);
            return std::ptr::null_mut();
        }
        set_last_error(last_error);
    }
    // SAFETY: The exactly typed provider is published before any callsite can
    // enter here and remains callable for rollback survivors. Forward once.
    let original: LookupFn = unsafe { std::mem::transmute(PROVIDER.load(Ordering::Acquire)) };
    unsafe { original(node) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpsycho::os::windows::winapi::{
        native_system_layout, virtual_make_noaccess, virtual_release, virtual_reserve_commit,
    };

    #[test]
    fn production_owner_admission_rejects_the_reported_base_pointer() {
        // Supporting the supplied runtime report: execute production admission
        // and the real OS reader. No provider or game execution is simulated.
        let mut owner = [0u32; (BASE_OFFSET + 4) / 4];
        owner[BASE_OFFSET / 4] = 1;
        assert_eq!(
            owner_is_ammo(owner.as_ptr() as usize),
            Err(Rejection::BaseType)
        );
        owner[BASE_OFFSET / 4] = 0;
        assert_eq!(owner_is_ammo(owner.as_ptr() as usize), Ok(false));
    }

    #[test]
    fn production_owner_admission_copies_only_the_consumed_type_byte() {
        struct Pages(*mut c_void);
        impl Drop for Pages {
            fn drop(&mut self) {
                // SAFETY: The test owns this complete reservation.
                unsafe { virtual_release(self.0) }.expect("release test pages");
            }
        }
        let page_size = native_system_layout().page_size as usize;
        // SAFETY: The test owns both pages until all production reads end.
        let pages = Pages(unsafe { virtual_reserve_commit(None, page_size * 2) });
        assert!(!pages.0.is_null());
        let edge = pages.0 as usize + page_size;
        // SAFETY: Both writes are in the live, writable first page. The second
        // page is protected only after setting the adjacent test type byte.
        unsafe {
            ((edge - 1) as *mut u8).write(AMMO_TYPE);
            virtual_make_noaccess(edge as *mut c_void, page_size).expect("protect second page");
        }
        let mut owner = [0u32; (BASE_OFFSET + 4) / 4];
        owner[BASE_OFFSET / 4] = (edge - 1 - FORM_TYPE_OFFSET) as u32;
        assert_eq!(owner_is_ammo(owner.as_ptr() as usize), Ok(true));
        owner[BASE_OFFSET / 4] += 1;
        assert_eq!(
            owner_is_ammo(owner.as_ptr() as usize),
            Err(Rejection::BaseType)
        );
        assert_eq!(
            owner_is_ammo(edge - BASE_OFFSET - 2),
            Err(Rejection::BaseSlot)
        );
        assert_eq!(owner_is_ammo(usize::MAX - 1), Err(Rejection::BaseSlot));
    }
}

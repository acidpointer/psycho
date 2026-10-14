//! Observe enrollment, physical publication and first-match removal independently.
//!
//! The native cell lock protects list traversal; sidecar keys do not retain an
//! engine object. Canonical enrollment precedes old-owner removal, so its caller
//! frame is an invocation token until publication. Reload begins at the actual
//! locked counter store and finishes before unlock from the surviving list.
//! Providers chain once. Unexpected publication, traversal overflow or counter
//! behavior blocks ordinary retirement without altering native ownership.

use super::{
    CELL_VWD_READY_OFFSET, CELL_VWD_TOTAL_OFFSET,
    native::{Site, word},
    read_cell_counter, read_pointer, state,
};
use libpsycho::{ffi::fnptr::FnPtr, os::windows::hook::transaction::ModificationTransaction};
use std::{
    ffi::c_void,
    sync::atomic::{AtomicU32, Ordering},
};

const LIST_LIMIT: usize = 4096;
type AppendFn = unsafe extern "thiscall" fn(*mut c_void, *const *mut c_void);
type RemoveFn = unsafe extern "thiscall" fn(*mut c_void, *const *mut c_void);
static MISMATCHES: AtomicU32 = AtomicU32::new(0);
static INTERIOR: Site = Site::new(
    "lod_canonical_interior",
    0x5482AB,
    &[0xE8, 0x20, 0x61, 6, 0],
    true,
);
static EXTERIOR: Site = Site::new(
    "lod_canonical_exterior",
    0x548344,
    &[0xE8, 0x87, 0x60, 6, 0],
    true,
);
static ALTERNATE_INTERIOR: Site = Site::new(
    "lod_physical_interior",
    0x548785,
    &[0xE8, 0x46, 0x5C, 6, 0],
    true,
);
static ALTERNATE_EXTERIOR: Site = Site::new(
    "lod_physical_exterior",
    0x548801,
    &[0xE8, 0xCA, 0x5B, 6, 0],
    true,
);
static REMOVE: Site = Site::new(
    "lod_physical_remove",
    0x54CB2C,
    &[0xE8, 0xFF, 0x87, 0x3B, 0],
    true,
);
static ENROLL: Site = Site::new(
    "lod_counter_enroll",
    0x54827F,
    &[0x66, 0x89, 0x81, 0xA8, 0, 0, 0],
    false,
);
static RELOAD: Site = Site::new(
    "lod_reload_epoch",
    0x5508E5,
    &[0x66, 0x89, 0x81, 0xA8, 0, 0, 0],
    false,
);
static RELOAD_UNLOCK: Site = Site::new(
    "lod_reload_survivors",
    0x550AF0,
    &[0xE8, 0xEB, 0x0F, 0xFF, 0xFF],
    true,
);

/// Native provider ownership and failed publication count for explicit reports.
pub(in crate::mods::engine_fixes) struct Snapshot {
    pub interior_predecessor: usize,
    pub exterior_predecessor: usize,
    pub publication_mismatches: u64,
}

/// Read atomic observer diagnostics without touching engine state.
pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        interior_predecessor: INTERIOR.provider(),
        exterior_predecessor: EXTERIOR.provider(),
        publication_mismatches: u64::from(MISMATCHES.load(Ordering::Relaxed)),
    }
}

/// Install every membership observer under the owning handoff transaction.
pub(super) fn install(tx: &mut ModificationTransaction) -> anyhow::Result<()> {
    // These exact surrounding instructions establish the frame-local owner,
    // reference-slot address and list interface. Only the provider E8 itself
    // may differ; unexpected calling contexts roll back the entire group.
    for (address, bytes) in [
        (
            0x548230,
            &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x1C, 0x89, 0x4D, 0xE4][..],
        ),
        (
            0x548740,
            &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 8, 0x89, 0x4D, 0xF8][..],
        ),
        (
            0x54829D,
            &[
                0x8D, 0x45, 8, 0x50, 0x8B, 0x4D, 0xE4, 0xE8, 0x47, 0x82, 0x41, 0, 0x8B, 0xC8,
            ][..],
        ),
        (
            0x548336,
            &[
                0x8D, 0x55, 8, 0x52, 0x8B, 0x4D, 0xE4, 0xE8, 0xAE, 0x81, 0x41, 0, 0x8B, 0xC8,
            ][..],
        ),
        (
            0x548777,
            &[
                0x8D, 0x4D, 8, 0x51, 0x8B, 0x4D, 0xF8, 0xE8, 0x6D, 0x7D, 0x41, 0, 0x8B, 0xC8,
            ][..],
        ),
        (
            0x5487F3,
            &[
                0x8D, 0x55, 8, 0x52, 0x8B, 0x4D, 0xF8, 0xE8, 0xF1, 0x7C, 0x41, 0, 0x8B, 0xC8,
            ][..],
        ),
        (
            0x54CB1E,
            &[
                0x8D, 0x55, 8, 0x52, 0x8B, 0x4D, 0xE4, 0xE8, 0xC6, 0x39, 0x41, 0, 0x8B, 0xC8,
            ][..],
        ),
        (0x54CB31, &[0x8B, 0x4D, 0xE4][..]),
        (0x550AED, &[0x8B, 0x4D, 0xB0][..]),
        (0x550AF5, &[0x8B, 0x4D, 0xB0][..]),
    ] {
        unsafe {
            super::super::patching::verify_bytes(address, bytes)?;
        }
    }
    for (site, entry) in [
        (&INTERIOR, interior as *const () as usize),
        (&EXTERIOR, exterior as *const () as usize),
        (
            &ALTERNATE_INTERIOR,
            alternate_interior as *const () as usize,
        ),
        (
            &ALTERNATE_EXTERIOR,
            alternate_exterior as *const () as usize,
        ),
        (&REMOVE, remove as *const () as usize),
        (&ENROLL, enroll as *const () as usize),
        (&RELOAD, reload as *const () as usize),
        (&RELOAD_UNLOCK, reload_unlock as *const () as usize),
    ] {
        site.install(tx, entry)?;
    }
    Ok(())
}

#[unsafe(naked)]
unsafe extern "thiscall" fn interior(_: *mut c_void, _: *const *mut c_void) {
    core::arch::naked_asm!("mov edx, ebp", "call {}", "ret 4", sym interior_body);
}
#[unsafe(naked)]
unsafe extern "thiscall" fn exterior(_: *mut c_void, _: *const *mut c_void) {
    core::arch::naked_asm!("mov edx, ebp", "call {}", "ret 4", sym exterior_body);
}
#[unsafe(naked)]
unsafe extern "thiscall" fn alternate_interior(_: *mut c_void, _: *const *mut c_void) {
    core::arch::naked_asm!("mov edx, ebp", "call {}", "ret 4", sym alternate_interior_body);
}
#[unsafe(naked)]
unsafe extern "thiscall" fn alternate_exterior(_: *mut c_void, _: *const *mut c_void) {
    core::arch::naked_asm!("mov edx, ebp", "call {}", "ret 4", sym alternate_exterior_body);
}
unsafe extern "fastcall" fn interior_body(list: *mut c_void, frame: usize) {
    unsafe { append(&INTERIOR, list, frame, -0x1C, true) };
}
unsafe extern "fastcall" fn exterior_body(list: *mut c_void, frame: usize) {
    unsafe { append(&EXTERIOR, list, frame, -0x1C, true) };
}
unsafe extern "fastcall" fn alternate_interior_body(list: *mut c_void, frame: usize) {
    unsafe { append(&ALTERNATE_INTERIOR, list, frame, -8, false) };
}
unsafe extern "fastcall" fn alternate_exterior_body(list: *mut c_void, frame: usize) {
    unsafe { append(&ALTERNATE_EXTERIOR, list, frame, -8, false) };
}

unsafe fn append(
    site: &Site,
    list: *mut c_void,
    frame: usize,
    cell_offset: isize,
    canonical: bool,
) {
    // Verified EBP/argument slots are live through this call; the native lock
    // owns both list and reference until the provider and observation finish.
    let cell = unsafe { word(frame, cell_offset) };
    let slot = (frame + 8) as *const *mut c_void;
    let reference = unsafe { slot.read_unaligned() };
    state::publication_begin(cell);
    let provider = unsafe { FnPtr::<AppendFn>::from_address_unchecked(site.provider()) }.as_fn();
    unsafe { provider(list, slot) };
    if reference.is_null() || read_pointer(list, 0) != Some(reference) {
        MISMATCHES.fetch_add(1, Ordering::Relaxed);
        state::publication_failed(cell);
        return;
    }
    state::publish(cell, reference as usize, frame, canonical);
}

#[unsafe(naked)]
unsafe extern "C" fn enroll() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, ebp", "call {}", "popad", "popfd",
        "mov [ecx + 0xA8], ax", "push 0x548286", "ret", sym enroll_body);
}
unsafe extern "fastcall" fn enroll_body(frame: usize) {
    state::reserve(
        unsafe { word(frame, -0x1C) },
        unsafe { word(frame, 8) },
        frame,
    );
}
#[unsafe(naked)]
unsafe extern "C" fn reload() {
    core::arch::naked_asm!("pushfd", "pushad", "call {}", "popad", "popfd",
        "mov [ecx + 0xA8], ax", "push 0x5508EC", "ret", sym reload_body);
}
unsafe extern "fastcall" fn reload_body(cell: usize) {
    state::begin_reload(cell);
}

#[unsafe(naked)]
unsafe extern "thiscall" fn remove(_: *mut c_void, _: *const *mut c_void) {
    core::arch::naked_asm!("mov edx, ebp", "call {}", "ret 4", sym remove_body);
}
unsafe extern "fastcall" fn remove_body(list: *mut c_void, frame: usize) {
    let cell = unsafe { word(frame, -0x1C) };
    let reference = unsafe { word(frame, 8) };
    let before = unsafe { occurrences(list, reference) };
    let provider = unsafe { FnPtr::<RemoveFn>::from_address_unchecked(REMOVE.provider()) }.as_fn();
    // Native 54CB1E passes the address of its stack argument. 905339 and
    // 90536A dereference this slot; forwarding the value changes the ABI.
    unsafe { provider(list, (frame + 8) as *const *mut c_void) };
    let after = unsafe { occurrences(list, reference) };
    if let (Some(before), Some(after)) = (before, after) {
        state::physical_remove(cell, reference, before, after);
    } else {
        state::mark_uncertain(cell as *mut c_void, total(cell), ready(cell));
    }
}

unsafe fn occurrences(mut node: *mut c_void, reference: usize) -> Option<usize> {
    let mut count = 0;
    for _ in 0..LIST_LIMIT {
        if node.is_null() {
            return Some(count);
        }
        if read_pointer(node, 0)? as usize == reference {
            count += 1;
        }
        node = read_pointer(node, 4)?;
    }
    node.is_null().then_some(count)
}

/// Read the real embedded list only while the caller holds CellRefLock.
unsafe fn with_members(cell: usize, action: impl FnOnce(&[usize])) -> bool {
    let mut members = [0usize; LIST_LIMIT];
    let mut count = 0;
    let mut node = (cell + 0xAC) as *mut c_void;
    for _ in 0..LIST_LIMIT {
        if node.is_null() {
            break;
        }
        let Some(reference) = read_pointer(node, 0) else {
            return false;
        };
        if !reference.is_null() {
            members[count] = reference as usize;
            count += 1;
        }
        let Some(next) = read_pointer(node, 4) else {
            return false;
        };
        node = next;
    }
    if !node.is_null() {
        return false;
    }
    members[..count].sort_unstable();
    action(&members[..count]);
    true
}

unsafe extern "thiscall" fn reload_unlock(cell: *mut c_void) {
    if !unsafe {
        with_members(cell as usize, |members| {
            state::finish_reload(cell as usize, members)
        })
    } {
        state::reload_snapshot_failed(cell as usize);
    }
    unsafe { super::native::call_owner(&RELOAD_UNLOCK, cell) };
}

/// Reconcile an uncertain identity ledger against the actual locked native list.
/// Native recursive locking preserves callers that already hold CellRefLock.
pub(super) unsafe fn reconcile(cell: *mut c_void) {
    if cell.is_null() || !state::needs_reconciliation(cell as usize) {
        return;
    }
    type LockFn = unsafe extern "thiscall" fn(*mut c_void);
    let lock = unsafe { FnPtr::<LockFn>::from_address_unchecked(0x541AC0) }.as_fn();
    let unlock = unsafe { FnPtr::<LockFn>::from_address_unchecked(0x541AE0) }.as_fn();
    unsafe { lock(cell) };
    unsafe {
        with_members(cell as usize, |members| {
            state::reconcile(cell as usize, members, total(cell as usize))
        })
    };
    unsafe { unlock(cell) };
}
fn total(cell: usize) -> i16 {
    read_cell_counter(cell as *mut c_void, CELL_VWD_TOTAL_OFFSET).unwrap_or(i16::MIN)
}
fn ready(cell: usize) -> i16 {
    read_cell_counter(cell as *mut c_void, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN)
}

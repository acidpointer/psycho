//! Atomic ordinary-handoff permission and scoped native hidden queries.
//!
//! The ledger serializes all publishers; geometry readers load cell identity,
//! mode and permission as one atomic word without allocation, locking or retry.
//! The supported target has 32-bit addresses, leaving room for both verdict
//! fields in an AtomicU64. A concurrent publication cannot turn a tracked
//! pending decision into an untracked fallback. Forced loading/save/grid writes
//! publish their mode before D0 changes. Untracked cells retain native behavior;
//! ordinary incomplete cells keep LOD. The full epoch belongs to the ledger,
//! which derives permission and invalidates it before native reset mutations.
//! A complete current epoch is required independently at the completion splice.

use super::{native::Site, state};
use libpsycho::{ffi::fnptr::FnPtr, os::windows::hook::transaction::ModificationTransaction};
use std::{
    ffi::c_void,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

const CAPACITY: usize = 4096;
const PROBES: usize = 32;
pub(super) const ORDINARY: u32 = 1;
pub(super) const FORCED: u32 = 2;
struct Slot {
    decision: AtomicU64,
}
impl Slot {
    fn new() -> Self {
        Self {
            decision: AtomicU64::new(0),
        }
    }
}
static TABLE: OnceLock<Box<[Slot]>> = OnceLock::new();
static OVERFLOW: AtomicU64 = AtomicU64::new(0);
static UNPUBLISHED_COMPLETIONS: AtomicU64 = AtomicU64::new(0);

fn slot(cell: usize, create: bool) -> Option<&'static Slot> {
    if cell == 0 {
        return None;
    }
    let table = TABLE.get()?;
    let start = (cell >> 4).wrapping_mul(0x9E3779B1) & (CAPACITY - 1);
    let mut empty = None;
    for offset in 0..PROBES {
        let slot = &table[(start + offset) & (CAPACITY - 1)];
        let key = slot.decision.load(Ordering::Acquire) as u32 as usize;
        if key == cell {
            return Some(slot);
        }
        if key == 0 {
            empty.get_or_insert(slot);
        }
    }
    if create { empty } else { None }
}

/// Publish under the ledger lock. No engine pointers are retained or followed.
pub(super) fn publish(cell: usize, mode: u32, allowed: bool) {
    let Some(slot) = slot(cell, true) else {
        OVERFLOW.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // All callers use neutral/ordinary/forced (0/1/2); other classifications
    // retain neutral native behavior rather than being interpreted as a hide.
    let mode = if mode <= FORCED { mode } else { 0 };
    let decision = u64::from(cell as u32) | (u64::from(mode) << 32) | (u64::from(allowed) << 34);
    slot.decision.store(decision, Ordering::Release);
}

/// Invalidate under the ledger lock before lifetime reuse or reset.
pub(super) fn invalidate(cell: usize) {
    if let Some(slot) = slot(cell, false) {
        slot.decision.store(0, Ordering::Release);
    }
}

/// Clear publications at the worldspace boundary under the ledger lock.
pub(super) fn reset() {
    if let Some(table) = TABLE.get() {
        for slot in table {
            slot.decision.store(0, Ordering::Release);
        }
    }
}

fn snapshot(cell: usize) -> Option<(u32, bool)> {
    if cell == 0 {
        return None;
    }
    let table = TABLE.get()?;
    let start = (cell >> 4).wrapping_mul(0x9E3779B1) & (CAPACITY - 1);
    for offset in 0..PROBES {
        let decision = table[(start + offset) & (CAPACITY - 1)]
            .decision
            .load(Ordering::Acquire);
        if decision as u32 as usize == cell {
            // Use the same load for identity and verdict. A second load after
            // finding the slot could instead observe invalidation/address reuse.
            return Some((((decision >> 32) as u32) & 3, decision & (1 << 34) != 0));
        }
    }
    None
}

fn select_hidden(native: u8, publication: Option<(u32, bool)>) -> u8 {
    if native != 0 && publication.is_some_and(|(mode, allowed)| mode == ORDINARY && !allowed) {
        0
    } else {
        native
    }
}

static SEGMENTED: Site = Site::new(
    "lod_segmented_hidden",
    0x6FEFD1,
    &[0xE8, 0x5A, 0x8D, 0xE5, 0xFF],
    true,
);
static WHOLE: Site = Site::new(
    "lod_whole_hidden",
    0x6F5A39,
    &[0xE8, 0xF2, 0x22, 0xE6, 0xFF],
    true,
);
static COMPLETE: Site = Site::new(
    "lod_ordinary_complete",
    0x551AAA,
    &[0x8B, 0x8D, 0xF8, 0xFE, 0xFF, 0xFF],
    false,
);
static START: Site = Site::new(
    "lod_ordinary_start",
    0x557AB7,
    &[0x8B, 0x55, 0xFC, 0xC6, 0x82, 0xCE, 0, 0, 0, 1],
    false,
);
static REVERSE: Site = Site::new(
    "lod_reverse",
    0x557C7A,
    &[0x8B, 0x55, 0xEC, 0xC6, 0x82, 0xD0, 0, 0, 0, 0],
    false,
);
static LOAD_SAVE: Site = Site::new(
    "lod_forced_load_save",
    0x5494FC,
    &[0x8B, 0x8D, 4, 0xFF, 0xFF, 0xFF],
    false,
);
static GRID: Site = Site::new(
    "lod_forced_grid",
    0x557BA6,
    &[0x8B, 0x55, 0xEC, 0xC6, 0x82, 0xD0, 0, 0, 0, 1],
    false,
);
static FOLLOWUP: Site = Site::new(
    "lod_forced_followup",
    0x551A16,
    &[0x8B, 0x95, 0xF8, 0xFE, 0xFF, 0xFF],
    false,
);

/// Append degraded coverage counts without touching native state.
pub(super) fn append_report(out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "LOD coverage publication-overflow={} publication-blocked-completions={}",
        OVERFLOW.load(Ordering::Relaxed),
        UNPUBLISHED_COMPLETIONS.load(Ordering::Relaxed)
    );
}

/// Prepare bounded publication storage and install the full coverage transaction.
pub(super) fn install(tx: &mut ModificationTransaction) -> anyhow::Result<()> {
    for (address, bytes) in [
        (0x6FEFCE, &[0x8B, 0x4D, 0xE0][..]),
        (0x6FEFD6, &[0x0F, 0xB6, 0xC0][..]),
        (0x6F5A36, &[0x8B, 0x4D, 0xF0][..]),
        (0x6F5A3E, &[0x0F, 0xB6, 0xC8][..]),
    ] {
        unsafe {
            super::super::patching::verify_bytes(address, bytes)?;
        }
    }
    TABLE.get_or_init(|| (0..CAPACITY).map(|_| Slot::new()).collect());
    for (site, entry) in [
        (&SEGMENTED, segmented as *const () as usize),
        (&WHOLE, whole as *const () as usize),
        (&COMPLETE, complete as *const () as usize),
        (&START, start as *const () as usize),
        (&REVERSE, reverse as *const () as usize),
        (&LOAD_SAVE, load_save as *const () as usize),
        (&GRID, grid as *const () as usize),
        (&FOLLOWUP, followup as *const () as usize),
    ] {
        site.install(tx, entry)?;
    }
    Ok(())
}
unsafe fn hidden(site: &Site, cell: *mut c_void) -> u8 {
    let provider = unsafe {
        FnPtr::<unsafe extern "thiscall" fn(*mut c_void) -> u8>::from_address_unchecked(
            site.provider(),
        )
    }
    .as_fn();
    let native = unsafe { provider(cell) };
    let result = select_hidden(native, snapshot(cell as usize));
    if result == 0 {
        super::metrics::selection(cell as usize);
    }
    result
}
unsafe extern "thiscall" fn segmented(cell: *mut c_void) -> u8 {
    unsafe { hidden(&SEGMENTED, cell) }
}
unsafe extern "thiscall" fn whole(cell: *mut c_void) -> u8 {
    unsafe { hidden(&WHOLE, cell) }
}

#[unsafe(naked)]
unsafe extern "C" fn complete() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, [ebp - 0x108]", "call {}", "test al, al", "jz 2f",
        "popad", "popfd", "mov ecx, [ebp - 0x108]", "push 0x551AB0", "ret",
        "2:", "popad", "popfd", "push 0x551B0C", "ret", sym complete_body);
}
fn completion_allowed(native_ready: bool, publication: Option<(u32, bool)>) -> bool {
    native_ready && publication.is_some_and(|(_, allowed)| allowed)
}

unsafe extern "fastcall" fn complete_body(cell: *mut c_void) -> u8 {
    if unsafe { super::hook_cell_ready_gate(cell) } == 0 {
        return 0;
    }
    // An ordinary hide must have a published slot that later membership can
    // invalidate for geometry readers. Capacity failure cannot authorize a
    // hide whose subsequent pending membership would be unobservable there.
    if !completion_allowed(true, snapshot(cell as usize)) {
        UNPUBLISHED_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    1
}

#[unsafe(naked)]
unsafe extern "C" fn start() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, [ebp - 4]", "call {}", "popad", "popfd",
        "mov edx, [ebp - 4]", "mov byte ptr [edx + 0xCE], 1", "push 0x557AC1", "ret", sym ordinary);
}
unsafe extern "fastcall" fn ordinary(cell: usize) {
    state::set_mode(cell, ORDINARY);
}
#[unsafe(naked)]
unsafe extern "C" fn reverse() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, [ebp - 0x14]", "call {}", "popad", "popfd",
        "mov edx, [ebp - 0x14]", "mov byte ptr [edx + 0xD0], 0", "push 0x557C84", "ret", sym neutral);
}
unsafe extern "fastcall" fn neutral(cell: usize) {
    state::set_mode(cell, 0);
    super::metrics::reverse(cell);
}
unsafe extern "fastcall" fn forced(cell: usize) {
    state::set_mode(cell, FORCED);
}
#[unsafe(naked)]
unsafe extern "C" fn load_save() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, [ebp - 0xFC]", "call {}", "popad", "popfd",
        "mov ecx, [ebp - 0xFC]", "push 0x549502", "ret", sym forced);
}
#[unsafe(naked)]
unsafe extern "C" fn grid() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, [ebp - 0x14]", "call {}", "popad", "popfd",
        "mov edx, [ebp - 0x14]", "mov byte ptr [edx + 0xD0], 1", "push 0x557BB0", "ret", sym forced);
}
#[unsafe(naked)]
unsafe extern "C" fn followup() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, [ebp - 0x108]", "call {}", "popad", "popfd",
        "mov edx, [ebp - 0x108]", "push 0x551A1C", "ret", sym forced);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_pending_publication_never_hides_ordinary_coverage() {
        // There is one serialized publisher, as under the ledger lock. Readers
        // execute the actual table lookup and selection while it republishes
        // an ordinary cell whose real-model membership remains incomplete.
        let cell = 0x4000;
        TABLE.get_or_init(|| (0..CAPACITY).map(|_| Slot::new()).collect());
        publish(cell, ORDINARY, false);
        let barrier = std::sync::Barrier::new(2);
        let mut unexpected = None;
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..100_000 {
                    publish(cell, ORDINARY, false);
                }
            });
            barrier.wait();
            for _ in 0..100_000 {
                let publication = snapshot(cell);
                if select_hidden(1, publication) != 0 {
                    unexpected = Some(publication);
                    break;
                }
            }
        });
        assert_eq!(unexpected, None, "pending ordinary coverage was hidden");
        invalidate(cell);
    }

    #[test]
    fn concurrent_mode_publication_never_combines_different_verdicts() {
        let cell = 0x5000;
        TABLE.get_or_init(|| (0..CAPACITY).map(|_| Slot::new()).collect());
        publish(cell, ORDINARY, false);
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                for i in 0..100_000 {
                    if i & 1 == 0 {
                        publish(cell, FORCED, true);
                    } else {
                        publish(cell, ORDINARY, false);
                    }
                }
            });
            barrier.wait();
            for _ in 0..100_000 {
                let publication = snapshot(cell);
                assert!(matches!(
                    publication,
                    Some((ORDINARY, false)) | Some((FORCED, true))
                ));
            }
        });
        invalidate(cell);
        assert_eq!(snapshot(cell), None);
        publish(cell, ORDINARY, false);
        assert_eq!(select_hidden(1, snapshot(cell)), 0);
        invalidate(cell);
    }

    #[test]
    fn scoped_selection_obeys_native_forced_and_ordinary_contracts() {
        assert_eq!(select_hidden(0, Some((ORDINARY, true))), 0);
        assert_eq!(select_hidden(1, Some((ORDINARY, false))), 0);
        assert_eq!(select_hidden(1, Some((ORDINARY, true))), 1);
        assert_eq!(select_hidden(1, Some((FORCED, false))), 1);
        assert_eq!(select_hidden(1, None), 1);
    }
    #[test]
    fn completion_rechecks_the_current_publication_after_native_readiness() {
        assert!(!completion_allowed(true, Some((ORDINARY, false))));
        assert!(!completion_allowed(true, None));
        assert!(!completion_allowed(false, Some((ORDINARY, true))));
        assert!(completion_allowed(true, Some((ORDINARY, true))));
    }
}

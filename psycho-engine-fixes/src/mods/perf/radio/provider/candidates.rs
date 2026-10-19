//! Radio candidates under the native cell reference lock.
//!
//! The admitted helper's list order, flags, door type, teleport-presence bit and
//! native append semantics are retained. Null list payloads and base forms are
//! skipped before dereference; no reference or list membership is repaired.
//! The engine owns the cell/references; the query owns its output. Nothing
//! escapes.
//! Native locking is balanced by RAII. Normal traversal adds no allocation,
//! page probes or logging; only the first missing-base rejection logs a warning.
//! See docs/crash_20261019_teleport_door_null_base_plan.md for binary evidence.

use std::sync::atomic::{AtomicBool, Ordering};

use super::{contract, field, game_bytes_equal};

const CELL_LOCK_ENTER: usize = 0x00541AC0;
const CELL_LOCK_LEAVE: usize = 0x00541AE0;
const APPEND: usize = 0x007CB2E0;
type CellLockFn = unsafe extern "thiscall" fn(*mut u8);
type AppendFn = unsafe extern "thiscall" fn(*mut u8, *const *mut u8) -> u32;

static MISSING_BASE_REPORTED: AtomicBool = AtomicBool::new(false);

/// Verify fixed process-lifetime game code before using native locking/append.
/// Admission runs only in the game, with its supported executable mapped.
pub(super) fn native_contract_matches() -> bool {
    // SAFETY: fixed supported-game code ranges are mapped for process lifetime.
    unsafe {
        game_bytes_equal(CELL_LOCK_ENTER, contract::CELL_LOCK_ENTER)
            && game_bytes_equal(CELL_LOCK_LEAVE, contract::CELL_LOCK_LEAVE)
            && (game_bytes_equal(APPEND, contract::CANDIDATE_APPEND)
                || game_bytes_equal(APPEND, contract::CANDIDATE_APPEND_INLINE))
    }
}

/// Own one native CellRefLock recursion level; release before the query resumes.
struct CellRefLock(*mut u8);

impl CellRefLock {
    /// The cell is alive through Drop, and admission proved the native lock ABI.
    unsafe fn acquire(cell: *mut u8) -> Self {
        // SAFETY: caller supplies a live cell and the verified thiscall entry.
        unsafe {
            let enter: CellLockFn = std::mem::transmute(CELL_LOCK_ENTER);
            enter(cell);
        }
        Self(cell)
    }
}

impl Drop for CellRefLock {
    fn drop(&mut self) {
        // SAFETY: acquire owns this recursion level; the query retains the cell.
        unsafe {
            let leave: CellLockFn = std::mem::transmute(CELL_LOCK_LEAVE);
            leave(self.0);
        }
    }
}

/// Append eligible references without clearing the caller-owned array.
///
/// # Safety
/// The cell and output array must be live and follow the admitted native layouts.
/// Non-null list nodes and reference payloads must be live through their reads.
/// A non-null base must be live through its type read. CellRefLock serializes
/// list mutation, but does not validate arbitrary pointers or base-form writers.
/// Native function ABIs must have been admitted before this call.
pub(super) unsafe fn enumerate(cell: *mut u8, output: *mut u8) {
    let mut missing_base = false;
    // SAFETY: caller supplies the native object, ownership and locking contract.
    unsafe {
        let _lock = CellRefLock::acquire(cell);
        let append: AppendFn = std::mem::transmute(APPEND);
        let mut node = cell.add(0xAC);
        while !node.is_null() {
            let reference = field::<*mut u8>(node, 0);
            // Native 0x0054DB83 skips null payloads, including sparse nodes.
            // The embedded {null, null} sentinel exits via its null next link.
            if !reference.is_null() && field::<u32>(reference, 8) & ((1 << 11) | (1 << 5)) == 0 {
                let base = field::<*const u8>(reference, 0x20);
                match base_type(base) {
                    None => missing_base = true,
                    Some(0x1C) if field::<u8>(reference, 0x51) & 8 != 0 => {
                        append(output, &reference);
                    }
                    _ => {}
                }
            }
            // Append may grow the native array. Reread the live next link at
            // the same point as the admitted helper, while retaining the lock.
            node = field(node, 4);
        }
    }
    // The guard has released the native lock before the exceptional warning.
    if missing_base {
        report_missing_base();
    }
}

/// Read the native base type, returning None for the reported null input.
///
/// # Safety
/// A non-null base must be a live form with a readable type byte at +4. Null
/// requires no readable memory and is rejected before any pointer arithmetic.
unsafe fn base_type(base: *const u8) -> Option<u8> {
    if base.is_null() {
        return None;
    }
    // SAFETY: the caller proves non-null base lifetime and layout above.
    Some(unsafe { field::<u8>(base, 4) })
}

/// Report the first rejection only, after native list locking has ended.
#[cold]
fn report_missing_base() {
    if !MISSING_BASE_REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!("[RADIO] Ignored a candidate with a missing base form; door search continues");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reported_null_base_is_rejected_before_the_type_read() {
        // EAX=0 at the captured type read. Execute the production rejection
        // with that actual input, without constructing a substitute cell graph.
        let base = std::hint::black_box(std::ptr::null::<u8>());
        // SAFETY: null is explicitly accepted and requires no pointee.
        assert_eq!(unsafe { super::base_type(base) }, None);
    }
}

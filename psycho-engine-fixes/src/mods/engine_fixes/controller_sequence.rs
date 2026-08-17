//! Final-owner containment for unresolved `NiControllerSequence` ID tags.
//!
//! `NiControllerSequence::~NiControllerSequence` at `0x00A35640` destroys an
//! owned prefixed array from `this + 0x18`. Each 20-byte record contains five
//! `NiFixedString` pointers. The native record destructor subtracts the
//! eight-byte string header and atomically decrements its reference count.
//! The reported sequence reached this boundary with `0x0000000D` in one field,
//! so native code decremented address `0x00000005` and faulted.
//!
//! Legacy sequence post-linking converts five string-palette offsets into the
//! fixed-string representation and maps the `0xFFFFFFFF` offset sentinel to
//! NULL. This guard does not attempt that conversion during retirement: the
//! palette can already be absent or partially released, and the dying object
//! has no remaining behavioral state to preserve. Instead it proves the exact
//! allocator-owned array boundary, scans only records that fit that allocation,
//! requires the allocation prefix count to match the sequence's native count,
//! and clears a complete record when any field proves the representation is
//! unresolved.
//! Valid arrays and records remain byte-for-byte unchanged.
//!
//! Known-invalid owned arrays are detached as one unit before native teardown.
//! Their uncertain storage is deliberately leaked rather than traversed or
//! freed. Structurally plausible aligned high addresses outside Psycho's
//! allocation domains are left to the active predecessor because they may
//! belong to a compatible foreign or pre-hook owner. The path is
//! destructor-cold, performs bounded O(record count) work, and has no routine
//! allocation, file IO, or logging.

use std::{
    mem::{align_of, size_of},
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use libc::c_void;
use libpsycho::os::windows::hook::transaction::ModificationTransaction;

use super::statics;
use crate::mods::{
    diagnostics,
    heap_replacer::{
        allocation_state::{self, AllocationState},
        heap_validate,
    },
};

const CONTROLLED_BLOCK_COUNT_OFFSET: usize = 0x0C;
const ID_TAG_ARRAY_DATA_OFFSET: usize = 0x18;
const ARRAY_COUNT_PREFIX_SIZE: usize = size_of::<u32>();
const ID_TAG_FIELD_COUNT: usize = 5;
const ID_TAG_RECORD_SIZE: usize = ID_TAG_FIELD_COUNT * size_of::<u32>();
const FIXED_STRING_HEADER_SIZE: usize = 2 * size_of::<u32>();
const LOW_POINTER_LIMIT: usize = 0x1_0000;
const LEGACY_NULL_STRING_OFFSET: u32 = u32::MAX;
const DETAILED_LOG_LIMIT: u64 = 16;

static INSTALLED: AtomicBool = AtomicBool::new(false);
static ORIGINAL_MISSING_LOGGED: AtomicBool = AtomicBool::new(false);
static SANITIZED_ARRAYS: AtomicU64 = AtomicU64::new(0);
static DETACHED_ARRAYS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
struct InvalidMarker {
    record_index: u32,
    field_index: u8,
    value: u32,
}

#[derive(Clone, Copy, Debug)]
struct InspectionSummary {
    array_count: u32,
    usable_size: usize,
    allocation: AllocationState,
    sanitized_records: u32,
    first_marker: Option<InvalidMarker>,
}

#[derive(Clone, Copy, Debug)]
struct InvalidLayout {
    array_count: u32,
    usable_size: usize,
    allocation: AllocationState,
}

#[derive(Clone, Copy, Debug)]
enum InspectionResult {
    Complete(InspectionSummary),
    Invalid(InvalidLayout),
}

#[derive(Clone, Copy, Debug)]
enum DetachReason {
    LowDataPointer,
    MisalignedDataPointer,
    InvalidAllocation(AllocationState),
    InvalidLayout(InvalidLayout),
}

/// Install the shared sequence-destructor owner hook.
///
/// The heap cache is initialized independently of other engine fixes because
/// modes zero and one use it to prove non-SBM GameHeap allocations.
pub(super) fn install() -> anyhow::Result<()> {
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    heap_validate::init_heap_cache();
    unsafe {
        statics::NI_CONTROLLER_SEQUENCE_DTOR_HOOK.init(
            "ni_controller_sequence_idtag_retirement_guard",
            statics::NI_CONTROLLER_SEQUENCE_DTOR_ADDR as *mut c_void,
            hook_ni_controller_sequence_dtor,
        )?;
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::NI_CONTROLLER_SEQUENCE_DTOR_HOOK)?;
    transaction.commit();
    INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[ANIM_SEQUENCE] IDTag retirement guard active at 0x{:08X}",
        statics::NI_CONTROLLER_SEQUENCE_DTOR_ADDR,
    );
    Ok(())
}

/// Contain an unresolved IDTag representation before native fixed-string
/// reference release.
///
/// # Safety
///
/// `sequence` must satisfy the native destructor's live `this` contract. The
/// hook preserves the original thiscall ABI and invokes the active predecessor
/// exactly once after any final-owner containment.
unsafe extern "thiscall" fn hook_ni_controller_sequence_dtor(sequence: *mut c_void) {
    unsafe { contain_retiring_idtags(sequence) };

    match statics::NI_CONTROLLER_SEQUENCE_DTOR_HOOK.original() {
        Ok(original) => unsafe { original(sequence) },
        Err(error) => {
            if !ORIGINAL_MISSING_LOGGED.swap(true, Ordering::Relaxed) {
                log::error!(
                    "[ANIM_SEQUENCE] Destructor trampoline unavailable; retiring sequence was leaked: {error:?}"
                );
            }
        }
    }
}

/// Validate and, when necessary, mutate only the destructor-owned IDTag array.
///
/// # Safety
///
/// `sequence` must be a live native sequence at the entry of its shared
/// destructor. That owner boundary must exclude concurrent access to the
/// sequence and its IDTag array for the duration of this call.
unsafe fn contain_retiring_idtags(sequence: *mut c_void) {
    if sequence.is_null() {
        return;
    }

    let sequence_bytes = sequence.cast::<u8>();
    let sequence_count = unsafe {
        ptr::read_unaligned(
            sequence_bytes
                .add(CONTROLLED_BLOCK_COUNT_OFFSET)
                .cast::<u32>(),
        )
    };
    let array_data = unsafe {
        ptr::read_unaligned(
            sequence_bytes
                .add(ID_TAG_ARRAY_DATA_OFFSET)
                .cast::<*mut u8>(),
        )
    };
    if array_data.is_null() {
        return;
    }

    let data_address = array_data as usize;
    // Native first reads the prefix at `data - 4`; the complete read must stay
    // above the supported process's unmapped low-address guard.
    if data_address < LOW_POINTER_LIMIT + ARRAY_COUNT_PREFIX_SIZE {
        unsafe { detach_array(sequence_bytes) };
        log_detachment(
            sequence,
            array_data,
            sequence_count,
            DetachReason::LowDataPointer,
        );
        return;
    }
    if data_address & (align_of::<u32>() - 1) != 0 {
        unsafe { detach_array(sequence_bytes) };
        log_detachment(
            sequence,
            array_data,
            sequence_count,
            DetachReason::MisalignedDataPointer,
        );
        return;
    }

    // The native destructor derives this exact prefixed allocation start with
    // `data - 4`; the low-pointer check above proves subtraction cannot wrap.
    let allocation = (data_address - ARRAY_COUNT_PREFIX_SIZE) as *mut c_void;
    let inspected = unsafe {
        allocation_state::with_allocation_mut(
            allocation,
            ARRAY_COUNT_PREFIX_SIZE,
            |allocation, usable_size, state| {
                inspect_and_sanitize(allocation, usable_size, state, sequence_count)
            },
        )
    };

    match inspected {
        Ok(InspectionResult::Complete(summary)) => {
            if summary.sanitized_records != 0 {
                log_sanitization(sequence, array_data, sequence_count, summary);
            }
        }
        Ok(InspectionResult::Invalid(issue)) => {
            unsafe { detach_array(sequence_bytes) };
            log_detachment(
                sequence,
                array_data,
                sequence_count,
                DetachReason::InvalidLayout(issue),
            );
        }
        Err(AllocationState::Unowned) => {
            // A high foreign or pre-hook allocation may still satisfy the
            // active predecessor's ownership contract. Without exact proof,
            // neither inspect nor detach it.
        }
        Err(state) => {
            unsafe { detach_array(sequence_bytes) };
            log_detachment(
                sequence,
                array_data,
                sequence_count,
                DetachReason::InvalidAllocation(state),
            );
        }
    }
}

/// Inspect one exact prefixed allocation and clear only ambiguous records.
///
/// The caller holds the vanilla SBM lock when required and owns the native
/// array lifetime for gheap and Windows allocations.
///
/// # Safety
///
/// `allocation` must be the admitted allocation start and remain live for the
/// call. `usable_size` must be that allocation's proven writable extent. No
/// other owner may access the record fields concurrently.
unsafe fn inspect_and_sanitize(
    allocation: *mut u8,
    usable_size: usize,
    state: AllocationState,
    sequence_count: u32,
) -> InspectionResult {
    let array_count = unsafe { ptr::read_unaligned(allocation.cast::<u32>()) };
    if array_count != sequence_count {
        return InspectionResult::Invalid(InvalidLayout {
            array_count,
            usable_size,
            allocation: state,
        });
    }
    let Some(required_size) = (array_count as usize)
        .checked_mul(ID_TAG_RECORD_SIZE)
        .and_then(|records| records.checked_add(ARRAY_COUNT_PREFIX_SIZE))
    else {
        return InspectionResult::Invalid(InvalidLayout {
            array_count,
            usable_size,
            allocation: state,
        });
    };
    if required_size > usable_size {
        return InspectionResult::Invalid(InvalidLayout {
            array_count,
            usable_size,
            allocation: state,
        });
    }

    let mut sanitized_records = 0u32;
    let mut first_marker = None;
    for record_index in 0..array_count as usize {
        let record =
            unsafe { allocation.add(ARRAY_COUNT_PREFIX_SIZE + record_index * ID_TAG_RECORD_SIZE) };
        let mut marker = None;
        for field_index in 0..ID_TAG_FIELD_COUNT {
            let value = unsafe {
                ptr::read_unaligned(record.add(field_index * size_of::<u32>()).cast::<u32>())
            };
            if is_invalid_runtime_string(value) {
                marker = Some(InvalidMarker {
                    record_index: record_index as u32,
                    field_index: field_index as u8,
                    value,
                });
                break;
            }
        }

        let Some(marker) = marker else {
            continue;
        };
        for field_index in 0..ID_TAG_FIELD_COUNT {
            unsafe {
                ptr::write_unaligned(record.add(field_index * size_of::<u32>()).cast::<u32>(), 0)
            };
        }
        sanitized_records += 1;
        if first_marker.is_none() {
            first_marker = Some(marker);
        }
    }

    InspectionResult::Complete(InspectionSummary {
        array_count,
        usable_size,
        allocation: state,
        sanitized_records,
        first_marker,
    })
}

#[inline]
fn is_invalid_runtime_string(value: u32) -> bool {
    value == LEGACY_NULL_STRING_OFFSET
        || (value != 0 && (value as usize) < LOW_POINTER_LIMIT + FIXED_STRING_HEADER_SIZE)
}

/// Remove the uncertain array from the object the native destructor is about
/// to retire. The original destructor observes NULL and skips that one array.
///
/// # Safety
///
/// `sequence` must be a live, exclusively owned native sequence with a writable
/// IDTag-array field at `ID_TAG_ARRAY_DATA_OFFSET`.
unsafe fn detach_array(sequence: *mut u8) {
    unsafe {
        ptr::write_unaligned(
            sequence.add(ID_TAG_ARRAY_DATA_OFFSET).cast::<*mut u8>(),
            ptr::null_mut(),
        )
    };
}

fn log_sanitization(
    sequence: *mut c_void,
    array_data: *mut u8,
    sequence_count: u32,
    summary: InspectionSummary,
) {
    let event = SANITIZED_ARRAYS.fetch_add(1, Ordering::Relaxed) + 1;
    if !should_log_detail(event) {
        return;
    }
    let Some(marker) = summary.first_marker else {
        return;
    };
    log::warn!(
        "[ANIM_SEQUENCE] discarded unresolved retiring IDTag record: sequence=0x{:08X} array=0x{:08X} sequence_count={} array_count={} record={} field={} value=0x{:08X} usable={} allocation={:?} repaired={} event={}",
        sequence as usize,
        array_data as usize,
        sequence_count,
        summary.array_count,
        marker.record_index,
        marker.field_index,
        marker.value,
        summary.usable_size,
        summary.allocation,
        summary.sanitized_records,
        event,
    );
}

fn log_detachment(
    sequence: *mut c_void,
    array_data: *mut u8,
    sequence_count: u32,
    reason: DetachReason,
) {
    let total = DETACHED_ARRAYS.fetch_add(1, Ordering::Relaxed) + 1;
    if !should_log_detail(total) {
        return;
    }
    match reason {
        DetachReason::LowDataPointer => log::warn!(
            "[ANIM_SEQUENCE] detached invalid retiring IDTag array: sequence=0x{:08X} array=0x{:08X} sequence_count={} reason=low-data-pointer total={}",
            sequence as usize,
            array_data as usize,
            sequence_count,
            total,
        ),
        DetachReason::MisalignedDataPointer => log::warn!(
            "[ANIM_SEQUENCE] detached invalid retiring IDTag array: sequence=0x{:08X} array=0x{:08X} sequence_count={} reason=misaligned-data-pointer total={}",
            sequence as usize,
            array_data as usize,
            sequence_count,
            total,
        ),
        DetachReason::InvalidAllocation(allocation) => log::warn!(
            "[ANIM_SEQUENCE] detached invalid retiring IDTag array: sequence=0x{:08X} array=0x{:08X} sequence_count={} reason=invalid-allocation allocation={:?} total={}",
            sequence as usize,
            array_data as usize,
            sequence_count,
            allocation,
            total,
        ),
        DetachReason::InvalidLayout(layout) => log::warn!(
            "[ANIM_SEQUENCE] detached invalid retiring IDTag array: sequence=0x{:08X} array=0x{:08X} sequence_count={} reason=invalid-layout array_count={} usable={} allocation={:?} total={}",
            sequence as usize,
            array_data as usize,
            sequence_count,
            layout.array_count,
            layout.usable_size,
            layout.allocation,
            total,
        ),
    }
}

fn should_log_detail(total: u64) -> bool {
    total <= DETAILED_LOG_LIMIT || diagnostics::should_log_power_of_two(total)
}

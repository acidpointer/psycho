//! Mod-independent LowProcess generic-location ownership enforcement.

use std::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering},
};

use anyhow::{Context, ensure};
use windows::Win32::System::Memory::{
    MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS,
};

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::winapi::{get_current_thread_id, safe_write_32, virtual_query},
};

use crate::{events, mods::diagnostics};

use super::{
    patching, statics,
    types::{AppendRefIdFn, MainTaskDrainFn},
};

const SLOT_PENDING: u8 = 0;
const SLOT_WRAPPED: u8 = 1;
const SLOT_UNSUPPORTED: u8 = 2;
const SLOT_DISABLED: u8 = 3;
const SLOT_CHAINED: u8 = 4;
const OBSERVATION_WINDOW: u32 = 120;

const LIST_HEAD_REMOVE_ADDR: usize = 0x0063_F7B0;
const LIST_REMOVE_ADDR: usize = 0x0090_5330;
const LIST_NEXT_ADDR: usize = 0x0072_6070;
const GENERIC_LOCATIONS_OFFSET: usize = 0x6C;

type ProcessCleanupFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
type ListHeadRemoveFn = unsafe extern "fastcall" fn(*mut ListNode);
type ListRemoveFn = unsafe extern "thiscall" fn(*mut ListNode, *mut *mut c_void);
type ListNextFn = unsafe extern "fastcall" fn(*mut ListNode) -> *mut ListNode;

#[repr(C)]
struct ListNode {
    data: *mut c_void,
    next: *mut ListNode,
}

static ENABLED: AtomicBool = AtomicBool::new(true);
static OBSERVATIONS: AtomicU32 = AtomicU32::new(0);
static PREVIOUS_APPEND_REF_ID: AtomicUsize = AtomicUsize::new(statics::APPEND_REF_ID_ADDR);
static PREVIOUS_MAIN_TASK_DRAIN: AtomicUsize = AtomicUsize::new(statics::MAIN_TASK_DRAIN_ADDR);
static PREDECESSORS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static SLOT_STATES: [AtomicU8; 4] = [const { AtomicU8::new(SLOT_PENDING) }; 4];

static WRAPS: AtomicU32 = AtomicU32::new(0);
static REWRAPS: AtomicU32 = AtomicU32::new(0);
static UNSUPPORTED: AtomicU32 = AtomicU32::new(0);
static SANITIZED_ENTRIES: AtomicU32 = AtomicU32::new(0);
static INVALID_SAVE_FORMS: AtomicU32 = AtomicU32::new(0);
static PATCH_FAILURES: AtomicU32 = AtomicU32::new(0);

pub(super) struct DiagnosticSnapshot {
    pub enabled: bool,
    pub observations: u32,
    pub slot_states: [u8; 4],
    pub predecessors: [usize; 4],
    pub wraps: u32,
    pub rewraps: u32,
    pub unsupported: u32,
    pub sanitized_entries: u32,
    pub invalid_save_forms: u32,
    pub patch_failures: u32,
}

pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        enabled: ENABLED.load(Ordering::Acquire),
        observations: OBSERVATIONS.load(Ordering::Relaxed),
        slot_states: std::array::from_fn(|index| SLOT_STATES[index].load(Ordering::Acquire)),
        predecessors: std::array::from_fn(|index| PREDECESSORS[index].load(Ordering::Acquire)),
        wraps: WRAPS.load(Ordering::Relaxed),
        rewraps: REWRAPS.load(Ordering::Relaxed),
        unsupported: UNSUPPORTED.load(Ordering::Relaxed),
        sanitized_entries: SANITIZED_ENTRIES.load(Ordering::Relaxed),
        invalid_save_forms: INVALID_SAVE_FORMS.load(Ordering::Relaxed),
        patch_failures: PATCH_FAILURES.load(Ordering::Relaxed),
    }
}

pub(super) fn slot_state_name(state: u8) -> &'static str {
    match state {
        SLOT_PENDING => "pending",
        SLOT_WRAPPED => "wrapped",
        SLOT_UNSUPPORTED => "unsupported",
        SLOT_DISABLED => "disabled",
        SLOT_CHAINED => "chained",
        _ => "unknown",
    }
}

pub(super) fn disable() {
    ENABLED.store(false, Ordering::Release);
    for state in &SLOT_STATES {
        state.store(SLOT_DISABLED, Ordering::Release);
    }
}

pub(super) fn install_save_containment() -> anyhow::Result<()> {
    let previous = unsafe { patching::relative_call_target(statics::LOWPROCESS_SAVE_CALL_ADDR) }?;
    if previous == checked_append_ref_id as *const () as usize {
        return Ok(());
    }
    ensure!(
        is_executable(previous),
        "save serializer target 0x{previous:08X} is not executable"
    );
    let redirected = unsafe {
        patching::redirect_relative_call(
            statics::LOWPROCESS_SAVE_CALL_ADDR,
            checked_append_ref_id as *mut c_void,
        )
    }
    .context("install LowProcess save containment")?;
    ensure!(
        redirected == previous,
        "save call target changed during install"
    );
    PREVIOUS_APPEND_REF_ID.store(previous, Ordering::Release);
    log::info!(
        "[LOWPROCESS] Generic-location save containment active predecessor=0x{:08X}",
        previous
    );
    Ok(())
}

pub(super) fn install_late_boundary() -> anyhow::Result<()> {
    let previous = unsafe { patching::relative_call_target(statics::MAIN_TASK_DRAIN_CALL_ADDR) }?;
    if previous == main_task_drain_with_slot_wrapping as *const () as usize {
        return Ok(());
    }
    ensure!(
        is_executable(previous),
        "main task-drain target 0x{previous:08X} is not executable"
    );
    let redirected = unsafe {
        patching::redirect_relative_call(
            statics::MAIN_TASK_DRAIN_CALL_ADDR,
            main_task_drain_with_slot_wrapping as *mut c_void,
        )
    }
    .context("install LowProcess late wrapping boundary")?;
    ensure!(
        redirected == previous,
        "main-drain target changed during install"
    );
    PREVIOUS_MAIN_TASK_DRAIN.store(previous, Ordering::Release);
    log::info!(
        "[LOWPROCESS] Late slot-wrapping boundary active predecessor=0x{:08X}",
        previous
    );
    Ok(())
}

pub(super) fn observe_event(kind: u32) {
    if kind == events::DEFERRED_INIT {
        ensure_slots_wrapped();
    }
}

unsafe extern "thiscall" fn checked_append_ref_id(
    writer: *mut c_void,
    form: *mut c_void,
    flags: u32,
) {
    let checked = if form.is_null() || is_valid_tes_form(form) {
        form
    } else {
        let n = INVALID_SAVE_FORMS.fetch_add(1, Ordering::Relaxed) + 1;
        if diagnostics::should_log_power_of_two(u64::from(n)) {
            log::warn!(
                "[LOWPROCESS] invalid generic-location form encoded as NULL total={} form=0x{:08X} writer=0x{:08X} flags=0x{:X} tid={}",
                n,
                form as usize,
                writer as usize,
                flags,
                get_current_thread_id(),
            );
        }
        ptr::null_mut()
    };

    let predecessor = PREVIOUS_APPEND_REF_ID.load(Ordering::Acquire);
    let target = if is_executable(predecessor) {
        predecessor
    } else {
        statics::APPEND_REF_ID_ADDR
    };
    let Ok(original) = (unsafe { FnPtr::<AppendRefIdFn>::from_raw(target as *mut c_void) }) else {
        return;
    };
    let original = original.as_fn();
    unsafe { original(writer, checked, flags) };
}

unsafe extern "thiscall" fn main_task_drain_with_slot_wrapping(manager: *mut c_void, arg: u32) {
    ensure_slots_wrapped();
    let predecessor = PREVIOUS_MAIN_TASK_DRAIN.load(Ordering::Acquire);
    let target = if predecessor != 0 {
        predecessor
    } else {
        statics::MAIN_TASK_DRAIN_ADDR
    };
    let Ok(original) = (unsafe { FnPtr::<MainTaskDrainFn>::from_raw(target as *mut c_void) })
    else {
        return;
    };
    let original = original.as_fn();
    unsafe { original(manager, arg) };
}

unsafe extern "thiscall" fn process_cleanup_wrapper_0(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(0, process, removed_ref) };
}

unsafe extern "thiscall" fn process_cleanup_wrapper_1(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(1, process, removed_ref) };
}

unsafe extern "thiscall" fn process_cleanup_wrapper_2(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(2, process, removed_ref) };
}

unsafe extern "thiscall" fn process_cleanup_wrapper_3(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(3, process, removed_ref) };
}

unsafe fn process_cleanup_for_slot(index: usize, process: *mut c_void, removed_ref: *mut c_void) {
    let predecessor = PREDECESSORS[index].load(Ordering::Acquire);
    sanitize_generic_locations(process, removed_ref);

    let wrapper = wrapper_for_slot(index);
    let target = if predecessor != 0 && predecessor != wrapper {
        predecessor
    } else {
        statics::VANILLA_LOWPROCESS_FUNC011F
    };
    let Ok(original) = (unsafe { FnPtr::<ProcessCleanupFn>::from_raw(target as *mut c_void) })
    else {
        return;
    };
    let original = original.as_fn();
    unsafe { original(process, removed_ref) };
}

fn wrapper_for_slot(index: usize) -> usize {
    match index {
        0 => process_cleanup_wrapper_0 as *const () as usize,
        1 => process_cleanup_wrapper_1 as *const () as usize,
        2 => process_cleanup_wrapper_2 as *const () as usize,
        3 => process_cleanup_wrapper_3 as *const () as usize,
        _ => 0,
    }
}

fn ensure_slots_wrapped() {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let observation = OBSERVATIONS.load(Ordering::Relaxed);
    if observation >= OBSERVATION_WINDOW {
        return;
    }
    OBSERVATIONS.store(observation + 1, Ordering::Relaxed);

    for index in 0..statics::LOWPROCESS_FUNC011F_SLOTS.len() {
        wrap_slot(index);
    }
}

fn wrap_slot(index: usize) {
    let slot = statics::LOWPROCESS_FUNC011F_SLOTS[index];
    let wrapper = wrapper_for_slot(index);
    let current = unsafe { ptr::read_unaligned(slot as *const u32) as usize };

    if current == wrapper {
        if PREDECESSORS[index].load(Ordering::Acquire) == 0 {
            PREDECESSORS[index].store(statics::VANILLA_LOWPROCESS_FUNC011F, Ordering::Release);
        }
        SLOT_STATES[index].store(SLOT_WRAPPED, Ordering::Release);
        return;
    }
    if !is_executable(current) {
        mark_slot_unsupported(index, current, "non-executable-predecessor");
        return;
    }

    let previous_predecessor = PREDECESSORS[index].load(Ordering::Acquire);
    if previous_predecessor != 0 && current != previous_predecessor {
        mark_slot_chained(index, current);
        return;
    }

    if previous_predecessor == 0 {
        PREDECESSORS[index].store(current, Ordering::Release);
    }
    if unsafe { ptr::read_unaligned(slot as *const u32) as usize } != current {
        if previous_predecessor == 0 {
            PREDECESSORS[index].store(0, Ordering::Release);
        }
        return;
    }

    if let Err(err) = safe_write_32(slot as *mut c_void, wrapper as u32) {
        if previous_predecessor == 0 {
            PREDECESSORS[index].store(0, Ordering::Release);
        }
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
        SLOT_STATES[index].store(SLOT_UNSUPPORTED, Ordering::Release);
        log::error!(
            "[LOWPROCESS] slot wrap failed index={} slot=0x{:08X}: {}",
            index,
            slot,
            err,
        );
        return;
    }

    if unsafe { ptr::read_unaligned(slot as *const u32) as usize } != wrapper {
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
        SLOT_STATES[index].store(SLOT_UNSUPPORTED, Ordering::Release);
        return;
    }

    SLOT_STATES[index].store(SLOT_WRAPPED, Ordering::Release);
    let count = if previous_predecessor == 0 {
        WRAPS.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        REWRAPS.fetch_add(1, Ordering::Relaxed) + 1
    };
    log::info!(
        "[LOWPROCESS] slot wrapped index={} base=0x{:08X} slot=0x{:08X} predecessor=0x{:08X} count={}",
        index,
        statics::LOWPROCESS_VTABLE_BASES[index],
        slot,
        current,
        count,
    );
}

fn mark_slot_chained(index: usize, target: usize) {
    let previous = SLOT_STATES[index].swap(SLOT_CHAINED, Ordering::AcqRel);
    if previous == SLOT_CHAINED {
        return;
    }
    log::info!(
        "[LOWPROCESS] later hook retained above wrapper index={} slot=0x{:08X} target=0x{:08X}",
        index,
        statics::LOWPROCESS_FUNC011F_SLOTS[index],
        target,
    );
}

fn sanitize_generic_locations(process: *mut c_void, removed_ref: *mut c_void) {
    // This is entered through a live process object's vtable slot, so the
    // embedded head is already covered by the virtual-call ownership
    // contract. Heap-linked successor nodes retain the corruption probe.
    if process.is_null() || removed_ref.is_null() {
        return;
    }

    let remove_head =
        unsafe { FnPtr::<ListHeadRemoveFn>::from_address_unchecked(LIST_HEAD_REMOVE_ADDR) }.as_fn();
    let remove = unsafe { FnPtr::<ListRemoveFn>::from_address_unchecked(LIST_REMOVE_ADDR) }.as_fn();
    let next = unsafe { FnPtr::<ListNextFn>::from_address_unchecked(LIST_NEXT_ADDR) }.as_fn();
    let mut current =
        unsafe { (process as *mut u8).add(GENERIC_LOCATIONS_OFFSET) as *mut ListNode };
    let mut previous: *mut ListNode = ptr::null_mut();
    let mut embedded_head = true;

    while !current.is_null()
        && (embedded_head || is_readable(current as usize, std::mem::size_of::<ListNode>()))
    {
        embedded_head = false;
        let payload = unsafe { ptr::read_unaligned(ptr::addr_of!((*current).data)) };
        if payload.is_null() {
            break;
        }
        if payload == removed_ref {
            SANITIZED_ENTRIES.fetch_add(1, Ordering::Relaxed);
            if previous.is_null() {
                unsafe { remove_head(current) };
            } else {
                let mut item = payload;
                unsafe { remove(previous, &mut item) };
                current = unsafe { next(previous) };
            }
        } else {
            previous = current;
            current = unsafe { next(current) };
        }
    }
}

fn mark_slot_unsupported(index: usize, target: usize, reason: &'static str) {
    let previous = SLOT_STATES[index].swap(SLOT_UNSUPPORTED, Ordering::AcqRel);
    if previous == SLOT_UNSUPPORTED {
        return;
    }
    UNSUPPORTED.fetch_add(1, Ordering::Relaxed);
    log::warn!(
        "[LOWPROCESS] slot left untouched index={} slot=0x{:08X} target=0x{:08X} reason={}",
        index,
        statics::LOWPROCESS_FUNC011F_SLOTS[index],
        target,
        reason,
    );
}

fn is_valid_tes_form(form: *mut c_void) -> bool {
    let address = form as usize;
    if !is_readable(address, 0x10) {
        return false;
    }
    let vtable = unsafe { ptr::read_unaligned(form as *const usize) };
    if !is_readable(vtable, 4) {
        return false;
    }
    let first_method = unsafe { ptr::read_unaligned(vtable as *const usize) };
    is_executable(first_method)
}

fn is_readable(address: usize, len: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    if info.state != MEM_COMMIT.0 || info.protect == PAGE_NOACCESS {
        return false;
    }
    if (info.protect.0 & PAGE_GUARD.0) != 0 {
        return false;
    }
    address.saturating_add(len) <= (info.base_address as usize).saturating_add(info.region_size)
}

fn is_executable(address: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    info.state == MEM_COMMIT.0
        && (info.protect.0 & PAGE_GUARD.0) == 0
        && matches!(
            info.protect,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
}

//! Guard for `ExtraContainerChanges::EntryData` save/load.
//!
//! The crash at `0x00865DFB` was a save-time dereference of
//! `EntryData.type == 0x00000007`. Ghidra shows the form-ref load resolver
//! returns either a real `TESForm*` or NULL, and vanilla only rejects NULL
//! before appending loaded entries. That makes this a containment boundary:
//! stale or overwritten entries must be filtered before the save writer
//! encodes their form pointer.
//!
//! Do not guard `0x004BED60` directly. The caller `0x004D4090` increments
//! the saved EntryData count only after `0x004BED60` returns, so skipping
//! inside the body-save function would desync the serialized count.

use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;
use libpsycho::{ffi::fnptr::FnPtr, os::windows::winapi::virtual_query};

use super::statics;

const ENTRYDATA_EXTEND_LIST_OFFSET: usize = 0x00;
const ENTRYDATA_COUNT_DELTA_OFFSET: usize = 0x04;
const ENTRYDATA_TYPE_OFFSET: usize = 0x08;
const ENTRYDATA_SIZE: usize = 0x0C;

const SAVE_BUFFER_CHANGE_FLAGS_OFFSET: usize = 0x17;
const SAVE_BUFFER_STATE_OFFSET: usize = 0x20;
const ENTRYDATA_CHANGE_FLAGS: u32 = 0x400;

const FNV_TEXT_START: usize = 0x0040_0000;
const FNV_TEXT_END: usize = 0x00E0_0000;
const FNV_RDATA_START: usize = 0x0100_0000;
const FNV_RDATA_END: usize = 0x0110_0000;

const ENTRYDATA_BODY_SAVE_ADDR: usize = 0x004BED60;
const SAVE_COUNT_BEGIN_ADDR: usize = 0x00865F20;
const SAVE_COUNT_END_ADDR: usize = 0x00865FF0;
const LIST_NODE_DATA_ADDR: usize = 0x006815C0;
const LIST_NODE_NEXT_ADDR: usize = 0x00726070;

type SaveGetStateFn = unsafe extern "thiscall" fn(*mut c_void) -> u32;
type SaveCountBeginFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;
type SaveCountEndFn = unsafe extern "thiscall" fn(*mut c_void, u32, u32);
type ListNodeDataFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut *mut EntryData;
type ListNodeNextFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type EntryDataBodySaveFn = unsafe extern "thiscall" fn(*mut EntryData, *mut c_void);

#[repr(C)]
struct EntryData {
    extend_data: *mut c_void,
    count_delta: i32,
    type_form: *mut c_void,
}

static SAVE_SKIP_COUNT: AtomicU64 = AtomicU64::new(0);
static LOAD_DROP_COUNT: AtomicU64 = AtomicU64::new(0);

pub unsafe extern "thiscall" fn hook_entrydata_list_save(
    list: *mut c_void,
    save_buffer: *mut c_void,
) {
    if list.is_null() || save_buffer.is_null() {
        call_original_list_save(list, save_buffer);
        return;
    }

    let old_state = read_save_state(save_buffer);
    let old_flags = read_unaligned_u32(save_buffer, SAVE_BUFFER_CHANGE_FLAGS_OFFSET);

    write_unaligned_u32(save_buffer, SAVE_BUFFER_STATE_OFFSET, 0);
    write_unaligned_u32(
        save_buffer,
        SAVE_BUFFER_CHANGE_FLAGS_OFFSET,
        ENTRYDATA_CHANGE_FLAGS,
    );

    let count_marker = save_count_begin(save_buffer);
    let mut saved_count = 0u32;
    let mut node = unsafe { ptr::read_unaligned(list as *const *mut c_void) };

    while !node.is_null() {
        let entry = node_entry(node);
        if !entry.is_null() {
            if is_valid_entry(entry) {
                entrydata_body_save(entry, save_buffer);
                saved_count = saved_count.saturating_add(1);
            } else {
                log_invalid_entry(&SAVE_SKIP_COUNT, "save-skip", entry);
            }
        }
        node = list_node_next(node);
    }

    save_count_end(save_buffer, saved_count, count_marker);

    write_unaligned_u32(save_buffer, SAVE_BUFFER_STATE_OFFSET, old_state);
    write_unaligned_u32(save_buffer, SAVE_BUFFER_CHANGE_FLAGS_OFFSET, old_flags);
}

pub unsafe extern "thiscall" fn hook_entrydata_load(entry: *mut c_void, load_buffer: *mut c_void) {
    if let Ok(original) = statics::ENTRYDATA_LOAD_HOOK.original() {
        unsafe { original(entry, load_buffer) };
    }

    if entry.is_null() {
        return;
    }

    let entry = entry as *mut EntryData;
    if !is_readable(entry as usize, ENTRYDATA_SIZE) {
        log_invalid_entry(&LOAD_DROP_COUNT, "load-unreadable-entry", entry);
        return;
    }

    let form = unsafe { ptr::read_unaligned(ptr::addr_of!((*entry).type_form)) };
    if form.is_null() || is_valid_tes_form(form) {
        return;
    }

    log_invalid_entry(&LOAD_DROP_COUNT, "load-invalid-type", entry);
    unsafe {
        ptr::write_unaligned(ptr::addr_of_mut!((*entry).type_form), ptr::null_mut());
    }
}

fn call_original_list_save(list: *mut c_void, save_buffer: *mut c_void) {
    if let Ok(original) = statics::ENTRYDATA_LIST_SAVE_HOOK.original() {
        unsafe { original(list, save_buffer) };
    }
}

fn read_save_state(save_buffer: *mut c_void) -> u32 {
    let vtable = unsafe { ptr::read_unaligned(save_buffer as *const *const usize) };
    let get_state_addr = unsafe { ptr::read_unaligned(vtable) };
    let Ok(get_state) =
        (unsafe { FnPtr::<SaveGetStateFn>::from_raw(get_state_addr as *mut c_void) })
    else {
        return 0;
    };
    unsafe { get_state.as_fn()(save_buffer) }
}

fn save_count_begin(save_buffer: *mut c_void) -> u32 {
    let begin =
        unsafe { FnPtr::<SaveCountBeginFn>::from_address_unchecked(SAVE_COUNT_BEGIN_ADDR) }.as_fn();
    unsafe { begin(save_buffer) }
}

fn save_count_end(save_buffer: *mut c_void, count: u32, marker: u32) {
    let end =
        unsafe { FnPtr::<SaveCountEndFn>::from_address_unchecked(SAVE_COUNT_END_ADDR) }.as_fn();
    unsafe { end(save_buffer, count, marker) };
}

fn node_entry(node: *mut c_void) -> *mut EntryData {
    let get_data =
        unsafe { FnPtr::<ListNodeDataFn>::from_address_unchecked(LIST_NODE_DATA_ADDR) }.as_fn();
    let slot = unsafe { get_data(node) };
    if slot.is_null() {
        ptr::null_mut()
    } else {
        unsafe { ptr::read_unaligned(slot) }
    }
}

fn list_node_next(node: *mut c_void) -> *mut c_void {
    let next =
        unsafe { FnPtr::<ListNodeNextFn>::from_address_unchecked(LIST_NODE_NEXT_ADDR) }.as_fn();
    unsafe { next(node) }
}

fn entrydata_body_save(entry: *mut EntryData, save_buffer: *mut c_void) {
    let save =
        unsafe { FnPtr::<EntryDataBodySaveFn>::from_address_unchecked(ENTRYDATA_BODY_SAVE_ADDR) }
            .as_fn();
    unsafe { save(entry, save_buffer) };
}

fn is_valid_entry(entry: *mut EntryData) -> bool {
    if !is_readable(entry as usize, ENTRYDATA_SIZE) {
        return false;
    }

    let form = unsafe { ptr::read_unaligned(ptr::addr_of!((*entry).type_form)) };
    !form.is_null() && is_valid_tes_form(form)
}

fn is_valid_tes_form(form: *mut c_void) -> bool {
    let form_addr = form as usize;
    if !is_readable(form_addr, 0x10) {
        return false;
    }

    let vtable = unsafe { ptr::read_unaligned(form as *const usize) };
    if !is_rdata_ptr(vtable) || !is_readable(vtable, 4) {
        return false;
    }

    let first_method = unsafe { ptr::read_unaligned(vtable as *const usize) };
    is_text_ptr(first_method)
}

fn read_unaligned_u32(base: *mut c_void, offset: usize) -> u32 {
    unsafe { ptr::read_unaligned((base as *const u8).add(offset) as *const u32) }
}

fn write_unaligned_u32(base: *mut c_void, offset: usize, value: u32) {
    unsafe { ptr::write_unaligned((base as *mut u8).add(offset) as *mut u32, value) };
}

fn is_rdata_ptr(addr: usize) -> bool {
    (FNV_RDATA_START..FNV_RDATA_END).contains(&addr)
}

fn is_text_ptr(addr: usize) -> bool {
    (FNV_TEXT_START..FNV_TEXT_END).contains(&addr)
}

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(addr as *mut c_void) else {
        return false;
    };
    if !info.is_accessible() {
        return false;
    }
    let end = addr.saturating_add(len);
    let region_end = (info.base_address as usize).saturating_add(info.region_size);
    end <= region_end
}

fn log_invalid_entry(counter: &AtomicU64, reason: &'static str, entry: *mut EntryData) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if !n.is_power_of_two() {
        return;
    }

    let entry_addr = entry as usize;
    let (extend_data, count_delta, form) = if is_readable(entry_addr, ENTRYDATA_SIZE) {
        unsafe {
            (
                ptr::read_unaligned(
                    (entry as *const u8).add(ENTRYDATA_EXTEND_LIST_OFFSET) as *const usize
                ),
                ptr::read_unaligned(
                    (entry as *const u8).add(ENTRYDATA_COUNT_DELTA_OFFSET) as *const i32
                ),
                ptr::read_unaligned((entry as *const u8).add(ENTRYDATA_TYPE_OFFSET) as *const usize),
            )
        }
    } else {
        (0, 0, 0)
    };

    let vtable = if is_readable(form, 4) {
        unsafe { ptr::read_unaligned(form as *const usize) }
    } else {
        0
    };

    log::warn!(
        "[ENTRYDATA] guard={} total={} entry=0x{:08x} type=0x{:08x} vt=0x{:08x} count_delta={} extend=0x{:08x}",
        reason,
        n,
        entry_addr,
        form,
        vtable,
        count_delta,
        extend_data,
    );
}

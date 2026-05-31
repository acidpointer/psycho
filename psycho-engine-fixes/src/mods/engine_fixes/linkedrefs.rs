//! Guard for stale `ExtraLinkedRefChildren` lists during reference cleanup.
//!
//! The save-to-save crash at `0x00410286` happens while vanilla removes a
//! child link from a deleted reference in an unloading cell:
//!
//! - `0x0041E600` calls `BaseExtraList::GetByType(0x52)`
//! - vanilla walks `BaseExtraList + 0x04`
//! - a stale node pointer is dereferenced as `BSExtraData`
//!
//! Ghidra shows this exact caller already checks for NULL and returns if the
//! `ExtraLinkedRefChildren` extra is missing. This patch only replaces that
//! removal-side lookup. It does not change the add path, where returning NULL
//! would make vanilla allocate and append through the same corrupt list.

use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use libc::c_void;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};

use libpsycho::os::windows::winapi::{replace_call, virtual_query};

use super::{statics, types::BaseExtraListGetByTypeFn};

const EXTRA_LINKED_REF_CHILDREN_TYPE: u8 = 0x52;
const MAX_EXTRA_DATA_TYPE: u8 = 0x92;

const BASE_EXTRA_LIST_HEAD_OFFSET: usize = 0x04;
const BASE_EXTRA_LIST_TYPE_BITS_OFFSET: usize = 0x08;
const BASE_EXTRA_LIST_TYPE_BITS_LEN: usize = 0x15;
const BASE_EXTRA_LIST_MIN_SIZE: usize =
    BASE_EXTRA_LIST_TYPE_BITS_OFFSET + BASE_EXTRA_LIST_TYPE_BITS_LEN;

const BS_EXTRA_DATA_VTABLE_OFFSET: usize = 0x00;
const BS_EXTRA_DATA_TYPE_OFFSET: usize = 0x04;
const BS_EXTRA_DATA_NEXT_OFFSET: usize = 0x08;
const BS_EXTRA_DATA_MIN_SIZE: usize = 0x0C;
const EXTRA_LINKED_REF_CHILDREN_SIZE: usize = 0x14;

const LOW_POINTER_LIMIT: usize = 0x10000;
const FNV_RDATA_START: usize = 0x0100_0000;
const FNV_RDATA_END: usize = 0x0110_0000;

const MAX_LIST_NODES: usize = 1024;

static STALE_LIST_SKIP_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn install_remove_guard() -> anyhow::Result<()> {
    unsafe {
        replace_call(
            statics::LINKED_REF_CHILDREN_REMOVE_GET_BY_TYPE_CALL_ADDR as *mut c_void,
            get_linked_ref_children_for_remove_checked as *mut c_void,
        )
        .with_context(|| {
            format!(
                "patch ExtraLinkedRefChildren removal lookup at 0x{:08X}",
                statics::LINKED_REF_CHILDREN_REMOVE_GET_BY_TYPE_CALL_ADDR
            )
        })?;
    }

    Ok(())
}

unsafe extern "thiscall" fn get_linked_ref_children_for_remove_checked(
    list: *mut c_void,
    type_id: u8,
) -> *mut c_void {
    if type_id != EXTRA_LINKED_REF_CHILDREN_TYPE {
        log_bad_list("unexpected-type", list, ptr::null_mut(), type_id, 0);
        return ptr::null_mut();
    }

    if !is_linked_ref_children_lookup_safe(list) {
        return ptr::null_mut();
    }

    call_original_get_by_type(list, type_id)
}

fn is_linked_ref_children_lookup_safe(list: *mut c_void) -> bool {
    if !is_readable(list as usize, BASE_EXTRA_LIST_MIN_SIZE) {
        log_bad_list(
            "unreadable-list",
            list,
            ptr::null_mut(),
            EXTRA_LINKED_REF_CHILDREN_TYPE,
            0,
        );
        return false;
    }

    if !has_type_bit(list, EXTRA_LINKED_REF_CHILDREN_TYPE) {
        return true;
    }

    let mut node = unsafe {
        ptr::read_unaligned(
            (list as *const u8).add(BASE_EXTRA_LIST_HEAD_OFFSET) as *const *mut c_void
        )
    };
    let mut visited = 0usize;

    while !node.is_null() {
        if visited >= MAX_LIST_NODES {
            log_bad_list(
                "node-limit",
                list,
                node,
                EXTRA_LINKED_REF_CHILDREN_TYPE,
                visited,
            );
            return false;
        }
        visited += 1;

        if !is_valid_extra_node(node, BS_EXTRA_DATA_MIN_SIZE) {
            log_bad_list(
                "invalid-node",
                list,
                node,
                EXTRA_LINKED_REF_CHILDREN_TYPE,
                visited,
            );
            return false;
        }

        let node_type =
            unsafe { ptr::read_unaligned((node as *const u8).add(BS_EXTRA_DATA_TYPE_OFFSET)) };
        if node_type == EXTRA_LINKED_REF_CHILDREN_TYPE {
            if is_valid_extra_node(node, EXTRA_LINKED_REF_CHILDREN_SIZE) {
                return true;
            }
            log_bad_list("invalid-linked-ref-extra", list, node, node_type, visited);
            return false;
        }

        if node_type > MAX_EXTRA_DATA_TYPE {
            log_bad_list("invalid-node-type", list, node, node_type, visited);
            return false;
        }

        let next = unsafe {
            ptr::read_unaligned(
                (node as *const u8).add(BS_EXTRA_DATA_NEXT_OFFSET) as *const *mut c_void
            )
        };
        if next == node {
            log_bad_list("self-cycle", list, node, node_type, visited);
            return false;
        }
        node = next;
    }

    true
}

fn call_original_get_by_type(list: *mut c_void, type_id: u8) -> *mut c_void {
    if let Ok(original) = statics::BASE_EXTRA_LIST_GET_BY_TYPE_HOOK.original() {
        return unsafe { original(list, type_id) };
    }

    let original: BaseExtraListGetByTypeFn =
        unsafe { std::mem::transmute(statics::BASE_EXTRA_LIST_GET_BY_TYPE_ADDR) };
    unsafe { original(list, type_id) }
}

fn has_type_bit(list: *mut c_void, type_id: u8) -> bool {
    let byte_index = (type_id >> 3) as usize;
    if byte_index >= BASE_EXTRA_LIST_TYPE_BITS_LEN {
        return false;
    }

    let mask = 1u8 << (type_id & 7);
    let byte = unsafe {
        ptr::read_unaligned((list as *const u8).add(BASE_EXTRA_LIST_TYPE_BITS_OFFSET + byte_index))
    };
    (byte & mask) != 0
}

fn is_valid_extra_node(node: *mut c_void, len: usize) -> bool {
    if !is_readable(node as usize, len) {
        return false;
    }

    let vtable = unsafe {
        ptr::read_unaligned((node as *const u8).add(BS_EXTRA_DATA_VTABLE_OFFSET) as *const usize)
    };
    is_rdata_ptr(vtable)
}

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < LOW_POINTER_LIMIT || len == 0 {
        return false;
    }

    let Ok(info) = virtual_query(addr as *mut c_void) else {
        return false;
    };
    if info.state != MEM_COMMIT.0 || info.protect == PAGE_NOACCESS {
        return false;
    }
    if (info.protect.0 & PAGE_GUARD.0) != 0 {
        return false;
    }

    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    let region_end = (info.base_address as usize).saturating_add(info.region_size);
    end <= region_end
}

fn is_rdata_ptr(addr: usize) -> bool {
    (FNV_RDATA_START..FNV_RDATA_END).contains(&addr)
}

fn log_bad_list(
    reason: &'static str,
    list: *mut c_void,
    node: *mut c_void,
    type_id: u8,
    visited: usize,
) {
    let n = STALE_LIST_SKIP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n != 1 && !n.is_power_of_two() {
        return;
    }

    log::warn!(
        "[LINKED_REFS] stale child-list ignored: reason={} total={} list=0x{:08X} node=0x{:08X} type=0x{:02X} visited={}",
        reason,
        n,
        list as usize,
        node as usize,
        type_id,
        visited,
    );
}

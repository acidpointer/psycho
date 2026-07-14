//! Guards for broken linked-reference extras.
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
//!
//! The activation crash at `0x00401170` has a different contract break:
//! `ExtraLinkedRef` can point at a reference whose `baseForm` field is a
//! non-NULL invalid pointer. Vanilla's `0x00568680` type gate checks only for
//! NULL before calling `TESForm::GetTypeID`. Returning false at that gate keeps
//! the bad target out of the activation/message path without deleting link data.

use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use libc::c_void;
use libpsycho::os::windows::winapi::{replace_call, virtual_query};

use super::statics;

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
const FNV_TEXT_START: usize = 0x0040_0000;
const FNV_TEXT_END: usize = 0x00E0_0000;
const FNV_RDATA_START: usize = 0x0100_0000;
const FNV_RDATA_END: usize = 0x0110_0000;

const MAX_LIST_NODES: usize = 1024;
const TES_OBJECT_REFR_BASE_FORM_OFFSET: usize = 0x20;
const TES_OBJECT_REFR_MIN_SIZE: usize = TES_OBJECT_REFR_BASE_FORM_OFFSET + 4;
const TES_FORM_TYPE_OFFSET: usize = 0x04;
const TES_FORM_MIN_SIZE: usize = 0x10;
const LINKED_REF_TARGET_BASE_TYPE: u8 = 0x27;

static STALE_LIST_SKIP_COUNT: AtomicU64 = AtomicU64::new(0);
static INVALID_TARGET_SKIP_COUNT: AtomicU64 = AtomicU64::new(0);

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

pub fn install_target_base_form_guard() -> anyhow::Result<()> {
    unsafe {
        statics::LINKED_REF_TARGET_TYPE_GATE_HOOK.init(
            "linked_ref_target_base_form_guard",
            statics::LINKED_REF_TARGET_TYPE_GATE_ADDR as *mut c_void,
            hook_linked_ref_target_type_gate,
        )?;
    }
    statics::LINKED_REF_TARGET_TYPE_GATE_HOOK.enable()?;
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

    find_linked_ref_children_checked(list)
}

fn find_linked_ref_children_checked(list: *mut c_void) -> *mut c_void {
    if !is_readable(list as usize, BASE_EXTRA_LIST_MIN_SIZE) {
        log_bad_list(
            "unreadable-list",
            list,
            ptr::null_mut(),
            EXTRA_LINKED_REF_CHILDREN_TYPE,
            0,
        );
        return ptr::null_mut();
    }

    if !has_type_bit(list, EXTRA_LINKED_REF_CHILDREN_TYPE) {
        return ptr::null_mut();
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
            return ptr::null_mut();
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
            return ptr::null_mut();
        }

        let node_type =
            unsafe { ptr::read_unaligned((node as *const u8).add(BS_EXTRA_DATA_TYPE_OFFSET)) };
        if node_type == EXTRA_LINKED_REF_CHILDREN_TYPE {
            if is_valid_extra_node(node, EXTRA_LINKED_REF_CHILDREN_SIZE) {
                return node;
            }
            log_bad_list("invalid-linked-ref-extra", list, node, node_type, visited);
            return ptr::null_mut();
        }

        if node_type > MAX_EXTRA_DATA_TYPE {
            log_bad_list("invalid-node-type", list, node, node_type, visited);
            return ptr::null_mut();
        }

        let next = unsafe {
            ptr::read_unaligned(
                (node as *const u8).add(BS_EXTRA_DATA_NEXT_OFFSET) as *const *mut c_void
            )
        };
        if next == node {
            log_bad_list("self-cycle", list, node, node_type, visited);
            return ptr::null_mut();
        }
        node = next;
    }

    ptr::null_mut()
}

unsafe extern "thiscall" fn hook_linked_ref_target_type_gate(target: *mut c_void) -> u8 {
    let Some(base_form) = checked_base_form(target) else {
        return 0;
    };

    if !is_valid_tes_form(base_form) {
        log_bad_target("invalid-base-form", target, base_form);
        return 0;
    }

    u8::from(read_form_type(base_form) == LINKED_REF_TARGET_BASE_TYPE)
}

fn checked_base_form(target: *mut c_void) -> Option<*mut c_void> {
    if target.is_null() {
        return None;
    }

    if !is_valid_game_object(target, TES_OBJECT_REFR_MIN_SIZE) {
        log_bad_target("invalid-target-ref", target, ptr::null_mut());
        return None;
    }

    let base_form = unsafe {
        ptr::read_unaligned(
            (target as *const u8).add(TES_OBJECT_REFR_BASE_FORM_OFFSET) as *const *mut c_void
        )
    };
    if base_form.is_null() {
        return None;
    }

    Some(base_form)
}

fn is_valid_tes_form(form: *mut c_void) -> bool {
    is_valid_game_object(form, TES_FORM_MIN_SIZE)
}

fn is_valid_game_object(ptr: *mut c_void, len: usize) -> bool {
    if !is_readable(ptr as usize, len) {
        return false;
    }

    let vtable = unsafe { ptr::read_unaligned(ptr as *const usize) };
    if !is_rdata_ptr(vtable) || !is_readable(vtable, 4) {
        return false;
    }

    let first_method = unsafe { ptr::read_unaligned(vtable as *const usize) };
    is_text_ptr(first_method)
}

fn read_form_type(form: *mut c_void) -> u8 {
    unsafe { ptr::read_unaligned((form as *const u8).add(TES_FORM_TYPE_OFFSET)) }
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
    if !info.is_accessible() {
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

fn is_text_ptr(addr: usize) -> bool {
    (FNV_TEXT_START..FNV_TEXT_END).contains(&addr)
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

fn log_bad_target(reason: &'static str, target: *mut c_void, base_form: *mut c_void) {
    let n = INVALID_TARGET_SKIP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n != 1 && !n.is_power_of_two() {
        return;
    }

    let target_vtable = read_vtable_for_log(target);
    let base_vtable = read_vtable_for_log(base_form);

    log::warn!(
        "[LINKED_REFS] invalid linked target ignored: reason={} total={} target=0x{:08X} target_vt=0x{:08X} base=0x{:08X} base_vt=0x{:08X}",
        reason,
        n,
        target as usize,
        target_vtable,
        base_form as usize,
        base_vtable,
    );
}

fn read_vtable_for_log(ptr: *mut c_void) -> usize {
    if is_readable(ptr as usize, 4) {
        unsafe { ptr::read_unaligned(ptr as *const usize) }
    } else {
        0
    }
}

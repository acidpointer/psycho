//! Guard for invalid `ExtraOwnership.owner` pointers.
//!
//! The crash chain is now proven at the data boundary:
//! `ExtraOwnership.owner` can contain a small non-NULL value such as `7`.
//! Consumer-side checks only move the crash to the next caller because
//! xNVSE and vanilla both read the same stored owner field.
//!
//! This module repairs the boundary instead:
//! - save-load owner resolution is filtered before vanilla writes +0x0C
//! - `BaseExtraList::GetByType(0x21)` scrubs already-corrupt ownership data
//!
//! A NULL owner is valid. The ExtraOwnership default constructor writes
//! owner=NULL, and known callers already treat NULL as "no owner".

use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use libc::c_void;
use windows::Win32::System::Memory::{
    MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
    PAGE_READWRITE, PAGE_WRITECOPY,
};

use libpsycho::os::windows::winapi::{replace_call, virtual_query};

use super::statics;

const EXTRAOWNERSHIP_TYPE: u8 = 0x21;
const EXTRAOWNERSHIP_OWNER_OFFSET: usize = 0x0C;
const EXTRAOWNERSHIP_SIZE: usize = 0x10;

const LOW_POINTER_LIMIT: usize = 0x10000;
const FNV_TEXT_START: usize = 0x0040_0000;
const FNV_TEXT_END: usize = 0x00E0_0000;
const FNV_RDATA_START: usize = 0x0100_0000;
const FNV_RDATA_END: usize = 0x0110_0000;

const LOADED_FORM_RESOLVER_ADDR: usize = 0x004839C0;

type LoadedFormResolverFn = unsafe extern "C" fn(u32) -> *mut c_void;

static LOAD_SCRUB_COUNT: AtomicU64 = AtomicU64::new(0);
static ACCESS_SCRUB_COUNT: AtomicU64 = AtomicU64::new(0);
static ACCESS_UNREADABLE_COUNT: AtomicU64 = AtomicU64::new(0);
static HITCH_LOAD_SCRUB_COUNT: AtomicU64 = AtomicU64::new(0);
static HITCH_ACCESS_SCRUB_COUNT: AtomicU64 = AtomicU64::new(0);
static HITCH_ACCESS_UNREADABLE_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) struct HitchCounters {
    pub load_scrubs: u64,
    pub access_scrubs: u64,
    pub unreadable: u64,
}

pub(super) fn take_hitch_counters() -> HitchCounters {
    HitchCounters {
        load_scrubs: HITCH_LOAD_SCRUB_COUNT.swap(0, Ordering::AcqRel),
        access_scrubs: HITCH_ACCESS_SCRUB_COUNT.swap(0, Ordering::AcqRel),
        unreadable: HITCH_ACCESS_UNREADABLE_COUNT.swap(0, Ordering::AcqRel),
    }
}

pub fn install_load_hook() -> anyhow::Result<()> {
    unsafe {
        replace_call(
            statics::EXTRAOWNERSHIP_LOAD_RESOLVE_CALL_ADDR as *mut c_void,
            resolve_loaded_owner_checked as *mut c_void,
        )
        .with_context(|| {
            format!(
                "patch ExtraOwnership owner resolver call at 0x{:08X}",
                statics::EXTRAOWNERSHIP_LOAD_RESOLVE_CALL_ADDR
            )
        })?;
    }

    Ok(())
}

pub unsafe extern "thiscall" fn hook_base_extra_list_get_by_type(
    list: *mut c_void,
    type_id: u8,
) -> *mut c_void {
    let extra = match statics::BASE_EXTRA_LIST_GET_BY_TYPE_HOOK.original() {
        Ok(original) => unsafe { original(list, type_id) },
        Err(e) => {
            log::error!(
                "[EXTRAOWNERSHIP] BaseExtraList::GetByType original trampoline missing: {:?}",
                e
            );
            ptr::null_mut()
        }
    };

    if type_id != EXTRAOWNERSHIP_TYPE || extra.is_null() {
        return extra;
    }

    scrub_extraownership(extra)
}

unsafe extern "C" fn resolve_loaded_owner_checked(saved_ref: u32) -> *mut c_void {
    let resolve: LoadedFormResolverFn = unsafe { std::mem::transmute(LOADED_FORM_RESOLVER_ADDR) };
    let owner = unsafe { resolve(saved_ref) };
    if owner.is_null() || is_valid_tes_form(owner) {
        return owner;
    }

    HITCH_LOAD_SCRUB_COUNT.fetch_add(1, Ordering::Relaxed);
    log_invalid_owner(&LOAD_SCRUB_COUNT, "load", ptr::null_mut(), owner);
    ptr::null_mut()
}

fn scrub_extraownership(extra: *mut c_void) -> *mut c_void {
    if !is_readable(extra as usize, EXTRAOWNERSHIP_SIZE) {
        log_unreadable_extra(extra);
        return ptr::null_mut();
    }

    let owner_slot = unsafe { (extra as *mut u8).add(EXTRAOWNERSHIP_OWNER_OFFSET) as *mut usize };
    let owner = unsafe { ptr::read_unaligned(owner_slot) as *mut c_void };
    if owner.is_null() || is_valid_tes_form(owner) {
        return extra;
    }

    HITCH_ACCESS_SCRUB_COUNT.fetch_add(1, Ordering::Relaxed);
    log_invalid_owner(&ACCESS_SCRUB_COUNT, "access", extra, owner);

    if is_writable(owner_slot as usize, 4) {
        unsafe { ptr::write_unaligned(owner_slot, 0) };
        extra
    } else {
        ptr::null_mut()
    }
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

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < LOW_POINTER_LIMIT {
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
    let end = addr.saturating_add(len);
    let region_end = (info.base_address as usize).saturating_add(info.region_size);
    end <= region_end
}

fn is_writable(addr: usize, len: usize) -> bool {
    if !is_readable(addr, len) {
        return false;
    }
    let Ok(info) = virtual_query(addr as *mut c_void) else {
        return false;
    };
    let protect = info.protect.0;
    protect == PAGE_READWRITE.0
        || protect == PAGE_WRITECOPY.0
        || protect == PAGE_EXECUTE_READWRITE.0
        || protect == PAGE_EXECUTE_WRITECOPY.0
}

fn is_rdata_ptr(addr: usize) -> bool {
    (FNV_RDATA_START..FNV_RDATA_END).contains(&addr)
}

fn is_text_ptr(addr: usize) -> bool {
    (FNV_TEXT_START..FNV_TEXT_END).contains(&addr)
}

fn log_unreadable_extra(extra: *mut c_void) {
    HITCH_ACCESS_UNREADABLE_COUNT.fetch_add(1, Ordering::Relaxed);
    let n = ACCESS_UNREADABLE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[EXTRAOWNERSHIP] unreadable ownership extra hidden: total={} extra=0x{:08X}",
            n,
            extra as usize,
        );
    }
}

fn log_invalid_owner(
    counter: &AtomicU64,
    site: &'static str,
    extra: *mut c_void,
    owner: *mut c_void,
) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n != 1 && !n.is_power_of_two() {
        return;
    }

    let owner_addr = owner as usize;
    let vtable = if is_readable(owner_addr, 4) {
        unsafe { ptr::read_unaligned(owner as *const usize) }
    } else {
        0
    };

    log::warn!(
        "[EXTRAOWNERSHIP] invalid owner scrubbed: site={} total={} extra=0x{:08X} owner=0x{:08X} vt=0x{:08X}",
        site,
        n,
        extra as usize,
        owner_addr,
        vtable,
    );
}

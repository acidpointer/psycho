//! Scrap heap hooks.

use libc::c_void;
use std::cell::UnsafeCell;
use std::ptr::null_mut;
use libmimalloc::{
    mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc, mi_usable_size,
};


use super::small_blocks_allocator::region_allocator::RegionAllocator;


pub(super) unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    let result = unsafe { mi_malloc(size) };
    log::trace!("malloc({}) -> {:p}", size, result);
    result
}

pub(super) unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let result = unsafe { mi_calloc(count, size) };
    log::trace!("calloc({}, {}) -> {:p}", count, size, result);
    result
}

pub(super) unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        let result = unsafe { mi_realloc(raw_ptr, size) };
        log::trace!(
            "realloc({:p}, {}) -> {:p} [mimalloc]",
            raw_ptr,
            size,
            result
        );
        return result;
    }

    match super::replacer::CRT_INLINE_REALLOC_HOOK_1.original() {
        Ok(orig_realloc) => {
            unsafe { orig_realloc(raw_ptr, size) }
        }

        Err(err) => {
            log::error!("Failed to call original realloc: {:?}", err);

            null_mut()
        }
    }
}

pub(super) unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    unsafe { mi_recalloc(raw_ptr, count, size) }
}

pub(super) unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        return unsafe { mi_usable_size(raw_ptr) };
    }

    match super::replacer::CRT_INLINE_MSIZE_HOOK.original() {
        Ok(orig_msize) => {
            let orig_size = unsafe { orig_msize(raw_ptr) };

            if orig_size == usize::MAX {
                log::warn!("hook_msize: pointer is unknown {:p}!", raw_ptr);
                return 0;
            }
            orig_size
        }
        Err(err) => {
            log::error!("Failed to call original msize: {:?}", err);
            0
        }
    }
}

pub(super) unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        return unsafe { mi_free(raw_ptr) };
    }

    match super::replacer::CRT_INLINE_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(raw_ptr) };
        }

        Err(err) => {
            log::error!(
                "Failed to call original free for pointer={:p}; Error: {:?}",
                raw_ptr,
                err
            );
        }
    }
}

/// Game's scrap heap structure.
/// Must match the game's struct layout exactly.
#[repr(C)]
struct SheapStruct {
    blocks: *mut *mut c_void, // 0x00
    cur: *mut c_void,          // 0x04
    last: *mut c_void,         // 0x08
}


pub unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    // So, game expects that this call will return pointer
    // to valid SheapStruct per thread.
    // Let's try with UnsafeCell<SheapStruct> wrapped in thread_local!

    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct { blocks: null_mut(), cur: null_mut(), last: null_mut() }) };
    }

    DUMMY_SHEAP.with(|d| d.get() as *mut c_void)
}

/// Fixed-size sheap initialization hook (0x00AA53F0 FNV, 0x0086CB70 GECK).
pub unsafe extern "fastcall" fn sheap_init_fix(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }
   
    RegionAllocator::purge(sheap_ptr);
}

/// Variable-size sheap initialization hook (0x00AA5410 FNV, 0x0086CB90 GECK).
pub unsafe extern "fastcall" fn sheap_init_var(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_var: NULL heap pointer");
        return;
    }
    
    // Ensure your RegionAllocator knows this heap is "fresh"
    RegionAllocator::purge(sheap_ptr);
}


/// Sheap allocation hook (0x00AA5430 FNV, 0x0086CBA0 GECK).
pub unsafe extern "fastcall" fn sheap_alloc(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    if sheap_ptr.is_null() {
        log::error!("sheap_alloc: sheap_ptr is NULL!");
        return sheap_ptr;
    }

    // Ensure that we have CORRECT align
    let actual_align = align.max(16); // 4
    RegionAllocator::alloc_align(sheap_ptr, size, actual_align)
}

/// Sheap free hook.
pub unsafe extern "fastcall" fn sheap_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    RegionAllocator::free(sheap_ptr, ptr);
}

/// Sheap purge hook (0x00AA5460 FNV, 0x0086CAA0 GECK).
pub unsafe extern "fastcall" fn sheap_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    RegionAllocator::purge(sheap_ptr);
}

pub unsafe extern "C" fn sheap_maintenance(sheap_ptr: *mut c_void) {
    log::debug!("MAINTENANCE CALLED YAAAAY!");

    // Redirect the engine's internal maintenance to our safe purge
    RegionAllocator::purge(sheap_ptr);
}
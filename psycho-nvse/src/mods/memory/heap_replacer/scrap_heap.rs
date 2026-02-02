//! Scrap heap hooks.

use crate::mods::memory::sheap::ScrapHeap;

use super::sheap;
use ahash::AHashMap;
use libc::c_void;
use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::ptr::null_mut;

/// Game's scrap heap structure.
/// Must match the game's struct layout exactly.
#[repr(C)]
struct SheapStruct {
    blocks: *mut *mut c_void,
    cur: *mut c_void,
    last: *mut c_void,
}

pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    // So, game expects that this call will return pointer
    // to valid SheapStruct per thread.
    // Let's try with UnsaceCell<SheapStruct> wrapped in thread_local!

    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct { blocks: null_mut(), cur: null_mut(), last: null_mut() }) };
    }

    DUMMY_SHEAP.with(|d| d.get() as *mut c_void)
}

/// Fixed-size sheap initialization hook (0x00AA53F0 FNV, 0x0086CB70 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_fix(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }

    // Initialize sheap structure with NULL pointers
    let sheap = heap as *mut SheapStruct;

    let sheap_mut = unsafe { &mut *sheap };
    sheap_mut.blocks = null_mut();
    sheap_mut.cur = null_mut();
    sheap_mut.last = null_mut();
}

/// Variable-size sheap initialization hook (0x00AA5410 FNV, 0x0086CB90 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_var(
    heap: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if heap.is_null() {
        log::error!("sheap_init_var: NULL heap pointer");
        return;
    }

    // Initialize sheap structure with NULL pointers
    // This is safe because our hooks handle all actual allocations
    let sheap = heap as *mut SheapStruct;
    let sheap_mut = unsafe { &mut *sheap };

    sheap_mut.blocks = null_mut();
    sheap_mut.cur = null_mut();
    sheap_mut.last = null_mut();
}


/// Sheap allocation hook (0x00AA5430 FNV, 0x0086CBA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_alloc(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    sheap::sheap_alloc_align(sheap_ptr, size, align)
}

/// Sheap free hook.
pub(super) unsafe extern "fastcall" fn sheap_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    sheap::sheap_free(sheap_ptr, ptr)
}

/// Sheap purge hook (0x00AA5460 FNV, 0x0086CAA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    sheap::sheap_purge(sheap_ptr);
}

//! Scrap heap hooks.

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc, mi_usable_size,
};
use std::cell::{RefCell, UnsafeCell};
use std::ptr::null_mut;

use rand::rngs::SmallRng;
use rand::{Rng, RngExt};

thread_local! {
    // We use a thread-local RNG so we don't need a Mutex/Lock
    static RNG: RefCell<SmallRng> = RefCell::new(rand::make_rng());
}

// Why this is here? Because, i wont to mess with new structure for rng mod.
// Did you know that Fallout: New Vegas uses 20+ years old RNG generation algorithm?
// And did you know that rng call is... HOT. Very hot.
// So, what we do here is use actually fast and modern SmallRng.
// It is extremely fast and has a tiny state compared to the 2.5KB state array of the engine's Mersenne Twister.
pub(super) unsafe extern "thiscall" fn hook_rng(_this: *mut c_void, param_1: u32) -> u32 {
    if param_1 == 0 {
        return 0;
    }

    RNG.with(|rng_cell| {
        let mut rng = rng_cell.borrow_mut();

        // Match the engine's original logic for specific bitmasks
        if param_1 == 0xFFFFFFFF {
            rng.next_u32()
        } else if param_1 == 0x7FFF {
            rng.next_u32() & 0x7FFF
        } else {
            // gen_range is significantly optimized compared to a simple modulo
            rng.random_range(0..param_1)
        }
    })
}

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
        Ok(orig_realloc) => unsafe { orig_realloc(raw_ptr, size) },

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
                log::warn!(
                    "hook_msize: pointer={:p} is unknown (orig_size==usize::MAX)!",
                    raw_ptr
                );
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

pub(super) unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { mi_malloc(size) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_free(this: *mut c_void, ptr: *mut c_void) {
    let is_mimalloc = unsafe { mi_is_in_heap_region(ptr) };

    if is_mimalloc {
        return unsafe { mi_free(ptr) };
    }

    match super::replacer::GHEAP_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(this, ptr) };
        }

        Err(err) => {
            log::error!(
                "Failed to call original gheap_free for pointer={:p}; Error: {:?}",
                ptr,
                err
            );
        }
    }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_msize(
    this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    let is_mimalloc = unsafe { mi_is_in_heap_region(ptr) };

    if is_mimalloc {
        return unsafe { mi_usable_size(ptr) };
    }

    match super::replacer::GHEAP_MSIZE_HOOK.original() {
        Ok(orig_msize) => {
            let orig_size = unsafe { orig_msize(this, ptr) };

            if orig_size == usize::MAX {
                log::warn!("hook_gheap_msize: pointer is unknown {:p}!", ptr);
                return 0;
            }
            orig_size
        }
        Err(err) => {
            log::error!("Failed to call original gheap_msize: {:?}", err);
            0
        }
    }
}

// ===========================================================================
//   SCRAP HEAP
//
// ===========================================================================

use super::sbm::runtime::Runtime;

/// Game's scrap heap structure.
/// Must match the game's struct layout exactly.
#[repr(C)]
pub struct SheapStruct {
    blocks: *mut *mut c_void, // 0x00
    cur: *mut c_void,         // 0x04
    last: *mut c_void,        // 0x08
}

impl SheapStruct {
    pub const fn new_nulled() -> Self {
        Self {
            blocks: null_mut(),
            cur: null_mut(),
            last: null_mut(),
        }
    }
}

/// This is source of all sheap instances!
#[allow(clippy::let_and_return)]
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct::new_nulled()) };
    }

    let sheap_ptr = DUMMY_SHEAP.with(|d| d.get() as *mut c_void);

    sheap_ptr
}

/// Fixed-size sheap initialization hook (0x00AA53F0 FNV, 0x0086CB70 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_fix(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }

    Runtime::get_instance().purge(sheap_ptr);
}

/// Variable-size sheap initialization hook (0x00AA5410 FNV, 0x0086CB90 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_var(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_var: NULL heap pointer");
        return;
    }

    // Ensure your RegionAllocator knows this heap is "fresh"
    Runtime::get_instance().purge(sheap_ptr);
}

/// Sheap allocation hook (0x00AA5430 FNV, 0x0086CBA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_alloc(
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
    let actual_align = align.max(16);
    Runtime::get_instance().alloc(sheap_ptr, size, actual_align)
}

/// Sheap free hook.
/// In our case - NOOP
pub(super) unsafe extern "fastcall" fn sheap_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    Runtime::get_instance().free(sheap_ptr, ptr);
}

/// Sheap purge hook (0x00AA5460 FNV, 0x0086CAA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    Runtime::get_instance().purge(sheap_ptr);
}

pub(super) unsafe extern "C" fn sheap_maintenance(sheap_ptr: *mut c_void) {
    log::warn!(
        "sheap_maintenance: maintenance function called! IDK why and how, but i'll purge sheap (sheap_ptr={:p})",
        sheap_ptr
    );

    // Redirect the engine's internal maintenance to our safe purge
    Runtime::get_instance().purge(sheap_ptr);
}

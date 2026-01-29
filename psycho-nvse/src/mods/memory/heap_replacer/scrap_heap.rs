//! Scrap heap hook implementations.
//!
//! Provides the FFI hook functions that replace the game's scrap heap operations.
//! All hooks delegate to the ScrapHeapManager which manages bump allocator instances.

use libc::c_void;
use super::sheap::*;

/// Game's scrap heap structure (12 bytes, FFI boundary).
/// Must match the game's struct layout exactly.
#[repr(C)]
struct SheapStruct {
    blocks: *mut *mut c_void,
    cur: *mut c_void,
    last: *mut c_void,
}

/// Fixed-size sheap initialization hook (0x00AA53F0 FNV, 0x0086CB70 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_fix(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }

    // Initialize sheap structure with NULL pointers
    // This is safe because our hooks handle all actual allocations
    let sheap = heap as *mut SheapStruct;
    (*sheap).blocks = std::ptr::null_mut();
    (*sheap).cur = std::ptr::null_mut();
    (*sheap).last = std::ptr::null_mut();
}

/// Variable-size sheap initialization hook (0x00AA5410 FNV, 0x0086CB90 GECK).
///
/// The size parameter is ignored (matches original C++ behavior).
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
    (*sheap).blocks = std::ptr::null_mut();
    (*sheap).cur = std::ptr::null_mut();
    (*sheap).last = std::ptr::null_mut();
}

/// Sheap allocation hook (0x00AA5430 FNV, 0x0086CBA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_alloc(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    // Validate sheap structure hasn't been corrupted
    if !sheap_ptr.is_null() {
        let sheap = sheap_ptr as *const SheapStruct;
        let cur = (*sheap).cur;
        if !cur.is_null() && (cur as usize) < 0x10000 {
            log::error!("sheap_alloc: Detected corrupted sheap structure at {:p}, cur={:p}", sheap_ptr, cur);
        }
    }

    Sheap::malloc_aligned(sheap_ptr, size, align)
}

/// Sheap free hook.
///
/// For bump allocator memory, this is a no-op (memory is reclaimed on purge).
/// For mimalloc fallback allocations, frees the memory individually.
pub(super) unsafe extern "fastcall" fn sheap_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    Sheap::free(sheap_ptr, ptr);
}

/// Sheap purge hook (0x00AA5460 FNV, 0x0086CAA0 GECK).
///
/// Drops the bump allocator for the specified sheap, freeing all memory.
pub(super) unsafe extern "fastcall" fn sheap_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    Sheap::purge(sheap_ptr);
}

use std::cell::RefCell;

thread_local! {
    /// Fake scrap heap structure that the game can safely access.
    /// Boxed and leaked to ensure stable address per thread.
    static FAKE_SHEAP: RefCell<Option<*mut SheapStruct>> = const { RefCell::new(None) };
}

/// Thread-local sheap getter hook (0x00AA42E0 FNV, 0x0086BCB0 GECK).
///
/// Returns a thread-local sheap instance, allocating and initializing it on first access.
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    FAKE_SHEAP.with(|cell| {
        let mut opt = cell.borrow_mut();

        if let Some(ptr) = *opt {
            // Already initialized, return existing pointer
            ptr as *mut c_void
        } else {
            // First call on this thread - create and leak a fake sheap structure
            let fake_sheap = Box::new(SheapStruct {
                blocks: std::ptr::null_mut(),
                cur: std::ptr::null_mut(),
                last: std::ptr::null_mut(),
            });

            let ptr = Box::into_raw(fake_sheap);
            *opt = Some(ptr);

            ptr as *mut c_void
        }
    })
}

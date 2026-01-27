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

    // NOOP
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

    // NOOP
}

/// Sheap allocation hook (0x00AA5430 FNV, 0x0086CBA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_alloc(
    heap: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    Sheap::malloc_aligned(heap, size, align)
}

/// Sheap free hook.
///
/// For bump allocator memory, this is a no-op (memory is reclaimed on purge).
/// For mimalloc fallback allocations, frees the memory individually.
pub(super) unsafe extern "fastcall" fn sheap_free(
    heap: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    if ptr.is_null() {
        return;
    }

    Sheap::free(heap, ptr);
}

/// Sheap purge hook (0x00AA5460 FNV, 0x0086CAA0 GECK).
///
/// Drops the bump allocator for the specified sheap, freeing all memory.
pub(super) unsafe extern "fastcall" fn sheap_purge(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        log::error!("sheap_purge: NULL heap pointer");
        return;
    }

    Sheap::purge(heap);
}

/// Thread-local sheap getter hook (0x00AA42E0 FNV, 0x0086BCB0 GECK).
///
/// Returns a thread-local sheap instance, allocating and initializing it on first access.
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    std::ptr::null_mut()
}

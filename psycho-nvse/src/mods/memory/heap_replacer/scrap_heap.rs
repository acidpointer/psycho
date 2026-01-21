//! Scrap heap hook implementations.
//!
//! Provides the FFI hook functions that replace the game's scrap heap operations.
//! All hooks delegate to the ScrapHeapManager which manages bump allocator instances.

use std::cell::RefCell;
use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{mi_free, mi_is_in_heap_region, mi_malloc};

use super::ScrapHeapManager;

/// Game's scrap heap structure (12 bytes, FFI boundary).
/// Must match the game's struct layout exactly.
#[repr(C)]
struct SheapStruct {
    blocks: *mut *mut c_void,
    cur: *mut c_void,
    last: *mut c_void,
}

static SCRAP_HEAP_MANAGER: LazyLock<ScrapHeapManager> = LazyLock::new(ScrapHeapManager::new);

/// Fixed-size sheap initialization hook (0x00AA53F0 FNV, 0x0086CB70 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_fix(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }

    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    SCRAP_HEAP_MANAGER.init(heap, thread_id);
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

    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    SCRAP_HEAP_MANAGER.init(heap, thread_id);
}

/// Sheap allocation hook (0x00AA5430 FNV, 0x0086CBA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_alloc(
    heap: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    if heap.is_null() {
        log::warn!("sheap_alloc: NULL heap pointer, using global malloc");
        return unsafe { libmimalloc::mi_malloc_aligned(size, align) };
    }

    let result = SCRAP_HEAP_MANAGER.alloc(heap, size, align);

    if result.is_null() {
        log::error!(
            "sheap_alloc: Failed to allocate {} bytes (align={}) for sheap {:p}",
            size,
            align,
            heap
        );
    }

    result
}

/// Sheap free hook.
///
/// For bump allocator memory, this is a no-op (memory is reclaimed on purge).
/// For mimalloc fallback allocations, frees the memory individually.
pub(super) unsafe extern "fastcall" fn sheap_free(
    heap: *mut c_void,
    _edx: *mut c_void,
    addr: *mut c_void,
) {
    if addr.is_null() {
        return;
    }

    if !SCRAP_HEAP_MANAGER.free(heap, addr) {
        if unsafe { mi_is_in_heap_region(addr) } {
            unsafe { mi_free(addr) };
        }
    }
}

/// Sheap purge hook (0x00AA5460 FNV, 0x0086CAA0 GECK).
///
/// Drops the bump allocator for the specified sheap, freeing all memory.
pub(super) unsafe extern "fastcall" fn sheap_purge(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        log::error!("sheap_purge: NULL heap pointer");
        return;
    }

    SCRAP_HEAP_MANAGER.purge(heap);
}

/// Thread-local sheap getter hook (0x00AA42E0 FNV, 0x0086BCB0 GECK).
///
/// Returns a thread-local sheap instance, allocating and initializing it on first access.
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    thread_local! {
        static THREAD_SHEAP: RefCell<Option<*mut SheapStruct>> = const { RefCell::new(None) };
    }

    THREAD_SHEAP.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            let sheap =
                unsafe { mi_malloc(std::mem::size_of::<SheapStruct>()) } as *mut SheapStruct;

            if sheap.is_null() {
                log::error!("sheap_get_thread_local: Failed to allocate SheapStruct");
                return std::ptr::null_mut();
            }

            unsafe {
                sheap_init_fix(sheap as *mut c_void, std::ptr::null_mut());
            }

            *opt = Some(sheap);
        }

        opt.unwrap() as *mut c_void
    })
}

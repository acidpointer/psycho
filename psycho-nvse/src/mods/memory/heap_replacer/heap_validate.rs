//! Heap pointer validation for safe cross-heap routing.
//!
//! When multiple CRT heaps coexist (game's embedded CRT, system CRT,
//! plugin CRTs), freeing a pointer through the wrong heap causes
//! corruption. This module caches process heap handles at startup and
//! uses HeapValidate to determine ownership before routing operations.

use std::sync::OnceLock;

use libc::c_void;
use libpsycho::os::windows::winapi;

/// Cached list of process heap handles, populated once at init.
static HEAP_HANDLES: OnceLock<Vec<isize>> = OnceLock::new();

/// Initialize the heap handle cache. Call once during startup.
pub fn init_heap_cache() {
    HEAP_HANDLES.get_or_init(|| {
        let heaps = winapi::get_process_heaps();

        log::debug!(
            "[HEAP] Cached {} process heap handles for pointer validation",
            heaps.len()
        );

        heaps
    });
}

/// Free a pointer through the correct Windows heap.
/// Returns true if freed successfully, false if no heap owns it.
pub unsafe fn heap_validated_free(ptr: *mut c_void) -> bool {
    let heaps = match HEAP_HANDLES.get() {
        Some(h) => h,
        None => return false,
    };

    if let Some(heap) = winapi::find_owning_heap(heaps, ptr as *const c_void) {
        return unsafe { winapi::heap_free(heap, ptr) };
    }

    false
}

/// Get the size of a pointer through the correct Windows heap.
/// Returns usize::MAX if no heap owns it.
pub unsafe fn heap_validated_size(ptr: *const c_void) -> usize {
    let heaps = match HEAP_HANDLES.get() {
        Some(h) => h,
        None => return usize::MAX,
    };

    if let Some(heap) = winapi::find_owning_heap(heaps, ptr) {
        return unsafe { winapi::heap_size(heap, ptr) };
    }

    usize::MAX
}

/// Realloc a pointer through the correct Windows heap.
/// Returns null if no heap owns the original pointer.
pub unsafe fn heap_validated_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let heaps = match HEAP_HANDLES.get() {
        Some(h) => h,
        None => return std::ptr::null_mut(),
    };

    if let Some(heap) = winapi::find_owning_heap(heaps, ptr as *const c_void) {
        return unsafe { winapi::heap_realloc(heap, ptr, size) };
    }

    std::ptr::null_mut()
}

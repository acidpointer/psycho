//! IAT hook replacements for CRT allocator functions (malloc, free, etc.).
//!
//! Mirrors the gheap allocator behavior:
//!   - Large allocs (>= 1MB) --> VirtualAlloc (immediate VAS reclamation)
//!   - Small allocs (< 1MB)  --> mimalloc arena
//!
//! No OOM recovery -- mi_collect is too dangerous at the system allocator
//! level (can trigger reentrant allocations from game cleanup stages,
//! causing deadlock or stack overflow through our own hooks). If allocation
//! fails, return NULL directly -- the caller must handle it.

use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{
    mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc, mi_usable_size,
};
use libpsycho::os::windows::{
    hook::iat::iathook::IatHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
};

pub static MALLOC_IAT_HOOK: LazyLock<IatHookContainer<MallocFn>> =
    LazyLock::new(IatHookContainer::new);
pub static CALLOC_IAT_HOOK: LazyLock<IatHookContainer<CallocFn>> =
    LazyLock::new(IatHookContainer::new);
pub static REALLOC_IAT_HOOK: LazyLock<IatHookContainer<ReallocFn>> =
    LazyLock::new(IatHookContainer::new);
pub static RECALLOC_IAT_HOOK: LazyLock<IatHookContainer<RecallocFn>> =
    LazyLock::new(IatHookContainer::new);
pub static MSIZE_IAT_HOOK: LazyLock<IatHookContainer<MsizeFn>> =
    LazyLock::new(IatHookContainer::new);
pub static FREE_IAT_HOOK: LazyLock<IatHookContainer<FreeFn>> = LazyLock::new(IatHookContainer::new);

// -----------------------------------------------------------------------
// CRT hook implementations: all routes through mimalloc
// -----------------------------------------------------------------------

pub unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    unsafe { iat_alloc(size) }
}

pub unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let total = count.checked_mul(size).unwrap_or(0);
    if total == 0 {
        return std::ptr::null_mut();
    }
    let ptr = unsafe { iat_alloc(total) };
    if !ptr.is_null() {
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, total) };
    }
    ptr
}

pub unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    if raw_ptr.is_null() {
        return unsafe { iat_alloc(size) };
    }
    if size == 0 {
        unsafe { iat_free(raw_ptr) };
        return std::ptr::null_mut();
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_realloc(raw_ptr, size) };
    }

    if let Ok(original_realloc) = REALLOC_IAT_HOOK.original() {
        unsafe { original_realloc(raw_ptr, size) }
    } else {
        std::ptr::null_mut()
    }
}

pub unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    if raw_ptr.is_null() {
        let total = count.checked_mul(size).unwrap_or(0);
        if total == 0 {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { iat_alloc(total) };
        if !ptr.is_null() {
            unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, total) };
        }
        return ptr;
    }
    if count == 0 || size == 0 {
        unsafe { iat_free(raw_ptr) };
        return std::ptr::null_mut();
    }

    let total = count.checked_mul(size).unwrap_or(0);
    if total == 0 {
        unsafe { iat_free(raw_ptr) };
        return std::ptr::null_mut();
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_recalloc(raw_ptr, count, size) };
    }

    if let Ok(original_recalloc) = RECALLOC_IAT_HOOK.original() {
        unsafe { original_recalloc(raw_ptr, count, size) }
    } else {
        std::ptr::null_mut()
    }
}

pub unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    if raw_ptr.is_null() {
        return 0;
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_usable_size(raw_ptr) };
    }

    if let Ok(original_msize) = MSIZE_IAT_HOOK.original() {
        unsafe { original_msize(raw_ptr) }
    } else {
        log::warn!("_msize({:p}) -> 0 [no fallback available]", raw_ptr);
        0
    }
}

pub unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    if raw_ptr.is_null() {
        return;
    }
    unsafe { iat_free(raw_ptr) };
}

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

/// Allocate through mimalloc.
#[inline]
unsafe fn iat_alloc(size: usize) -> *mut c_void {
    unsafe { mi_malloc(size) }
}

/// Free: route based on pointer ownership.
#[inline]
unsafe fn iat_free(ptr: *mut c_void) {
    if unsafe { mi_is_in_heap_region(ptr) } {
        unsafe { mi_free(ptr) };
        return;
    }

    // Unknown origin: fallback to original free.
    if let Ok(original_free) = FREE_IAT_HOOK.original() {
        unsafe { original_free(ptr) };
    } else {
        log::warn!("free({:p}) [no fallback available, potential leak]", ptr);
    }
}

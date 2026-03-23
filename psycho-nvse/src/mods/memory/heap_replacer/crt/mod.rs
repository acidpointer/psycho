//! CRT allocator hooks: malloc/calloc/realloc/recalloc/msize/free.
//!
//! Replaces the game's embedded MSVCRT heap with mimalloc. Pre-hook
//! pointers (allocated before our hooks were installed) are routed
//! through the original CRT trampoline or HeapValidate fallback.

use std::ptr::null_mut;
use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc,
    mi_usable_size,
};
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
};

use crate::mods::memory::heap_replacer::heap_validate;

// ---- Addresses ----

pub const MALLOC_ADDR_1: usize = 0x00ECD1C7;
pub const MALLOC_ADDR_2: usize = 0x00ED0CDF;
pub const CALLOC_ADDR_1: usize = 0x00EDDD7D;
pub const CALLOC_ADDR_2: usize = 0x00ED0D24;
pub const REALLOC_ADDR_1: usize = 0x00ECCF5D;
pub const REALLOC_ADDR_2: usize = 0x00ED0D70;
pub const RECALLOC_ADDR_1: usize = 0x00EE1700;
pub const RECALLOC_ADDR_2: usize = 0x00ED0DBE;
pub const MSIZE_ADDR: usize = 0x00ECD31F;
pub const FREE_ADDR: usize = 0x00ECD291;

// ---- Hook statics ----

pub static MALLOC_HOOK_1: LazyLock<InlineHookContainer<MallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static MALLOC_HOOK_2: LazyLock<InlineHookContainer<MallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CALLOC_HOOK_1: LazyLock<InlineHookContainer<CallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CALLOC_HOOK_2: LazyLock<InlineHookContainer<CallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static REALLOC_HOOK_1: LazyLock<InlineHookContainer<ReallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static REALLOC_HOOK_2: LazyLock<InlineHookContainer<ReallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static RECALLOC_HOOK_1: LazyLock<InlineHookContainer<RecallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static RECALLOC_HOOK_2: LazyLock<InlineHookContainer<RecallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static MSIZE_HOOK: LazyLock<InlineHookContainer<MsizeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static FREE_HOOK: LazyLock<InlineHookContainer<FreeFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Hook implementations ----

pub unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    let result = unsafe { mi_malloc(size) };
    log::trace!("malloc({}) -> {:p}", size, result);
    result
}

pub unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let result = unsafe { mi_calloc(count, size) };
    log::trace!("calloc({}, {}) -> {:p}", count, size, result);
    result
}

pub unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    if raw_ptr.is_null() {
        return unsafe { mi_malloc(size) };
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_realloc(raw_ptr, size) };
    }

    if let Ok(orig_realloc) = REALLOC_HOOK_1.original() {
        return unsafe { orig_realloc(raw_ptr, size) };
    }

    let result = unsafe { heap_validate::heap_validated_realloc(raw_ptr, size) };
    if !result.is_null() {
        return result;
    }

    log::error!("realloc({:p}, {}): no heap owns this pointer!", raw_ptr, size);
    null_mut()
}

pub unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    if raw_ptr.is_null() {
        return unsafe { mi_calloc(count, size) };
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_recalloc(raw_ptr, count, size) };
    }

    let new_total = match count.checked_mul(size) {
        Some(total) => total,
        None => return null_mut(),
    };

    let old_size = unsafe { hook_msize(raw_ptr) };
    let new_ptr = unsafe { mi_calloc(count, size) };
    if !new_ptr.is_null() && old_size > 0 && old_size != usize::MAX {
        unsafe {
            std::ptr::copy_nonoverlapping(
                raw_ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_total),
            );
        }
        unsafe { hook_free(raw_ptr) };
    }
    new_ptr
}

pub unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    if raw_ptr.is_null() {
        return 0;
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_usable_size(raw_ptr) };
    }

    if let Ok(orig_msize) = MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(raw_ptr) };
        if size != usize::MAX {
            return size;
        }
    }

    let size = unsafe { heap_validate::heap_validated_size(raw_ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }

    usize::MAX
}

pub unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    if raw_ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_free(raw_ptr) };
    }

    if let Ok(orig_free) = FREE_HOOK.original() {
        unsafe { orig_free(raw_ptr) };
        return;
    }

    if unsafe { heap_validate::heap_validated_free(raw_ptr) } {
        return;
    }

    log::error!("free({:p}): no heap owns this pointer!", raw_ptr);
}

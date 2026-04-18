//! Inline CRT allocator hooks for the game binary itself
//! (FalloutNV.exe's linked msvcrt entry points).
//!
//! Dispatch on each hook:
//!   1. Our tiers (pool / block / va_alloc) -- new allocations created
//!      after hooks activated land here, so most frees hit this path.
//!   2. Mimalloc -- pointers from the IAT hooks (third-party DLLs) may
//!      reach these inline hooks too; route them to mi_free.
//!   3. Original CRT trampoline (FREE_HOOK.original, etc.) -- pre-hook
//!      allocations that the game made before we installed hooks still
//!      live in the game's original msvcrt heap. They must be freed
//!      via the original CRT functions, NOT via our allocator or
//!      the game-heap trampoline.
//!   4. heap_validate fallback -- last-resort HeapValidate walk across
//!      all process heaps for pointers we can't identify.
//!
//! New allocations from `malloc` / `calloc` always go to our allocator.

use std::ptr::null_mut;
use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{mi_free, mi_is_in_heap_region, mi_realloc, mi_recalloc, mi_usable_size};
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
};

use super::gheap::{allocator, block, pool, va_alloc};
use super::heap_validate;

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

// ---------------------------------------------------------------------------
// Ownership checks
// ---------------------------------------------------------------------------

#[inline]
fn is_our_ptr(ptr: *const c_void) -> bool {
    pool::is_pool_ptr(ptr) || block::is_block_ptr(ptr) || va_alloc::size_of(ptr).is_some()
}

#[inline]
fn is_mimalloc_ptr(ptr: *const c_void) -> bool {
    unsafe { mi_is_in_heap_region(ptr) }
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    unsafe { allocator::alloc(size) }
}

pub unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let total = match count.checked_mul(size) {
        Some(t) if t != 0 => t,
        _ => return null_mut(),
    };
    let ptr = unsafe { allocator::alloc(total) };
    if !ptr.is_null() {
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, total) };
    }
    ptr
}

pub unsafe extern "C" fn hook_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { allocator::alloc(size) };
    }
    if size == 0 {
        unsafe { hook_free(ptr) };
        return null_mut();
    }

    // Our tier: use the unified realloc which does alloc+copy+free
    // with correct tier-aware size detection.
    if is_our_ptr(ptr as *const c_void) {
        return unsafe { allocator::realloc(ptr, size) };
    }

    // Mimalloc (pointer originated from crt_iat IAT hooks).
    if is_mimalloc_ptr(ptr as *const c_void) {
        return unsafe { mi_realloc(ptr, size) };
    }

    // Pre-hook CRT pointer: must go through the original CRT
    // realloc, NOT our allocator and NOT the game-heap trampoline.
    if let Ok(orig) = REALLOC_HOOK_1.original() {
        return unsafe { orig(ptr, size) };
    }

    let result = unsafe { heap_validate::heap_validated_realloc(ptr, size) };
    if !result.is_null() {
        return result;
    }
    log::error!("realloc({:p}, {}): no heap owns this pointer", ptr, size);
    null_mut()
}

pub unsafe extern "C" fn hook_recalloc(
    ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    let new_total = match count.checked_mul(size) {
        Some(t) => t,
        None => return null_mut(),
    };

    if ptr.is_null() {
        if new_total == 0 {
            return null_mut();
        }
        let np = unsafe { allocator::alloc(new_total) };
        if !np.is_null() {
            unsafe { std::ptr::write_bytes(np as *mut u8, 0, new_total) };
        }
        return np;
    }

    if new_total == 0 {
        unsafe { hook_free(ptr) };
        return null_mut();
    }

    // Our tier: alloc new, copy, zero tail, free old.
    if is_our_ptr(ptr as *const c_void) {
        let old_size = unsafe { allocator::msize(ptr) };
        let np = unsafe { allocator::alloc(new_total) };
        if np.is_null() {
            return null_mut();
        }
        unsafe {
            let copy_len = old_size.min(new_total);
            if copy_len > 0 {
                std::ptr::copy_nonoverlapping(ptr as *const u8, np as *mut u8, copy_len);
            }
            if new_total > copy_len {
                std::ptr::write_bytes(
                    (np as *mut u8).add(copy_len),
                    0,
                    new_total - copy_len,
                );
            }
            allocator::free(ptr);
        }
        return np;
    }

    // Mimalloc path.
    if is_mimalloc_ptr(ptr as *const c_void) {
        return unsafe { mi_recalloc(ptr, count, size) };
    }

    // Pre-hook CRT: original _recalloc.
    if let Ok(orig) = RECALLOC_HOOK_1.original() {
        return unsafe { orig(ptr, count, size) };
    }

    null_mut()
}

pub unsafe extern "C" fn hook_msize(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }

    if pool::is_pool_ptr(ptr as *const c_void) {
        return pool::usable_size(ptr as *const c_void);
    }
    if block::is_block_ptr(ptr as *const c_void) {
        return block::usable_size(ptr as *const c_void);
    }
    if let Some(sz) = va_alloc::size_of(ptr as *const c_void) {
        return sz;
    }

    if is_mimalloc_ptr(ptr as *const c_void) {
        return unsafe { mi_usable_size(ptr as *const c_void) };
    }

    // Pre-hook CRT pointer.
    if let Ok(orig) = MSIZE_HOOK.original() {
        let sz = unsafe { orig(ptr) };
        if sz != usize::MAX {
            return sz;
        }
    }

    let sz = unsafe { heap_validate::heap_validated_size(ptr as *const c_void) };
    if sz != usize::MAX {
        return sz;
    }

    0
}

pub unsafe extern "C" fn hook_free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    // Our tiers.
    if pool::is_pool_ptr(ptr as *const c_void) {
        pool::free(ptr);
        return;
    }
    if block::is_block_ptr(ptr as *const c_void) {
        block::free(ptr);
        return;
    }
    if unsafe { va_alloc::free(ptr) } {
        return;
    }

    // Mimalloc-owned (from crt_iat or similar).
    if is_mimalloc_ptr(ptr as *const c_void) {
        unsafe { mi_free(ptr) };
        return;
    }

    // Pre-hook CRT pointer -- must go through CRT's original free.
    if let Ok(orig) = FREE_HOOK.original() {
        unsafe { orig(ptr) };
        return;
    }

    if unsafe { heap_validate::heap_validated_free(ptr) } {
        return;
    }

    log::error!("free({:p}): no heap owns this pointer", ptr);
}

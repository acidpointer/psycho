use std::sync::LazyLock;

use libc::c_void;
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

use super::gheap;
use super::types::*;

/// Game heap hooks
pub static GAME_HEAP_ALLOCATE_HOOK: LazyLock<InlineHookContainer<GameHeapAllocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_REALLOCATE_HOOK_1: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_REALLOCATE_HOOK_2: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_MSIZE_HOOK: LazyLock<InlineHookContainer<GameHeapMsizeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_FREE_HOOK: LazyLock<InlineHookContainer<GameHeapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);

pub(crate) unsafe extern "fastcall" fn game_heap_allocate(
    heap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
) -> *mut c_void {
    let result = gheap::gheap_alloc(heap_ptr, size);
    if result.is_null() && size > 0 {
        log::error!("game_heap_allocate: Allocation failed: size={}", size);
    }

    result
}

pub(crate) unsafe extern "fastcall" fn game_heap_reallocate(
    heap_ptr: *mut c_void,
    edx: *mut c_void,
    ptr: *mut c_void,
    size: usize,
) -> *mut c_void {
    if ptr.is_null() {
        return gheap::gheap_alloc(heap_ptr, size);
    }

    // Try our allocator first
    match gheap::gheap_realloc(heap_ptr, ptr, size) {
        Some(result) => result,  // Our allocator handled it
        None => {
            // Our allocator doesn't recognize this pointer, use original
            match GAME_HEAP_REALLOCATE_HOOK_1.original() {
                Ok(orig_realloc) => unsafe { orig_realloc(heap_ptr, edx, ptr, size) },
                Err(err) => {
                    log::error!(
                        "game_heap_reallocate: Failed to call original for {:p}: {:?}",
                        ptr,
                        err
                    );
                    std::ptr::null_mut()
                }
            }
        }
    }
}

pub(crate) unsafe extern "fastcall" fn game_heap_msize(
    heap_ptr: *mut c_void,
    edx: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    // Try our allocator first
    match gheap::gheap_msize(heap_ptr, ptr) {
        Some(size) => size,  // Our allocator handled it
        None => {
            // Our allocator doesn't recognize this pointer, use original
            match GAME_HEAP_MSIZE_HOOK.original() {
                Ok(orig_msize) => unsafe { orig_msize(heap_ptr, edx, ptr) },
                Err(err) => {
                    log::error!(
                        "game_heap_msize: Failed to call original for {:p}: {:?}",
                        ptr,
                        err
                    );
                    0
                }
            }
        }
    }
}



pub(crate) unsafe extern "fastcall" fn game_heap_free(
    heap_ptr: *mut c_void,
    edx: *mut c_void,
    ptr: *mut c_void,
) {
    // Research insight
    // Did you know that if you call mi_collect/mi_heap_collect here,
    // game will crash even not reach main menu!
    // Funny, isnt it?


    if ptr.is_null() {
        return;
    }

    // Try our allocator first
    if gheap::gheap_free(heap_ptr, ptr) {
        // Our allocator handled it
        return;
    }

    // Our allocator doesn't recognize this pointer, use original
    match GAME_HEAP_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(heap_ptr, edx, ptr) };
        }
        Err(err) => {
            log::error!(
                "game_heap_free: Failed to call original for {:p}: {:?}",
                ptr,
                err
            );
        }
    }
}

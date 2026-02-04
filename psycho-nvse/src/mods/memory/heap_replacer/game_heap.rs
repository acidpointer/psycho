use libc::c_void;

use crate::mods::memory::gheap;

pub(super) unsafe extern "fastcall" fn game_heap_allocate(
    _self: *mut c_void,
    _edx: *mut c_void,
    size: usize,
) -> *mut c_void {
    let result = gheap::gheap_alloc(size);
    if result.is_null() && size > 0 {
        log::error!("game_heap_allocate: Allocation failed: size={}", size);
    }

    result
}

pub(super) unsafe extern "fastcall" fn game_heap_reallocate(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    ptr: *mut c_void,
    size: usize,
) -> *mut c_void {
    if ptr.is_null() {
        return gheap::gheap_alloc(size);
    }

    // Try our allocator first
    match gheap::gheap_realloc(ptr, size) {
        Some(result) => result,  // Our allocator handled it
        None => {
            // Our allocator doesn't recognize this pointer, use original
            match super::GAME_HEAP_REALLOCATE_HOOK_1.original() {
                Ok(orig_realloc) => unsafe { orig_realloc(self_ptr, edx, ptr, size) },
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

pub(super) unsafe extern "fastcall" fn game_heap_msize(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    // Try our allocator first
    match gheap::gheap_msize(ptr) {
        Some(size) => size,  // Our allocator handled it
        None => {
            // Our allocator doesn't recognize this pointer, use original
            match super::GAME_HEAP_MSIZE_HOOK.original() {
                Ok(orig_msize) => unsafe { orig_msize(self_ptr, edx, ptr) },
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



pub(super) unsafe extern "fastcall" fn game_heap_free(
    self_ptr: *mut c_void,
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
    if gheap::gheap_free(ptr) {
        // Our allocator handled it
        return;
    }

    // Our allocator doesn't recognize this pointer, use original
    match super::GAME_HEAP_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(self_ptr, edx, ptr) };
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

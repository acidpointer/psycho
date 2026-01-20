use std::sync::LazyLock;
use libc::c_void;
use libmimalloc::{heap::MiHeap, mi_free, mi_is_in_heap_region, mi_usable_size};

static GAME_HEAP: LazyLock<MiHeap> = LazyLock::new(MiHeap::new);


pub(super) unsafe extern "fastcall" fn game_heap_allocate(
    _self: *mut c_void,
    _edx: *mut c_void,
    size: usize,
) -> *mut c_void {
    //unsafe { mi_malloc(size) }
    GAME_HEAP.malloc(size)
}

pub(super) unsafe extern "fastcall" fn game_heap_reallocate(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    addr: *mut c_void,
    size: usize,
) -> *mut c_void {
    if addr.is_null() {
        //return unsafe { mi_malloc(size) };
        return GAME_HEAP.malloc(size)
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(addr) };
    
    if is_mimalloc {
        if size == 0 {
            unsafe { mi_free(addr) };            
            return std::ptr::null_mut();
        }
        
        //return unsafe { mi_realloc(addr, size) };
        return GAME_HEAP.realloc(addr, size);
    }

    match super::GAME_HEAP_REALLOCATE_HOOK_1.original() {
        Ok(orig_realloc) => unsafe { orig_realloc(self_ptr, edx, addr, size) },
        Err(err) => {
            log::error!(
                "[game_heap_reallocate] Failed to call original game_heap_reallocate for {:p}: {:?}",
                addr,
                err
            );
            std::ptr::null_mut()
        }
    }
}

pub(super) unsafe extern "fastcall" fn game_heap_msize(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    addr: *mut c_void,
) -> usize {
    if addr.is_null() {
        return 0;
    }

    if unsafe { mi_is_in_heap_region(addr) } {
        return unsafe { mi_usable_size(addr) };
    }

    match super::GAME_HEAP_MSIZE_HOOK.original() {
        Ok(orig_msize) => unsafe { orig_msize(self_ptr, edx, addr) },
        Err(err) => {
            log::error!(
                "[game_heap_msize] Failed to call original game_heap_msize for {:p}: {:?}",
                addr,
                err
            );
            0
        }
    }
}

pub(super) unsafe extern "fastcall" fn game_heap_free(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    addr: *mut c_void,
) {
    if addr.is_null() {
        return;
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(addr) };
    
    if is_mimalloc {
        unsafe { mi_free(addr) };
        return;
    }

    match super::GAME_HEAP_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(self_ptr, edx, addr) };
        }
        Err(err) => {
            log::error!(
                "[game_heap_free] Failed to call original game_heap_free for {:p}: {:?}",
                addr,
                err
            );
        }
    }
}
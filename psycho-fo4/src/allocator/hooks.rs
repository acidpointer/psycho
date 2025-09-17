#![allow(dead_code)]

use std::ffi::c_void;

use libpsycho::os::windows::constants::errcodes::*;

use libmimalloc::*;

pub unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    unsafe { mi_malloc(size) }    
}

pub unsafe extern "C" fn hook_malloc_aligned(size: usize, align: usize) -> *mut c_void {
    unsafe { mi_malloc_aligned(size, align) }
}

pub unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    unsafe { mi_calloc(count, size) }
}

pub unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { mi_realloc(raw_ptr, size) }
}

pub unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    unsafe { mi_recalloc(raw_ptr, count, size) }
}

pub unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    unsafe { mi_usable_size(raw_ptr) }
}

pub unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    unsafe { mi_free(raw_ptr); }
}

pub unsafe extern "C" fn hook_free_aligned(raw_ptr: *mut c_void, align: usize) {
    unsafe { mi_free_aligned(raw_ptr, align); }
}

pub unsafe extern "C" fn hook_memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    let a = unsafe { std::slice::from_raw_parts(s1 as *const u8, n) };
    let b = unsafe { std::slice::from_raw_parts(s2 as *const u8, n) };

    for i in 0..n {
        let diff = (a[i] as i32) - (b[i] as i32);
        if diff != 0 {
            return diff;
        }
    }
    0
}

pub unsafe extern "C" fn hook_memmove(
    dest: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    unsafe { std::ptr::copy(src as *const u8, dest as *mut u8, n) };
    dest
}

pub unsafe extern "C" fn hook_memcpy(
    dest: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    unsafe { std::ptr::copy_nonoverlapping(src as *const u8, dest as *mut u8, n) };
    dest
}

pub unsafe extern "C" fn hook_memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { std::ptr::write_bytes(dest as *mut u8, c as u8, n) };
    dest
}

pub unsafe extern "C" fn hook_memmove_s(
    dest: *mut c_void,
    dest_size: usize,
    src: *const c_void,
    n: usize,
) -> i32 {
    if dest.is_null() || src.is_null() {
        return EINVAL;
    }

    if n == 0 {
        return 0;
    }

    if n > dest_size {
        unsafe { std::ptr::write_bytes(dest as *mut u8, 0, dest_size) };
        return ERANGE;
    }

    unsafe { std::ptr::copy(src as *const u8, dest as *mut u8, n) };
    0
}

pub unsafe extern "C" fn hook_memcpy_s(
    dest: *mut c_void,
    dest_size: usize,
    src: *const c_void,
    n: usize,
) -> i32 {
    if dest.is_null() || src.is_null() {
        return EINVAL;
    }

    if n == 0 {
        return 0;
    }

    if n > dest_size {
        unsafe { std::ptr::write_bytes(dest as *mut u8, 0, dest_size) };
        return ERANGE;
    }

    // Check for overlap
    let dest_end = (dest as usize) + dest_size;
    let src_end = (src as usize) + n;

    if (dest as usize <= src as usize && (src as usize) < dest_end)
        || (src as usize <= dest as usize && (dest as usize) < src_end)
    {
        unsafe { std::ptr::write_bytes(dest as *mut u8, 0, dest_size) };
        return EINVAL;
    }

    unsafe { std::ptr::copy_nonoverlapping(src as *const u8, dest as *mut u8, n) };
    0
}

// === BGSScrapHeap ===

// BGSScrapHeap::dealloc
pub unsafe extern "C" fn hook_bgsscrapheap_dealloc(_this: *mut c_void, memory_ptr: *mut c_void) {
    unsafe { mi_free(memory_ptr); }
}

// BGSScrapHeap::alloc
pub unsafe extern "C" fn hook_bgsscrapheap_alloc(
    _this: *mut c_void,
    size: usize,
    alignment: u32,
) -> *mut c_void {
    if alignment != 0 {
        unsafe { mi_malloc_aligned(size, alignment as usize) }
    } else {
        unsafe { mi_malloc(size) }
    }
}

// === BGSMemoryManager ===

// BGSMemoryManager::alloc
pub unsafe extern "C" fn hook_bgsmemorymanager_alloc(
    _this: *mut c_void,
    size: usize,
    alignment: u32,
    _aligned: bool,
) -> *mut c_void {
    if alignment != 0 {
        unsafe { mi_malloc_aligned(size, alignment as usize) }
    } else {
        unsafe { mi_malloc(size) }
    }
}

// BGSMemoryManager::dealloc
pub unsafe extern "C" fn hook_bgsmemorymanager_dealloc(
    _this: *mut c_void,
    block: *mut c_void,
    _aligned: bool,
) {
    unsafe { mi_free(block); }
}

// BGSMemoryManager::realloc (NG ONLY)
pub unsafe extern "C" fn hook_bgsmemorymanager_realloc(
    _this: *mut c_void,
    old_block: *mut c_void,
    size: usize,
    alignment: u32,
    _aligned: bool,
) -> *mut c_void {
    if alignment != 0 {
        unsafe { mi_realloc_aligned(old_block, size, alignment as usize) }
    } else {
        unsafe { mi_realloc(old_block, size) }
    }
}

// BGSMemoryManager::msize
pub unsafe extern "C" fn hook_bgsmemorymanager_msize(
    _this: *mut c_void,
    memory_ptr: *mut c_void,
) -> usize {
    unsafe { mi_usable_size(memory_ptr) }
}

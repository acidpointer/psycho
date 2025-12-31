use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{mi_calloc, mi_free, mi_malloc, mi_realloc, mi_recalloc, mi_usable_size};
use libpsycho::os::windows::{hook::inline::inlinehook::InlineHookContainer, types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn}};

const CRT_MALLOC_ADDR_1: usize = 0x00ECD1C7;
const CRT_MALLOC_ADDR_2: usize = 0x00ED0CDF;

const CRT_CALLOC_ADDR_1: usize = 0x00EDDD7D;
const CRT_CALLOC_ADDR_2: usize = 0x00ED0D24;

const CRT_REALLOC_ADDR_1: usize = 0x00ECCF5D;
const CRT_REALLOC_ADDR_2: usize = 0x00ED0D70;

const CRT_RECALLOC_ADDR_1: usize = 0x00EE1700;
const CRT_RECALLOC_ADDR_2: usize = 0x00ED0DBE;

const CRT_MSIZE_ADDR: usize = 0x00ECD31F;

const CRT_FREE_ADDR: usize = 0x00ECD291;

pub static CRT_INLINE_MALLOC_HOOK_1: LazyLock<InlineHookContainer<MallocFn>> = LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_MALLOC_HOOK_2: LazyLock<InlineHookContainer<MallocFn>> = LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_CALLOC_HOOK_1: LazyLock<InlineHookContainer<CallocFn>> = LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_CALLOC_HOOK_2: LazyLock<InlineHookContainer<CallocFn>> = LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_REALLOC_HOOK_1: LazyLock<InlineHookContainer<ReallocFn>> = LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_REALLOC_HOOK_2: LazyLock<InlineHookContainer<ReallocFn>> = LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_RECALLOC_HOOK_1: LazyLock<InlineHookContainer<RecallocFn>> = LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_RECALLOC_HOOK_2: LazyLock<InlineHookContainer<RecallocFn>> = LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_MSIZE_HOOK: LazyLock<InlineHookContainer<MsizeFn>> = LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_FREE_HOOK: LazyLock<InlineHookContainer<FreeFn>> = LazyLock::new(InlineHookContainer::new);


pub unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    let result = unsafe { mi_malloc(size) };
    log::debug!("malloc({}) -> {:p}", size, result);
    result
}

pub unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let result = unsafe { mi_calloc(count, size) };
    log::debug!("calloc({}, {}) -> {:p}", count, size, result);
    result
}

pub unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    if raw_ptr.is_null() {
        // Realloc with null pointer is same as malloc
        let result = unsafe { mi_malloc(size) };
        log::debug!("realloc(null, {}) -> {:p}", size, result);
        return result;
    }

    // Check if this pointer belongs to mimalloc
    let ptr_size = unsafe { mi_usable_size(raw_ptr) };

    if ptr_size > 0 {
        // This is a mimalloc pointer, realloc with mimalloc
        let result = unsafe { mi_realloc(raw_ptr, size) };
        log::debug!("realloc({:p}, {}) -> {:p} [mimalloc]", raw_ptr, size, result);
        result
    } else {
        // This pointer doesn't belong to mimalloc
        // Allocate new block with mimalloc, copy data, free old block
        if let Ok(original_msize) = CRT_INLINE_MSIZE_HOOK.original() {
            let old_size = unsafe { original_msize(raw_ptr) };
            let new_ptr = unsafe { mi_malloc(size) };

            if !new_ptr.is_null() && old_size > 0 {
                // Copy min(old_size, new_size) bytes
                let copy_size = if old_size < size { old_size } else { size };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        raw_ptr as *const u8,
                        new_ptr as *mut u8,
                        copy_size,
                    )
                };

                // Free old block with original free
                if let Ok(original_free) = CRT_INLINE_FREE_HOOK.original() {
                    unsafe { original_free(raw_ptr) };
                }
            }

            log::debug!("realloc({:p}, {}) -> {:p} [mixed: old_size={}]", raw_ptr, size, new_ptr, old_size);
            new_ptr
        } else {
            log::warn!("realloc({:p}, {}) -> null [no fallback available]", raw_ptr, size);
            std::ptr::null_mut()
        }
    }
}

pub unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    if raw_ptr.is_null() {
        // Recalloc with null pointer is same as calloc
        let result = unsafe { mi_calloc(count, size) };
        log::debug!("_recalloc(null, {}, {}) -> {:p}", count, size, result);
        return result;
    }

    // Check if this pointer belongs to mimalloc
    let ptr_size = unsafe { mi_usable_size(raw_ptr) };

    if ptr_size > 0 {
        // This is a mimalloc pointer, recalloc with mimalloc
        let result = unsafe { mi_recalloc(raw_ptr, count, size) };
        log::debug!("_recalloc({:p}, {}, {}) -> {:p} [mimalloc]", raw_ptr, count, size, result);
        result
    } else {
        // This pointer doesn't belong to mimalloc
        // Allocate new block with mimalloc (zeroed), copy data, free old block
        let new_size = count * size;
        let new_ptr = unsafe { mi_calloc(count, size) };

        if !new_ptr.is_null() {
            if let Ok(original_msize) = CRT_INLINE_MSIZE_HOOK.original() {
                let old_size = unsafe { original_msize(raw_ptr) };
                if old_size > 0 {
                    // Copy min(old_size, new_size) bytes
                    let copy_size = if old_size < new_size {
                        old_size
                    } else {
                        new_size
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            raw_ptr as *const u8,
                            new_ptr as *mut u8,
                            copy_size,
                        )
                    };
                }
                log::debug!("_recalloc({:p}, {}, {}) -> {:p} [mixed: old_size={}]", raw_ptr, count, size, new_ptr, old_size);
            } else {
                log::debug!("_recalloc({:p}, {}, {}) -> {:p} [mixed: old_size unknown]", raw_ptr, count, size, new_ptr);
            }

            // Free old block with original free
            if let Ok(original_free) = CRT_INLINE_FREE_HOOK.original() {
                unsafe { original_free(raw_ptr) };
            }
        } else {
            log::warn!("_recalloc({:p}, {}, {}) -> null [allocation failed]", raw_ptr, count, size);
        }

        new_ptr
    }
}

pub unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    if raw_ptr.is_null() {
        //log::debug!("_msize(null) -> 0");
        return 0;
    }

    // Check if this pointer belongs to mimalloc
    let size = unsafe { mi_usable_size(raw_ptr) };

    if size > 0 {
        // This is a mimalloc pointer
        log::debug!("_msize({:p}) -> {} [mimalloc]", raw_ptr, size);
        size
    } else {
        // This pointer doesn't belong to mimalloc, use original _msize
        if let Ok(original_msize) = CRT_INLINE_MSIZE_HOOK.original() {
            let result = unsafe { original_msize(raw_ptr) };
            log::debug!("_msize({:p}) -> {} [original]", raw_ptr, result);
            result
        } else {
            log::warn!("_msize({:p}) -> 0 [no fallback available]", raw_ptr);
            0
        }
    }
}

pub unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    if raw_ptr.is_null() {
        log::debug!("free(null) [ignored]");
        return;
    }

    // Check if this pointer belongs to mimalloc by checking its usable size
    // If mi_usable_size returns 0, the pointer doesn't belong to mimalloc
    let size = unsafe { mi_usable_size(raw_ptr) };

    if size > 0 {
        // This is a mimalloc pointer, free it with mimalloc
        log::debug!("free({:p}) [mimalloc, size={}]", raw_ptr, size);
        unsafe { mi_free(raw_ptr) }
    } else {
        // This pointer doesn't belong to mimalloc, use original free
        if let Ok(original_free) = CRT_INLINE_FREE_HOOK.original() {
            log::debug!("free({:p}) [original]", raw_ptr);
            unsafe { original_free(raw_ptr) }
        } else {
            log::warn!(
                "free({:p}) [no fallback available, potential leak]",
                raw_ptr
            );
        }
    }
}

pub fn install_crt_inline_hooks() -> anyhow::Result<()> {
    unsafe {
        // Inline hooks
        CRT_INLINE_MALLOC_HOOK_1.init("malloc1", CRT_MALLOC_ADDR_1 as *mut c_void, hook_malloc)?;
        CRT_INLINE_MALLOC_HOOK_2.init("malloc2", CRT_MALLOC_ADDR_2 as *mut c_void, hook_malloc)?;

        CRT_INLINE_CALLOC_HOOK_1.init("calloc1", CRT_CALLOC_ADDR_1 as *mut c_void, hook_calloc)?;
        CRT_INLINE_CALLOC_HOOK_2.init("calloc2", CRT_CALLOC_ADDR_2 as *mut c_void, hook_calloc)?;

        CRT_INLINE_REALLOC_HOOK_1.init("realloc1", CRT_REALLOC_ADDR_1 as *mut c_void, hook_realloc)?;
        CRT_INLINE_REALLOC_HOOK_2.init("realloc2", CRT_REALLOC_ADDR_2 as *mut c_void, hook_realloc)?;

        CRT_INLINE_RECALLOC_HOOK_1.init("recalloc1", CRT_RECALLOC_ADDR_1 as *mut c_void, hook_recalloc)?;
        CRT_INLINE_RECALLOC_HOOK_2.init("recalloc2", CRT_RECALLOC_ADDR_2 as *mut c_void, hook_recalloc)?;

        CRT_INLINE_FREE_HOOK.init("free", CRT_FREE_ADDR as *mut c_void, hook_free)?;

        CRT_INLINE_MSIZE_HOOK.init("msize", CRT_MSIZE_ADDR as *mut c_void, hook_msize)?;        
    }

    // Inline hooks
    
    CRT_INLINE_MALLOC_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked malloc_1");

    CRT_INLINE_MALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked malloc_2");
    
    CRT_INLINE_CALLOC_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked calloc_1");

    CRT_INLINE_CALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked calloc_2");

    CRT_INLINE_REALLOC_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked realloc_1");

    CRT_INLINE_REALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked realloc_2");

    CRT_INLINE_RECALLOC_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked recalloc_1");

    CRT_INLINE_RECALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked recalloc_2");

    CRT_INLINE_FREE_HOOK.enable()?;
    log::info!("[INLINE] Hooked free");

    CRT_INLINE_MSIZE_HOOK.enable()?;
    log::info!("[INLINE] Hooked msize");

    log::info!("[INLINE] All CRT hooks installed!");

    Ok(())
}

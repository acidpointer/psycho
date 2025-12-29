use std::sync::LazyLock;

use libpsycho::os::windows::{
    hook::iat::iathook::IatHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
    winapi::get_module_handle_a,
};

use libc::c_void;
use libmimalloc::*;

// Hook implementations - redirect to mimalloc
pub unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    let result = unsafe { mi_malloc(size) };
    //log::debug!("malloc({}) -> {:p}", size, result);
    result
}

pub unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let result = unsafe { mi_calloc(count, size) };
    //log::debug!("calloc({}, {}) -> {:p}", count, size, result);
    result
}

pub unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    if raw_ptr.is_null() {
        // Realloc with null pointer is same as malloc
        let result = unsafe { mi_malloc(size) };
        //log::debug!("realloc(null, {}) -> {:p}", size, result);
        return result;
    }

    // Check if this pointer belongs to mimalloc
    let ptr_size = unsafe { mi_usable_size(raw_ptr) };

    if ptr_size > 0 {
        // This is a mimalloc pointer, realloc with mimalloc
        let result = unsafe { mi_realloc(raw_ptr, size) };
        //log::debug!("realloc({:p}, {}) -> {:p} [mimalloc]", raw_ptr, size, result);
        result
    } else {
        // This pointer doesn't belong to mimalloc
        // Allocate new block with mimalloc, copy data, free old block
        if let Ok(original_msize) = MSIZE_HOOK.original() {
            let old_size = unsafe { original_msize(raw_ptr) };
            let new_ptr = unsafe { mi_malloc(size) };

            if !new_ptr.is_null() && old_size > 0 {
                // Copy min(old_size, new_size) bytes
                let copy_size = if old_size < size { old_size } else { size };
                unsafe { std::ptr::copy_nonoverlapping(raw_ptr as *const u8, new_ptr as *mut u8, copy_size) };

                // Free old block with original free
                if let Ok(original_free) = FREE_HOOK.original() {
                    unsafe { original_free(raw_ptr) };
                }
            }

            //log::debug!("realloc({:p}, {}) -> {:p} [mixed: old_size={}]", raw_ptr, size, new_ptr, old_size);
            new_ptr
        } else {
            // Fallback: try with original realloc
            if let Ok(original_realloc) = REALLOC_HOOK.original() {
                let result = unsafe { original_realloc(raw_ptr, size) };
                //log::debug!("realloc({:p}, {}) -> {:p} [fallback]", raw_ptr, size, result);
                result
            } else {
                //log::warn!("realloc({:p}, {}) -> null [no fallback available]", raw_ptr, size);
                std::ptr::null_mut()
            }
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
        //log::debug!("_recalloc(null, {}, {}) -> {:p}", count, size, result);
        return result;
    }

    // Check if this pointer belongs to mimalloc
    let ptr_size = unsafe { mi_usable_size(raw_ptr) };

    if ptr_size > 0 {
        // This is a mimalloc pointer, recalloc with mimalloc
        let result = unsafe { mi_recalloc(raw_ptr, count, size) };
        //log::debug!("_recalloc({:p}, {}, {}) -> {:p} [mimalloc]", raw_ptr, count, size, result);
        result
    } else {
        // This pointer doesn't belong to mimalloc
        // Allocate new block with mimalloc (zeroed), copy data, free old block
        let new_size = count * size;
        let new_ptr = unsafe { mi_calloc(count, size) };

        if !new_ptr.is_null() {
            if let Ok(original_msize) = MSIZE_HOOK.original() {
                let old_size = unsafe { original_msize(raw_ptr) };
                if old_size > 0 {
                    // Copy min(old_size, new_size) bytes
                    let copy_size = if old_size < new_size { old_size } else { new_size };
                    unsafe { std::ptr::copy_nonoverlapping(raw_ptr as *const u8, new_ptr as *mut u8, copy_size) };
                }
                //log::debug!("_recalloc({:p}, {}, {}) -> {:p} [mixed: old_size={}]", raw_ptr, count, size, new_ptr, old_size);
            } else {
                //log::debug!("_recalloc({:p}, {}, {}) -> {:p} [mixed: old_size unknown]", raw_ptr, count, size, new_ptr);
            }

            // Free old block with original free
            if let Ok(original_free) = FREE_HOOK.original() {
                unsafe { original_free(raw_ptr) };
            }
        } else {
            //log::warn!("_recalloc({:p}, {}, {}) -> null [allocation failed]", raw_ptr, count, size);
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
        //log::debug!("_msize({:p}) -> {} [mimalloc]", raw_ptr, size);
        size
    } else {
        // This pointer doesn't belong to mimalloc, use original _msize
        if let Ok(original_msize) = MSIZE_HOOK.original() {
            let result = unsafe { original_msize(raw_ptr) };
            //log::debug!("_msize({:p}) -> {} [original]", raw_ptr, result);
            result
        } else {
            //log::warn!("_msize({:p}) -> 0 [no fallback available]", raw_ptr);
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
        //log::debug!("free({:p}) [mimalloc, size={}]", raw_ptr, size);
        unsafe { mi_free(raw_ptr) }
    } else {
        // This pointer doesn't belong to mimalloc, use original free
        if let Ok(original_free) = FREE_HOOK.original() {
            //log::debug!("free({:p}) [original]", raw_ptr);
            unsafe { original_free(raw_ptr) }
        } else {
            log::warn!("free({:p}) [no fallback available, potential leak]", raw_ptr);
        }
    }
}

// Global hook containers
static MALLOC_HOOK: LazyLock<IatHookContainer<MallocFn>> = LazyLock::new(IatHookContainer::new);
static CALLOC_HOOK: LazyLock<IatHookContainer<CallocFn>> = LazyLock::new(IatHookContainer::new);
static REALLOC_HOOK: LazyLock<IatHookContainer<ReallocFn>> = LazyLock::new(IatHookContainer::new);
static RECALLOC_HOOK: LazyLock<IatHookContainer<RecallocFn>> = LazyLock::new(IatHookContainer::new);
static MSIZE_HOOK: LazyLock<IatHookContainer<MsizeFn>> = LazyLock::new(IatHookContainer::new);
static FREE_HOOK: LazyLock<IatHookContainer<FreeFn>> = LazyLock::new(IatHookContainer::new);

/// Install memory allocation hooks targeting NVSE runtime
pub fn install_memory_hooks() -> anyhow::Result<()> {
    let module_base = get_module_handle_a(None)?.as_ptr();

    // Hook UCRT functions from api-ms-win-crt-heap-l1-1-0.dll

    // Install malloc hook
    (unsafe { MALLOC_HOOK.init("malloc", module_base, None, "malloc", hook_malloc) })?;
    MALLOC_HOOK.enable()?;
    log::info!("Hooked malloc");

    // Install calloc hook
    (unsafe { CALLOC_HOOK.init("calloc", module_base, None, "calloc", hook_calloc) })?;
    CALLOC_HOOK.enable()?;
    log::info!("Hooked calloc");

    // Install realloc hook
    (unsafe { REALLOC_HOOK.init("realloc", module_base, None, "realloc", hook_realloc) })?;
    REALLOC_HOOK.enable()?;
    log::info!("Hooked realloc");

    // Install recalloc hook
    (unsafe { RECALLOC_HOOK.init("_recalloc", module_base, None, "_recalloc", hook_recalloc) })?;
    RECALLOC_HOOK.enable()?;
    log::info!("Hooked _recalloc");

    // Install free hook
    (unsafe { FREE_HOOK.init("free", module_base, None, "free", hook_free) })?;
    FREE_HOOK.enable()?;
    log::info!("Hooked free");

    // Install msize hook (needed for realloc/recalloc to work with mixed allocators)
    (unsafe { MSIZE_HOOK.init("_msize", module_base, None, "_msize", hook_msize) })?;
    MSIZE_HOOK.enable()?;
    log::info!("Hooked _msize");

    log::info!("Successfully installed all memory allocation hooks");

    Ok(())
}

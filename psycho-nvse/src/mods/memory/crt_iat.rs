use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc, mi_usable_size,
};
use libpsycho::os::windows::{
    hook::iat::iathook::IatHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
    winapi::get_module_handle_a,
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

// Hook implementations - redirect to mimalloc
pub unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    unsafe { mi_malloc(size) }
}

pub unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    unsafe { mi_calloc(count, size) }
}

pub unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    if raw_ptr.is_null() {
        // Realloc with null pointer is same as malloc
        return unsafe { mi_malloc(size) };
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        return unsafe { mi_realloc(raw_ptr, size) };
    }

    // Fallback: try with original realloc
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
        // Recalloc with null pointer is same as calloc
        return unsafe { mi_calloc(count, size) };
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        return unsafe { mi_recalloc(raw_ptr, count, size) };
    }

    // Fallback: try with original realloc
    if let Ok(original_realloc) = RECALLOC_IAT_HOOK.original() {
        unsafe { original_realloc(raw_ptr, count, size) }
    } else {
        std::ptr::null_mut()
    }
}

pub unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    if raw_ptr.is_null() {
        return 0;
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        let size = unsafe { mi_usable_size(raw_ptr) };

        return size;
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

    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        unsafe { mi_free(raw_ptr) }

        return;
    }

    if let Ok(original_free) = FREE_IAT_HOOK.original() {
        unsafe { original_free(raw_ptr) }
    } else {
        log::warn!(
            "free({:p}) [no fallback available, potential leak]",
            raw_ptr
        );
    }
}

/// Install memory allocation hooks targeting NVSE runtime
pub fn install_crt_hooks() -> anyhow::Result<()> {
    super::configure_mimalloc();

    let module_base = get_module_handle_a(None)?.as_ptr();

    log::info!("Initializing IAT CRT hooks...");

    unsafe {
        MALLOC_IAT_HOOK.init("malloc", module_base, None, "malloc", hook_malloc)?;
        CALLOC_IAT_HOOK.init("calloc", module_base, None, "calloc", hook_calloc)?;
        REALLOC_IAT_HOOK.init("realloc", module_base, None, "realloc", hook_realloc)?;
        RECALLOC_IAT_HOOK.init("_recalloc", module_base, None, "_recalloc", hook_recalloc)?;
        FREE_IAT_HOOK.init("free", module_base, None, "free", hook_free)?;
        MSIZE_IAT_HOOK.init("_msize", module_base, None, "_msize", hook_msize)?;
    }

    log::info!("[IAT] CRT hooks initialized!");

    MALLOC_IAT_HOOK.enable()?;
    log::info!("[IAT] Hooked malloc");

    CALLOC_IAT_HOOK.enable()?;
    log::info!("[IAT] Hooked calloc");

    REALLOC_IAT_HOOK.enable()?;
    log::info!("[IAT] Hooked realloc");

    RECALLOC_IAT_HOOK.enable()?;
    log::info!("[IAT] Hooked _recalloc");

    FREE_IAT_HOOK.enable()?;
    log::info!("[IAT] Hooked free");

    log::info!("[IAT] CRT hooks enabled!");

    Ok(())
}

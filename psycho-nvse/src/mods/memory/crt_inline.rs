use std::{ptr::null_mut, sync::LazyLock};

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc, mi_usable_size,
};
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
};

// Source: https://github.com/iranrmrf/Heap-Replacer/blob/master/heap_replacer/main/heap_replacer.h

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

pub static CRT_INLINE_MALLOC_HOOK_1: LazyLock<InlineHookContainer<MallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_MALLOC_HOOK_2: LazyLock<InlineHookContainer<MallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_CALLOC_HOOK_1: LazyLock<InlineHookContainer<CallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_CALLOC_HOOK_2: LazyLock<InlineHookContainer<CallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_REALLOC_HOOK_1: LazyLock<InlineHookContainer<ReallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_REALLOC_HOOK_2: LazyLock<InlineHookContainer<ReallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_RECALLOC_HOOK_1: LazyLock<InlineHookContainer<RecallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_RECALLOC_HOOK_2: LazyLock<InlineHookContainer<RecallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_MSIZE_HOOK: LazyLock<InlineHookContainer<MsizeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_FREE_HOOK: LazyLock<InlineHookContainer<FreeFn>> =
    LazyLock::new(InlineHookContainer::new);

unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    let result = unsafe { mi_malloc(size) };
    log::trace!("malloc({}) -> {:p}", size, result);
    result
}

unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let result = unsafe { mi_calloc(count, size) };
    log::trace!("calloc({}, {}) -> {:p}", count, size, result);
    result
}

unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        let result = unsafe { mi_realloc(raw_ptr, size) };
        log::trace!(
            "realloc({:p}, {}) -> {:p} [mimalloc]",
            raw_ptr,
            size,
            result
        );
        return result;
    }

    match CRT_INLINE_REALLOC_HOOK_1.original() {
        Ok(orig_realloc) => {
            unsafe { orig_realloc(raw_ptr, size) }
        }

        Err(err) => {
            log::error!("Failed to call original realloc: {:?}", err);

            null_mut()
        }
    }
}

unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    unsafe { mi_recalloc(raw_ptr, count, size) }
}

unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        return unsafe { mi_usable_size(raw_ptr) };
    }

    match CRT_INLINE_MSIZE_HOOK.original() {
        Ok(orig_msize) => {
            let orig_size = unsafe { orig_msize(raw_ptr) };

            if orig_size == usize::MAX {
                log::warn!("hook_msize: pointer is unknown {:p}!", raw_ptr);
                return 0;
            }
            orig_size
        }
        Err(err) => {
            log::error!("Failed to call original msize: {:?}", err);
            0
        }
    }
}

unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    let is_mimalloc = unsafe { mi_is_in_heap_region(raw_ptr) };

    if is_mimalloc {
        return unsafe { mi_free(raw_ptr) };
    }

    match CRT_INLINE_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(raw_ptr) };
        }

        Err(err) => {
            log::error!(
                "Failed to call original free for pointer={:p}; Error: {:?}",
                raw_ptr,
                err
            );
        }
    }
}

pub fn install_crt_inline_hooks() -> anyhow::Result<()> {
    super::configure_mimalloc();

    // Inline hooks
    CRT_INLINE_MALLOC_HOOK_1.init("malloc1", CRT_MALLOC_ADDR_1 as *mut c_void, hook_malloc)?;
    CRT_INLINE_MALLOC_HOOK_2.init("malloc2", CRT_MALLOC_ADDR_2 as *mut c_void, hook_malloc)?;

    CRT_INLINE_CALLOC_HOOK_1.init("calloc1", CRT_CALLOC_ADDR_1 as *mut c_void, hook_calloc)?;
    CRT_INLINE_CALLOC_HOOK_2.init("calloc2", CRT_CALLOC_ADDR_2 as *mut c_void, hook_calloc)?;

    CRT_INLINE_REALLOC_HOOK_1.init("realloc1", CRT_REALLOC_ADDR_1 as *mut c_void, hook_realloc)?;
    CRT_INLINE_REALLOC_HOOK_2.init("realloc2", CRT_REALLOC_ADDR_2 as *mut c_void, hook_realloc)?;

    CRT_INLINE_RECALLOC_HOOK_1.init(
        "recalloc1",
        CRT_RECALLOC_ADDR_1 as *mut c_void,
        hook_recalloc,
    )?;
    CRT_INLINE_RECALLOC_HOOK_2.init(
        "recalloc2",
        CRT_RECALLOC_ADDR_2 as *mut c_void,
        hook_recalloc,
    )?;

    CRT_INLINE_FREE_HOOK.init("free", CRT_FREE_ADDR as *mut c_void, hook_free)?;

    CRT_INLINE_MSIZE_HOOK.init("msize", CRT_MSIZE_ADDR as *mut c_void, hook_msize)?;

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

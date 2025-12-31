#![allow(clippy::let_and_return)]

use libc::c_void;
use libmimalloc::{mi_free, mi_malloc, mi_realloc, mi_usable_size, mi_zalloc};
use std::sync::LazyLock;
use windows::Win32::System::Memory::HEAP_ZERO_MEMORY;

use libpsycho::os::windows::{
    hook::iat::iathook::IatHookContainer,
    types::{HeapAllocFn, HeapFreeFn, HeapReAllocFn, VirtualAllocFn},
    winapi::get_module_handle_a,
};

// Windows Heap API hook containers
pub static HEAP_ALLOC_HOOK: LazyLock<IatHookContainer<HeapAllocFn>> =
    LazyLock::new(IatHookContainer::new);
pub static HEAP_REALLOC_HOOK: LazyLock<IatHookContainer<HeapReAllocFn>> =
    LazyLock::new(IatHookContainer::new);
pub static HEAP_FREE_HOOK: LazyLock<IatHookContainer<HeapFreeFn>> =
    LazyLock::new(IatHookContainer::new);

// Windows VirtualAlloc hook container
pub static VIRTUAL_ALLOC_HOOK: LazyLock<IatHookContainer<VirtualAllocFn>> =
    LazyLock::new(IatHookContainer::new);

// Windows Heap API hooks
pub unsafe extern "system" fn hook_heap_alloc(
    h_heap: *mut c_void,
    dw_flags: u32,
    dw_bytes: usize,
) -> *mut c_void {
    if dw_bytes == 0 {
        return std::ptr::null_mut();
    }

    // Allocate with mimalloc
    let result = if dw_flags & HEAP_ZERO_MEMORY.0 != 0 {
        // Zero memory requested
        unsafe { mi_zalloc(dw_bytes) }
    } else {
        unsafe { mi_malloc(dw_bytes) }
    };

    //log::debug!("HeapAlloc({:p}, {:#x}, {}) -> {:p}", h_heap, dw_flags, dw_bytes, result);
    result
}

pub unsafe extern "system" fn hook_heap_realloc(
    h_heap: *mut c_void,
    dw_flags: u32,
    lp_mem: *mut c_void,
    dw_bytes: usize,
) -> *mut c_void {
    if lp_mem.is_null() {
        // Realloc with null pointer is same as HeapAlloc
        return unsafe { hook_heap_alloc(h_heap, dw_flags, dw_bytes) };
    }

    if dw_bytes == 0 {
        // Realloc with zero size is same as HeapFree
        unsafe { hook_heap_free(h_heap, dw_flags, lp_mem) };
        return std::ptr::null_mut();
    }

    // Check if this pointer belongs to mimalloc
    let ptr_size = unsafe { mi_usable_size(lp_mem) };

    if ptr_size > 0 {
        // This is a mimalloc pointer, realloc with mimalloc
        let result = unsafe { mi_realloc(lp_mem, dw_bytes) };

        // Handle HEAP_ZERO_MEMORY flag for expanded memory
        if !result.is_null() && dw_flags & HEAP_ZERO_MEMORY.0 != 0 && dw_bytes > ptr_size {
            // Zero the expanded portion
            let expanded_start = (result as usize + ptr_size) as *mut u8;
            let expanded_size = dw_bytes - ptr_size;
            unsafe { std::ptr::write_bytes(expanded_start, 0, expanded_size) };
        }

        //log::debug!("HeapReAlloc({:p}, {:#x}, {:p}, {}) -> {:p} [mimalloc]", h_heap, dw_flags, lp_mem, dw_bytes, result);
        result
    } else {
        // This pointer doesn't belong to mimalloc - just use mimalloc anyway
        // We can't safely call the original without risking recursion
        let result = unsafe { mi_realloc(lp_mem, dw_bytes) };
        //log::debug!("HeapReAlloc({:p}, {:#x}, {:p}, {}) -> {:p} [mimalloc fallback]", h_heap, dw_flags, lp_mem, dw_bytes, result);
        result
    }
}

pub unsafe extern "system" fn hook_heap_free(
    h_heap: *mut c_void,
    dw_flags: u32,
    lp_mem: *mut c_void,
) -> i32 {
    if lp_mem.is_null() {
        //log::debug!("HeapFree({:p}, {:#x}, null) [ignored]", h_heap, dw_flags);
        return 1;
    }

    // Always use mimalloc's free - it will handle both mimalloc and non-mimalloc pointers safely
    // mimalloc's mi_free can detect if a pointer belongs to it
    unsafe { mi_free(lp_mem) };
    //log::debug!("HeapFree({:p}, {:#x}, {:p}) [mimalloc]", h_heap, dw_flags, lp_mem);
    1
}

// Windows VirtualAlloc hook - DISABLED to prevent recursion
// VirtualAlloc is used internally by the Windows loader and system,
// and hooking it causes deadlocks. This function should never be called
// because the hook should not be installed.
pub unsafe extern "system" fn hook_virtual_alloc(
    _lp_address: *mut c_void,
    _dw_size: usize,
    _fl_allocation_type: u32,
    _fl_protect: u32,
) -> *mut c_void {
    // This should never be called
    log::error!("hook_virtual_alloc called - this hook should not be enabled!");
    std::ptr::null_mut()
}

pub fn install_heap_hooks() -> anyhow::Result<()> {
    let module_base = get_module_handle_a(None)?.as_ptr();
    
    unsafe {
        VIRTUAL_ALLOC_HOOK.init("VirtualAlloc", module_base, None, "VirtualAlloc", hook_virtual_alloc)?;
        HEAP_FREE_HOOK.init("HeapFree", module_base, None, "HeapFree", hook_heap_free)?;
        HEAP_ALLOC_HOOK.init("HeapAlloc", module_base, None, "HeapAlloc", hook_heap_alloc)?;
        HEAP_REALLOC_HOOK.init("HeapReAloc", module_base, None, "HeapReAlloc", hook_heap_realloc)?;
    }

    VIRTUAL_ALLOC_HOOK.enable()?;
    log::info!("Hooked VirtualAlloc");
    
    HEAP_FREE_HOOK.enable()?;
    log::info!("Hooked HeapFree");

    HEAP_ALLOC_HOOK.enable()?;
    log::info!("Hooked HeapAlloc");

    HEAP_REALLOC_HOOK.enable()?;
    log::info!("Hooked HeapReAlloc");

    Ok(())
}

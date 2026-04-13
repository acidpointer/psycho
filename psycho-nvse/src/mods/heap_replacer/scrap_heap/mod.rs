//! Scrap heap (SBM2) replacement module.
//!
//! Replaces the game's ScrapHeap allocator with a per-identity bump-pointer
//! allocator backed by mimalloc. Each game thread gets its own Heap with
//! lock-free fast-path allocation.

mod heap;
mod region;
pub mod runtime;

use std::cell::UnsafeCell;
use std::ptr::null_mut;
use std::sync::LazyLock;

use libc::c_void;
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

use runtime::Runtime;

// ---- Types ----

pub type SheapInitFixFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapInitVarFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize);
pub type SheapAllocFn =
    unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
pub type SheapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
pub type SheapPurgeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapGetThreadLocalFn = unsafe extern "C" fn() -> *mut c_void;

// ---- Addresses ----

pub const SHEAP_INIT_FIX_ADDR: usize = 0x00AA53F0;
pub const SHEAP_INIT_VAR_ADDR: usize = 0x00AA5410;
pub const SHEAP_ALLOC_ADDR: usize = 0x00AA54A0;
pub const SHEAP_FREE_ADDR: usize = 0x00AA5610;
pub const SHEAP_PURGE_ADDR: usize = 0x00AA5460;
pub const SHEAP_GET_THREAD_LOCAL_ADDR: usize = 0x00AA42E0;

// ---- Hook statics ----

pub static INIT_FIX_HOOK: LazyLock<InlineHookContainer<SheapInitFixFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static INIT_VAR_HOOK: LazyLock<InlineHookContainer<SheapInitVarFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static ALLOC_HOOK: LazyLock<InlineHookContainer<SheapAllocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static FREE_HOOK: LazyLock<InlineHookContainer<SheapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PURGE_HOOK: LazyLock<InlineHookContainer<SheapPurgeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GET_THREAD_LOCAL_HOOK: LazyLock<InlineHookContainer<SheapGetThreadLocalFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Hook implementations ----

/// Game's scrap heap structure. Must match the game's struct layout exactly.
#[repr(C)]
pub struct SheapStruct {
    blocks: *mut *mut c_void,
    cur: *mut c_void,
    last: *mut c_void,
}

impl SheapStruct {
    pub const fn new_nulled() -> Self {
        Self {
            blocks: null_mut(),
            cur: null_mut(),
            last: null_mut(),
        }
    }
}

#[allow(clippy::let_and_return)]
pub unsafe extern "C" fn hook_get_thread_local() -> *mut c_void {
    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct::new_nulled()) };
    }
    let sheap_ptr = DUMMY_SHEAP.with(|d| d.get() as *mut c_void);
    sheap_ptr
}

pub unsafe extern "fastcall" fn hook_init_fix(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }
    Runtime::get_instance().purge(sheap_ptr);
}

pub unsafe extern "fastcall" fn hook_init_var(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_var: NULL heap pointer");
        return;
    }
    Runtime::get_instance().purge(sheap_ptr);
}

/// Maximum OOM retry attempts before giving up.
const SHEAP_OOM_RETRIES: u32 = 3;

pub unsafe extern "fastcall" fn hook_alloc(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    if sheap_ptr.is_null() {
        log::error!("sheap_alloc: sheap_ptr is NULL!");
        return null_mut();
    }
    let actual_align = align.max(16);
    let rt = Runtime::get_instance();

    let ptr = rt.alloc(sheap_ptr, size, actual_align);
    if !ptr.is_null() {
        return ptr;
    }

    unsafe { alloc_oom_recovery(rt, sheap_ptr, size, actual_align) }
}

#[cold]
unsafe fn alloc_oom_recovery(
    rt: &Runtime,
    sheap_ptr: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    use super::gheap::{heap_manager::HeapManager, slab};

    // First: signal main thread to run cleanup (same as main OOM path)
    HeapManager::get().signal_emergency_drain();

    // Decommit slab dirty pages + collect mimalloc to free memory
    unsafe { slab::decommit_sweep() };
    unsafe { libmimalloc::mi_collect(false) };

    for attempt in 1..=SHEAP_OOM_RETRIES {
        log::warn!(
            "[SBM] OOM on sheap_alloc(size={}, align={}), attempt {}/{}",
            size, align, attempt, SHEAP_OOM_RETRIES
        );

        // Signal main thread cleanup + mi_collect to reclaim empty pages
        HeapManager::get().signal_emergency_drain();
        unsafe { libmimalloc::mi_collect(false) };

        let ptr = rt.alloc(sheap_ptr, size, align);
        if !ptr.is_null() {
            log::info!("[SBM] OOM recovered on attempt {}", attempt);
            return ptr;
        }

        // If pool was drained and still failing, wait briefly for main thread cleanup
        if attempt > 1 {
            libpsycho::os::windows::winapi::sleep(1);
        }
    }

    log::error!(
        "[SBM] CRITICAL: sheap_alloc failed after {} retries (size={}, align={})",
        SHEAP_OOM_RETRIES, size, align
    );
    null_mut()
}

pub unsafe extern "fastcall" fn hook_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    Runtime::get_instance().free(sheap_ptr, ptr);
}

pub unsafe extern "fastcall" fn hook_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    Runtime::get_instance().purge(sheap_ptr);
}

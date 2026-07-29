//! Fallout: New Vegas ScrapHeap replacement and hook ABI.
//!
//! The native entrypoints are replaced with a per-identity bump allocator.
//! The hook treats the engine's ScrapHeap pointer as an opaque identity; Psycho
//! owns all allocation metadata and never reads or writes the native
//! ScrapHeap fields after hook activation. Thread-local identities use a
//! dummy layout-compatible [`SheapStruct`] so engine callers still receive a
//! stable non-null pointer.
//!
//! Standard regions come from a protected reusable reserve. Oversized or
//! overflow regions use exact dynamic mappings. Region lifetime, FIFO reuse,
//! and `PAGE_NOACCESS` idle protection are implemented below the ABI layer;
//! see [`runtime`] for allocation order and recovery, and `reserve` for the
//! slot-state contract.
//!
//! Startup is transactional: hook instruction boundaries are prepared first,
//! [`initialize_runtime`] proves the minimum reserve, and only then does the
//! installer publish all ScrapHeap jumps. A failed reserve therefore leaves
//! the vanilla allocator active.
//!
//! The allocation hook performs no engine cleanup. On complete backing failure
//! it makes three bounded retries, each preceded only by reclaiming queued
//! Psycho-owned heaps that are still empty. Returning null after those retries
//! preserves the native allocation ABI; fabricating success would create
//! unowned memory and corrupt later frees.

mod heap;
mod region;
mod reserve;
pub mod runtime;

use std::cell::UnsafeCell;
use std::ptr::null_mut;
use std::sync::LazyLock;

use libc::c_void;
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;
use libpsycho::os::windows::hook::replacement::ReplacementHookContainer;

use runtime::Runtime;
pub use runtime::ScrapSnapshot;

// ---- Types ----

/// ABI of the native fixed-size ScrapHeap initializer.
pub type SheapInitFixFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
/// ABI of the native variable-size ScrapHeap initializer.
pub type SheapInitVarFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize);
/// ABI of the native aligned ScrapHeap allocation entrypoint.
pub type SheapAllocFn =
    unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
/// ABI of the native ScrapHeap free entrypoint.
pub type SheapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
/// ABI of the native ScrapHeap purge entrypoint.
pub type SheapPurgeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
/// ABI of the native thread-local ScrapHeap accessor.
pub type SheapGetThreadLocalFn = unsafe extern "C" fn() -> *mut c_void;

// ---- Addresses ----

/// Address of the supported executable's fixed-size initializer.
pub const SHEAP_INIT_FIX_ADDR: usize = 0x00AA53F0;
/// Address of the supported executable's variable-size initializer.
pub const SHEAP_INIT_VAR_ADDR: usize = 0x00AA5410;
/// Address of the supported executable's aligned allocation entrypoint.
pub const SHEAP_ALLOC_ADDR: usize = 0x00AA54A0;
/// Address of the supported executable's free entrypoint.
pub const SHEAP_FREE_ADDR: usize = 0x00AA5610;
/// Address of the supported executable's explicit purge entrypoint.
pub const SHEAP_PURGE_ADDR: usize = 0x00AA5460;
/// Address of the supported executable's thread-local accessor.
pub const SHEAP_GET_THREAD_LOCAL_ADDR: usize = 0x00AA42E0;

// ---- Hook statics ----

/// Prepared inline hook for fixed-size initialization.
pub static INIT_FIX_HOOK: LazyLock<InlineHookContainer<SheapInitFixFn>> =
    LazyLock::new(InlineHookContainer::new);
/// Prepared inline hook for variable-size initialization.
pub static INIT_VAR_HOOK: LazyLock<InlineHookContainer<SheapInitVarFn>> =
    LazyLock::new(InlineHookContainer::new);
/// Prepared inline hook for allocation.
pub static ALLOC_HOOK: LazyLock<InlineHookContainer<SheapAllocFn>> =
    LazyLock::new(InlineHookContainer::new);
/// Prepared inline hook for free.
pub static FREE_HOOK: LazyLock<InlineHookContainer<SheapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);
/// Prepared inline hook for explicit purge.
pub static PURGE_HOOK: LazyLock<InlineHookContainer<SheapPurgeFn>> =
    LazyLock::new(InlineHookContainer::new);
/// Prepared replacement hook for the thread-local accessor.
pub static GET_THREAD_LOCAL_HOOK: LazyLock<ReplacementHookContainer<SheapGetThreadLocalFn>> =
    LazyLock::new(ReplacementHookContainer::new);

// ---- Hook implementations ----

/// Game's scrap heap structure. Must match the game's struct layout exactly.
#[repr(C)]
pub struct SheapStruct {
    blocks: *mut *mut c_void,
    cur: *mut c_void,
    last: *mut c_void,
}

impl SheapStruct {
    /// Construct the inert layout returned for Psycho-owned thread identities.
    pub const fn new_nulled() -> Self {
        Self {
            blocks: null_mut(),
            cur: null_mut(),
            last: null_mut(),
        }
    }
}

/// Return this thread's stable, inert ScrapHeap identity.
///
/// # Safety
///
/// This function must be called through the audited native accessor ABI.
#[allow(clippy::let_and_return)]
pub unsafe extern "C" fn hook_get_thread_local() -> *mut c_void {
    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct::new_nulled()) };
    }
    let sheap_ptr = DUMMY_SHEAP.with(|d| d.get() as *mut c_void);
    sheap_ptr
}

/// Reset Psycho state for the native fixed-size initialization boundary.
///
/// # Safety
///
/// `sheap_ptr` must be the identity supplied by the hooked native ABI, and the
/// engine must have ended the lifetime of allocations from its previous
/// generation.
pub unsafe extern "fastcall" fn hook_init_fix(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    if sheap_ptr.is_null() {
        log::error!("[scrap_heap] init_fix: null heap pointer");
        return;
    }
    Runtime::get_instance().purge(sheap_ptr);
}

/// Reset Psycho state for the native variable-size initialization boundary.
///
/// The native size is intentionally ignored because Psycho uses fixed standard
/// regions plus exact oversized mappings.
///
/// # Safety
///
/// `sheap_ptr` must be the identity supplied by the hooked native ABI, and the
/// engine must have ended the lifetime of allocations from its previous
/// generation.
pub unsafe extern "fastcall" fn hook_init_var(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if sheap_ptr.is_null() {
        log::error!("[scrap_heap] init_var: null heap pointer");
        return;
    }
    Runtime::get_instance().purge(sheap_ptr);
}

/// Maximum OOM retry attempts before giving up.
const SHEAP_OOM_RETRIES: u32 = 3;

/// Allocate through the replacement while preserving the native fastcall ABI.
///
/// # Safety
///
/// `sheap_ptr`, `size`, and `align` must satisfy the native ScrapHeap call
/// contract established for the supported executable.
pub unsafe extern "fastcall" fn hook_alloc(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    if sheap_ptr.is_null() {
        log::error!("[scrap_heap] alloc: null heap pointer");
        return null_mut();
    }
    let actual_align = align;
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
    for attempt in 1..=SHEAP_OOM_RETRIES {
        // Allocation returned with all heap/reserve locks released. Reclaim
        // only queued heaps whose live count is still zero, then retry.
        let reclaimed = rt.reclaim_queued_regions();
        log::warn!(
            "[scrap_heap] OOM on alloc(size={}, align={}), attempt {}/{} reclaimed_regions={}",
            size,
            align,
            attempt,
            SHEAP_OOM_RETRIES,
            reclaimed,
        );

        let ptr = rt.alloc(sheap_ptr, size, align);
        if !ptr.is_null() {
            log::info!("[scrap_heap] OOM recovered on attempt {}", attempt);
            return ptr;
        }

        // Avoid a tight retry loop while other threads may be freeing regions.
        if attempt > 1 {
            libpsycho::os::windows::winapi::sleep(1);
        }
    }

    log::error!(
        "[scrap_heap] CRITICAL: alloc failed after {} retries (size={}, align={})",
        SHEAP_OOM_RETRIES,
        size,
        align
    );
    rt.record_final_failure();
    null_mut()
}

/// Free an exact payload through the replacement's native fastcall ABI.
///
/// # Safety
///
/// A non-null `ptr` must be the exact payload returned for `sheap_ptr` and must
/// not already have been freed.
pub unsafe extern "fastcall" fn hook_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    Runtime::get_instance().free(sheap_ptr, ptr);
}

/// Purge one native ScrapHeap identity at an engine-owned lifetime boundary.
///
/// # Safety
///
/// The engine must guarantee that no allocation from this identity remains
/// live or concurrently accessible.
pub unsafe extern "fastcall" fn hook_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    Runtime::get_instance().purge(sheap_ptr);
}

/// Return a diagnostic snapshot of the process-wide replacement.
pub fn snapshot() -> ScrapSnapshot {
    Runtime::get_instance().current_snapshot()
}

/// Initialize the runtime and prove the minimum reserve before hook activation.
///
/// Returns an error when the mandatory reserve cannot be established. The
/// caller must leave the native allocator unmodified in that case.
pub fn initialize_runtime() -> anyhow::Result<()> {
    let runtime = Runtime::get_instance();
    anyhow::ensure!(
        runtime.is_ready(),
        "ScrapHeap reusable reserve could not establish its minimum capacity"
    );
    Ok(())
}

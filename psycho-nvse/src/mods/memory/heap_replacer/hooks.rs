//! Hook functions for game heap, CRT, scrap heap, and main loop.
//!
//! This module contains ONLY extern hook functions and the minimal glue
//! to dispatch into business logic modules (mimalloc, sbm2, pressure, etc.).

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_collect, mi_free, mi_is_in_heap_region, mi_malloc, mi_malloc_aligned, mi_realloc,
    mi_realloc_aligned, mi_recalloc, mi_usable_size,
};

use std::cell::UnsafeCell;
use std::ptr::null_mut;

use super::gheap::pressure::PressureRelief;
use super::sbm2::runtime::Runtime;

// ===========================================================================
//   GAME HEAP CONSTANTS
// ===========================================================================

const GHEAP_ALIGN: usize = 16;

/// GameHeap singleton (DAT_011f6238 in Ghidra).
const GHEAP_SINGLETON: usize = 0x011F6238;

/// Pressure check interval (every N gheap allocations).
const PRESSURE_CHECK_INTERVAL: u32 = 50_000;

// Thread-local allocation counter for pressure check interval.
// No atomic ops, no cache contention — each thread has its own counter.
thread_local! {
    static ALLOC_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

// ===========================================================================
//   CRT HOOKS — malloc/calloc/realloc/recalloc/msize/free
// ===========================================================================

pub(super) unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    let result = unsafe { mi_malloc(size) };
    log::trace!("malloc({}) -> {:p}", size, result);
    result
}

pub(super) unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let result = unsafe { mi_calloc(count, size) };
    log::trace!("calloc({}, {}) -> {:p}", count, size, result);
    result
}

pub(super) unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    if raw_ptr.is_null() {
        return unsafe { mi_malloc(size) };
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_realloc(raw_ptr, size) };
    }

    if let Ok(orig_realloc) = super::replacer::CRT_INLINE_REALLOC_HOOK_1.original() {
        return unsafe { orig_realloc(raw_ptr, size) };
    }

    let result = unsafe { super::heap_validate::heap_validated_realloc(raw_ptr, size) };
    if !result.is_null() {
        return result;
    }

    log::error!("realloc({:p}, {}): no heap owns this pointer!", raw_ptr, size);
    null_mut()
}

pub(super) unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    if raw_ptr.is_null() {
        return unsafe { mi_calloc(count, size) };
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_recalloc(raw_ptr, count, size) };
    }

    // Pre-hook pointer: allocate new via mimalloc, copy old data, free via original CRT
    let new_total = match count.checked_mul(size) {
        Some(total) => total,
        None => return null_mut(),
    };

    let old_size = unsafe { hook_msize(raw_ptr) };
    let new_ptr = unsafe { mi_calloc(count, size) };
    if !new_ptr.is_null() && old_size > 0 && old_size != usize::MAX {
        unsafe {
            std::ptr::copy_nonoverlapping(
                raw_ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_total),
            );
        }
        unsafe { hook_free(raw_ptr) };
    }
    new_ptr
}

pub(super) unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    if raw_ptr.is_null() {
        return 0;
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_usable_size(raw_ptr) };
    }

    if let Ok(orig_msize) = super::replacer::CRT_INLINE_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(raw_ptr) };
        if size != usize::MAX {
            return size;
        }
    }

    let size = unsafe { super::heap_validate::heap_validated_size(raw_ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }

    usize::MAX
}

pub(super) unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    if raw_ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_free(raw_ptr) };
    }

    if let Ok(orig_free) = super::replacer::CRT_INLINE_FREE_HOOK.original() {
        unsafe { orig_free(raw_ptr) };
        return;
    }

    if unsafe { super::heap_validate::heap_validated_free(raw_ptr) } {
        return;
    }

    log::error!("free({:p}): no heap owns this pointer!", raw_ptr);
}

// ===========================================================================
//   GAME HEAP HOOKS — GameHeap::Allocate/Free/Realloc/Msize
// ===========================================================================

pub(super) unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    let ptr = unsafe { mi_malloc_aligned(size, GHEAP_ALIGN) };
    if !ptr.is_null() {
        // Periodic pressure check using thread-local counter (zero contention).
        ALLOC_COUNTER.with(|c| {
            let count = c.get().wrapping_add(1);
            c.set(count);
            if count % PRESSURE_CHECK_INTERVAL == 0 {
                if let Some(pr) = PressureRelief::instance() {
                    unsafe { pr.check() };
                }
            }
        });

        return ptr;
    }

    // OOM: thread-local collect and retry.
    // NEVER mi_collect(true) — it purges cross-thread segments and races with
    // AI Linear Task Threads (EXCEPTION_ACCESS_VIOLATION inside psycho_nvse).
    unsafe { mi_collect(false) };
    unsafe { mi_malloc_aligned(size, GHEAP_ALIGN) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        unsafe { mi_free(ptr) };
        return;
    }

    // Pre-hook pointer: original trampoline handles SBM arenas
    if let Ok(orig_free) = super::replacer::GHEAP_FREE_HOOK.original() {
        unsafe { orig_free(GHEAP_SINGLETON as *mut c_void, ptr) };
        return;
    }

    unsafe { super::heap_validate::heap_validated_free(ptr) };
}

pub(super) unsafe extern "thiscall" fn hook_gheap_msize(
    _this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    if ptr.is_null() {
        return 0;
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        return unsafe { mi_usable_size(ptr as *const c_void) };
    }

    if let Ok(orig_msize) = super::replacer::GHEAP_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(GHEAP_SINGLETON as *mut c_void, ptr) };
        if size != 0 {
            return size;
        }
    }

    let size = unsafe { super::heap_validate::heap_validated_size(ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }

    0
}

pub(super) unsafe extern "thiscall" fn hook_gheap_realloc(
    _this: *mut c_void,
    ptr: *mut c_void,
    new_size: usize,
) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { hook_gheap_alloc(_this, new_size) };
    }

    if new_size == 0 {
        unsafe { hook_gheap_free(_this, ptr) };
        return null_mut();
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, GHEAP_ALIGN) };
        if !new_ptr.is_null() {
            return new_ptr;
        }
        // NEVER mi_collect(true) — races with AI threads. See hook_gheap_alloc.
        unsafe { mi_collect(false) };
        return unsafe { mi_realloc_aligned(ptr, new_size, GHEAP_ALIGN) };
    }

    // Pre-hook pointer: alloc new, copy, free old via trampoline
    let old_size = unsafe { hook_gheap_msize(_this, ptr) };
    if old_size == 0 {
        return null_mut();
    }

    let new_ptr = unsafe { mi_malloc_aligned(new_size, GHEAP_ALIGN) };
    if !new_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_size),
            )
        };
        unsafe { hook_gheap_free(_this, ptr) };
    }
    new_ptr
}

// ===========================================================================
//   MAIN LOOP HOOK — pressure relief between frames
// ===========================================================================

pub(super) unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
    if let Ok(original) = super::replacer::MAIN_LOOP_MAINTENANCE_HOOK.original() {
        unsafe { original(this) };
    }

    if let Some(pr) = PressureRelief::instance() {
        unsafe { pr.relieve() };
    }
}

// ===========================================================================
//   PER-FRAME QUEUE DRAIN HOOK — boost NiNode drain under pressure
// ===========================================================================

/// Extra rounds of FUN_00868850 to call when under memory pressure.
/// Each round drains ~10-20 NiNodes from queue 0x08 (the game's own
/// batch size). 9 extra rounds = ~100-200 NiNodes per frame total.
const EXTRA_DRAIN_ROUNDS: u32 = 9;

pub(super) unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Call original — game's normal per-frame drain (10-20 items from highest-priority queue)
    if let Ok(original) = super::replacer::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        unsafe { original() };

        // Under memory pressure, call the drain function additional times.
        // Each call processes up to 10-20 NiNodes from queue 0x08 (if non-empty).
        //
        // This is safe because:
        // - FUN_00868850 runs at line ~802, BEFORE AI dispatch and render
        // - AI threads are idle — no concurrent heightfield access
        // - The game itself calls this function here every frame
        // - The function uses internal try-locks for queue access
        // - Render hasn't built draw lists yet — destroyed BSTreeNodes won't
        //   appear in this frame's draw lists
        if let Some(pr) = PressureRelief::instance() {
            if pr.is_requested() {
                for _ in 0..EXTRA_DRAIN_ROUNDS {
                    unsafe { original() };
                }
            }
        }
    }
}

// ===========================================================================
//   SCRAP HEAP HOOKS
// ===========================================================================

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
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct::new_nulled()) };
    }
    let sheap_ptr = DUMMY_SHEAP.with(|d| d.get() as *mut c_void);
    sheap_ptr
}

pub(super) unsafe extern "fastcall" fn sheap_init_fix(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }
    Runtime::get_instance().purge(sheap_ptr);
}

pub(super) unsafe extern "fastcall" fn sheap_init_var(
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

pub(super) unsafe extern "fastcall" fn sheap_alloc(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    if sheap_ptr.is_null() {
        log::error!("sheap_alloc: sheap_ptr is NULL!");
        return sheap_ptr;
    }
    let actual_align = align.max(16);
    Runtime::get_instance().alloc(sheap_ptr, size, actual_align)
}

pub(super) unsafe extern "fastcall" fn sheap_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    Runtime::get_instance().free(sheap_ptr, ptr);
}

pub(super) unsafe extern "fastcall" fn sheap_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    Runtime::get_instance().purge(sheap_ptr);
}

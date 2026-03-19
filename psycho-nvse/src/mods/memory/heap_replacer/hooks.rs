//! Hook functions for game heap, CRT, scrap heap, and main loop.
//!
//! Extern hook functions are thin wrappers. GameHeap logic lives in
//! `gheap::Gheap`, scrap heap logic in `sbm2::Runtime`.

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_collect, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc,
    mi_usable_size,
};

use std::cell::UnsafeCell;
use std::ptr::null_mut;

use super::gheap::Gheap;
use super::sbm2::runtime::Runtime;

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
//   GAME HEAP HOOKS — thin wrappers delegating to Gheap
// ===========================================================================

pub(super) unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { Gheap::alloc(size) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
    unsafe { Gheap::free(ptr) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_msize(
    _this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    unsafe { Gheap::msize(ptr) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_realloc(
    _this: *mut c_void,
    ptr: *mut c_void,
    new_size: usize,
) -> *mut c_void {
    unsafe { Gheap::realloc(ptr, new_size) }
}

// ===========================================================================
//   MAIN LOOP HOOK — frame tick + pressure relief
// ===========================================================================

pub(super) unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
    if let Ok(original) = super::replacer::MAIN_LOOP_MAINTENANCE_HOOK.original() {
        unsafe { original(this) };
    }

    unsafe { Gheap::on_frame_tick() };
}

// ===========================================================================
//   PER-FRAME QUEUE DRAIN HOOK — boost NiNode drain under pressure
// ===========================================================================

/// Extra rounds of FUN_00868850 to call when under memory pressure.
/// Each round drains ~10-20 NiNodes from queue 0x08 (the game's own
/// batch size). 19 extra rounds = ~200-400 NiNodes per frame total.
const EXTRA_DRAIN_ROUNDS: u32 = 19;

/// NiNode PDD queue (DAT_011de808). Queue count is at offset +0x0A (u16).
const NINODE_QUEUE_ADDR: usize = 0x011DE808;
const NINODE_QUEUE_COUNT_OFFSET: usize = 0x0A;

/// HeapCompact trigger field (heap_singleton + 0x134).
const HEAP_COMPACT_TRIGGER_PTR: usize = 0x011F636C;

/// All PDD queue addresses — count at offset +0x0A (u16) each.
const TEXTURE_QUEUE_ADDR: usize = 0x011DE910; // queue 0x04
const ANIM_QUEUE_ADDR: usize = 0x011DE888; // queue 0x02
const GENERIC_QUEUE_ADDR: usize = 0x011DE874; // queue 0x01
const FORM_QUEUE_ADDR: usize = 0x011DE828; // queue 0x10
// Havok queue at 0x011DE924 uses different structure (not u16 count)

/// Diagnostic counter — log queue states every N frames when under pressure.
const DIAG_LOG_INTERVAL: u32 = 300; // ~5 seconds at 60fps

thread_local! {
    static DIAG_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub(super) unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Call original — game's normal per-frame drain (10-20 items from highest-priority queue)
    if let Ok(original) = super::replacer::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        unsafe { original() };

        if let Some(pr) = super::gheap::pressure::PressureRelief::instance()
            && pr.is_requested() {
                // Diagnostic: this hook runs at line ~802, RIGHT AFTER
                // HeapCompact (line ~797). Check if HeapCompact consumed
                // our trigger (reset to 0) or if it's still pending.
                DIAG_COUNTER.with(|c| {
                    let count = c.get().wrapping_add(1);
                    c.set(count);
                    if count % DIAG_LOG_INTERVAL == 0 {
                        let trigger_val =
                            unsafe { *(HEAP_COMPACT_TRIGGER_PTR as *const u32) };
                        let ninode_q = unsafe {
                            *((NINODE_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let texture_q = unsafe {
                            *((TEXTURE_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let anim_q = unsafe {
                            *((ANIM_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let generic_q = unsafe {
                            *((GENERIC_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let form_q = unsafe {
                            *((FORM_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        log::info!(
                            "[DIAG] trigger={} queues: NiNode={} Tex={} Anim={} Gen={} Form={}",
                            trigger_val, ninode_q, texture_q, anim_q, generic_q, form_q
                        );
                    }
                });

                // Boosted drain: call original additional times for NiNode queue
                for _ in 0..EXTRA_DRAIN_ROUNDS {
                    let count = unsafe {
                        *((NINODE_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    if count == 0 {
                        break;
                    }
                    unsafe { original() };
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

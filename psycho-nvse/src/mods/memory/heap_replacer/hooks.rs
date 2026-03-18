//! Game heap and scrap heap hooks.

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_collect, mi_free, mi_is_in_heap_region, mi_malloc, mi_malloc_aligned, mi_realloc,
    mi_realloc_aligned, mi_recalloc, mi_usable_size,
};

use std::cell::UnsafeCell;
use std::ptr::null_mut;

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
    // realloc(NULL, size) = malloc(size)
    if raw_ptr.is_null() {
        return unsafe { mi_malloc(size) };
    }

    // Fast path: mimalloc pointer
    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_realloc(raw_ptr, size) };
    }

    // Try game's CRT realloc first
    if let Ok(orig_realloc) = super::replacer::CRT_INLINE_REALLOC_HOOK_1.original() {
        return unsafe { orig_realloc(raw_ptr, size) };
    }

    // Last resort: HeapValidate-based realloc
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
    unsafe { mi_recalloc(raw_ptr, count, size) }
}

pub(super) unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    if raw_ptr.is_null() {
        return 0;
    }

    // Fast path: mimalloc pointer
    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_usable_size(raw_ptr) };
    }

    // Try game's CRT _msize first
    if let Ok(orig_msize) = super::replacer::CRT_INLINE_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(raw_ptr) };
        if size != usize::MAX {
            return size;
        }
    }

    // Fallback: HeapValidate-based size query
    let size = unsafe { super::heap_validate::heap_validated_size(raw_ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }

    // Unknown pointer - return usize::MAX (error) so callers handle gracefully
    usize::MAX
}

pub(super) unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    if raw_ptr.is_null() {
        return;
    }

    // Fast path: mimalloc pointer
    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_free(raw_ptr) };
    }

    // Try game's CRT free first (most common case for non-mimalloc pointers).
    // If this is the wrong heap, fall back to HeapValidate-based routing.
    if let Ok(orig_free) = super::replacer::CRT_INLINE_FREE_HOOK.original() {
        unsafe { orig_free(raw_ptr) };
        return;
    }

    // Last resort: find the correct heap via Windows HeapValidate
    if unsafe { super::heap_validate::heap_validated_free(raw_ptr) } {
        return;
    }

    log::error!("free({:p}): no heap owns this pointer!", raw_ptr);
}

// ===========================================================================
//   GAME HEAP — Complete ownership via raw mimalloc
//
//   ALL allocations: mi_malloc_aligned(size, 16)
//   ALL frees: mi_is_in_heap_region → mi_free, else HeapValidate (pre-hook)
//   No original GameHeap trampoline. No SBM. No pool. No overhead.
//
//   Pre-hook pointers (allocated before DllMain) are a finite, shrinking set.
//   They are detected by mi_is_in_heap_region returning false, and freed
//   via Windows HeapValidate-based routing.
// ===========================================================================

const GHEAP_ALIGN: usize = 16;

/// GameHeap singleton (DAT_011f6238 in Ghidra).
/// Used ONLY for pre-hook pointer free/msize via original trampoline.
/// The original GameHeap::Free knows about SBM arenas; HeapValidate does NOT.
const GHEAP_SINGLETON: usize = 0x011F6238;

pub(super) unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    // Fast path: mimalloc succeeds (99.99% of calls)
    let ptr = unsafe { mi_malloc_aligned(size, GHEAP_ALIGN) };
    if !ptr.is_null() {
        return ptr;
    }

    // OOM: collect mimalloc garbage and retry
    unsafe { mi_collect(true) };
    let ptr = unsafe { mi_malloc_aligned(size, GHEAP_ALIGN) };
    if !ptr.is_null() {
        return ptr;
    }

    // Still OOM: fall back to original GameHeap::Allocate.
    // This triggers the game's heap compaction loop (FUN_00866A90) which
    // unloads cells, flushes texture caches, purges render targets — the
    // game's built-in response to memory pressure. Without this, the game
    // loads content faster than it frees during rapid cell transitions,
    // and commit grows monotonically until OOM.
    if let Ok(orig_alloc) = super::replacer::GHEAP_ALLOC_HOOK.original() {
        return unsafe { orig_alloc(GHEAP_SINGLETON as *mut c_void, size) };
    }

    null_mut()
}

pub(super) unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        unsafe { mi_free(ptr) };
        return;
    }

    // Pre-hook pointer: use original GameHeap::Free trampoline.
    // HeapValidate can't find SBM arena pointers (they're VirtualAlloc blocks,
    // not Windows heaps). The original Free knows about SBM arenas.
    if let Ok(orig_free) = super::replacer::GHEAP_FREE_HOOK.original() {
        unsafe { orig_free(GHEAP_SINGLETON as *mut c_void, ptr) };
        return;
    }

    // Last resort fallback
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

    // Pre-hook pointer: original msize knows SBM arena sizes
    if let Ok(orig_msize) = super::replacer::GHEAP_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(GHEAP_SINGLETON as *mut c_void, ptr) };
        if size != 0 {
            return size;
        }
    }

    // Fallback
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

    // mimalloc pointer: native realloc (can expand in-place)
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, GHEAP_ALIGN) };
        if !new_ptr.is_null() {
            return new_ptr;
        }
        // OOM: collect and retry
        unsafe { mi_collect(true) };
        return unsafe { mi_realloc_aligned(ptr, new_size, GHEAP_ALIGN) };
    }

    // Pre-hook pointer: get size from original msize, alloc new in mimalloc,
    // copy, free old via original trampoline (handles SBM arenas)
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
//   SCRAP HEAP
//
// ===========================================================================

use super::sbm2::runtime::Runtime;

/// Game's scrap heap structure.
/// Must match the game's struct layout exactly.
#[repr(C)]
pub struct SheapStruct {
    blocks: *mut *mut c_void, // 0x00
    cur: *mut c_void,         // 0x04
    last: *mut c_void,        // 0x08
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

/// This is source of all sheap instances!
#[allow(clippy::let_and_return)]
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct::new_nulled()) };
    }

    let sheap_ptr = DUMMY_SHEAP.with(|d| d.get() as *mut c_void);

    sheap_ptr
}

/// Fixed-size sheap initialization hook (0x00AA53F0 FNV, 0x0086CB70 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_fix(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }

    Runtime::get_instance().purge(sheap_ptr);
}

/// Variable-size sheap initialization hook (0x00AA5410 FNV, 0x0086CB90 GECK).
pub(super) unsafe extern "fastcall" fn sheap_init_var(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_var: NULL heap pointer");
        return;
    }

    // Ensure your RegionAllocator knows this heap is "fresh"
    Runtime::get_instance().purge(sheap_ptr);
}

/// Sheap allocation hook (0x00AA5430 FNV, 0x0086CBA0 GECK).
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

    // Ensure that we have CORRECT align
    let actual_align = align.max(16);
    Runtime::get_instance().alloc(sheap_ptr, size, actual_align)
}

/// Sheap free hook.
/// In our case - NOOP
pub(super) unsafe extern "fastcall" fn sheap_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    Runtime::get_instance().free(sheap_ptr, ptr);
}

/// Sheap purge hook (0x00AA5460 FNV, 0x0086CAA0 GECK).
pub(super) unsafe extern "fastcall" fn sheap_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    Runtime::get_instance().purge(sheap_ptr);
}

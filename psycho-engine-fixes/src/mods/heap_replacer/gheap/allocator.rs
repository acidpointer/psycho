//! Game heap allocator: pure size-based dispatch.
//!
//!   size == 0                    -> 8-byte pool cell (vanilla GameHeap)
//!   1 <= size <= 3584            -> pool (size-class, NVHR mheap style)
//!   3585 <= size <= 16 MB        -> block (variable-size, NVHR dheap style)
//!   size > 16 MB                 -> va_alloc (direct VirtualAlloc)
//!   pool failure                 -> existing/new block as an emergency path
//!   all remaining tiers fail     -> NULL (NVHR semantics)
//!
//! The allocator has no knowledge of game state -- no loading flags, no
//! menu-mode checks, no pool-active gating, no OOM recovery stages. That
//! was a workaround layer that added failure modes without changing
//! behaviour that actually belongs in the allocator.
//!
//! On final OOM we return NULL rather than calling the vanilla
//! `FormHeap_Allocate` trampoline. The trampoline approach caused two
//! bugs: (1) it hangs worker threads for 15 s in vanilla's Stage 8
//! retry loop, and (2) vanilla's last-resort CRT `_malloc` escape
//! calls into our own `hook_malloc`, which calls back into this
//! function -- infinite recursion through the game's OOM stages.
//! NVHR accepts the NULL-return failure mode for the same reason.
//!
//! Zombie safety:
//!   pool - out-of-band freelist; freed cell bytes are untouched.
//!   block - cell metadata sits in a separate `Vec<Cell>`, user data is
//!           not overwritten on free.
//!   va_alloc - MEM_DECOMMIT / MEM_RELEASE on free; no zombie, but huge
//!              allocations have fewer stale-reader patterns anyway.

use libc::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use libmimalloc::{mi_is_in_heap_region, mi_usable_size};

use super::super::heap_validate;
use super::engine::addr;
use super::statics;

// ---------------------------------------------------------------------------
// VAS diagnostics (watchdog reads HEADROOM)
// ---------------------------------------------------------------------------

/// Free VAS threshold below which CRITICAL logging fires.
pub const VAS_CRITICAL_REMAINING: usize = 400 * 1024 * 1024;

/// Free VAS threshold below which EMERGENCY logging fires.
pub const VAS_EMERGENCY_REMAINING: usize = 200 * 1024 * 1024;

static HEADROOM: AtomicUsize = AtomicUsize::new(0);

pub fn current_free_vas() -> usize {
    libpsycho::os::windows::winapi::available_virtual_memory().unwrap_or(usize::MAX)
}

pub fn calibrate_thresholds(baseline: usize) {
    if baseline == 0 {
        return;
    }
    let free_vas = current_free_vas();
    HEADROOM.store(free_vas, Ordering::Release);
    log::info!(
        "[VAS] Baseline calibrated: commit={}MB free={}MB (watch below {}MB, high below {}MB)",
        baseline / 1024 / 1024,
        free_vas / 1024 / 1024,
        VAS_CRITICAL_REMAINING / 1024 / 1024,
        VAS_EMERGENCY_REMAINING / 1024 / 1024,
    );
}

pub fn get_headroom() -> usize {
    HEADROOM.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Block tier overflow diagnostic
// ---------------------------------------------------------------------------

/// Count of medium allocations that fell from `block` to `va_alloc`
/// because the block tier was full. Rate-limited to power-of-two
/// reporting so save-load bursts don't spam the log.
static BLOCK_OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);
static POOL_FALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);

#[cold]
fn log_pool_fallback(size: usize) {
    let n = POOL_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        log::warn!(
            "[ALLOC] exact pool unavailable: size={} total={} (using emergency block fallback)",
            size,
            n,
        );
    }
}

#[cold]
fn log_block_overflow(size: usize) {
    let n = BLOCK_OVERFLOW_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        log::warn!(
            "[ALLOC] block tier overflow: size={} total={} (falling through to va_alloc)",
            size,
            n,
        );
    }
}

pub fn block_overflow_count() -> u64 {
    BLOCK_OVERFLOW_COUNT.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Alloc / Free / Msize / Realloc
// ---------------------------------------------------------------------------

/// Allocate `size` bytes. Pure size-based tier dispatch; game state
/// is not consulted. See module docs for tier boundaries.
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    let size = if size == 0 {
        // Ghidra: vanilla GameHeap::Allocate (0x00AA3E40) rounds any
        // request below 9 bytes up to 8 after the SBM is initialized.
        // NIF geometry load uses some non-NULL zero-length arrays as
        // "present" markers; returning NULL changes later Havok logic.
        8
    } else {
        size
    };

    if size <= super::pool::POOL_MAX_SIZE {
        let ptr = super::pool::alloc(size);
        if !ptr.is_null() {
            return ptr;
        }

        // Exact-size overflow is the normal growth path. Reaching here means
        // that it could not reserve or commit more memory. This is an
        // emergency safety valve rather than a sustained strategy, but it is
        // still safer than returning immediate NULL while an existing block
        // has reusable space.
        log_pool_fallback(size);
    }

    if size <= super::block::BLOCK_MAX_ALLOC {
        let ptr = super::block::alloc(size);
        if !ptr.is_null() {
            return ptr;
        }
        // Medium alloc that could not fit in the block tier. Rare in
        // practice; logged rate-limited so we can tell if the tier
        // cap needs bumping.
        log_block_overflow(size);
    }

    let ptr = super::va_alloc::alloc(size);
    if !ptr.is_null() {
        return ptr;
    }

    // All tiers refused. Return NULL -- same as NVHR. The trampoline
    // path was a recursion trap: vanilla's CRT _malloc escape calls
    // back into our own hook_malloc, which calls back into this
    // function. Workers would also hang 15 s in vanilla's Stage 8
    // sleep-retry loop. Honest NULL on OOM is safer.
    null_mut()
}

/// Free a block. Dispatch by ownership; falls back to vanilla SBM
/// trampoline for any pointer that originated outside our tiers.
#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    if super::pool::free(ptr) {
        return;
    }

    if super::block::free_if_owned(ptr).is_some() {
        return;
    }

    if unsafe { super::va_alloc::free(ptr) } {
        return;
    }

    // Defensive: pre-hook CRT allocations may still sit in mimalloc.
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        unsafe { libmimalloc::mi_free(ptr) };
        return;
    }

    if let Ok(orig_free) = statics::GHEAP_FREE_HOOK.original() {
        unsafe { orig_free(addr::HEAP_SINGLETON as *mut c_void, ptr) };
        return;
    }

    unsafe { heap_validate::heap_validated_free(ptr) };
}

/// Return usable size of an allocated block.
#[inline]
pub unsafe fn msize(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }

    if super::pool::is_pool_ptr(ptr as *const c_void) {
        return super::pool::usable_size(ptr as *const c_void);
    }

    if let Some(size) = super::block::size_of(ptr as *const c_void) {
        return size;
    }

    if let Some(sz) = super::va_alloc::size_of(ptr as *const c_void) {
        return sz;
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        return unsafe { mi_usable_size(ptr as *const c_void) };
    }

    if let Ok(orig_msize) = statics::GHEAP_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(addr::HEAP_SINGLETON as *mut c_void, ptr) };
        if size != 0 {
            return size;
        }
    }
    let size = unsafe { heap_validate::heap_validated_size(ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }
    0
}

/// Reallocate a block.
#[inline]
pub unsafe fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { alloc(new_size) };
    }
    if new_size == 0 {
        unsafe { free(ptr) };
        return null_mut();
    }

    let old_size_opt = if super::pool::is_pool_ptr(ptr as *const c_void) {
        Some(super::pool::usable_size(ptr as *const c_void))
    } else if let Some(size) = super::block::size_of(ptr as *const c_void) {
        Some(size)
    } else {
        super::va_alloc::size_of(ptr as *const c_void)
    };

    if let Some(old_size) = old_size_opt {
        if new_size <= old_size {
            return ptr;
        }
        let new_ptr = unsafe { alloc(new_size) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_size.min(new_size),
                );
                free(ptr);
            }
        }
        return new_ptr;
    }

    let old_size = unsafe { msize(ptr) };
    if old_size == 0 {
        return null_mut();
    }
    let new_ptr = unsafe { alloc(new_size) };
    if !new_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_size),
            );
            free(ptr);
        }
    }
    new_ptr
}

// ---------------------------------------------------------------------------

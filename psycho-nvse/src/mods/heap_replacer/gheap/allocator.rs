//! Game heap allocator: pure size-based dispatch.
//!
//!   size == 0                    -> NULL
//!   1 <= size <= 3584            -> pool (size-class, NVHR mheap style)
//!   3585 <= size <= 16 MB        -> block (variable-size, NVHR dheap style)
//!   size > 16 MB                 -> va_alloc (direct VirtualAlloc)
//!   any tier fails               -> NULL (NVHR semantics)
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
//!   block - cell metadata sits in a separate Vec<Cell>, user data is
//!           not overwritten on free.
//!   va_alloc - MEM_DECOMMIT / MEM_RELEASE on free; no zombie, but huge
//!              allocations have fewer stale-reader patterns anyway.

use libc::c_void;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use libmimalloc::{mi_is_in_heap_region, mi_usable_size};

use super::super::heap_validate;
use super::engine::{addr, globals};
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
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    if ok.is_err() {
        return usize::MAX;
    }
    status.ullAvailVirtual as usize
}

pub fn calibrate_thresholds(baseline: usize) {
    if baseline == 0 {
        return;
    }
    let free_vas = current_free_vas();
    HEADROOM.store(free_vas, Ordering::Release);
    log::info!(
        "[VAS] Calibrated: baseline={}MB, free_vas={}MB, \
         critical_at=<{}MB free, emergency_at=<{}MB free",
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
// Thread identity
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ThreadRole {
    Unknown = 0,
    Main = 1,
    Worker = 2,
}

thread_local! {
    static THREAD_ROLE: Cell<ThreadRole> = const { Cell::new(ThreadRole::Unknown) };
}

/// True when the current OS thread is the game's main thread. Cached
/// in a TLS cell after first call. Used by `cell_unload` and the OOM
/// Stage 8 handler only -- the allocator itself does not branch on it.
#[inline]
pub fn is_main_thread() -> bool {
    THREAD_ROLE.with(|r| match r.get() {
        ThreadRole::Main => true,
        ThreadRole::Worker => false,
        ThreadRole::Unknown => {
            let is_main = globals::is_main_thread_by_tid();
            r.set(if is_main {
                ThreadRole::Main
            } else {
                ThreadRole::Worker
            });
            is_main
        }
    })
}

/// Legacy scoped guard retained as an ABI shim so `heap_manager`
/// keeps compiling. Large-bypass had meaning in the old
/// slab+mimalloc world; with pool+block it's a no-op.
pub fn with_large_bypass<R>(f: impl FnOnce() -> R) -> R {
    f()
}

// ---------------------------------------------------------------------------
// Block tier overflow diagnostic
// ---------------------------------------------------------------------------

/// Count of medium allocations that fell from `block` to `va_alloc`
/// because the block tier was full. Rate-limited to power-of-two
/// reporting so save-load bursts don't spam the log.
static BLOCK_OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);

#[cold]
fn log_block_overflow(size: usize) {
    let n = BLOCK_OVERFLOW_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        log::warn!(
            "[ALLOC] block tier overflow: size={} total={} (falling through to va_alloc)",
            size, n,
        );
    }
}

// ---------------------------------------------------------------------------
// Alloc / Free / Msize / Realloc
// ---------------------------------------------------------------------------

/// Allocate `size` bytes. Pure size-based tier dispatch; game state
/// is not consulted. See module docs for tier boundaries.
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    if size == 0 {
        return null_mut();
    }

    if size <= super::pool::POOL_MAX_SIZE {
        let ptr = super::pool::alloc(size);
        if !ptr.is_null() {
            return ptr;
        }
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

    if super::pool::is_pool_ptr(ptr as *const c_void) {
        super::pool::free(ptr);
        return;
    }

    if super::block::is_block_ptr(ptr as *const c_void) {
        super::block::free(ptr);
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

    if super::block::is_block_ptr(ptr as *const c_void) {
        return super::block::usable_size(ptr as *const c_void);
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
    } else if super::block::is_block_ptr(ptr as *const c_void) {
        Some(super::block::usable_size(ptr as *const c_void))
    } else { super::va_alloc::size_of(ptr as *const c_void) };

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

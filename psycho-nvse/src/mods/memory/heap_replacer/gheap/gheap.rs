//! GameHeap replacement — routes alloc/free/realloc/msize through mimalloc.
//!
//! This module encapsulates all GameHeap allocation logic. The extern hook
//! functions in `hooks.rs` are thin wrappers that delegate here.

use libc::c_void;
use std::ptr::null_mut;

use libmimalloc::{
    mi_collect, mi_free, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned,
    mi_usable_size,
};

use super::delayed_free;
use super::pressure::PressureRelief;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Enable delayed free (quarantine) for GameHeap frees.
/// When true, freed pointers are held for a few frames before mi_free,
/// keeping memory contents intact for subsystems with stale pointers
/// (IO thread QueuedTexture, AI thread heightfields, SpeedTree cache).
/// When false, all quarantine code is eliminated by the compiler.
const DELAYED_FREE: bool = true;

/// Alignment for all GameHeap allocations (matches original engine).
const ALIGN: usize = 16;

/// GameHeap singleton address (DAT_011f6238 in Ghidra).
/// Used when calling original trampoline for pre-hook pointer cleanup.
const SINGLETON: usize = 0x011F6238;

/// Pressure check interval (every N gheap allocations per thread).
const PRESSURE_CHECK_INTERVAL: u32 = 50_000;

// Thread-local allocation counter for pressure check interval.
// No atomic ops, no cache contention — each thread has its own counter.
thread_local! {
    static ALLOC_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

// ---------------------------------------------------------------------------
// Gheap
// ---------------------------------------------------------------------------

/// GameHeap replacement backed by mimalloc.
///
/// All methods are stateless — state lives in thread-locals and statics.
/// The struct exists as a namespace and to enforce initialization order.
pub struct Gheap;

impl Gheap {
    /// Allocate `size` bytes with 16-byte alignment.
    ///
    /// Includes periodic memory pressure checks and OOM recovery
    /// (quarantine flush + thread-local collect + retry).
    #[inline]
    pub unsafe fn alloc(size: usize) -> *mut c_void {
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            // Periodic pressure check using thread-local counter (zero contention).
            ALLOC_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % PRESSURE_CHECK_INTERVAL == 0
                    && let Some(pr) = PressureRelief::instance() {
                        unsafe { pr.check() };
                    }
            });
            return ptr;
        }

        // OOM recovery. The original FUN_00aa3e40 had a do-while loop that
        // retried forever with HeapCompact. We replicate escalating recovery:
        //
        // Stage 1: flush this thread's quarantine + thread-local collect
        // Stage 2: mi_collect(false) to reclaim cross-thread abandoned segments
        // Stage 3: log and return NULL (true VA exhaustion)
        //
        // NEVER mi_collect(true) -- races with AI threads.

        // Stage 1: flush quarantine on this thread
        if DELAYED_FREE {
            unsafe { delayed_free::flush_current_thread() };
        }
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 2: collect abandoned segments from other threads
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        log::error!(
            "[GHEAP] OOM: mi_malloc_aligned({}, {}) failed after recovery",
            size, ALIGN,
        );
        std::ptr::null_mut()
    }

    /// Free a GameHeap pointer.
    ///
    /// Routes through: quarantine (mimalloc ptrs) → original trampoline
    /// (pre-hook SBM ptrs) → heap_validate fallback.
    #[inline]
    pub unsafe fn free(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            if DELAYED_FREE {
                unsafe { delayed_free::quarantine_free(ptr) };
            } else {
                unsafe { mi_free(ptr) };
            }
            return;
        }

        // Pre-hook pointer: original trampoline handles SBM arenas.
        if let Ok(orig_free) =
            crate::mods::memory::heap_replacer::replacer::GHEAP_FREE_HOOK.original()
        {
            unsafe { orig_free(SINGLETON as *mut c_void, ptr) };
            return;
        }

        unsafe {
            crate::mods::memory::heap_replacer::heap_validate::heap_validated_free(ptr)
        };
    }

    /// Get the usable size of a GameHeap pointer.
    #[inline]
    pub unsafe fn msize(ptr: *mut c_void) -> usize {
        if ptr.is_null() {
            return 0;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            return unsafe { mi_usable_size(ptr as *const c_void) };
        }

        if let Ok(orig_msize) =
            crate::mods::memory::heap_replacer::replacer::GHEAP_MSIZE_HOOK.original()
        {
            let size = unsafe { orig_msize(SINGLETON as *mut c_void, ptr) };
            if size != 0 {
                return size;
            }
        }

        let size = unsafe {
            crate::mods::memory::heap_replacer::heap_validate::heap_validated_size(
                ptr as *const c_void,
            )
        };
        if size != usize::MAX {
            return size;
        }

        0
    }

    /// Reallocate a GameHeap pointer.
    ///
    /// Handles null/zero edge cases, mimalloc fast path, and cross-heap
    /// copy-and-free for pre-hook pointers.
    #[inline]
    pub unsafe fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
        if ptr.is_null() {
            return unsafe { Self::alloc(new_size) };
        }

        if new_size == 0 {
            unsafe { Self::free(ptr) };
            return null_mut();
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
            if !new_ptr.is_null() {
                return new_ptr;
            }
            // OOM: same escalating recovery as alloc
            if DELAYED_FREE {
                unsafe { delayed_free::flush_current_thread() };
            }
            let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
            if !new_ptr.is_null() {
                return new_ptr;
            }
            unsafe { mi_collect(false) };
            let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
            if new_ptr.is_null() {
                log::error!(
                    "[GHEAP] OOM: mi_realloc_aligned({}, {}) failed after recovery",
                    new_size, ALIGN,
                );
            }
            return new_ptr;
        }

        // Pre-hook pointer: alloc new via mimalloc, copy, free old via trampoline.
        let old_size = unsafe { Self::msize(ptr) };
        if old_size == 0 {
            return null_mut();
        }

        let new_ptr = unsafe { mi_malloc_aligned(new_size, ALIGN) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_size.min(new_size),
                );
            }
            unsafe { Self::free(ptr) };
        }
        new_ptr
    }

    /// Called once per frame from the main loop hook.
    /// Advances the quarantine frame counter, proactively flushes stale
    /// quarantine buckets, and runs pressure relief.
    pub unsafe fn on_frame_tick() {
        if DELAYED_FREE {
            delayed_free::tick();
        }

        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.relieve() };
        }
    }
}

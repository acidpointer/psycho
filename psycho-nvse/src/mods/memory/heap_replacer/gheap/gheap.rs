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

/// Hard commit ceiling. When mimalloc commit exceeds this, Gheap::alloc
/// triggers the game's OOM handler (Stage 5 = cell unloading) instead of
/// allocating more. This mimics SBM's arena limit -- the vanilla game's
/// allocator NEVER grows past its arena, forcing OOM recovery to free
/// cells/textures. Without this ceiling, mimalloc consumes all VA during
/// loading, starving D3D9 (which uses VirtualAlloc for GPU resources).
///
/// 1.6GB leaves ~2.4GB for D3D9 + DLLs + stacks in a 4GB LAA process.
const COMMIT_CEILING: usize = 1600 * 1024 * 1024;

// Thread-local allocation counter for pressure check interval.
// No atomic ops, no cache contention — each thread has its own counter.
thread_local! {
    static ALLOC_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// GLOBAL ceiling flag. When ANY thread detects commit > COMMIT_CEILING,
/// ALL threads see it immediately and trigger OOM recovery on next alloc.
/// Must be global — thread-local missed BSTaskManagerThread allocations,
/// allowing commit to reach 2.4GB during loading.
static OVER_CEILING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
        // Hard commit ceiling check. When over ceiling, trigger OOM recovery
        // BEFORE allocating — mimics SBM's arena limit. This is critical:
        // without it, mimalloc consumes all VA during loading, starving D3D9.
        //
        // OVER_CEILING is set periodically (every PRESSURE_CHECK_INTERVAL)
        // and checked on every alloc. This avoids expensive mi_process_info
        // calls on the hot path while ensuring the ceiling is enforced.
        if OVER_CEILING.load(std::sync::atomic::Ordering::Relaxed) {
            // Try to free memory via game's OOM handler before allocating
            let ptr = unsafe { Self::oom_recover(size) };
            if !ptr.is_null() {
                // Recovery succeeded — check if we're back under ceiling
                let commit = libmimalloc::process_info::MiMallocProcessInfo::get()
                    .get_current_commit();
                if commit < COMMIT_CEILING {
                    OVER_CEILING.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                return ptr;
            }
            return ptr; // NULL — true OOM
        }

        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            // Periodic pressure + ceiling check (zero contention).
            ALLOC_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % PRESSURE_CHECK_INTERVAL == 0 {
                    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
                    let commit = info.get_current_commit();

                    // Check hard ceiling — global flag, all threads see it
                    if commit >= COMMIT_CEILING {
                        OVER_CEILING.store(true, std::sync::atomic::Ordering::Relaxed);
                    }

                    // Check pressure threshold
                    if let Some(pr) = PressureRelief::instance() {
                        unsafe { pr.check() };
                    }
                }
            });
            return ptr;
        }

        unsafe { Self::oom_recover(size) }
    }

    /// OOM recovery: replicate the vanilla allocator's escalating retry loop.
    ///
    /// The original FUN_00aa3e40 calls FUN_00866a90 (OOM stage executor)
    /// with escalating stages 0-8. Each stage frees different resources:
    ///   0: ProcessPendingCleanup
    ///   1: SBM/geometry cache cleanup
    ///   2: Texture/BSA cache cleanup
    ///   3: Async flush (blocking)
    ///   4: Lock + PDD + release
    ///   5: FindCellToUnload + full PDD (falls through to 4->3)
    ///   6: Pool compaction
    ///   7: Final flag
    ///   8: Worker thread: trigger HeapCompact + Sleep(1) retry
    ///
    /// The vanilla allocator NEVER returns NULL -- it retries until success.
    /// We first try mimalloc-specific recovery, then call the game's handler.
    #[cold]
    unsafe fn oom_recover(size: usize) -> *mut c_void {
        // Stage 1: flush this thread's quarantine + collect
        if DELAYED_FREE {
            unsafe { delayed_free::flush_current_thread() };
        }
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 2: call the game's own OOM handler with escalating stages.
        // FUN_00866a90(heap_singleton, pool_ptr, stage, &done_flag)
        // pool_ptr = *(heap_singleton + 0x110) = primary heap pointer.
        const OOM_STAGE_EXEC: usize = 0x00866A90;
        const PRIMARY_HEAP_OFFSET: usize = 0x110;

        let heap_singleton = SINGLETON as *mut c_void;
        let primary_heap = unsafe {
            let p = (heap_singleton as *const u8).add(PRIMARY_HEAP_OFFSET)
                as *const *mut c_void;
            *p
        };
        let mut stage: i32 = 0;
        let mut done: u8 = 0;

        // Check if we're on the main thread. Many OOM stages (4, 5, 6)
        // are only safe on the main thread (PDD, cell unload, defrag).
        // Worker threads should only run stages 1, 3, 8.
        // FUN_0040fc90 = GetCurrentThreadId, FUN_0044edb0 = get main thread ID
        const GET_THREAD_ID: usize = 0x0040FC90;
        const GET_MAIN_THREAD_ID: usize = 0x0044EDB0;
        const TES_OBJECT: usize = 0x011DEA0C;

        let is_main_thread = unsafe {
            let get_tid: unsafe extern "C" fn() -> u32 = std::mem::transmute(GET_THREAD_ID);
            let get_main: unsafe extern "fastcall" fn(*mut c_void) -> u32 =
                std::mem::transmute(GET_MAIN_THREAD_ID);
            let tes = *(TES_OBJECT as *const *mut c_void);
            if tes.is_null() {
                false
            } else {
                get_tid() == get_main(tes)
            }
        };

        if !is_main_thread {
            // Worker thread (BSTaskManagerThread): DON'T call FUN_00866a90.
            // Calling OOM stages from inside IO task processing causes
            // re-entrancy crashes — the IO system is mid-operation.
            // Instead: signal main thread to do cleanup, then sleep/retry.
            unsafe {
                let trigger = (heap_singleton as *mut u8).add(0x134) as *mut u32;
                std::ptr::write_volatile(trigger, 6); // HeapCompact stages 0-6
            }
            // Retry up to 15000 times (matching vanilla Stage 8's limit).
            // During loading, the main thread may not run HeapCompact for
            // seconds. We must wait for it. 15000 × 1ms = 15 seconds max.
            for retry in 0..15000u32 {
                unsafe { libpsycho::os::windows::winapi::sleep(1) };
                if DELAYED_FREE {
                    unsafe { delayed_free::flush_current_thread() };
                }
                unsafe { mi_collect(true) };
                let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
                if !ptr.is_null() {
                    if retry > 100 {
                        log::info!("[GHEAP] OOM (worker): recovered after {} retries", retry);
                    }
                    return ptr;
                }
                // Re-signal HeapCompact periodically
                if retry % 1000 == 0 {
                    unsafe {
                        let trigger = (heap_singleton as *mut u8).add(0x134) as *mut u32;
                        std::ptr::write_volatile(trigger, 6);
                    }
                }
            }
            // 15 seconds exhausted — true VA exhaustion
            let info = libmimalloc::process_info::MiMallocProcessInfo::get();
            log::error!(
                "[GHEAP] OOM (worker): mi_malloc_aligned({}, {}) failed after 15s. \
                 RSS={}MB, Commit={}MB",
                size, ALIGN,
                info.get_current_rss() / 1024 / 1024,
                info.get_current_commit() / 1024 / 1024,
            );
            return std::ptr::null_mut();
        }

        // Main thread ONLY: call game's OOM stages 0-8.
        while stage <= 8 {
            done = 0;
            stage = unsafe {
                type OomStageExecFn =
                    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, i32, *mut u8) -> i32;
                let f: OomStageExecFn = std::mem::transmute(OOM_STAGE_EXEC);
                f(heap_singleton, primary_heap, stage, &mut done)
            };

            if DELAYED_FREE {
                unsafe { delayed_free::flush_current_thread() };
            }
            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                return ptr;
            }
        }

        // Final stage: force collect on current thread's heap.
        // mi_collect only affects the CALLING thread's heap (verified in
        // mimalloc source: mi_theap_collect(_mi_theap_default(), force)).
        // force=true: frees ALL empty pages (not just retired), purges arenas.
        // force=false: only frees pages with expired retirement.
        // Neither touches other threads' heaps — no AI thread race.
        //
        // Also flush quarantine on this thread to release zombie pages.
        if DELAYED_FREE {
            unsafe { delayed_free::flush_current_thread() };
        }
        unsafe { mi_collect(true) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Log detailed diagnostics for debugging
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::error!(
            "[GHEAP] OOM: mi_malloc_aligned({}, {}) failed after all recovery. \
             RSS={}MB, Commit={}MB, PeakRSS={}MB, PeakCommit={}MB",
            size, ALIGN,
            info.get_current_rss() / 1024 / 1024,
            info.get_current_commit() / 1024 / 1024,
            info.get_peak_rss() / 1024 / 1024,
            info.get_peak_commit() / 1024 / 1024,
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
            // OOM: same escalating recovery as alloc — call game's OOM stages.
            return unsafe { Self::oom_recover(new_size) };
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

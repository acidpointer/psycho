//! GameHeap replacement -- routes alloc/free/realloc/msize through mimalloc.
//!
//! Frees go through per-thread quarantine (main thread: double-buffer
//! delayed by 1 frame, worker threads: immediate mi_free). Stale pointer
//! issues handled by quarantine timing + targeted engine hooks.
//!
//! OOM recovery: react to allocation failures, not commit thresholds.
//! VA exhaustion is about fragmentation, not total commit.

use libc::c_void;
use std::ptr::null_mut;

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned,
    mi_usable_size,
};
use libpsycho::ffi::fnptr::FnPtr;

use super::delayed_free;
use super::pressure::PressureRelief;
use super::statics;
use super::types::{GetMainThreadIdFn, GetThreadIdFn, OomStageExecFn};
use crate::mods::memory::heap_replacer::heap_validate;

// ---- Configuration ----

const ALIGN: usize = 16;
const SINGLETON: usize = 0x011F6238;

/// Pressure check interval. Every N allocs, check if commit exceeds
/// the dynamic threshold (baseline + 500MB) and trigger pressure relief.
const PRESSURE_CHECK_INTERVAL: u32 = 50_000;

thread_local! {
    static ALLOC_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

// ---- OOM recovery game addresses ----

const OOM_STAGE_EXEC: usize = 0x00866A90;
const PRIMARY_HEAP_OFFSET: usize = 0x110;
const GET_THREAD_ID: usize = 0x0040FC90;
const GET_MAIN_THREAD_ID: usize = 0x0044EDB0;
const TES_OBJECT: usize = 0x011DEA0C;

// ---- Gheap ----

pub struct Gheap;

impl Gheap {
    /// Allocate `size` bytes with 16-byte alignment.
    ///
    /// Fast path: mi_malloc_aligned directly. Periodic pressure check
    /// every 50K allocs. On failure: oom_recover with escalating stages.
    #[inline]
    pub unsafe fn alloc(size: usize) -> *mut c_void {
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            // Periodic pressure check (no ceiling, just dynamic threshold).
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

        // Allocation failed -- actual VA exhaustion or fragmentation.
        unsafe { Self::oom_recover(size) }
    }

    /// OOM recovery with escalating stages + bounded retry.
    ///
    /// Only called when mi_malloc_aligned actually fails. Escalates:
    /// 1. Collect this thread's empty pages
    /// 2. Flush quarantine + force collect
    /// 3. Main thread: game's OOM stages 0-8
    /// 4. Retry loop with Sleep(1) — gives other threads time to free memory
    ///
    /// The vanilla allocator never returns NULL (retries for 15 seconds).
    /// We retry for up to 3 seconds before giving up.
    #[cold]
    unsafe fn oom_recover(size: usize) -> *mut c_void {
        let is_main = unsafe { Self::is_main_thread() };
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::warn!(
            "[GHEAP] OOM recovery started: size={}, thread={}, RSS={}MB, Commit={}MB, Quarantine={}MB",
            size,
            if is_main { "main" } else { "worker" },
            info.get_current_rss() / 1024 / 1024,
            info.get_current_commit() / 1024 / 1024,
            delayed_free::get_quarantine_usage() / 1024 / 1024,
        );

        // Stage 1: collect empty pages from this thread's heap.
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 2: flush quarantine to reclaim deferred memory + force collect.
        unsafe { delayed_free::flush_current_thread() };
        unsafe { mi_collect(true) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 3 (main thread only): game's OOM stages 0-8.
        // SKIP if AI threads are active — game OOM stages 4-5 acquire
        // the process manager lock and run FindCellToUnload, which race
        // with AI threads that read actor/cell data.
        if is_main && !super::hooks::is_ai_active() {
            let ptr = unsafe { Self::run_game_oom_stages(size) };
            if !ptr.is_null() {
                return ptr;
            }
        }

        // Stage 4: bounded retry loop. Give other threads time to free
        // memory via pressure relief, quarantine flush, or OOM stages.
        // 500 iterations * Sleep(1) = ~500ms max stutter.
        // Uses mi_collect(false) per iteration (lightweight) with one
        // force collect + quarantine flush at the halfway point.
        for attempt in 0..500u32 {
            libpsycho::os::windows::winapi::sleep(1);
            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                if attempt > 10 {
                    log::info!(
                        "[GHEAP] OOM recovered after {} retries (size={})",
                        attempt, size,
                    );
                }
                return ptr;
            }
            // Halfway: force collect + quarantine flush as escalation.
            if attempt == 250 {
                unsafe { delayed_free::flush_current_thread() };
                unsafe { mi_collect(true) };
            }
        }

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::error!(
            "[GHEAP] OOM: mi_malloc_aligned({}, {}) failed after all recovery. \
             RSS={}MB, Commit={}MB, Quarantine={}MB",
            size, ALIGN,
            info.get_current_rss() / 1024 / 1024,
            info.get_current_commit() / 1024 / 1024,
            delayed_free::get_quarantine_usage() / 1024 / 1024,
        );
        null_mut()
    }

    unsafe fn is_main_thread() -> bool {
        unsafe {
            let get_tid = FnPtr::<GetThreadIdFn>::from_raw(GET_THREAD_ID as *mut c_void);
            let get_main =
                FnPtr::<GetMainThreadIdFn>::from_raw(GET_MAIN_THREAD_ID as *mut c_void);
            let tes = *(TES_OBJECT as *const *mut c_void);

            match (get_tid, get_main) {
                (Ok(tid_fn), Ok(main_fn)) if !tes.is_null() => {
                    match (tid_fn.as_fn(), main_fn.as_fn()) {
                        (Ok(tid), Ok(main)) => tid() == main(tes),
                        _ => false,
                    }
                }
                _ => false,
            }
        }
    }

    /// Run game's OOM stages 0-8, then collect and retry.
    #[cold]
    unsafe fn run_game_oom_stages(size: usize) -> *mut c_void {
        let heap_singleton = SINGLETON as *mut c_void;
        let primary_heap = unsafe {
            let p =
                (heap_singleton as *const u8).add(PRIMARY_HEAP_OFFSET) as *const *mut c_void;
            *p
        };

        let oom_exec = match unsafe {
            FnPtr::<OomStageExecFn>::from_raw(OOM_STAGE_EXEC as *mut c_void)
        } {
            Ok(f) => f,
            Err(_) => return null_mut(),
        };

        let mut stage: i32 = 0;
        let mut done: u8;
        while stage <= 8 {
            done = 0;
            stage = match unsafe { oom_exec.as_fn() } {
                Ok(f) => unsafe { f(heap_singleton, primary_heap, stage, &mut done) },
                Err(_) => break,
            };
        }

        // After all game stages, flush quarantine + force collect.
        unsafe { delayed_free::flush_current_thread() };
        unsafe { mi_collect(true) };

        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::error!(
            "[GHEAP] OOM: mi_malloc_aligned({}, {}) failed after all stages. \
             RSS={}MB, Commit={}MB",
            size, ALIGN,
            info.get_current_rss() / 1024 / 1024,
            info.get_current_commit() / 1024 / 1024,
        );
        null_mut()
    }

    /// Free a GameHeap pointer through quarantine.
    #[inline]
    pub unsafe fn free(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            unsafe { delayed_free::quarantine_free(ptr) };
            return;
        }

        // Pre-hook pointer: original trampoline handles SBM arenas.
        if let Ok(orig_free) = statics::GHEAP_FREE_HOOK.original() {
            unsafe { orig_free(SINGLETON as *mut c_void, ptr) };
            return;
        }

        unsafe { heap_validate::heap_validated_free(ptr) };
    }

    #[inline]
    pub unsafe fn msize(ptr: *mut c_void) -> usize {
        if ptr.is_null() {
            return 0;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            return unsafe { mi_usable_size(ptr as *const c_void) };
        }

        if let Ok(orig_msize) = statics::GHEAP_MSIZE_HOOK.original() {
            let size = unsafe { orig_msize(SINGLETON as *mut c_void, ptr) };
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
            return unsafe { Self::oom_recover(new_size) };
        }

        // Pre-hook pointer: alloc new, copy, free old.
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

    /// Called once per frame from hook_main_loop_maintenance (between render and AI_JOIN).
    pub unsafe fn on_frame_tick() {
        delayed_free::tick_rotate();

        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.relieve() };
        }
    }

    /// Called from hook_per_frame_queue_drain (Phase 7, before AI_START).
    pub unsafe fn on_pre_pdd() {
        delayed_free::tick_flush();
    }
}

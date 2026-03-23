//! GameHeap replacement -- routes alloc/free/realloc/msize through mimalloc.
//!
//! No quarantine. All frees are immediate via mi_free. Stale pointer
//! issues are fixed at the source with targeted hooks (texture dead set,
//! IO task validation, queued ref HAVOK_DEATH check) rather than delaying
//! frees with a timing-based zombie window.

use libc::c_void;
use std::ptr::null_mut;

use libmimalloc::{
    mi_collect, mi_free, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned,
    mi_usable_size,
};
use libpsycho::ffi::fnptr::FnPtr;

use super::pressure::PressureRelief;
use super::statics;
use super::texture_cache;
use super::types::{GetMainThreadIdFn, GetThreadIdFn, OomStageExecFn};
use crate::mods::memory::heap_replacer::heap_validate;

// ---- Configuration ----

/// Alignment for all GameHeap allocations (matches original engine).
const ALIGN: usize = 16;

/// GameHeap singleton address (DAT_011f6238).
const SINGLETON: usize = 0x011F6238;

/// Check pressure every N gheap allocations per thread.
const PRESSURE_CHECK_INTERVAL: u32 = 50_000;

/// Hard commit ceiling. When mimalloc commit exceeds this, Gheap::alloc
/// triggers OOM recovery. 1.6GB leaves ~2.4GB for D3D9 + DLLs + stacks.
const COMMIT_CEILING: usize = 1600 * 1024 * 1024;

thread_local! {
    static ALLOC_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Global ceiling flag. Managed by periodic check in alloc().
static OVER_CEILING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ---- OOM recovery game addresses ----

const OOM_STAGE_EXEC: usize = 0x00866A90;
const PRIMARY_HEAP_OFFSET: usize = 0x110;
const GET_THREAD_ID: usize = 0x0040FC90;
const GET_MAIN_THREAD_ID: usize = 0x0044EDB0;
const TES_OBJECT: usize = 0x011DEA0C;

// ---- Gheap ----

pub struct Gheap;

impl Gheap {
    #[inline]
    pub unsafe fn alloc(size: usize) -> *mut c_void {
        if OVER_CEILING.load(std::sync::atomic::Ordering::Relaxed) {
            let ptr = unsafe { Self::oom_recover(size) };
            if !ptr.is_null() {
                ALLOC_COUNTER.with(|c| {
                    let count = c.get().wrapping_add(1);
                    c.set(count);
                    if count % PRESSURE_CHECK_INTERVAL == 0 {
                        let commit = libmimalloc::process_info::MiMallocProcessInfo::get()
                            .get_current_commit();
                        OVER_CEILING.store(
                            commit >= COMMIT_CEILING,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                });
            }
            return ptr;
        }

        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            ALLOC_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % PRESSURE_CHECK_INTERVAL == 0 {
                    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
                    let commit = info.get_current_commit();

                    OVER_CEILING.store(
                        commit >= COMMIT_CEILING,
                        std::sync::atomic::Ordering::Relaxed,
                    );

                    if let Some(pr) = PressureRelief::instance() {
                        unsafe { pr.check() };
                    }
                }
            });
            return ptr;
        }

        unsafe { Self::oom_recover(size) }
    }

    /// OOM recovery with escalating stages.
    ///
    /// Stage 1: try alloc (for OVER_CEILING path where memory is available).
    /// Stage 2: mi_collect to reclaim empty pages, retry.
    /// Stage 3: force collect, retry.
    /// Stage 4 (main thread): game's OOM stages 0-8 to free game data.
    #[cold]
    unsafe fn oom_recover(size: usize) -> *mut c_void {
        // Stage 1: try without cleanup (OVER_CEILING path usually succeeds).
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 2: collect empty pages, retry.
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 3: force collect (purge all empty pages + arenas), retry.
        unsafe { mi_collect(true) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 4 (main thread only): game's OOM stages 0-8.
        if unsafe { Self::is_main_thread() } {
            unsafe { Self::run_game_oom_stages(size) }
        } else {
            let info = libmimalloc::process_info::MiMallocProcessInfo::get();
            log::error!(
                "[GHEAP] OOM (worker): mi_malloc_aligned({}, {}) failed. \
                 RSS={}MB, Commit={}MB",
                size, ALIGN,
                info.get_current_rss() / 1024 / 1024,
                info.get_current_commit() / 1024 / 1024,
            );
            std::ptr::null_mut()
        }
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

    /// Run game's OOM stages 0-8 then force-collect and retry.
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
            Err(_) => return std::ptr::null_mut(),
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

        unsafe { mi_collect(true) };

        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::error!(
            "[GHEAP] OOM: mi_malloc_aligned({}, {}) failed after all stages. \
             RSS={}MB, Commit={}MB, PeakRSS={}MB, PeakCommit={}MB",
            size, ALIGN,
            info.get_current_rss() / 1024 / 1024,
            info.get_current_commit() / 1024 / 1024,
            info.get_peak_rss() / 1024 / 1024,
            info.get_peak_commit() / 1024 / 1024,
        );
        std::ptr::null_mut()
    }

    /// Free a GameHeap pointer. Direct mi_free.
    ///
    /// Stale pointer protection is handled by mimalloc's purge_delay (500ms).
    /// Freed pages stay committed (readable as zombie data) for 500ms before
    /// decommit, covering all stale access paths.
    #[inline]
    pub unsafe fn free(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            unsafe { mi_free(ptr) };
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
    pub unsafe fn on_frame_tick() {
        // Clear texture dead set every frame.
        texture_cache::clear_dead_set();

        if let Some(pr) = PressureRelief::instance() {
            pr.calibrate_baseline();
            unsafe { pr.relieve() };
        }
    }
}

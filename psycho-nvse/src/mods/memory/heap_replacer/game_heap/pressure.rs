//! Memory pressure relief for the game heap.
//!
//! # Hook position: FUN_008705d0 (post-render)
//!
//! The hook runs after render but BEFORE the main loop's AI thread join.
//! AI Linear Task Threads are still active at our hook position.
//!
//! ```text
//! 0x0086ec87  AI_START                <- AI threads dispatched
//! 0x0086ede8  RENDER
//! 0x0086edf0  OUR_HOOK (0x008705d0)  <- We are here
//! 0x0086ee4e  AI_JOIN (0x008c7990)   <- AI threads joined
//! 0x0086ee62  POST_AI (0x0086f6a0)
//! ```
//!
//! # Multi-layer pressure relief
//!
//! ## Layer 1: Post-render cell unloading + PDD (this module)
//! Unloads cells using the game's destruction protocol: loading state
//! counter, hkWorld_Lock, SceneGraphInvalidate, FindCellToUnload,
//! DeferredCleanupSmall (PDD + blocking async flush).
//!
//! ## Layer 2: Boosted per-frame NiNode drain (FUN_00868850 hook)
//! Under pressure, calls the game's per-frame drain 20x instead of 1x,
//! draining 200-400 NiNodes per frame.
//!
//! ## Layer 3: HeapCompact trigger (heap_singleton + 0x134)
//! Under pressure, writes `6` to the HeapCompact trigger field. On the
//! next frame, HeapCompact runs stages 0-6 including cell unloading.

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::LazyLock;

use libmimalloc::mi_collect;
use libpsycho::ffi::fnptr::FnPtr;

use super::types::{
    DeferredCleanupSmallFn, FindCellToUnloadFn,
    PostDestructionRestoreFn, PreDestructionSetupFn,
};
use crate::mods::memory::heap_replacer::mem_stats;


// ---- Configuration ----

/// Cell unloading during gameplay is unsafe -- multiple deferred processing
/// queues hold raw pointers to forms in loaded cells. Instead, the commit
/// ceiling in alloc.rs triggers the game's OWN OOM handler which unloads
/// cells inside the allocator retry loop where all queues are idle.
#[allow(dead_code)]
const CELL_UNLOAD_ENABLED: bool = false;

/// Maximum commit growth above baseline before triggering pressure relief.
/// 500MB balances normal gameplay headroom with stress test stability.
const MAX_GROWTH_ABOVE_BASELINE: usize = 500 * 1024 * 1024;

/// Max cells to unload per relief cycle.
const MAX_CELLS_PER_CYCLE: usize = 20;

/// Minimum milliseconds between relief cycles.
/// Normal relief: lightweight collect every 2 seconds.
const COOLDOWN_MS: u64 = 2000;

/// Minimum milliseconds between aggressive relief (mi_collect(true)).
/// Force collect walks all pages — expensive but actually frees memory.
/// Only triggers when commit exceeds baseline + 2x MAX_GROWTH.
const AGGRESSIVE_COOLDOWN_MS: u64 = 10_000;

// ---- Game addresses ----

const FIND_CELL_TO_UNLOAD: usize = 0x00453A80;
const PRE_DESTRUCTION_SETUP: usize = 0x00878160;
const POST_DESTRUCTION_RESTORE: usize = 0x00878200;
const DEFERRED_CLEANUP_SMALL: usize = 0x00878250;

#[allow(dead_code)]
const TEXTURE_CACHE_PRE_RESET: usize = 0x00A62030;
#[allow(dead_code)]
const GET_AI_THREAD_MANAGER: usize = 0x00713D80;
#[allow(dead_code)]
const AI_THREAD_JOIN: usize = 0x008C7990;

const GAME_MANAGER_PTR: usize = 0x011DEA10;
const TES_SINGLETON_PTR: usize = 0x011DEA3C;
const TES_PENDING_CELL_LOAD_OFFSET: usize = 0x77C;
#[allow(dead_code)]
const AI_ACTIVE_FLAG_PTR: usize = 0x011DFA19;
const HEAP_COMPACT_TRIGGER_PTR: usize = 0x011F636C;
const GAME_LOADING_FLAG_PTR: usize = 0x011DEA2B;
const LOADING_STATE_COUNTER_PTR: usize = 0x01202D6C;

// ---- BSTaskManagerThread IO synchronization ----

/// Runtime manager singleton. Contains Havok world fields and
/// IOManager/BSTaskManager fields (dequeue lock at +0x20, thread array at +0x50).
const IO_MANAGER_SINGLETON_PTR: usize = 0x01202D98;
const IO_DEQUEUE_LOCK_OFFSET: usize = 0x20;
const IO_DEQUEUE_LOCK_COUNTER_OFFSET: usize = 0x24;
const IO_THREAD_ARRAY_OFFSET: usize = 0x50;
const IO_THREAD_SEM_COUNT_OFFSET: usize = 0x18;
const IO_THREAD_ITER_SEM_HANDLE_OFFSET: usize = 0x1C;

/// Bethesda's spin-lock acquire (threadID-based CAS, non-standard ABI).
const SPIN_LOCK_ACQUIRE: usize = 0x0040FBF0;

// ---- PressureRelief ----

pub struct PressureRelief {
    requested: AtomicBool,
    active: AtomicBool,
    last_time_ms: AtomicU64,

    /// Set by relieve() on multi-threaded systems when cell unloading is
    /// needed but AI threads are still active. Cleared by run_deferred_unload()
    /// from the AI thread join hook (after AI threads are idle).
    deferred_unload: AtomicBool,

    /// Set by destruction_protocol when cells were unloaded. The loading
    /// state counter is kept elevated to suppress PLChangeEvent dispatch.
    /// tick() decrements it on the next frame.
    pending_counter_decrement: AtomicBool,

    find_cell: FnPtr<FindCellToUnloadFn>,
    pre_destruction: FnPtr<PreDestructionSetupFn>,
    post_destruction: FnPtr<PostDestructionRestoreFn>,
    deferred_cleanup: FnPtr<DeferredCleanupSmallFn>,

    /// Commit at first tick. Dynamic threshold = baseline + MAX_GROWTH.
    baseline_commit: std::sync::atomic::AtomicUsize,
}

impl PressureRelief {
    fn new() -> anyhow::Result<Self> {
        let instance = unsafe {
            Self {
                requested: AtomicBool::new(false),
                active: AtomicBool::new(false),
                deferred_unload: AtomicBool::new(false),
                pending_counter_decrement: AtomicBool::new(false),
                last_time_ms: AtomicU64::new(0),
                find_cell: FnPtr::from_raw(FIND_CELL_TO_UNLOAD as *mut c_void)?,
                pre_destruction: FnPtr::from_raw(PRE_DESTRUCTION_SETUP as *mut c_void)?,
                post_destruction: FnPtr::from_raw(POST_DESTRUCTION_RESTORE as *mut c_void)?,
                deferred_cleanup: FnPtr::from_raw(DEFERRED_CLEANUP_SMALL as *mut c_void)?,
                baseline_commit: std::sync::atomic::AtomicUsize::new(0),
            }
        };

        log::info!(
            "[PRESSURE] Initialized (baseline=deferred, growth={}MB, max_cells={}, cooldown={}ms)",
            MAX_GROWTH_ABOVE_BASELINE / 1024 / 1024,
            MAX_CELLS_PER_CYCLE,
            COOLDOWN_MS,
        );

        Ok(instance)
    }

    /// Dynamic threshold: baseline commit + MAX_GROWTH_ABOVE_BASELINE.
    /// Returns usize::MAX if baseline not yet measured (suppress all checks).
    #[inline]
    fn threshold(&self) -> usize {
        let baseline = self.baseline_commit.load(Ordering::Relaxed);
        if baseline == 0 {
            return usize::MAX;
        }
        baseline + MAX_GROWTH_ABOVE_BASELINE
    }

    /// Measure baseline commit on first tick (main loop started, mods loaded).
    pub fn calibrate_baseline(&self) {
        if self.baseline_commit.load(Ordering::Relaxed) != 0 {
            return;
        }
        let commit = libmimalloc::process_info::MiMallocProcessInfo::get()
            .get_current_commit();
        self.baseline_commit.store(commit, Ordering::Release);
        let threshold_mb = (commit + MAX_GROWTH_ABOVE_BASELINE) / 1024 / 1024;
        log::info!(
            "[PRESSURE] Baseline calibrated: {}MB, threshold={}MB",
            commit / 1024 / 1024,
            threshold_mb,
        );
    }

    pub fn instance() -> Option<&'static Self> {
        static INSTANCE: LazyLock<Option<PressureRelief>> = LazyLock::new(|| {
            match PressureRelief::new() {
                Ok(instance) => Some(instance),
                Err(err) => {
                    log::error!("[PRESSURE] Failed to initialize: {:?}", err);
                    None
                }
            }
        });
        INSTANCE.as_ref()
    }

    #[cold]
    pub unsafe fn check(&self) {
        if self.requested.load(Ordering::Relaxed) {
            return;
        }
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        if info.get_current_commit() >= self.threshold() {
            self.requested.store(true, Ordering::Release);
        }
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Relaxed)
    }

    /// Decrement the loading state counter if a previous destruction_protocol
    /// left it elevated.
    #[allow(dead_code)]
    pub fn flush_pending_counter_decrement(&self) {
        if self.pending_counter_decrement.swap(false, Ordering::AcqRel) {
            let loading_counter =
                unsafe { &*(LOADING_STATE_COUNTER_PTR as *const std::sync::atomic::AtomicI32) };
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Must be called on the main thread, between frames.
    ///
    /// Two-tier escalation:
    /// - Normal (every 2s): mi_collect(false) — reclaim retired pages.
    /// - Aggressive (every 10s, commit > 2x growth): mi_collect(true) +
    ///   quarantine flush — force-walk all pages, reclaim cross-thread.
    pub unsafe fn relieve(&self) {
        if !self.requested.load(Ordering::Acquire) {
            return;
        }

        if self.active.swap(true, Ordering::AcqRel) {
            return;
        }

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let now_ms = info.get_elapsed_ms() as u64;
        let last_ms = self.last_time_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_ms) < COOLDOWN_MS {
            self.active.store(false, Ordering::Release);
            return;
        }

        let commit = info.get_current_commit();
        if commit < self.threshold() {
            self.requested.store(false, Ordering::Release);
            self.active.store(false, Ordering::Release);
            return;
        }

        let baseline = self.baseline_commit.load(Ordering::Relaxed);
        let aggressive_threshold = baseline + MAX_GROWTH_ABOVE_BASELINE * 2;
        let commit_mb = commit / 1024 / 1024;
        let quarantine_mb = super::delayed_free::get_quarantine_usage() / 1024 / 1024;

        // Signal HeapCompact stages 0-2 for the NEXT frame.
        // This is just a u32 volatile write — no objects freed here.
        // The actual HeapCompact runs at Phase 6 of the next frame,
        // before AI_Start, through our PDD hook (write lock).
        // Stage 0: texture cache flush. Stage 1: no-op. Stage 2: menu cleanup.
        unsafe {
            let trigger = HEAP_COMPACT_TRIGGER_PTR as *mut u32;
            trigger.write_volatile(2);
        }

        if commit >= aggressive_threshold {
            // Aggressive: also flush quarantine + force collect.
            static LAST_AGGRESSIVE_MS: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let last_agg = LAST_AGGRESSIVE_MS.load(Ordering::Relaxed);

            if now_ms.saturating_sub(last_agg) >= AGGRESSIVE_COOLDOWN_MS {
                LAST_AGGRESSIVE_MS.store(now_ms, Ordering::Relaxed);
                unsafe { super::delayed_free::flush_current_thread() };
                unsafe { mi_collect(true) };
                log::warn!(
                    "[PRESSURE] Aggressive: HeapCompact+flush+collect, commit={}MB (thresh={}MB), quarantine={}MB, RSS={}MB",
                    commit_mb, aggressive_threshold / 1024 / 1024,
                    quarantine_mb, info.get_current_rss() / 1024 / 1024,
                );
            } else {
                unsafe { mi_collect(false) };
                log::info!(
                    "[PRESSURE] Relief: HeapCompact signaled, commit={}MB, quarantine={}MB",
                    commit_mb, quarantine_mb,
                );
            }
        } else {
            unsafe { mi_collect(false) };
            log::info!(
                "[PRESSURE] Relief: HeapCompact signaled, commit={}MB, quarantine={}MB",
                commit_mb, quarantine_mb,
            );
        }

        self.last_time_ms.store(now_ms, Ordering::Relaxed);
        self.requested.store(false, Ordering::Release);
        self.active.store(false, Ordering::Release);
    }

    /// Run deferred cell unloading. Called from the AI thread join hook
    /// after AI threads have completed their work.
    pub unsafe fn run_deferred_unload(&self) {
        if !self.deferred_unload.load(Ordering::Acquire) {
            return;
        }

        let loading = unsafe { *(GAME_LOADING_FLAG_PTR as *const u8) != 0 };
        if loading {
            return; // keep flag set, retry next frame
        }

        self.deferred_unload.store(false, Ordering::Release);

        let manager = unsafe { *(GAME_MANAGER_PTR as *const *mut c_void) };
        if manager.is_null() {
            return;
        }

        let find_cell = match unsafe { self.find_cell.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };
        let pre_destruction = match unsafe { self.pre_destruction.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };
        let post_destruction = match unsafe { self.post_destruction.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };
        let deferred_cleanup = match unsafe { self.deferred_cleanup.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };

        // Check BSTaskManagerThread guard
        let io_busy = unsafe {
            let tes = *(TES_SINGLETON_PTR as *const *const u8);
            if tes.is_null() {
                true
            } else {
                let handle_ptr = tes.add(TES_PENDING_CELL_LOAD_OFFSET) as *const i32;
                (*handle_ptr) != -1
            }
        };
        if io_busy {
            log::debug!("[PRESSURE] Deferred unload skipped -- BSTaskManagerThread busy");
            return;
        }

        let cells = unsafe {
            Self::destruction_protocol(
                find_cell, pre_destruction, post_destruction,
                deferred_cleanup, manager,
            )
        };

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let commit_mb = info.get_current_commit() / 1024 / 1024;

        mem_stats::global().record_pressure_relief(cells);

        if cells > 0 {
            self.pending_counter_decrement.store(true, Ordering::Release);
            log::info!(
                "[PRESSURE] Deferred unload: {} cells (commit={}MB)",
                cells, commit_mb,
            );
        }
    }

    /// Cell unloading + PDD sequence with IO synchronization.
    ///
    /// Before DeferredCleanupSmall (which runs PDD), acquires the IO dequeue
    /// spin-lock and waits for BSTaskManagerThread to finish any in-flight task.
    /// This prevents PDD from destroying NiSourceTexture objects while
    /// BSTaskManagerThread reads them.
    unsafe fn destruction_protocol(
        find_cell: FindCellToUnloadFn,
        pre_destruction: PreDestructionSetupFn,
        post_destruction: PostDestructionRestoreFn,
        deferred_cleanup: DeferredCleanupSmallFn,
        manager: *mut c_void,
    ) -> usize {
        let mut cells: usize = 0;

        let loading_counter =
            unsafe { &*(LOADING_STATE_COUNTER_PTR as *const std::sync::atomic::AtomicI32) };
        loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let mut state = [0u8; 12];
        let state_ptr = state.as_mut_ptr() as *mut c_void;

        unsafe { pre_destruction(state_ptr, 1, 1, 1) };

        for _ in 0..MAX_CELLS_PER_CYCLE {
            let result = unsafe { find_cell(manager) };
            if (result & 0xFF) != 0 {
                cells += 1;
            } else {
                break;
            }
        }

        // IO synchronization: acquire dequeue lock so BSTaskManagerThread
        // cannot dequeue new tasks during PDD.
        let io_locked = if cells > 0 {
            unsafe { Self::io_lock_acquire() }
        } else {
            false
        };

        unsafe { deferred_cleanup(state[5]) };

        if io_locked {
            unsafe { Self::io_lock_release() };
        }

        unsafe { post_destruction(state_ptr) };

        // If cells were unloaded, keep loading counter elevated so NVSE
        // event dispatch is suppressed. tick() decrements next frame.
        if cells == 0 {
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }

        cells
    }

    /// Acquire the IO dequeue spin-lock and wait for BSTaskManagerThread
    /// to finish any in-flight task. Returns true if lock was acquired.
    pub(super) unsafe fn io_lock_acquire() -> bool {
        use libpsycho::os::windows::winapi::{self, WaitResult};

        let io_mgr = unsafe { *(IO_MANAGER_SINGLETON_PTR as *const *mut u8) };
        if io_mgr.is_null() {
            return false;
        }

        // Acquire the IO dequeue spin-lock (FUN_0040fbf0).
        // Non-standard calling convention: fastcall ECX + 1 stack param + RET 0x4.
        let lock_ptr = unsafe { io_mgr.add(IO_DEQUEUE_LOCK_OFFSET) };
        unsafe {
            std::arch::asm!(
                "push 0",
                "call {func}",
                func = in(reg) SPIN_LOCK_ACQUIRE as u32,
                in("ecx") lock_ptr,
                out("eax") _,
                out("edx") _,
            );
        }

        // Wait for both BSTaskManagerThread instances to finish in-flight tasks.
        for bst_index in 0..2u32 {
            if let Some(sem_handle) = unsafe { Self::read_bst_iter_sem_handle(io_mgr, bst_index) } {
                match winapi::wait_for_single_object(sem_handle, 0) {
                    WaitResult::Signaled => {
                        if let Err(e) = winapi::release_semaphore(sem_handle, 1) {
                            log::error!("[IO_SYNC] ReleaseSemaphore failed: {:?}", e);
                        }
                    }
                    _ => {
                        if let Some(count_before) =
                            unsafe { Self::read_bst_sem_count(io_mgr, bst_index) }
                        {
                            let start = winapi::get_tick_count();
                            loop {
                                winapi::sleep(0);
                                if let Some(c) =
                                    unsafe { Self::read_bst_sem_count(io_mgr, bst_index) }
                                    && c != count_before
                                {
                                    break;
                                }
                                if winapi::get_tick_count().wrapping_sub(start) >= 50 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        true
    }

    /// Release the IO dequeue spin-lock.
    pub(super) unsafe fn io_lock_release() {
        let io_mgr = unsafe { *(IO_MANAGER_SINGLETON_PTR as *const *mut u8) };
        if io_mgr.is_null() {
            return;
        }
        let counter_ptr = unsafe { io_mgr.add(IO_DEQUEUE_LOCK_COUNTER_OFFSET) as *mut i32 };
        let lock_ptr = unsafe { io_mgr.add(IO_DEQUEUE_LOCK_OFFSET) as *mut i32 };

        let new_count = unsafe { std::ptr::read_volatile(counter_ptr) } - 1;
        unsafe { std::ptr::write_volatile(counter_ptr, new_count) };
        if new_count == 0 {
            unsafe { std::ptr::write_volatile(lock_ptr, 0) };
        }
    }

    unsafe fn read_bst_sem_count(io_mgr: *const u8, index: u32) -> Option<i32> {
        let bst = unsafe { Self::read_bst_ptr(io_mgr, index) }?;
        let count_ptr = unsafe { bst.add(IO_THREAD_SEM_COUNT_OFFSET) as *const i32 };
        Some(unsafe { std::ptr::read_volatile(count_ptr) })
    }

    unsafe fn read_bst_iter_sem_handle(
        io_mgr: *const u8,
        index: u32,
    ) -> Option<windows::Win32::Foundation::HANDLE> {
        let bst = unsafe { Self::read_bst_ptr(io_mgr, index) }?;
        let handle_ptr = unsafe {
            bst.add(IO_THREAD_ITER_SEM_HANDLE_OFFSET) as *const windows::Win32::Foundation::HANDLE
        };
        let handle = unsafe { std::ptr::read_volatile(handle_ptr) };
        if handle.is_invalid() {
            return None;
        }
        Some(handle)
    }

    unsafe fn read_bst_ptr(io_mgr: *const u8, index: u32) -> Option<*const u8> {
        let thread_array_ptr =
            unsafe { io_mgr.add(IO_THREAD_ARRAY_OFFSET) as *const *const *const u8 };
        let thread_array = unsafe { *thread_array_ptr };
        if thread_array.is_null() {
            return None;
        }
        let bst = unsafe { *thread_array.add(index as usize) };
        if bst.is_null() {
            return None;
        }
        Some(bst)
    }
}

//! Memory pressure relief for the game heap.
//!
//! The original GameHeap::Allocate had a retry loop: when allocation failed,
//! it called HeapCompact — a multi-stage state machine that unloads cells,
//! destroys deferred objects, and purges SBM arenas.
//!
//! Since mimalloc never fails (far more VA than the 500MB game heap budget),
//! HeapCompact never triggers. The game loads cells without bound during fast
//! travel/movement, exhausting the 32-bit address space.
//!
//! # Thread safety for deferred destruction
//!
//! `ProcessDeferredDestruction` destroys physics objects (hkBSHeightFieldShape)
//! that AI worker threads reference during raycasting. The game's cell transition
//! handler (FUN_008774a0) calls `FUN_008324e0(0)` before destruction, which
//! drains PPL Concurrency Runtime task groups — this waits for all background
//! tasks (including AI physics) to complete before proceeding.
//!
//! We replicate only the task group drain/wait (not the music stop/start
//! that `FUN_008324e0` also performs).

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::LazyLock;

use libmimalloc::mi_collect;
use libpsycho::ffi::fnptr::FnPtr;

use super::types::{
    FindCellToUnloadFn, ProcessDeferredDestructionFn, ProcessPendingCleanupFn,
    SetTlsCleanupFlagFn, TaskGroupDrainFn, TaskGroupWaitFn,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Trigger cell cleanup when commit exceeds this (bytes).
const THRESHOLD: usize = 700 * 1024 * 1024;

/// Max cells to unload per relief cycle.
const MAX_CELLS_PER_CYCLE: usize = 15;

/// Minimum milliseconds between relief cycles.
const COOLDOWN_MS: u64 = 3000;

// ---------------------------------------------------------------------------
// Game function addresses (Fallout New Vegas)
// ---------------------------------------------------------------------------

const FIND_CELL_TO_UNLOAD: usize = 0x00453A80;
const PROCESS_PENDING_CLEANUP: usize = 0x00452490;
const SET_TLS_CLEANUP_FLAG: usize = 0x00869190;
const PROCESS_DEFERRED_DESTRUCTION: usize = 0x00868D70;
const TASK_GROUP_DRAIN: usize = 0x00AD88F0;
const TASK_GROUP_WAIT: usize = 0x00AD8D10;

/// DAT_011dea10 — pointer to the game's TES/DataHandler manager singleton.
const GAME_MANAGER_PTR: usize = 0x011DEA10;

/// PPL task group handles used by the game for background work (AI physics, etc).
/// Draining + waiting on these ensures no AI thread is actively using physics data.
const TASK_GROUP_1: usize = 0x011DD5BC;
const TASK_GROUP_2: usize = 0x011DD638;

// ---------------------------------------------------------------------------
// PressureRelief
// ---------------------------------------------------------------------------

pub struct PressureRelief {
    requested: AtomicBool,
    active: AtomicBool,
    last_time_ms: AtomicU64,
    relief_count: AtomicI64,
    cells_unloaded: AtomicI64,

    find_cell: FnPtr<FindCellToUnloadFn>,
    process_cleanup: FnPtr<ProcessPendingCleanupFn>,
    set_tls_flag: FnPtr<SetTlsCleanupFlagFn>,
    process_deferred: FnPtr<ProcessDeferredDestructionFn>,
    task_drain: FnPtr<TaskGroupDrainFn>,
    task_wait: FnPtr<TaskGroupWaitFn>,
}

impl PressureRelief {
    fn new() -> anyhow::Result<Self> {
        let instance = unsafe {
            Self {
                requested: AtomicBool::new(false),
                active: AtomicBool::new(false),
                last_time_ms: AtomicU64::new(0),
                relief_count: AtomicI64::new(0),
                cells_unloaded: AtomicI64::new(0),
                find_cell: FnPtr::from_raw(FIND_CELL_TO_UNLOAD as *mut c_void)?,
                process_cleanup: FnPtr::from_raw(PROCESS_PENDING_CLEANUP as *mut c_void)?,
                set_tls_flag: FnPtr::from_raw(SET_TLS_CLEANUP_FLAG as *mut c_void)?,
                process_deferred: FnPtr::from_raw(PROCESS_DEFERRED_DESTRUCTION as *mut c_void)?,
                task_drain: FnPtr::from_raw(TASK_GROUP_DRAIN as *mut c_void)?,
                task_wait: FnPtr::from_raw(TASK_GROUP_WAIT as *mut c_void)?,
            }
        };

        log::info!(
            "[PRESSURE] Initialized (threshold={}MB, max_cells={}, cooldown={}ms)",
            THRESHOLD / 1024 / 1024,
            MAX_CELLS_PER_CYCLE,
            COOLDOWN_MS,
        );

        Ok(instance)
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
        if info.get_current_commit() >= THRESHOLD {
            self.requested.store(true, Ordering::Release);
        }
    }

    pub fn stats(&self) -> (i64, i64) {
        (
            self.relief_count.load(Ordering::Relaxed),
            self.cells_unloaded.load(Ordering::Relaxed),
        )
    }

    /// Drain PPL task groups and wait for completion.
    /// After this returns, no AI thread is actively using physics objects.
    unsafe fn drain_task_groups(&self) {
        let drain = match unsafe { self.task_drain.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] TaskGroupDrain: {:?}", err);
                return;
            }
        };
        let wait = match unsafe { self.task_wait.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] TaskGroupWait: {:?}", err);
                return;
            }
        };

        unsafe {
            drain(TASK_GROUP_1 as *mut i32);
            wait(TASK_GROUP_1 as *mut i32);
            drain(TASK_GROUP_2 as *mut i32);
            wait(TASK_GROUP_2 as *mut i32);
        }
    }

    /// # Safety
    ///
    /// Must be called on the main thread, between frames.
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
        if commit < THRESHOLD {
            self.requested.store(false, Ordering::Release);
            self.active.store(false, Ordering::Release);
            return;
        }

        let manager = unsafe { *(GAME_MANAGER_PTR as *const *mut c_void) };
        if manager.is_null() {
            self.requested.store(false, Ordering::Release);
            self.active.store(false, Ordering::Release);
            return;
        }

        let find_cell = match unsafe { self.find_cell.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] FindCellToUnload: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let process_cleanup = match unsafe { self.process_cleanup.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] ProcessPendingCleanup: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let set_tls_flag = match unsafe { self.set_tls_flag.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] SetTlsCleanupFlag: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let process_deferred = match unsafe { self.process_deferred.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] ProcessDeferredDestruction: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };

        // ===================================================================
        // Safe cleanup sequence:
        //
        // 1. Drain PPL task groups — waits for all AI physics tasks to finish.
        //    No AI thread is touching hkBSHeightFieldShape after this.
        //    (Same mechanism used by cell transition handler FUN_008774a0,
        //     but without touching the music system.)
        //
        // 2. Unload cells + process pending cleanup
        //
        // 3. ProcessDeferredDestruction — safe: AI tasks drained
        //
        // 4. Collect freed mimalloc pages
        // ===================================================================

        // 1. Drain AI tasks
        unsafe { self.drain_task_groups() };

        // 2. Unload cells
        unsafe { set_tls_flag(0) };

        let mut cells: usize = 0;
        for _ in 0..MAX_CELLS_PER_CYCLE {
            let result = unsafe { find_cell(manager) };
            if (result & 0xFF) != 0 {
                cells += 1;
            } else {
                break;
            }
        }

        unsafe { process_cleanup(manager, 0) };
        unsafe { set_tls_flag(1) };

        // 3. Deferred destruction — safe: AI tasks are drained
        unsafe { process_deferred(1) };

        // 4. Collect freed pages
        unsafe { mi_collect(false) };

        self.last_time_ms.store(now_ms, Ordering::Relaxed);

        if cells > 0 {
            self.relief_count.fetch_add(1, Ordering::Relaxed);
            self.cells_unloaded.fetch_add(cells as i64, Ordering::Relaxed);
            log::info!(
                "[PRESSURE] Unloaded {} cells (commit={}MB)",
                cells,
                commit / 1024 / 1024,
            );
        } else {
            self.requested.store(false, Ordering::Release);
        }

        self.active.store(false, Ordering::Release);
    }
}

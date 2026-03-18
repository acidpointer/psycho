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
//! This module implements a deferred pressure relief system:
//! - `check()` is called periodically from `hook_gheap_alloc` to detect pressure.
//! - `relieve()` is called from the main-loop hook (between frames) to perform
//!   cell unloading at a safe point — no render objects or AI physics in use.

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::LazyLock;

use libmimalloc::mi_collect;
use libpsycho::ffi::fnptr::FnPtr;

use super::types::{
    FindCellToUnloadFn, ProcessDeferredDestructionFn, ProcessPendingCleanupFn,
    SetTlsCleanupFlagFn,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Trigger cell cleanup when commit exceeds this (bytes).
const THRESHOLD: usize = 700 * 1024 * 1024;

/// Max cells to unload per relief cycle.
const MAX_CELLS_PER_CYCLE: usize = 15;

/// Minimum milliseconds between relief cycles.
/// AI threads hold references to physics objects in cells — this cooldown
/// gives them time to finish current raycasts before we unload more cells.
const COOLDOWN_MS: u64 = 3000;

// ---------------------------------------------------------------------------
// Game function addresses (Fallout New Vegas)
// ---------------------------------------------------------------------------

const FIND_CELL_TO_UNLOAD: usize = 0x00453A80;
const PROCESS_PENDING_CLEANUP: usize = 0x00452490;
const SET_TLS_CLEANUP_FLAG: usize = 0x00869190;
const PROCESS_DEFERRED_DESTRUCTION: usize = 0x00868D70;

/// DAT_011dea10 — pointer to the game's TES/DataHandler manager singleton.
const GAME_MANAGER_PTR: usize = 0x011DEA10;

// ---------------------------------------------------------------------------
// PressureRelief
// ---------------------------------------------------------------------------

pub struct PressureRelief {
    /// Set by `check()` when commit > threshold. Cleared after relief.
    requested: AtomicBool,

    /// Reentrancy guard — cell unloading re-enters our alloc/free hooks.
    active: AtomicBool,

    /// Timestamp of last relief (ms since process start).
    last_time_ms: AtomicU64,

    /// Cumulative stats.
    relief_count: AtomicI64,
    cells_unloaded: AtomicI64,

    // Cached game function pointers (validated once at construction).
    find_cell: FnPtr<FindCellToUnloadFn>,
    process_cleanup: FnPtr<ProcessPendingCleanupFn>,
    set_tls_flag: FnPtr<SetTlsCleanupFlagFn>,
    process_deferred: FnPtr<ProcessDeferredDestructionFn>,
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

    /// Singleton access. Returns `None` if initialization failed.
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

    /// Lightweight pressure check. Sets a flag if commit > threshold.
    /// Called periodically from `hook_gheap_alloc`.
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

    /// Returns `(relief_count, cells_unloaded)` for logging.
    pub fn stats(&self) -> (i64, i64) {
        (
            self.relief_count.load(Ordering::Relaxed),
            self.cells_unloaded.load(Ordering::Relaxed),
        )
    }

    /// Perform pressure relief if requested. Called from the main-loop hook
    /// (between frames, on the main thread, before rendering).
    ///
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

        // Cooldown
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let now_ms = info.get_elapsed_ms() as u64;
        let last_ms = self.last_time_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_ms) < COOLDOWN_MS {
            self.active.store(false, Ordering::Release);
            return;
        }

        // Re-check commit
        let commit = info.get_current_commit();
        if commit < THRESHOLD {
            self.requested.store(false, Ordering::Release);
            self.active.store(false, Ordering::Release);
            return;
        }

        // Read game manager pointer
        let manager = unsafe { *(GAME_MANAGER_PTR as *const *mut c_void) };
        if manager.is_null() {
            self.requested.store(false, Ordering::Release);
            self.active.store(false, Ordering::Release);
            return;
        }

        // Resolve cached function pointers
        let find_cell = match unsafe { self.find_cell.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] FindCellToUnload resolve failed: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let process_cleanup = match unsafe { self.process_cleanup.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] ProcessPendingCleanup resolve failed: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let set_tls_flag = match unsafe { self.set_tls_flag.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] SetTlsCleanupFlag resolve failed: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let process_deferred = match unsafe { self.process_deferred.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] ProcessDeferredDestruction resolve failed: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };

        // HeapCompact stages 4+5 (between frames):
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
        unsafe { process_deferred(1) };
        unsafe { mi_collect(false) };

        // Re-check commit after cleanup
        let info2 = libmimalloc::process_info::MiMallocProcessInfo::get();
        let new_commit = info2.get_current_commit();
        if new_commit < THRESHOLD {
            self.requested.store(false, Ordering::Release);
        }

        self.last_time_ms.store(now_ms, Ordering::Relaxed);

        if cells > 0 {
            self.relief_count.fetch_add(1, Ordering::Relaxed);
            self.cells_unloaded.fetch_add(cells as i64, Ordering::Relaxed);
            log::info!(
                "[PRESSURE] Unloaded {} cells (commit={}MB -> {}MB)",
                cells,
                commit / 1024 / 1024,
                new_commit / 1024 / 1024,
            );
        }

        self.active.store(false, Ordering::Release);
    }
}

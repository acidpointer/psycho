//! Memory pressure relief for the game heap.
//!
//! # Hook position: FUN_0086ff70 (post-render, line 485)
//!
//! The hook runs AFTER both the render pipeline and AI tasks have completed
//! for the current frame. This is the only safe position:
//!
//! - **Pre-render hooks (line 273)**: Crash — render pipeline still needs
//!   scene graph data from cells we're unloading (BSTreeNode use-after-free).
//! - **Post-AI hooks (line 485)**: Safe for cell unloading — render is done,
//!   AI tasks are done, scene data is no longer needed for this frame.
//!
//! We only call `FindCellToUnload + ProcessPendingCleanup`. We do NOT call
//! `ProcessDeferredDestruction` — AI threads from the NEXT frame's dispatch
//! may hold references to physics objects. The game's own deferred destruction
//! runs at internally-synchronized points.

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::LazyLock;

use libmimalloc::mi_collect;
use libpsycho::ffi::fnptr::FnPtr;

use super::types::{FindCellToUnloadFn, ProcessPendingCleanupFn, SetTlsCleanupFlagFn};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Trigger cell cleanup when commit exceeds this (bytes).
const THRESHOLD: usize = 700 * 1024 * 1024;

/// Max cells to unload per relief cycle.
const MAX_CELLS_PER_CYCLE: usize = 20;

/// Minimum milliseconds between relief cycles.
const COOLDOWN_MS: u64 = 2000;

// ---------------------------------------------------------------------------
// Game function addresses (Fallout New Vegas)
// ---------------------------------------------------------------------------

const FIND_CELL_TO_UNLOAD: usize = 0x00453A80;
const PROCESS_PENDING_CLEANUP: usize = 0x00452490;
const SET_TLS_CLEANUP_FLAG: usize = 0x00869190;

/// DAT_011dea10 — pointer to the game's TES/DataHandler manager singleton.
const GAME_MANAGER_PTR: usize = 0x011DEA10;

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

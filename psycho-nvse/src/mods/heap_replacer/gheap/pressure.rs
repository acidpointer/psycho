//! Memory pressure relief for the game heap.
//!
//! Pressure detection is handled by the watchdog thread (watchdog.rs).
//! This module provides:
//!   - Baseline commit calibration
//!   - Deferred cell unload (signaled by watchdog, executed at AI_JOIN)
//!   - Destruction protocol (Havok lock + FindCellToUnload + pool drain)
//!   - Loading state counter management
//!
//! # Hook positions
//!
//!   Phase 7  (hook_per_frame_queue_drain): watchdog flag consumption
//!   Phase 10 (hook_main_loop_maintenance): baseline calibration
//!   AI_JOIN  (hook_ai_thread_join): deferred cell unload execution

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::LazyLock;

use super::engine::globals;

/// Max cells to unload per relief cycle.
const MAX_CELLS_PER_CYCLE: usize = 20;

// ---------------------------------------------------------------------------
// PressureRelief
// ---------------------------------------------------------------------------

/// Manages deferred cell unloading and baseline commit tracking.
///
/// Pressure detection is handled by the watchdog thread. This struct
/// holds the deferred-unload flag (set by watchdog, consumed at AI_JOIN)
/// and the baseline commit used for threshold computation.
pub struct PressureRelief {
    /// Set by destruction_protocol when cells were unloaded. The loading
    /// state counter is kept elevated to suppress PLChangeEvent dispatch.
    /// `flush_pending_counter_decrement()` decrements it on the next frame.
    pending_counter_decrement: AtomicBool,

    /// Commit at first tick. Used by watchdog for threshold computation.
    baseline_commit: AtomicUsize,
}

impl PressureRelief {
    fn new() -> Self {
        log::info!("[PRESSURE] Initialized (max_cells={})", MAX_CELLS_PER_CYCLE,);

        Self {
            pending_counter_decrement: AtomicBool::new(false),
            baseline_commit: AtomicUsize::new(0),
        }
    }

    /// Get the calibrated baseline commit (0 if not yet calibrated).
    pub fn baseline_commit(&self) -> usize {
        self.baseline_commit.load(Ordering::Relaxed)
    }

    /// Measure baseline commit on first tick (main loop started, mods loaded).
    pub fn calibrate_baseline(&self) {
        if self.baseline_commit.load(Ordering::Relaxed) != 0 {
            return;
        }
        let commit = libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit();
        self.baseline_commit.store(commit, Ordering::Release);

        // Now that we know baseline, calculate VAS crisis thresholds
        // based on available VAS (from VirtualQuery at startup).
        super::allocator::calibrate_thresholds(commit);

        log::info!("[PRESSURE] Baseline calibrated: {}MB", commit / 1024 / 1024,);
    }

    /// Get the global singleton (lazily initialized).
    pub fn instance() -> Option<&'static Self> {
        static INSTANCE: LazyLock<Option<PressureRelief>> =
            LazyLock::new(|| Some(PressureRelief::new()));
        INSTANCE.as_ref()
    }

    /// Decrement the loading state counter if a previous destruction_protocol
    /// left it elevated. Called once per frame from Phase 10.
    pub fn flush_pending_counter_decrement(&self) {
        if self.pending_counter_decrement.swap(false, Ordering::AcqRel) {
            globals::loading_state_counter().fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

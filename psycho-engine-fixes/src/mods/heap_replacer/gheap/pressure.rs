//! Memory pressure relief for the game heap.
//!
//! Pressure detection is handled by the watchdog thread (watchdog.rs).
//! This module provides:
//!   - Baseline commit calibration
//!
//! # Hook positions
//!
//!   Phase 7  (hook_per_frame_queue_drain): watchdog flag consumption
//!   Phase 10 (hook_main_loop_maintenance): baseline calibration

use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// PressureRelief
// ---------------------------------------------------------------------------

/// Tracks baseline commit.
///
/// Pressure detection is handled by the watchdog thread. This struct keeps the
/// baseline commit used for threshold computation.
pub struct PressureRelief {
    /// Commit at first tick. Used by watchdog for threshold computation.
    baseline_commit: AtomicUsize,
}

impl PressureRelief {
    fn new() -> Self {
        log::info!("[PRESSURE] Initialized");

        Self {
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
}

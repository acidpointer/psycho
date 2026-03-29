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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

use super::engine::globals;
use super::pool;
use crate::mods::memory::heap_replacer::mem_stats;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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
    /// Set by watchdog (via hooks.rs) when cell unload is needed.
    /// Cleared by `run_deferred_unload()` at AI_JOIN.
    deferred_unload: AtomicBool,

    /// Set by destruction_protocol when cells were unloaded. The loading
    /// state counter is kept elevated to suppress PLChangeEvent dispatch.
    /// `flush_pending_counter_decrement()` decrements it on the next frame.
    pending_counter_decrement: AtomicBool,

    /// Commit at first tick. Used by watchdog for threshold computation.
    baseline_commit: std::sync::atomic::AtomicUsize,
}

impl PressureRelief {
    fn new() -> Self {
        log::info!(
            "[PRESSURE] Initialized (max_cells={})",
            MAX_CELLS_PER_CYCLE,
        );

        Self {
            deferred_unload: AtomicBool::new(false),
            pending_counter_decrement: AtomicBool::new(false),
            baseline_commit: std::sync::atomic::AtomicUsize::new(0),
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
        let commit = libmimalloc::process_info::MiMallocProcessInfo::get()
            .get_current_commit();
        self.baseline_commit.store(commit, Ordering::Release);
        log::info!(
            "[PRESSURE] Baseline calibrated: {}MB",
            commit / 1024 / 1024,
        );
    }

    /// Get the global singleton (lazily initialized).
    pub fn instance() -> Option<&'static Self> {
        static INSTANCE: LazyLock<Option<PressureRelief>> = LazyLock::new(|| {
            Some(PressureRelief::new())
        });
        INSTANCE.as_ref()
    }

    /// Signal that cell unload should run at the next AI_JOIN.
    /// Called from hooks.rs when watchdog requests aggressive cleanup.
    pub fn set_deferred_unload(&self) {
        self.deferred_unload.store(true, Ordering::Release);
    }

    /// Clear the deferred unload flag. Called from on_ai_join when
    /// post-load cooldown is active -- prevents destruction_protocol
    /// from running during post-load init.
    pub fn clear_deferred_unload(&self) {
        self.deferred_unload.store(false, Ordering::Release);
    }

    /// Flag that loading counter needs decrementing next frame.
    pub fn set_pending_counter_decrement(&self) {
        self.pending_counter_decrement.store(true, Ordering::Release);
    }

    /// Decrement the loading state counter if a previous destruction_protocol
    /// left it elevated. Called once per frame from Phase 10.
    pub fn flush_pending_counter_decrement(&self) {
        if self.pending_counter_decrement.swap(false, Ordering::AcqRel) {
            globals::loading_state_counter()
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Run deferred cell unload after AI_JOIN. Called from the AI thread
    /// join hook after AI threads have completed their work.
    ///
    /// AI threads are idle here, so mi_collect(true) and cell unload are safe.
    /// Watchdog handles cooldown — we just execute when signaled.
    pub unsafe fn run_deferred_unload(&self) {
        if !self.deferred_unload.load(Ordering::Acquire) {
            return;
        }

        self.deferred_unload.store(false, Ordering::Release);

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();

        // Aggressive collect: safe here because AI threads are joined.
        unsafe { libmimalloc::mi_collect(true) };
        log::info!(
            "[PRESSURE] Post AI_JOIN collect: commit={}MB, RSS={}MB",
            info.get_current_commit() / 1024 / 1024,
            info.get_current_rss() / 1024 / 1024,
        );

        let manager = match globals::game_manager() {
            Some(m) => m,
            None => return,
        };

        let cells = unsafe { Self::destruction_protocol(manager) };

        mem_stats::global().record_pressure_relief(cells);

        if cells > 0 {
            self.pending_counter_decrement.store(true, Ordering::Release);
            log::info!(
                "[PRESSURE] Deferred unload: {} cells (commit={}MB)",
                cells,
                libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
            );
        }
    }

    // Cell unloading + PDD drain with large bypass.
    //
    // Sequence:
    //   1. Suppress NVSE events (loading counter + TLS flag).
    //   2. Lock Havok (pre_destruction_setup).
    //   3. Enable large bypass.
    //   4. FindCellToUnload loop (queues PDD entries).
    //   5. Pump PDD to process queued destruction WITH bypass active.
    //      This is critical: FindCellToUnload only queues, PDD does
    //      the actual frees. Bypass must be on during PDD.
    //   6. Unlock Havok, disable bypass.
    //   7. drain_large + mi_collect to decommit freed pages.
    //
    // Safety: must be called on the main thread when AI threads are idle.
    unsafe fn destruction_protocol(manager: *mut libc::c_void) -> usize {
        let mut cells: usize = 0;

        // Suppress NVSE event dispatch during destruction.
        let loading_counter = globals::loading_state_counter();
        loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        // pre_destruction_setup: locks Havok world + invalidates scene graph.
        let mut state = match unsafe { globals::pre_destruction_setup() } {
            Some(s) => s,
            None => {
                loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                return 0;
            }
        };

        // Suppress NVSE PLChangeEvent dispatch via TLS flag.
        unsafe { globals::set_tls_cleanup_flag(0) };

        // Find and unload cells (queues PDD entries for later processing).
        for _ in 0..MAX_CELLS_PER_CYCLE {
            match unsafe { globals::find_cell_to_unload(manager) } {
                Some(true) => cells += 1,
                _ => break,
            }
        }

        // Clear TLS cell unload flag (re-enable event dispatch).
        unsafe { globals::set_tls_cleanup_flag(1) };

        if cells > 0 {
            log::debug!(
                "[DESTRUCTION] {} cells unloaded, pdd queued: NiNode={} Gen={} Form={}",
                cells,
                globals::pdd_queue_count(globals::PddQueue::NiNode),
                globals::pdd_queue_count(globals::PddQueue::Generic),
                globals::pdd_queue_count(globals::PddQueue::Form),
            );
        }

        unsafe { globals::post_destruction_restore(&mut state) };

        // Drain remaining large pool blocks + collect.
        if cells > 0 {
            let drained = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
            unsafe { libmimalloc::mi_collect(false) };

            let commit = libmimalloc::process_info::MiMallocProcessInfo::get()
                .get_current_commit();
            log::debug!(
                "[DESTRUCTION] Post: {} large drained, commit={}MB, pool={}MB",
                drained, commit / 1024 / 1024,
                pool::pool_held_bytes() / 1024 / 1024,
            );
        }

        if cells == 0 {
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }

        cells
    }
}

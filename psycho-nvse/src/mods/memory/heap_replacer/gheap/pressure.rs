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

        let heap = super::heap_manager::HeapManager::get();

        // Drain large pool blocks + collect before destruction.
        unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
        log::info!(
            "[PRESSURE] Post AI_JOIN drain: commit={}MB, pool={}MB",
            heap.commit_mb(), heap.pool_mb(),
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

    // Cell unloading via the game's own OOM stage executor.
    //
    // Calls run_oom_stage(5) which runs vanilla's EXACT stage 5 sequence:
    //   TLS flag → FindCellToUnload → ProcessPendingCleanup → PDD
    //   → fallthrough stage 4 (PDD again) → stage 3 (Havok GC)
    //
    // If a cell is found, stage 5 returns stage=5 (stays). We repeat
    // until no more cells or max reached. This matches how vanilla's
    // OOM handler unloads cells — same function, same context, same
    // state management. No custom Havok locking needed.
    //
    // Safety: must be called on the main thread when AI threads are idle.
    unsafe fn destruction_protocol(_manager: *mut libc::c_void) -> usize {
        let heap = super::heap_manager::HeapManager::get();
        let mut cells: usize = 0;

        // Suppress NVSE event dispatch during destruction.
        let loading_counter = globals::loading_state_counter();
        loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        // Lock Havok world + invalidate scene graph. Without this,
        // AI threads access Havok objects from unloaded cells → crash.
        let mut state = match unsafe { globals::pre_destruction_setup() } {
            Some(s) => s,
            None => {
                loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                return 0;
            }
        };

        // Run stage 5 repeatedly with Havok locked. Each call does:
        //   TLS flag + FindCellToUnload + ProcessPendingCleanup + PDD + Havok GC
        // bypass=false: frees go to pool (zombie-safe for IO thread).
        // Returns stage=5 if cell found (stay), stage=6 if none (done).
        let mut stage: i32 = 5;
        for _ in 0..MAX_CELLS_PER_CYCLE {
            let (next, _) = unsafe { heap.run_oom_stage(stage, false) };
            if next != 5 {
                break;
            }
            cells += 1;
            stage = next;
        }

        // DeferredCleanupSmall (FUN_00878250): processes freed objects
        // from cell unload that are stuck in async queues and caches.
        //   → PDD purge (FUN_00868d70)
        //   → Async flush (FUN_00b5fd60) — releases async references
        //   → Model cleanup (FUN_00651e30/40) — frees scene graph models
        //   → Cancel stale IO tasks (FUN_00448620)
        //   → Texture cache flush (FUN_00452490)
        //
        // Without this, cell unload queues objects for destruction but
        // they aren't fully processed until next frame's Phase 4. By
        // then new cells load and commit climbs back up.
        // param = state[5] from pre_destruction_setup.
        if cells > 0 {
            unsafe { globals::deferred_cleanup_small(state[5]) };
        }

        unsafe { globals::post_destruction_restore(&mut state) };

        // Drain pool to reclaim VAS. Small zombie blocks prevent
        // mimalloc segments from becoming fully free — only drain_all
        // releases enough for large allocations (22MB+).
        //
        // Safe here: AI is idle (AI_JOIN), Havok unlocked, NVSE events
        // suppressed (loading counter elevated).
        // IO check: skip full drain if BSTaskManagerThread is busy
        // loading — IO thread may access freed zombie blocks.
        let drained = if !globals::is_bst_cell_load_pending() {
            unsafe { pool::pool_drain_all() }
        } else {
            unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) }
        };
        unsafe { libmimalloc::mi_collect(false) };

        log::debug!(
            "[DESTRUCTION] {} cells, {} drained, io_busy={}, commit={}MB, pool={}MB",
            cells, drained, globals::is_bst_cell_load_pending(),
            heap.commit_mb(), heap.pool_mb(),
        );

        if cells == 0 {
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }

        cells
    }
}

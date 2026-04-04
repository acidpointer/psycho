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

use super::engine::{addr, globals};
use crate::mods::memory::heap_replacer::mem_stats;

/// Number of full OOM cleanup rounds to run per pressure relief cycle.
///
/// IMPORTANT: This MUST be 1.
/// The vanilla game's HeapCompact loop (0x00878080) has a built-in safety
/// check: `if (current_stage < loop_counter) break;`.
/// When Stage 5 (Cell Unload) succeeds, it returns 5. The loop counter
/// becomes 6. The check `5 < 6` is true, so it breaks immediately.
/// The game relies on this to unload only ONE cell per HeapCompact call,
/// allowing the engine time to update references before the next unload.
/// Running multiple rounds unloads cells too aggressively, causing UAF
/// crashes in AI threads (e.g., projectiles referencing unloaded cells).
const DESTRUCTION_ROUNDS: usize = 1;

/// Maximum number of destruction protocol runs per Phase 7 call.
/// When allocation rate is high, we run cleanup multiple times in one frame
/// to catch up with allocation spikes. Each run blocks new cell loads briefly,
/// unloads eligible cells, then restores loading. This ensures we free
/// enough memory during stress testing without running multiple rounds
/// per protocol (which causes UAF).
const MAX_DESTRUCTION_RUNS_PER_FRAME: usize = 3;

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
    /// Watchdog handles cooldown -- we just execute when signaled.
    /// Run deferred cell unload if flagged. Called from AI_JOIN.
    pub unsafe fn run_deferred_unload(&self) {
        if !self.deferred_unload.load(Ordering::Acquire) {
            return;
        }
        self.deferred_unload.store(false, Ordering::Release);
        unsafe { self.run_cleanup() };
    }

    /// Run cell unload + full cleanup unconditionally.
    /// Safe to call from Phase 7 (before AI_START) or AI_JOIN.
    ///
    /// When allocation rate is high, we run the destruction protocol
    /// multiple times to catch up with allocation spikes.
    ///
    /// Strategy:
    /// 1. Block loading ONCE for entire cleanup cycle
    /// 2. Wait for pending load to finish (up to 100ms)
    /// 3. Run cleanup stages repeatedly, unloading up to MAX cells total
    /// 4. Restore loading only when done
    ///
    /// This ensures we don't unload cells while game loads, and we don't
    /// alternate between unloading and loading within a single cleanup.
    pub unsafe fn run_cleanup(&self) {
        let heap = super::heap_manager::HeapManager::get();

        let manager = match globals::game_manager() {
            Some(m) => m,
            None => return,
        };

        // Block new cell loads for entire cleanup cycle.
        let loading_flag = addr::LOADING_FLAG as *mut u8;
        let was_loading = unsafe { *loading_flag };
        unsafe { *loading_flag = 1 };

        // Wait for pending load to finish before cleanup.
        if globals::is_bst_cell_load_pending() {
            const MAX_WAIT_MS: u32 = 100;
            const SLEEP_MS: u32 = 1;
            for _ in 0..MAX_WAIT_MS / SLEEP_MS {
                if !globals::is_bst_cell_load_pending() {
                    break;
                }
                libpsycho::os::windows::winapi::sleep(SLEEP_MS);
            }
            // If still loading after 100ms, abort cleanup.
            if globals::is_bst_cell_load_pending() {
                unsafe { *loading_flag = was_loading };
                return;
            }
        }

        let mut total_cells: usize = 0;

        // Run destruction protocol multiple times while loading is blocked.
        // This ensures we unload cells without competition from loading.
        for _ in 0..MAX_DESTRUCTION_RUNS_PER_FRAME {
            let cells = unsafe { Self::destruction_protocol_internal(manager) };
            total_cells += cells;

            // If no cells were unloaded, more runs won't help -- stop early.
            if cells == 0 {
                break;
            }
        }

        // Restore loading: allow new cell loads to resume.
        unsafe { *loading_flag = was_loading };

        mem_stats::global().record_pressure_relief(total_cells);

        if total_cells > 0 {
            self.pending_counter_decrement.store(true, Ordering::Release);
            log::info!(
                "[PRESSURE] Cleanup: {} cells (commit={}MB, pool={}MB)",
                total_cells, heap.commit_mb(), heap.pool_mb(),
            );
        }
    }

    // Cell unloading via the game's own OOM stage executor.
    //
    // Internal version: does NOT manage the loading flag.
    // Caller must block/restore loading before/after calling this.
    //
    // We run the FULL OOM sequence (stages 0-6), not just cell unload:
    //   Stage 0: Texture cache flush (frees cached textures)
    //   Stage 1: Free cached geometry (frees mesh data)
    //   Stage 2: Menu system cleanup (frees UI resources)
    //   Stage 3: Havok GC (frees physics data)
    //   Stage 4: PDD purge (processes deferred destruction)
    //   Stage 5: Cell unloading (FindCellToUnload + ProcessPendingCleanup)
    //   Stage 6: Heap defragmentation (compacts VA space)
    //
    // The game's OOM handler runs these sequentially for a reason:
    // each stage frees different types of memory. Cell unload alone
    // only frees cell data -- we miss textures, geometry, physics,
    // and heap fragmentation. Running all stages frees significantly
    // more memory per pressure relief cycle.
    //
    // bypass=false: frees go to pool (zombie-safe for IO thread).
    //
    // Safety: must be called on the main thread when AI threads are idle.
    // Caller must have already blocked loading and waited for pending load.
    unsafe fn destruction_protocol_internal(_manager: *mut libc::c_void) -> usize {
        let heap = super::heap_manager::HeapManager::get();
        let mut cells: usize = 0;

        // Suppress NVSE event dispatch during destruction.
        let loading_counter = globals::loading_state_counter();
        loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        // Lock Havok world + invalidate scene graph. Without this,
        // AI threads access Havok objects from unloaded cells --> crash.
        let mut state = match unsafe { globals::pre_destruction_setup() } {
            Some(s) => s,
            None => {
                loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                return 0;
            }
        };

        // Run full OOM sequence for 2 rounds.
        // Each stage frees different types of memory:
        //   0: Texture cache flush
        //   1: Cached geometry free
        //   2: Menu system cleanup
        //   3: Havok GC
        //   4: PDD purge (+ fallthrough to 3)
        //   5: Cell unload (+ fallthrough to 4+3)
        //   6: Heap defragmentation
        //
        // Running 2 rounds unloads more cells because:
        // - First round: unloads immediately eligible cells
        // - After first round: references released, NPCs move, paths cleared
        // - Second round: additional cells become eligible
        // Total: 4-6 cells per cycle vs 2 with single round.
        for _round in 0..DESTRUCTION_ROUNDS {
            for stage in 0..=6 {
                let (next, _done) = unsafe { heap.run_oom_stage(stage, false) };
                if next == 5 {
                    cells += 1;
                }
            }
        }

        // DeferredCleanupSmall (FUN_00878250): processes freed objects
        // from cell unload that are stuck in async queues and caches.
        //   --> PDD purge (FUN_00868d70)
        //   --> Async flush (FUN_00b5fd60) -- releases async references
        //   --> Model cleanup (FUN_00651e30/40) -- frees scene graph models
        //   --> Cancel stale IO tasks (FUN_00448620)
        //   --> Texture cache flush (FUN_00452490)
        //
        // Without this, cell unload queues objects for destruction but
        // they aren't fully processed until next frame's Phase 4. By
        // then new cells load and commit climbs back up.
        // param = state[5] from pre_destruction_setup.
        if cells > 0 {
            unsafe { globals::deferred_cleanup_small(state[5]) };
        }

        // Gentle GC only -- decommits free pages to reclaim VAS.
        // Do NOT drain pool aggressively. The quarantine protects
        // objects still referenced by renderer. Let objects age out
        // naturally through pool eviction when capacity is reached.
        // Aggressive draining causes rendering corruption (geometry
        // disappears, occlusion glitches) because freed blocks get
        // reused for unrelated data while renderer still holds refs.
        unsafe { libmimalloc::mi_collect(false) };

        unsafe { globals::post_destruction_restore(&mut state) };

        log::debug!(
            "[DESTRUCTION] {} cells, full OOM 0-6 done, commit={}MB, pool={}MB",
            cells, heap.commit_mb(), heap.pool_mb(),
        );

        if cells == 0 {
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }

        cells
    }
}

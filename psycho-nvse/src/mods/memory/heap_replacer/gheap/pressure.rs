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

        // Now that we know baseline, calculate VAS crisis thresholds
        // based on available VAS (from VirtualQuery at startup).
        super::allocator::calibrate_thresholds(commit);

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

    /// Decrement the loading state counter if a previous destruction_protocol
    /// left it elevated. Called once per frame from Phase 10.
    pub fn flush_pending_counter_decrement(&self) {
        if self.pending_counter_decrement.swap(false, Ordering::AcqRel) {
            globals::loading_state_counter()
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Run cell unload + full cleanup unconditionally.
    /// Safe to call from Phase 7 (before AI_START) or AI_JOIN.
    ///
    /// The vanilla game runs HeapCompact once per trigger without manipulating
    /// the loading flag. We follow the same pattern: run one cleanup cycle,
    /// let the game manage its own loading state.
    pub unsafe fn run_cleanup(&self) {
        let heap = super::heap_manager::HeapManager::get();

        let manager = match globals::game_manager() {
            Some(m) => m,
            None => return,
        };

        let cells = unsafe { Self::destruction_protocol(manager) };

        mem_stats::global().record_pressure_relief(cells);

        if cells > 0 {
            self.pending_counter_decrement.store(true, Ordering::Release);
            log::info!(
                "[PRESSURE] Cleanup: {} cells (commit={}MB, pool={}MB)",
                cells, heap.commit_mb(), heap.pool_mb(),
            );
        }
    }

    // Cell unloading via the game's own OOM stage executor.
    //
    // Run only Stage 5 (Cell Unload).
    //
    // Stage 5 falls through to Stage 4 and Stage 3 automatically
    // (no break statements in the game's switch case at 0x00866a90):
    //   Stage 5: FindCellToUnload + PDD + Async flush + Texture cache
    //   Stage 4: PDD purge + Havok GC
    //   Stage 3: Havok GC
    //
    // Stages 0, 1, 2 are NOT run because:
    //   Stage 0 (texture cache): Only frees during loading, NO-OP during gameplay
    //   Stage 1 (geometry cache): Only frees during loading, NO-OP during gameplay
    //   Stage 2 (menu cleanup): Only frees during loading, NO-OP during gameplay
    //   Stage 6 (heap defrag / SBM GlobalCleanup): ALLOCATES temporary memory
    //
    // Running stages 0-6 was counterproductive: stages 0-2 do nothing
    // during active gameplay, and stage 6 allocates memory (gained=212KB
    // in stress tests), negating the freed memory from stages 3-5.
    //
    // bypass=false: frees go to pool (zombie-safe for IO thread).
    //
    // Safety: must be called on the main thread when AI threads are idle.
    unsafe fn destruction_protocol(_manager: *mut libc::c_void) -> usize {
        let heap = super::heap_manager::HeapManager::get();
        let mut cells: usize = 0;

        // Suppress NVSE event dispatch during destruction.
        let loading_counter = globals::loading_state_counter();
        loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        // Run loading stages 0-2 BEFORE attempting Havok lock.
        // During fast travel, Havok is often busy or uninitialized, causing
        // pre_destruction_setup to fail. Stages 0-2 (Texture/Geometry cache
        // flush) do NOT require the Havok lock and can run safely at any time.
        // This ensures we free cache memory even if the Havok lock fails.
        if globals::is_loading() {
            unsafe { heap.run_oom_stage(0, false) };
            unsafe { heap.run_oom_stage(1, false) };
            unsafe { heap.run_oom_stage(2, false) };
        }

        // Check if Havok is already locked before attempting to lock.
        // If Havok is already locked (e.g., console command during Phase 7 cleanup),
        // pre_destruction_setup would deadlock because hkWorld_Lock is a spin-lock
        // with no timeout. Skip cleanup to avoid hard freeze.
        if crate::mods::memory::heap_replacer::gheap::game_guard::is_havok_active() {
            log::warn!(
                "[DESTRUCTION] Havok already locked (physics in progress), skipping cleanup"
            );
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            return 0;
        }

        // Lock Havok world + invalidate scene graph. Without this,
        // AI threads access Havok objects from unloaded cells --> crash.
        let mut state = match unsafe { globals::pre_destruction_setup() } {
            Some(s) => s,
            None => {
                // Havok lock failed (physics busy). Run Havok-independent
                // cleanup as fallback: Havok GC + PDD purge + pool drain.
                // This is significantly better than doing nothing.
                //
                // Ghidra-verified: Havok GC (FUN_00c459d0) operates on
                // hkMemorySystem, NOT the physics world -- no lock needed.
                // PDD purge (FUN_00868d70) only needs process manager lock.
                log::debug!(
                    "[DESTRUCTION] Havok lock failed, running fallback cleanup"
                );
                unsafe { globals::havok_gc(1) }; // force=true
                unsafe { globals::pdd_purge() };
                unsafe { libmimalloc::mi_collect(false) };
                let drained = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
                unsafe { libmimalloc::mi_collect(false) };

                loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                log::debug!(
                    "[DESTRUCTION] Fallback cleanup: {} drained, commit={}MB",
                    drained, heap.commit_mb(),
                );
                return 0;
            }
        };

        // Wait 10ms for any in-flight AI thread operations to complete.
        // pre_destruction_setup locks Havok (prevents NEW operations) but
        // doesn't stop AI threads that are already mid-raycast. This brief
        // pause ensures stale readers finish before we start freeing terrain.
        libpsycho::os::windows::winapi::sleep(10);

        // Run Stage 5 in a loop until game says no more cells eligible.
        // Each call runs 5 --> 4 --> 3 automatically (fallthrough in switch case).
        // The game's FindCellToUnload returns no cell when none are eligible,
        // causing stage to advance to 6.
        let mut stage: i32 = 5;
        loop {
            let (next, _done) = unsafe { heap.run_oom_stage(stage, false) };
            if next == 5 {
                cells += 1;
                stage = next;
            } else {
                break;
            }
        }

        // DeferredCleanupSmall ONCE after ALL cells unloaded.
        // This processes the complete set of queued references from all cells.
        if cells > 0 {
            unsafe { globals::deferred_cleanup_small(state[5]) };
        }

        // mi_collect after async flush completes all deferred destruction.
        unsafe { libmimalloc::mi_collect(false) };

        // Drain pool AFTER cell unload + async flush.
        //
        // Always use pool_drain_large (>= 1KB), NEVER pool_drain_all.
        // Small objects like BSMultiBoundNode, NiNodes, and NiTransformInterpolators
        // are still referenced by persistent scene graph structures (LandLOD)
        // across cell transitions. Draining them causes UAF crashes.
        //
        // Large blocks (>= 1KB) are typically cell data, geometry, textures -
        // safe to free because their owning cells are being destroyed.
        let drained = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
        unsafe { libmimalloc::mi_collect(false) };

        unsafe { globals::post_destruction_restore(&mut state) };

        log::debug!(
            "[DESTRUCTION] {} cells, {} drained, commit={}MB, pool={}MB",
            cells, drained, heap.commit_mb(), heap.pool_mb(),
        );

        if cells == 0 {
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }

        cells
    }
}

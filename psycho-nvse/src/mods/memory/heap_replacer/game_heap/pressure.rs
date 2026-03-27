// Memory pressure relief for the game heap.
//
// # Hook position: FUN_008705d0 (post-render, PRE-AI_JOIN)
//
// WARNING: The hook runs AFTER render but BEFORE AI_JOIN.
// AI Linear Task Threads are STILL ACTIVE at our hook position.
// Never call mi_collect(true) or acquire write locks here.
//
//   0x0086eac9  HeapCompact       -- Phase 6
//   0x0086eadf  PerFrameDrain     -- Phase 7 (our queue drain hook)
//   0x0086ec87  AI_START          -- Phase 8, AI threads dispatched
//   0x0086ecba  RENDER            -- Phase 9 (AI running parallel)
//   0x0086edf0  OUR_HOOK          -- HERE: AI still running
//   0x0086ee4e  AI_JOIN           -- Phase 10, AI threads joined
//   0x0086ee62  POST_AI           -- Phase 11
//
// # Multi-layer pressure relief
//
// Layer 1 -- Post-render cell unloading + PDD (this module).
// Unloads cells using the game's destruction protocol: loading state
// counter, hkWorld_Lock, SceneGraphInvalidate, FindCellToUnload,
// DeferredCleanupSmall (PDD + blocking async flush).
//
// Layer 2 -- Boosted per-frame NiNode drain (FUN_00868850 hook).
// Under pressure, calls the game's per-frame drain 20x instead of 1x,
// draining 200-400 NiNodes per frame.
//
// Layer 3 -- HeapCompact trigger (heap_singleton + 0x134).
// Under pressure, writes 4 to the HeapCompact trigger field. On the
// next frame, HeapCompact runs stages 0-4 (texture flush, geometry,
// menu, Havok GC, PDD purge). Stage 5 (cell unloading) is NEVER
// triggered -- it deadlocks during fast travel and loading screens.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::LazyLock;

use libmimalloc::mi_collect;

use super::engine::{globals, io_sync};
use crate::mods::memory::heap_replacer::mem_stats;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Maximum commit growth above baseline before triggering pressure relief.
// 500MB balances normal gameplay headroom with stress test stability.
const MAX_GROWTH_ABOVE_BASELINE: usize = 500 * 1024 * 1024;

// Max cells to unload per relief cycle.
const MAX_CELLS_PER_CYCLE: usize = 20;

// Minimum milliseconds between relief cycles (stages 0-3).
const COOLDOWN_MS: u64 = 2000;

// Minimum milliseconds between aggressive relief (mi_collect(true)).
// Force collect walks all pages -- expensive but actually frees memory.
// Only triggers when commit exceeds baseline + 2x MAX_GROWTH.
const AGGRESSIVE_COOLDOWN_MS: u64 = 10_000;

// ---------------------------------------------------------------------------
// PressureRelief
// ---------------------------------------------------------------------------

pub struct PressureRelief {
    requested: AtomicBool,
    active: AtomicBool,
    last_time_ms: AtomicU64,

    // Set by relieve() when aggressive collection is needed but AI threads
    // are still active. Cleared by run_deferred_unload() from the AI thread
    // join hook (after AI threads are idle).
    deferred_unload: AtomicBool,

    // Set by destruction_protocol when cells were unloaded. The loading
    // state counter is kept elevated to suppress PLChangeEvent dispatch.
    // flush_pending_counter_decrement() decrements it on the next frame.
    pending_counter_decrement: AtomicBool,

    // Commit at first tick. Dynamic threshold = baseline + MAX_GROWTH.
    baseline_commit: std::sync::atomic::AtomicUsize,

}

impl PressureRelief {
    fn new() -> Self {
        log::info!(
            "[PRESSURE] Initialized (baseline=deferred, growth={}MB, max_cells={}, cooldown={}ms)",
            MAX_GROWTH_ABOVE_BASELINE / 1024 / 1024,
            MAX_CELLS_PER_CYCLE,
            COOLDOWN_MS,
        );

        Self {
            requested: AtomicBool::new(false),
            active: AtomicBool::new(false),
            deferred_unload: AtomicBool::new(false),
            pending_counter_decrement: AtomicBool::new(false),
            last_time_ms: AtomicU64::new(0),
            baseline_commit: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    // Dynamic threshold: baseline commit + MAX_GROWTH_ABOVE_BASELINE.
    // Returns usize::MAX if baseline not yet measured (suppress all checks).
    #[inline]
    fn threshold(&self) -> usize {
        let baseline = self.baseline_commit.load(Ordering::Relaxed);
        if baseline == 0 {
            return usize::MAX;
        }
        baseline + MAX_GROWTH_ABOVE_BASELINE
    }

    /// Get the calibrated baseline commit (0 if not yet calibrated).
    pub fn baseline_commit(&self) -> usize {
        self.baseline_commit.load(Ordering::Relaxed)
    }

    // Measure baseline commit on first tick (main loop started, mods loaded).
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
            Some(PressureRelief::new())
        });
        INSTANCE.as_ref()
    }

    // Periodic check called from the allocator hot path (every 50K allocs).
    // Sets the requested flag if commit exceeds the dynamic threshold.
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

    /// Clear the deferred unload flag. Called from on_ai_join when
    /// post-load cooldown is active — prevents destruction_protocol
    /// from running during post-load init.
    pub fn clear_deferred_unload(&self) {
        self.deferred_unload.store(false, Ordering::Release);
    }

    // Flag that loading counter needs decrementing next frame.
    // Called by external code (cell_unload command, OOM recovery) that
    // ran cell unload outside the normal pressure relief path.
    pub fn set_pending_counter_decrement(&self) {
        self.pending_counter_decrement.store(true, Ordering::Release);
    }

    // Decrement the loading state counter if a previous destruction_protocol
    // left it elevated. Called once per frame from tick_rotate.
    pub fn flush_pending_counter_decrement(&self) {
        if self.pending_counter_decrement.swap(false, Ordering::AcqRel) {
            globals::loading_state_counter()
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    // Must be called on the main thread, between frames.
    //
    // Two-tier escalation:
    // - Normal (every 2s): mi_collect(false) -- reclaim retired pages.
    // - Aggressive (every 10s, commit > 2x growth): deferred to after AI_JOIN
    //   where mi_collect(true) + quarantine flush are safe.
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
        let quarantine_mb = super::orchestrator::HeapOrchestrator::quarantine_usage() / 1024 / 1024;

        // HeapCompact stage 3 ONLY from pressure relief. NEVER stage 4.
        //
        // The vanilla game NEVER signals HeapCompact during normal gameplay
        // (HEAP_COMPACT_TRIGGER has zero game references). HeapCompact is
        // OOM-only. Stage 4 (full PDD drain) processing 1000+ Gen entries
        // causes multi-second freezes — verified repeatedly.
        //
        // Stage 3 is sufficient:
        //   Stage 0: ProcessPendingCleanup → BSTreeManager::cleanup (partial)
        //   Stage 1: geometry cache free
        //   Stage 2: menu cleanup
        //   Stage 3: Havok GC + async flush (try mode)
        //
        // NiNode PDD queue stays at 0 via per-frame PDD drain (verified).
        // Stage 4 (full PDD) only runs from OOM executor inline — matching
        // vanilla behavior exactly.
        //
        // Aggressive pressure: deferred unload (flush + collect) at AI_JOIN,
        // but NO stage 4 signal.
        globals::signal_heap_compact(globals::HeapCompactStage::HavokGC);
        unsafe { mi_collect(false) };

        if commit >= aggressive_threshold {
            self.deferred_unload.store(true, Ordering::Release);
            log::warn!(
                "[PRESSURE] HeapCompact 0-3 + deferred, commit={}MB (thresh={}MB), quarantine={}MB",
                commit_mb, aggressive_threshold / 1024 / 1024, quarantine_mb,
            );
        } else {
            log::info!(
                "[PRESSURE] Relief: HeapCompact 0-3, commit={}MB, quarantine={}MB",
                commit_mb, quarantine_mb,
            );
        }

        self.last_time_ms.store(now_ms, Ordering::Relaxed);
        self.requested.store(false, Ordering::Release);
        self.active.store(false, Ordering::Release);
    }

    // Run deferred work after AI_JOIN. Called from the AI thread join
    // hook after AI threads have completed their work.
    //
    // This is the ONLY safe place for mi_collect(true) -- AI threads are
    // idle so no allocation races. Also handles deferred cell unloading
    // when not in a loading screen.
    pub unsafe fn run_deferred_unload(&self) {
        if !self.deferred_unload.load(Ordering::Acquire) {
            return;
        }

        self.deferred_unload.store(false, Ordering::Release);

        // Aggressive collect: safe here because AI threads are joined.
        static LAST_AGGRESSIVE_MS: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let now_ms = info.get_elapsed_ms() as u64;
        let last_agg = LAST_AGGRESSIVE_MS.load(Ordering::Relaxed);

        if now_ms.saturating_sub(last_agg) >= AGGRESSIVE_COOLDOWN_MS {
            LAST_AGGRESSIVE_MS.store(now_ms, Ordering::Relaxed);
            unsafe { super::orchestrator::HeapOrchestrator::flush_reclaimable_and_collect() };
            let commit_mb = info.get_current_commit() / 1024 / 1024;
            let quarantine_mb = super::orchestrator::HeapOrchestrator::quarantine_usage() / 1024 / 1024;
            log::warn!(
                "[PRESSURE] Aggressive collect (post AI_JOIN): commit={}MB, quarantine={}MB, RSS={}MB",
                commit_mb, quarantine_mb, info.get_current_rss() / 1024 / 1024,
            );
        }

        // No is_loading() check: cell unload during loading is needed —
        // the game's own OOM stage 5 does FindCellToUnload without checking
        // loading state. Unloading old cells frees VAS for new ones.

        let manager = match globals::game_manager() {
            Some(m) => m,
            None => return,
        };

        // No BST pending check: FindCellToUnload handles cell eligibility
        // internally (FUN_004511e0, FUN_00557090). BST loads NEW cells
        // while we unload OLD cells — different cells, no conflict.

        let cells = unsafe { Self::destruction_protocol(manager) };

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

    // Cell unloading + PDD sequence with IO synchronization.
    //
    // 1. Increment loading counter (suppress NVSE PLChangeEvent).
    // 2. Lock Havok world + invalidate scene graph (pre_destruction_setup).
    // 3. Loop FindCellToUnload up to MAX_CELLS_PER_CYCLE times.
    // 4. Acquire IO dequeue lock (block BSTaskManagerThread during PDD).
    // 5. Run DeferredCleanupSmall (PDD + async flush).
    // 6. Release IO lock.
    // 7. Unlock Havok world (post_destruction_restore).
    //
    // Safety: must be called on the main thread when AI threads are idle.
    unsafe fn destruction_protocol(manager: *mut libc::c_void) -> usize {
        let mut cells: usize = 0;

        // Suppress NVSE event dispatch during destruction.
        let loading_counter = globals::loading_state_counter();
        loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        // Lock order: IO → Havok (matches CellTransitionHandler to prevent deadlock).

        // 1. IO lock FIRST.
        let io_locked = unsafe { io_sync::io_lock_acquire() };

        // 2. Havok lock SECOND.
        let mut state = match unsafe { globals::pre_destruction_setup() } {
            Some(s) => s,
            None => {
                if io_locked {
                    unsafe { io_sync::io_lock_release() };
                }
                loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                return 0;
            }
        };

        // Find and unload cells.
        for _ in 0..MAX_CELLS_PER_CYCLE {
            match unsafe { globals::find_cell_to_unload(manager) } {
                Some(true) => cells += 1,
                _ => break,
            }
        }

        // Run PDD + async flush + cleanup. IO lock held to prevent BST
        // from dequeuing tasks that reference objects being destroyed.
        unsafe { globals::deferred_cleanup_small(state[5]) };

        // Release in reverse order: Havok first, then IO.
        unsafe { globals::post_destruction_restore(&mut state) };

        if io_locked {
            unsafe { io_sync::io_lock_release() };
        }

        if cells == 0 {
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }

        cells
    }
}

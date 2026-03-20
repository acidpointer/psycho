//! Memory pressure relief for the game heap.
//!
//! # Hook position: FUN_008705d0 (post-render)
//!
//! The hook runs after render but BEFORE the main loop's AI thread join
//! (FUN_008c7990 at 0x0086ee4e). AI Linear Task Threads are still active
//! at our hook position. Frame timeline (from Ghidra disassembly):
//!
//! ```text
//! 0x0086ec87  AI_START                ← AI threads dispatched
//! 0x0086ede8  RENDER                  ← Render
//! 0x0086edf0  OUR_HOOK (0x008705d0)   ← We are here
//! 0x0086ee4e  AI_JOIN (0x008c7990)    ← AI threads joined
//! 0x0086ee62  POST_AI (0x0086f6a0)    ← Post-AI cleanup
//! ```
//!
//! Before cell unloading, we explicitly call FUN_008c7990 to join AI
//! threads, and check TES+0x77c for pending BSTaskManagerThread loads.
//!
//! # Multi-layer pressure relief
//!
//! Three mechanisms work together to prevent OOM:
//!
//! ## Layer 1: Post-render cell unloading + full PDD (this module)
//! Unloads cells using the game's full destruction protocol: loading state
//! counter, hkWorld_Lock, SceneGraphInvalidate, FindCellToUnload,
//! DeferredCleanupSmall (full PDD + blocking async flush).
//!
//! ## Layer 2: Boosted per-frame NiNode drain (FUN_00868850 hook)
//! The game's per-frame queue processor runs at line ~802, before AI dispatch.
//! Under pressure, we call it 20x instead of 1x, draining ~200-400 NiNodes
//! per frame. Stops when queue 0x08 empties to avoid over-draining Havok.
//!
//! ## Layer 3: HeapCompact trigger (heap_singleton + 0x134)
//! Under pressure, we write `2` to the HeapCompact trigger field. On the
//! NEXT frame, FUN_00878080 at line ~797 runs HeapCompact stages 0-2:
//! Stage 0 (reset + ProcessPendingCleanup), Stage 1 (SBM no-op),
//! Stage 2 (BSA/texture cache cleanup).
//! Stages 3+ are EXCLUDED — Stage 5 TLS=0 + mimalloc = BSTreeNode crash.

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::LazyLock;

use libmimalloc::mi_collect;
use libpsycho::ffi::fnptr::FnPtr;

use super::types::{
    DeferredCleanupSmallFn, FindCellToUnloadFn,
    PostDestructionRestoreFn, PreDestructionSetupFn,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Enable manual cell unloading via FindCellToUnload.
/// When true, pressure relief actively unloads cells + runs selective PDD.
/// When false, relies solely on HeapCompact stages 0-2 + boosted per-frame
/// drain. Disabling eliminates all stale-pointer crashes (QueuedTexture,
/// hkBSHeightFieldShape, BSTreeNode) at the cost of higher commit under
/// extreme stress (32-bit VA ceiling reached sooner).
const CELL_UNLOAD_ENABLED: bool = true;

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
const PROCESS_DEFERRED_DESTRUCTION: usize = 0x00868D70;
/// PreDestruction_Setup: hkWorld_Lock + SceneGraphInvalidate.
const PRE_DESTRUCTION_SETUP: usize = 0x00878160;
/// PostDestruction_Restore: hkWorld_Unlock + restore state.
const POST_DESTRUCTION_RESTORE: usize = 0x00878200;
/// DeferredCleanup_Small: PDD(1) + AsyncFlush(0) + ProcessPendingCleanup.
const DEFERRED_CLEANUP_SMALL: usize = 0x00878250;

/// FUN_00713d80 — returns the AI thread manager singleton pointer.
const GET_AI_THREAD_MANAGER: usize = 0x00713D80;

/// FUN_008c7990 — waits for all AI Linear Task Threads to finish
/// their current work item. Called with the AI thread manager pointer.
///
/// The main loop calls this at 0x0086ee4e AFTER our hook (0x0086edf0).
/// Our hook runs between render and AI join — AI threads are ACTIVE.
/// We must call this before cell unloading to prevent AI threads from
/// accessing Havok/actor data for cells we're about to destroy.
const AI_THREAD_JOIN: usize = 0x008C7990;

/// DAT_011dea10 — pointer to the game's TES/DataHandler manager singleton.
const GAME_MANAGER_PTR: usize = 0x011DEA10;

/// DAT_011dea3c — pointer to the TES singleton (player, world, cells).
/// TES+0x77c holds a pending cell load task handle for BSTaskManagerThread.
/// When -1 (0xFFFFFFFF), no cell loads are pending — safe to unload cells.
/// When != -1, BSTaskManagerThread is loading cells — unloading would race.
///
/// The game's CellTransitionHandler (FUN_008774a0) waits for this via
/// FUN_00877700 → FUN_00ad8da0(TES+0x77c, 1000ms) before any cell work.
const TES_SINGLETON_PTR: usize = 0x011DEA3C;

/// Offset into TES where the pending cell load task handle lives.
const TES_PENDING_CELL_LOAD_OFFSET: usize = 0x77C;

/// DAT_011dfa19 — AI thread active flag.
/// Set to 1 by FUN_008c78c0 (AI Start, at 0x0086ec87 in per-frame).
/// Set to 0 by FUN_008c7990 (AI Join, at 0x0086ee4e in per-frame).
/// At our Hook 1 position (between dispatch and join), this is 1 when
/// AI threads are active, 0 when they were not dispatched this frame.
const AI_ACTIVE_FLAG_PTR: usize = 0x011DFA19;

/// HeapCompact trigger field: heap_singleton + 0x134.
/// Writing N causes HeapCompact stages 0..N to run on the NEXT FRAME.
const HEAP_COMPACT_TRIGGER_PTR: usize = 0x011F636C;

/// DAT_01202d6c — Loading/destruction state counter.
///
/// FUN_0043b2b0(1) increments, FUN_0043b2b0(0) decrements (InterlockedIncrement/Decrement).
/// When > 0, the game is in a loading/destruction state. Actor processing during
/// cell destruction skips event dispatching (PLChangeEvent, etc.), preventing NVSE
/// plugins (JohnnyGuitar, Stewie's Tweaks) from accessing mid-destruction objects.
///
/// The game's own PDD caller (FUN_004556d0) sets this to 1 before cleanup.
/// CellTransitionHandler runs during loading screens where this is already > 0.
/// HeapCompact Stage 5 runs in the allocation retry loop where events don't fire.
///
/// We must set this > 0 before FindCellToUnload to suppress event dispatching.
const LOADING_STATE_COUNTER_PTR: usize = 0x01202D6C;

// ---------------------------------------------------------------------------
// PressureRelief
// ---------------------------------------------------------------------------

pub struct PressureRelief {
    requested: AtomicBool,
    active: AtomicBool,
    last_time_ms: AtomicU64,

    /// Set by relieve() on multi-threaded systems when cell unloading is needed
    /// but AI threads are still active. Cleared by run_deferred_unload() which
    /// runs from the AI thread join hook (after AI threads are idle).
    deferred_unload: AtomicBool,

    find_cell: FnPtr<FindCellToUnloadFn>,
    pre_destruction: FnPtr<PreDestructionSetupFn>,
    post_destruction: FnPtr<PostDestructionRestoreFn>,
    deferred_cleanup: FnPtr<DeferredCleanupSmallFn>,
}

impl PressureRelief {
    fn new() -> anyhow::Result<Self> {
        let instance = unsafe {
            Self {
                requested: AtomicBool::new(false),
                active: AtomicBool::new(false),
                deferred_unload: AtomicBool::new(false),
                last_time_ms: AtomicU64::new(0),
                find_cell: FnPtr::from_raw(FIND_CELL_TO_UNLOAD as *mut c_void)?,
                pre_destruction: FnPtr::from_raw(PRE_DESTRUCTION_SETUP as *mut c_void)?,
                post_destruction: FnPtr::from_raw(POST_DESTRUCTION_RESTORE as *mut c_void)?,
                deferred_cleanup: FnPtr::from_raw(DEFERRED_CLEANUP_SMALL as *mut c_void)?,
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

            // Do NOT trigger HeapCompact here. check() runs from any thread
            // (including BSTaskManagerThread) every 50K allocs. HeapCompact
            // Stage 2 cleans BSA/texture caches, but without the blocking
            // async flush from relieve(), the IO thread may still hold refs
            // to textures being cleaned — NiPixelData/NiSourceTexture UAF.
            //
            // HeapCompact is triggered in relieve() after the full destruction
            // protocol (loading state, Havok lock, DeferredCleanupSmall with
            // blocking async flush) ensures all IO tasks are drained first.
        }
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Relaxed)
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
        let pre_destruction = match unsafe { self.pre_destruction.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] PreDestructionSetup: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let post_destruction = match unsafe { self.post_destruction.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] PostDestructionRestore: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };
        let deferred_cleanup = match unsafe { self.deferred_cleanup.as_fn() } {
            Ok(f) => f,
            Err(err) => {
                log::error!("[PRESSURE] DeferredCleanupSmall: {:?}", err);
                self.active.store(false, Ordering::Release);
                return;
            }
        };

        let mut cells: usize = 0;

        if CELL_UNLOAD_ENABLED {
            // === GUARD: Skip if BSTaskManagerThread is loading cells ===
            //
            // TES+0x77c holds a pending cell load task handle. When != -1,
            // BSTaskManagerThread is actively running ExteriorCellLoaderTask(s).
            // Unloading cells while the IO thread loads them causes:
            // - ExteriorCellLoaderTask::AddReference on NotLoaded cell → crash
            // - VanillaPlusSkin reading geometry from unloaded cell → ACCESS_VIOLATION
            //
            // The game's CellTransitionHandler (FUN_008774a0) WAITS for this
            // via FUN_00877700 before touching cells. We do a non-blocking check
            // and skip this cycle if busy. Pressure retries in COOLDOWN_MS.
            let io_busy = unsafe {
                let tes = *(TES_SINGLETON_PTR as *const *const u8);
                if tes.is_null() {
                    true // TES not initialized, skip
                } else {
                    let handle_ptr = tes.add(TES_PENDING_CELL_LOAD_OFFSET) as *const i32;
                    (*handle_ptr) != -1
                }
            };

            if io_busy {
                log::debug!("[PRESSURE] Skipping cell unload — BSTaskManagerThread busy");
                self.active.store(false, Ordering::Release);
                return;
            }

            // === AI THREAD SAFETY: Two-hook architecture ===
            //
            // Our hook runs at 0x008705d0, between AI dispatch (0x0086ec87)
            // and AI join (0x0086ee4e). AI threads are ACTIVE.
            //
            // On multi-threaded systems: defer cell unloading to the AI join
            // hook (FUN_008c7990 wrapper) which runs AFTER AI threads are idle.
            // On single-threaded systems: no AI threads exist, unload directly.
            let ai_active = unsafe {
                *(AI_ACTIVE_FLAG_PTR as *const u8) != 0
            };

            if ai_active {
                // Multi-threaded: defer to AI join hook
                self.deferred_unload.store(true, Ordering::Release);
                log::debug!("[PRESSURE] Cell unload deferred to AI join");
            } else {
                // Single-threaded: no AI threads, safe to unload directly
                cells = unsafe {
                    Self::destruction_protocol(
                        find_cell, pre_destruction, post_destruction,
                        deferred_cleanup, manager,
                    )
                };
            }
        }

        // Trigger HeapCompact stages 0-2 for the NEXT frame.
        unsafe {
            let trigger = HEAP_COMPACT_TRIGGER_PTR as *mut u32;
            trigger.write_volatile(2);
        }

        unsafe { mi_collect(false) };

        self.last_time_ms.store(now_ms, Ordering::Relaxed);

        // Record stats in the shared MemStats (clean separation of concerns).
        let stats = crate::mods::memory::heap_replacer::mem_stats::global();
        stats.record_pressure_relief(cells);

        let commit_mb = commit / 1024 / 1024;

        // Always clear requested so check() can re-evaluate on the next trigger.
        // If commit is still above threshold, check() will re-set it.
        self.requested.store(false, Ordering::Release);

        if CELL_UNLOAD_ENABLED && cells > 0 {
            log::info!(
                "[PRESSURE] Unloaded {} cells (commit={}MB)",
                cells,
                commit_mb,
            );
        } else {
            log::info!("[PRESSURE] Relief cycle (commit={}MB)", commit_mb);
        }

        // HUD notification only under heavy memory pressure
        if commit_mb >= 1550 {
            if cells > 0 {
                crate::nvse_services::show_notification(
                    &format!("Pip-Boy: {}MB, freed {} sectors", commit_mb, cells),
                );
            } else {
                crate::nvse_services::show_notification(
                    &format!("Pip-Boy: {}MB, cache optimized", commit_mb),
                );
            }
        }

        self.active.store(false, Ordering::Release);
    }

    /// Run deferred cell unloading. Called from the AI thread join hook
    /// (FUN_008c7990 wrapper) AFTER AI threads have completed their work.
    ///
    /// # Safety
    ///
    /// Must be called on the main thread, after AI thread join.
    pub unsafe fn run_deferred_unload(&self) {
        if !self.deferred_unload.swap(false, Ordering::AcqRel) {
            return;
        }

        let manager = unsafe { *(GAME_MANAGER_PTR as *const *mut c_void) };
        if manager.is_null() {
            return;
        }

        let find_cell = match unsafe { self.find_cell.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };
        let pre_destruction = match unsafe { self.pre_destruction.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };
        let post_destruction = match unsafe { self.post_destruction.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };
        let deferred_cleanup = match unsafe { self.deferred_cleanup.as_fn() } {
            Ok(f) => f,
            Err(_) => return,
        };

        // Check BSTaskManagerThread guard again (state may have changed)
        let io_busy = unsafe {
            let tes = *(TES_SINGLETON_PTR as *const *const u8);
            if tes.is_null() {
                true
            } else {
                let handle_ptr = tes.add(TES_PENDING_CELL_LOAD_OFFSET) as *const i32;
                (*handle_ptr) != -1
            }
        };
        if io_busy {
            log::debug!("[PRESSURE] Deferred unload skipped — BSTaskManagerThread busy");
            return;
        }

        // AI threads are idle (join completed), BSTaskManagerThread idle.
        // Run the full destruction protocol.
        let cells = unsafe {
            Self::destruction_protocol(find_cell, pre_destruction, post_destruction,
                                       deferred_cleanup, manager)
        };

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let commit_mb = info.get_current_commit() / 1024 / 1024;

        let stats = crate::mods::memory::heap_replacer::mem_stats::global();
        stats.record_pressure_relief(cells);

        if cells > 0 {
            log::info!(
                "[PRESSURE] Deferred unload: {} cells (commit={}MB)",
                cells, commit_mb,
            );
        }
    }

    /// The actual cell unloading + PDD sequence. Extracted so both
    /// relieve() (single-threaded) and run_deferred_unload() (multi-threaded)
    /// can use the same code.
    unsafe fn destruction_protocol(
        find_cell: FindCellToUnloadFn,
        pre_destruction: PreDestructionSetupFn,
        post_destruction: PostDestructionRestoreFn,
        deferred_cleanup: DeferredCleanupSmallFn,
        manager: *mut c_void,
    ) -> usize {
        let mut cells: usize = 0;

        let loading_counter =
            unsafe { &*(LOADING_STATE_COUNTER_PTR as *const std::sync::atomic::AtomicI32) };
        loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let mut state = [0u8; 12];
        let state_ptr = state.as_mut_ptr() as *mut c_void;

        unsafe { pre_destruction(state_ptr, 1, 1, 1) };

        for _ in 0..MAX_CELLS_PER_CYCLE {
            let result = unsafe { find_cell(manager) };
            if (result & 0xFF) != 0 {
                cells += 1;
            } else {
                break;
            }
        }

        unsafe { deferred_cleanup(state[5]) };
        unsafe { post_destruction(state_ptr) };

        loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);

        cells
    }
}

//! Memory pressure relief for the game heap.
//!
//! # Hook position: FUN_008705d0 (post-render, line 486)
//!
//! The hook runs AFTER both the render pipeline and AI tasks have completed
//! for the current frame. This is the only safe position:
//!
//! - **Pre-render hooks (line 273)**: Crash — render pipeline still needs
//!   scene graph data from cells we're unloading (BSTreeNode use-after-free).
//! - **Post-AI hooks (line 486)**: Safe for cell unloading — render is done,
//!   AI tasks are done, scene data is no longer needed for this frame.
//!
//! # Multi-layer pressure relief
//!
//! Three mechanisms work together to prevent OOM:
//!
//! ## Layer 1: Post-render cell unloading + selective PDD (this module)
//! Unloads cells and runs PDD with NiNode queue (0x08) skipped. Safe because
//! render is done and scene data is consumed.
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
//! Stages 3+ are EXCLUDED — Stage 3 async queue flush completes stale IO
//! tasks on freed cell data (QueuedTexture NULL vtable), Stage 4 full PDD
//! races with IO/AI threads, Stage 5 TLS=0 + mimalloc = BSTreeNode crash.

use libc::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::LazyLock;

use libmimalloc::mi_collect;
use libpsycho::ffi::fnptr::FnPtr;

use super::types::{
    DeferredCleanupSmallFn, FindCellToUnloadFn, PostDestructionRestoreFn,
    PreDestructionSetupFn,
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

/// DAT_011dea10 — pointer to the game's TES/DataHandler manager singleton.
const GAME_MANAGER_PTR: usize = 0x011DEA10;

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

            // Trigger HeapCompact stages 0-2 for the next frame.
            // Stage 0: Reset + ProcessPendingCleanup
            // Stage 1: SBM arena teardown (RET-patched → no-op)
            // Stage 2: Cell/resource cleanup (BSA/texture caches)
            unsafe {
                let trigger = HEAP_COMPACT_TRIGGER_PTR as *mut u32;
                trigger.write_volatile(2);
            }
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
            // === FULL DESTRUCTION PROTOCOL ===
            //
            // Replicates the EXACT sequence the game uses for safe cleanup:
            //
            // 0. Enter loading state (suppress NVSE event dispatching)
            // 1. PreDestructionSetup — hkWorld_Lock + SceneGraphInvalidate
            // 2. FindCellToUnload (our addition — cells freed with zombies)
            // 3. DeferredCleanupSmall — full PDD (all queues) + async flush
            // 4. PostDestructionRestore — hkWorld_Unlock + restore
            // 5. Exit loading state
            // 6. Flush quarantine (zombie data no longer needed)
            //
            // Each step addresses a specific crash vector:
            // - Loading state: prevents NVSE plugins from firing event handlers
            //   on mid-destruction objects (PLChangeEvent, OnCellDetach, etc.)
            // - hkWorld_Lock: blocks AI raycasting → no heightfield UAF
            // - SceneGraphInvalidate: rebuilds SpeedTree draw lists → no BSTreeNode UAF
            // - Full PDD: all queues, no selective skip needed
            // - Quarantine: IO thread reads intact zombie data during async flush
            // - Immediate flush: reclaims zombie memory before new cell loading

            // Step 0: Enter loading state — suppress NVSE event dispatching.
            // DAT_01202d6c is an InterlockedIncrement/Decrement counter.
            // When > 0, actor process changes during cell destruction skip
            // event dispatch, preventing NVSE plugins from accessing
            // mid-destruction objects (refcount 0, partially freed).
            let loading_counter =
                unsafe { &*(LOADING_STATE_COUNTER_PTR as *const std::sync::atomic::AtomicI32) };
            loading_counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

            // 12-byte state struct on stack (matches game's local_10/local_48)
            let mut state = [0u8; 12];
            let state_ptr = state.as_mut_ptr() as *mut c_void;

            // Step 1: Lock Havok world + invalidate scene graph
            unsafe { pre_destruction(state_ptr, 1, 1, 1) };

            // Step 2: Unload cells (our pressure relief)
            for _ in 0..MAX_CELLS_PER_CYCLE {
                let result = unsafe { find_cell(manager) };
                if (result & 0xFF) != 0 {
                    cells += 1;
                } else {
                    break;
                }
            }

            // Step 3: Full PDD + async flush + ProcessPendingCleanup
            unsafe { deferred_cleanup(state[5]) };

            // Step 4: Unlock Havok world + restore state
            unsafe { post_destruction(state_ptr) };

            // Step 5: Exit loading state
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);

            // Step 6: Flush quarantine immediately.
            // The blocking async flush in DeferredCleanupSmall already drained
            // all stale IO tasks — zombie data served its purpose.
            unsafe { super::delayed_free::flush_current_thread() };
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
}

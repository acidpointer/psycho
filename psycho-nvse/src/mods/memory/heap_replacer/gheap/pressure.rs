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
//! ## Layer 1: Post-render cell unloading + PDD (this module)
//! Unloads cells using the game's destruction protocol: loading state
//! counter, hkWorld_Lock, SceneGraphInvalidate, FindCellToUnload,
//! DeferredCleanupSmall (PDD + blocking async flush).
//!
//! Two subsystem-specific synchronizations protect against cross-thread
//! use-after-free during PDD:
//!
//! **IO dequeue lock (BSTaskManagerThread):** Before PDD, we acquire the
//! game's IO dequeue spin-lock (IOManager+0x20, same lock IO_DequeueTask
//! uses). BSTaskManagerThread can't start new tasks. We wait for any
//! in-flight task to complete (sem_count at BSTaskManagerThread+0x18).
//! DeferredCleanupSmall's FUN_00448620 cancels stale queued tasks
//! (sets task state != 1, so BSTaskManagerThread's CAS safely fails).
//! Without this: NiSourceTexture destructor zeroes pixelData →
//! BSFile::Read(NULL) → __VEC_memcpy crash at 0x00ED17A0.
//!
//! **Havok queue 0x20 skip:** The Havok broadphase requires a
//! step-after-removal lifecycle (remove → hkpWorld::step → query).
//! Our hook runs after AI join (end of frame). The next Havok step
//! runs during AI work on the NEXT frame, but AI dispatch queries
//! the broadphase before the step processes our removals → NULL entity
//! → crash at 0x00CFFA08 in addEntitiesBatch. Queue 0x20 is deferred
//! to the game's per-frame PDD (FUN_004556d0) which runs before AI
//! dispatch at the correct lifecycle position.
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
/// Cell unloading during gameplay is unsafe — the game has multiple
/// deferred processing queues (IO completion, animation, POST_AI tasks)
/// that hold raw pointers to forms in loaded cells. Unloading cells
/// invalidates these pointers, causing crashes in every queue.
///
/// Instead, the commit ceiling (COMMIT_CEILING in gheap.rs) triggers the
/// game's OWN OOM handler (FUN_00866a90 Stage 5) which unloads cells
/// INSIDE the allocator retry loop. At that point, the main thread is
/// blocked — all deferred queues are idle, no stale pointer access.
/// This is exactly how the vanilla game with SBM handles memory pressure.
const CELL_UNLOAD_ENABLED: bool = false;

/// Maximum commit GROWTH above baseline before triggering pressure relief.
/// Baseline is measured when PressureRelief initializes (after game loads).
/// This adapts to any mod count:
///   - 423 mods, baseline 500MB → triggers at ~1000MB
///   - 1500 mods, baseline 1500MB → triggers at ~2000MB
/// Maximum commit growth above baseline before triggering pressure relief.
/// 500MB balances normal gameplay headroom with stress test stability.
/// Cell unloading + HeapCompact keep commit from climbing further.
const MAX_GROWTH_ABOVE_BASELINE: usize = 500 * 1024 * 1024;

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

/// FUN_00a62030 — TextureCache_PreReset.
/// Clears ALL texture cache hash table entries (DAT_011f4468) and texture
/// array entries (DAT_011f4464). The game calls this during cell transitions
/// (from FUN_0086a850) to invalidate stale entries. Without it, freed
/// NiSourceTexture pointers persist in the cache → BSTaskManagerThread crash.
const TEXTURE_CACHE_PRE_RESET: usize = 0x00A62030;
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

/// DAT_011dea2b — Game loading/menu state flag.
/// Set to 1 during loading screens, cell transitions, and menu states.
/// The main loop guards per-frame PDD (FUN_004556d0) with this flag.
/// FUN_00868850 (per-frame drain) runs unconditionally — we must check
/// this flag ourselves before running destruction.
const GAME_LOADING_FLAG_PTR: usize = 0x011DEA2B;

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
// BSTaskManagerThread IO synchronization
// ---------------------------------------------------------------------------

/// DAT_01202d98 — Unified runtime manager singleton pointer.
/// Object contains Havok world fields (+0x44/+0x48/+0x7c) AND
/// IOManager/BSTaskManager fields (+0x20 dequeue lock, +0x50 thread array).
/// Confirmed by Ghidra disassembly:
///   Main loop:           MOV ECX,[0x01202d98]; CALL FUN_00c3dbf0 (IO processing)
///   PreDestructionSetup: MOV ECX,[0x01202d98]; CALL FUN_00c3e310 (hkWorld_Lock)
///   IO_DequeueTask:      ADD ECX,0x20; CALL FUN_0040fbf0 (spin-lock acquire)
///   BSTaskManagerBase_ctor: *(this+0x20) = 0; *(this+0x24) = 0 (lock init)
const IO_MANAGER_SINGLETON_PTR: usize = 0x01202D98;

/// Offset of the IO dequeue spin-lock within the runtime manager.
const IO_DEQUEUE_LOCK_OFFSET: usize = 0x20;

/// Reentrance counter at lock + 4.
const IO_DEQUEUE_LOCK_COUNTER_OFFSET: usize = 0x24;

/// BSTaskManagerThread pointer array within the runtime manager.
const IO_THREAD_ARRAY_OFFSET: usize = 0x50;

/// Iteration semaphore count within BSTaskManagerThread.
/// InterlockedIncrement'd after each task iteration.
const IO_THREAD_SEM_COUNT_OFFSET: usize = 0x18;

/// Inter-iteration semaphore HANDLE within BSTaskManagerThread.
/// Created by BSTaskThread_init with initial count=1, max=1.
/// Count=1 when idle/between-iterations, 0 when mid-task processing.
/// Used by io_lock_acquire to probe whether BSTaskManagerThread is mid-task.
const IO_THREAD_ITER_SEM_HANDLE_OFFSET: usize = 0x1C;

/// FUN_0040fbf0 — Bethesda's spin-lock acquire (threadID-based CAS).
/// Non-standard ABI: fastcall ECX + 1 stack param + RET 0x4.
const SPIN_LOCK_ACQUIRE: usize = 0x0040FBF0;



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

    /// Set by destruction_protocol when cells were unloaded. The loading state
    /// counter (DAT_01202D6C) is kept elevated to suppress PLChangeEvent
    /// dispatch. tick() decrements it on the next frame, AFTER NVSE plugins
    /// have seen the elevated counter and skipped event processing.
    pending_counter_decrement: AtomicBool,

    find_cell: FnPtr<FindCellToUnloadFn>,
    pre_destruction: FnPtr<PreDestructionSetupFn>,
    post_destruction: FnPtr<PostDestructionRestoreFn>,
    deferred_cleanup: FnPtr<DeferredCleanupSmallFn>,

    /// Commit when main loop first starts (first tick). 0 = not yet measured.
    /// Dynamic threshold = baseline + MAX_GROWTH.
    /// Measured at first tick() rather than DLL init because mods load
    /// between init and main menu, inflating commit by 500MB+.
    baseline_commit: std::sync::atomic::AtomicUsize,
}

impl PressureRelief {
    fn new() -> anyhow::Result<Self> {
        let instance = unsafe {
            Self {
                requested: AtomicBool::new(false),
                active: AtomicBool::new(false),
                deferred_unload: AtomicBool::new(false),
                pending_counter_decrement: AtomicBool::new(false),
                last_time_ms: AtomicU64::new(0),
                find_cell: FnPtr::from_raw(FIND_CELL_TO_UNLOAD as *mut c_void)?,
                pre_destruction: FnPtr::from_raw(PRE_DESTRUCTION_SETUP as *mut c_void)?,
                post_destruction: FnPtr::from_raw(POST_DESTRUCTION_RESTORE as *mut c_void)?,
                deferred_cleanup: FnPtr::from_raw(DEFERRED_CLEANUP_SMALL as *mut c_void)?,
                baseline_commit: std::sync::atomic::AtomicUsize::new(0),
            }
        };

        log::info!(
            "[PRESSURE] Initialized (baseline=deferred, growth={}MB, max_cells={}, cooldown={}ms)",
            MAX_GROWTH_ABOVE_BASELINE / 1024 / 1024,
            MAX_CELLS_PER_CYCLE,
            COOLDOWN_MS,
        );

        Ok(instance)
    }

    /// Dynamic threshold: baseline commit + MAX_GROWTH_ABOVE_BASELINE.
    /// Returns usize::MAX if baseline not yet measured (suppress all checks).
    #[inline]
    fn threshold(&self) -> usize {
        let baseline = self.baseline_commit.load(Ordering::Relaxed);
        if baseline == 0 {
            return usize::MAX; // not yet calibrated
        }
        baseline + MAX_GROWTH_ABOVE_BASELINE
    }

    /// Measure baseline commit on first tick (main loop started, mods loaded).
    /// Called from tick() once.
    pub fn calibrate_baseline(&self) {
        if self.baseline_commit.load(Ordering::Relaxed) != 0 {
            return; // already calibrated
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
        if info.get_current_commit() >= self.threshold() {
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

    /// Decrement the loading state counter if a previous destruction_protocol
    /// left it elevated. Called from tick() on the next frame, AFTER NVSE
    /// plugins have processed their events with the counter > 0.
    pub fn flush_pending_counter_decrement(&self) {
        if self.pending_counter_decrement.swap(false, Ordering::AcqRel) {
            let loading_counter =
                unsafe { &*(LOADING_STATE_COUNTER_PTR as *const std::sync::atomic::AtomicI32) };
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
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
        if commit < self.threshold() {
            self.requested.store(false, Ordering::Release);
            self.active.store(false, Ordering::Release);
            return;
        }

        if CELL_UNLOAD_ENABLED {
            // Defer cell unloading to the AI join hook (Hook 2,
            // FUN_008c7990 wrapper). This post-render, post-AI-join
            // position is the only safe one:
            // - SpeedTree: render consumed draw lists ✓
            // - AI threads: idle (joined) ✓
            // - BSTaskManagerThread: IO dequeue lock during PDD ✓
            self.deferred_unload.store(true, Ordering::Release);
            log::debug!("[PRESSURE] Cell unload deferred to AI join");
        }

        // Trigger HeapCompact stages 0-2 for the NEXT frame.
        unsafe {
            let trigger = HEAP_COMPACT_TRIGGER_PTR as *mut u32;
            trigger.write_volatile(2);
        }

        unsafe { mi_collect(false) };

        self.last_time_ms.store(now_ms, Ordering::Relaxed);

        let commit_mb = commit / 1024 / 1024;

        // Always clear requested so check() can re-evaluate on the next trigger.
        // If commit is still above threshold, check() will re-set it.
        self.requested.store(false, Ordering::Release);

        log::info!("[PRESSURE] Relief cycle (commit={}MB)", commit_mb);

        // HUD notification only under heavy memory pressure
        if commit_mb >= 1800 {
            crate::nvse_services::show_notification(
                &format!("Pip-Boy: {}MB, cache optimized", commit_mb),
            );
        }

        self.active.store(false, Ordering::Release);
    }

    /// Run deferred cell unloading. Called from the AI thread join hook
    /// (FUN_008c7990 wrapper) AFTER AI threads have completed their work.
    ///
    /// # Safety
    ///
    /// Must be called on the main thread, BEFORE AI dispatch and render
    /// (per-frame drain hook at FUN_00868850, line ~802).
    pub unsafe fn run_deferred_unload(&self) {
        if !self.deferred_unload.load(Ordering::Acquire) {
            return;
        }

        // FUN_00868850 runs unconditionally — including during loading screens
        // and cell transitions. The game's own per-frame PDD (FUN_004556d0) is
        // guarded by DAT_011dea2b == 0. We must do the same: only run during
        // normal gameplay, not during loading/menu states.
        let loading = unsafe { *(GAME_LOADING_FLAG_PTR as *const u8) != 0 };
        if loading {
            return; // keep flag set, retry next frame
        }

        // Now consume the flag
        self.deferred_unload.store(false, Ordering::Release);

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

        // AI threads idle (not dispatched yet), BSTaskManagerThread idle.
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
            // Loading counter still elevated — schedule decrement for next tick()
            self.pending_counter_decrement.store(true, Ordering::Release);
            log::info!(
                "[PRESSURE] Deferred unload: {} cells (commit={}MB)",
                cells, commit_mb,
            );
        }
    }

    /// The actual cell unloading + PDD sequence. Extracted so both
    /// relieve() (single-threaded) and run_deferred_unload() (multi-threaded)
    /// can use the same code.
    ///
    /// IO synchronization: Before DeferredCleanupSmall (which runs PDD),
    /// we acquire the IO dequeue spin-lock and wait for BSTaskManagerThread
    /// to finish any in-flight task. This prevents a use-after-free where
    /// PDD runs the NiSourceTexture destructor (zeroing pixelData) while
    /// BSTaskManagerThread reads it for BSFile::Read → __VEC_memcpy(NULL,...)
    /// → EXCEPTION_ACCESS_VIOLATION at 0x00ED17A0.
    ///
    /// DeferredCleanupSmall calls FUN_00448620 which cancels stale queued
    /// tasks (sets task state != 1), so BSTaskManagerThread's CAS(task+3,3,1)
    /// safely fails for stale tasks after we release the lock.
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

        // === IO SYNCHRONIZATION ===
        // Acquire the IO dequeue lock so BSTaskManagerThread cannot dequeue
        // new tasks during PDD. Wait for any in-flight task to complete.
        // IoLockScope tells quarantine that flushes during PDD can skip
        // lock acquisition (we already hold it).
        let io_locked = if cells > 0 {
            unsafe { Self::io_lock_acquire() }
        } else {
            false
        };

        let _io_scope = if io_locked {
            Some(super::delayed_free::IoLockScope::enter())
        } else {
            None
        };

        unsafe { deferred_cleanup(state[5]) };

        drop(_io_scope);

        if io_locked {
            unsafe { Self::io_lock_release() };
        }

        unsafe { post_destruction(state_ptr) };

        // If cells were unloaded, do NOT decrement the loading counter here.
        // NVSE MainLoopHook fires immediately after FUN_0086a850 returns
        // (at 0x00ecc470). JIP LN NVSE's LN_ProcessEvents dispatches cell
        // change events from there. If the counter is 0, PLChangeEvent fires
        // for destroyed actors → stale reference → crash.
        //
        // Keep counter > 0 so event dispatch is suppressed. tick() on the
        // NEXT frame decrements it, after NVSE hooks have already run.
        if cells == 0 {
            loading_counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }

        cells
    }

    /// Acquire the IO dequeue spin-lock and wait for BSTaskManagerThread
    /// to finish any in-flight task. Returns true if lock was acquired.
    pub(in crate::mods::memory::heap_replacer) unsafe fn io_lock_acquire() -> bool {
        use libpsycho::os::windows::winapi::{
            self, WaitResult,
        };

        let io_mgr = unsafe { *(IO_MANAGER_SINGLETON_PTR as *const *mut u8) };
        if io_mgr.is_null() {
            return false;
        }

        // Acquire the IO dequeue spin-lock (FUN_0040fbf0).
        //
        // Non-standard calling convention (verified by Ghidra disassembly):
        //   fastcall ECX = lock pointer, 1 stack param (debug), RET 0x4.
        // No Rust ABI matches this — inline asm is the only correct way.
        let lock_ptr = unsafe { io_mgr.add(IO_DEQUEUE_LOCK_OFFSET) };
        unsafe {
            std::arch::asm!(
                "push 0",
                "call {func}",
                func = in(reg) SPIN_LOCK_ACQUIRE as u32,
                in("ecx") lock_ptr,
                out("eax") _,
                out("edx") _,
            );
        }

        // Wait for BOTH BSTaskManagerThread instances to finish in-flight tasks.
        // The game has TWO IO threads (indices 0 and 1, confirmed by OOM Stage 8
        // which checks FUN_00866da0(DAT_01202d98, 0) and (DAT_01202d98, 1)).
        //
        // For each thread, after acquiring our IO lock, it's in one of:
        // a) Idle (semaphore count=1): probe succeeds immediately.
        // b) Blocked on our lock (consumed sem, trying to dequeue): count=0,
        //    no in-flight task, safe to proceed.
        // c) Mid-task processing (dequeued before us): count=0,
        //    in-flight task, must wait for completion.
        //
        // Distinguish (b) vs (c) via iter_count polling (50ms timeout).
        for bst_index in 0..2u32 {
            if let Some(sem_handle) = unsafe { Self::read_bst_iter_sem_handle(io_mgr, bst_index) } {
                match winapi::wait_for_single_object(sem_handle, 0) {
                    WaitResult::Signaled => {
                        if let Err(e) = winapi::release_semaphore(sem_handle, 1) {
                            log::error!("[IO_SYNC] ReleaseSemaphore failed: {:?}", e);
                        }
                    }
                    _ => {
                        if let Some(count_before) = unsafe { Self::read_bst_sem_count(io_mgr, bst_index) } {
                            let start = winapi::get_tick_count();
                            loop {
                                winapi::sleep(0);
                                if let Some(c) = unsafe { Self::read_bst_sem_count(io_mgr, bst_index) } {
                                    if c != count_before {
                                        break;
                                    }
                                }
                                if winapi::get_tick_count().wrapping_sub(start) >= 50 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        true
    }

    /// Release the IO dequeue spin-lock.
    pub(in crate::mods::memory::heap_replacer) unsafe fn io_lock_release() {
        let io_mgr = unsafe { *(IO_MANAGER_SINGLETON_PTR as *const *mut u8) };
        if io_mgr.is_null() {
            return;
        }
        let counter_ptr =
            unsafe { io_mgr.add(IO_DEQUEUE_LOCK_COUNTER_OFFSET) as *mut i32 };
        let lock_ptr =
            unsafe { io_mgr.add(IO_DEQUEUE_LOCK_OFFSET) as *mut i32 };

        let new_count = unsafe { std::ptr::read_volatile(counter_ptr) } - 1;
        unsafe { std::ptr::write_volatile(counter_ptr, new_count) };
        if new_count == 0 {
            unsafe { std::ptr::write_volatile(lock_ptr, 0) };
        }
    }

    /// Read BSTaskManagerThread's iteration semaphore count (+0x18).
    /// InterlockedIncrement'd AFTER task ref release and ReleaseSemaphore.
    unsafe fn read_bst_sem_count(io_mgr: *const u8, index: u32) -> Option<i32> {
        let bst = unsafe { Self::read_bst_ptr(io_mgr, index) }?;
        let count_ptr = unsafe { bst.add(IO_THREAD_SEM_COUNT_OFFSET) as *const i32 };
        Some(unsafe { std::ptr::read_volatile(count_ptr) })
    }

    /// Read BSTaskManagerThread's inter-iteration semaphore HANDLE.
    /// This is the semaphore at +0x1c that BSTaskManagerThread waits on
    /// between iterations. Count=1 when idle/between-iterations, 0 when mid-task.
    unsafe fn read_bst_iter_sem_handle(
        io_mgr: *const u8,
        index: u32,
    ) -> Option<windows::Win32::Foundation::HANDLE> {
        let bst = unsafe { Self::read_bst_ptr(io_mgr, index) }?;
        let handle_ptr =
            unsafe { bst.add(IO_THREAD_ITER_SEM_HANDLE_OFFSET) as *const windows::Win32::Foundation::HANDLE };
        let handle = unsafe { std::ptr::read_volatile(handle_ptr) };
        if handle.is_invalid() {
            return None;
        }
        Some(handle)
    }

    /// Get BSTaskManagerThread object pointer from IOManager by index.
    /// Index 0 or 1 — the game has TWO IO worker threads.
    unsafe fn read_bst_ptr(io_mgr: *const u8, index: u32) -> Option<*const u8> {
        let thread_array_ptr =
            unsafe { io_mgr.add(IO_THREAD_ARRAY_OFFSET) as *const *const *const u8 };
        let thread_array = unsafe { *thread_array_ptr };
        if thread_array.is_null() {
            return None;
        }
        let bst = unsafe { *thread_array.add(index as usize) };
        if bst.is_null() {
            return None;
        }
        Some(bst)
    }
}

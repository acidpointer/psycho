//! Hook wrappers that delegate to gheap::allocator.
//!
//! Each function matches the calling convention of the game function it
//! replaces. The hook infrastructure (InlineHookContainer) handles the
//! trampoline.
//!
//! Also contains frame-level orchestration: loading transition detection,
//! watchdog flag consumption, emergency cleanup, and AI thread sync.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use libc::c_void;

use super::allocator;
use super::engine::globals::{self, PddQueue};
use super::game_guard;
use super::pressure::PressureRelief;
use super::statics;
use super::texture_cache;
use super::watchdog;

// ---- Game heap alloc/free/msize/realloc ----

/// GameHeap::Allocate hook (thiscall). Forwards to [`allocator::alloc`].
pub unsafe extern "thiscall" fn hook_gheap_alloc(_this: *mut c_void, size: usize) -> *mut c_void {
    unsafe { allocator::alloc(size) }
}

/// GameHeap::Free hook (thiscall). Forwards to [`allocator::free`].
pub unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
    unsafe { allocator::free(ptr) }
}

/// GameHeap::Msize hook (thiscall). Forwards to [`allocator::msize`].
pub unsafe extern "thiscall" fn hook_gheap_msize(_this: *mut c_void, ptr: *mut c_void) -> usize {
    unsafe { allocator::msize(ptr) }
}

/// GameHeap::Reallocate hook (thiscall). Forwards to [`allocator::realloc`].
pub unsafe extern "thiscall" fn hook_gheap_realloc(
    _this: *mut c_void,
    ptr: *mut c_void,
    new_size: usize,
) -> *mut c_void {
    unsafe { allocator::realloc(ptr, new_size) }
}

/// PDD drain rounds by pressure level.
/// Level 1 (normal): moderate drain -- keep queues from growing.
/// Level 2 (aggressive): clear backlog. Capped at 50 -- at 60fps that's
/// 3000 items/sec, plenty for cell transitions. 200 was excessive and
/// consumed too much main thread time calling game code each round.
const PDD_ROUNDS_NORMAL: u32 = 75;
const PDD_ROUNDS_AGGRESSIVE: u32 = 50;

thread_local! {
    // Loading transition detection.
    static WAS_LOADING: Cell<bool> = const { Cell::new(false) };
}

/// Last destruction_protocol result: cells unloaded.
/// When 0 and commit hasn't grown, skip the next call to avoid
/// the 12ms/cycle death spiral observed in heavy mod setups.
static LAST_DESTRUCTION_CELLS: AtomicU32 = AtomicU32::new(u32::MAX); // MAX = "never ran, always run first time"

/// Commit (MB) at last destruction_protocol call.
static LAST_DESTRUCTION_COMMIT_MB: AtomicU32 = AtomicU32::new(0);

/// Cooldown for destruction_protocol during VAS crisis.
/// Running pre_destruction_setup 4x/sec allocates terrain/LOD memory
/// (Ghidra: FUN_00878160 step 5), making VAS pressure WORSE.
/// Limit to 1 cycle per second during crisis.
static DESTRUCTION_COOLDOWN_MS: AtomicU64 = AtomicU64::new(0);

/// Post-loading cooldown: suppress watchdog cleanup after loading ends.
/// jip_nvse's nvseRuntimeScript263CellChange fires events that reference
/// objects from the old cell. If PDD drains those objects before the
/// script finishes, the script reads freed memory --> crash in PopulateArgs.
static POST_LOADING_COOLDOWN_MS: AtomicU64 = AtomicU64::new(0);

/// Consecutive ineffective VAS EMERGENCY cycle counter.
/// If 3+ cycles drain < 1MB each, we're in a death spiral — disable
/// emergency until commit drops below threshold.
static EMERGENCY_INEFFECTIVE: AtomicU32 = AtomicU32::new(0);

/// Set when death spiral detected. Overrides the commit-based emergency
/// calculation until commit drops below the emergency threshold.
static EMERGENCY_SUPPRESSED: AtomicBool = AtomicBool::new(false);

/// Last tick count when periodic pool drain ran.
/// Drains large blocks (> 1KB) when pool is near capacity.
static LAST_POOL_DRAIN_MS: AtomicU64 = AtomicU64::new(0);

/// Last tick when mi_collect(true) was called. Rate-limited to once per 2s
/// to avoid O(total_memory) full collection freezing the main thread.
static LAST_MI_COLLECT_TRUE_MS: AtomicU64 = AtomicU64::new(0);

/// Minimum interval between mi_collect(true) calls in the per-frame path.
/// OOM recovery in allocator.rs calls mi_collect(true) directly, bypassing
/// this limit -- crash prevention must not be throttled.
const MI_COLLECT_TRUE_COOLDOWN_MS: u64 = 2000;

/// Cooldown for periodic pool drain (500ms).
/// With 16MB hard cap, blocks cycle in ~133ms at stress-test rates.
/// 500ms prevents drain storms while keeping large blocks flowing to
/// mi_free for purge_delay-based decommit.
const POOL_DRAIN_COOLDOWN_MS: u64 = 500;

/// Rate-limited mi_collect(true). No-op if cooldown hasn't elapsed.
/// Returns true if collection ran.
fn try_mi_collect_true() -> bool {
    let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
    let last = LAST_MI_COLLECT_TRUE_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= MI_COLLECT_TRUE_COOLDOWN_MS {
        LAST_MI_COLLECT_TRUE_MS.store(now, Ordering::Relaxed);
        unsafe { libmimalloc::mi_collect(true) };
        true
    } else {
        false
    }
}

/// Phase 7: per-frame queue drain (before AI_START).
///
/// Vanilla behavior: Only drains PDD queues and emergency pool.
/// Cleanup (cell unload, Havok GC, etc.) runs ONLY on allocation failure
/// via the OOM retry loop in the allocator, NOT on a timer.
///
/// This matches vanilla timing: cleanup runs when needed (alloc fails),
/// not when we think it's needed (watchdog timer).
pub unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Update cached tick for slab free() hot path (avoids syscall per free).
    super::slab::update_cached_tick();

    // Set main thread ID on first frame.
    if !allocator::is_pool_active() {
        globals::set_main_thread_id();
        if !globals::is_loading() {
            allocator::activate_pool();
        }
    }

    // Slab decommit sweep: decommit pages with zero live blocks.
    // This is the slab's equivalent of SBM_PurgeUnusedArenas.
    let (decommit_pages, decommit_bytes) = unsafe { super::slab::decommit_sweep() };
    if decommit_pages > 0 {
        log::debug!(
            "[SLAB] Decommit sweep: {} pages, {}KB freed",
            decommit_pages,
            decommit_bytes / 1024,
        );
    }

    // --- Loading transition detection ---
    let loading_now = globals::is_loading();
    let was_loading = WAS_LOADING.with(|c| {
        let prev = c.get();
        c.set(loading_now);
        prev
    });

    if loading_now && !was_loading {
        unsafe { on_loading_start() };
    }
    if !loading_now && was_loading {
        on_loading_end();
    }

    let heap = super::heap_manager::HeapManager::get();

    // --- Emergency pool drain (worker OOM signal) ---
    // Worker threads can't free memory from the main thread's pool. They
    // signal this flag; we drain it here.
    //
    // CRITICAL: Use pool::ALIGN (drain ALL blocks) during emergency.
    // The pool is often entirely small blocks (< 1KB) during crisis.
    // Draining small blocks risks UAF, but purge_delay=15s on mimalloc
    // gives stale readers a 15s window before page decommit.
    // The alternative (drain 0 blocks) is a guaranteed crash.
    if heap.take_emergency_drain() {
        let commit_before = heap.commit_mb();
        let drained = unsafe {
            super::slab::decommit_sweep();
            libmimalloc::mi_collect(false);
            (0, 0).0
        };
        try_mi_collect_true();

        // purge_delay=15s already provides the stale reader safety window.
        // The previous Sleep(50) cost 3 dropped frames at 60fps. Removed:
        // mimalloc's internal purge timer handles page decommit timing.

        log::warn!(
            "[OOM] Emergency drain: {} blocks, commit={}-->{}MB pool={}MB",
            drained,
            commit_before,
            heap.commit_mb(),
            super::slab::committed_bytes() / 1024 / 1024,
        );
    }

    // --- Watchdog-driven cleanup (timer-based, NOT eviction-based) ---
    // Cleanup runs on a schedule when the watchdog detects sustained growth.
    // This is the ONLY reliable mechanism during stress testing. Eviction-
    // based triggers caused cleanup storms and froze the game.
    //
    // Level 1 (normal): Havok GC + PDD drain
    // Level 2 (aggressive): Level 1 + cell unload via destruction protocol
    let request = watchdog::take_cleanup_request();
    let commit = heap.commit_bytes();

    // --- VAS Crisis Management ---
    //
    // When commit exceeds critical thresholds, the pool becomes a liability:
    // it fills with small blocks (< 1KB) that drain_large can't touch.
    // At 1.5GB+, we drain ALL pool blocks. At 1.8GB+, we enter emergency
    // mode where ALL frees bypass the pool entirely.
    //
    // Ghidra-verified safety: Phase 7 runs after AI_JOIN (frame timeline
    // PHASE 12). AI threads are STOPPED. BSTaskManagerThread may still
    // process IO, but texture cache dead set protects against those.
    // The FreeNode header (usable_size at offset +4) subverts the
    // NiRefObject RefCount mechanism even after drain+reuse.
    // Live VAS check via GlobalMemoryStatusEx -- always accurate.
    // No stale snapshots, no commit-vs-reserved mismatch.
    let free_vas = allocator::current_free_vas();
    let vas_emergency_active =
        free_vas < allocator::VAS_EMERGENCY_REMAINING
            && !EMERGENCY_SUPPRESSED.load(Ordering::Relaxed);
    let vas_critical = free_vas < allocator::VAS_CRITICAL_REMAINING;

    // Death spiral suppression: if free VAS recovers above emergency,
    // clear the suppression flag so emergency can fire again next time.
    if free_vas >= allocator::VAS_EMERGENCY_REMAINING {
        EMERGENCY_SUPPRESSED.store(false, Ordering::Relaxed);
    }

    allocator::set_vas_emergency(vas_emergency_active);

    // Cap VAS EMERGENCY cycles: if 3+ consecutive cycles drain < 1MB,
    // we're in a death spiral. Disable emergency until commit drops
    // below the threshold. This prevents the 40+ cycle death spiral
    // that corrupted the stack during the last crash.
    const MAX_INEFFECTIVE_EMERGENCY_CYCLES: u32 = 3;
    const MIN_EFFECTIVE_DRAIN_MB: usize = 1;

    if vas_emergency_active {
        let (decom_pages, decom_bytes) = unsafe { super::slab::decommit_sweep() };
        unsafe { libmimalloc::mi_collect(false) };
        let freed_mb = decom_bytes as usize / 1024 / 1024;

        if freed_mb < MIN_EFFECTIVE_DRAIN_MB {
            let count = EMERGENCY_INEFFECTIVE.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= MAX_INEFFECTIVE_EMERGENCY_CYCLES {
                // Death spiral detected — suppress emergency until commit
                // drops below the emergency threshold. This prevents the
                // 40+ cycle death spiral that corrupted the stack.
                EMERGENCY_SUPPRESSED.store(true, Ordering::Relaxed);
                allocator::set_vas_emergency(false);
                log::error!(
                    "[VAS] EMERGENCY SUPPRESSED: {} ineffective cycles, free_vas={}MB, commit={}MB, decommitted {} pages",
                    count,
                    free_vas / 1024 / 1024,
                    commit / 1024 / 1024,
                    decom_pages,
                );
            }
        } else {
            EMERGENCY_INEFFECTIVE.store(0, Ordering::Relaxed);
        }

        // F3: Nuclear option — drain ALL pool blocks + force decommit
        // partially-empty mimalloc segments. Rate-limited to avoid
        // O(total_memory) traversal every frame during crisis.
        try_mi_collect_true();
        log::error!(
            "[VAS] EMERGENCY: free_vas={}MB, commit={}MB, decommitted {} pages, slab={}MB",
            free_vas / 1024 / 1024,
            commit / 1024 / 1024,
            decom_pages,
            super::slab::committed_bytes() / 1024 / 1024,
        );
    } else {
        // Not in emergency — reset ineffective counter so it starts fresh
        // next time we enter emergency.
        EMERGENCY_INEFFECTIVE.store(0, Ordering::Relaxed);

        if vas_critical {
            // F2: Slab decommit sweep + lightweight mi_collect.
            // With corrected remaining-VAS thresholds, CRITICAL only fires
            // when < 400MB free VAS. Keep the per-frame cost low.
            let (cp, _cb) = unsafe { super::slab::decommit_sweep() };
            unsafe { libmimalloc::mi_collect(false) };
            log::warn!(
                "[VAS] CRITICAL: free_vas={}MB, commit={}MB, decommitted {} pages, slab={}MB",
                free_vas / 1024 / 1024,
                commit / 1024 / 1024,
                cp,
                super::slab::committed_bytes() / 1024 / 1024,
            );
        }
    }

    // --- Periodic Pool Drain ---
    // Slab decommit sweep only (no mi_collect). mi_collect with
    // purge_delay=15s is safer than before but we still avoid it during
    // normal gameplay. jip_nvse CellChange handlers hold stale pointers
    // that chain into mimalloc overflow pages. Only call mi_collect
    // during OOM / VAS crisis where the alternative is guaranteed crash.
    if super::slab::committed_bytes() / 1024 / 1024 >= 12 {
        let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
        let last = LAST_POOL_DRAIN_MS.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= POOL_DRAIN_COOLDOWN_MS {
            unsafe { super::slab::decommit_sweep() };
            LAST_POOL_DRAIN_MS.store(now, Ordering::Relaxed);
        }
    }

    if request >= 1 && !vas_emergency_active {
        // Post-loading cooldown: suppress cleanup to let jip_nvse's
        // nvseRuntimeScript263CellChange finish processing events that
        // reference objects from the old cell.
        let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
        let cooldown_end = POST_LOADING_COOLDOWN_MS.load(Ordering::Acquire);
        if now < cooldown_end {
            return;
        }

        // During loading, DO NOT signal HeapCompact stages. Stages 0-2
        // (texture/geometry/menu cache flush) corrupt caches while the IO
        // thread is actively loading textures — causes UAF when textures
        // are cleared mid-load. This was the root cause of the crash at
        // 0x08F744B4 (nvseRuntimeScript263CellChange).
        //
        // During normal gameplay (not loading), signal Stage 2 only — safe
        // because no cell transition is in progress.
        // Stage 3+ (HavokGC / FUN_00c459d0) MUST go through destruction_protocol
        // which has Havok locking + AI safety. Signaling stage 3+ here runs
        // async queue flush without locks, disrupting NVTF Geometry Precache
        // Queue -> NiGeometryBufferData UAF (heap_analysis.md:1345).
        if !globals::is_loading() {
            heap.signal_heap_compact(globals::HeapCompactStage::MenuCleanup);
        }

        // NOTE: pool drain moved to AFTER PDD (below). Draining before PDD
        // causes UAF: PDD destructors access AnimSequenceBase, BSFadeNode
        // etc. that were in pool blocks. If we mi_free those blocks before
        // PDD runs, destructors read decommitted memory.
        if !vas_critical {
            log::info!(
                "[WATCHDOG] Phase 7 cleanup: level={}, commit={}MB, pdd(NiNode={} Gen={} Form={})",
                request,
                commit / 1024 / 1024,
                globals::pdd_queue_count(PddQueue::NiNode),
                globals::pdd_queue_count(PddQueue::Generic),
                globals::pdd_queue_count(PddQueue::Form),
            );
        }
    }

    // F4: Cap destruction_protocol to 1/sec during VAS crisis.
    // pre_destruction_setup allocates terrain/LOD memory (Ghidra: FUN_00878160),
    // running it 4x/sec during crisis makes VAS pressure WORSE.
    //
    // Effectiveness gate: if the last destruction_protocol found 0 cells AND
    // commit hasn't grown significantly, skip. Prevents the 82-cycle death
    // spiral where each futile call costs ~12ms on the main thread.
    if request >= 2
        && let Some(pr) = PressureRelief::instance()
    {
        // Post-loading cooldown: also suppress destruction_protocol
        let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
        let cooldown_end = POST_LOADING_COOLDOWN_MS.load(Ordering::Acquire);
        if now < cooldown_end {
            return;
        }

        let last = DESTRUCTION_COOLDOWN_MS.load(Ordering::Relaxed);

        // Check if destruction_protocol is likely to be effective
        let last_cells = LAST_DESTRUCTION_CELLS.load(Ordering::Relaxed);
        let last_commit = LAST_DESTRUCTION_COMMIT_MB.load(Ordering::Relaxed);
        let current_commit_mb = commit / 1024 / 1024;
        let commit_grew = (current_commit_mb as u32).saturating_sub(last_commit) > 50;
        let should_run = last_cells > 0 || commit_grew || last_commit == 0;

        if should_run {
            if vas_critical {
                if now.saturating_sub(last) >= 1000 {
                    DESTRUCTION_COOLDOWN_MS.store(now, Ordering::Relaxed);
                    let cells = unsafe { pr.run_cleanup() };
                    LAST_DESTRUCTION_CELLS.store(cells as u32, Ordering::Relaxed);
                    LAST_DESTRUCTION_COMMIT_MB.store(current_commit_mb as u32, Ordering::Relaxed);
                }
            } else {
                let cells = unsafe { pr.run_cleanup() };
                LAST_DESTRUCTION_CELLS.store(cells as u32, Ordering::Relaxed);
                LAST_DESTRUCTION_COMMIT_MB.store(current_commit_mb as u32, Ordering::Relaxed);
            }
        }
    }

    // Clear texture dead set under write lock.
    game_guard::with_write("dead_set_clear", || {
        texture_cache::clear_dead_set();
    });

    // Call the original per-frame queue drain (PDD).
    if let Ok(original) = statics::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        unsafe { original() };

        // Boosted PDD drain when watchdog flagged cleanup.
        // During loading, skip entirely — the game's cell transition already
        // runs its own PDD. Our aggressive drain frees objects the transition
        // still needs, causing UAF when NVSE scripts access freed Characters
        // (crash in InternalFunctionCaller::PopulateArgs).
        //
        // Post-loading cooldown: also suppress to let jip_nvse events finish.
        if request >= 1 && !globals::is_loading() {
            let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
            let cooldown_end = POST_LOADING_COOLDOWN_MS.load(Ordering::Acquire);
            if now < cooldown_end {
                return;
            }
            let max_rounds = if request >= 2 {
                PDD_ROUNDS_AGGRESSIVE
            } else {
                PDD_ROUNDS_NORMAL
            };
            let mut rounds = 0u32;

            for _ in 0..max_rounds {
                let ni = globals::pdd_queue_count(PddQueue::NiNode);
                let generic = globals::pdd_queue_count(PddQueue::Generic);
                let form = globals::pdd_queue_count(PddQueue::Form);
                if ni == 0 && generic == 0 && form == 0 {
                    break;
                }
                unsafe { original() };
                rounds += 1;
            }

            // Slab decommit after PDD. No mi_collect -- see pool drain comment.
            if !vas_critical {
                unsafe { super::slab::decommit_sweep() };
                log::debug!(
                    "[PDD] Drained {} rounds, pdd(NiNode={} Gen={} Form={}), commit={}MB, pool={}MB",
                    rounds,
                    globals::pdd_queue_count(PddQueue::NiNode),
                    globals::pdd_queue_count(PddQueue::Generic),
                    globals::pdd_queue_count(PddQueue::Form),
                    heap.commit_mb(),
                    super::slab::committed_bytes() / 1024 / 1024,
                );
            } else {
                log::debug!(
                    "[PDD] Drained {} rounds, pdd(NiNode={} Gen={} Form={}), commit={}MB, pool={}MB",
                    rounds,
                    globals::pdd_queue_count(PddQueue::NiNode),
                    globals::pdd_queue_count(PddQueue::Generic),
                    globals::pdd_queue_count(PddQueue::Form),
                    heap.commit_mb(),
                    super::slab::committed_bytes() / 1024 / 1024,
                );
            }
        }
    }
}

// Cell unload from Phase 7 during loading - REMOVED
// Vanilla doesn't do proactive cell unload during loading on a timer.
// The game's OOM handler handles cell unloading when allocation fails.
//
// First frame where loading starts. Run proper cleanup:
//   1. HeapCompact 0-3 (texture, geometry, menu, Havok GC)
//   2. Cell unload (bypass off so frees accumulate in pool)
//   3. Drain pool blocks + mi_collect (batch decommit)
//   4. Enable loading bypass (subsequent frees -> mi_free)
#[cold]
unsafe fn on_loading_start() {
    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    let commit_before = info.get_current_commit();

    // DO NOT force-decommit here. BSTaskManagerThread is still active
    // during loading transitions (processing texture IO). Force decommit
    // would decommit pages that BSTask might free to --> writing FreeNode
    // to a decommitted page --> access violation in our slab::free().
    // The 30-second delay in the per-frame sweep handles decommit safely.
    log::info!(
        "[LOADING] Transition detected: commit={}MB, slab={}MB, dirty={}",
        commit_before / 1024 / 1024,
        super::slab::committed_bytes() / 1024 / 1024,
        super::slab::dirty_pages(),
    );

    // Enable loading bypass immediately. Subsequent frees during loading
    // go directly to mi_free for immediate VAS recovery.
}

// First frame after loading ends. Disable loading bypass, resume normal pooling.
//
// Activate pool BEFORE clearing loading bypass to avoid a race window
// where neither pool nor bypass is active:
//   1. activate_pool() --> sets POOL_ACTIVE = true
//   2. set_loading_bypass(false) --> clears bypass
// If we clear bypass first, there's a brief window where allocations go to
// mimalloc without pool tracking (POOL_ACTIVE still false), and frees go to
// mi_free without zombie safety.
//
// DO NOT call mi_collect or drain_pool here. During post-loading stabilization,
// NVSE is rebuilding its FunctionInfo cache from freshly-reallocated Script
// bytecode buffers. mi_collect decommits freed pages within partially-empty
// mimalloc segments. If the OLD bytecode pages are decommitted BEFORE NVSE
// finishes building its cache, NVSE's ScriptIterator dereferences decommitted
// memory --> C0000005 in ScriptAnalyzer.cpp:162.
//
// See: analysis/ghidra/output/memory/bulletproof_script_crash.txt
#[cold]
fn on_loading_end() {
    // Step 1: Activate pool first (sets POOL_ACTIVE = true)
    if !allocator::is_pool_active() {
        allocator::activate_pool();
    }

    // Set post-loading cooldown: suppress watchdog cleanup for 5 seconds
    // to let jip_nvse's nvseRuntimeScript263CellChange finish processing
    // events that reference objects from the old cell.
    let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
    POST_LOADING_COOLDOWN_MS.store(now + 5000, Ordering::Release);

    // Suppress NVSE event dispatch (PLChangeEvent) for one frame after loading.
    // Actors allocated from virgin slab pages have VirtualAlloc-zeroed memory.
    // Game constructors don't always initialize all sub-fields -- PLChangeEvent
    // handlers (JohnnyGuitar HandlePLChangeEvent) access NULL pointers in
    // partially-initialized actor processes, crashing at NULL+offset.
    // LOADING_STATE_COUNTER > 0 makes FUN_0096e150 skip event dispatch.
    // Decrement happens in Phase 10 via flush_pending_counter_decrement.
    globals::loading_state_counter().fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if let Some(pr) = PressureRelief::instance() {
        pr.set_pending_counter_decrement();
    }

    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    log::info!(
        "[LOADING] Loading ended, commit={}MB, pool={}MB",
        info.get_current_commit() / 1024 / 1024,
        super::slab::committed_bytes() / 1024 / 1024,
    );
}

/// Phase 10: post-render maintenance (before AI_JOIN).
///
/// Calibrates baseline commit and flushes pending loading counter decrements.
/// Pressure relief is driven by the watchdog via Phase 7 flag consumption.
pub unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
    if let Ok(original) = statics::MAIN_LOOP_MAINTENANCE_HOOK.original() {
        unsafe { original(this) };
    }

    if let Some(pr) = PressureRelief::instance() {
        pr.calibrate_baseline();
        pr.flush_pending_counter_decrement();
    }
}

/// Phase 8: AI thread dispatch. Sets AI_ACTIVE flag before dispatching.
pub unsafe extern "fastcall" fn hook_ai_thread_start(mgr: *mut c_void) {
    game_guard::set_ai_active();
    if let Ok(original) = statics::AI_THREAD_START_HOOK.original() {
        unsafe { original(mgr) };
    }
}

/// AI_JOIN: AI threads completed.
pub unsafe extern "fastcall" fn hook_ai_thread_join(mgr: *mut c_void) {
    if let Ok(original) = statics::AI_THREAD_JOIN_HOOK.original() {
        unsafe { original(mgr) };
    }
    game_guard::clear_ai_active();

    // Console command deferred request during loading (pcell).
    if globals::is_loading() {
        let deferred = super::engine::cell_unload::take_deferred_request();
        if deferred > 0 {
            let _ = super::engine::cell_unload::execute_during_loading(deferred);
        }
        return;
    }

    // Normal gameplay: only console commands.
    let deferred = super::engine::cell_unload::take_deferred_request();
    if deferred > 0 {
        let _ = super::engine::cell_unload::execute(deferred);
    }
}

// ---- Havok world synchronization hooks ----

/// Hook for hkWorld_Lock (0x00C3E310).
/// Sets HAVOK_PHYSICS_ACTIVE flag to signal that physics stepping is in progress.
/// This allows cell unload to wait for physics to complete before destroying objects.
pub unsafe extern "fastcall" fn hook_hkworld_lock(this: *mut c_void) {
    game_guard::set_havok_active();
    if let Ok(original) = statics::HKWORLD_LOCK_HOOK.original() {
        unsafe { original(this) };
    }
}

/// Hook for hkWorld_Unlock (0x00C3E340).
/// Clears HAVOK_PHYSICS_ACTIVE flag to signal that physics stepping is complete.
pub unsafe extern "fastcall" fn hook_hkworld_unlock(this: *mut c_void) {
    if let Ok(original) = statics::HKWORLD_UNLOCK_HOOK.original() {
        unsafe { original(this) };
    }
    game_guard::clear_havok_active();
}

//! Hook wrappers that delegate to gheap::allocator.
//!
//! Each function matches the calling convention of the game function it
//! replaces. The hook infrastructure (InlineHookContainer) handles the
//! trampoline.
//!
//! Also contains frame-level orchestration: loading transition detection,
//! watchdog flag consumption, emergency cleanup, and AI thread sync.

use libc::c_void;

use super::allocator;
use super::pool;
use super::engine::globals::{self, PddQueue};
use super::pressure::PressureRelief;
use super::statics;
use super::texture_cache;
use super::game_guard;
use super::watchdog;

// ---- Game heap alloc/free/msize/realloc ----

/// GameHeap::Allocate hook (thiscall). Forwards to [`allocator::alloc`].
pub unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { allocator::alloc(size) }
}

/// GameHeap::Free hook (thiscall). Forwards to [`allocator::free`].
pub unsafe extern "thiscall" fn hook_gheap_free(
    _this: *mut c_void,
    ptr: *mut c_void,
) {
    unsafe { allocator::free(ptr) }
}

/// GameHeap::Msize hook (thiscall). Forwards to [`allocator::msize`].
pub unsafe extern "thiscall" fn hook_gheap_msize(
    _this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
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
/// Level 2 (aggressive): heavy drain -- clear backlog.
const PDD_ROUNDS_NORMAL: u32 = 75;
const PDD_ROUNDS_AGGRESSIVE: u32 = 200;

thread_local! {
    // Loading transition detection.
    static WAS_LOADING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Cooldown counter for "turbo cleanup" during loading spikes.
/// Prevents per-frame destruction_protocol calls when Havok is busy.
static TURBO_COOLDOWN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Cooldown for destruction_protocol during VAS crisis.
/// Running pre_destruction_setup 4x/sec allocates terrain/LOD memory
/// (Ghidra: FUN_00878160 step 5), making VAS pressure WORSE.
/// Limit to 1 cycle per second during crisis.
static DESTRUCTION_COOLDOWN_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Consecutive ineffective VAS EMERGENCY cycle counter.
/// If 3+ cycles drain < 1MB each, we're in a death spiral — disable
/// emergency until commit drops below threshold.
static EMERGENCY_INEFFECTIVE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Set when death spiral detected. Overrides the commit-based emergency
/// calculation until commit drops below the emergency threshold.
static EMERGENCY_SUPPRESSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Last tick count when periodic pool drain ran.
/// Drains large blocks (> 1KB) when pool is near capacity.
static LAST_POOL_DRAIN_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Cooldown for periodic pool drain (1 second).
/// Only drains large blocks (>= 1KB) which are safer to free than small
/// UAF-sensitive blocks. Small blocks stay in the zombie pool for protection.
const POOL_DRAIN_COOLDOWN_MS: u64 = 1000;

/// Phase 7: per-frame queue drain (before AI_START).
///
/// Vanilla behavior: Only drains PDD queues and emergency pool.
/// Cleanup (cell unload, Havok GC, etc.) runs ONLY on allocation failure
/// via the OOM retry loop in the allocator, NOT on a timer.
///
/// This matches vanilla timing: cleanup runs when needed (alloc fails),
/// not when we think it's needed (watchdog timer).
pub unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Activate pool on first non-loading frame.
    if !allocator::is_pool_active() {
        globals::set_main_thread_id();
        if !globals::is_loading() {
            allocator::activate_pool();
        }
    }

    // Snapshot pool held bytes for cross-thread diagnostics (watchdog).
    pool::snapshot_pool_stats();

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
    // Draining small blocks risks UAF, but purge_delay=50ms gives stale
    // readers a 50ms window to finish before pages are decommitted.
    // The alternative (drain 0 blocks) is a guaranteed crash.
    if heap.take_emergency_drain() {
        let commit_before = heap.commit_mb();
        let drained = unsafe { heap.drain_pool(pool::ALIGN) };
        unsafe { libmimalloc::mi_collect(true) };

        // Sleep 50ms to let the purge_delay window expire.
        // This gives stale readers time to finish accessing pages that
        // were just decommitted by mi_collect(true). Without this sleep,
        // the worker thread might retry allocation immediately and hit
        // decommitted pages.
        libpsycho::os::windows::winapi::sleep(50);

        log::warn!(
            "[OOM] Emergency drain: {} blocks, commit={}-->{}MB pool={}MB",
            drained, commit_before, heap.commit_mb(), heap.pool_mb(),
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
    let vas_emergency_commit = allocator::get_emergency_commit();
    let vas_critical_commit = allocator::get_critical_commit();

    // Death spiral suppression: if commit drops below emergency threshold,
    // clear the suppression flag so emergency can fire again next time.
    if commit < vas_emergency_commit {
        EMERGENCY_SUPPRESSED.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    // Emergency is active if commit exceeds threshold AND not suppressed.
    let vas_emergency = commit >= vas_emergency_commit
        && !EMERGENCY_SUPPRESSED.load(std::sync::atomic::Ordering::Relaxed);
    let vas_critical = commit >= vas_critical_commit;

    allocator::set_vas_emergency(vas_emergency);

    // Cap VAS EMERGENCY cycles: if 3+ consecutive cycles drain < 1MB,
    // we're in a death spiral. Disable emergency until commit drops
    // below the threshold. This prevents the 40+ cycle death spiral
    // that corrupted the stack during the last crash.
    const MAX_INEFFECTIVE_EMERGENCY_CYCLES: u32 = 3;
    const MIN_EFFECTIVE_DRAIN_MB: usize = 1;

    if vas_emergency {
        let drained = unsafe { pool::pool_drain_all() };
        let freed_mb = drained.saturating_mul(64) / 1024; // rough: 64B avg per block

        if freed_mb < MIN_EFFECTIVE_DRAIN_MB {
            let count = EMERGENCY_INEFFECTIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if count >= MAX_INEFFECTIVE_EMERGENCY_CYCLES {
                // Death spiral detected — suppress emergency until commit
                // drops below the emergency threshold. This prevents the
                // 40+ cycle death spiral that corrupted the stack.
                EMERGENCY_SUPPRESSED.store(true, std::sync::atomic::Ordering::Relaxed);
                allocator::set_vas_emergency(false);
                log::error!(
                    "[VAS] EMERGENCY SUPPRESSED: {} ineffective cycles, commit={}MB, threshold={}MB, drained {} blocks",
                    count, commit / 1024 / 1024, vas_emergency_commit / 1024 / 1024, drained,
                );
            }
        } else {
            EMERGENCY_INEFFECTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
        }

        // F3: Nuclear option — drain ALL pool blocks + force decommit
        // partially-empty mimalloc segments. mi_collect(true) is needed
        // because during loading/stress, segments are partially-empty
        // (freed pages mixed with allocated pages). mi_collect(false)
        // only decommits fully-empty segments — a no-op during crisis.
        unsafe { libmimalloc::mi_collect(true) };
        log::error!(
            "[VAS] EMERGENCY: commit={}MB, drained {} blocks, pool={}MB",
            commit / 1024 / 1024, drained, heap.pool_mb(),
        );
    } else {
        // Not in emergency — reset ineffective counter so it starts fresh
        // next time we enter emergency.
        EMERGENCY_INEFFECTIVE.store(0, std::sync::atomic::Ordering::Relaxed);

        if vas_critical {
            // F2: Drain ALL pool blocks (not just >= 1KB).
            // The 127MB pool is entirely small blocks (< 1KB). drain_large returns 0.
            let drained = unsafe { heap.drain_pool(pool::ALIGN) };
            log::warn!(
                "[VAS] CRITICAL: commit={}MB, drained {} blocks, pool={}MB",
                commit / 1024 / 1024, drained, heap.pool_mb(),
            );
        }
    }

    // --- Periodic Pool Drain ---
    // When the pool exceeds 50MB (80% of 64MB hard cap), drain large blocks
    // (>= 1KB) to prevent the pool from filling up completely. Large blocks
    // are safer to free than small UAF-sensitive blocks (NiRefObjects are
    // typically 16-128 bytes). Small blocks stay in the zombie pool.
    //
    // This runs every 1 second to avoid draining too aggressively.
    if heap.pool_mb() >= 50 {
        let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
        let last = LAST_POOL_DRAIN_MS.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) >= POOL_DRAIN_COOLDOWN_MS {
            let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
            LAST_POOL_DRAIN_MS.store(now, std::sync::atomic::Ordering::Relaxed);
            if drained > 0 {
                log::info!("[POOL] Periodic drain: {} blocks freed, pool={}MB", drained, heap.pool_mb());
            }
        }
    }

    if request >= 1 && !vas_emergency {
        heap.signal_heap_compact(globals::HeapCompactStage::HavokGC);
        // During VAS crisis, skip redundant drain_large (already done above).
        if !vas_critical {
            let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
            log::info!(
                "[WATCHDOG] Phase 7 cleanup: drained {}, level={}, commit={}MB, pdd(NiNode={} Gen={} Form={})",
                drained, request, commit / 1024 / 1024,
                globals::pdd_queue_count(PddQueue::NiNode),
                globals::pdd_queue_count(PddQueue::Generic),
                globals::pdd_queue_count(PddQueue::Form),
            );
        }
    }

    // F4: Cap destruction_protocol to 1/sec during VAS crisis.
    // pre_destruction_setup allocates terrain/LOD memory (Ghidra: FUN_00878160),
    // running it 4x/sec during crisis makes VAS pressure WORSE.
    if request >= 2
        && let Some(pr) = PressureRelief::instance() {
            let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
            let last = DESTRUCTION_COOLDOWN_MS.load(std::sync::atomic::Ordering::Relaxed);
            if vas_critical {
                // During VAS crisis: 1 second cooldown
                if now.saturating_sub(last) >= 1000 {
                    DESTRUCTION_COOLDOWN_MS.store(now, std::sync::atomic::Ordering::Relaxed);
                    unsafe { pr.run_cleanup() };
                }
            } else {
                // Normal: no cooldown
                unsafe { pr.run_cleanup() };
            }
        }

    // --- "Turbo" Cleanup during loading spikes ---
    // During fast travel, the game allocates rapidly. The 500ms cooldown is
    // too slow to keep up with these spikes.
    // If we are loading AND commit exceeds the session baseline by a safety
    // margin (512MB), run cleanup to prevent OOM.
    // This is fully dynamic: it adapts to the user's specific baseline usage.
    //
    // Cooldown: 10 frames (~166ms) between turbo cleanup calls to avoid
    // per-frame wasted calls when Havok is busy.
    const LOADING_SAFETY_MARGIN: usize = 512 * 1024 * 1024; // 512MB
    if globals::is_loading()
        && let Some(pr) = PressureRelief::instance() {
            let baseline = pr.baseline_commit();
            let cooldown = TURBO_COOLDOWN.load(std::sync::atomic::Ordering::Relaxed);
            if cooldown > 0 {
                TURBO_COOLDOWN.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            } else if baseline > 0 && heap.commit_bytes() > baseline + LOADING_SAFETY_MARGIN {
                unsafe { pr.run_cleanup() };
                TURBO_COOLDOWN.store(10, std::sync::atomic::Ordering::Release);
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
        // Drain ALL queues (NiNode + Generic + Form), not just NiNode.
        if request >= 1 {
            let max_rounds = if request >= 2 { PDD_ROUNDS_AGGRESSIVE } else { PDD_ROUNDS_NORMAL };
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

            // Drain pool to catch blocks freed by PDD + decommit.
            unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };

            log::debug!(
                "[PDD] Drained {} rounds, pdd(NiNode={} Gen={} Form={}), commit={}MB, pool={}MB",
                rounds,
                globals::pdd_queue_count(PddQueue::NiNode),
                globals::pdd_queue_count(PddQueue::Generic),
                globals::pdd_queue_count(PddQueue::Form),
                heap.commit_mb(),
                heap.pool_mb(),
            );
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

    log::info!(
        "[LOADING] Transition detected: commit={}MB, pool={}MB",
        commit_before / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
    );

    // Enable loading bypass immediately. Subsequent frees during loading
    // go directly to mi_free for immediate VAS recovery. We don't do
    // proactive cleanup - vanilla doesn't either.
    allocator::set_loading_bypass(true);
}

// First frame after loading ends. Disable loading bypass, resume normal pooling.
//
// DO NOT call mi_collect or drain_pool here. During post-loading stabilization,
// NVSE is rebuilding its FunctionInfo cache from freshly-reallocated Script
// bytecode buffers. mi_collect(false) decommits freed pages within partially-
// empty mimalloc segments. If the OLD bytecode pages are decommitted BEFORE
// NVSE finishes building its cache, NVSE's ScriptIterator dereferences
// decommitted memory → C0000005 in ScriptAnalyzer.cpp:162.
//
// The pool is always empty after loading (inactive during loading), so
// drain_pool returns 0 blocks. The mi_collect provides zero VAS benefit
// (commit is already stable after loading ends) but introduces a page
// decommit race window that causes deterministic crashes with large mod
// lists (525MB+ loading spikes).
//
// See: analysis/ghidra/output/memory/bulletproof_script_crash.txt
#[cold]
fn on_loading_end() {
    allocator::set_loading_bypass(false);

    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    log::info!(
        "[LOADING] Loading ended, commit={}MB, pool={}MB",
        info.get_current_commit() / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
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

    // Pressure relief is now driven by the watchdog thread via
    // CLEANUP_REQUESTED flags consumed at Phase 7. No per-frame
    // relieve() call needed here.
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
        if deferred > 0
            && let Some(result) =
                super::engine::cell_unload::execute_during_loading(deferred)
                && result.cells > 0 {
                    static PENDING_CELLS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                    PENDING_CELLS.store(true, std::sync::atomic::Ordering::Release);
                }
        return;
    }

    // Normal gameplay: only console commands.
    let deferred = super::engine::cell_unload::take_deferred_request();
    if deferred > 0
        && let Some(result) = super::engine::cell_unload::execute(deferred)
            && result.cells > 0 {
                static PENDING_CELLS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                PENDING_CELLS.store(true, std::sync::atomic::Ordering::Release);
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

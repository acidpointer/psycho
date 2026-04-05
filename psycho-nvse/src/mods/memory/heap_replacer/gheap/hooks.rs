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
    // Drain large blocks (>= 1KB) from main thread's pool. Safe --
    // small zombie blocks preserved for concurrent readers.
    if heap.take_emergency_drain() {
        let commit_before = heap.commit_mb();
        let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
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

    if request >= 1 {
        heap.signal_heap_compact(globals::HeapCompactStage::HavokGC);
        let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
        log::info!(
            "[WATCHDOG] Phase 7 cleanup: drained {}, level={}, pdd(NiNode={} Gen={} Form={})",
            drained, request,
            globals::pdd_queue_count(PddQueue::NiNode),
            globals::pdd_queue_count(PddQueue::Generic),
            globals::pdd_queue_count(PddQueue::Form),
        );
    }
    if request >= 2
        && let Some(pr) = PressureRelief::instance() {
            unsafe { pr.run_cleanup() };
        }

    // --- "Turbo" Cleanup during loading spikes ---
    // During fast travel, the game allocates rapidly. The 500ms cooldown is
    // too slow to keep up with these spikes.
    // If we are loading AND commit exceeds the session baseline by a safety
    // margin (512MB), run cleanup every frame to prevent OOM.
    // This is fully dynamic: it adapts to the user's specific baseline usage.
    const LOADING_SAFETY_MARGIN: usize = 512 * 1024 * 1024; // 512MB
    if globals::is_loading()
        && let Some(pr) = PressureRelief::instance() {
            let baseline = pr.baseline_commit();
            // baseline is in bytes. If baseline is 0 (not yet calibrated), skip.
            if baseline > 0 && heap.commit_bytes() > baseline + LOADING_SAFETY_MARGIN {
                unsafe { pr.run_cleanup() };
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

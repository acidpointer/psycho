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
/// Level 1 (normal): moderate drain — keep queues from growing.
/// Level 2 (aggressive): heavy drain — clear backlog.
const PDD_ROUNDS_NORMAL: u32 = 75;
const PDD_ROUNDS_AGGRESSIVE: u32 = 200;

thread_local! {
    // Loading transition detection.
    static WAS_LOADING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Phase 7: per-frame queue drain (before AI_START).
///
/// 1. Loading transition detection (on_loading_start / on_loading_end)
/// 2. Emergency cleanup from worker OOM (two-step pool drain)
/// 3. Watchdog-driven cleanup (HeapCompact + drain_large + cell unload)
/// 4. Clear texture dead set (under write lock for BST coherency)
/// 5. Call original PDD + boosted NiNode drain under pressure
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
    // Drain large blocks (>= 1KB) from main thread's pool. Safe —
    // small zombie blocks preserved for concurrent readers.
    if heap.take_emergency_drain() {
        let commit_before = heap.commit_mb();
        let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
        log::warn!(
            "[OOM] Emergency drain: {} blocks, commit={}→{}MB pool={}MB",
            drained, commit_before, heap.commit_mb(), heap.pool_mb(),
        );
    }

    // --- Watchdog-driven cleanup ---
    let request = watchdog::take_cleanup_request();

    if request >= 1 {
        heap.signal_heap_compact(globals::HeapCompactStage::HavokGC);
        // Drain large blocks (>= 1KB). Small blocks stay for zombie safety —
        // BSTreeNode (256-1200 bytes) and NiRefObject (16-128 bytes) are
        // accessed by scene graph traversal after free. Draining them causes
        // C0000417 (dangling BSTreeManager pointers).
        let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
        log::info!(
            "[WATCHDOG] Phase 7 cleanup: drained {}, level={}, pdd(NiNode={} Gen={} Form={})",
            drained, request,
            globals::pdd_queue_count(PddQueue::NiNode),
            globals::pdd_queue_count(PddQueue::Generic),
            globals::pdd_queue_count(PddQueue::Form),
        );
    }
    if request >= 2 && !globals::is_loading() {
        // Normal gameplay: signal cell unload for AI_JOIN.
        // During loading: large bypass is already active (on_loading_start),
        // game's own CellTransitionHandler handles cleanup.
        if let Some(pr) = PressureRelief::instance() {
            pr.set_deferred_unload();
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

// Cell unload from Phase 7 during loading.
// Phase 7 runs before AI_START — AI is not active, CellUnloadGuard succeeds.
// CellUnloadGuard enables large bypass so freed objects reclaim VAS.
// 5-second cooldown to avoid over-triggering.
// Loading transition cleanup threshold.
const LOADING_CLEANUP_GROWTH: usize = 300 * 1024 * 1024; // 300MB
const LOADING_CLEANUP_MAX_CELLS: usize = 20;

// First frame where loading starts. Run proper cleanup:
//   1. Enable large bypass (frees during cleanup reclaim VAS)
//   2. HeapCompact 0-3 (texture, geometry, menu, Havok GC)
//   3. Cell unload via execute_during_loading (if growth warrants)
//   4. Drain large pool blocks + mi_collect
//   5. Disable large bypass
#[cold]
unsafe fn on_loading_start() {
    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    let commit_before = info.get_current_commit();

    log::info!(
        "[LOADING] Transition detected: commit={}MB, pool={}MB",
        commit_before / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
    );

    // Enable loading bypass for the entire loading phase.
    // Game's CellTransitionHandler + PDD frees will reclaim VAS.
    allocator::set_loading_bypass(true);

    let heap = super::heap_manager::HeapManager::get();

    // HeapCompact 0-3 (texture flush, geometry cache, menu, Havok GC).
    heap.signal_heap_compact(globals::HeapCompactStage::HavokGC);

    // Cell unload with scoped bypass (cleanup runs inside with_large_bypass).
    let (cells, drained) = allocator::with_large_bypass(|| {
        let mut cells = 0usize;
        if let Some(pr) = PressureRelief::instance() {
            let baseline = pr.baseline_commit();
            if baseline > 0 {
                let growth = commit_before.saturating_sub(baseline);
                if growth >= LOADING_CLEANUP_GROWTH
                    && let Some(result) =
                        super::engine::cell_unload::execute_during_loading(LOADING_CLEANUP_MAX_CELLS)
                    {
                        cells = result.cells;
                        if cells > 0 {
                            pr.set_pending_counter_decrement();
                        }
                    }
            }
        }

        let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
        (cells, drained)
    });

    let commit_after = libmimalloc::process_info::MiMallocProcessInfo::get()
        .get_current_commit();
    log::info!(
        "[LOADING] Cleanup done: {} cells, {} large drained, commit {}MB-->{}MB, pool={}MB",
        cells, drained,
        commit_before / 1024 / 1024,
        commit_after / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
    );
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

/// Post-load cooldown: timestamp (elapsed_ms) until which game cleanup
/// must NOT run. After loading ends, the game does Havok restart, scene
/// graph rebuild, NPC setup, NVSE events. Running cleanup during this
/// window corrupts game state (frozen enemies, broken physics).
static POST_LOAD_UNTIL: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Cooldown duration after loading ends (milliseconds).
const POST_LOAD_COOLDOWN_MS: u64 = 5000;

fn is_post_load_cooldown() -> bool {
    let until = POST_LOAD_UNTIL.load(std::sync::atomic::Ordering::Relaxed);
    if until == 0 {
        return false;
    }
    let now = libmimalloc::process_info::MiMallocProcessInfo::get().get_elapsed_ms();
    now < until
}

/// Commit growth threshold for proactive cell unload during loading.
/// Lowered from 800MB to 600MB -- loading needs more VAS headroom.
const LOADING_CELL_UNLOAD_GROWTH: usize = 600 * 1024 * 1024;

/// Max cells to unload per loading-time cycle.
const LOADING_MAX_CELLS: usize = 5;

/// Watchdog signals this when level 2 fires during loading.
/// `maybe_loading_cell_unload` reads it to bypass memory-based cooldown.
static FORCE_LOADING_UNLOAD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// AI_JOIN: AI threads completed. Safe for mi_collect(true) and cell unload.
///
/// Three paths:
/// - Loading: set post-load cooldown, proactive cell unload, console commands
/// - Post-load cooldown: discard all cleanup signals
/// - Normal gameplay: run deferred unload, console commands
pub unsafe extern "fastcall" fn hook_ai_thread_join(mgr: *mut c_void) {
    if let Ok(original) = statics::AI_THREAD_JOIN_HOOK.original() {
        unsafe { original(mgr) };
    }
    game_guard::clear_ai_active();

    // --- During loading: set cooldown + proactive cell unload ---
    if globals::is_loading() {
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let until = info.get_elapsed_ms() + POST_LOAD_COOLDOWN_MS as usize;
        POST_LOAD_UNTIL.store(until, std::sync::atomic::Ordering::Relaxed);

        // Proactive cell unload when commit growth is critical.
        unsafe { maybe_loading_cell_unload() };

        // Console command (pcell) during loading.
        let deferred = super::engine::cell_unload::take_deferred_request();
        if deferred > 0
            && let Some(result) =
                super::engine::cell_unload::execute_during_loading(deferred)
                && result.cells > 0
                && let Some(pr) = PressureRelief::instance() {
                    pr.set_pending_counter_decrement();
                }
        return;
    }

    // --- Post-load cooldown: discard all cleanup signals ---
    if is_post_load_cooldown() {
        if let Some(pr) = PressureRelief::instance() {
            pr.clear_deferred_unload();
        }
        super::engine::cell_unload::take_deferred_request();
        return;
    }

    // --- Normal gameplay ---

    // Pressure-driven deferred unload (cell unload + aggressive collect).
    if let Some(pr) = PressureRelief::instance() {
        unsafe { pr.run_deferred_unload() };
    }

    // Console command deferred request (pcell).
    let deferred = super::engine::cell_unload::take_deferred_request();
    if deferred > 0
        && let Some(result) = super::engine::cell_unload::execute(deferred)
            && result.cells > 0
            && let Some(pr) = PressureRelief::instance() {
                pr.set_pending_counter_decrement();
            }
}

#[cold]
unsafe fn maybe_loading_cell_unload() {
    let pr = match PressureRelief::instance() {
        Some(pr) => pr,
        None => return,
    };
    let baseline = pr.baseline_commit();
    if baseline == 0 {
        return;
    }

    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    let commit = info.get_current_commit();
    let growth = commit.saturating_sub(baseline);

    // Watchdog can force cell unload during loading (bypasses growth check).
    let forced = FORCE_LOADING_UNLOAD.swap(false, std::sync::atomic::Ordering::AcqRel);

    if !forced && growth < LOADING_CELL_UNLOAD_GROWTH {
        return;
    }

    // Memory-based cooldown: skip if commit hasn't grown back.
    // Watchdog force bypasses this cooldown too.
    static LOADING_COOLDOWN_COMMIT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    if !forced {
        let cooldown = LOADING_COOLDOWN_COMMIT.load(std::sync::atomic::Ordering::Relaxed);
        if cooldown > 0 && commit < cooldown {
            if cooldown.saturating_sub(commit) < LOADING_CELL_UNLOAD_GROWTH {
                return;
            }
            LOADING_COOLDOWN_COMMIT.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    let max_cells = if forced { LOADING_MAX_CELLS.max(10) } else { LOADING_MAX_CELLS };

    if forced {
        log::warn!(
            "[LOADING] Watchdog-forced cell unload: commit={}MB, growth={}MB",
            commit / 1024 / 1024, growth / 1024 / 1024,
        );
    }

    if let Some(result) =
        super::engine::cell_unload::execute_during_loading(max_cells)
        && result.cells > 0
    {
        let post_commit =
            libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit();
        LOADING_COOLDOWN_COMMIT.store(post_commit, std::sync::atomic::Ordering::Relaxed);

        if let Some(pr) = PressureRelief::instance() {
            pr.set_pending_counter_decrement();
        }
    }
}

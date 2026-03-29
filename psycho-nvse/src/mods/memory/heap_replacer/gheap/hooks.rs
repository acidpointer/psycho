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

/// Extra PDD rounds under pressure (19 extra = 20x total).
const EXTRA_NINODE_ROUNDS: u32 = 19;

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

    // --- Emergency cleanup from worker OOM ---
    // Worker threads can't drain pool (thread-local). This is their
    // ONLY chance to get pool memory freed.
    //   1. Drain large blocks from pool (safe, no UAF)
    //   2. Enable EMERGENCY_LARGE_BYPASS so NEW large frees skip pool
    //      (small blocks still go to pool — preserves zombie data)
    //   3. Run game OOM stages if not loading
    if allocator::EMERGENCY_CLEANUP.swap(false, std::sync::atomic::Ordering::AcqRel) {
        log::warn!("[POOL] Emergency: worker OOM, draining large + enabling bypass");

        let freed = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
        unsafe { libmimalloc::mi_collect(true) };

        // Enable large-block bypass: future frees of >=1KB blocks go
        // directly to mi_free, keeping VAS available for large allocs.
        // Small blocks still go to pool (zombie data safe).
        allocator::EMERGENCY_LARGE_BYPASS.store(true, std::sync::atomic::Ordering::Release);

        log::warn!(
            "[POOL] Emergency: drained {} large blocks, bypass ON, pool={}MB",
            freed, pool::pool_held_bytes() / 1024 / 1024,
        );

        if !globals::is_loading() {
            let ptr = unsafe { globals::run_oom_stages(0) };
            if !ptr.is_null() {
                unsafe { libmimalloc::mi_free(ptr) };
            }
            log::warn!("[POOL] Emergency: game OOM stages completed");
        }
    }

    // --- Watchdog-driven cleanup ---
    let request = watchdog::take_cleanup_request();

    // Clear emergency large bypass when memory is healthy (no cleanup needed).
    if request == 0 && allocator::EMERGENCY_LARGE_BYPASS.load(std::sync::atomic::Ordering::Relaxed) {
        allocator::EMERGENCY_LARGE_BYPASS.store(false, std::sync::atomic::Ordering::Release);
        log::info!("[POOL] Emergency bypass cleared (memory healthy)");
    }

    if request >= 1 {
        // Normal: HeapCompact 0-3 + drain large pool blocks.
        globals::signal_heap_compact(globals::HeapCompactStage::HavokGC);
        let drained = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
        unsafe { libmimalloc::mi_collect(false) };
        log::info!(
            "[WATCHDOG] Phase 7 cleanup: drained {} large blocks, level={}",
            drained, request,
        );
    }
    if request >= 2 {
        if globals::is_loading() {
            // During loading, AI_JOIN does NOT fire — deferred unload is useless.
            // Run cell unload directly from Phase 7 (AI not started yet, safe).
            unsafe { loading_cell_unload_phase7() };
        } else {
            // Normal gameplay: signal cell unload for AI_JOIN.
            if let Some(pr) = PressureRelief::instance() {
                pr.set_deferred_unload();
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

        // Boosted NiNode drain when watchdog flagged cleanup.
        if request >= 1 {
            for _ in 0..EXTRA_NINODE_ROUNDS {
                if globals::pdd_queue_count(PddQueue::NiNode) == 0 {
                    break;
                }
                unsafe { original() };
            }
        }
    }
}

// First frame where loading starts. Proactive cleanup to free VAS.
//
// drain_all is safe here: Phase 7 runs BEFORE AI_START, so no worker
// threads are reading stale pointers at this instant. NVSE MainLoopHook
// already ran for this frame. Next frame's NVSE hook will see the pool
// empty but the game is now in loading state (events suppressed).
#[cold]
unsafe fn on_loading_start() {
    // Drain ALL pool blocks at the transition boundary.
    let drained = unsafe { pool::pool_drain_all() };
    globals::signal_heap_compact(globals::HeapCompactStage::HavokGC);
    unsafe { libmimalloc::mi_collect(true) };

    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    log::info!(
        "[LOADING] Pre-load cleanup: drained {} blocks (all), commit={}MB",
        drained,
        info.get_current_commit() / 1024 / 1024,
    );
}

// First frame after loading ends. Log transition.
#[cold]
fn on_loading_end() {
    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    log::info!(
        "[LOADING] Loading ended, commit={}MB, pool={}MB",
        info.get_current_commit() / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
    );
}

// Cell unload from Phase 7 during loading.
//
// AI_JOIN does NOT fire during loading screens, so deferred cell unload
// never executes. This runs cell unload directly from Phase 7 where
// AI threads are not yet dispatched (is_ai_active = false).
//
// Uses execute_during_loading() which doesn't abort on is_loading().
// Cooldown: minimum 10 seconds between calls (matches watchdog aggressive cooldown).
#[cold]
unsafe fn loading_cell_unload_phase7() {
    static LAST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    const COOLDOWN_MS: u64 = 10_000;

    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    let now_ms = info.get_elapsed_ms() as u64;
    let last = LAST_MS.load(std::sync::atomic::Ordering::Relaxed);
    if now_ms.saturating_sub(last) < COOLDOWN_MS {
        return;
    }
    LAST_MS.store(now_ms, std::sync::atomic::Ordering::Relaxed);

    let commit_before = info.get_current_commit();
    log::warn!(
        "[LOADING] Phase 7 cell unload: commit={}MB, pool={}MB",
        commit_before / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
    );

    // Drain large blocks first to free VAS.
    let drained = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
    unsafe { libmimalloc::mi_collect(true) };

    // Cell unload (up to 10 cells).
    if let Some(result) = super::engine::cell_unload::execute_during_loading(10) {
        if result.cells > 0 {
            // Drain large blocks freed by cell unload.
            let drained2 = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
            unsafe { libmimalloc::mi_collect(true) };

            if let Some(pr) = PressureRelief::instance() {
                pr.set_pending_counter_decrement();
            }

            let commit_after = libmimalloc::process_info::MiMallocProcessInfo::get()
                .get_current_commit();
            log::warn!(
                "[LOADING] Phase 7 cell unload: {} cells, drained {}+{} large blocks, commit {}MB-->{}MB",
                result.cells, drained, drained2,
                commit_before / 1024 / 1024, commit_after / 1024 / 1024,
            );
        }
    }
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
        if deferred > 0 {
            if let Some(result) =
                super::engine::cell_unload::execute_during_loading(deferred)
                && result.cells > 0
            {
                if let Some(pr) = PressureRelief::instance() {
                    pr.set_pending_counter_decrement();
                }
            }
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
    if deferred > 0 {
        if let Some(result) = super::engine::cell_unload::execute(deferred)
            && result.cells > 0
        {
            if let Some(pr) = PressureRelief::instance() {
                pr.set_pending_counter_decrement();
            }
        }
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

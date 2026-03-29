// Thin hook wrappers that delegate to gheap::allocator.
//
// Each function matches the calling convention of the game function it
// replaces. The hook infrastructure (InlineHookContainer) handles the
// trampoline. These wrappers contain zero logic -- just forwarding.

use libc::c_void;

use super::allocator;
use super::pool;
use super::engine::globals::{self, PddQueue};
use super::pressure::PressureRelief;
use super::statics;
use super::texture_cache;
use super::game_guard;

// ---- Game heap alloc/free/msize/realloc ----

pub unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { allocator::alloc(size) }
}

pub unsafe extern "thiscall" fn hook_gheap_free(
    _this: *mut c_void,
    ptr: *mut c_void,
) {
    unsafe { allocator::free(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_msize(
    _this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    unsafe { allocator::msize(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_realloc(
    _this: *mut c_void,
    ptr: *mut c_void,
    new_size: usize,
) -> *mut c_void {
    unsafe { allocator::realloc(ptr, new_size) }
}

// ---- Phase 7: per-frame queue drain (before AI_START) ----
//
// 1. Activate deferred-free on first non-loading frame
// 2. Hand pending buffer to GC thread (frame_tick)
// 3. Clear texture dead set (under write lock for BST coherency)
// 4. Run boosted PDD drain if under pressure

const EXTRA_NINODE_ROUNDS: u32 = 19;
const DIAG_LOG_INTERVAL: u32 = 300;

thread_local! {
    static DIAG_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Activate pool on first non-loading frame.
    if !allocator::is_pool_active() {
        globals::set_main_thread_id();
        if !globals::is_loading() {
            allocator::activate_pool();
        }
    }

    // Handle emergency cleanup signal from worker OOM.
    // Worker threads can't run game OOM stages or drain the main thread's
    // pool. They signal here, and we do it on the main thread at Phase 7.
    if allocator::EMERGENCY_CLEANUP.swap(false, std::sync::atomic::Ordering::AcqRel) {
        log::warn!("[POOL] Emergency: worker OOM, draining pool + game cleanup");
        let freed = unsafe { pool::pool_drain_all() };
        if freed > 0 {
            log::warn!("[POOL] Emergency drained {} blocks", freed);
        }
        unsafe { libmimalloc::mi_collect(true) };

        // Run game's OOM stages on behalf of the stuck worker.
        // This includes cell unload (stage 5), texture flush, PDD purge.
        // The 22MB+ allocation that triggered OOM needs contiguous VAS
        // that only game cleanup can free.
        if !globals::is_loading() {
            let ptr = unsafe { globals::run_oom_stages(0) };
            if !ptr.is_null() {
                // run_oom_stages allocated internally, free it (we don't need it).
                unsafe { libmimalloc::mi_free(ptr) };
            }
            log::warn!("[POOL] Emergency: game OOM stages completed");
        }
    }

    // Pool maintenance: drain excess blocks if BST is idle.
    // Two triggers:
    //   1. Pool exceeds 64MB cap (size-based)
    //   2. Commit exceeds pressure threshold (VAS-based)
    // BST idle check is a non-intrusive semaphore read (~50ns).
    if unsafe { super::engine::io_sync::are_bst_threads_idle() } {
        let should_drain = pool::pool_held_bytes() > 0 && {
            let commit = libmimalloc::process_info::MiMallocProcessInfo::get()
                .get_current_commit();
            let threshold = PressureRelief::instance()
                .map(|pr| pr.threshold())
                .unwrap_or(usize::MAX);
            pool::pool_held_bytes() >= 64 * 1024 * 1024 || commit >= threshold
        };
        if should_drain {
            unsafe { pool::pool_maintain() };
        }
    }

    // Clear texture dead set under write lock.
    // BST's texture_cache_find uses try_read -- blocked during clear.
    game_guard::with_write("dead_set_clear", || {
        texture_cache::clear_dead_set();
    });

    // Call the original per-frame queue drain (PDD).
    if let Ok(original) = statics::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        unsafe { original() };

        // Boosted NiNode drain under pressure.
        if PressureRelief::instance().is_some_and(|pr| pr.is_requested()) {
            for _ in 0..EXTRA_NINODE_ROUNDS {
                if globals::pdd_queue_count(PddQueue::NiNode) == 0 {
                    break;
                }
                unsafe { original() };
            }

            DIAG_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % DIAG_LOG_INTERVAL == 0 {
                    log::debug!(
                        "[PDD] trigger={} queues: NiNode={} Tex={} Anim={} Gen={} Form={}",
                        globals::heap_compact_trigger_value(),
                        globals::pdd_queue_count(PddQueue::NiNode),
                        globals::pdd_queue_count(PddQueue::Texture),
                        globals::pdd_queue_count(PddQueue::Anim),
                        globals::pdd_queue_count(PddQueue::Generic),
                        globals::pdd_queue_count(PddQueue::Form),
                    );
                }
            });
        }
    }
}

// ---- Phase 10: post-render maintenance (before AI_JOIN) ----

pub unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
    if let Ok(original) = statics::MAIN_LOOP_MAINTENANCE_HOOK.original() {
        unsafe { original(this) };
    }

    if let Some(pr) = PressureRelief::instance() {
        pr.calibrate_baseline();
        pr.flush_pending_counter_decrement();
    }

    if let Some(pr) = PressureRelief::instance() {
        unsafe { pr.relieve() };
    }
}

// ---- AI thread start/join ----

pub unsafe extern "fastcall" fn hook_ai_thread_start(mgr: *mut c_void) {
    game_guard::set_ai_active();
    if let Ok(original) = statics::AI_THREAD_START_HOOK.original() {
        unsafe { original(mgr) };
    }
}

// Post-load cooldown: timestamp (elapsed_ms) until which game cleanup
// must NOT run. After loading ends, the game does Havok restart, scene
// graph rebuild, NPC setup, NVSE events. Running cleanup during this
// window corrupts game state (frozen enemies, broken physics).
static POST_LOAD_UNTIL: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const POST_LOAD_COOLDOWN_MS: u64 = 5000;

fn is_post_load_cooldown() -> bool {
    let until = POST_LOAD_UNTIL.load(std::sync::atomic::Ordering::Relaxed);
    if until == 0 {
        return false;
    }
    let now = libmimalloc::process_info::MiMallocProcessInfo::get().get_elapsed_ms();
    now < until
}

// During loading: commit growth threshold for proactive cell unload.
const LOADING_CELL_UNLOAD_GROWTH: usize = 800 * 1024 * 1024;
const LOADING_MAX_CELLS: usize = 3;

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

    if growth < LOADING_CELL_UNLOAD_GROWTH {
        return;
    }

    // Memory-based cooldown: skip if commit hasn't grown back.
    static LOADING_COOLDOWN_COMMIT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    let cooldown = LOADING_COOLDOWN_COMMIT.load(std::sync::atomic::Ordering::Relaxed);
    if cooldown > 0 && commit < cooldown {
        // Stale check: if commit dropped far below cooldown, new session.
        if cooldown.saturating_sub(commit) < LOADING_CELL_UNLOAD_GROWTH {
            return;
        }
        LOADING_COOLDOWN_COMMIT.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    if let Some(result) =
        super::engine::cell_unload::execute_during_loading(LOADING_MAX_CELLS)
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

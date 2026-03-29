//! Central coordinator for all game heap operations.
//!
//! Replaces the game's SBM pool allocator (FUN_00aa3e40/FUN_00aa4060)
//! with mimalloc. Quarantine provides zombie protection for freed objects.
//!
//! # Quarantine design -- double-buffer with frame separation
//!
//! Freed objects go to the current buffer (zombie, readable). At Phase 7
//! the previous buffer is drained (mi_free). Mid-frame the buffers swap.
//! Objects survive at least one full frame before reclamation.
//!
//! ```text
//! free(ptr):  push to current buffer (zombie, readable)
//! Phase 7:    drain previous buffer (mi_free here ONLY)
//! mid-frame:  swap current <-> previous (NO mi_free)
//! OOM:        drain all + game cleanup + bounded retry.
//! ```
//!
//! # Thread model
//!
//! | Thread            | Quarantine behavior        |
//! |-------------------|----------------------------|
//! | Main              | push to quarantine on free  |
//! | AI worker (2)     | mi_free directly            |
//! | BSTaskMgr (2)     | mi_free directly            |
//!
//! # Frame lifecycle
//!
//! ```text
//! Phase 6  (HeapCompact)  PDD processes queues
//! Phase 7  on_pre_ai:     drain previous, clear dead set (write lock)
//! Phase 8  on_ai_start:   set AI_ACTIVE
//! Phase 9  (render)
//! Phase 10 on_mid_frame:  rotate buffers, calibrate pressure, relieve
//! Phase 11 on_ai_join:    clear AI_ACTIVE, deferred unload
//! ```

use libc::c_void;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned, mi_usable_size,
};

use super::engine::{addr, globals};
use super::game_guard;
use super::pressure::PressureRelief;
use super::quarantine;
use super::statics;
use crate::mods::memory::heap_replacer::heap_validate;

const ALIGN: usize = 16;

// Pressure check interval. Every N allocs, check commit threshold.
const PRESSURE_CHECK_INTERVAL: u32 = 50_000;

// During loading: only unload cells when commit growth is very high.
// Higher threshold than normal pressure relief (800MB vs 500MB) because
// loading is more sensitive to disruption. The game's own OOM stage 5
// does the same thing -- FindCellToUnload during loading with no loading check.
const LOADING_CELL_UNLOAD_GROWTH: usize = 800 * 1024 * 1024;

// Max cells to unload per frame during loading. Conservative to minimize
// loading frame time impact. FindCellToUnload + IO/Havok lock ceremony
// takes ~1-5ms per cell.
const LOADING_MAX_CELLS: usize = 3;

thread_local! {
    static ALLOC_COUNTER: Cell<u32> = const { Cell::new(0) };
}

// ===========================================================================
// Watchdog -- background thread for memory monitoring
// ===========================================================================

/// Signal from watchdog to main thread: how many cells to unload.
/// 0 = no action needed. Read + cleared by on_ai_join.
static WATCHDOG_CELL_UNLOAD: AtomicU8 = AtomicU8::new(0);

/// Emergency cleanup signal from worker OOM --> main thread alloc.
/// When a worker can't allocate, it sets this flag. The main thread's
/// next alloc checks it and runs quarantine flush inline.
pub static EMERGENCY_CLEANUP: AtomicBool = AtomicBool::new(false);

/// Watchdog check interval. 200ms for responsive loading detection.
const WATCHDOG_INTERVAL_MS: u64 = 200;

/// Post-load cooldown: timestamp (elapsed_ms) until which game cleanup
/// functions must NOT be called. Set by on_ai_join when loading is
/// detected, checked by on_ai_join AND recover_oom.
///
/// After loading ends, the game does post-load init (Havok restart,
/// scene graph rebuild, NPC setup, NVSE events). Calling game cleanup
/// (OOM stages, HeapCompact, cell unload) during this window corrupts
/// game state -- frozen enemies, broken physics, black screen freeze.
static POST_LOAD_UNTIL: AtomicUsize = AtomicUsize::new(0);
const POST_LOAD_COOLDOWN_MS: u64 = 5000;

/// Check if we're in the post-load cooldown window.
fn is_post_load_cooldown() -> bool {
    let until = POST_LOAD_UNTIL.load(Ordering::Relaxed);
    if until == 0 {
        return false;
    }
    let now = libmimalloc::process_info::MiMallocProcessInfo::get().get_elapsed_ms();
    now < until
}

/// Start the watchdog thread. Called once from install.
/// The thread monitors commit growth and logs loading transitions.
/// Does NOT touch game state -- only reads mimalloc stats and sets atomics.
pub fn start_watchdog() {
    std::thread::Builder::new()
        .name("psycho-watchdog".into())
        .spawn(watchdog_loop)
        .ok();
}

fn watchdog_loop() {
    use libpsycho::os::windows::winapi;

    log::info!("[WATCHDOG] Started (interval={}ms)", WATCHDOG_INTERVAL_MS);

    // Wait for pressure baseline to be calibrated (first frame tick).
    loop {
        winapi::sleep(WATCHDOG_INTERVAL_MS as u32);
        if PressureRelief::instance().is_some_and(|pr| pr.baseline_commit() > 0) {
            break;
        }
    }

    let mut was_loading = false;

    loop {
        winapi::sleep(WATCHDOG_INTERVAL_MS as u32);

        // Log loading transitions (off main thread, no FPS impact).
        let loading = globals::is_loading();
        if loading != was_loading {
            was_loading = loading;
            let info = libmimalloc::process_info::MiMallocProcessInfo::get();
            if loading {
                log::warn!(
                    "[LOADING] Started: commit={}MB, quarantine={}MB",
                    info.get_current_commit() / 1024 / 1024,
                    quarantine::usage() / 1024 / 1024,
                );
            } else {
                log::warn!(
                    "[LOADING] Ended: commit={}MB, quarantine={}MB",
                    info.get_current_commit() / 1024 / 1024,
                    quarantine::usage() / 1024 / 1024,
                );
            }
        }

        let pr = match PressureRelief::instance() {
            Some(pr) => pr,
            None => continue,
        };

        let baseline = pr.baseline_commit();
        if baseline == 0 {
            continue;
        }

        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        let commit = info.get_current_commit();
        let growth = commit.saturating_sub(baseline);

        // Thresholds for cell unload signal.
        // High thresholds -- only trigger when genuinely near OOM.
        // Low thresholds cause useless cell churn (unload --> reload cycle).
        const HIGH: usize = 1000 * 1024 * 1024;
        const CRITICAL: usize = 1200 * 1024 * 1024;

        let cells = if growth >= CRITICAL {
            10u8
        } else if growth >= HIGH {
            5
        } else {
            0
        };

        if cells > 0 {
            let current = WATCHDOG_CELL_UNLOAD.load(Ordering::Relaxed);
            if current == 0 {
                WATCHDOG_CELL_UNLOAD.store(cells, Ordering::Release);
                log::info!(
                    "[WATCHDOG] Cell unload signaled: {} cells (commit={}MB, growth={}MB)",
                    cells,
                    commit / 1024 / 1024,
                    growth / 1024 / 1024,
                );
            }
        }
    }
}

// ===========================================================================
// Thread identity (cached per-thread)
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ThreadRole {
    Unknown = 0,
    Main = 1,
    Worker = 2,
}

thread_local! {
    static THREAD_ROLE: Cell<ThreadRole> = const { Cell::new(ThreadRole::Unknown) };
}

// ===========================================================================
// HeapOrchestrator
// ===========================================================================

pub struct HeapOrchestrator;

impl HeapOrchestrator {
    // =======================================================================
    // Thread identity
    // =======================================================================

    /// Check if current thread is main. Cached per-thread once TES is available.
    ///
    /// Before TES init: returns false without caching (re-checks next call).
    /// After TES init: resolves via OS thread ID, caches permanently.
    /// Cached path: single TLS read (same perf as previous commit).
    #[inline]
    pub fn is_main_thread() -> bool {
        THREAD_ROLE.with(|r| {
            match r.get() {
                ThreadRole::Main => true,
                ThreadRole::Worker => false,
                ThreadRole::Unknown => {
                    let is_main = globals::is_main_thread_by_tid();
                    if is_main {
                        r.set(ThreadRole::Main);
                    } else if quarantine::is_active() {
                        // Game loop started (on_pre_ai set quarantine active).
                        // TES is fully initialized. Safe to cache Worker.
                        r.set(ThreadRole::Worker);
                    }
                    is_main
                }
            }
        })
    }

    /// Quarantine byte count (for logging/diagnostics).
    pub fn quarantine_usage() -> usize {
        quarantine::usage()
    }

    // =======================================================================
    // Allocation API
    // =======================================================================

    #[inline]
    pub unsafe fn alloc(size: usize) -> *mut c_void {
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            ALLOC_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % PRESSURE_CHECK_INTERVAL == 0
                    && let Some(pr) = PressureRelief::instance() {
                        unsafe { pr.check() };
                    }
            });
            return ptr;
        }
        unsafe { Self::recover_oom(size) }
    }

    #[inline]
    pub unsafe fn free(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            if Self::is_main_thread() {
                if !quarantine::is_active() {
                    // Before first frame tick: mi_free directly.
                    unsafe { libmimalloc::mi_free(ptr) };
                } else {
                    // Pending-free: stays allocated until Phase 7 BST-idle drain.
                    quarantine::push(ptr);
                }
                return;
            }

            // Worker thread: free directly. Thread-local mimalloc heap is safe.
            unsafe { libmimalloc::mi_free(ptr) };
            return;
        }

        // Pre-hook pointer: original trampoline handles SBM arenas.
        if let Ok(orig_free) = statics::GHEAP_FREE_HOOK.original() {
            unsafe { orig_free(addr::HEAP_SINGLETON as *mut c_void, ptr) };
            return;
        }

        unsafe { heap_validate::heap_validated_free(ptr) };
    }

    #[inline]
    pub unsafe fn msize(ptr: *mut c_void) -> usize {
        if ptr.is_null() {
            return 0;
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            return unsafe { mi_usable_size(ptr as *const c_void) };
        }

        if let Ok(orig_msize) = statics::GHEAP_MSIZE_HOOK.original() {
            let size = unsafe { orig_msize(addr::HEAP_SINGLETON as *mut c_void, ptr) };
            if size != 0 {
                return size;
            }
        }

        let size = unsafe { heap_validate::heap_validated_size(ptr as *const c_void) };
        if size != usize::MAX {
            return size;
        }

        0
    }

    #[inline]
    pub unsafe fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
        if ptr.is_null() {
            return unsafe { Self::alloc(new_size) };
        }

        if new_size == 0 {
            unsafe { Self::free(ptr) };
            return null_mut();
        }

        if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
            let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
            if !new_ptr.is_null() {
                return new_ptr;
            }
            return unsafe { Self::recover_oom(new_size) };
        }

        // Pre-hook pointer: alloc new, copy, free old.
        let old_size = unsafe { Self::msize(ptr) };
        if old_size == 0 {
            return null_mut();
        }

        // Use alloc() which has full OOM recovery + CRT fallback.
        let new_ptr = unsafe { Self::alloc(new_size) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_size.min(new_size),
                );
            }
            unsafe { Self::free(ptr) };
        }
        new_ptr
    }

    // =======================================================================
    // Frame lifecycle
    // =======================================================================

    /// Phase 7 (before AI_START): drain pending-free list if threads are idle.
    ///
    /// Checks BST idle state (non-intrusive semaphore read). If idle,
    /// mi_frees all pending entries under write lock and clears dead set.
    /// If BST busy, skips — objects stay as zombies until next frame.
    ///
    /// Also handles EMERGENCY_CLEANUP signal from worker OOM (forces drain
    /// even if BST is busy — OOM is worse than potential BST stale read).
    pub unsafe fn on_pre_ai() {
        // First call: set main thread ID from here -- the ONE place we're
        // 100% certain is the game's main thread (main loop Phase 7 hook).
        // Also activates pending-free. Before this, all frees go to mi_free.
        if !quarantine::is_active() {
            globals::set_main_thread_id();

            // Only activate when NOT loading.
            // First save load from menu: game loop runs frames during loading.
            // If we activate here, loading frees accumulate in the pending list
            // instead of mi_free --> unbounded growth.
            // After loading ends: next on_pre_ai activates for gameplay.
            if !globals::is_loading() {
                quarantine::activate();
            }
        }

        // Handle emergency cleanup signal from worker OOM.
        // Forces drain even if BST is busy — OOM is worse.
        let force = EMERGENCY_CLEANUP.swap(false, Ordering::AcqRel);
        if force {
            log::warn!("[EMERGENCY] Forcing pending-free drain at Phase 7");
        }

        // Drain pending-free list at Phase 7 — the ONE safe point.
        // AI is idle (not yet dispatched). BST idle checked internally.
        // HeapCompact (Phase 6) already ran. AI hasn't started (Phase 8).
        quarantine::tick_flush(force);

        // During loading: discard stale watchdog signals.
        // Console command (deferred request) is NOT discarded here --
        // it's handled by on_ai_join's loading path via execute_during_loading.
        if globals::is_loading() {
            WATCHDOG_CELL_UNLOAD.store(0, Ordering::Relaxed);
        }
    }

    /// Mid-frame (post-render, before AI_JOIN): pressure relief only.
    ///
    /// AI threads are STILL ACTIVE — no memory operations here.
    pub unsafe fn on_mid_frame() {

        if let Some(pr) = PressureRelief::instance() {
            pr.calibrate_baseline();
            pr.flush_pending_counter_decrement();
        }

        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.relieve() };
        }
    }

    /// AI_START: mark AI threads active.
    pub fn on_ai_start() {
        game_guard::set_ai_active();
    }

    /// AI_JOIN: mark AI threads inactive, run deferred unload.
    ///
    /// Cell unload runs ONLY through pressure relief's destruction_protocol
    /// (which has proper cooldowns) or the console command's deferred request.
    /// Watchdog signals are consumed but NOT acted on directly -- the pressure
    /// system handles memory-driven cell unload with its own rate limiting.
    pub unsafe fn on_ai_join() {
        game_guard::clear_ai_active();

        // During loading: skip normal cleanup but allow cell unload when
        // commit growth is critical. AI is idle (just joined), same lock
        // sequence as the game's own OOM handler (run_oom_stages stage 5).
        if globals::is_loading() {
            let info = libmimalloc::process_info::MiMallocProcessInfo::get();
            let until = info.get_elapsed_ms() + POST_LOAD_COOLDOWN_MS as usize;
            POST_LOAD_UNTIL.store(until, Ordering::Relaxed);

            // Proactive cell unload during loading (commit-gated).
            unsafe { Self::maybe_loading_cell_unload() };

            // Console command (pcell) during loading: use loading-aware path.
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

        if is_post_load_cooldown() {
            // Discard all cleanup signals during cooldown.
            if let Some(pr) = PressureRelief::instance() {
                pr.clear_deferred_unload();
            }
            WATCHDOG_CELL_UNLOAD.store(0, Ordering::Relaxed);
            super::engine::cell_unload::take_deferred_request();
            return;
        }

        // Pressure-driven deferred unload (aggressive collect + cell unload).
        // Has its own cooldowns (COOLDOWN_MS: 2000, AGGRESSIVE_COOLDOWN_MS: 10000).
        if let Some(pr) = PressureRelief::instance() {
            unsafe { pr.run_deferred_unload() };
        }

        // Console command deferred request (pcell command).
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

        // Consume watchdog signal. Pressure relief system handles memory-driven
        // cell unload through run_deferred_unload with proper cooldowns.
        // Direct watchdog-to-cell-unload caused cascading failure:
        // longer frames -> more pressure -> more cell unloads -> even longer frames.
        WATCHDOG_CELL_UNLOAD.swap(0, Ordering::AcqRel);
    }

    /// Whether pressure relief is active (for PDD boost decisions in hooks).
    pub fn is_pressure_active() -> bool {
        PressureRelief::instance().is_some_and(|pr| pr.is_requested())
    }

    // =======================================================================
    // Loading cell unload (proactive memory reclamation during loading)
    // =======================================================================

    /// Unload old cells during loading when commit growth is critical.
    ///
    /// Same principle as the game's own OOM handler (run_oom_stages stage 5):
    /// FindCellToUnload during loading with IO → Havok lock order. The game's
    /// eligibility checks (FUN_004511e0, FUN_00557090) prevent unloading cells
    /// being loaded. Grid compact and cell array flush happen at next Phase 6.
    ///
    /// Gated by:
    /// - Commit growth > 800MB above baseline (higher than normal 500MB)
    /// - Memory-based cooldown (don't fire again until commit grows back)
    /// - Max 3 cells per frame (minimize loading frame disruption)
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

        // Memory-based cooldown: don't unload again until commit grows back
        // above the post-unload level. Prevents per-frame unload churn.
        // Stale detection: if commit dropped far below cooldown (new loading
        // session at lower commit), reset cooldown to avoid blocking.
        static LOADING_COOLDOWN_COMMIT: AtomicUsize = AtomicUsize::new(0);
        let cooldown = LOADING_COOLDOWN_COMMIT.load(Ordering::Relaxed);
        if cooldown > 0 && commit < cooldown {
            if cooldown.saturating_sub(commit) < LOADING_CELL_UNLOAD_GROWTH {
                return; // still in cooldown, commit hasn't grown back
            }
            // Commit dropped significantly -- new loading session. Reset.
            LOADING_COOLDOWN_COMMIT.store(0, Ordering::Relaxed);
        }

        if let Some(result) = super::engine::cell_unload::execute_during_loading(LOADING_MAX_CELLS)
            && result.cells > 0
        {
            // Set cooldown: don't fire again until commit exceeds current level.
            let post_commit =
                libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit();
            LOADING_COOLDOWN_COMMIT.store(post_commit, Ordering::Relaxed);

            if let Some(pr) = PressureRelief::instance() {
                pr.set_pending_counter_decrement();
            }
        }
    }

    // =======================================================================
    // Quarantine flush (used by pressure.rs for aggressive collect)
    // =======================================================================

    /// Flush ALL quarantine + mi_collect.
    /// Uses try_write -- skips if readers active.
    pub unsafe fn flush_all_and_collect() {
        unsafe { quarantine::flush_all_and_collect() };
    }

    // =======================================================================
    // OOM recovery
    // =======================================================================

    /// OOM recovery with escalating stages.
    ///
    /// ENGINE CONTRACT: the original game allocator NEVER returns NULL.
    /// All game code assumes alloc succeeds. We match this contract with
    /// an infinite last-resort retry after bounded fast stages.
    ///
    /// Key principles:
    /// - try_write for quarantine flush (never blocking write in fast path)
    /// - mi_collect(false) every retry iteration (reclaims thread-local pools)
    /// - run_oom_stages does flush+collect+alloc internally (no VAS gap)
    /// - Bounded fast retry (main: 10x50ms, worker: 200x50ms)
    /// - Infinite last-resort retry with game cleanup (matches engine contract)
    #[cold]
    unsafe fn recover_oom(size: usize) -> *mut c_void {
        let is_main = Self::is_main_thread();

        log::warn!(
            "[OOM] size={}, thread={}, commit={}MB, quarantine={}MB",
            size,
            if is_main { "main" } else { "worker" },
            libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit()
                / 1024
                / 1024,
            quarantine::usage() / 1024 / 1024,
        );

        // Stage 1: collect this thread's empty pages (lock-free, instant).
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            return ptr;
        }

        // Stage 2: flush ALL quarantine + mi_collect(true).
        unsafe { quarantine::flush_all_and_collect() };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::warn!("[OOM] Recovered via quarantine flush (size={})", size);
            return ptr;
        }

        // Stage 3 (main thread, AI idle): game's OOM stages 0-8.
        // Allowed during loading (game's own OOM handler does this).
        // Blocked only during post-load cooldown (Havok restart, scene rebuild).
        if is_main
            && !game_guard::is_ai_active()
            && (!is_post_load_cooldown() || globals::is_loading())
        {
            let ptr = unsafe { globals::run_oom_stages(size) };
            if !ptr.is_null() {
                return ptr;
            }
        }

        // Signal main thread to run emergency cleanup on its next alloc.
        if !is_main {
            EMERGENCY_CLEANUP.store(true, Ordering::Release);
            let tid = libpsycho::os::windows::winapi::get_current_thread_id();
            log::warn!("[OOM] Emergency signaled from worker tid={}", tid);
        }

        // Stage 4: bounded retry loop.
        // Main thread: short (10 x 50ms = 500ms) -- longer blocks = frozen game.
        // Workers: longer (200 x 50ms = 10s) -- workers can wait for main to free.
        let max_retries: u32 = if is_main { 10 } else { 200 };
        for attempt in 0..max_retries {
            libpsycho::os::windows::winapi::sleep(50);
            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                if attempt > 0 {
                    log::info!("[OOM] Recovered after {} retries (size={})", attempt, size);
                }
                return ptr;
            }
            if attempt == max_retries / 2 {
                unsafe { quarantine::flush_all_and_collect() };
            }
        }

        // Stage 5 (main thread, AI idle, NOT post-load unless loading):
        // Run game OOM stages 0-8 + quarantine flush as escalation.
        if is_main
            && !game_guard::is_ai_active()
            && (!is_post_load_cooldown() || globals::is_loading())
        {
            log::warn!(
                "[OOM] Stage 5: game cleanup (commit={}MB, quarantine={}MB)",
                libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit()
                    / 1024
                    / 1024,
                quarantine::usage() / 1024 / 1024,
            );

            let ptr = unsafe { globals::run_oom_stages(size) };
            if !ptr.is_null() {
                log::info!("[OOM] Recovered via game cleanup (size={})", size);
                return ptr;
            }

            // Flush objects freed by game stages.
            unsafe { quarantine::flush_all_and_collect() };

            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!("[OOM] Recovered post-game-cleanup (size={})", size);
                return ptr;
            }
        }

        // Stage 6: infinite last-resort retry.
        // ENGINE CONTRACT: the game's allocator never returns NULL.
        // All game code assumes alloc succeeds -- returning NULL crashes
        // the caller immediately. We must retry until memory is available.
        //
        // Recovery comes from: other threads freeing memory, quarantine
        // drain at Phase 7 tick_flush, game HeapCompact at Phase 6,
        // loading completing and freeing transitional allocations.
        unsafe { Self::oom_last_resort(size, is_main) }
    }

    /// Infinite last-resort OOM retry. Matches the vanilla allocator's
    /// contract of never returning NULL.
    ///
    /// Uses longer sleep (200ms) to avoid burning CPU while waiting for
    /// memory to become available from other threads, frame-driven cleanup,
    /// or loading completion.
    #[cold]
    unsafe fn oom_last_resort(size: usize, is_main: bool) -> *mut c_void {
        let info = libmimalloc::process_info::MiMallocProcessInfo::get();
        log::error!(
            "[OOM] Last resort: size={}, thread={}, commit={}MB, quarantine={}MB, RSS={}MB",
            size,
            if is_main { "main" } else { "worker" },
            info.get_current_commit() / 1024 / 1024,
            quarantine::usage() / 1024 / 1024,
            info.get_current_rss() / 1024 / 1024,
        );

        if !is_main {
            EMERGENCY_CLEANUP.store(true, Ordering::Release);
        }

        let mut attempt: u32 = 0;
        loop {
            // Quarantine flush (try_write -- non-blocking).
            unsafe { quarantine::flush_all_and_collect() };

            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::warn!("[OOM] Last resort recovered at attempt {} (size={})", attempt, size);
                return ptr;
            }

            // Main thread, AI idle, not in post-load cooldown (or loading):
            // run game OOM stages. This is the REAL memory reclamation --
            // texture flush, PDD purge, cell unload (stages 0-8).
            if is_main
                && !game_guard::is_ai_active()
                && (!is_post_load_cooldown() || globals::is_loading())
            {
                let ptr = unsafe { globals::run_oom_stages(size) };
                if !ptr.is_null() {
                    log::warn!(
                        "[OOM] Last resort: game cleanup recovered at attempt {} (size={})",
                        attempt, size,
                    );
                    return ptr;
                }

                // Flush objects freed by game stages.
                unsafe { quarantine::flush_all_and_collect() };

                let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
                if !ptr.is_null() {
                    log::warn!(
                        "[OOM] Last resort: post-cleanup recovered at attempt {} (size={})",
                        attempt, size,
                    );
                    return ptr;
                }
            }

            // Wait for other threads to free memory, frame-driven cleanup,
            // or loading to complete.
            libpsycho::os::windows::winapi::sleep(200);

            attempt += 1;
            if attempt % 5 == 0 {
                let info = libmimalloc::process_info::MiMallocProcessInfo::get();
                log::error!(
                    "[OOM] Last resort attempt {}: size={}, commit={}MB, quarantine={}MB",
                    attempt, size,
                    info.get_current_commit() / 1024 / 1024,
                    quarantine::usage() / 1024 / 1024,
                );
            }
        }
    }
}

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
use super::engine::globals;
use super::game_guard;
use super::pressure::PressureRelief;
use super::statics;
use super::texture_cache;

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

/// Post-loading cooldown: no longer needed. Watchdog cleanup runs on
/// its own background thread and checks is_loading() directly.
#[allow(dead_code)]
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
/// OOM recovery in allocator.rs uses mi_collect(false) to stay within
/// safe purge_delay. Only the infinite retry loop uses mi_collect(true).
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
    // Use is_real_loading() to detect actual cell loading only.
    // is_loading() includes console/menu state (FUN_00709bc0), causing
    // false transitions when user opens console to type coc commands.
    // Ghidra: LOADING_FLAG = FUN_00702360() || FUN_00709bc0().
    let loading_now = globals::is_real_loading();
    let was_loading = WAS_LOADING.with(|c| {
        let prev = c.get();
        c.set(loading_now);
        prev
    });

    if loading_now && !was_loading {
        unsafe { on_loading_start() };
    }

    // LOADING_STATE_COUNTER manipulation REMOVED.
    // Incrementing the counter during loading made the game skip script
    // infrastructure initialization that NVSE PopulateArgs depends on.
    // The counter affects game-internal actor processing but jip_nvse
    // checks g_interfaceManager->currentMode, not the counter.
    // Artificially elevating the counter caused PopulateArgs to crash
    // writing to an uninitialized ScriptEventList variable.

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

    // Watchdog cleanup runs on its own background thread (watchdog.rs).
    // It calls havok_gc + mi_collect + decommit_sweep directly -- all
    // thread-safe, no main thread involvement. No signal_heap_compact,
    // no destruction_protocol on the main thread.
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
    let vas_emergency_active = free_vas < allocator::VAS_EMERGENCY_REMAINING
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

    // Clear texture dead set under write lock.
    game_guard::with_write("dead_set_clear", || {
        texture_cache::clear_dead_set();
    });

    // Call the original per-frame queue drain (PDD).
    // Guard: skip if any PDD queue has a NULL internal buffer pointer.
    // During heavy mod loading, aggressive cleanup can free a queue buffer
    // while the count is still non-zero, causing memcpy(NULL) crashes.
    if let Ok(original) = statics::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        if !pdd_queues_have_valid_buffers() {
            log::warn!("[PDD] Queue buffer is NULL, skipping drain this frame");
            return;
        }
        unsafe { original() };

        // Extra PDD rounds REMOVED. Aggressive PDD drain frees TESObjectCELL
        // objects that jip_nvse's LN_ProcessEvents holds via static lastCell
        // pointer (lutana.h:338). CallFunction passes lastCell to script ->
        // PopulateArgs reads freed/recycled cell data -> crash.
        //
        // Vanilla PDD drains 5-40 items per queue per frame via the original
        // per_frame_queue_drain. No extra rounds needed. The watchdog thread
        // handles memory reclamation (havok_gc + mi_collect + decommit_sweep).
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

/// Check if PDD queues with pending items have valid buffer pointers.
/// Empty queues legitimately have a NULL buffer -- only dangerous when
/// count > 0 and buffer == NULL (memcpy would crash with ESI=0).
/// Returns false if any non-empty queue has a NULL buffer.
fn pdd_queues_have_valid_buffers() -> bool {
    const BUFFER_OFFSET: usize = 0x04;
    let queues = [
        super::engine::addr::NINODE_QUEUE,
        super::engine::addr::FORM_QUEUE,
        super::engine::addr::GENERIC_QUEUE,
        super::engine::addr::ANIM_QUEUE,
        super::engine::addr::TEXTURE_QUEUE,
    ];
    for &base in &queues {
        let count =
            unsafe { *((base + super::engine::addr::PDD_QUEUE_COUNT_OFFSET) as *const u16) };
        if count == 0 {
            continue;
        }
        let buf = unsafe { *((base + BUFFER_OFFSET) as *const usize) };
        if buf == 0 {
            return false;
        }
    }
    true
}

//! Hook wrappers that delegate to gheap::allocator.
//!
//! Game-heap allocation hooks are pure forwarders. Frame-level orchestration
//! is limited to things that are not allocator-state dependent:
//!   - main-thread id capture on the first Phase 7 frame
//!   - texture cache dead-set clear
//!   - vanilla per-frame PDD drain pass-through
//!   - periodic full PDD drain (10 s cooldown) -- PDD maintenance only,
//!     does not consult game loading/menu state
//!   - AI start / AI join sync flags
//!   - deferred console cell-unload execution on AI join
//!   - OOM Stage 8 safe BSTaskManagerThread semaphore release
//!
//! No explicit `havok_gc` call here. It races with AI Linear Task
//! Threads (PPL Concurrency Runtime pool dispatched by IOManager),
//! which are NOT joined by AI_JOIN and can only be drained by
//! `stop_havok_drain` (FUN_008324e0). Even from the main thread,
//! calling `havok_gc` at Phase 7 reproduces the documented crash at
//! 0x00C94DA5 inside hkScaledMoppBvTreeShape while AI Linear Task
//! Thread 2 is walking collision data -- see
//! analysis/ghidra/output/memory/havok_gc_thread_analysis.txt. The
//! game's own stage 4 / stage 5 / AI_JOIN paths already invoke
//! havok_gc internally at safe points, so we do not need to.

use std::sync::atomic::{AtomicU64, Ordering};

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

/// Phase 7: per-frame queue drain (before AI_START).
///
/// Orchestration is intentionally minimal and game-state-free. The
/// allocator tiers are always "active"; there is no loading / menu /
/// console branching here.
pub unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Capture the main thread id on the first Phase 7 frame. Cheap to
    // call every frame since it short-circuits once set.
    globals::set_main_thread_id();

    // Clear texture dead-set under write lock.
    game_guard::with_write("dead_set_clear", || {
        texture_cache::clear_dead_set();
    });

    // Vanilla per-frame PDD drain. Skip if any queue has a NULL buffer
    // (memcpy(NULL) crash defence).
    if let Ok(original) = statics::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        if !pdd_queues_have_valid_buffers() {
            log::warn!("[PDD] Queue buffer is NULL, skipping drain this frame");
            return;
        }
        unsafe { original() };
    }

    // Periodic full PDD drain on 10 s cooldown. PDD maintenance --
    // independent of loading/menu state; prevents BSTreeNode C0000417
    // under sustained cell churn. Calls pdd_purge directly rather than
    // run_oom_stage(4, ...) so we skip the havok_gc fall-through; see
    // `maybe_drain_pdd` docstring below for the full Ghidra-verified
    // rationale.
    //
    // KNOWN LATENT CRASH: pdd_purge still frees NiRefObject children
    // on the main thread. Our NVHR-style pool does immediate LIFO
    // reuse; if the parent BSTreeNode destructor that follows in the
    // same drain dereferences an already-reused child, we hit the
    // documented BSTreeNode C0000417 fastfail (see the detailed
    // "Known latent crash" block on `Pool::free` in gheap/pool.rs and
    // memory note project_bstreenode_crash_chain.md). Confirmed repro
    // CrashLogger.2026-04-18-18-32-08.log. The historical fix was
    // Stage 4 + 2-epoch quarantine (gone since 35a326b) or the
    // narrower slab-era DESTRUCTION_FREEZE (also gone). Leaving the
    // periodic drain enabled here is the lesser evil: skipping it
    // trades this race for a different BSTreeNode crash from the
    // per-frame PDD rate-limit backlog.
    maybe_drain_pdd();
}

/// Cooldown gate + direct PDD purge on a 10 s cadence. No-op if less
/// than `STAGE4_COOLDOWN_MS` has elapsed since the last run.
///
/// # Why direct pdd_purge, not run_oom_stage(4, ...)
///
/// Stage 4 in `FUN_00866a90` has a C switch fall-through: `case 4`'s
/// body is just a PDD purge (`FUN_00868d70('\x01')`) wrapped in an
/// interlock on `DAT_011f11a0`, but there's NO `break` between `case 4`
/// and `case 3`. `case 3` calls `FUN_00c459d0('\x01')` -- havok_gc
/// force=1. Verified in
/// `analysis/ghidra/output/memory/oom_stage4_havok_trace.txt`.
///
/// That havok_gc fall-through races with AI Linear Task Threads (PPL
/// Concurrency Runtime pool). Three separate crashes at `0x00C94DA5`
/// on `AI Linear Task Thread 1` across runs trace to this race. An
/// earlier fix wrapped the Stage 4 call with
/// `stop_havok_drain` + `start_havok` but that deadlocked the game:
/// when a Stage 4 triggered cell unload, the game enters destruction
/// mode (`DAT_011dd437 != 0`), which makes mode=1 `start_havok` a
/// silent no-op per the decomp in
/// `analysis/ghidra/output/memory/stop_havok_drain_mode_analysis.txt`.
/// PPL stayed drained, next AI_START dispatched a task that nothing
/// would consume, main thread hung.
///
/// `pdd_purge` (our existing wrapper, passes arg=0 for the full
/// blocking variant) is exactly what `case 4`'s body does before the
/// fall-through. Calling it directly keeps BSTreeNode queue
/// prevention intact and skips the Havok machinery entirely.
///
/// # Why we skip the DAT_011f11a0 interlock
///
/// The interlock in `case 4` protects against concurrent game-internal
/// PDD purges (Stage 4 vs Stage 5 path). We call from the main thread
/// inside `hook_per_frame_queue_drain` after the vanilla per-frame
/// drain has already completed -- no concurrent caller possible from
/// our side. If we ever see PDD-internal races we can add back the
/// interlock emulation with atomic CAS on the flag address.
fn maybe_drain_pdd() {
    const STAGE4_COOLDOWN_MS: u64 = 10_000;
    static LAST_STAGE4_MS: AtomicU64 = AtomicU64::new(0);

    let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
    let last = LAST_STAGE4_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < STAGE4_COOLDOWN_MS {
        return;
    }
    if LAST_STAGE4_MS
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    // Full blocking PDD purge, no Havok involvement, no PPL drain.
    unsafe { globals::pdd_purge() };
}


/// Phase 10: post-render maintenance (before AI_JOIN).
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

/// AI_JOIN: AI threads completed. Execute any deferred console
/// cell-unload request. `execute` itself aborts when AI/Havok are
/// busy, which is the real safety condition -- no need to branch on
/// game loading/menu state here.
pub unsafe extern "fastcall" fn hook_ai_thread_join(mgr: *mut c_void) {
    if let Ok(original) = statics::AI_THREAD_JOIN_HOOK.original() {
        unsafe { original(mgr) };
    }
    game_guard::clear_ai_active();

    let deferred = super::engine::cell_unload::take_deferred_request();
    if deferred > 0 {
        let _ = super::engine::cell_unload::execute(deferred);
    }
}

// ---- Havok world synchronization hooks ----

pub unsafe extern "fastcall" fn hook_hkworld_lock(this: *mut c_void) {
    game_guard::set_havok_active();
    if let Ok(original) = statics::HKWORLD_LOCK_HOOK.original() {
        unsafe { original(this) };
    }
}

pub unsafe extern "fastcall" fn hook_hkworld_unlock(this: *mut c_void) {
    if let Ok(original) = statics::HKWORLD_UNLOCK_HOOK.original() {
        unsafe { original(this) };
    }
    game_guard::clear_havok_active();
}

/// Check if PDD queues with pending items have valid buffer pointers.
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

// ---------------------------------------------------------------------------
// OOM Stage 8 hook (HeapCompact)
// ---------------------------------------------------------------------------

pub unsafe extern "thiscall" fn hook_oom_stage_exec(
    heap_singleton: *mut c_void,
    primary_heap: *mut c_void,
    stage: i32,
    done: *mut u8,
) -> i32 {
    if stage != 8 {
        if let Ok(original) = statics::OOM_STAGE_EXEC_HOOK.original() {
            return unsafe { original(heap_singleton, primary_heap, stage, done) };
        }
        return stage + 1;
    }

    let is_main = super::engine::globals::is_main_thread_by_tid();
    if is_main {
        let trigger = unsafe { (heap_singleton as *const u8).add(0x134) } as *mut i32;
        unsafe { trigger.write_volatile(6) };
        unsafe { *done = 1 };
        return stage + 1;
    }

    let trigger = unsafe { (heap_singleton as *const u8).add(0x134) } as *mut i32;
    unsafe { trigger.write_volatile(6) };

    const SLEEP_COUNTER_ADDR: usize = 0x011DE70C;
    let counter = SLEEP_COUNTER_ADDR as *mut i32;
    let count = unsafe { counter.read_volatile() };

    if count < 15000 {
        unsafe { super::engine::globals::release_bstask_sems_if_owned() };
        libpsycho::os::windows::winapi::sleep(1);
        unsafe { counter.write_volatile(count + 1) };
        return stage;
    }

    unsafe { *done = 1 };
    stage + 1
}

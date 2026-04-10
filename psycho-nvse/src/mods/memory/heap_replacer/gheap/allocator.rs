//! Game heap allocator: routes alloc/free/realloc/msize through slab + va_allocator.
//!
//! Dispatch:
//!   size < 1MB  -> slab (per-page refcount, zombie memory protection)
//!   size >= 1MB -> va_allocator (VirtualAlloc per-alloc)
//!
//! UAF protection: slab preserves all original cell data on free (bitmap tracking).
//! Pages stay committed until Phase 7 decommit sweep.

use libc::c_void;
use libpsycho::os::windows::va_allocator;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::engine::{addr, globals};
use super::statics;
use crate::mods::memory::heap_replacer::heap_validate;

/// Remaining free VAS (bytes) at which VAS CRITICAL mode activates.
/// Measured via live GlobalMemoryStatusEx -- always accurate.
/// 400MB accounts for loading spikes + fragmentation overhead.
pub const VAS_CRITICAL_REMAINING: usize = 400 * 1024 * 1024; // 400MB

/// Remaining free VAS (bytes) at which VAS EMERGENCY mode activates.
/// Below 200MB, allocations start failing from fragmentation alone.
pub const VAS_EMERGENCY_REMAINING: usize = 200 * 1024 * 1024; // 200MB

/// Headroom (free_vas_at_calibration) in bytes. Set during calibration,
/// read by watchdog for proportional growth thresholds.
static HEADROOM: AtomicUsize = AtomicUsize::new(0);

/// Get current free VAS via GlobalMemoryStatusEx. One syscall, always
/// accurate. Includes ALL reservations (DLLs, D3D9, mapped files).
/// Returns ullAvailVirtual -- actual free user-mode address space.
pub fn current_free_vas() -> usize {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    if ok.is_err() {
        return usize::MAX; // cant read = assume plenty of VAS
    }
    status.ullAvailVirtual as usize
}

/// Calibrate watchdog headroom from live VAS measurement.
/// Called when baseline_commit is first calibrated by PressureRelief.
pub fn calibrate_thresholds(baseline: usize) {
    if baseline == 0 {
        return;
    }
    let free_vas = current_free_vas();
    // headroom = current free VAS (at calibration, commit ~ baseline)
    HEADROOM.store(free_vas, Ordering::Release);

    log::info!(
        "[VAS] Calibrated: baseline={}MB, free_vas={}MB, \
         critical_at=<{}MB free, emergency_at=<{}MB free",
        baseline / 1024 / 1024,
        free_vas / 1024 / 1024,
        VAS_CRITICAL_REMAINING / 1024 / 1024,
        VAS_EMERGENCY_REMAINING / 1024 / 1024,
    );
}

/// Get calibrated headroom (available_vas - baseline). Used by watchdog
/// for proportional growth thresholds. Returns 0 if not yet calibrated.
pub fn get_headroom() -> usize {
    HEADROOM.load(Ordering::Acquire)
}

// -----------------------------------------------------------------------
// Thread identity
// -----------------------------------------------------------------------

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

static POOL_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn is_pool_active() -> bool {
    POOL_ACTIVE.load(Ordering::Acquire)
}

pub fn activate_pool() {
    POOL_ACTIVE.store(true, Ordering::Release);
    log::info!("[POOL] Activated");
}

#[inline]
pub fn is_main_thread() -> bool {
    THREAD_ROLE.with(|r| match r.get() {
        ThreadRole::Main => true,
        ThreadRole::Worker => false,
        ThreadRole::Unknown => {
            let is_main = globals::is_main_thread_by_tid();
            if is_main {
                r.set(ThreadRole::Main);
            } else if is_pool_active() {
                r.set(ThreadRole::Worker);
            }
            is_main
        }
    })
}

// -----------------------------------------------------------------------
// Alloc / Free / Msize / Realloc
// -----------------------------------------------------------------------

/// Allocate `size` bytes.
///
/// Dispatch:
///   size < 1MB  -> slab (per-page refcount, zombie memory)
///   size >= 1MB -> va_allocator (VirtualAlloc, MEM_RELEASE on free)
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    // Large raw buffers (>= 1MB) --> VirtualAlloc for immediate VAS reclamation.
    if size >= va_allocator::LARGE_ALLOC_THRESHOLD {
        let ptr = unsafe { va_allocator::malloc(size) };
        if !ptr.is_null() {
            return ptr;
        }
        return unsafe { recover_oom(size) };
    }

    // Small/medium objects (< 1MB) --> slab allocator.
    // Covers NPC sub-objects (Process, ExtraData, scripts) for UAF protection.
    // Per-page refcounting + zombie memory for stale readers.
    if size > 0 {
        let ptr = unsafe { super::slab::alloc(size) };
        if !ptr.is_null() {
            return ptr;
        }
        // Slab exhausted -- fall through to va_allocator as last resort.
    }

    // Slab exhausted or zero size --> va_allocator.
    let ptr = unsafe { va_allocator::malloc(size) };
    if !ptr.is_null() {
        return ptr;
    }
    unsafe { recover_oom(size) }
}

/// Free a block. Dispatch by ownership:
///   slab ptr     -> slab_free (zombie memory, deferred decommit)
///   va_allocator -> va_free (VirtualFree MEM_RELEASE)
///   pre-hook SBM -> original trampoline
#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    // FAST PATH: slab check (two comparisons, no function call).
    // Majority of GameHeap frees are slab allocations.
    if super::slab::is_slab_ptr(ptr as *const c_void) {
        unsafe { super::slab::free(ptr) };
        return;
    }

    // VirtualAlloc header check. Simple memory read, no syscall.
    if unsafe { va_allocator::is_virtual_alloc_ptr(ptr) } {
        unsafe { va_allocator::free(ptr) };
        return;
    }

    // Pre-hook pointer: route to original SBM trampoline.
    if let Ok(orig_free) = statics::GHEAP_FREE_HOOK.original() {
        unsafe { orig_free(addr::HEAP_SINGLETON as *mut c_void, ptr) };
        return;
    }

    unsafe { heap_validate::heap_validated_free(ptr) };
}

/// Return usable size of an allocated block.
#[inline]
pub unsafe fn msize(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }

    // FAST PATH: slab check.
    if super::slab::is_slab_ptr(ptr as *const c_void) {
        return unsafe { super::slab::usable_size(ptr as *const c_void) };
    }

    // VirtualAlloc header.
    if let Some(size) = unsafe { va_allocator::msize(ptr) } {
        return size;
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

/// Reallocate a block.
#[inline]
pub unsafe fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { alloc(new_size) };
    }
    if new_size == 0 {
        unsafe { free(ptr) };
        return null_mut();
    }
    // Slab pointers: alloc new, copy, free old (slab has no in-place realloc).
    if super::slab::is_slab_ptr(ptr as *const c_void) {
        let old_size = unsafe { super::slab::usable_size(ptr as *const c_void) };
        if new_size <= old_size {
            return ptr; // fits in current cell
        }
        let new_ptr = unsafe { alloc(new_size) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_size.min(new_size),
                );
            }
            unsafe { free(ptr) };
        }
        return new_ptr;
    }
    // va_allocator: try in-place realloc.
    if unsafe { va_allocator::is_virtual_alloc_ptr(ptr) } {
        if let Some(new_ptr) = unsafe { va_allocator::realloc(ptr, new_size) } {
            return new_ptr;
        }
        // va_allocator realloc failed -- alloc new, copy, free old.
        let old_size = unsafe { msize(ptr) };
        if old_size == 0 {
            return null_mut();
        }
        let new_ptr = unsafe { alloc(new_size) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_size.min(new_size),
                );
            }
            unsafe { free(ptr) };
        }
        return new_ptr;
    }
    let old_size = unsafe { msize(ptr) };
    if old_size == 0 {
        return null_mut();
    }
    let new_ptr = unsafe { alloc(new_size) };
    if !new_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_size),
            );
        }
        unsafe { free(ptr) };
    }
    new_ptr
}

// -----------------------------------------------------------------------
// OOM recovery
// -----------------------------------------------------------------------

/// Retry allocation with the correct backend for the given size.
/// Large (>= 1MB): try VirtualAlloc first (free VAS holes from
/// MEM_RELEASE), then slab. This matches the original alloc() dispatch.
#[cold]
#[inline]
unsafe fn retry_alloc(size: usize) -> *mut c_void {
    if size >= va_allocator::LARGE_ALLOC_THRESHOLD {
        let p = unsafe { va_allocator::malloc(size) };
        if !p.is_null() {
            return p;
        }
    }
    unsafe { super::slab::alloc(size) }
}

// Reentrancy guard. Game cleanup stages allocate small temporaries.
// Without this guard, those allocations failing would recurse into
// the full OOM recovery -- stack overflow or deadlock on PDD lock.
thread_local! {
    static IN_OOM_RECOVERY: Cell<bool> = const { Cell::new(false) };
}

/// OOM recovery matching vanilla FUN_00aa3e40 retry pattern.
///
/// Pattern: **cleanup --> retry --> cleanup --> retry**.
/// Cleanup runs through game OOM stages (3-5) which free objects via
/// our hooks (slab or va_allocator). Slab decommit sweeps return pages
/// to the OS after cooldown.
#[cold]
unsafe fn recover_oom(size: usize) -> *mut c_void {
    // Reentrancy: game cleanup stages may allocate. Don't recurse into
    // the full recovery -- just decommit aged slab pages and retry.
    if IN_OOM_RECOVERY.with(|r| r.get()) {
        unsafe { super::slab::decommit_sweep() };
        return unsafe { retry_alloc(size) };
    }

    IN_OOM_RECOVERY.with(|r| r.set(true));
    let result = unsafe { do_recover_oom(size) };
    IN_OOM_RECOVERY.with(|r| r.set(false));
    result
}

#[cold]
unsafe fn do_recover_oom(size: usize) -> *mut c_void {
    use super::heap_manager::HeapManager;

    let heap = HeapManager::get();
    let is_main = is_main_thread();
    let commit_entry = heap.commit_mb();

    log::warn!(
        "[OOM] size={} thread={} commit={}MB pool={}MB",
        size,
        if is_main { "main" } else { "worker" },
        commit_entry,
        super::slab::committed_bytes() / 1024 / 1024,
    );

    // --- Emergency pool drain (main thread only) ---
    // Workers set this flag; main thread Phase 7 normally consumes it.
    // But when the main thread is IN OOM recovery, it never reaches Phase 7.
    // Consume the flag here to drain stale zombie blocks immediately.
    if is_main && heap.take_emergency_drain() {
        unsafe {
            super::slab::decommit_sweep();
            super::slab::decommit_sweep_full(false);
        };
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Recovered after emergency drain: size={} commit={}-->{}MB",
                size,
                commit_entry,
                heap.commit_mb(),
            );
            return ptr;
        }
    }

    // --- Phase 1: Active cleanup ---
    //
    // The game's allocator contract: NEVER return NULL.
    // Pattern from vanilla FUN_00aa3e40:
    //   do {
    //       stage = FUN_00866a90(heap, stage, &give_up);
    //       if (give_up) { ptr = _malloc(size); break; }
    //       ptr = heap_vtable->alloc(size);
    //   } while (!ptr);
    //
    // For WORKER threads: run thread-safe cleanup stages (Havok GC + semaphore
    // release) to actively free memory instead of passively waiting for main
    // thread. This matches the game's Stage 8 behavior (Ghidra-verified).
    //
    // For MAIN thread: run full stages 3-5 (Havok GC, PDD purge, Cell Unload).
    // All frees go through our hooks (slab or va_allocator) with zombie safety.
    //
    // Stages 0-2 are skipped (NO-OP during gameplay), Stage 6 is skipped (allocates memory).
    // Stage 5 (Cell Unload) runs until game says no more cells eligible (give_up flag).
    // This matches vanilla behavior: unload ALL eligible cells, not just 1-2.
    //
    // During loading, start at Stage 0 (Texture/Geometry cache flush).
    // Stages 3-5 (Havok/Cell Unload) are blocked by the Loading state, so
    // we must run 0-2 to free the old cache data before loading new cells.
    //
    // LOADING DEATH SPIRAL FIX:
    // During loading, stages 0-5 are almost entirely ineffective:
    //   Stage 0: flushes OLD textures --> game immediately reloads them --> net zero
    //   Stage 1: flushes OLD geometry --> game immediately reloads it --> net zero
    //   Stage 2: menu cleanup --> nothing during loading
    //   Stages 3-5: blocked by loading state --> nothing
    //   Stage 6: give_up --> break
    // The game then cycles 30+ times over 2.5 seconds, freeing ~4MB total,
    // before crashing in d3d9. Skip this death spiral during loading: go
    // straight to nuclear option (force decommit all aged slab pages).
    let loading = globals::is_loading();

    if !is_main {
        // WORKER THREAD OOM -- matching vanilla FUN_00aa3e40 contract.
        //
        // Vanilla contract (Ghidra-verified): the allocator NEVER returns
        // NULL. Game code has zero null checks after allocation. Returning
        // NULL causes memcpy to address 0 in BSFile::Read, IOManager, etc.
        //
        // Vanilla worker OOM path (FUN_00866a90):
        //   Stages 0-3: quick cleanup (some skipped on worker)
        //   Stages 4-5: skipped on worker (main-thread-only)
        //   Stage 6: skipped on worker (SBM defrag, main-thread-only)
        //   Stage 7: falls through to Stage 8 on worker
        //   Stage 8: THE worker recovery -- Sleep(1) x 15000 (15 seconds),
        //     release BSTaskManager sems, set HeapCompact trigger, retry.
        //     After 15000 iterations: give_up -> CRT malloc fallback.
        //
        // We replicate this: run game stages 0-6 via run_oom_stage (the
        // game function handles main/worker distinction internally), then
        // enter Stage 8 pattern ourselves with correct retry_alloc.

        // -- Phase 1: Run game OOM stages --
        // The game's stage executor skips main-thread-only stages for us.
        // bypass=false: frees go to pool (zombie-safe for concurrent readers).
        // During loading, skip Stage 5 (Cell Unload) — same rationale as main
        // thread: NVSE event handlers reference cell objects being destroyed.
        let loading_oom_stage_max: i32 = if loading { 4 } else { 5 };
        let mut stage: i32 = if loading { 0 } else { 3 };
        loop {
            let (next, done) = unsafe { heap.run_oom_stage(stage, false) };
            stage = next;

            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Worker recovered: stage={} size={} commit={}-->{}MB",
                    stage,
                    size,
                    commit_entry,
                    heap.commit_mb(),
                );
                return ptr;
            }

            if done || stage > loading_oom_stage_max {
                break;
            }
        }

        // -- Phase 2: Stage 8 pattern (vanilla-matched) --
        //
        // Vanilla Stage 8 (Ghidra: 0x00866a90 case 8):
        //   *(this+0x134) = 6   <-- HeapCompact trigger for main thread
        //   release BSTaskManager sems
        //   Sleep(1)
        //   retry up to 15000 iterations (15 seconds)
        //
        // The HeapCompact trigger tells the main thread to run cleanup on
        // its next frame. If main thread is blocked at AI_JOIN waiting for
        // us, the trigger waits -- but Sleep(1) gives other threads time
        // to free memory naturally. This IS the vanilla design: workers
        // wait patiently for the main thread to eventually run cleanup.
        //
        // We write stage 2 max (MenuCleanup) to avoid triggering
        // FUN_00c459d0 (async flush) which crashes NVTF's geometry
        // precache thread. Stage 2 is safe: texture + geometry cache
        // flush with explicit break statements (Ghidra-verified).
        //
        // We also signal emergency_drain so Phase 7 drains the main
        // thread's pool, and set_deferred_unload so AI_JOIN runs
        // destruction_protocol (the safe path for stage 3+ cleanup).
        const MAX_STAGE8_ITERS: u32 = 15_000;

        log::warn!(
            "[OOM] Worker entering Stage 8: size={} commit={}MB pool={}MB",
            size,
            heap.commit_mb(),
            super::slab::committed_bytes() / 1024 / 1024,
        );

        for iter in 0..MAX_STAGE8_ITERS {
            // Match vanilla: set HeapCompact trigger + release sems + sleep
            heap.signal_heap_compact(super::engine::globals::HeapCompactStage::MenuCleanup);
            heap.signal_emergency_drain();
            unsafe { super::engine::globals::release_bstask_sems_if_owned() };

            // Signal destruction_protocol periodically (safe cell unload
            // path with Havok lock, consumed at AI_JOIN).
            if iter.is_multiple_of(16)
                && let Some(pr) = super::pressure::PressureRelief::instance()
            {
                pr.set_deferred_unload();
            }

            libpsycho::os::windows::winapi::sleep(1);

            // Periodic cleanup: decommit aged slab dirty pages (respects
            // cooldown delay, force=false). Worker can self-recover VAS
            // from pages that have been dirty long enough without main
            // thread help.
            if iter.is_multiple_of(50) {
                unsafe {
                    super::slab::decommit_sweep_full(false);
                }
            }

            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Worker recovered (Stage 8): iter={} size={} commit={}-->{}MB",
                    iter,
                    size,
                    commit_entry,
                    heap.commit_mb(),
                );
                return ptr;
            }

            if iter.is_multiple_of(1000) && iter > 0 {
                log::warn!(
                    "[OOM] Worker Stage 8: {}ms size={} commit={}MB pool={}MB",
                    iter,
                    size,
                    heap.commit_mb(),
                    super::slab::committed_bytes() / 1024 / 1024,
                );
            }
        }

        // -- Phase 3: CRT malloc fallback (vanilla give_up path) --
        //
        // Vanilla: after 15000 iterations, sets give_up flag, caller
        // calls _malloc(size) as CRT fallback. We do the same.
        // libc::malloc bypasses both mimalloc and va_allocator, going
        // straight to the OS heap (Windows HeapAlloc). This may succeed
        // when mimalloc arena is fragmented but OS still has free pages.
        log::error!(
            "[OOM] Worker Stage 8 exhausted ({}ms), CRT fallback: size={} commit={}MB",
            MAX_STAGE8_ITERS,
            size,
            heap.commit_mb(),
        );
        let ptr = unsafe { libc::malloc(size) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Worker recovered (CRT): size={} commit={}MB",
                size,
                heap.commit_mb(),
            );
            return ptr;
        }

        // CRT also failed. Vanilla loops forever here (do-while never
        // exits). We do one final nuclear drain (force decommit all aged
        // pages), then loop CRT malloc indefinitely. This matches the
        // engine contract: the allocator NEVER returns NULL.
        log::error!(
            "[OOM] Worker CRT failed, nuclear drain + infinite retry: size={} commit={}MB",
            size,
            heap.commit_mb(),
        );
        unsafe { super::slab::decommit_sweep_full(true) };

        loop {
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                return ptr;
            }
            let ptr = unsafe { libc::malloc(size) };
            if !ptr.is_null() {
                return ptr;
            }
            // Yield to let other threads make progress.
            unsafe { super::engine::globals::release_bstask_sems_if_owned() };
            libpsycho::os::windows::winapi::sleep(10);
            unsafe { super::slab::decommit_sweep_full(false) };
        }
    }

    // MAIN THREAD: Full cleanup with stages 3-5.
    //
    // During loading, skip Stage 5 (Cell Unload). The game is already in a
    // cell transition — unloading MORE cells destroys objects that NVSE event
    // handlers and scripts still reference (crash in
    // InternalFunctionCaller::PopulateArgs accessing freed Character during
    // nvseRuntimeScript263CellChange).
    let loading_oom_stage_max: i32 = if loading { 4 } else { 5 };
    let mut stage: i32 = if loading { 0 } else { 3 };
    let mut cycles: u32 = 0;

    // Death spiral detection: if an OOM cycle frees less than 1% of current
    // commit, further stage cycles won't help. Go nuclear immediately.
    //
    // During loading: stages 0-5 are almost entirely ineffective
    // (log: 1494-->1490MB over 30 cycles = 4MB in 2.5 seconds).
    // During gameplay: stages 3-5 free ~4MB/cycle but allocation rate
    // exceeds free rate, causing slow death spiral over 1.5 minutes.
    //
    // The 1% threshold distinguishes real cleanup from death spiral.
    // At 1.5GB commit, 1% = 15MB. Death spiral frees ~4MB (0.27%).
    let mut death_spiral_detected = false;
    let death_spiral_threshold = commit_entry / 100; // 1% of commit at OOM entry

    loop {
        cycles += 1;
        let commit_before = heap.commit_bytes();

        // --- Death Spiral Detection ---
        // If previous cycle freed < 1% of commit, further stages won't help.
        // Go straight to nuclear: force decommit all aged slab pages.
        if death_spiral_detected {
            log::warn!(
                "[OOM] Death spiral detected: cycle={}, commit={}MB, going nuclear",
                cycles,
                commit_before / 1024 / 1024,
            );
            unsafe {
                super::slab::decommit_sweep();
                super::slab::decommit_sweep_full(true);
            };
            let freed_bytes = commit_entry.saturating_sub(heap.commit_bytes());
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered via nuclear: freed={}MB size={} commit={}-->{}MB",
                    freed_bytes / 1024 / 1024,
                    size,
                    commit_entry,
                    heap.commit_mb(),
                );
                return ptr;
            }
            log::error!(
                "[OOM] FATAL (nuclear failed): size={} commit={}MB freed={}MB",
                size,
                heap.commit_mb(),
                freed_bytes / 1024 / 1024,
            );
            return null_mut();
        }

        // Run current stage. Choose bypass mode based on stage and loading state:
        //
        // During loading OOM, bypass is ALWAYS false. Stages 0-2 (texture/geometry
        // cache flush) have cross-thread readers: the IO thread holds raw pointers
        // to QueuedTexture objects being loaded. Freeing them immediately
        // while the IO thread is mid-load causes RefCount:0 UAF crash (seen at
        // 0x0044DDC0 during cell transitions with NiSourceTexture RefCount=0).
        //
        // Stage 5 (Cell Unload) — Havok entities and scene
        // graph nodes freed during cell teardown have active stale readers (AI
        // threads, BSTaskManagerThread).
        //
        // During active gameplay (not loading), all stages use zombie-safe routing.
        let bypass = false;
        let (next, done) = unsafe { heap.run_oom_stage(stage, bypass) };
        stage = next;

        // Try allocation after every stage
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Recovered: cycle={} stage={} size={} commit={}-->{}MB",
                cycles,
                stage,
                size,
                commit_entry,
                heap.commit_mb(),
            );
            return ptr;
        }

        // Detect ineffective cleanup cycle. If we freed less than 1% of
        // the commit at OOM entry, further stage cycles won't help —
        // escalate to nuclear on the next iteration.
        if cycles == 1 {
            let freed = commit_before.saturating_sub(heap.commit_bytes());
            if freed < death_spiral_threshold {
                death_spiral_detected = true;
                log::warn!(
                    "[OOM] Ineffective cycle #1: freed={}KB (threshold={}MB), will go nuclear",
                    freed / 1024,
                    death_spiral_threshold / 1024 / 1024,
                );
            }
        }

        // If give_up was set (stage 7 on main thread), fall back to CRT
        if done {
            break;
        }

        // Stage 6 allocates memory (SBM GlobalCleanup) -- skip it.
        // Stage 7 falls through to Stage 8 (thread suspend/resume) which crashes
        // when BSTaskManager thread array has NULL entries. Skip both 7 and 8.
        // During loading, also skip Stage 5 (Cell Unload) via loading_oom_stage_max.
        if stage > loading_oom_stage_max {
            // Log final stats before fallback
            let freed = commit_before.saturating_sub(heap.commit_bytes());
            if freed < 64 * 1024 {
                log::warn!(
                    "[OOM] Minimal cleanup ({}) at stage {}, commit={}-->{}MB",
                    if freed == 0 {
                        "nothing freed"
                    } else {
                        "very little"
                    },
                    stage,
                    commit_entry,
                    heap.commit_mb(),
                );
            }
            break;
        }
    }

    // --- Emergency pool drain: Last resort before wait/CRT fallback ---
    //
    // When OOM recovery exhausted all game cleanup stages (stages 0-7)
    // but still couldn't allocate, force-decommit aged slab pages.
    {
        unsafe {
            super::slab::decommit_sweep();
            super::slab::decommit_sweep_full(false);
        };
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Recovered after emergency drain: size={} commit={}-->{}MB",
                size,
                commit_entry,
                heap.commit_mb(),
            );
            return ptr;
        }
    }

    // --- Phase 2: Last resort ---
    //
    // Workers returned early above with their own VAS wait loop.
    // Only the main thread reaches here.
    log::warn!(
        "[OOM] Escalating: commit={}-->{}MB pool={}MB",
        commit_entry,
        heap.commit_mb(),
        super::slab::committed_bytes() / 1024 / 1024,
    );

    // Safe drain.
    unsafe {
        super::slab::decommit_sweep();
        super::slab::decommit_sweep_full(false);
    };
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() {
        return ptr;
    }

    // Nuclear: force decommit ALL aged pages. UAF risk accepted -- crash is
    // the alternative. But first, wait for AI threads to join and
    // release BSTaskManager semaphores to minimize stale readers.
    //
    // Wait up to 2 seconds for AI threads to complete. They should
    // join within one frame (~16ms), so 2s is generous.
    let ai_wait_start = libpsycho::os::windows::winapi::get_tick_count();
    while super::game_guard::is_ai_active() {
        unsafe { super::engine::globals::release_bstask_sems_if_owned() };
        libpsycho::os::windows::winapi::sleep(1);
        if libpsycho::os::windows::winapi::get_tick_count() - ai_wait_start > 2000 {
            log::warn!("[OOM] AI threads did not join within 2s, proceeding with nuclear");
            break;
        }
    }
    // Final semaphore release before drain.
    unsafe { super::engine::globals::release_bstask_sems_if_owned() };

    unsafe { super::slab::decommit_sweep_full(true) };
    let commit_after_drain = heap.commit_mb();
    let freed_mb = commit_entry.saturating_sub(commit_after_drain);
    log::error!(
        "[OOM] Last resort: commit={}-->{}MB freed={}MB",
        commit_entry,
        commit_after_drain,
        freed_mb,
    );

    // Only retry if drain freed meaningful amount relative to request.
    // If we freed < requested size, VAS is too fragmented.
    let size_mb = size / 1024 / 1024;
    if freed_mb > size_mb {
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Recovered post-drain: commit={}-->{}MB",
                commit_entry,
                heap.commit_mb(),
            );
            return ptr;
        }
    }

    log::error!(
        "[OOM] FATAL: size={} commit={}MB thread={}",
        size,
        heap.commit_mb(),
        if is_main { "main" } else { "worker" },
    );
    null_mut()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Alloc contract: NEVER returns NULL ----

    #[test]
    fn alloc_never_null_small() {
        // Allocate many small blocks, all must be non-null.
        let mut ptrs = Vec::new();
        for _ in 0..500 {
            let p = unsafe { alloc(64) };
            assert!(!p.is_null(), "alloc(64) returned NULL");
            ptrs.push(p);
        }
        for p in ptrs {
            unsafe { free(p) };
        }
    }

    #[test]
    fn alloc_never_null_various() {
        let sizes = [16, 32, 64, 128, 256, 512, 1024, 4096, 16384, 65536, 262144, 524288, 1048575];
        for &size in &sizes {
            let p = unsafe { alloc(size) };
            assert!(!p.is_null(), "alloc({}) returned NULL", size);
            unsafe { free(p) };
        }
    }

    // ---- Alloc contract: 16-byte alignment ----

    #[test]
    fn alloc_16_byte_alignment() {
        let sizes = [16, 17, 31, 32, 63, 64, 100, 255, 256, 1024, 8192, 65536, 262144, 524288];
        for &size in &sizes {
            let p = unsafe { alloc(size) };
            assert!(!p.is_null(), "alloc({}) returned NULL", size);
            let addr = p as usize;
            assert_eq!(addr % 16, 0, "alloc({}) = {:p} not 16-byte aligned", size, p);
            unsafe { free(p) };
        }
    }

    // ---- Alloc: large allocations (>= 1MB) ----

    #[test]
    fn alloc_1mb_and_above() {
        let sizes = [1048576, 1500000, 2097152, 4194304];
        for &size in &sizes {
            let p = unsafe { alloc(size) };
            assert!(!p.is_null(), "alloc({}) returned NULL", size);
            let usable = unsafe { msize(p) };
            assert!(usable >= size, "msize({}) = {} < requested {}", size, usable, size);
            unsafe { free(p) };
        }
    }

    // ---- Alloc boundary: slab vs va_allocator ----

    #[test]
    fn alloc_boundary_1mb_minus_1() {
        let p = unsafe { alloc(1048575) };
        assert!(!p.is_null());
        // Contract: msize must be >= requested
        let s = unsafe { msize(p) };
        assert!(s >= 1048575, "msize(1MB-1) = {} < 1048575", s);
        assert_eq!(p as usize % 16, 0);
        unsafe { free(p) };
    }

    #[test]
    fn alloc_boundary_1mb() {
        let p = unsafe { alloc(1048576) };
        assert!(!p.is_null());
        let s = unsafe { msize(p) };
        assert!(s >= 1048576, "msize(1MB) = {} < 1048576", s);
        assert_eq!(p as usize % 16, 0);
        unsafe { free(p) };
    }

    // ---- Free contract: NULL-tolerant ----

    #[test]
    fn free_null_is_noop() {
        // Must not crash
        unsafe { free(std::ptr::null_mut()) };
    }

    #[test]
    fn free_small_alloc() {
        let p = unsafe { alloc(128) };
        assert!(!p.is_null());
        unsafe { free(p) };
    }

    #[test]
    fn free_large_alloc() {
        let p = unsafe { alloc(2097152) };
        assert!(!p.is_null());
        unsafe { free(p) };
    }

    #[test]
    fn free_mid_range_alloc() {
        let p = unsafe { alloc(524288) };
        assert!(!p.is_null());
        unsafe { free(p) };
    }

    #[test]
    fn free_boundary_sizes() {
        let p1 = unsafe { alloc(1048575) };
        assert!(!p1.is_null());
        unsafe { free(p1) };

        let p2 = unsafe { alloc(1048576) };
        assert!(!p2.is_null());
        unsafe { free(p2) };
    }

    // ---- Msize contract ----

    #[test]
    fn msize_null_returns_zero() {
        assert_eq!(unsafe { msize(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn msize_small_alloc() {
        let p = unsafe { alloc(64) };
        assert!(!p.is_null());
        let s = unsafe { msize(p) };
        assert!(s >= 64, "msize(64) = {} < 64", s);
        unsafe { free(p) };
    }

    #[test]
    fn msize_large_alloc() {
        let p = unsafe { alloc(2097152) };
        assert!(!p.is_null());
        let s = unsafe { msize(p) };
        assert!(s >= 2097152, "msize(2MB) = {} < 2MB", s);
        unsafe { free(p) };
    }

    #[test]
    fn msize_boundary_1mb() {
        let p1 = unsafe { alloc(1048575) };
        assert!(!p1.is_null());
        let s1 = unsafe { msize(p1) };
        assert!(s1 >= 1048575);
        unsafe { free(p1) };

        let p2 = unsafe { alloc(1048576) };
        assert!(!p2.is_null());
        let s2 = unsafe { msize(p2) };
        assert!(s2 >= 1048576);
        unsafe { free(p2) };
    }

    // ---- Realloc contract ----

    #[test]
    fn realloc_null_is_alloc() {
        let p = unsafe { realloc(std::ptr::null_mut(), 64) };
        assert!(!p.is_null(), "realloc(NULL, 64) returned NULL");
        unsafe { free(p) };
    }

    #[test]
    fn realloc_zero_is_free() {
        let p = unsafe { alloc(128) };
        assert!(!p.is_null());
        let q = unsafe { realloc(p, 0) };
        assert!(q.is_null(), "realloc(ptr, 0) should return NULL");
    }

    #[test]
    fn realloc_grow_preserves_data() {
        let p = unsafe { alloc(64) };
        assert!(!p.is_null());
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xDE, 64) };
        let q = unsafe { realloc(p, 256) };
        assert!(!q.is_null());
        // First 64 bytes should still be 0xDE
        let buf = unsafe { std::slice::from_raw_parts(q as *const u8, 64) };
        assert!(buf.iter().all(|&b| b == 0xDE), "data corrupted after realloc grow");
        unsafe { free(q) };
    }

    #[test]
    fn realloc_shrink_preserves_data() {
        let p = unsafe { alloc(256) };
        assert!(!p.is_null());
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xAD, 256) };
        let q = unsafe { realloc(p, 32) };
        assert!(!q.is_null());
        // First 32 bytes should still be 0xAD
        let buf = unsafe { std::slice::from_raw_parts(q as *const u8, 32) };
        assert!(buf.iter().all(|&b| b == 0xAD), "data corrupted after realloc shrink");
        unsafe { free(q) };
    }

    #[test]
    fn realloc_preserves_data_across_sizes() {
        // Test that realloc preserves data for various size transitions.
        for &(from, to) in &[(64, 256), (256, 64), (1024, 4096), (4096, 512)] {
            let p = unsafe { alloc(from) };
            assert!(!p.is_null(), "alloc({}) failed", from);
            unsafe { std::ptr::write_bytes(p as *mut u8, (from & 0xFF) as u8, from) };
            let q = unsafe { realloc(p, to) };
            assert!(!q.is_null(), "realloc({}→{}) returned NULL", from, to);
            // Data preserved for min(from, to) bytes
            let keep = from.min(to);
            let expected = (from & 0xFF) as u8;
            let buf = unsafe { std::slice::from_raw_parts(q as *const u8, keep) };
            assert!(buf.iter().all(|&b| b == expected),
                "data corrupted after realloc {}→{}", from, to);
            unsafe { free(q) };
        }
    }

    #[test]
    fn realloc_large_grow_preserves_data() {
        // Alloc 1MB-1, realloc to 2MB — data must be preserved.
        let p = unsafe { alloc(1048575) };
        assert!(!p.is_null());
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xBB, 1048575) };
        let q = unsafe { realloc(p, 2097152) };
        assert!(!q.is_null());
        // First 1MB-1 bytes preserved
        let buf = unsafe { std::slice::from_raw_parts(q as *const u8, 1048575) };
        assert!(buf.iter().all(|&b| b == 0xBB), "data corrupted after large realloc grow");
        unsafe { free(q) };
    }

    // ---- Stress: many alloc/free cycles ----

    #[test]
    fn stress_alloc_free_cycle() {
        for i in 0..100 {
            let size = 16 + (i * 7) % 1048560; // varied sizes up to ~1MB
            let p = unsafe { alloc(size) };
            assert!(!p.is_null(), "stress alloc({}) returned NULL at iter {}", size, i);
            assert_eq!(p as usize % 16, 0, "stress alloc({}) not aligned at iter {}", size, i);
            unsafe { free(p) };
        }
    }

    #[test]
    fn stress_concurrent_sizes() {
        // Allocate many different sizes, then free in reverse
        let mut ptrs = Vec::new();
        for size in [16, 48, 128, 384, 1024, 4096, 16384, 65536, 262144, 524288, 1048575, 1048576, 2097152] {
            let p = unsafe { alloc(size) };
            assert!(!p.is_null(), "stress alloc({}) returned NULL", size);
            unsafe { std::ptr::write_bytes(p as *mut u8, (size & 0xFF) as u8, size.min(100)) };
            ptrs.push((p, size));
        }
        // Verify all data, then free in reverse
        for &(p, size) in &ptrs {
            let expected_byte = (size & 0xFF) as u8;
            let buf = unsafe { std::slice::from_raw_parts(p as *const u8, size.min(100)) };
            assert!(buf.iter().all(|&b| b == expected_byte), "data mismatch for size {}", size);
        }
        for &(p, _) in ptrs.iter().rev() {
            unsafe { free(p) };
        }
    }
}

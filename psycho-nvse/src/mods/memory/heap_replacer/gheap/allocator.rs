//! Game heap allocator: routes alloc/free/realloc/msize through slab + mimalloc.
//!
//! Dispatch:
//!   size <= 16KB  -> slab (per-page refcount, FreeNode UAF protection)
//!   size 16KB+1..1MB -> mimalloc (mid-range, CRT compat)
//!   size >= 1MB   -> va_allocator (VirtualAlloc per-alloc)
//!
//! UAF protection: slab writes FreeNode header on ALL freed cells.
//! Pages stay committed until Phase 7 decommit sweep.

use libc::c_void;
use libpsycho::os::windows::va_allocator;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned, mi_usable_size,
};

use super::engine::{addr, globals};
use super::statics;
use crate::mods::memory::heap_replacer::heap_validate;

const ALIGN: usize = 16;

/// When true, frees of large blocks (>= SMALL_BLOCK_THRESHOLD) bypass the
/// pool and go directly to mi_free. Small blocks still pool for zombie safety.
///
/// Two sources: `with_large_bypass(f)` (scoped) and `set_loading_bypass` (persistent).
static LARGE_BYPASS: AtomicBool = AtomicBool::new(false);
static LOADING_BYPASS: AtomicBool = AtomicBool::new(false);

/// VAS emergency mode: when commit exceeds critical threshold, all frees
/// bypass the pool and go directly to mi_free. This prevents the pool
/// from filling with undrainable small blocks during a memory crisis.
/// Set by Phase 7 watchdog when commit exceeds emergency threshold.
static VAS_EMERGENCY: AtomicBool = AtomicBool::new(false);

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

pub fn set_vas_emergency(active: bool) {
    VAS_EMERGENCY.store(active, Ordering::Release);
}

pub fn with_large_bypass<R>(f: impl FnOnce() -> R) -> R {
    struct BypassGuard;
    impl Drop for BypassGuard {
        fn drop(&mut self) {
            LARGE_BYPASS.store(false, Ordering::Release);
        }
    }
    LARGE_BYPASS.store(true, Ordering::Release);
    let _guard = BypassGuard;
    f()
}

pub fn set_loading_bypass(active: bool) {
    LOADING_BYPASS.store(active, Ordering::Release);
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

/// Allocate `size` bytes. Uses thread-local pool, falls back to mi_malloc.
///
/// When mi_malloc succeeds, we check the object's vtable and mark its
/// segment in the UAF bitmap if it's a UAF-sensitive type. This happens
/// at allocation time when the vtable is guaranteed valid (just constructed).
///
/// Large allocations (>= 1MB) go through VirtualAlloc for immediate VAS
/// reclamation.
///   Dispatch:
///   size <= 16KB  -> slab (per-page refcount, FreeNode UAF protection)
///   size 16KB+1..1MB -> mimalloc (mid-range, CRT compat)
///   size >= 1MB   -> va_allocator (VirtualAlloc, MEM_RELEASE on free)
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

    // Small/medium objects (<= 16KB) --> slab allocator.
    // Per-page refcounting + FreeNode headers for UAF protection.
    if size <= super::slab::MAX_SLAB_SIZE && size > 0 {
        let ptr = unsafe { super::slab::alloc(size) };
        if !ptr.is_null() {
            return ptr;
        }
        // Slab exhausted for this size class -- fall through to mimalloc
    }

    // Mid-range objects (16KB+1..1MB) or slab fallback --> mimalloc.
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() {
        return ptr;
    }
    unsafe { recover_oom(size) }
}

/// Free a block. Dispatch by ownership:
///   slab ptr     -> slab_free (refcount--, FreeNode header, deferred decommit)
///   mimalloc ptr -> mi_free (mid-range 16KB+1..1MB)
///   va_allocator -> va_free (VirtualFree MEM_RELEASE, >= 1MB)
///   pre-hook SBM -> original trampoline
///
/// UAF protection: slab writes FreeNode header on ALL freed cells (<= 16KB):
///   offset 0: original vtable (preserved for async flush dispatch)
///   offset 4: usable_size (fake refcount -- InterlockedDecrement never hits 0)
///   offset 8: usable_size (IOTask refcount guard)
///   offset 12: next (per-page freelist chain)
/// Pages stay committed until decommit sweep (Phase 7). Stale readers see
/// valid zombie data until then.
#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    // FAST PATH: slab check (two comparisons, no function call).
    // 95%+ of GameHeap frees are slab allocations (<= 16KB).
    if super::slab::is_slab_ptr(ptr as *const c_void) {
        unsafe { super::slab::free(ptr) };
        return;
    }

    // mimalloc arena check (CRT hooks, mid-range GameHeap allocs 16KB+1..1MB).
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        // Write UAF guard before mi_free. mi_free overwrites offset 0 with
        // a freelist pointer (which could be NULL at end of chain). Stale
        // readers doing virtual dispatch through offset 0 would crash at
        // eip=0. Writing usable_size at offsets 4 and 8 prevents
        // InterlockedDecrement from reaching 0 (NiRefObject at +4, IOTask at +8).
        // mi_free only overwrites offset 0 — offsets 4 and 8 survive.
        let usable = unsafe { mi_usable_size(ptr as *const c_void) } as u32;
        if usable >= 16 {
            unsafe {
                let p = ptr as *mut u32;
                // offset 4: NiRefObject refcount guard
                p.add(1).write(usable);
                // offset 8: IOTask refcount guard
                p.add(2).write(usable);
            }
        }
        unsafe { libmimalloc::mi_free(ptr) };
        return;
    }

    // VirtualAlloc header check (>= 1MB allocs). Simple memory read, no syscall.
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

    // mimalloc arena (CRT hooks, mid-range allocs).
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        return unsafe { mi_usable_size(ptr as *const c_void) };
    }

    // VirtualAlloc header (>= 1MB allocs).
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
    // mimalloc: in-place realloc when possible.
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
        if !new_ptr.is_null() {
            return new_ptr;
        }
        return unsafe { recover_oom(new_size) };
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
/// MEM_RELEASE), then mimalloc (arena space). This matches the
/// original alloc() dispatch: large goes to va_allocator, small to mimalloc.
#[cold]
#[inline]
unsafe fn retry_alloc(size: usize) -> *mut c_void {
    if size >= va_allocator::LARGE_ALLOC_THRESHOLD {
        let p = unsafe { va_allocator::malloc(size) };
        if !p.is_null() {
            return p;
        }
    }
    unsafe { mi_malloc_aligned(size, ALIGN) }
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
/// Each cleanup step uses HeapManager (mi_collect encapsulated).
/// Large bypass during game stages so large frees --> mi_free,
/// small frees --> pool (zombie safety preserved), then drain catches them.
#[cold]
unsafe fn recover_oom(size: usize) -> *mut c_void {
    // Reentrancy: game cleanup stages may allocate. Don't recurse into
    // the full recovery -- just collect and retry.
    if IN_OOM_RECOVERY.with(|r| r.get()) {
        unsafe { mi_collect(false) };
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
        let drained = unsafe {
            super::slab::decommit_sweep();
            mi_collect(false);
            0
        };
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Recovered after emergency drain: drained={} size={} commit={}-->{}MB",
                drained,
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
    // bypass=false -- ALL frees go to pool (zombie-safe).
    // bypass=true causes SBM state corruption: objects freed via mi_free
    // during HeapCompact stages 5-8 leave dangling references in SBM
    // internal structures, causing crashes when Stage 8 accesses them.
    // The vanilla SBM keeps objects in arenas until cleanup completes --
    // our pool quarantine provides the same behavior.
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
    // straight to nuclear option (pool_drain_all + mi_collect(true)).
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

            if done || stage >= 6 {
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

            // Periodic cleanup: decommit aged slab dirty pages (respects 30s
            // delay, force=false) + mi_collect. Worker can self-recover VAS
            // from pages that have been dirty >30s without main thread help.
            if iter.is_multiple_of(50) {
                unsafe {
                    super::slab::decommit_sweep_full(false);
                    mi_collect(false);
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
        // exits). We do one final nuclear drain + collect, then loop
        // CRT malloc indefinitely. This matches the engine contract:
        // the allocator NEVER returns NULL.
        log::error!(
            "[OOM] Worker CRT failed, nuclear drain + infinite retry: size={} commit={}MB",
            size,
            heap.commit_mb(),
        );
        unsafe { mi_collect(true) };

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
            unsafe { mi_collect(false) };
        }
    }

    // MAIN THREAD: Full cleanup with stages 3-5.
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
        // Go straight to nuclear: drain ALL pool blocks + mi_collect(true).
        if death_spiral_detected {
            log::warn!(
                "[OOM] Death spiral detected: cycle={}, commit={}MB, going nuclear",
                cycles,
                commit_before / 1024 / 1024,
            );
            let drained = unsafe {
                super::slab::decommit_sweep();
                mi_collect(false);
                (0, 0).0
            };
            unsafe { mi_collect(true) };
            let freed_bytes = commit_entry.saturating_sub(heap.commit_bytes());
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered via nuclear: drained={} freed={}MB size={} commit={}-->{}MB",
                    drained,
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
        // During loading OOM, stages 0-2 (texture/geometry/menu cache flush)
        // have no cross-thread readers -- the IO thread is loading new content,
        // not reading the old cache. Using bypass=true reclaims VAS immediately,
        // which is critical during loading when VAS pressure is highest.
        //
        // Stage 5 (Cell Unload) MUST use bypass=false because Havok entities
        // and scene graph nodes freed during cell teardown may have active
        // stale readers (AI threads, BSTaskManagerThread).
        //
        // During active gameplay (not loading), all stages use bypass=false
        // for maximum zombie safety.
        let bypass = loading && stage <= 2;
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
        if stage >= 6 {
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
    // but still couldn't allocate, drain large quarantined blocks.
    // We drain large blocks (>= 1024 bytes) which are less likely to have
    // active stale readers than small RefCount-sized blocks.
    {
        let drained = unsafe {
            super::slab::decommit_sweep();
            mi_collect(false);
            (0, 0).0
        };
        unsafe { libmimalloc::mi_collect(false) };
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Recovered after emergency pool drain: drained={} size={} commit={}-->{}MB",
                drained,
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

    // Safe drain (>= 1KB only -- no BSTreeNode UAF risk).
    unsafe {
        super::slab::decommit_sweep();
        mi_collect(false);
        0
    };
    unsafe { mi_collect(true) };
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() {
        return ptr;
    }

    // Nuclear: drain ALL pool blocks. UAF risk accepted -- crash is
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
            log::warn!("[OOM] AI threads did not join within 2s, proceeding with drain_all");
            break;
        }
    }
    // Final semaphore release before drain.
    unsafe { super::engine::globals::release_bstask_sems_if_owned() };

    let drained = unsafe {
        super::slab::decommit_sweep();
        mi_collect(false);
        (0, 0).0
    };
    let commit_after_drain = heap.commit_mb();
    let freed_mb = commit_entry.saturating_sub(commit_after_drain);
    log::error!(
        "[OOM] Last resort: drain_all={} commit={}-->{}MB freed={}MB",
        drained,
        commit_entry,
        commit_after_drain,
        freed_mb,
    );

    // Only retry if drain freed meaningful amount relative to request.
    // If we freed < requested size, VAS is too fragmented -- retrying
    // with mi_collect(true) just freezes the game for seconds.
    let size_mb = size / 1024 / 1024;
    if freed_mb > size_mb {
        unsafe { mi_collect(true) };
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

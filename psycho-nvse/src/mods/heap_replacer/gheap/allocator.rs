//! Game heap allocator: routes alloc/free/realloc/msize through slab + mimalloc.
//!
//! Dispatch:
//!   size <= 256KB -> slab (bitmap free tracking, zombie memory, 15s cooldown)
//!   size > 256KB  -> mimalloc (15s purge_delay, UAF guard at offsets 4/8)
//!
//! UAF protection: slab preserves all cell bytes on free (bitmap tracking).
//! Mimalloc freed pages stay committed for 15s (purge_delay).

use libc::c_void;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned, mi_usable_size,
};

use super::engine::{addr, globals};
use super::statics;
use super::super::heap_validate;

const ALIGN: usize = 16;

/// When true, frees of large blocks (>= SMALL_BLOCK_THRESHOLD) bypass the
/// pool and go directly to mi_free. Small blocks still pool for zombie safety.
/// Controlled by `with_large_bypass(f)` (scoped).
static LARGE_BYPASS: AtomicBool = AtomicBool::new(false);

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
/// Large allocations (> 256KB) go through mimalloc for immediate VAS
/// reclamation via purge_delay.
///   Dispatch:
///   size <= 256KB -> slab (bitmap free tracking, zombie memory, 15s cooldown)
///   size > 256KB  -> mimalloc (15s purge_delay, UAF guard at offsets 4/8)
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    // Small/medium objects (<= 256KB) --> slab allocator.
    // Bitmap free writes ZERO bytes: vtable at offset 0 preserved on free.
    // This is critical: mi_free writes NULL at offset 0 (freelist end-of-chain),
    // causing EIP=0 when BSTaskManagerThread does virtual dispatch on freed IOTasks.
    if size <= super::slab::MAX_SLAB_SIZE && size > 0 {
        let ptr = unsafe { super::slab::alloc(size) };
        if !ptr.is_null() {
            return ptr;
        }
        // Slab exhausted for this size class -- fall through to mimalloc
    }

    // Large objects (> 256KB) or slab fallback --> mimalloc.
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() {
        return ptr;
    }
    unsafe { recover_oom(size) }
}

/// Free a block. Dispatch by ownership:
///   slab ptr     -> slab_free (bitmap mark, zero writes, deferred decommit)
///   mimalloc ptr -> mi_free (UAF guard at offsets 4/8, 15s purge_delay)
///   pre-hook SBM -> original trampoline
///
/// UAF protection:
///   slab (<= 256KB): bitmap free tracking, zero bytes written to freed cells.
///     All original data preserved ("zombie memory") until page decommit.
///   mimalloc (> 256KB): UAF guard at offsets 4 (NiRefObject refcount)
///     and 8 (IOTask refcount). Pages stay committed for 15s (purge_delay).
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

    // mimalloc arena check (CRT hooks, mid-range GameHeap allocs 256KB+1..1MB).
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

/// Retry allocation with mimalloc.
#[cold]
#[inline]
unsafe fn retry_alloc(size: usize) -> *mut c_void {
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
    let loading = globals::is_loading();

    log::warn!(
        "[OOM] size={} thread={} commit={}MB pool={}MB",
        size,
        if is_main { "main" } else { "worker" },
        commit_entry,
        super::slab::committed_bytes() / 1024 / 1024,
    );

    // Immediate aggressive collection. During OOM, the 15s purge_delay
    // safety window is irrelevant -- the game will crash from memory
    // exhaustion if we don't reclaim now.
    unsafe { mi_collect(false) };
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() {
        return ptr;
    }

    // --- Phase 1: Game cleanup stages ---
    //
    // Vanilla pattern (FUN_00aa3e40):
    //   do {
    //       ptr = heap->alloc(size);
    //       if (!ptr) stage = HeapCompact(heap, heap_ptr, stage, &give_up);
    //       if (give_up) ptr = _malloc(size);
    //   } while (!ptr);
    //
    // Each call to run_oom_stage runs ONE case of the switch. The caller
    // increments the stage between calls. Stage 5 DOES NOT auto-fallthrough
    // to 4→3 -- that only happens inside the game function for a single call.
    //
    // We call stages 3, 4, 5 explicitly with alloc retry between each.
    // Stage 3: Havok GC (FUN_00c459d0 force=true)
    // Stage 4: PDD purge (non-blocking try-lock)
    // Stage 5: Cell unload + PDD + Havok GC fallthrough
    // Stages 0-2: NO-OP during gameplay (texture/geometry/menu cache)
    // Stage 6: Allocates memory (SBM defrag) -- skip
    // Stage 7/8: Thread suspend/resume -- crashes on gheap

    if loading {
        // During loading, stages 0-2 can free old cache data.
        for stage in 0..=4i32 {
            let _ = unsafe { heap.run_oom_stage(stage, false) };
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered at stage {} (loading): size={} commit={}-->{}MB",
                    stage,
                    size,
                    commit_entry,
                    heap.commit_mb(),
                );
                return ptr;
            }
        }
    } else {
        // Gameplay: run stages 3, 4, 5 with alloc retry.
        // Stage 5 also runs 4+3 internally via fallthrough, so calling
        // stage 5 alone is equivalent to running 5→4→3.
        // But we try each independently for better granularity.
        for stage in [3i32, 4, 5] {
            let _ = unsafe { heap.run_oom_stage(stage, false) };
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered at stage {}: size={} commit={}-->{}MB",
                    stage,
                    size,
                    commit_entry,
                    heap.commit_mb(),
                );
                return ptr;
            }
        }

        // Run stage 5 in a loop until no more cells eligible (vanilla behavior).
        // Each call processes one cell (5→4→3 fallthrough).
        for _ in 0..20 {
            let (_, done) = unsafe { heap.run_oom_stage(5, false) };
            if done {
                break;
            }
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered during cell unload: size={} commit={}-->{}MB",
                    size,
                    commit_entry,
                    heap.commit_mb(),
                );
                return ptr;
            }
        }
    }

    // Emergency drain: force decommit of aged pages.
    unsafe {
        super::slab::decommit_sweep_full(true);
        mi_collect(false);
    }
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() {
        log::warn!(
            "[OOM] Recovered after drain: size={} commit={}-->{}MB",
            size,
            commit_entry,
            heap.commit_mb(),
        );
        return ptr;
    }

    if !is_main {
        // --- Worker: Stage 8 pattern (vanilla-matched) ---
        //
        // Vanilla Stage 8 (case 8, worker path):
        //   Set HeapCompact trigger = 6 (main thread runs cleanup next frame)
        //   release BSTaskManager sems
        //   Sleep(1ms)
        //   Return same stage (param_2 - 1) so caller loops back to case 8
        //   Repeat up to 15000 iterations (15 seconds)
        //
        // Key: Stage 8 is a WAIT pattern. The worker signals the main thread
        // and sleeps, giving the main thread time to run cleanup on its next
        // frame. The worker only retries allocation after waking.
        //
        // We do NOT release BSTaskManager semaphores initially -- this
        // unblocks IOManager processing while freed objects may still be
        // referenced, causing crash at 0x0044DDC0. We only release after
        // giving the main thread time to drain the IO queue.
        const MAX_STAGE8: u32 = 15_000;

        log::warn!(
            "[OOM] Worker Stage 8: size={} commit={}MB pool={}MB",
            size,
            heap.commit_mb(),
            super::slab::committed_bytes() / 1024 / 1024,
        );

        for iter in 0..MAX_STAGE8 {
            // Signal main thread to run cleanup.
            heap.signal_heap_compact(super::engine::globals::HeapCompactStage::MenuCleanup);
            heap.signal_emergency_drain();

            // Periodically signal destruction_protocol (safe cell unload).
            if iter.is_multiple_of(16)
                && let Some(pr) = super::pressure::PressureRelief::instance()
            {
                pr.set_deferred_unload();
            }

            // Sleep 1ms (vanilla pattern).
            libpsycho::os::windows::winapi::sleep(1);

            // Only release BSTask semaphores after sufficient wait time.
            // This gives the main thread time to process signals and drain
            // IO before we unblock BSTaskManagerThread.
            if iter > 100 {
                unsafe { super::engine::globals::release_bstask_sems_if_owned() };
            }

            // Periodic memory reclamation. Uses mi_collect(false) to respect
            // purge_delay -- forced decommit (mi_collect(true)) causes UAF
            // when IO threads read freed texture/collision data.
            if iter.is_multiple_of(100) {
                unsafe {
                    super::slab::decommit_sweep_full(true);
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

        // Infinite retry (vanilla contract: allocator NEVER returns NULL).
        // The IN_OOM_RECOVERY guard prevents recursion if retry_alloc
        // re-enters recover_oom. All pointers stay in mimalloc ownership --
        // never use libc::malloc which creates untracked pointers that crash
        // when our free hook routes them to the game's original allocator.
        log::error!(
            "[OOM] Worker infinite retry: size={} commit={}MB",
            size,
            heap.commit_mb(),
        );
        loop {
            unsafe { mi_collect(true) };
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                return ptr;
            }
            libpsycho::os::windows::winapi::sleep(10);
        }
    }

    // --- Main thread: final drain ---
    // Main thread has no Stage 8 (it processes the trigger via frame loop).
    // Drain, then return null_mut if nothing works.
    unsafe {
        super::slab::decommit_sweep();
        mi_collect(false);
    }
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() {
        return ptr;
    }

    log::error!(
        "[OOM] FATAL: size={} commit={}MB thread=main",
        size,
        heap.commit_mb(),
    );
    null_mut()
}

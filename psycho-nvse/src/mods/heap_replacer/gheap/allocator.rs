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

/// Allocate `size` bytes. Dispatch table:
///
///   size <= 256 KB               -> slab (zombie bitmap, 15 s cooldown)
///   256 KB < size < 2 MB         -> mimalloc (purge_delay=-1, UAF guards)
///   size >= 2 MB (VA_ALLOC_THRESHOLD) -> va_alloc (direct VirtualAlloc)
///
/// The size >= 2 MB path bypasses mimalloc entirely. Rationale: on
/// 32-bit x86 mimalloc's segment size is 4 MB and anything larger
/// takes an internal huge-object direct-VA path anyway, but routing
/// through mimalloc for huge objects has two drawbacks --
/// (a) mimalloc's arena metadata tracks them, fragmenting the
///     internal segment map; and
/// (b) on failure mimalloc returns NULL with no fallback, which was
///     the root cause of the 21 MB NiDDSReader crash and the 5.6 MB
///     crash.
/// Routing huge allocations through `va_alloc` gives them a clean
/// direct-VirtualAlloc path with retry / side-table tracking, keeps
/// mimalloc's arena unfragmented by large objects, and lets
/// `free` / `msize` / `realloc` route correctly via the side table.
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

    // Huge allocations bypass mimalloc entirely.
    if size >= super::va_alloc::VA_ALLOC_THRESHOLD {
        let ptr = super::va_alloc::alloc(size);
        if !ptr.is_null() {
            return ptr;
        }
        // va_alloc failed -- OS refused. Fall into recover_oom for
        // stage-based cleanup + one retry before giving up.
        return unsafe { recover_oom(size) };
    }

    // Medium objects (256 KB < size < 2 MB) --> mimalloc.
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

    // va_alloc side-table check (huge allocations, direct VirtualAlloc).
    // Side table is tiny (< 20 entries typical) so the mutex + scan is
    // cheap, and this is only reached for pointers that are NOT in
    // slab and NOT in mimalloc -- which historically meant they went
    // straight to the CRT/HeapValidate fallback below.
    if unsafe { super::va_alloc::free(ptr) } {
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

    // va_alloc side-table check.
    if let Some(sz) = super::va_alloc::size_of(ptr as *const c_void) {
        return sz;
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
    // va_alloc: no in-place; alloc new, copy, free old. `alloc(new_size)`
    // automatically routes the new buffer through va_alloc again if the
    // new size is still above the threshold, or to mimalloc/slab if it
    // shrank below.
    if let Some(old_va_size) = super::va_alloc::size_of(ptr as *const c_void) {
        let new_ptr = unsafe { alloc(new_size) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_va_size.min(new_size),
                );
                super::va_alloc::free(ptr);
            }
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

/// OOM recovery. Two very different policies depending on thread role.
///
/// **Main thread.** Vanilla `FUN_00aa3e40` spins `do { ... } while (!ptr)`
/// with a CRT `_malloc` fallback inside the loop. Main-thread callers
/// therefore assume never-NULL. We approximate that contract: run every
/// cleanup stage the game supports (cell unload, PDD, Havok GC), drain
/// slab, `mi_collect(true)`, retry. Return NULL only after the full drill
/// fails, and log FATAL so the next crash has a clear cause.
///
/// **Worker thread.** Vanilla `FUN_00866a90` case 5 (cell unload) is
/// gated `if (!bVar5) break;` -- main-only. Cases 6, 7, and the main
/// halves of 0, 1, 2 are similarly main-only. The only worker-meaningful
/// stages are 3 (Havok GC via `TryEnterCriticalSection`) and 4 (PDD
/// try-lock wrapper `FUN_0078d200`). Case 8 is vanilla's sleep-and-
/// retry-from-the-outer-loop helper that relies on `_malloc` escaping to
/// the NT process heap -- a fallback we no longer have because we hook
/// all CRT malloc symbols into mimalloc.
///
/// So: run 3 and 4, drain slab, `mi_collect(true)`, retry -- and on
/// failure **return NULL**. No Stage-8 sleep loop, no
/// `release_bstask_sems_if_owned`, no main-thread dependency. The
/// previous sleep-loop implementation was exactly the reason the stress
/// test froze: worker sleeps waiting for main to free memory, main is
/// blocked in `PPL_wait` waiting for the worker's IO task to complete,
/// deadlock.
///
/// Worker NULL return is the contract change. With Landing B's 1024 MB
/// mimalloc reservation, genuine worker OOM should be rare or never.
/// When it does fire, returning NULL surfaces as a propagated load
/// failure in whichever NIF/BSA/texture loader made the request -- far
/// better than a hard freeze.
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
        "[OOM] size={} thread={} commit={}MB slab={}MB",
        size,
        if is_main { "main" } else { "worker" },
        commit_entry,
        super::slab::committed_bytes() / 1024 / 1024,
    );

    // Fast path: mi_collect(false) + retry. Cheap, catches the common
    // "mimalloc had free pages but hadn't reclaimed them yet" case.
    unsafe { mi_collect(false) };
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() {
        return ptr;
    }

    // ------------------------------------------------------------------
    // Worker thread: one aggressive pass, then last-resort va_alloc,
    // then NULL. va_alloc is the final fallback for ANY size, not just
    // huge objects. The 2 MB threshold is for normal-path routing
    // (where va_alloc avoids wasting VA on small requests); on the
    // failure fallback, we don't care about efficiency -- we care
    // about not returning NULL and crashing the caller.
    // ------------------------------------------------------------------
    if !is_main {
        for stage in [3i32, 4] {
            let _ = unsafe { heap.run_oom_stage(stage, false) };
        }
        unsafe {
            super::slab::decommit_sweep_full(true);
            mi_collect(true);
        }

        // Retry mimalloc once after cleanup.
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            return ptr;
        }

        // Final fallback: direct VirtualAlloc via va_alloc, any size.
        let ptr = super::va_alloc::alloc(size);
        if !ptr.is_null() {
            return ptr;
        }

        log::error!(
            "[OOM] Worker returning NULL: size={} commit={}MB slab={}MB \
             va_live={} va_bytes={}MB. OS refused direct VirtualAlloc.",
            size,
            heap.commit_mb(),
            super::slab::committed_bytes() / 1024 / 1024,
            super::va_alloc::live_count(),
            super::va_alloc::live_bytes() / 1024 / 1024,
        );
        return null_mut();
    }

    // ------------------------------------------------------------------
    // Main thread: run every cleanup stage, retry between each.
    // ------------------------------------------------------------------
    //
    // Stages 0-5 are all main-thread-safe. We run them in order, cheap
    // first, and bail as soon as mimalloc can satisfy the request.
    //
    // Stage 0: texture cache flush (FUN_00452490)
    // Stage 1: SBM dealloc (ret-patched in our build -- no-op but safe)
    // Stage 2: menu/journal cleanup
    // Stage 3: Havok GC
    // Stage 4: PDD try-lock wrapper
    // Stage 5: FindCellToUnload (+ PDD + Havok GC fallthrough)
    let loading = globals::is_loading();
    let stage_set: &[i32] = if loading {
        &[0, 1, 2, 3, 4, 5]
    } else {
        &[3, 4, 5]
    };

    for &stage in stage_set {
        let _ = unsafe { heap.run_oom_stage(stage, false) };
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Main recovered at stage {}: size={} commit={}-->{}MB",
                stage,
                size,
                commit_entry,
                heap.commit_mb(),
            );
            return ptr;
        }
    }

    // Stage 5 loop: keep unloading cells until none remain eligible.
    // Each call processes one cell via the internal 5->4->3 fallthrough.
    for _ in 0..20 {
        let (_, done) = unsafe { heap.run_oom_stage(5, false) };
        if done {
            break;
        }
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Main recovered during cell unload: size={} commit={}-->{}MB",
                size,
                commit_entry,
                heap.commit_mb(),
            );
            return ptr;
        }
    }

    // Final hammer: force slab decommit + mi_collect(true). Main thread
    // only -- these are safe here because main cannot race itself.
    unsafe {
        super::slab::decommit_sweep_full(true);
        mi_collect(true);
    }

    // Retry mimalloc once after cleanup.
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() {
        return ptr;
    }

    // Final fallback: direct VirtualAlloc via va_alloc, any size.
    let ptr = super::va_alloc::alloc(size);
    if !ptr.is_null() {
        return ptr;
    }

    log::error!(
        "[OOM] FATAL main: size={} commit={}MB slab={}MB va_live={} va_bytes={}MB. \
         OS refused direct VirtualAlloc. Returning NULL.",
        size,
        heap.commit_mb(),
        super::slab::committed_bytes() / 1024 / 1024,
        super::va_alloc::live_count(),
        super::va_alloc::live_bytes() / 1024 / 1024,
    );
    null_mut()
}

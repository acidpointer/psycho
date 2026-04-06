//! Game heap allocator: routes alloc/free/realloc/msize through pool + mimalloc.
//!
//! Every thread gets its own thread-local pool (zombie freelist). Freed blocks
//! stay readable until reused by a same-size allocation. This preserves the
//! SBM "freed memory stays readable" contract that the game engine relies on.
//!
//! - Alloc: pool (freelist hit) or mi_malloc (freelist miss).
//! - Free:  pool freelist push (block stays readable).
//! - OOM:   drain own pool + game OOM stages (mutex-protected) + retry.

use libc::c_void;
use libpsycho::os::windows::va_allocator;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned, mi_usable_size,
};

use super::engine::{addr, globals};
use super::pool;
use super::statics;
use super::uaf_bitmap;
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

/// Percentage of headroom (available_vas - baseline) at which VAS CRITICAL
/// mode activates. 60% of headroom used = danger zone.
/// e.g., if available=3200MB, baseline=731MB, headroom=2469MB,
/// critical = 731 + 2469*0.60 = 2212MB
const VAS_CRITICAL_PCT: f64 = 0.60;

/// Percentage of headroom at which VAS EMERGENCY mode activates.
/// 70% of headroom used = crisis mode.
const VAS_EMERGENCY_PCT: f64 = 0.70;

/// Minimum viable headroom (bytes) for VAS crisis management to be effective.
/// Below this, our cleanup mechanisms (pool drain, mi_collect, cell unload)
/// free less memory than the game allocates per cycle, making the crisis
/// management counterproductive — it causes a death spiral instead of
/// recovering memory. 500MB guarantees enough buffer for loading spikes.
const MINIMUM_VIABLE_HEADROOM: usize = 500 * 1024 * 1024; // 500MB

/// Available VAS at startup, calculated once via VirtualQuery.
/// Set during init, read at baseline calibration.
static AVAILABLE_VAS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Dynamic VAS CRITICAL threshold (bytes). Calculated when baseline is calibrated.
/// = baseline + (available_vas - baseline) * VAS_CRITICAL_PCT
static VAS_CRITICAL_COMMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Dynamic VAS EMERGENCY threshold (bytes).
/// = baseline + (available_vas - baseline) * VAS_EMERGENCY_PCT
static VAS_EMERGENCY_COMMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Walk the process address space via VirtualQuery and sum all MEM_FREE regions.
/// Returns total available virtual address space in bytes.
/// Called once at startup (after all DLLs loaded).
pub fn init_available_vas() -> usize {
    use windows::Win32::System::Memory::{
        MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQuery,
    };

    let mut addr = 0x10000usize; // Skip NULL guard page
    let mut available: usize = 0;

    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let result = unsafe {
            VirtualQuery(
                Some(addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if result == 0 {
            break; // End of address space
        }
        if mbi.State == MEM_FREE {
            available += mbi.RegionSize;
        }
        addr = mbi.BaseAddress as usize + mbi.RegionSize;
        // Safety check: prevent infinite loop on wraparound
        if addr <= mbi.BaseAddress as usize {
            break;
        }
    }

    AVAILABLE_VAS.store(available, std::sync::atomic::Ordering::Release);
    log::info!(
        "[VAS] Available: {}MB (address space scan complete)",
        available / 1024 / 1024,
    );
    available
}

/// Recalculate VAS thresholds based on the calibrated baseline commit.
/// Called when baseline_commit is first calibrated by PressureRelief.
///
/// If headroom is too small (< 500MB), VAS crisis management is disabled
/// (thresholds set to MAX). Our cleanup mechanisms free less memory than
/// the game allocates per cycle in tight headroom situations, making
/// crisis management counterproductive — it causes a death spiral.
pub fn calibrate_thresholds(baseline: usize) {
    let available = AVAILABLE_VAS.load(std::sync::atomic::Ordering::Acquire);
    if available == 0 || baseline == 0 {
        return;
    }
    let headroom = available.saturating_sub(baseline);

    if headroom < MINIMUM_VIABLE_HEADROOM {
        // Headroom too small — VAS crisis management would cause a death
        // spiral instead of recovering memory. Disable it entirely.
        VAS_CRITICAL_COMMIT.store(usize::MAX, std::sync::atomic::Ordering::Release);
        VAS_EMERGENCY_COMMIT.store(usize::MAX, std::sync::atomic::Ordering::Release);

        log::warn!(
            "[VAS] Headroom too small ({}MB < 500MB). VAS crisis DISABLED. \
             Game's own OOM handler will manage memory pressure.",
            headroom / 1024 / 1024,
        );
        return;
    }

    let critical = baseline + ((headroom as f64 * VAS_CRITICAL_PCT) as usize);
    let emergency = baseline + ((headroom as f64 * VAS_EMERGENCY_PCT) as usize);

    VAS_CRITICAL_COMMIT.store(critical, std::sync::atomic::Ordering::Release);
    VAS_EMERGENCY_COMMIT.store(emergency, std::sync::atomic::Ordering::Release);

    log::info!(
        "[VAS] Thresholds calibrated: baseline={}MB, headroom={}MB, critical={}MB ({}%), emergency={}MB ({}%)",
        baseline / 1024 / 1024,
        headroom / 1024 / 1024,
        critical / 1024 / 1024,
        (VAS_CRITICAL_PCT * 100.0) as u32,
        emergency / 1024 / 1024,
        (VAS_EMERGENCY_PCT * 100.0) as u32,
    );
}

/// Get the current VAS CRITICAL threshold.
pub fn get_critical_commit() -> usize {
    VAS_CRITICAL_COMMIT.load(std::sync::atomic::Ordering::Acquire)
}

/// Get the current VAS EMERGENCY threshold.
pub fn get_emergency_commit() -> usize {
    VAS_EMERGENCY_COMMIT.load(std::sync::atomic::Ordering::Acquire)
}

pub fn set_vas_emergency(active: bool) {
    VAS_EMERGENCY.store(active, std::sync::atomic::Ordering::Release);
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

#[inline]
pub fn is_bypass_active() -> bool {
    LARGE_BYPASS.load(Ordering::Relaxed)
        || LOADING_BYPASS.load(Ordering::Relaxed)
        || VAS_EMERGENCY.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------
// Thread identity
// -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ThreadRole { Unknown = 0, Main = 1, Worker = 2 }

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
/// reclamation. This threshold is chosen so that:
/// - Havok shapes (100KB-500KB) --> mimalloc + pool (UAF protected)
/// - NiRefObjects (16-1200B) --> mimalloc + pool (UAF protected)
/// - Terrain meshes, DDS files (1MB+) --> VirtualAlloc (VAS reclaimed)
///   Game objects are rarely > 1MB. Raw data buffers often are.
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    // Large raw buffers (>= 1MB) --> VirtualAlloc for immediate VAS reclamation.
    // Game objects (Havok shapes, NiNodes, etc.) are < 1MB and go through
    // mimalloc where they get UAF protection via pool + purge_delay.
    if size >= va_allocator::LARGE_ALLOC_THRESHOLD {
        let ptr = unsafe { va_allocator::malloc(size) };
        if !ptr.is_null() {
            return ptr;
        }
        return unsafe { recover_oom(size) };
    }

    let ptr = if is_pool_active() {
        let (p, _) = unsafe { pool::pool_alloc(size) };
        p
    } else {
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        // Mark segment at alloc time when vtable is guaranteed valid
        if !ptr.is_null() {
            uaf_bitmap::mark_segment(ptr as *mut u8);
        }
        ptr
    };

    if !ptr.is_null() {
        return ptr;
    }
    unsafe { recover_oom(size) }
}

/// Free a block. Pushes to thread-local pool (zombie-safe).
/// Pre-hook pointers are routed to the original SBM trampoline.
///
/// ## UAF Protection via FreeNode Header + Dual Detection
///
/// UAF-sensitive objects (NiRefObjects, Havok physics entities) are detected
/// via TWO mechanisms:
///
/// 1. PRIMARY: Vtable range check at free time
///    - Works for ALL objects regardless of when allocated
///    - Catches pre-plugin objects that bitmap misses
///    - Safe because destructor hasn't run yet (we're in free())
///
/// 2. SECONDARY: Allocation-time bitmap
///    - Catches objects where vtable might be borderline
///    - Provides defense-in-depth
///
/// FreeNode header at pool entry provides runtime protection:
///   offset 0: original vtable (preserved for safe async flush dispatch)
///   offset 4: usable_size (block size, replaces RefCount)
///   offset 8: next pointer (freelist chain)
///
/// When game accesses freed object:
///   1. Reads offset 4 as RefCount --> gets usable_size (e.g., 48)
///   2. Calls InterlockedDecrement(48) --> 47, NOT zero
///   3. No destructor call --> NO CRASH
///
/// This protects against cross-thread UAF from:
///   - AI worker threads running Havok broadphase
///   - IO threads completing texture loads
///   - Scene graph traversals accessing freed nodes
///
/// ## Loading-Safe Free Path
///
/// During loading (LOADING_BYPASS active), the game frees entire cells worth
/// of objects. If all these went to mi_free (the old behavior), cross-thread
/// readers (AI threads finishing, BSTaskManagerThread loading textures) would
/// read garbage. Instead, we use a tiered approach:
///   - UAF-sensitive objects: ALWAYS pool (zombie quarantine)
///   - Non-sensitive, large (>= 1KB): mi_free (VAS recovery)
///   - Non-sensitive, small (< 1KB): pool (minimal VAS impact)
#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    // FAST PATH: Check mimalloc arena first. 95%+ of frees are mimalloc
    // allocations — avoid the expensive VirtualQuery sys call for these.
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        if is_pool_active() {
            // PRIMARY: Vtable check - works for ALL objects including pre-plugin
            let vtable = unsafe { *(ptr as *const *const u8) };
            let addr = vtable as usize;
            let is_uaf_sensitive_vtable =
                // NiRefObjects: textures, nodes, BSTree, etc.
                (0x01010000..0x010F0000).contains(&addr)
                // Havok physics: broadphase, islands, collision, rigid bodies
                || (0x010C0000..0x010D0000).contains(&addr);

            // SECONDARY: Bitmap check for defense-in-depth
            let is_uaf_sensitive_bitmap = uaf_bitmap::is_uaf_sensitive_segment(ptr as *mut u8);

            if is_uaf_sensitive_vtable || is_uaf_sensitive_bitmap {
                // ALWAYS pool UAF-sensitive types, even during loading bypass.
                // FreeNode header makes RefCount irrelevant - stale readers
                // see usable_size instead of RefCount, preventing destructor calls.
                // This is the KEY FIX for loading-time UAF crashes.
                unsafe { pool::pool_free(ptr) };
                return;
            }

            // Non-sensitive: tiered free path.
            // During loading bypass, large blocks go to mi_free for VAS recovery.
            // Small blocks still pool for zombie safety (minimal VAS impact).
            if is_bypass_active() {
                let usable = unsafe { mi_usable_size(ptr as *const c_void) };
                if usable >= pool::SMALL_BLOCK_THRESHOLD {
                    unsafe { libmimalloc::mi_free(ptr) };
                    return;
                }
                // Small non-sensitive blocks: pool for zombie safety.
                // VAS impact is minimal (< 1KB per block, soft cap at 32MB).
                unsafe { pool::pool_free(ptr) };
                return;
            }

            // Normal (no bypass): large blocks (>= 1MB) are raw data buffers
            // (terrain, textures) that went through VirtualAlloc. They don't
            // have UAF risk — no vtables at this size. Free via VirtualAlloc
            // header check (simple memory read, NO sys call).
            // Small blocks pool for zombie safety.
            let usable = unsafe { mi_usable_size(ptr as *const c_void) };
            if usable >= va_allocator::LARGE_ALLOC_THRESHOLD {
                // This shouldn't happen for GameHeap (we route >= 1MB to
                // VirtualAlloc at alloc time), but if somehow a large block
                // came through mimalloc (pre-plugin or edge case), free it
                // via mi_free + mi_collect(true) for VAS reclamation.
                unsafe { libmimalloc::mi_free(ptr) };
                unsafe { libmimalloc::mi_collect(true) };
                return;
            }

            // Small blocks pool for zombie safety.
            unsafe { pool::pool_free(ptr) };
        } else {
            unsafe { libmimalloc::mi_free(ptr) };
        }
        return;
    }

    // SLOW PATH: Check VirtualAlloc header. Large allocations (>= 1MB) go
    // through VirtualAlloc. Header magic check is a simple memory read — NO
    // sys call. This handles both GameHeap large allocations and CRT large
    // allocations that were routed through VirtualAlloc.
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

    // FAST PATH: Check mimalloc first. 95%+ of allocations are in the arena.
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        return unsafe { mi_usable_size(ptr as *const c_void) };
    }

    // SLOW PATH: Outside arena — check VirtualAlloc header (simple memory
    // read, NO sys call). Large allocations (>= 1MB) use VirtualAlloc.
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
        size, if is_main { "main" } else { "worker" },
        commit_entry, heap.pool_mb(),
    );

    // --- Emergency pool drain (main thread only) ---
    // Workers set this flag; main thread Phase 7 normally consumes it.
    // But when the main thread is IN OOM recovery, it never reaches Phase 7.
    // Consume the flag here to drain stale zombie blocks immediately.
    if is_main && heap.take_emergency_drain() {
        let drained = unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Recovered after emergency drain: drained={} size={} commit={}-->{}MB",
                drained, size, commit_entry, heap.commit_mb(),
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
                    stage, size, commit_entry, heap.commit_mb(),
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
            size, heap.commit_mb(), heap.pool_mb(),
        );

        for iter in 0..MAX_STAGE8_ITERS {
            // Match vanilla: set HeapCompact trigger + release sems + sleep
            heap.signal_heap_compact(
                super::engine::globals::HeapCompactStage::MenuCleanup,
            );
            heap.signal_emergency_drain();
            unsafe { super::engine::globals::release_bstask_sems_if_owned() };

            // Signal destruction_protocol periodically (safe cell unload
            // path with Havok lock, consumed at AI_JOIN).
            if iter.is_multiple_of(16) {
                if let Some(pr) = super::pressure::PressureRelief::instance() {
                    pr.set_deferred_unload();
                }
            }

            libpsycho::os::windows::winapi::sleep(1);

            // Periodic mi_collect to decommit freed pages.
            if iter.is_multiple_of(50) {
                unsafe { mi_collect(false) };
            }

            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Worker recovered (Stage 8): iter={} size={} commit={}-->{}MB",
                    iter, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }

            if iter.is_multiple_of(1000) && iter > 0 {
                log::warn!(
                    "[OOM] Worker Stage 8: {}ms size={} commit={}MB pool={}MB",
                    iter, size, heap.commit_mb(), heap.pool_mb(),
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
            MAX_STAGE8_ITERS, size, heap.commit_mb(),
        );
        let ptr = unsafe { libc::malloc(size) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Worker recovered (CRT): size={} commit={}MB",
                size, heap.commit_mb(),
            );
            return ptr as *mut c_void;
        }

        // CRT also failed. Vanilla loops forever here (do-while never
        // exits). We do one final nuclear drain + collect, then loop
        // CRT malloc indefinitely. This matches the engine contract:
        // the allocator NEVER returns NULL.
        log::error!(
            "[OOM] Worker CRT failed, nuclear drain + infinite retry: size={} commit={}MB",
            size, heap.commit_mb(),
        );
        unsafe { mi_collect(true) };

        loop {
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                return ptr;
            }
            let ptr = unsafe { libc::malloc(size) };
            if !ptr.is_null() {
                return ptr as *mut c_void;
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
                cycles, commit_before / 1024 / 1024,
            );
            let drained = unsafe { pool::pool_drain_all() };
            unsafe { mi_collect(true) };
            let freed_bytes = commit_entry.saturating_sub(heap.commit_bytes());
            let ptr = unsafe { retry_alloc(size) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered via nuclear: drained={} freed={}MB size={} commit={}-->{}MB",
                    drained, freed_bytes / 1024 / 1024, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }
            log::error!(
                "[OOM] FATAL (nuclear failed): size={} commit={}MB freed={}MB",
                size, heap.commit_mb(), freed_bytes / 1024 / 1024,
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
                cycles, stage, size, commit_entry, heap.commit_mb(),
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
                    freed / 1024, death_spiral_threshold / 1024 / 1024,
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
                    if freed == 0 { "nothing freed" } else { "very little" },
                    stage, commit_entry, heap.commit_mb(),
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
        let drained = unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
        unsafe { libmimalloc::mi_collect(false) };
        let ptr = unsafe { retry_alloc(size) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Recovered after emergency pool drain: drained={} size={} commit={}-->{}MB",
                drained, size, commit_entry, heap.commit_mb(),
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
        commit_entry, heap.commit_mb(), heap.pool_mb(),
    );

    // Safe drain (>= 1KB only -- no BSTreeNode UAF risk).
    unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
    unsafe { mi_collect(true) };
    let ptr = unsafe { retry_alloc(size) };
    if !ptr.is_null() { return ptr; }

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

    let drained = unsafe { pool::pool_drain_all() };
    let commit_after_drain = heap.commit_mb();
    let freed_mb = commit_entry.saturating_sub(commit_after_drain);
    log::error!(
        "[OOM] Last resort: drain_all={} commit={}-->{}MB freed={}MB",
        drained, commit_entry, commit_after_drain, freed_mb,
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
                commit_entry, heap.commit_mb(),
            );
            return ptr;
        }
    }

    log::error!(
        "[OOM] FATAL: size={} commit={}MB thread={}",
        size, heap.commit_mb(), if is_main { "main" } else { "worker" },
    );
    null_mut()
}

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

pub fn with_large_bypass<R>(f: impl FnOnce() -> R) -> R {
    LARGE_BYPASS.store(true, Ordering::Release);
    let result = f();
    LARGE_BYPASS.store(false, Ordering::Release);
    result
}

pub fn set_loading_bypass(active: bool) {
    LOADING_BYPASS.store(active, Ordering::Release);
}

#[inline]
pub fn is_bypass_active() -> bool {
    LARGE_BYPASS.load(Ordering::Relaxed) || LOADING_BYPASS.load(Ordering::Relaxed)
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
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
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
///   1. Reads offset 4 as RefCount → gets usable_size (e.g., 48)
///   2. Calls InterlockedDecrement(48) → 47, NOT zero
///   3. No destructor call → NO CRASH
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

            // Normal (no bypass): pool everything
            unsafe { pool::pool_free(ptr) };
        } else {
            unsafe { libmimalloc::mi_free(ptr) };
        }
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
        return unsafe { mi_malloc_aligned(size, ALIGN) };
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
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Recovered after emergency drain: drained={} size={} commit={}-->{}MB",
                drained, size, commit_entry, heap.commit_mb(),
            );
            return ptr;
        }
    }

    // Worker: signal main thread to drain its pool at Phase 7.
    if !is_main {
        heap.signal_emergency_drain();

        // Release BSTaskManagerThread semaphores if we own them.
        // This matches vanilla OOM Stage 8 behavior (FUN_00866a90 case 8).
        // Without this, worker threads holding IO semaphores deadlock:
        //   - Worker holds semaphore, waits for memory
        //   - Main thread can't drain IO (semaphore held by worker)
        //   - Memory can't be freed, worker waits forever
        // Releasing semaphores lets IO complete, freeing memory for retry.
        unsafe { super::engine::globals::release_bstask_sems_if_owned() };
    }

    // --- Phase 1: Active cleanup (stages 3-5, retry alloc after each) ---
    //
    // The game's allocator contract: NEVER return NULL.
    // Pattern from vanilla FUN_00aa3e40:
    //   do {
    //       stage = FUN_00866a90(heap, stage, &give_up);
    //       if (give_up) { ptr = _malloc(size); break; }
    //       ptr = heap_vtable->alloc(size);
    //   } while (!ptr);
    //
    // We run stages 3-5 (Havok GC, PDD purge, Cell Unload) which actually
    // free memory during active gameplay. Stages 0-2 (texture, geometry,
    // menu) are NO-OP during gameplay. Stage 6 (SBM GlobalCleanup)
    // ALLOCATES memory. Stage 7 is give_up check.
    //
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
    let mut stage: i32 = if globals::is_loading() { 0 } else { 3 };
    let mut cycles: u32 = 0;

    loop {
        cycles += 1;
        let commit_before = heap.commit_bytes();

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
        let loading = globals::is_loading();
        let bypass = loading && stage <= 2;
        let (next, done) = unsafe { heap.run_oom_stage(stage, bypass) };
        stage = next;

        // Try allocation after every stage
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::info!(
                "[OOM] Recovered: cycle={} stage={} size={} commit={}-->{}MB",
                cycles, stage, size, commit_entry, heap.commit_mb(),
            );
            return ptr;
        }

        // If give_up was set (stage 7 on main thread), fall back to CRT
        if done {
            break;
        }

        // Workers: signal main thread + yield between stages.
        // Main thread skips yield -- it IS the cleanup thread.
        if !is_main {
            heap.signal_heap_compact(
                super::engine::globals::HeapCompactStage::CellUnload,
            );
            heap.signal_emergency_drain();

            // Release BSTaskManagerThread semaphores on each iteration.
            unsafe { super::engine::globals::release_bstask_sems_if_owned() };

            libpsycho::os::windows::winapi::sleep(1);

            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered after yield: cycle={} stage={} size={} commit={}-->{}MB",
                    cycles, stage, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }
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
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::warn!(
                "[OOM] Recovered after emergency pool drain: drained={} size={} commit={}-->{}MB",
                drained, size, commit_entry, heap.commit_mb(),
            );
            return ptr;
        }
    }

    // --- Phase 2: Wait for main thread cleanup (workers only) ---
    //
    // Workers can't run stage 5 (cell unload, main-thread-only).
    // Signal main thread to run destruction_protocol at each AI_JOIN.
    // Each AI_JOIN (~16ms) unloads 11 cells, freeing ~10-30MB.
    // Re-signal every frame so destruction_protocol runs repeatedly
    // until enough memory is freed.
    if !is_main {
        // Normal gameplay: 2 seconds (main loop runs destruction_protocol).
        // Loading/menu/console: 30 seconds (main loop paused, will resume
        // when player closes menu -- no point going to FATAL).
        let max_wait = if globals::is_loading() { 30_000u32 } else { 2_000u32 };

        for iter in 0..max_wait {
            // Re-signal every ~16ms (once per frame) so main thread
            // runs destruction_protocol at every AI_JOIN when it resumes.
            if iter.is_multiple_of(16) {
                heap.signal_heap_compact(
                    super::engine::globals::HeapCompactStage::CellUnload,
                );
                heap.signal_emergency_drain();
                if let Some(pr) = super::pressure::PressureRelief::instance() {
                    pr.set_deferred_unload();
                }
            }

            // Release BSTaskManagerThread semaphores every iteration.
            // Vanilla Stage 8 releases semaphores before each Sleep(1).
            // This is the KEY FIX: lets IO complete so memory can be freed.
            unsafe { super::engine::globals::release_bstask_sems_if_owned() };
            
            libpsycho::os::windows::winapi::sleep(1);

            // Re-check loading state -- if menu closed, switch to short wait.
            if iter == 2000 && !globals::is_loading() {
                break;
            }

            unsafe { mi_collect(false) };
            let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
            if !ptr.is_null() {
                log::info!(
                    "[OOM] Recovered during wait: iter={}ms size={} commit={}-->{}MB",
                    iter, size, commit_entry, heap.commit_mb(),
                );
                return ptr;
            }

            if iter.is_multiple_of(1000) && iter > 0 {
                log::warn!(
                    "[OOM] Waiting: {}ms commit={}-->{}MB pool={}MB loading={}",
                    iter, commit_entry, heap.commit_mb(), heap.pool_mb(),
                    globals::is_loading(),
                );
            }
        }

        log::warn!(
            "[OOM] Wait expired: commit={}-->{}MB pool={}MB",
            commit_entry, heap.commit_mb(), heap.pool_mb(),
        );
    }

    // --- Phase 3: Last resort ---
    //
    // Main thread arrives here fast (no Phase 2 wait). Workers arrive
    // after 3 seconds of waiting. Now we escalate to unsafe operations.
    log::warn!(
        "[OOM] Escalating: commit={}-->{}MB pool={}MB",
        commit_entry, heap.commit_mb(), heap.pool_mb(),
    );

    // Safe drain (>= 1KB only -- no BSTreeNode UAF risk).
    unsafe { heap.drain_pool(pool::SMALL_BLOCK_THRESHOLD) };
    unsafe { mi_collect(true) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
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
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
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

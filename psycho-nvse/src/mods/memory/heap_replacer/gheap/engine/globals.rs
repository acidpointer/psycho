//! Safe wrappers for reading game globals and calling game functions.
//!
//! Every function here encapsulates the unsafe pointer-from-integer cast
//! and volatile/atomic reads. Callers never touch raw addresses directly.
//!
//! Functions that call game code (OOM stages, FindCellToUnload, etc.) are
//! marked unsafe because they have thread/phase preconditions that the
//! compiler cannot verify.

#![allow(dead_code)]

use libc::c_void;

use libpsycho::ffi::fnptr::FnPtr;
use libpsycho::os::windows::winapi::{self, WaitResult};

use super::addr;
use crate::mods::memory::heap_replacer::gheap::types;

// ---------------------------------------------------------------------------
// Game state reads (all safe -- reading from known static addresses)
// ---------------------------------------------------------------------------

/// True when the game is in a loading screen (save load, fast travel, coc).
/// Simple volatile read. No edge detection overhead on the hot path.
/// Loading transitions are logged by the watchdog thread instead.
/// WARNING: includes console/menu state. Use is_real_loading() for
/// loading detection that doesn't fire on console open/close.
#[inline]
pub fn is_loading() -> bool {
    unsafe { *(addr::LOADING_FLAG as *const u8) != 0 }
}

/// True only during actual cell data loading (not console/menu/pause).
/// Calls FUN_00702360 directly, bypassing the IsMenuMode check in LOADING_FLAG.
/// Ghidra-validated: LOADING_FLAG = FUN_00702360() || FUN_00709bc0().
/// FUN_00709bc0 checks console/menu state -> causes false loading transitions.
pub fn is_real_loading() -> bool {
    let f = match unsafe {
        FnPtr::<types::IsRealLoadingFn>::from_raw(addr::IS_REAL_LOADING as *mut c_void)
    } {
        Ok(f) => f,
        Err(_) => return false,
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f() },
        Err(_) => false,
    }
}

/// HeapCompact stages. The game's HeapCompact dispatcher at Phase 6
/// reads the trigger field and runs stages 0..=N, then resets to 0.
///
/// Stage 0: Texture cache flush (NiDX9SourceTextureData purge)
/// Stage 1: Geometry cache flush (NiDX9RenderedTexture purge)
/// Stage 2: Menu cleanup (InterfaceManager release)
/// Stage 3: Havok GC (hkMemorySystem garbage collect)
/// Stage 4: PDD purge (ProcessManager lock + full deferred destruction)
/// Stage 5: Cell unloading (FindCellToUnload) -- DANGEROUS: deadlocks
///          during fast travel and loading screens. Never use from
///          pressure relief.
#[allow(dead_code)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeapCompactStage {
    TextureCache = 0,
    GeometryCache = 1,
    MenuCleanup = 2,
    HavokGC = 3,
    PddPurge = 4,
    CellUnload = 5,
}

/// Read the current HeapCompact trigger value.
pub fn heap_compact_trigger_value() -> u32 {
    unsafe { *(addr::HEAP_COMPACT_TRIGGER as *const u32) }
}

/// Signal HeapCompact to run stages 0..=stage on the next frame.
/// Raw write -- prefer HeapManager::signal_heap_compact() which uses
/// MAX semantics (never downgrades an existing trigger).
pub fn signal_heap_compact(stage: HeapCompactStage) {
    unsafe {
        let trigger = addr::HEAP_COMPACT_TRIGGER as *mut u32;
        trigger.write_volatile(stage as u32);
    }
}

/// PDD skip mask bits. When set, the corresponding queue is SKIPPED
/// during full PDD drain (FUN_00868d70). Checked by FUN_00869180.
#[allow(dead_code)]
pub mod pdd_skip {
    pub const NINODE: u32 = 0x10;
    pub const FORM: u32 = 0x08;
    pub const TEXTURE: u32 = 0x04;
    pub const ANIM: u32 = 0x02;
    pub const GENERIC: u32 = 0x01;
    pub const LAST: u32 = 0x20;
}

/// Set the PDD skip mask. Queues with matching bits are SKIPPED
/// by the next full PDD drain (stage 4). Reset after PDD completes.
pub fn set_pdd_skip_mask(mask: u32) {
    unsafe {
        let p = addr::PDD_SKIP_MASK as *mut u32;
        p.write_volatile(mask);
    }
}

/// Read the current PDD skip mask.
pub fn pdd_skip_mask() -> u32 {
    unsafe { *(addr::PDD_SKIP_MASK as *const u32) }
}

/// Get the loading state counter as an atomic reference. Incremented to
/// suppress NVSE PLChangeEvent dispatch during our destruction protocol.
pub fn loading_state_counter() -> &'static std::sync::atomic::AtomicI32 {
    unsafe { &*(addr::LOADING_STATE_COUNTER as *const std::sync::atomic::AtomicI32) }
}

/// Get the game manager pointer (DataHandler). Returns None if null.
/// Passed to FindCellToUnload.
pub fn game_manager() -> Option<*mut c_void> {
    let ptr = unsafe { *(addr::GAME_MANAGER as *const *mut c_void) };
    if ptr.is_null() { None } else { Some(ptr) }
}

/// Check if BSTaskManagerThread has a pending cell load in progress.
/// Returns true if busy (handle != -1), false if idle.
pub fn is_bst_cell_load_pending() -> bool {
    unsafe {
        let tes = *(addr::TES_SINGLETON as *const *const u8);
        if tes.is_null() {
            return true; // assume busy if singleton not available
        }
        let handle = *(tes.add(addr::TES_PENDING_CELL_LOAD_OFFSET) as *const i32);
        handle != -1
    }
}

// ---------------------------------------------------------------------------
// PDD queue diagnostics
// ---------------------------------------------------------------------------

/// Which PDD queue to query.
#[allow(dead_code)]
pub enum PddQueue {
    NiNode,
    Form,
    Generic,
    Anim,
    Texture,
}

/// Read the entry count of a PDD queue (u16 at base + 0x0A).
pub fn pdd_queue_count(queue: PddQueue) -> u16 {
    let base = match queue {
        PddQueue::NiNode => addr::NINODE_QUEUE,
        PddQueue::Form => addr::FORM_QUEUE,
        PddQueue::Generic => addr::GENERIC_QUEUE,
        PddQueue::Anim => addr::ANIM_QUEUE,
        PddQueue::Texture => addr::TEXTURE_QUEUE,
    };
    unsafe { *((base + addr::PDD_QUEUE_COUNT_OFFSET) as *const u16) }
}

// ---------------------------------------------------------------------------
// Thread identification
// ---------------------------------------------------------------------------

/// Check if the current thread is the game's main thread by comparing
/// thread IDs through the engine's own GetCurrentThreadId wrapper and
/// the main thread ID stored in the TES object.
/// Stored main thread ID. Set ONLY from on_pre_ai (game main loop Phase 7).
/// This is the ONE place we are 100% certain is the main thread.
static MAIN_THREAD_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Set main thread ID. Called ONCE from on_pre_ai (first frame tick).
/// on_pre_ai is a hook inside the game's main loop -- guaranteed main thread.
pub fn set_main_thread_id() {
    let tid = libpsycho::os::windows::winapi::get_current_thread_id();
    let prev = MAIN_THREAD_ID.swap(tid, std::sync::atomic::Ordering::Release);
    if prev == 0 {
        log::info!("[THREAD] Main thread ID confirmed from on_pre_ai: {}", tid);
    } else if prev != tid {
        log::error!(
            "[THREAD] Main thread ID changed: {} -> {} (should never happen)",
            prev,
            tid,
        );
    }
}

/// Check if current thread is main. Simple OS thread ID comparison.
/// Returns false until on_pre_ai sets the ID (first frame tick).
/// Before that: all frees go to mi_free (QUARANTINE_ACTIVE is also false).
pub fn is_main_thread_by_tid() -> bool {
    let main_tid = MAIN_THREAD_ID.load(std::sync::atomic::Ordering::Acquire);
    if main_tid == 0 {
        return false;
    }
    libpsycho::os::windows::winapi::get_current_thread_id() == main_tid
}

// ---------------------------------------------------------------------------
// BSTaskManagerThread semaphore management (OOM Stage 8)
// ---------------------------------------------------------------------------

/// Release BSTaskManagerThread semaphores if the current thread owns them.
///
/// This matches vanilla OOM Stage 8 behavior (FUN_00866a90 case 8):
/// - Checks if current thread owns BSTaskManagerThread[0] or [1] semaphore
/// - If yes: releases the semaphore and signals idle
/// - This lets IO processing continue, freeing memory for retry
///
/// Returns `true` if any semaphore was released, `false` if none were owned.
///
/// # Safety
/// Calls game code. Safe to call from any thread during OOM recovery.
pub unsafe fn release_bstask_sems_if_owned() -> bool {
    let io_manager = match unsafe { *(addr::IO_MANAGER_SINGLETON as *const *mut c_void) } {
        ptr if !ptr.is_null() => ptr,
        _ => {
            log::error!("[BSTASK] IOManager singleton is null, cannot release semaphores");
            return false;
        }
    };

    let get_owner = match unsafe {
        FnPtr::<types::BstaskGetOwnerFn>::from_raw(addr::BSTASK_GET_OWNER as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[BSTASK] FnPtr::from_raw(BSTASK_GET_OWNER) failed: {:?}", e);
            return false;
        }
    };

    let release_sem = match unsafe {
        FnPtr::<types::BstaskReleaseSemFn>::from_raw(addr::BSTASK_RELEASE_SEM as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[BSTASK] FnPtr::from_raw(BSTASK_RELEASE_SEM) failed: {:?}", e);
            return false;
        }
    };

    let signal_idle = match unsafe {
        FnPtr::<types::BstaskSignalIdleFn>::from_raw(addr::BSTASK_SIGNAL_IDLE as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[BSTASK] FnPtr::from_raw(BSTASK_SIGNAL_IDLE) failed: {:?}", e);
            return false;
        }
    };

    let current_tid = libpsycho::os::windows::winapi::get_current_thread_id();
    let mut released = false;

    // Check and release thread 0
    let owner0 = match unsafe { get_owner.as_fn() } {
        Ok(f) => unsafe { f(io_manager, 0) },
        Err(e) => {
            log::error!("[BSTASK] get_owner.as_fn() failed for thread 0: {:?}", e);
            // Don't return early -- thread 1 might still need releasing.
            0  // 0 != current_tid, so thread 0 check will be skipped
        }
    };
    if owner0 == current_tid {
        log::debug!("[BSTASK] Thread 0 semaphore owned by current thread, releasing...");
        match unsafe { release_sem.as_fn() } {
            Ok(f) => unsafe { f(io_manager, 0) },
            Err(e) => log::error!("[BSTASK] release_sem.as_fn() failed for thread 0: {:?}", e),
        }
        match unsafe { signal_idle.as_fn() } {
            Ok(f) => unsafe { f(io_manager, 0) },
            Err(e) => log::error!("[BSTASK] signal_idle.as_fn() failed for thread 0: {:?}", e),
        }
        released = true;
    }

    // Check and release thread 1
    let owner1 = match unsafe { get_owner.as_fn() } {
        Ok(f) => unsafe { f(io_manager, 1) },
        Err(e) => {
            log::error!("[BSTASK] get_owner.as_fn() failed for thread 1: {:?}", e);
            0  // Don't return early -- thread 0 may have been released already
        }
    };
    if owner1 == current_tid {
        log::debug!("[BSTASK] Thread 1 semaphore owned by current thread, releasing...");
        match unsafe { release_sem.as_fn() } {
            Ok(f) => unsafe { f(io_manager, 1) },
            Err(e) => log::error!("[BSTASK] release_sem.as_fn() failed for thread 1: {:?}", e),
        }
        match unsafe { signal_idle.as_fn() } {
            Ok(f) => unsafe { f(io_manager, 1) },
            Err(e) => log::error!("[BSTASK] signal_idle.as_fn() failed for thread 1: {:?}", e),
        }
        released = true;
    }

    released
}

// ---------------------------------------------------------------------------
// OOM recovery -- game stage executor
// ---------------------------------------------------------------------------

/// Raw FFI call to the game's OOM stage executor (FUN_00866a90).
///
/// Returns `(next_stage, give_up)`. Does NOT call mi_collect --
/// use HeapManager::run_oom_stage() which encapsulates collect + logging.
///
/// # Safety
/// Calls game code.
pub unsafe fn run_single_oom_stage(stage: i32) -> (i32, bool) {
    let heap_singleton = addr::HEAP_SINGLETON as *mut c_void;
    let primary_heap = unsafe {
        let p = (heap_singleton as *const u8).add(addr::HEAP_PRIMARY_OFFSET) as *const *mut c_void;
        *p
    };

    let oom_exec = match unsafe {
        FnPtr::<types::OomStageExecFn>::from_raw(addr::OOM_STAGE_EXEC as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[OOM] FnPtr::from_raw(OOM_STAGE_EXEC) failed: {:?}", e);
            return (stage + 1, true);
        }
    };

    let mut done: u8 = 0;
    let next = match unsafe { oom_exec.as_fn() } {
        Ok(f) => unsafe { f(heap_singleton, primary_heap, stage, &mut done) },
        Err(e) => {
            log::error!("[OOM] oom_exec.as_fn() failed at stage {}: {:?}", stage, e);
            return (stage + 1, true);
        }
    };

    (next, done != 0)
}

// ---------------------------------------------------------------------------
// Cell management -- destruction protocol helpers
// ---------------------------------------------------------------------------

/// Set/clear the TLS cell unload flag. Must bracket FindCellToUnload calls.
///
/// value=0: cell unload in progress (suppresses NVSE PLChangeEvent dispatch
///          via TLS+0x298 flag). Without this, NVSE plugins receive events
///          for partially-torn-down actors during cell unload --> crash.
/// value=1: cell unload done (re-enables event dispatch).
///
/// The game's HeapCompact stage 5 and CellTransitionHandler both call this.
/// Safety: must be called on the main thread.
pub unsafe fn set_tls_cleanup_flag(value: u8) {
    let f = match unsafe {
        FnPtr::<types::SetTlsCleanupFlagFn>::from_raw(addr::SET_TLS_CLEANUP_FLAG as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!(
                "[TLS_FLAG] FnPtr::from_raw(SET_TLS_CLEANUP_FLAG) failed: {:?}",
                e
            );
            return;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f(value) },
        Err(e) => log::error!("[TLS_FLAG] as_fn() failed: {:?}", e),
    }
}

/// Process pending cleanup queue after cell unloading.
///
/// This is the critical step vanilla stage 5 does AFTER FindCellToUnload.
/// FindCellToUnload only marks cells and queues async work in the
/// ProcessManager. This function EXECUTES that work -- destroys NiNode
/// hierarchies, releases textures, decrements refcounts, and queues
/// resulting objects into PDD. Without this call, cell unload frees
/// almost nothing.
///
/// flush=0 for normal cleanup after cell unload.
///
/// Safety: must be called on the main thread with GAME_MANAGER valid.
pub unsafe fn process_pending_cleanup(manager: *mut c_void, flush: u8) {
    let f = match unsafe {
        FnPtr::<types::ProcessPendingCleanupFn>::from_raw(
            addr::PROCESS_PENDING_CLEANUP as *mut c_void,
        )
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[PENDING_CLEANUP] FnPtr::from_raw failed: {:?}", e);
            return;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f(manager, flush) },
        Err(e) => log::error!("[PENDING_CLEANUP] as_fn() failed: {:?}", e),
    }
}

/// Try to find and unload one loaded cell. Returns true if a cell was
/// unloaded, false if none remain eligible.
///
/// Safety: must be called on the main thread. Modifies unsynchronized
/// cell arrays in the game manager.
pub unsafe fn find_cell_to_unload(manager: *mut c_void) -> Option<bool> {
    let f = match unsafe {
        FnPtr::<types::FindCellToUnloadFn>::from_raw(addr::FIND_CELL_TO_UNLOAD as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!(
                "[CELL_UNLOAD] FnPtr::from_raw(FIND_CELL_TO_UNLOAD) failed: {:?}",
                e
            );
            return None;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => Some((unsafe { f(manager) } & 0xFF) != 0),
        Err(e) => {
            log::error!("[CELL_UNLOAD] find_cell_to_unload as_fn() failed: {:?}", e);
            None
        }
    }
}

/// Lock the Havok world and invalidate the scene graph for safe destruction.
/// Returns an opaque 12-byte state buffer that must be passed to
/// post_destruction_restore.
///
/// Safety: must be called on the main thread.
pub unsafe fn pre_destruction_setup() -> Option<[u8; 12]> {
    let f = match unsafe {
        FnPtr::<types::PreDestructionSetupFn>::from_raw(addr::PRE_DESTRUCTION_SETUP as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[PRE_DESTRUCTION] FnPtr::from_raw failed: {:?}", e);
            return None;
        }
    };
    let f = match unsafe { f.as_fn() } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[PRE_DESTRUCTION] as_fn() failed: {:?}", e);
            return None;
        }
    };
    let mut state = [0u8; 12];
    unsafe { f(state.as_mut_ptr() as *mut c_void, 1, 1, 1) };
    Some(state)
}

/// Unlock the Havok world and restore state after destruction.
///
/// Safety: must be called after pre_destruction_setup on the main thread.
pub unsafe fn post_destruction_restore(state: &mut [u8; 12]) {
    let f = match unsafe {
        FnPtr::<types::PostDestructionRestoreFn>::from_raw(
            addr::POST_DESTRUCTION_RESTORE as *mut c_void,
        )
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[POST_DESTRUCTION] FnPtr::from_raw failed: {:?}", e);
            return;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f(state.as_mut_ptr() as *mut c_void) },
        Err(e) => log::error!("[POST_DESTRUCTION] as_fn() failed: {:?}", e),
    }
}

/// Run the standard deferred cleanup sequence (PDD + async flush + cleanup).
/// The param byte comes from state[5] of the pre_destruction_setup output.
///
/// Safety: must be called between pre/post_destruction on the main thread.
pub unsafe fn deferred_cleanup_small(param: u8) {
    let f = match unsafe {
        FnPtr::<types::DeferredCleanupSmallFn>::from_raw(
            addr::DEFERRED_CLEANUP_SMALL as *mut c_void,
        )
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[DEFERRED_CLEANUP] FnPtr::from_raw failed: {:?}", e);
            return;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f(param) },
        Err(e) => log::error!("[DEFERRED_CLEANUP] as_fn() failed: {:?}", e),
    }
}

/// Havok garbage collect (FUN_00c459d0).
///
/// force=true forces full collection. This operates on the Havok memory
/// system, NOT the physics world. Safe to call without holding the
/// Havok world lock.
pub unsafe fn havok_gc(force: u8) {
    let f = match unsafe {
        FnPtr::<types::HavokGcFn>::from_raw(addr::HAVOK_GC as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[HAVOK_GC] FnPtr::from_raw failed: {:?}", e);
            return;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f(force) },
        Err(e) => log::error!("[HAVOK_GC] as_fn() failed: {:?}", e),
    }
}

/// PDD purge (FUN_00868d70).
///
/// Purges all deferred destruction queues. try_lock=true means it will
/// skip if the process manager lock is already held.
pub unsafe fn pdd_purge() {
    let f = match unsafe {
        FnPtr::<types::PDDFn>::from_raw(super::super::statics::PDD_ADDR as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[PDD_PURGE] FnPtr::from_raw failed: {:?}", e);
            return;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f(0) }, // blocking purge
        Err(e) => log::error!("[PDD_PURGE] as_fn() failed: {:?}", e),
    }
}

/// Wait for all BSTaskManagerThreads to finish their current iteration.
///
/// Probes each thread's iter_sem (BSTaskManagerThread+0x1C) with a zero-
/// timeout WaitForSingleObject. WAIT_TIMEOUT = thread busy processing a
/// task. Retries up to 500ms per thread (1ms sleep between probes).
///
/// Must be called from the main thread before Stage 5 cell unload.
/// Without this barrier, IO threads and BackgroundCloneThread read
/// freed cell data -> UAF crash (see crash_root_cause_io_thread_uaf.md).
pub unsafe fn wait_for_io_idle() {
    let io_mgr = unsafe { *(addr::IO_MANAGER_SINGLETON as *const *mut c_void) };
    if io_mgr.is_null() {
        return;
    }

    // IOManager+0x50 = pointer to BSTaskManagerThread array
    let threads_ptr = unsafe { *((io_mgr as usize + 0x50) as *const *mut c_void) };
    if threads_ptr.is_null() {
        return;
    }

    // game has 2 BSTaskManagerThreads (indices 0 and 1)
    for idx in 0..2u32 {
        // each BSTaskManagerThread is 0x30 bytes, iter_sem HANDLE at +0x1C
        let thread_base = threads_ptr as usize + idx as usize * 0x30;
        let sem_raw = unsafe { *((thread_base + 0x1C) as *const *mut c_void) };
        if sem_raw.is_null() {
            continue;
        }
        let sem = windows::Win32::Foundation::HANDLE(sem_raw as *mut _);

        let mut waited = 0u32;
        loop {
            match winapi::wait_for_single_object(sem, 0) {
                WaitResult::Signaled => {
                    // thread is idle. restore the signal we consumed.
                    let _ = winapi::release_semaphore(sem, 1);
                    break;
                }
                WaitResult::Timeout => {
                    // thread is busy processing a task
                    waited += 1;
                    if waited >= 500 {
                        log::warn!("[IO_BARRIER] Thread {} still busy after 500ms, proceeding", idx);
                        break;
                    }
                    winapi::sleep(1);
                }
                _ => break, // abandoned or error, don't block
            }
        }

        if waited > 0 {
            log::debug!("[IO_BARRIER] Thread {} idle after {}ms", idx, waited);
        }
    }

    // BackgroundCloneThread: NOT in IOManager, lives in ModelLoader+0x28.
    // Uses same BSTaskManagerThread loop with iter_sem at +0x1C.
    // Clones NiNode/animation trees — crashes if cell data is freed mid-clone.
    let model_loader = unsafe { *(addr::MODEL_LOADER as *const *mut c_void) };
    if !model_loader.is_null() {
        let bg_clone = unsafe { *((model_loader as usize + 0x28) as *const *mut c_void) };
        if !bg_clone.is_null() {
            let sem_raw = unsafe { *((bg_clone as usize + 0x1C) as *const *mut c_void) };
            if !sem_raw.is_null() {
                let sem = windows::Win32::Foundation::HANDLE(sem_raw as *mut _);
                let mut waited = 0u32;
                loop {
                    match winapi::wait_for_single_object(sem, 0) {
                        WaitResult::Signaled => {
                            let _ = winapi::release_semaphore(sem, 1);
                            break;
                        }
                        WaitResult::Timeout => {
                            waited += 1;
                            if waited >= 500 {
                                log::warn!("[IO_BARRIER] bgCloneThread still busy after 500ms");
                                break;
                            }
                            winapi::sleep(1);
                        }
                        _ => break,
                    }
                }
                if waited > 0 {
                    log::debug!("[IO_BARRIER] bgCloneThread idle after {}ms", waited);
                }
            }
        }
    }
}

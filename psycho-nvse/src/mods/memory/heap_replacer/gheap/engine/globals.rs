// Safe wrappers for reading game globals and calling game functions.
//
// Every function here encapsulates the unsafe pointer-from-integer cast
// and volatile/atomic reads. Callers never touch raw addresses directly.
//
// Functions that call game code (OOM stages, FindCellToUnload, etc.) are
// marked unsafe because they have thread/phase preconditions that the
// compiler cannot verify.

use libc::c_void;

use libpsycho::ffi::fnptr::FnPtr;

use super::addr;
use crate::mods::memory::heap_replacer::gheap::types;

// ---------------------------------------------------------------------------
// Game state reads (all safe -- reading from known static addresses)
// ---------------------------------------------------------------------------

// True when the game is in a loading screen (save load, fast travel, coc).
// Simple volatile read. No edge detection overhead on the hot path.
// Loading transitions are logged by the watchdog thread instead.
#[inline]
pub fn is_loading() -> bool {
    unsafe { *(addr::LOADING_FLAG as *const u8) != 0 }
}

// HeapCompact stages. The game's HeapCompact dispatcher at Phase 6
// reads the trigger field and runs stages 0..=N, then resets to 0.
//
// Stage 0: Texture cache flush (NiDX9SourceTextureData purge)
// Stage 1: Geometry cache flush (NiDX9RenderedTexture purge)
// Stage 2: Menu cleanup (InterfaceManager release)
// Stage 3: Havok GC (hkMemorySystem garbage collect)
// Stage 4: PDD purge (ProcessManager lock + full deferred destruction)
// Stage 5: Cell unloading (FindCellToUnload) — DANGEROUS: deadlocks
//          during fast travel and loading screens. Never use from
//          pressure relief.
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

// Read the current HeapCompact trigger value.
pub fn heap_compact_trigger_value() -> u32 {
    unsafe { *(addr::HEAP_COMPACT_TRIGGER as *const u32) }
}

// Signal HeapCompact to run stages 0..=stage on the next frame.
// The game's dispatcher is inclusive: trigger=N runs stages 0, 1, ..., N.
pub fn signal_heap_compact(stage: HeapCompactStage) {
    unsafe {
        let trigger = addr::HEAP_COMPACT_TRIGGER as *mut u32;
        trigger.write_volatile(stage as u32);
    }
}

// PDD skip mask bits. When set, the corresponding queue is SKIPPED
// during full PDD drain (FUN_00868d70). Checked by FUN_00869180.
#[allow(dead_code)]
pub mod pdd_skip {
    pub const NINODE: u32 = 0x10;
    pub const FORM: u32 = 0x08;
    pub const TEXTURE: u32 = 0x04;
    pub const ANIM: u32 = 0x02;
    pub const GENERIC: u32 = 0x01;
    pub const LAST: u32 = 0x20;
}

// Set the PDD skip mask. Queues with matching bits are SKIPPED
// by the next full PDD drain (stage 4). Reset after PDD completes.
pub fn set_pdd_skip_mask(mask: u32) {
    unsafe {
        let p = addr::PDD_SKIP_MASK as *mut u32;
        p.write_volatile(mask);
    }
}

// Read the current PDD skip mask.
pub fn pdd_skip_mask() -> u32 {
    unsafe { *(addr::PDD_SKIP_MASK as *const u32) }
}

// Get the loading state counter as an atomic reference. Incremented to
// suppress NVSE PLChangeEvent dispatch during our destruction protocol.
pub fn loading_state_counter() -> &'static std::sync::atomic::AtomicI32 {
    unsafe { &*(addr::LOADING_STATE_COUNTER as *const std::sync::atomic::AtomicI32) }
}

// Get the game manager pointer (DataHandler). Returns None if null.
// Passed to FindCellToUnload.
pub fn game_manager() -> Option<*mut c_void> {
    let ptr = unsafe { *(addr::GAME_MANAGER as *const *mut c_void) };
    if ptr.is_null() { None } else { Some(ptr) }
}

// Check if BSTaskManagerThread has a pending cell load in progress.
// Returns true if busy (handle != -1), false if idle.
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

// Which PDD queue to query.
pub enum PddQueue {
    NiNode,
    Form,
    Generic,
    Anim,
    Texture,
}

// Read the entry count of a PDD queue (u16 at base + 0x0A).
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

// Check if the current thread is the game's main thread by comparing
// thread IDs through the engine's own GetCurrentThreadId wrapper and
// the main thread ID stored in the TES object.
/// Stored main thread ID. Set ONLY from on_pre_ai (game main loop Phase 7).
/// This is the ONE place we are 100% certain is the main thread.
static MAIN_THREAD_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Set main thread ID. Called ONCE from on_pre_ai (first frame tick).
/// on_pre_ai is a hook inside the game's main loop — guaranteed main thread.
pub fn set_main_thread_id() {
    let tid = libpsycho::os::windows::winapi::get_current_thread_id();
    let prev = MAIN_THREAD_ID.swap(tid, std::sync::atomic::Ordering::Release);
    if prev == 0 {
        log::info!("[THREAD] Main thread ID confirmed from on_pre_ai: {}", tid);
    } else if prev != tid {
        log::error!(
            "[THREAD] Main thread ID changed: {} -> {} (should never happen)",
            prev, tid,
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
// OOM recovery -- game stage executor
// ---------------------------------------------------------------------------

/// Run the game's OOM stages 0-8, then drain pool + collect + try alloc.
///
/// Returns allocated pointer if any stage freed enough, or null.
/// Two-step drain: large blocks first (safe), then all if still OOM.
///
/// # Safety
/// Must be called on the main thread when AI threads are NOT active.
pub unsafe fn run_oom_stages(size: usize) -> *mut c_void {
    use std::ptr::null_mut;

    let heap_singleton = addr::HEAP_SINGLETON as *mut c_void;
    let primary_heap = unsafe {
        let p = (heap_singleton as *const u8).add(addr::HEAP_PRIMARY_OFFSET)
            as *const *mut c_void;
        *p
    };

    let oom_exec = match unsafe {
        FnPtr::<types::OomStageExecFn>::from_raw(addr::OOM_STAGE_EXEC as *mut c_void)
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[OOM_STAGES] FnPtr::from_raw(OOM_STAGE_EXEC) failed: {:?}", e);
            return null_mut();
        }
    };

    let mut stage: i32 = 0;
    let mut done: u8;
    while stage <= 8 {
        done = 0;
        stage = match unsafe { oom_exec.as_fn() } {
            Ok(f) => unsafe { f(heap_singleton, primary_heap, stage, &mut done) },
            Err(e) => {
                log::error!("[OOM_STAGES] oom_exec.as_fn() failed at stage {}: {:?}", stage, e);
                break;
            }
        };
    }

    // Pool drain (large blocks only) + collect + alloc -- kept together
    // to avoid other threads consuming freed VAS between drain and alloc.
    // Small blocks stay on freelists to prevent UAF from stale readers.
    // If this isn't enough, oom_last_resort handles full drain.
    use crate::mods::memory::heap_replacer::gheap::pool;
    unsafe { pool::pool_drain_large(pool::SMALL_BLOCK_THRESHOLD) };
    unsafe { libmimalloc::mi_collect(true) };

    let ptr = unsafe { libmimalloc::mi_malloc_aligned(size, 16) };
    if !ptr.is_null() {
        return ptr;
    }

    null_mut()
}

// ---------------------------------------------------------------------------
// Cell management -- destruction protocol helpers
// ---------------------------------------------------------------------------

// Set/clear the TLS cell unload flag. Must bracket FindCellToUnload calls.
//
// value=0: cell unload in progress (suppresses NVSE PLChangeEvent dispatch
//          via TLS+0x298 flag). Without this, NVSE plugins receive events
//          for partially-torn-down actors during cell unload → crash.
// value=1: cell unload done (re-enables event dispatch).
//
// The game's HeapCompact stage 5 and CellTransitionHandler both call this.
// Safety: must be called on the main thread.
pub unsafe fn set_tls_cleanup_flag(value: u8) {
    let f = match unsafe {
        FnPtr::<types::SetTlsCleanupFlagFn>::from_raw(
            addr::SET_TLS_CLEANUP_FLAG as *mut c_void,
        )
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[TLS_FLAG] FnPtr::from_raw(SET_TLS_CLEANUP_FLAG) failed: {:?}", e);
            return;
        }
    };
    match unsafe { f.as_fn() } {
        Ok(f) => unsafe { f(value) },
        Err(e) => log::error!("[TLS_FLAG] as_fn() failed: {:?}", e),
    }
}

// Try to find and unload one loaded cell. Returns true if a cell was
// unloaded, false if none remain eligible.
//
// Safety: must be called on the main thread. Modifies unsynchronized
// cell arrays in the game manager.
pub unsafe fn find_cell_to_unload(manager: *mut c_void) -> Option<bool> {
    let f = match unsafe {
        FnPtr::<types::FindCellToUnloadFn>::from_raw(
            addr::FIND_CELL_TO_UNLOAD as *mut c_void,
        )
    } {
        Ok(f) => f,
        Err(e) => {
            log::error!("[CELL_UNLOAD] FnPtr::from_raw(FIND_CELL_TO_UNLOAD) failed: {:?}", e);
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

// Lock the Havok world and invalidate the scene graph for safe destruction.
// Returns an opaque 12-byte state buffer that must be passed to
// post_destruction_restore.
//
// Safety: must be called on the main thread.
pub unsafe fn pre_destruction_setup() -> Option<[u8; 12]> {
    let f = match unsafe {
        FnPtr::<types::PreDestructionSetupFn>::from_raw(
            addr::PRE_DESTRUCTION_SETUP as *mut c_void,
        )
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

// Unlock the Havok world and restore state after destruction.
//
// Safety: must be called after pre_destruction_setup on the main thread.
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

// Run the standard deferred cleanup sequence (PDD + async flush + cleanup).
// The param byte comes from state[5] of the pre_destruction_setup output.
//
// Safety: must be called between pre/post_destruction on the main thread.
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

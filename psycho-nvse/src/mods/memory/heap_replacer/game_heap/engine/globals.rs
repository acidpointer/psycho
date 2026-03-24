// Safe wrappers for reading game globals and calling game functions.
//
// Every function here encapsulates the unsafe pointer-from-integer cast
// and volatile/atomic reads. Callers never touch raw addresses directly.
//
// Functions that call game code (OOM stages, FindCellToUnload, etc.) are
// marked unsafe because they have thread/phase preconditions that the
// compiler cannot verify.

use libc::c_void;
use std::ptr::null_mut;

use libpsycho::ffi::fnptr::FnPtr;

use super::addr;
use crate::mods::memory::heap_replacer::game_heap::types;

// ---------------------------------------------------------------------------
// Game state reads (all safe -- reading from known static addresses)
// ---------------------------------------------------------------------------

// True when the game is in a loading screen (save load, fast travel, coc).
pub fn is_loading() -> bool {
    unsafe { *(addr::LOADING_FLAG as *const u8) != 0 }
}

// Read the HeapCompact trigger field. The game's HeapCompact dispatcher
// at Phase 6 reads this value and runs OOM stages 0..=N, then resets to 0.
pub fn heap_compact_trigger_value() -> u32 {
    unsafe { *(addr::HEAP_COMPACT_TRIGGER as *const u32) }
}

// Write to the HeapCompact trigger field. Setting N causes stages 0..=N
// to run on the next frame. Stage 5+ includes cell unloading -- never
// set higher than 4 from pressure relief.
pub fn set_heap_compact_trigger(value: u32) {
    unsafe {
        let trigger = addr::HEAP_COMPACT_TRIGGER as *mut u32;
        trigger.write_volatile(value);
    }
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
pub fn is_main_thread_by_tid() -> bool {
    unsafe {
        let get_tid = match FnPtr::<types::GetThreadIdFn>::from_raw(
            addr::GET_THREAD_ID as *mut c_void,
        ) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let get_main = match FnPtr::<types::GetMainThreadIdFn>::from_raw(
            addr::GET_MAIN_THREAD_ID as *mut c_void,
        ) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let tes = *(addr::TES_OBJECT as *const *mut c_void);
        if tes.is_null() {
            return false;
        }
        match (get_tid.as_fn(), get_main.as_fn()) {
            (Ok(tid), Ok(main)) => tid() == main(tes),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// OOM recovery -- game stage executor
// ---------------------------------------------------------------------------

// Run the game's OOM stages 0-8, then flush quarantine and force-collect.
// Returns a pointer to newly-allocated memory if any stage freed enough,
// or null if all stages exhausted.
//
// Safety: must be called on the main thread when AI threads are NOT active.
// Game stages 4-5 acquire the process manager lock and run FindCellToUnload,
// which race with AI threads on actor and cell data.
pub unsafe fn run_oom_stages(size: usize) -> *mut c_void {
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
        Err(_) => return null_mut(),
    };

    let mut stage: i32 = 0;
    let mut done: u8;
    while stage <= 8 {
        done = 0;
        stage = match unsafe { oom_exec.as_fn() } {
            Ok(f) => unsafe { f(heap_singleton, primary_heap, stage, &mut done) },
            Err(_) => break,
        };
    }

    // After all game stages, flush quarantine and force-collect.
    use crate::mods::memory::heap_replacer::game_heap::delayed_free;
    unsafe { delayed_free::flush_current_thread() };
    unsafe { libmimalloc::mi_collect(true) };

    let ptr = unsafe { libmimalloc::mi_malloc_aligned(size, 16) };
    if !ptr.is_null() {
        return ptr;
    }

    let info = libmimalloc::process_info::MiMallocProcessInfo::get();
    log::error!(
        "[GHEAP] OOM: mi_malloc_aligned({}, 16) failed after all game stages. \
         RSS={}MB, Commit={}MB",
        size,
        info.get_current_rss() / 1024 / 1024,
        info.get_current_commit() / 1024 / 1024,
    );
    null_mut()
}

// ---------------------------------------------------------------------------
// Cell management -- destruction protocol helpers
// ---------------------------------------------------------------------------

// Try to find and unload one loaded cell. Returns true if a cell was
// unloaded, false if none remain eligible.
//
// Safety: must be called on the main thread. Modifies unsynchronized
// cell arrays in the game manager.
pub unsafe fn find_cell_to_unload(manager: *mut c_void) -> Option<bool> {
    let f = unsafe {
        FnPtr::<types::FindCellToUnloadFn>::from_raw(
            addr::FIND_CELL_TO_UNLOAD as *mut c_void,
        )
    }
    .ok()?;
    let f = unsafe { f.as_fn() }.ok()?;
    Some((unsafe { f(manager) } & 0xFF) != 0)
}

// Lock the Havok world and invalidate the scene graph for safe destruction.
// Returns an opaque 12-byte state buffer that must be passed to
// post_destruction_restore.
//
// Safety: must be called on the main thread.
pub unsafe fn pre_destruction_setup() -> Option<[u8; 12]> {
    let f = unsafe {
        FnPtr::<types::PreDestructionSetupFn>::from_raw(
            addr::PRE_DESTRUCTION_SETUP as *mut c_void,
        )
    }
    .ok()?;
    let f = unsafe { f.as_fn() }.ok()?;
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
        Err(_) => return,
    };
    if let Ok(f) = unsafe { f.as_fn() } {
        unsafe { f(state.as_mut_ptr() as *mut c_void) };
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
        Err(_) => return,
    };
    if let Ok(f) = unsafe { f.as_fn() } {
        unsafe { f(param) };
    }
}

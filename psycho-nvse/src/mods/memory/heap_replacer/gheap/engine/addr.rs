//! All Fallout: New Vegas game addresses used by the heap replacer.
//!
//! These are static addresses in the FalloutNV.exe process image,
//! verified via Ghidra decompilation. Organized by engine subsystem.
//!
//! Hook TARGET addresses (where inline hooks are installed) stay in
//! statics.rs -- those are conceptually different from the data and
//! function addresses listed here.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Heap singleton
// ---------------------------------------------------------------------------

// DAT_011F6238: the global MemoryHeap object (2053 xrefs, 1156 functions).
// Our hooked alloc/free/realloc/msize receive this as the thiscall `this`.
pub const HEAP_SINGLETON: usize = 0x011F6238;

// Offset within MemoryHeap to the primary heap pointer (used by OOM stages).
pub const HEAP_PRIMARY_OFFSET: usize = 0x110;

// HeapCompact trigger field (MemoryHeap + 0x134). Writing N here causes
// HeapCompact to run OOM stages 0..=N on the next frame at Phase 6.
pub const HEAP_COMPACT_TRIGGER: usize = 0x011F636C;

// ---------------------------------------------------------------------------
// Game singletons and globals
// ---------------------------------------------------------------------------

// TES object pointer. Used to get the main thread ID via FUN_0044EDB0.
pub const TES_OBJECT: usize = 0x011DEA0C;

// DataHandler / game manager pointer. Passed to FindCellToUnload.
pub const GAME_MANAGER: usize = 0x011DEA10;

// TES singleton pointer. Contains the pending cell load handle at +0x77C.
pub const TES_SINGLETON: usize = 0x011DEA3C;

// Loading flag (u8). Set during save load, fast travel, cell transition.
// Phase 1 of the frame loop refreshes this from IsLoading || IsMenuMode.
pub const LOADING_FLAG: usize = 0x011DEA2B;

// AI running flag (u8). Set to 1 by AI_START, cleared by AI_JOIN.
// This is the game's own flag, separate from our AtomicBool.
pub const AI_ACTIVE_FLAG: usize = 0x011DFA19;

// Loading state counter (i32, treated as AtomicI32). Incremented to suppress
// NVSE PLChangeEvent dispatch during our destruction protocol.
pub const LOADING_STATE_COUNTER: usize = 0x01202D6C;

// ---------------------------------------------------------------------------
// TES singleton offsets
// ---------------------------------------------------------------------------

// Offset from TES_SINGLETON to the pending cell load handle (i32).
// Value of -1 means no cell load pending (BSTaskManagerThread idle).
pub const TES_PENDING_CELL_LOAD_OFFSET: usize = 0x77C;

// ---------------------------------------------------------------------------
// IOManager and BSTaskManagerThread
// ---------------------------------------------------------------------------

// IOManager singleton pointer. Contains the dequeue lock and thread array.
pub const IO_MANAGER_SINGLETON: usize = 0x01202D98;

// Offsets within IOManager:
pub const IO_DEQUEUE_LOCK_OFFSET: usize = 0x20;
pub const IO_DEQUEUE_LOCK_COUNTER_OFFSET: usize = 0x24;
pub const IO_THREAD_ARRAY_OFFSET: usize = 0x50;

// Offsets within each BSTaskManagerThread object:
pub const BST_SEM_COUNT_OFFSET: usize = 0x18;
pub const BST_ITER_SEM_HANDLE_OFFSET: usize = 0x1C;

// ---------------------------------------------------------------------------
// PDD (ProcessDeferredDestruction) queues
//
// Each queue is a structure with a count at +0x0A (u16).
// Used for diagnostic logging under memory pressure.
// ---------------------------------------------------------------------------

pub const PDD_QUEUE_COUNT_OFFSET: usize = 0x0A;

/// PDD skip mask (u32). Bits correspond to queues in full PDD drain.
/// If (DAT_011de804 & queue_bit) != 0, that queue is SKIPPED.
/// Bit 0x10 = NiNode, 0x08 = Form(?), 0x04 = Texture(?),
/// 0x02 = Anim, 0x01 = Generic, 0x20 = last queue.
pub const PDD_SKIP_MASK: usize = 0x011DE804;

pub const NINODE_QUEUE: usize = 0x011DE808;
pub const FORM_QUEUE: usize = 0x011DE828;
pub const GENERIC_QUEUE: usize = 0x011DE874;
pub const ANIM_QUEUE: usize = 0x011DE888;
pub const TEXTURE_QUEUE: usize = 0x011DE910;

// ---------------------------------------------------------------------------
// Game functions -- OOM recovery
// ---------------------------------------------------------------------------

// FUN_00866A90: OOM stage executor. Called with incrementing stage numbers
// (0-8) to free progressively more memory. Thiscall: this = heap singleton.
pub const OOM_STAGE_EXEC: usize = 0x00866A90;

// FUN_0040FC90: GetCurrentThreadId wrapper (cdecl, returns u32).
pub const GET_THREAD_ID: usize = 0x0040FC90;

// FUN_0044EDB0: get main thread ID from TES object (fastcall, TES in ECX).
pub const GET_MAIN_THREAD_ID: usize = 0x0044EDB0;

// ---------------------------------------------------------------------------
// Game functions -- cell management and destruction protocol
// ---------------------------------------------------------------------------

// FUN_00869190: set/clear TLS cell unload flag at TLS+0x298.
// value=0: cell unload in progress (suppresses NVSE PLChangeEvent dispatch).
// value=1: cell unload done (re-enables event dispatch).
// Called by HeapCompact stage 5 and CellTransitionHandler before/after
// FindCellToUnload. Without this, NVSE plugins receive events for
// partially-torn-down actors --> crash.
pub const SET_TLS_CLEANUP_FLAG: usize = 0x00869190;

// FUN_00452490: processes pending cleanup queue after cell unloading.
// Called by vanilla stage 5 after each FindCellToUnload to execute
// the queued async destruction work. Without this, FindCellToUnload
// only marks cells -- the actual object destruction doesn't happen.
pub const PROCESS_PENDING_CLEANUP: usize = 0x00452490;

// FUN_00453A80: finds a loaded cell eligible for eviction (fastcall).
// Returns low byte 1 if a cell was unloaded, 0 if none remain.
pub const FIND_CELL_TO_UNLOAD: usize = 0x00453A80;

// FUN_00878160: pre-destruction setup (hkWorld_Lock + scene graph invalidate).
pub const PRE_DESTRUCTION_SETUP: usize = 0x00878160;

// FUN_00878200: post-destruction restore (hkWorld_Unlock + restore state).
pub const POST_DESTRUCTION_RESTORE: usize = 0x00878200;

// FUN_00878250: combined PDD + async flush + cleanup.
pub const DEFERRED_CLEANUP_SMALL: usize = 0x00878250;

// ---------------------------------------------------------------------------
// Game functions -- IO synchronization
// ---------------------------------------------------------------------------

// FUN_0040FBF0: Bethesda's spin-lock acquire. Non-standard calling convention:
// fastcall with ECX = lock ptr, one stack param (timeout=0), RET 0x4.
pub const SPIN_LOCK_ACQUIRE: usize = 0x0040FBF0;

// ---------------------------------------------------------------------------
// Game functions -- BSTaskManagerThread semaphore management (OOM Stage 8)
// ---------------------------------------------------------------------------

// FUN_00866DA0: get owner thread ID of BSTaskManagerThread semaphore.
// fastcall: ECX = IOManager, EDX = thread index (0 or 1).
// Returns thread ID that owns the semaphore, or 0 if unowned.
pub const BSTASK_GET_OWNER: usize = 0x00866DA0;

// FUN_00866DC0: release BSTaskManagerThread semaphore.
// fastcall: ECX = IOManager, EDX = thread index (0 or 1).
pub const BSTASK_RELEASE_SEM: usize = 0x00866DC0;

// FUN_00866DE0: signal BSTaskManagerThread idle semaphore.
// fastcall: ECX = IOManager, EDX = thread index (0 or 1).
pub const BSTASK_SIGNAL_IDLE: usize = 0x00866DE0;

// ---------------------------------------------------------------------------
// Game functions -- unused but documented (from Ghidra analysis)
// ---------------------------------------------------------------------------

// FUN_00A62030: texture cache pre-reset.
pub const TEXTURE_CACHE_PRE_RESET: usize = 0x00A62030;

// FUN_00713D80: returns the AI thread manager singleton.
pub const GET_AI_THREAD_MANAGER: usize = 0x00713D80;

// FUN_008C7990: AI thread join (also a hook target in statics.rs).
pub const AI_THREAD_JOIN: usize = 0x008C7990;

// ---------------------------------------------------------------------------
// Memory layout constants (not addresses, but offset/range values)
// ---------------------------------------------------------------------------

// RDATA section bounds. Vtable pointers must fall in this range.
pub const RDATA_START: usize = 0x01000000;
pub const RDATA_END: usize = 0x01300000;

// TESForm flags offset and HAVOK_DEATH flag value.
pub const TESFORM_FLAGS_OFFSET: usize = 0x08;
pub const FLAG_HAVOK_DEATH: u32 = 0x10000;

// Ragdoll bone array offset and minimum valid pointer threshold.
pub const RAGDOLL_BONE_ARRAY_OFFSET: usize = 0xA4;
pub const MIN_VALID_PTR: usize = 0x10000;

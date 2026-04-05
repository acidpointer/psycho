//! Function type aliases for game heap operations and internal game functions.
//!
//! All types here correspond to Fallout New Vegas functions identified via
//! Ghidra decompilation. Addresses are in the constants below each type.

#![allow(dead_code)]

use libc::c_void;

// ---- Game heap vtable signatures ----

/// GameHeap::Allocate (thiscall, this = heap singleton).
pub type GameHeapAllocFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> *mut c_void;

/// GameHeap::Reallocate (thiscall).
pub type GameHeapReallocFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, usize) -> *mut c_void;

/// GameHeap::Msize (thiscall).
pub type GameHeapMsizeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> usize;

/// GameHeap::Free (thiscall).
pub type GameHeapFreeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

// ---- Main loop / frame hooks ----

/// FUN_008705d0: post-render maintenance, called at main loop line 486.
pub type MainLoopMaintenanceFn = unsafe extern "thiscall" fn(*mut c_void);

/// FUN_00868850: per-frame queue drain, runs before AI dispatch.
pub type PerFrameQueueDrainFn = unsafe extern "C" fn();

/// FUN_00c79680: skeleton update (fastcall, ragdoll controller in ECX).
/// Reads bone transforms from the ragdoll's bone array at +0xa4.
pub type SkeletonUpdateFn = unsafe extern "fastcall" fn(*mut c_void);

/// FUN_00868d70: ProcessDeferredDestruction (cdecl, 1037 bytes).
/// param=0 blocking, param=1 non-blocking (try-lock).
pub type PDDFn = unsafe extern "C" fn(try_lock: u8);

/// FUN_0086e650: inner per-frame loop (thiscall, 2272 bytes).
/// NVSE hooks the CALL to this function at 0x0086b3e3.
pub type InnerLoopFn = unsafe extern "thiscall" fn(*mut c_void);

/// FUN_00c3dbf0: IOManager main-thread task processing (646 bytes, thiscall).
/// Dequeues and executes completed IO tasks on the main thread.
/// This is Phase 3 of the inner loop -- reads game object data from tasks.
pub type IOManagerProcessFn = unsafe extern "thiscall" fn(*mut c_void);

/// FUN_008c78c0: dispatches AI Linear Task Threads (198 bytes, fastcall).
/// Sets DAT_011dfa19 = 1, kicks 2 AI worker threads.
pub type AIThreadStartFn = unsafe extern "fastcall" fn(mgr: *mut c_void);

/// FUN_008c7990: waits for all AI Linear Task Threads to finish.
pub type AIThreadJoinFn = unsafe extern "fastcall" fn(mgr: *mut c_void);

// ---- Cell transition (engine bug fix) ----

/// FUN_008774a0: orchestrates safe object destruction during cell transitions.
pub type CellTransitionHandlerFn = unsafe extern "thiscall" fn(*mut c_void, u8);

/// Havok world lock/unlock (fastcall, world ptr in ECX).
pub type HkWorldLockFn = unsafe extern "fastcall" fn(*mut c_void);

/// FUN_00448620: cancel stale queued tasks (thiscall, task_queue_mgr in ECX).
pub type CancelStaleTasksFn = unsafe extern "thiscall" fn(*mut c_void, u8);

// ---- Texture cache ----

/// FUN_00a61a60: texture cache hash table find (thiscall).
pub type TextureCacheFindFn =
    unsafe extern "thiscall" fn(*mut c_void, i32, i32, *mut *mut i32) -> u32;

/// FUN_00a5fca0: NiSourceTexture destructor (fastcall).
pub type NiSourceTextureDtorFn = unsafe extern "fastcall" fn(*mut c_void);

// ---- IO task ----

/// FUN_0044dd60: IOTask release, DecRef at this+8, if 0 calls vtable[0](1).
pub type TaskReleaseFn = unsafe extern "fastcall" fn(*mut c_void);

// ---- Pressure relief: cell management and destruction protocol ----

/// FUN_00453a80: finds a loaded exterior cell eligible for eviction.
///
/// Searches buffer cells (manager+0x38) then grid cells (manager+0x3c).
/// Returns low byte 1 if a cell was unloaded, 0 if none remain.
/// Main thread only -- modifies unsynchronized cell arrays.
pub type FindCellToUnloadFn = unsafe extern "fastcall" fn(manager: *mut c_void) -> u32;

/// FUN_00452490: processes pending cleanup queue after cell unloading.
///
/// flush=0 for normal cleanup, flush=1 to force-process regardless of flags.
/// Acquires global lock (DAT_011f4480), runs FUN_00664cd0 + FUN_00a61cd0.
pub type ProcessPendingCleanupFn = unsafe extern "thiscall" fn(this: *mut c_void, flush: u8);

/// FUN_00869190: sets thread-local deferred cleanup flag.
///
/// value=0 disables deferral (objects destroyed immediately on refcount zero).
/// value=1 re-enables deferral (objects queued for batch destruction).
pub type SetTlsCleanupFlagFn = unsafe extern "C" fn(value: u8);

/// FUN_00868d70: processes all deferred destruction queues.
///
/// try_lock=0 for blocking acquisition, try_lock=1 for non-blocking (skips
/// busy queues). Handles queues: 0x10 forms, 0x08 NiNodes, 0x04 textures,
/// 0x02 animations, 0x01 generic refcounted, 0x20 Havok wrappers.
pub type ProcessDeferredDestructionFn = unsafe extern "C" fn(try_lock: u8);

/// FUN_00ad88f0: drains a PPL Concurrency Runtime task group.
pub type TaskGroupDrainFn = unsafe extern "fastcall" fn(task_group: *mut i32) -> u32;

/// FUN_00ad8d10: waits for a PPL task group to complete after draining.
pub type TaskGroupWaitFn = unsafe extern "fastcall" fn(task_group: *mut i32) -> u32;

/// FUN_008324e0: stops or starts Havok physics simulation.
///
/// mode=0 stops simulation and drains all AI physics tasks (safe for PDD).
/// mode=1 restarts simulation.
pub type HavokStopStartFn = unsafe extern "C" fn(mode: u8) -> u8;

/// FUN_00c459d0: flushes async operation queue (IO, audio streaming).
///
/// non_blocking=0 waits for all ops, non_blocking=1 skips if busy.
pub type AsyncQueueFlushFn = unsafe extern "C" fn(non_blocking: u8);

/// FUN_00c459d0: Havok garbage collect (hkMemorySystem::garbageCollect).
/// force=true forces collection, force=0 is incremental.
/// This operates on the Havok memory system, NOT the physics world lock.
/// Safe to call from any thread without holding the Havok world lock.
pub type HavokGcFn = unsafe extern "C" fn(force: u8);

/// FUN_00703980: invalidates scene graph, forces SpeedTree draw list rebuild.
pub type SceneGraphInvalidateFn = unsafe extern "stdcall" fn();

/// FUN_008781e0: sets cell distance threshold for scene graph culling.
pub type SetDistanceThresholdFn = unsafe extern "C" fn(distance: i32);

/// FUN_00878160: pre-destruction setup (hkWorld_Lock + scene graph invalidate).
///
/// After this call, Havok world is locked and SpeedTree draw lists are rebuilt.
/// Safe to run PDD and cell unloading.
pub type PreDestructionSetupFn = unsafe extern "C" fn(
    state: *mut c_void,
    flush_textures: u8,
    param_3: u8,
    save_cell_lock: u8,
);

/// FUN_00878200: post-destruction restore (hkWorld_Unlock + restore state).
pub type PostDestructionRestoreFn = unsafe extern "C" fn(state: *mut c_void);

/// FUN_00878250: combined PDD + async flush + cleanup.
///
/// Runs PDD(1) + FUN_00b5fd60 + blocking async flush + optional BSA cleanup
/// + ProcessPendingCleanup. The standard destruction sequence.
pub type DeferredCleanupSmallFn = unsafe extern "C" fn(param_1: u8);

/// FUN_00713d80: returns the AI thread manager singleton.
pub type GetAIThreadManagerFn = unsafe extern "cdecl" fn() -> *mut c_void;

// ---- OOM recovery ----

/// FUN_00866a90: OOM stage executor, called by GameHeap::Allocate retry loop.
/// Executes escalating cleanup stages 0-8.
pub type OomStageExecFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, i32, *mut u8) -> i32;

/// FUN_0040fc90: GetCurrentThreadId wrapper.
pub type GetThreadIdFn = unsafe extern "C" fn() -> u32;

/// FUN_0044edb0: get main thread ID from TES object (fastcall, TES ptr in ECX).
pub type GetMainThreadIdFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;

// ---- BSTaskManagerThread semaphore management (OOM Stage 8) ----

/// FUN_00866DA0: get owner thread ID of BSTaskManagerThread semaphore.
/// fastcall: ECX = IOManager, EDX = thread index (0 or 1).
/// Returns thread ID that owns the semaphore, or 0 if unowned.
pub type BstaskGetOwnerFn = unsafe extern "fastcall" fn(*mut c_void, u32) -> u32;

/// FUN_00866DC0: release BSTaskManagerThread semaphore.
/// fastcall: ECX = IOManager, EDX = thread index (0 or 1).
pub type BstaskReleaseSemFn = unsafe extern "fastcall" fn(*mut c_void, u32);

/// FUN_00866DE0: signal BSTaskManagerThread idle semaphore.
/// fastcall: ECX = IOManager, EDX = thread index (0 or 1).
pub type BstaskSignalIdleFn = unsafe extern "fastcall" fn(*mut c_void, u32);

// ---- Havok broadphase synchronization ----

pub type HavokAddEntityFn =
    unsafe extern "thiscall" fn(*mut c_void, i32, i32, i32);
pub type HavokCollObjDtorFn =
    unsafe extern "thiscall" fn(*mut c_void, u8);
pub type HavokRaycastFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, i32, u32, u32);

/// hkWorld_Unlock (fastcall, world ptr in ECX).
pub type HkWorldUnlockFn = unsafe extern "fastcall" fn(*mut c_void);

// ---- Actor process synchronization ----

pub type ActorDowngradeInnerFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
pub type AIProcess1Fn = unsafe extern "fastcall" fn(i32);
pub type AIProcess2Fn = unsafe extern "fastcall" fn(i32);
pub type CellMgmtUpdateFn = unsafe extern "thiscall" fn(*mut c_void, f32);
pub type ProcessMgrUpdateFn = unsafe extern "fastcall" fn(i32);

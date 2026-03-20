#![allow(dead_code)]
use libc::c_void;

// Gentlemans. Remember!
// Always use correct calling convention in your hooks.
// If Ghidra says that it is "__thiscall", USE "thiscall", thanks!

/// Game heap function signatures (fastcall convention).
pub type GameHeapAllocateFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> *mut c_void;
pub type GameHeapReallocateFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapMsizeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> usize;
pub type GameHeapFreeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// Scrap heap function signatures (fastcall convention, except GetThreadLocal).
pub type SheapInitFixFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapInitVarFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize);
pub type SheapAllocFn =
    unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
pub type SheapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
pub type SheapPurgeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapGetThreadLocalFn = unsafe extern "C" fn() -> *mut c_void;
pub type SheapMaintenanceFn = unsafe extern "C" fn(*mut c_void);

//(void *this,undefined4 param_1,undefined4 param_2)
pub type SheapRegisterFn = unsafe extern "thiscall" fn(*mut c_void, u32, *mut c_void);

/// Main loop pre-render maintenance function (FUN_008705d0).
pub type MainLoopMaintenanceFn = unsafe extern "thiscall" fn(*mut c_void);

/// CellTransitionHandler (FUN_008774a0, 561 bytes).
///
/// Orchestrates safe object destruction during cell transitions (entering/
/// leaving buildings, fast travel). Called from the main game loop setup
/// (FUN_0086a850) — only 1 caller.
///
/// BUG: The original function calls BLOCKING PDD (FUN_00868d70('\0'))
/// and async flush (FUN_00c459d0('\0')) WITHOUT locking the Havok world.
/// AI threads from the previous frame's post-render signal may still be
/// doing physics raycasting → hkpSimulationIsland crash on AI thread.
///
/// FIX: We hook this function and wrap it with hkWorld_Lock/Unlock +
/// loading state counter to prevent AI physics races and NVSE event
/// dispatch during destruction.
pub type CellTransitionHandlerFn = unsafe extern "thiscall" fn(*mut c_void, u8);

/// Per-frame queue processor (FUN_00868850, line ~802).
///
/// Runs every frame BEFORE AI dispatch and BEFORE render. Processes
/// deferred destruction queues in priority order (0x08 first, then 0x04,
/// 0x02, 0x01, 0x20) with limited batch sizes (10-20 items per queue).
///
/// This is separate from PDD (FUN_00868d70) — it's a gradual per-frame
/// drain that prevents queue buildup during normal gameplay. PDD is the
/// aggressive full-drain called at specific sync points.
///
/// Safe to call multiple times: uses internal try-locks, processes one
/// queue per call, returns when batch limit reached.
pub type PerFrameQueueDrainFn = unsafe extern "C" fn();

/// AI thread join (FUN_008c7990, 72 bytes, fastcall).
///
/// Waits for all AI Linear Task Threads to complete their current work
/// via WaitForSingleObject on per-thread completion semaphores. Called
/// at 0x0086ee4e in the per-frame function, AFTER render and AFTER our
/// main hook. Only called on multi-threaded systems (processor count > 1).
///
/// We hook this to run deferred cell unloading after AI threads are idle.
pub type AIThreadJoinFn = unsafe extern "fastcall" fn(*mut c_void);

/// Texture cache hash table find (FUN_00a61a60, 103 bytes, thiscall).
/// Keys stored inside value objects at +4. With mimalloc, freed values
/// are recycled → NULL → crash at [NULL+4]. Hook adds NULL guard.
pub type TextureCacheFindFn =
    unsafe extern "thiscall" fn(*mut c_void, i32, i32, *mut *mut i32) -> u32;

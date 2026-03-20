//! FFI function signatures for game heap cleanup and cell management.
//!
//! These types correspond to internal Fallout New Vegas functions used by
//! `HeapCompact` (FUN_00866a90) — the game's memory pressure handler.
//! HeapCompact is a multi-stage state machine (stages 0-8) called from
//! `GameHeap::Allocate`'s retry loop when allocation fails:
//!
//! ```text
//! do {
//!     ptr = allocate(size);
//!     if (ptr == NULL) {
//!         stage = HeapCompact(this, allocator, stage, &give_up);
//!     }
//! } while (ptr == NULL);
//! ```
//!
//! Since our mimalloc replacement never fails allocation, HeapCompact is
//! never triggered. We call these functions directly from the pressure
//! relief system to simulate the cleanup that would have happened.
//!
//! # Ghidra analysis source
//!
//! Decompiled from `FalloutNV.exe` (GOG/Steam, unpatched).
//! Full analysis: `analysis/ghidra/output/memory/deep_heap_compact.txt`

#![allow(dead_code)]

use libc::c_void;

/// Finds a loaded exterior cell eligible for eviction and unloads it.
///
/// # Address
///
/// `0x00453A80` — `FUN_00453a80` (824 bytes)
///
/// # Calling convention
///
/// `__fastcall` — `manager` is passed in ECX.
///
/// # Parameters
///
/// - `manager`: Pointer to the TES game manager singleton (`DAT_011dea10`).
///   This is the main game data handler that owns cell arrays:
///   - `manager+0x38`: Array of loaded "buffer" cells (pre-loaded for streaming)
///   - `manager+0x3c`: Grid of active exterior cells (dimensions from `FUN_0084e3a0`)
///
/// # Return value
///
/// - Low byte `1`: A cell was found and successfully unloaded via `FUN_00462290`.
/// - Low byte `0`: No eligible cells remain for eviction.
///
/// # Behavior
///
/// The function searches for an unloadable cell in two phases:
///
/// 1. **Buffer cells** (`manager+0x38`): Iterates backwards through the buffer
///    array. For each non-null entry, checks `FUN_004511e0` (is cell safe to
///    unload?) and `FUN_00557090` (is cell still in use?). If both pass, the
///    cell pointer is taken from the array (slot zeroed) and unloaded.
///
/// 2. **Grid cells** (`manager+0x3c`): If no buffer cell was found, iterates
///    the active cell grid (excluding the current player cell via
///    `FUN_005f36f0`). Same safety checks apply.
///
/// When a cell is found, it is destroyed via `FUN_00462290` (which frees
/// the cell's object references, terrain, pathfinding data, etc.).
///
/// # Thread safety
///
/// **Main thread only.** Modifies cell arrays that are not synchronized
/// with AI worker threads. Must be called between frames (not during
/// rendering or AI physics updates) to avoid use-after-free on
/// `NiTriShape`, `hkBSHeightFieldShape`, and other cell-owned objects.
///
/// # Usage in HeapCompact
///
/// Called in stage 5 (main thread only) in a retry loop:
/// ```text
/// SetTlsCleanupFlag(0);
/// result = FindCellToUnload(manager);
/// if (result & 0xFF) != 0 {
///     stage -= 1;  // retry: try to unload more cells
/// } else {
///     ForceUnloadCell(manager, 1, 0);  // last resort
/// }
/// ProcessPendingCleanup(manager, 0);
/// SetTlsCleanupFlag(1);
/// ProcessDeferredDestruction(1);
/// ```
pub type FindCellToUnloadFn = unsafe extern "fastcall" fn(manager: *mut c_void) -> u32;

/// Processes the pending cleanup queue after cell unloading.
///
/// # Address
///
/// `0x00452490` — `FUN_00452490` (85 bytes)
///
/// # Calling convention
///
/// `__thiscall` — `this` (the TES manager) is passed in ECX.
///
/// # Parameters
///
/// - `this`: TES game manager singleton (`DAT_011dea10`).
/// - `flush`: Controls cleanup aggressiveness:
///   - `0`: Normal cleanup — processes the pending queue if the manager's
///     "needs cleanup" flag (`this+0xB5`) is set, or if the queue is non-empty.
///   - `1` (non-zero): Force flush — always processes the queue regardless of flags.
///
/// # Behavior
///
/// 1. Acquires a global lock (`FUN_00452510` / `DAT_011f4480`).
/// 2. Calls `FUN_00664cd0(1)` — processes one batch of queued operations.
/// 3. Checks `this+0xB5` (needs cleanup flag) OR the `flush` parameter.
/// 4. If cleanup needed: calls `FUN_00a61cd0()` — the main cleanup dispatcher
///    that finalizes freed cell data (BSA references, texture caches, etc.).
/// 5. Calls `FUN_00664cd0(1)` again for a second pass.
/// 6. Releases the global lock.
///
/// The function is guarded by `FUN_00452540()` which checks if the game is
/// in a state where cleanup is allowed (e.g., not during initial load).
///
/// # Thread safety
///
/// **Main thread only.** Uses a global lock internally, but the cleanup
/// dispatcher (`FUN_00a61cd0`) modifies shared game state.
///
/// # Usage in HeapCompact
///
/// Called in stages 0 and 5 with `flush=0` after cell operations:
/// ```text
/// // Stage 0 (reset):
/// ProcessPendingCleanup(manager, 0);
///
/// // Stage 5 (after cell unloading):
/// FindCellToUnload(manager);
/// ProcessPendingCleanup(manager, 0);
/// ```
pub type ProcessPendingCleanupFn = unsafe extern "thiscall" fn(this: *mut c_void, flush: u8);

/// Sets the thread-local "deferred cleanup enabled" flag.
///
/// # Address
///
/// `0x00869190` — `FUN_00869190` (29 bytes)
///
/// # Calling convention
///
/// `__cdecl` — standard C calling convention.
///
/// # Parameters
///
/// - `value`: The flag value to store at `TLS[_tls_index + 0x298]`.
///   - `0`: **Disable** deferred cleanup — objects are destroyed immediately
///     when their reference count reaches zero. Used during HeapCompact
///     cell unloading so freed objects don't pile up in deferred queues.
///   - `1`: **Enable** deferred cleanup (normal mode) — objects are queued
///     for batch destruction later. This is the default game state.
///
/// # Behavior
///
/// Directly writes the value to the current thread's TLS block:
/// ```text
/// *(TLS[_tls_index] + 0x298) = value;
/// ```
///
/// # Thread safety
///
/// Thread-local by nature. Each thread has its own TLS block. Only affects
/// the calling thread's destruction behavior.
///
/// **Important:** The TLS block at `_tls_index` must be initialized by the
/// game's runtime. Calling this from a non-game thread (e.g., our GC thread)
/// will read/write uninitialized memory and crash.
///
/// # Usage in HeapCompact
///
/// Brackets the cell unloading phase in stage 5:
/// ```text
/// SetTlsCleanupFlag(0);   // disable deferral: free objects immediately
/// FindCellToUnload(manager);
/// ProcessPendingCleanup(manager, 0);
/// SetTlsCleanupFlag(1);   // restore deferral
/// ProcessDeferredDestruction(1);
/// ```
pub type SetTlsCleanupFlagFn = unsafe extern "C" fn(value: u8);

/// Processes all deferred destruction queues — destroys queued game objects.
///
/// # Address
///
/// `0x00868D70` — `FUN_00868d70` (1037 bytes)
///
/// # Calling convention
///
/// `__cdecl` — standard C calling convention.
///
/// # Parameters
///
/// - `try_lock`: Lock acquisition mode:
///   - `0`: **Blocking** — acquires locks with `EnterCriticalSection` (waits).
///   - `1`: **Non-blocking** — uses `TryEnterCriticalSection`. If any lock
///     is held by another thread, that destruction queue is skipped.
///     Recommended for pressure relief to avoid deadlocks.
///
/// # Behavior
///
/// This is the game's main batch destruction function. It processes multiple
/// internal queues, each protected by a bitmask check (`FUN_00869180`):
///
/// | Bit  | Queue location  | Object type                     | Destructor        |
/// |------|-----------------|---------------------------------|-------------------|
/// | 0x10 | `DAT_011de828`  | Pending form deletions          | Queue flush       |
/// | 0x08 | `DAT_011de808`  | 3D models / NiNode trees        | `FUN_00418d20(1)` |
/// | 0x04 | `DAT_011de910`  | Texture/material references     | `FUN_00418e00(1)` |
/// | 0x02 | `DAT_011de888`  | Animation / controller tasks    | `FUN_00868ce0`    |
/// | 0x01 | `DAT_011de874`  | Generic ref-counted objects      | vtable `+0x10(1)` |
/// | 0x20 | `DAT_011de924`  | Havok physics wrappers          | `FUN_00401970`    |
///
/// For each queue:
/// 1. Check the bitmask via `FUN_00869180(bit)`.
/// 2. If the bit is clear (queue has work), acquire the global lock
///    (`DAT_011c3b3c` via `FUN_00868250`).
/// 3. Iterate the queue, calling each object's destructor.
/// 4. Clear the queue (`FUN_005e03d0` or `FUN_004dffa0`).
/// 5. Release the lock.
///
/// After all queues: if the TLS deferred flag (`TLS[0x298]`) is non-zero,
/// moves any newly-queued items from staging lists to the main queues for
/// next cycle processing.
///
/// # Thread safety
///
/// Reads `TLS[_tls_index + 0x298]` — **must be called from a game thread**
/// with initialized TLS. The function itself uses locks for queue access,
/// but the destroyed objects (NiNodes, hkShapes, textures) may be referenced
/// by AI worker threads doing raycasting or rendering.
///
/// **Critical:** A cooldown (3+ seconds) between calls is required to give
/// AI threads time to finish operations on objects that will be destroyed.
/// Without cooldown, `hkBSHeightFieldShape` use-after-free crashes occur
/// on AI Linear Task Threads during physics raycasting.
///
/// # Usage in HeapCompact
///
/// Called in stages 4 and 5 with `try_lock=1`:
/// ```text
/// // Stage 5 (after cell unloading):
/// ProcessDeferredDestruction(1);
///
/// // Stage 4 (standalone, with global lock):
/// if TryLock(DAT_011f11a0) {
///     ProcessDeferredDestruction(1);
///     Unlock(DAT_011f11a0);
/// }
/// ```
pub type ProcessDeferredDestructionFn = unsafe extern "C" fn(try_lock: u8);

/// Drains a PPL Concurrency Runtime task group, requesting cancellation/completion
/// of all running tasks.
///
/// # Address
///
/// `0x00AD88F0` — `FUN_00ad88f0` (51 bytes)
///
/// # Calling convention
///
/// `__fastcall` — task group pointer in ECX.
///
/// # Parameters
///
/// - `task_group`: Pointer to a PPL task group handle structure.
///   - If `*task_group == -1`: no-op (group not initialized).
///   - Otherwise: sets `task_group[2] = 2` (cancellation flag) and calls
///     the PPL runtime to drain.
///
/// # Usage in cell transition handler (FUN_008774a0 → FUN_008324e0)
///
/// Called on two task group globals before `ProcessDeferredDestruction`:
/// ```text
/// FUN_00ad88f0(&DAT_011dd5bc);  // drain task group 1
/// FUN_00ad8d10(&DAT_011dd5bc);  // wait for group 1
/// FUN_00ad88f0(&DAT_011dd638);  // drain task group 2
/// FUN_00ad8d10(&DAT_011dd638);  // wait for group 2
/// ```
///
/// These task groups are used by the PPL runtime for background work including
/// AI physics tasks. Draining them ensures no AI thread is actively
/// using physics objects when deferred destruction runs.
pub type TaskGroupDrainFn = unsafe extern "fastcall" fn(task_group: *mut i32) -> u32;

/// Waits for a PPL task group to complete after draining.
///
/// # Address
///
/// `0x00AD8D10` — `FUN_00ad8d10` (66 bytes)
///
/// # Calling convention
///
/// `__fastcall` — task group pointer in ECX.
///
/// # Parameters
///
/// - `task_group`: Same pointer passed to `TaskGroupDrainFn`.
///   Blocks until the task group has fully completed. On success,
///   sets `*task_group = -1` (marks group as not initialized).
pub type TaskGroupWaitFn = unsafe extern "fastcall" fn(task_group: *mut i32) -> u32;

/// Stops or starts the Havok physics simulation and drains AI task queues.
///
/// # Address
///
/// `0x008324E0` — `FUN_008324e0` (184 bytes)
///
/// # Calling convention
///
/// `__cdecl` — standard C calling convention.
///
/// # Parameters
///
/// - `mode`:
///   - `0`: **STOP** — Stops the Havok physics simulation and drains all
///     running physics tasks. After this call returns, no AI thread is
///     touching any `hkBSHeightFieldShape`, collision shape, or physics
///     world data. This makes it safe to call `ProcessDeferredDestruction`.
///     Internally calls:
///     - `FUN_008325a0(0)` — Stops the Havok world simulation
///     - `FUN_00ad88f0(&DAT_011dd5bc)` + `FUN_00ad8d10(&DAT_011dd5bc)` —
///       Drains and waits for physics task queue 1
///     - `FUN_00ad88f0(&DAT_011dd638)` + `FUN_00ad8d10(&DAT_011dd638)` —
///       Drains and waits for physics task queue 2
///     - Sets `DAT_011dd42c = 0` and `DAT_011dd434 = 0`
///   - `1`: **START** — Restarts the Havok simulation (only if
///     `DAT_011dd437 == 0`). Calls `FUN_008325a0(1)` to resume,
///     then `FUN_008300c0(7, NULL, 1000, 0, 0, 0.0, 0)` to initialize
///     the physics step. Sets `DAT_011dd434 = 1`.
///
/// # Guard
///
/// The function is gated by `DAT_011dd436`. If non-zero, the function
/// does nothing and returns `0`. This prevents nested stop/start calls.
///
/// # Thread safety
///
/// **Main thread only.** The stop mode blocks until all AI physics tasks
/// complete — this is the synchronization mechanism that makes deferred
/// destruction safe.
///
/// # Usage in cell transition handler (FUN_008774a0)
///
/// ```text
/// FUN_008324e0(0);               // STOP Havok, drain AI tasks
/// // ... cell unloading, cleanup ...
/// ProcessDeferredDestruction(0); // safe: no AI threads active
/// // ... more cleanup ...
/// // Havok restart happens later in the cell loading process
/// ```
pub type HavokStopStartFn = unsafe extern "C" fn(mode: u8) -> u8;

/// Flushes the async operation queue (IO, audio streaming, etc.).
///
/// # Address
///
/// `0x00C459D0` — `FUN_00c459d0` (172 bytes)
///
/// # Parameters
///
/// - `non_blocking`:
///   - `0`: Blocking — waits for all async operations to complete.
///   - `1`: Non-blocking — uses TryEnterCriticalSection, skips if busy.
///
/// # Why this is needed
///
/// When cells are unloaded, BSAudioManager::soundPlayingObjects still holds
/// NiAVObject pointers from the freed cell. The async queue flush cleans up
/// stale audio/IO references, preventing JIP LN NVSE's PlayingSoundsIterator
/// from accessing freed NiNodes via GetParentRef().
///
/// Called by DeferredCleanup_Small (FUN_00878250) and HeapCompact Stage 3.
pub type AsyncQueueFlushFn = unsafe extern "C" fn(non_blocking: u8);

/// Invalidates the scene graph, forcing SpeedTree draw list rebuild.
///
/// # Address
///
/// `0x00703980` — `FUN_00703980` (45 bytes)
///
/// # Calling convention
///
/// `__stdcall` — no parameters.
///
/// # Behavior
///
/// 1. Calls `FUN_004b7210()` to get the scene graph / renderer object.
///    If NULL, returns immediately (no scene graph active).
/// 2. Calls `FUN_009373f0(scene)` — condition check (likely "is exterior").
///    If false, returns (no invalidation needed for interiors).
/// 3. Calls `FUN_007160b0(scene)` — the actual invalidation:
///    - `FUN_007ffe00()` — setup
///    - `FUN_00586150(scene)` → `vtable+0x1c()` — scene graph cull/update
///      that rebuilds SpeedTree draw lists, clearing stale BSTreeNode pointers
///    - `FUN_007a1670()` — cleanup
///    - `ProcessPendingCleanup(manager, flush=TRUE)` — flushes cleanup queue
///
/// # Why this is needed
///
/// SpeedTree maintains internal draw list caches with raw pointers to
/// BSTreeNode objects that persist across frames. When cells are unloaded,
/// BSTreeNodes are removed from BSTreeManager's maps (via vtable dispatch
/// in TreeMgr_RemoveOnState), but the draw list pointers remain stale.
/// This function forces the draw lists to be rebuilt, making it safe to
/// then process PDD queue 0x08 (NiNode/BSTreeNode destruction).
///
/// # Callers in the game
///
/// Called exclusively by `FUN_00878160` (pre-destruction setup), which is
/// called by the same 5 functions that call `DeferredCleanup_Small`:
/// `FUN_004556d0`, `FUN_005b6cd0`, `FUN_008782b0`, `FUN_0093cdf0`,
/// `FUN_0093d500`. The pattern is always: setup → invalidate → PDD → cleanup.
///
/// # Thread safety
///
/// **Main thread only.** Accesses the scene graph and SpeedTree internals
/// which are not synchronized. Must be called after render completes.
pub type SceneGraphInvalidateFn = unsafe extern "stdcall" fn();

/// Sets the cell distance threshold used by the scene graph cull system.
///
/// # Address
///
/// `0x008781E0` — `FUN_008781e0` (16 bytes)
///
/// # Calling convention
///
/// `__cdecl` — distance value on stack.
///
/// # Parameters
///
/// - `distance`: The distance threshold. The pre-destruction setup passes
///   `0x7FFFFFFF` (INT_MAX) to ensure all cells are considered for culling
///   during scene graph invalidation.
///
/// # Behavior
///
/// Sets the global `DAT_011a95fc` to the given value. This controls
/// the maximum distance at which cells are considered visible during
/// scene graph operations. Setting to INT_MAX ensures the invalidation
/// covers all loaded cells.
///
/// # Usage
///
/// Called by `FUN_00878160` immediately before `FUN_00703980`:
/// ```text
/// FUN_008781e0(0x7fffffff);  // consider all cells
/// FUN_00703980();             // invalidate scene graph
/// ```
pub type SetDistanceThresholdFn = unsafe extern "C" fn(distance: i32);

/// Pre-destruction setup: locks Havok world + invalidates scene graph.
///
/// # Address
///
/// `0x00878160` — `FUN_00878160` (113 bytes)
///
/// # Calling convention
///
/// `__cdecl` — all parameters on stack.
///
/// # Parameters
///
/// - `state`: Pointer to a 12-byte local struct that saves/restores state.
///   The caller allocates this on the stack (e.g. `local_10[12]`).
///   - `state+3`: saved `param_2` (flush textures flag)
///   - `state+4`: saved `param_3`
///   - `state+5`: saved exterior cell manager lock state
///   - `state+8`: saved distance threshold (restored by PostDestruction)
/// - `flush_textures`: If nonzero, calls `FUN_0043c4b0` → `FUN_004a0370`
///   to flush texture/model queues before destruction.
/// - `param_3`: Stored into `state+4`, purpose unclear (passed through).
/// - `save_cell_lock`: If nonzero, saves exterior cell manager lock state
///   via `FUN_00652160`. If zero, sets `state+5 = 0`.
///
/// # Behavior
///
/// 1. `FUN_00c3e310(DAT_01202d98)` — **hkWorld_Lock**: locks the Havok
///    physics world. AI raycasting threads will block until unlock.
/// 2. Saves state into the `state` struct.
/// 3. `FUN_008781e0(0x7fffffff)` — **SetDistanceThreshold(INT_MAX)**: ensures
///    all cells are considered during scene graph cull.
/// 4. `FUN_00703980()` — **SceneGraphInvalidate**: rebuilds SpeedTree draw
///    lists, removing stale BSTreeNode pointers from the cache.
///
/// # Thread safety
///
/// After this call returns, the Havok world is LOCKED. AI raycasting
/// threads are blocked. SpeedTree draw lists are rebuilt. It is now safe
/// to run PDD (all queues) and cell unloading without races.
///
/// # Usage
///
/// ALL 5 normal PDD callers follow this exact pattern:
/// ```text
/// FUN_00878160(local_state, flush, param3, save_lock);  // lock + invalidate
/// FUN_00878250(local_state[local_b]);                   // PDD + async flush + cleanup
/// FUN_00878200(local_state);                            // unlock + restore
/// ```
pub type PreDestructionSetupFn = unsafe extern "C" fn(
    state: *mut c_void,
    flush_textures: u8,
    param_3: u8,
    save_cell_lock: u8,
);

/// Post-destruction restore: unlocks Havok world + restores state.
///
/// # Address
///
/// `0x00878200` — `FUN_00878200` (80 bytes)
///
/// # Parameters
///
/// - `state`: The same state struct passed to `PreDestructionSetupFn`.
///   Restores the distance threshold from `state+8` and unlocks the
///   Havok world via `FUN_00c3e340(DAT_01202d98)`.
///
/// # Behavior
///
/// 1. Restores distance threshold from saved value.
/// 2. Conditionally restores exterior cell manager lock.
/// 3. `FUN_00c3e340(DAT_01202d98)` — **hkWorld_Unlock**: releases the
///    Havok world lock. AI raycasting threads resume.
pub type PostDestructionRestoreFn = unsafe extern "C" fn(state: *mut c_void);

/// Combined PDD + async flush + cleanup (DeferredCleanup_Small).
///
/// # Address
///
/// `0x00878250` — `FUN_00878250` (86 bytes)
///
/// # Parameters
///
/// - `param_1`: Controls whether BSA cache cleanup runs after PDD.
///   From the PreDestruction state struct (`state[local_b]`).
///
/// # Behavior
///
/// 1. `FUN_00868d70(1)` — PDD with try-lock (all queues)
/// 2. `FUN_00b5fd60` — some cleanup
/// 3. `FUN_00c459d0(0)` — blocking async queue flush
/// 4. Optional BSA cache cleanup
/// 5. `FUN_00452490(manager, 0)` — ProcessPendingCleanup
pub type DeferredCleanupSmallFn = unsafe extern "C" fn(param_1: u8);

/// Returns the AI thread manager singleton pointer.
///
/// # Address
///
/// `0x00713D80` — `FUN_00713d80`
///
/// # Return value
///
/// Pointer to the AI thread manager (passed to `AIThreadJoinFn`).
pub type GetAIThreadManagerFn = unsafe extern "cdecl" fn() -> *mut c_void;

/// Waits for all AI Linear Task Threads to complete their current work item.
///
/// # Address
///
/// `0x008C7990` — `FUN_008c7990` (72 bytes)
///
/// # Calling convention
///
/// `__fastcall` — AI thread manager pointer in ECX.
///
/// # Behavior
///
/// Iterates over AI thread pool (2 entries), calling `FUN_008c7490`
/// per thread which does `WaitForSingleObject` on the thread's
/// completion semaphore. Returns when all AI threads are idle.
///
/// The main loop calls this at `0x0086ee4e` AFTER our hook position
/// (`0x0086edf0`). We must call it explicitly before cell unloading.
pub type AIThreadJoinFn = unsafe extern "fastcall" fn(mgr: *mut c_void);

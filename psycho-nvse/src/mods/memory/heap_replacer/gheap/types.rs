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

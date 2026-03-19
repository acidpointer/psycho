# Fallout New Vegas Game Heap — Complete Analysis

This document is a comprehensive reference for the Fallout New Vegas (FNV) game heap
internals, covering the original allocator architecture, thread synchronization model,
cell lifecycle, and the design rationale for the gheap replacement. It is written so
that a developer with zero prior context can understand the entire system without
running Ghidra.

All addresses are for the Steam GOG/retail executable (FalloutNV.exe). Calling
conventions follow MSVC x86 (thiscall = ECX-based, fastcall = ECX+EDX, cdecl =
stack-only).

---

## Glossary

| Term | Full Name | Description |
|------|-----------|-------------|
| **PDD** | ProcessDeferredDestruction | FNV's internal batch object destructor (`0x00868D70`). Instead of destroying game objects immediately (which could crash concurrent systems like rendering or AI), the engine queues them for deferred destruction. PDD then processes these queues at safe, synchronized points in the frame — typically between major subsystem ticks (post-render, during cell transitions, etc.). It maintains 6 internal queues organized by object type (NiNodes, textures, physics wrappers, etc.), each gated by a bitmask and a try-lock so individual queues can be skipped if contended. See [Section 5](#5-processdeferreddestruction) for full details. |
| **PPL** | Parallel Patterns Library | Microsoft's C++ concurrency framework (`Concurrency::task_group`), shipped as part of the MSVC CRT. FNV uses PPL task groups for **audio streaming only** — NOT for AI thread coordination. The two PPL task groups (`DAT_011dd5bc`, `DAT_011dd638`) are drained/waited by the music system (`FUN_008324e0`). AI threads use a separate synchronization model based on Windows Events (`SetEvent`/`WaitForSingleObject`) and Semaphores. This distinction is critical: draining PPL task groups does NOT pause AI threads. See [Section 4](#4-ai-thread-architecture) and [Section 6](#6-cell-transition-handler) for details. |
| **SBM** | Small Block Manager | FNV's pool allocator for small allocations (replaced by mimalloc in psycho-nvse). |
| **TLS** | Thread-Local Storage | Per-thread data accessed via `_tls_index`. FNV stores per-thread flags (deferred cleanup mode, allocator pool index) in TLS slots. |
| **VA** | Virtual Address (space) | The 32-bit process address space. A 32-bit Windows process can address ~2GB (or ~3GB with LAA). OOM occurs when committed memory approaches this limit (~1.8GB in practice). |

---

## Table of Contents

1. [Original Game Heap Architecture](#1-original-game-heap-architecture)
2. [HeapCompact State Machine](#2-heapcompact-state-machine)
3. [Main Loop Frame Flow](#3-main-loop-frame-flow)
4. [AI Thread Architecture](#4-ai-thread-architecture)
5. [ProcessDeferredDestruction](#5-processdeferreddestruction)
6. [Cell Transition Handler](#6-cell-transition-handler)
7. [FindCellToUnload](#7-findcelltounload)
8. [Hook Position Analysis](#8-hook-position-analysis)
9. [Pressure Relief System](#9-pressure-relief-system)
10. [SBM Patches](#10-sbm-patches)
11. [Key Global Addresses](#11-key-global-addresses)
12. [Function Address Map](#12-function-address-map)
13. [Ghidra Analysis Scripts](#13-ghidra-analysis-scripts)
14. [Key Lessons Learned](#14-key-lessons-learned)
15. [SpeedTree Cache Analysis](#15-speedtree-cache-analysis)

---

## 1. Original Game Heap Architecture

FNV uses a singleton allocator called `MemoryHeap`, stored at global address
`DAT_011F6238`. All game-side memory allocations flow through this object.

### Allocator Functions

| Address      | Name                  | Convention | Description                            |
|--------------|-----------------------|------------|----------------------------------------|
| `0x00AA3E40` | `GameHeap::Allocate`  | thiscall   | Main allocator entry point (HOOKED)    |
| `0x00AA4060` | `GameHeap::Free`      | thiscall   | Main free entry point (HOOKED)         |
| `0x00AA4150` | `GameHeap::Realloc1`  | thiscall   | Realloc variant 1 (HOOKED)            |
| `0x00AA4200` | `GameHeap::Realloc2`  | thiscall   | Realloc variant 2 (HOOKED)            |
| `0x00AA44C0` | `GameHeap::Msize`     | thiscall   | Size query (HOOKED)                   |
| `0x00AA4290` | `FallbackAlloc`       | cdecl      | 39 bytes, calls CRT `_malloc()`       |
| `0x00AA42C0` | `FallbackFree`        | cdecl      | 25 bytes, calls CRT `_free()`         |

### Allocation Flow

```
  GameHeap::Allocate(size)
  |
  +-- size <= SBM_THRESHOLD ?
  |     |
  |     YES --> SBM_GetPool(size)            [0x00AA4960, 238 bytes]
  |             |
  |             +-- SBM_ArenaAlloc(pool)     [0x00AA6AA0, 462 bytes, fastcall]
  |             |     |
  |             |     +-- success --> return ptr
  |             |     +-- fail    --> fall through
  |             |
  |     NO --+
  |          |
  |          v
  +-- FallbackAlloc(size)                    [0x00AA4290]
  |     |
  |     +-- _malloc(size)
  |     |     |
  |     |     +-- success --> return ptr
  |     |     +-- fail    --> HeapCompact retry loop
  |     |
  +-- HeapCompact retry loop
        |
        +-- stage 0..8, retry up to 15000x
        +-- if all fail --> fatal error
```

The original allocator has a **500MB budget**. This budget served a dual purpose: it
was both a memory limit AND an implicit thread synchronization barrier (see
Lessons Learned).

When allocation fails, the allocator enters a retry loop calling `HeapCompact`
(`0x00866A90`) with incrementing stage parameters (0 through 8).

### Small Block Manager (SBM)

The SBM is a pool allocator for small allocations. It divides memory into fixed-size
arenas, each serving a specific size class. Key SBM functions:

| Address      | Name              | Convention | Description                    |
|--------------|-------------------|------------|--------------------------------|
| `0x00AA4960` | `SBM_GetPool`     | cdecl      | 238 bytes, finds pool for size |
| `0x00AA6AA0` | `SBM_ArenaAlloc`  | fastcall   | 462 bytes, allocate from arena |
| `0x00AA6C70` | `SBM_ArenaFree`   | thiscall   | 138 bytes, free to arena       |
| `0x00AA45A0` | `FindAllocator`   | thiscall   | 99 bytes, resolve allocator    |
| `0x00AA4610` | `FindAllocator2`  | thiscall   | 137 bytes, resolve allocator   |

Since our replacement (mimalloc) handles all allocations, most SBM functions are
RET-patched (see Section 10).

---

## 2. HeapCompact State Machine

**Address:** `0x00866A90` | **Size:** 602 bytes | **Convention:** thiscall

HeapCompact is a multi-stage state machine invoked when allocation fails. It is
called with an incrementing stage parameter (0 through 8), each stage attempting
progressively more aggressive memory reclamation.

### Stage Diagram

```
  HeapCompact(stage)
  |
  +-- Stage 0: RESET
  |     Set DAT_011de70c = 0
  |     If main thread: ProcessPendingCleanup(manager, 0)
  |
  +-- Stage 1: SBM ARENA TEARDOWN
  |     GetSBMSingleton() -> DeallocateAllArenas()
  |     [RET-patched by us -- no-op]
  |
  +-- Stage 2: CELL/RESOURCE CLEANUP
  |     Enter critical section
  |     Access exterior cell manager via FUN_00652110()
  |     Resource manager cleanup
  |
  +-- Stage 3: ASYNC QUEUE FLUSH
  |     FUN_00c459d0(1) with TryEnterCriticalSection
  |     Non-blocking async operation queue drain
  |
  +-- Stage 4: DEFERRED DESTRUCTION
  |     FUN_00868d70(1) -- ProcessDeferredDestruction
  |     Uses TryLock on DAT_011f11a0
  |     Falls through to Stage 3 if lock fails
  |
  +-- Stage 5: CELL UNLOADING  *** THE KEY STAGE ***
  |     Main thread ONLY
  |     Set TLS[0x298] = 0  (enable immediate cleanup)
  |     Loop: FindCellToUnload(manager)
  |     ProcessPendingCleanup(manager, 0)
  |     Restore TLS[0x298] = 1
  |     ProcessDeferredDestruction(1)
  |
  +-- Stage 6: GLOBAL CLEANUP
  |     GlobalCleanup() -> PurgeUnusedArenas for all SBM pools
  |     [RET-patched by us -- no-op]
  |
  +-- Stage 7: GIVE UP SIGNAL
  |     Main thread: signal that recovery failed
  |
  +-- Stage 8: NON-MAIN THREAD RETRY
        Sleep(1) loop, up to 15000 iterations
        (Waits for main thread to free memory)
```

### Main Thread Detection

HeapCompact determines whether it is running on the main thread by comparing:
```
GetCurrentThreadId() == *(DAT_011dea0c + 0x10)
```
This is critical because Stages 5 and 7 are main-thread-only operations.

### Callers of HeapCompact

| Address      | Context                                     |
|--------------|---------------------------------------------|
| `0x00AA3E40` | `GameHeap::Allocate` — allocation failure    |
| `0x00878080` | Main loop frame maintenance (line 379)       |
| `0x00AA5E30` | Secondary allocator path                     |
| `0x00AA5EC0` | Secondary allocator path                     |

---

## 3. Main Loop Frame Flow

**Address:** `0x0086E650` | **Size:** 2272 bytes | **Convention:** fastcall

The main game loop executes once per frame. The diagram below shows the critical
sequence with frame line numbers from the decompilation. Understanding this flow is
essential for knowing where it is safe to inject cleanup hooks.

```
  FUN_0086e650 (MainLoop) -- ONE FRAME
  |
  |  Line 271: FUN_008782b0()
  |              Conditionally calls ProcessDeferredDestruction(1)
  |              Only when cVar2==3 && !bVar1 (loading state)
  |
  |  Line 273: FUN_0086f940(param_1)        <-- Cell transition handler
  |              Conditionally calls FUN_0093bea0
  |                -> ProcessDeferredDestruction(1)
  |
  |  ... frame setup (lines 274-430) ...
  |
  |  Line 347: FUN_004556d0()
  |              Conditionally calls FUN_00878250
  |                -> ProcessDeferredDestruction(1)
  |
  |  Lines 359-377: Physics stepping, AI setup
  |
  |  Line 379: FUN_00878080()               <-- Calls HeapCompact
  |
  |  ============ AI THREAD LIFECYCLE ============
  |
  |  Line 431-440: AI THREAD DISPATCH + WAIT
  |    Line 437: FUN_008c80e0('\x01')        <-- Signal AI threads to START
  |    Line 439: FUN_008c78c0(puVar11)       <-- Reset AI thread events
  |
  |  ... frame work (lines 442-484) ...
  |
  |  ============ RENDER PHASE ==================
  |
  |  Line 485: FUN_0086ff70(param_1)         <-- Pre-render maintenance
  |
  |  Line 486: FUN_008705d0(param_1)         <-- RENDER/UPDATE
  |             ^^^ OUR HOOK wraps this ^^^
  |             We call original first, THEN run pressure relief
  |
  |  ============ POST-RENDER ===================
  |
  |  Lines 487-510: Post-render
  |    Lines 491-500: Post-render AI signal
  |      Line 497-499: FUN_008c7990()        <-- Signal AI threads (post-render)
  |
  |  Line 502: FUN_0086f6a0()               <-- Post-render cleanup
  |
  |  END FRAME
```

### AI Thread Activity Windows

```
  Frame timeline:
  ─────────────────────────────────────────────────────────────────────>
  |         |              |         |          |           |          |
  setup   line 379       line 431  line 440   line 486    line 497   end
          HeapCompact    AI START  AI WAIT    RENDER      AI POST
                                   DONE       (hook)      RENDER

  AI threads:
  ──────IDLE──────────────┤ACTIVE├──IDLE──────────────────┤ACTIVE?├───
                          ^        ^                      ^
                       dispatch   wait                  post-render
                                  complete              signal
```

AI threads are **IDLE** before line 431 and after line 440 (wait completed).
They **may be ACTIVE** between dispatch (line 431) and our hook position (line 486)
if post-render work is signaled.

---

## 4. AI Thread Architecture

FNV uses a multi-threaded AI system with dedicated "AI Linear Task Threads"
(typically 2 threads, named `[FNV] AI Linear Task Thread 1` and `2`).

**Synchronization model:** AI threads use **Windows Events and Semaphores** —
NOT PPL (Parallel Patterns Library) task groups. The main thread dispatches AI
work via `SetEvent`, and waits for completion via `WaitForSingleObject` on a
semaphore. This is entirely separate from the PPL Concurrency Runtime used for
audio streaming. Draining PPL task groups has zero effect on AI threads.

### AI Thread Main Loop

**Address:** `0x008C7720` | **Size:** 111 bytes | **Convention:** fastcall

```
  AIThread_MainLoop:
  +---------------------------+
  |  while (!shutdown) {      |
  |    WaitForSingleObject(   |
  |      event, INFINITE);    |  <-- blocked here most of the time
  |                           |
  |    if (!shutdown) {       |
  |      vtable[4]();         |  <-- execute task (fn ptr at offset 0x4c)
  |      ReleaseSemaphore(    |
  |        semaphore, 1, 0);  |  <-- signal completion
  |    }                      |
  |  }                        |
  +---------------------------+
```

### Dispatch and Wait

```
  Main Thread                          AI Thread(s)
  ───────────                          ────────────
       |                                    |
       |  AI_Dispatch (0x008C79E0)          |
       |  SetEvent(handles[group][phase])   |
       | ──────────────────────────────────>|
       |                                    |  Wake up
       |                                    |  Execute vtable[4]()
       |                                    |    -> AITask_FrameUpdate
       |                                    |       -> FUN_0096c330 (raycasting)
       |                                    |       -> FUN_0096cb50 (AI processing)
       |  AI_Wait (0x008C7A70)              |
       |  WaitForSingleObject(              |  ReleaseSemaphore()
       |    handles[group][phase])          |
       |<──────────────────────────────────|
       |                                    |  (goes back to wait)
```

### AI Task Execution

**Address:** `0x008C7F50` | **Size:** 346 bytes

The AI task function runs ON the AI thread. Its call chain:

```
  AITask_FrameUpdate (0x008C7F50)
  |
  +-- Dispatch sub-tasks via SetEvent
  +-- Wait for sub-task completion via WaitForSingleObject
  +-- FUN_0096c330 (991 bytes, fastcall)    <-- AI processing + Havok raycasting
  |     |
  |     +-- Accesses hkBSHeightFieldShape objects from loaded cells
  |     +-- Terrain heightfield collision queries
  |     +-- Does NOT call GameHeap::Allocate (verified at depth-2)
  |
  +-- FUN_0096cb50 (fastcall)               <-- More AI processing
```

### AI Coordinator Functions

| Address      | Name                  | Size     | Description                        |
|--------------|-----------------------|----------|------------------------------------|
| `0x008C7DA0` | `AI_MainCoordinator`  | 429 bytes| Main coordinator, dispatch + wait  |
| `0x008C7BD0` | `AI_Dispatcher2`      | 418 bytes| Alternative dispatcher             |
| `0x008C7290` | `AI_CoordinatorCaller`| —        | Calls both coordinators            |

**Critical finding:** AI threads do NOT call `GameHeap::Allocate` during raycasting,
neither directly nor at call-depth 2. This means an allocation-barrier approach for
AI thread synchronization will not work. The AI threads access cell data (heightfield
shapes) directly from memory without going through the allocator.

---

## 5. ProcessDeferredDestruction (PDD)

**Address:** `0x00868D70` | **Size:** 1037 bytes | **Convention:** cdecl

ProcessDeferredDestruction (PDD) is FNV's deferred object destruction system. The
engine cannot destroy game objects immediately when their refcount reaches zero,
because multiple subsystems may hold live pointers to the same object concurrently:

- The **render pipeline** caches pointers to NiNode scene graph nodes (including
  BSTreeNode for SpeedTree vegetation) in draw lists that persist across frames.
- **AI Linear Task Threads** hold pointers to Havok collision shapes
  (hkBSHeightFieldShape) for raycasting during pathfinding.
- The **IO Manager** asynchronously loads textures via a lock-free queue and holds
  pointers to QueuedTexture objects until loading completes.

To avoid use-after-free crashes, the engine queues objects for destruction instead
of freeing them immediately. PDD then processes these queues at carefully chosen
synchronization points — typically between major subsystem ticks where the engine
can guarantee no other thread holds references to the queued objects.

PDD uses a **try-lock** model: with `param_1 = 1` (non-blocking mode), it calls
`TryEnterCriticalSection` on a global lock (`DAT_011de8e0`). If the lock is held
(e.g., by another thread already running PDD), the entire call is skipped. This
prevents deadlocks but means PDD may silently skip a cycle.

A **reentrancy guard** (`DAT_011de958`) prevents recursive PDD calls — if PDD is
already running, a nested call returns immediately.

The **TLS deferred flag** (`_tls_index + 0x298`) controls whether objects are
queued or destroyed immediately. When flag=1 (default), freeing an object with
refcount=0 enqueues it for PDD. When flag=0, the object is destroyed inline.
HeapCompact Stage 5 sets this to 0 for immediate cleanup; we must keep it at 1.

### Destruction Queues

```
  ProcessDeferredDestruction(param)
  |
  |  param=0: BLOCKING   (EnterCriticalSection on DAT_011f11a0)
  |  param=1: NON-BLOCKING (TryEnterCriticalSection, skip if busy)
  |
  +-- Check TLS[_tls_index + 0x298] -- must be game thread with initialized TLS
  |
  +-- Bit 0x10: DAT_011de828 -- Pending form deletions
  |     Action: Queue flush
  |
  +-- Bit 0x08: DAT_011de808 -- 3D models / NiNode trees
  |     Action: FUN_00418d20(1)
  |
  +-- Bit 0x04: DAT_011de910 -- Texture/material refs
  |     Action: FUN_00418e00(1)
  |
  +-- Bit 0x02: DAT_011de888 -- Animation/controller tasks
  |     Action: FUN_00868ce0
  |
  +-- Bit 0x01: DAT_011de874 -- Generic ref-counted objects
  |     Action: vtable+0x10(1)
  |
  +-- Bit 0x20: DAT_011de924 -- Havok physics wrappers
        Action: FUN_00401970
```

### Callers (6 total)

| Address      | Name / Context                           | Size       | Notes                        |
|--------------|------------------------------------------|------------|------------------------------|
| `0x0045DFE0` | Big update function                      | 8357 bytes | Called from FUN_00450770     |
| `0x0084C5A0` | Savegame/load related                    | 1572 bytes | Called from FUN_0084be40     |
| `0x00866A90` | HeapCompact (stages 4 and 5)             | 602 bytes  | Memory pressure recovery     |
| `0x008774A0` | CellTransitionHandler                    | 561 bytes  | Cell transition cleanup      |
| `0x00878250` | DeferredCleanup_Small                    | 86 bytes   | 5 callers (see below)        |
| `0x0093BEA0` | CellTransition_Conditional               | 832 bytes  | Cell transition path         |

Callers of `DeferredCleanup_Small` (0x00878250):
- `FUN_004556d0`, `FUN_008782b0`, `FUN_0093cdf0`, `FUN_0093d500`, `FUN_005b6cd0`

### Queue Gate Function

**Address:** `0x00869180` | **Size:** 16 bytes | **Convention:** cdecl

```c
// Returns nonzero if the queue should be SKIPPED
uint FUN_00869180(uint flag) {
    return (DAT_011de804 & flag) != 0;
}
```

The global `DAT_011de804` is a bitmask. If a queue's bit is set, that queue is
skipped during PDD. We use this to implement selective PDD by writing to
`0x011DE804` before calling PDD, then restoring the original value after.

### Queue Lock Functions

Each queue has a try-lock guard (`FUN_00868250` calls `FUN_008691b0`) that
determines whether the queue can be processed. With `param_1 = 1` (non-blocking),
PDD calls `TryEnterCriticalSection` — if the lock is held by another thread, that
queue is silently skipped.

Queue 0x10 (forms) uses a separate lock: `FUN_0078d1f0` → `FUN_0078d200(DAT_011f4480)`.

### Selective PDD: Queue Safety Analysis (from hook at 0x008705D0)

Each queue was tested independently from our post-render hook position. Results:

| Bit  | Queue Address  | Destructor      | Content                 | Safety     | Crash Evidence                                    |
|------|----------------|-----------------|-------------------------|------------|---------------------------------------------------|
| 0x10 | DAT_011de828   | Queue flush     | Pending form deletions  | **SAFE**   | No crash observed                                 |
| 0x08 | DAT_011de808   | FUN_00418d20(1) | NiNode / BSTreeNode     | **UNSAFE** | BSTreeNode RefCount:0, SpeedTree cached draw list |
| 0x04 | DAT_011de910   | FUN_00418e00(1) | Texture/material refs   | **UNSAFE** | QueuedTexture NULL vtable, async IO race          |
| 0x02 | DAT_011de888   | FUN_00868ce0    | Animation/controller    | **SAFE**   | Just clears bit 0x40000000, no destruction        |
| 0x01 | DAT_011de874   | vtable+0x10(1)  | Generic ref-counted     | **UNSAFE** | Unknown object types, caused early crash          |
| 0x20 | DAT_011de924   | FUN_00401970    | Havok physics wrappers  | **UNSAFE** | hkBSHeightFieldShape UAF on AI thread             |

### Why Each Unsafe Queue Crashes

**Queue 0x08 (NiNodes/BSTreeNode):**
SpeedTree maintains a global model cache (`BSTreeManager` at `DAT_011d5c48`) with
persistent draw list pointers. These point to BSTreeNode objects across frames.
Destroying a BSTreeNode via PDD leaves stale pointers in the cache → next frame's
render dereferences freed memory → crash with `BSTreeNode RefCount: 0`.

**Queue 0x20 (Havok physics wrappers):**
AI Linear Task Threads perform raycasting via `FUN_0096c330` → `hkBSHeightFieldShape`.
These threads run concurrently with the main thread. Destroying physics wrappers in
PDD frees `hkBSHeightFieldShape` objects while AI threads hold live references →
crash `EXCEPTION_ACCESS_VIOLATION` on AI thread.

**Queue 0x04 (Textures/materials):**
The game's `IOManager` loads textures asynchronously via `LockFreeQueue<IOTask>`.
Destroying texture references in PDD invalidates objects the IO system is actively
processing → NULL vtable call (`eip = 0x00000000`), `QueuedTexture` on stack.

**Queue 0x01 (Generic ref-counted):**
Calls `vtable+0x10(1)` (virtual destructor) on arbitrary ref-counted objects. This
can include any NiRefObject subclass. Combined with other unsafe operations, caused
early crashes during aggressive testing.

### Current Selective PDD Strategy

Skip only `0x08` (NiNode queue). This is the **minimum viable skip** that prevents
the BSTreeNode crash while still processing physics, textures, animations, and
forms. The broader skip mask (0x08 | 0x20 | 0x04) was tested but caused FASTER
crashes, likely because the game's own PDD logic expects to find objects in those
queues and crashes when they're missing from expected state.

```rust
unsafe {
    let skip_mask = 0x011DE804 as *mut u32;
    let original = skip_mask.read_volatile();
    skip_mask.write_volatile(original | 0x08);  // skip NiNode queue only
    process_deferred(1);  // non-blocking
    skip_mask.write_volatile(original);
}
```

### TLS Deferred Cleanup Flag

**Critical:** The TLS flag at `_tls_index + 0x298` controls whether object
destruction is immediate (flag=0) or deferred (flag=1).

- **Flag = 0 (immediate):** When an object's refcount drops to 0 during
  `FindCellToUnload`, it is destroyed immediately — including BSTreeNodes.
  This bypasses the deferred queue entirely, so our PDD queue skip cannot
  protect against the SpeedTree crash.
- **Flag = 1 (deferred, default):** Objects go into deferred queues when their
  refcount hits 0. Our selective PDD then processes all queues except 0x08.

We MUST keep TLS flag at 1. Setting it to 0 was the root cause of BSTreeNode
crashes even when queue 0x08 was skipped in PDD.

### mi_collect Safety

- `mi_collect(false)` — thread-local collection only. Safe from any thread.
- `mi_collect(true)` — forces cross-thread segment purge. **UNSAFE** — races
  with AI thread allocations, causes `EXCEPTION_ACCESS_VIOLATION` inside
  `psycho_nvse` on AI Linear Task Thread.

---

## 6. Cell Transition Handler

**Address:** `0x008774A0` | **Size:** 561 bytes | **Convention:** thiscall

This function orchestrates safe object destruction during cell transitions (e.g.,
entering/leaving a building, fast travel). It is the canonical example of how the
game coordinates cleanup across subsystems.

### Sequence Diagram

```
  CellTransitionHandler (0x008774a0)
  |
  |  1. Save state
  |     uVar1 = FUN_004f1540(this)           // Read state byte at this+4
  |     FUN_004f15a0(this, 0)                // Set state = 0
  |
  |  2. Wait for player ready
  |     FUN_00877700(DAT_011dea3c)           // Wait with 1000ms timeout
  |       -> FUN_00ad8da0(player+0x77c, 1000)
  |
  |  3. Set render flags
  |     bVar2 = FUN_007d6bd0(DAT_011ddf38, 0) // Set bit 0 in flags at +0x244
  |
  |  4. Pre-cleanup
  |     FUN_00453a70()                        // Generic cleanup
  |     FUN_00ad8780()                        // No-op (empty function)
  |
  |  5. Stop MUSIC system (NOT Havok!)
  |     FUN_008324e0(0)                       // MusicStopStart(0)
  |       -> FUN_008325a0(0): sets DAT_011dd313 = 0
  |       -> Drains PPL task queues:
  |            DAT_011dd5bc (audio streaming group 1)
  |            DAT_011dd638 (audio streaming group 2)
  |
  |  6. Process player state (conditional logic)
  |
  |  7. Force unload cell
  |     FUN_004539a0(DAT_011dea10, 0, 0)     // ForceUnloadCell
  |     FUN_007037c0(DAT_011dea10, 0x7fffffff) // Cell operation
  |     FUN_0061cc40(DAT_011dea10, 0x7fffffff) // Cell operation
  |
  |  8. BLOCKING deferred destruction
  |     FUN_00868d70(0)                       // ProcessDeferredDestruction(BLOCKING)
  |
  |  9. BLOCKING async queue flush
  |     FUN_00c459d0(0)                       // Async queue flush (BLOCKING)
  |
  | 10. Restore state
  |     FUN_007d6bd0(DAT_011ddf38, bVar2)     // Restore render flags
  |     FUN_008776e0(DAT_011dea0c)            // Post-cleanup
  |     FUN_004f15a0(DAT_011dea0c, uVar1)    // Restore state byte
```

### Music System Misidentification

**IMPORTANT:** `FUN_008324e0` is the MUSIC system, NOT Havok physics. This was
a significant source of confusion during analysis:

- `FUN_008325a0(0/1)` simply sets/clears `DAT_011dd313` (music running flag)
- `FUN_008300c0` (944 bytes) is the music crossfade/step function
- The two PPL task queues (`DAT_011dd5bc`, `DAT_011dd638`) are audio streaming
  task groups, NOT AI physics task groups
- Calling `FUN_008324e0(1)` to "restart" triggers `FUN_008300c0(7, NULL, 1000, ...)`
  which crashes on the NULL music path argument

---

## 7. FindCellToUnload

**Address:** `0x00453A80` | **Size:** 824 bytes | **Convention:** fastcall

Parameter: TES manager singleton (`DAT_011dea10`).

This function searches for an unloadable cell and destroys it. It is used by
HeapCompact Stage 5 and by our pressure relief system.

### Search Algorithm

```
  FindCellToUnload(manager)
  |
  |  PHASE 1: Buffer cells (manager+0x38)
  |  +-----------------------------------------+
  |  | Iterate BACKWARDS through buffer array  |
  |  | For each cell:                          |
  |  |   Check FUN_004511e0(cell) -- loadable? |
  |  |   Check FUN_00557090(cell) -- in use?   |
  |  |   If both pass -> candidate             |
  |  +-----------------------------------------+
  |
  |  PHASE 2: Grid cells (manager+0x3c)
  |  +-----------------------------------------+
  |  | Iterate through active cell grid        |
  |  | EXCLUDE current player cell             |
  |  | Same checks as Phase 1                  |
  |  +-----------------------------------------+
  |
  |  If candidate found:
  |    FUN_00462290(cell)   -- DestroyCell
  |    return 1 (low byte)
  |
  |  If no candidate:
  |    return 0
```

### What DestroyCell Frees

When a cell is destroyed, ALL associated data is freed:

```
  Cell Destruction (FUN_00462290)
  |
  +-- BSTreeNodes           (SpeedTree vegetation geometry)
  +-- NiTriShapes           (static mesh render data)
  +-- hkBSHeightFieldShape  (terrain heightfield collision)
  +-- bhkCollisionObject    (physics collision bodies)
  +-- Landscape textures
  +-- Placed object references
  +-- Navmesh data
```

### Safety Constraints

FindCellToUnload is safe to call **post-render** because:

1. SpeedTree draw lists have been consumed by the render pass
2. Physics objects are queued for deferred destruction (not immediately freed
   from the Havok world)
3. AI threads do not directly index into the cell buffer/grid arrays

It is NOT safe pre-render because SpeedTree caches raw pointers to BSTreeNode
objects in its draw lists, and destroying a cell invalidates those pointers.

---

## 8. Hook Position Analysis

We tested every viable hook position in the main loop. This table summarizes
the results:

```
  Frame Timeline with Hook Positions Tested:

  ──[setup]──[line 273]──[line 379]──[line 431]──[line 440]──[line 485]──[line 486]──[line 497]──
              ^                       ^            ^           ^           ^
              |                       AI START     AI DONE     |           |
              |                                                |           |
              FUN_0086f940                              FUN_0086ff70  FUN_008705d0
              (pre-AI)                                  (pre-render) (POST-render)
              CRASH: BSTreeNode                         CRASH:       SAFE (chosen)
                                                        BSTreeNode
```

| Position         | Address      | Frame Line | Result                                       |
|------------------|--------------|------------|----------------------------------------------|
| `FUN_0086f940`   | `0x0086F940` | 273        | **CRASH** -- BSTreeNode use-after-free. Render pipeline uses cached tree draw lists from freed cells. |
| `FUN_0086ff70`   | `0x0086FF70` | 485        | **CRASH** -- BSTreeNode use-after-free. Same issue; render has not yet consumed tree data. |
| `FUN_008705d0`   | `0x008705D0` | 486        | **SAFE** for cell unloading. Render done, trees consumed. Only crash is OOM (32-bit VA limit). |

### Crash Types Encountered

```
  +----------------------------+-------------------------------------------+------------------+
  | Crash Type                 | Cause                                     | Hook Position    |
  +----------------------------+-------------------------------------------+------------------+
  | AI thread crash            | ProcessDeferredDestruction destroys       | ANY position     |
  | (hkBSHeightFieldShape)     | heightfields while AI threads raycast     | (PDD queue 0x20) |
  | EXCEPTION_ACCESS_VIOLATION | against them. AI threads hold persistent  |                  |
  |                            | references, no safe sync point exists.    |                  |
  +----------------------------+-------------------------------------------+------------------+
  | Render crash               | FindCellToUnload destroys BSTreeNodes     | Pre-render       |
  | (BSTreeNode UAF)           | while SpeedTree has cached draw list      | (0x0086F940,     |
  |                            | pointers to them                          |  0x0086FF70)     |
  +----------------------------+-------------------------------------------+------------------+
  | SpeedTree post-render      | PDD queue 0x08 destroys BSTreeNodes.      | Post-render      |
  | (BSTreeNode RefCount:0)    | BSTreeManager global cache holds cross-   | (PDD queue 0x08) |
  | C0000417                   | frame references. Also triggered by TLS   |                  |
  |                            | flag=0 causing immediate destruction      |                  |
  |                            | during FindCellToUnload.                  |                  |
  +----------------------------+-------------------------------------------+------------------+
  | Texture IO race            | PDD queue 0x04 destroys texture refs      | Post-render      |
  | (NULL vtable, eip=0)       | while IOManager async loads textures      | (PDD queue 0x04) |
  | QueuedTexture on stack     | via LockFreeQueue<IOTask>.                |                  |
  +----------------------------+-------------------------------------------+------------------+
  | mi_collect(true) race      | Forced cross-thread segment purge races   | Post-render      |
  | EXCEPTION_ACCESS_VIOLATION | with AI thread allocations. Crash inside  | (mi_collect)     |
  | inside psycho_nvse DLL     | psycho_nvse on AI Linear Task Thread.     |                  |
  +----------------------------+-------------------------------------------+------------------+
  | OOM crash                  | 32-bit VA space exhaustion at ~1.8GB      | Post-render      |
  | (fatal in exception        | commit. Without PDD, deferred objects     | (no PDD)         |
  | handler)                   | pile up unboundedly. With selective PDD   |                  |
  |                            | (skip 0x08), commit climbs slowly as      |                  |
  |                            | NiNode queue accumulates.                 |                  |
  +----------------------------+-------------------------------------------+------------------+
  | Aggressive cell unload     | Reducing cooldown (<500ms) or increasing  | Post-render      |
  | AI crash                   | max cells causes AI threads to access     | (aggressive      |
  | (hkBSHeightFieldShape)     | entities in cells being unloaded. AI      |  tuning)         |
  |                            | threads hold refs to cell objects beyond   |                  |
  |                            | the frame boundary.                       |                  |
  +----------------------------+-------------------------------------------+------------------+
  | Music broken               | FUN_008324e0(0) stops music system.       | N/A              |
  |                            | FUN_008324e0(1) crashes on NULL music     | (misidentified   |
  |                            | path in FUN_008300c0                      |  function)       |
  +----------------------------+-------------------------------------------+------------------+
```

---

## 9. Pressure Relief System

Our replacement heap uses mimalloc as the backing allocator and implements a
pressure relief system to prevent 32-bit virtual address space exhaustion.

### Configuration

| Parameter              | Value    | Rationale                                        |
|------------------------|----------|--------------------------------------------------|
| `THRESHOLD`            | 700 MB   | Commit size that triggers pressure check         |
| `MAX_CELLS_PER_CYCLE`  | 20       | Maximum cells unloaded per relief cycle          |
| `COOLDOWN_MS`          | 2000 ms  | Minimum time between relief cycles               |
| Check interval         | 50,000   | Allocations between pressure checks (thread-local counter) |

### Why Thread-Local Counters

Per-allocation atomic counters (e.g., `AtomicU32::fetch_add`) cause **5-7 FPS
regression** from CPU cache line bouncing between cores. Thread-local counters
have zero contention overhead.

### Hook Architecture

```
  Original frame:
    ...
    Line 486: FUN_008705d0(param_1)   -- RenderUpdate
    ...

  Hooked frame:
    ...
    Line 486: OUR_HOOK(param_1)
                |
                +-- Call original FUN_008705d0(param_1)  -- render first
                |
                +-- Check thread-local allocation counter
                |     counter < 50,000? --> return (skip check)
                |     counter >= 50,000? --> reset, proceed
                |
                +-- Query process commit size
                |     commit < 700MB? --> return (no pressure)
                |
                +-- Check cooldown timer
                |     elapsed < 2000ms? --> return (too soon)
                |
                +-- === PRESSURE RELIEF ===
                |
                +-- Loop (up to 20 iterations):
                |     FindCellToUnload(manager)
                |     if returned 0: break        -- no more cells
                |
                +-- ProcessPendingCleanup(manager, 0)
                |
                +-- Selective PDD:
                |     Set DAT_011de804 |= 0x08    -- skip NiNode queue
                |     ProcessDeferredDestruction(1) -- non-blocking
                |     Restore DAT_011de804         -- restore original mask
                |
                +-- mi_collect(false)             -- nudge mimalloc to decommit
    ...
```

**Key changes from earlier versions:**

1. **No TLS flag manipulation.** Setting `SetTlsCleanupFlag(0)` caused immediate
   BSTreeNode destruction during `FindCellToUnload`, bypassing deferred queues.
2. **Selective PDD with skip mask.** We call PDD but skip queue 0x08 (NiNodes)
   via `DAT_011de804`. All other queues are processed by PDD.
3. **Only `mi_collect(false)`.** Never `mi_collect(true)` — it races with AI threads.

### Game's Own PDD Call Sites

The game also calls PDD at internally-synchronized points:

- Line 271-273: `FUN_008782b0` -> `ProcessDeferredDestruction(1)` (loading state)
- Line 273: `FUN_0086f940` -> `FUN_0093bea0` -> `ProcessDeferredDestruction(1)`
  (cell transitions)
- Line 347: `FUN_004556d0` -> `FUN_00878250` -> `ProcessDeferredDestruction(1)`

These internal calls process ALL queues (including 0x08) because they run at
points where the SpeedTree cache has been properly invalidated.

### Remaining Issue: OOM Under Extreme Stress

During extreme stress testing (flying across map at maximum speed), commit
climbs to ~1.7-1.8GB and eventually OOMs. The NiNode queue (0x08) accumulates
because we skip it. Cell unloading alone cannot keep up with loading rate.

Observed memory behavior during stress:
- Idle gameplay: commit stable ~760MB
- Normal movement: ~1.0-1.1GB, pressure relief keeps up
- Max-speed flying: commit climbs ~30-50MB per relief cycle despite unloading
  11 cells per cycle. Eventually hits 32-bit VA limit (~1.8GB).

### Tuning Experiments and Results

| Config (threshold/cooldown/cells) | PDD                  | Result                        |
|-----------------------------------|----------------------|-------------------------------|
| 700MB / 2000ms / 20              | None                 | OOM at ~1.8GB after ~3min     |
| 700MB / 2000ms / 20              | Skip 0x08 only       | Best stability, OOM ~1.7GB    |
| 700MB / 2000ms / 20              | Full (all queues)    | AI thread crash (hkBSHeight)  |
| 700MB / 2000ms / 20              | Skip 0x08+0x20+0x04  | FASTER crash (unknown cause)  |
| 512MB / 500ms / 30               | Skip 0x08+0x20       | AI crash (too aggressive)     |
| 512MB / 500ms / 30               | Skip 0x08+0x20+0x04  | Texture NULL vtable crash     |

### mimalloc Configuration

| Parameter        | Value  | Rationale                                     |
|------------------|--------|-----------------------------------------------|
| Reserve          | 512 MB | Pre-reserved VA space                         |
| `purge_delay`    | 100 ms | How quickly freed pages are decommitted       |
| `retry_on_oom`   | 0      | Do not retry on OOM (let pressure relief work)|
| `eager_commit`   | 0      | Do not eagerly commit reserved pages          |

---

## 10. SBM Patches

Since mimalloc handles all allocations, the Small Block Manager must be disabled.
However, some SBM functions are still needed for pre-hook pointer cleanup.

### RET-Patched (Disabled)

These functions are patched with a `RET` instruction at their entry point:

| Address      | Name                   | Purpose                                |
|--------------|------------------------|----------------------------------------|
| `0x00AA6840` | SBM statistics reset   | SBM accounting (patched 2x, duplicate) |
| `0x00866770` | SBM config table init  | Size class configuration               |
| `0x00866E00` | SBM-related init       | SBM subsystem initialization           |
| `0x00866D10` | Get SBM singleton      | SBM singleton accessor                 |
| `0x00AA7030` | GlobalCleanup          | PurgeUnusedArenas for all pools         |
| `0x00AA5C80` | DeallocateAllArenas    | Bulk arena deallocation                |
| `0x00AA58D0` | Sheap SBM cleanup      | Scrap heap SBM interaction             |

### Left Alive (Needed for Pre-Hook Pointer Cleanup)

| Address      | Name                  | Size      | Why Needed                         |
|--------------|-----------------------|-----------|------------------------------------|
| `0x00AA6F90` | PurgeUnusedArenas     | 157 bytes | May be called for existing arenas  |
| `0x00AA7290` | DecrementArenaRef     | 110 bytes | Reference counting for live arenas |
| `0x00AA7300` | ReleaseArenaByPtr     | 106 bytes | Pointer-based arena release        |

### NOP-Patched Call Sites

These are specific CALL instructions patched with NOPs to prevent initialization:

| Address      | Context                              |
|--------------|--------------------------------------|
| `0x0086C56F` | Heap construction double-check       |
| `0x00C42EB1` | CRT heap initialization              |
| `0x00EC1701` | CRT heap initialization              |

### Scrap Heap Hooks (sbm2)

The scrap heap (per-thread bump allocator) is separately hooked:

| Address      | Name                  | Convention |
|--------------|-----------------------|------------|
| `0x00AA53F0` | SheapInitFix          | fastcall   |
| `0x00AA5410` | SheapInitVar          | fastcall   |
| `0x00AA54A0` | SheapAlloc            | fastcall   |
| `0x00AA5610` | SheapFree             | fastcall   |
| `0x00AA5460` | SheapPurge            | fastcall   |
| `0x00AA42E0` | SheapGetThreadLocal   | cdecl      |

---

## 11. Key Global Addresses

### Singletons and Managers

| Address        | Name                         | Description                              |
|----------------|------------------------------|------------------------------------------|
| `DAT_011F6238` | GameHeap singleton           | The MemoryHeap instance                  |
| `DAT_011DEA10` | TES game manager             | Cell arrays, data handler, world state   |
| `DAT_011DEA0C` | Game main controller         | Thread ID at offset +0x10               |
| `DAT_011DEA3C` | Player character pointer     | bhkCharacterProxy                        |
| `DAT_011DDF38` | BSRenderedLandData           | Flags at offset +0x244                  |

### Music System (NOT Havok)

| Address        | Description                                         |
|----------------|-----------------------------------------------------|
| `DAT_011DD313` | Music system running flag (set by FUN_008325a0)     |
| `DAT_011DD434` | Music/physics state flag                            |
| `DAT_011DD436` | Music stop/start guard                              |
| `DAT_011DD437` | Music restart condition                             |
| `DAT_011DD5BC` | PPL task group 1 (audio streaming, NOT AI)          |
| `DAT_011DD638` | PPL task group 2 (audio streaming, NOT AI)          |

### Deferred Destruction

| Address                  | Description                                    |
|--------------------------|------------------------------------------------|
| `DAT_011DE804`           | PDD queue skip bitmask (bit set = queue skip)  |
| `DAT_011DE808`           | PDD queue: NiNode / BSTreeNode (bit 0x08)      |
| `DAT_011DE828`           | PDD queue: Pending form deletions (bit 0x10)   |
| `DAT_011DE874`           | PDD queue: Generic ref-counted (bit 0x01)      |
| `DAT_011DE888`           | PDD queue: Animation/controller (bit 0x02)     |
| `DAT_011DE910`           | PDD queue: Texture/material refs (bit 0x04)    |
| `DAT_011DE924`           | PDD queue: Havok physics wrappers (bit 0x20)   |
| `DAT_011DE958`           | PDD reentrancy guard flag                      |

### SpeedTree

| Address                  | Description                                    |
|--------------------------|------------------------------------------------|
| `DAT_011D5C48`           | BSTreeManager singleton pointer                |

### Synchronization

| Address                  | Description                                    |
|--------------------------|------------------------------------------------|
| `DAT_011DE70C`           | HeapCompact retry counter                      |
| `DAT_011DE8E0`           | PDD critical section (lock object)             |
| `DAT_011DFA18`           | AI frame dispatch flag                         |
| `DAT_011DFA19`           | AI frame active flag                           |
| `DAT_011F11A0`           | Global lock for deferred destruction           |
| `DAT_011F4480`           | Queue 0x10 lock (form deletions)               |
| `_tls_index + 0x298`     | TLS deferred cleanup flag (per-thread)         |
| `_tls_index + 0x2B4`     | TLS per-thread allocator pool index            |

---

## 12. Function Address Map

### Heap Functions

| Address      | Name                  | Size      | Convention | Description                |
|--------------|-----------------------|-----------|------------|----------------------------|
| `0x00AA3E40` | GameHeap::Allocate    | —         | thiscall   | Main allocator (HOOKED)    |
| `0x00AA4060` | GameHeap::Free        | —         | thiscall   | Main free (HOOKED)         |
| `0x00AA4150` | GameHeap::Realloc1    | —         | thiscall   | Realloc variant 1 (HOOKED) |
| `0x00AA4200` | GameHeap::Realloc2    | —         | thiscall   | Realloc variant 2 (HOOKED) |
| `0x00AA44C0` | GameHeap::Msize       | —         | thiscall   | Size query (HOOKED)        |
| `0x00AA4290` | FallbackAlloc         | 39 bytes  | cdecl      | Calls `_malloc()`          |
| `0x00AA42C0` | FallbackFree          | 25 bytes  | cdecl      | Calls `_free()`            |
| `0x00AA45A0` | FindAllocator         | 99 bytes  | thiscall   | Resolve allocator          |
| `0x00AA4610` | FindAllocator2        | 137 bytes | thiscall   | Resolve allocator          |
| `0x00AA4960` | SBM_GetPool           | 238 bytes | cdecl      | Find pool for size         |
| `0x00AA6AA0` | SBM_ArenaAlloc        | 462 bytes | fastcall   | Allocate from arena        |
| `0x00AA6C70` | SBM_ArenaFree         | 138 bytes | thiscall   | Free to arena              |

### Cleanup Functions

| Address      | Name                        | Size       | Convention | Description                 |
|--------------|-----------------------------|------------|------------|-----------------------------|
| `0x00866A90` | HeapCompact                 | 602 bytes  | thiscall   | Multi-stage state machine   |
| `0x00868D70` | ProcessDeferredDestruction  | 1037 bytes | cdecl      | Batch object destructor     |
| `0x00869180` | PDD_QueueGateCheck          | 16 bytes   | cdecl      | Check DAT_011de804 skip mask|
| `0x00869190` | SetTlsCleanupFlag          | 29 bytes   | cdecl      | Sets TLS[0x298]             |
| `0x00453A80` | FindCellToUnload            | 824 bytes  | fastcall   | Cell eviction               |
| `0x00452490` | ProcessPendingCleanup       | 85 bytes   | thiscall   | Flush cleanup queue         |
| `0x004539A0` | ForceUnloadCell             | 196 bytes  | thiscall   | Force cell unload           |
| `0x00462290` | DestroyCell                 | —          | —          | Called by FindCellToUnload  |

### Cell Transition Functions

| Address      | Name                        | Size      | Convention | Description                   |
|--------------|-----------------------------|-----------|------------|-------------------------------|
| `0x008774A0` | CellTransitionHandler       | 561 bytes | thiscall   | Full cell transition sequence |
| `0x00877700` | CellTransition_PreCleanup   | 30 bytes  | fastcall   | Wait with timeout             |
| `0x008782B0` | CellTransition_SafePoint    | 130 bytes | —          | Conditional PDD call          |
| `0x00878250` | DeferredCleanup_Small       | 86 bytes  | —          | Calls PDD(1)                  |
| `0x0093BEA0` | CellTransition_Conditional  | 832 bytes | fastcall   | Conditional cell transition   |

### Music System Functions (NOT Havok)

| Address      | Name              | Size      | Convention | Description                    |
|--------------|-------------------|-----------|------------|--------------------------------|
| `0x008324E0` | MusicStopStart    | 184 bytes | cdecl      | Stop/start music + drain PPL   |
| `0x008325A0` | MusicFlagSet      | 13 bytes  | cdecl      | Sets DAT_011dd313 = param      |
| `0x008304A0` | MusicPre          | 20 bytes  | —          | Music pre-step                 |
| `0x008304C0` | MusicPost         | 46 bytes  | —          | Music post-step                |
| `0x008300C0` | MusicStepInit     | 944 bytes | cdecl      | Music crossfade initialization |
| `0x00830AD0` | MusicIsRunning    | 92 bytes  | —          | Check music state              |

### Main Loop Functions

| Address      | Name                  | Size       | Convention | Description                    |
|--------------|-----------------------|------------|------------|--------------------------------|
| `0x0086E650` | MainLoop              | 2272 bytes | fastcall   | Per-frame function             |
| `0x0086F940` | PreAI_CellHandler     | 595 bytes  | fastcall   | Calls FUN_0093bea0             |
| `0x0086FF70` | PreRender_Maintenance | 1616 bytes | fastcall   | Pre-render maintenance         |
| `0x008705D0` | RenderUpdate          | 55 bytes   | fastcall   | OUR HOOK TARGET                |
| `0x0086F640` | RenderUpdate_Pre      | 45 bytes   | —          | Render setup                   |
| `0x0086F670` | RenderUpdate_Post     | 48 bytes   | —          | Render teardown                |
| `0x0086F890` | RenderUpdate_Inner    | 161 bytes  | fastcall   | Inner render loop              |

### AI Thread Functions

| Address      | Name                  | Size      | Convention | Description                      |
|--------------|-----------------------|-----------|------------|----------------------------------|
| `0x00AA64D0` | ThreadEntry           | 20 bytes  | stdcall    | lpStartAddress, calls vtable[1]  |
| `0x008C7720` | AIThread_MainLoop     | 111 bytes | fastcall   | Wait/execute/signal loop         |
| `0x008C7190` | AIThread_TaskDispatch | 28 bytes  | fastcall   | Calls fn ptr at offset 0x4c      |
| `0x008C7F50` | AITask_FrameUpdate    | 346 bytes | —          | AI frame task                    |
| `0x008C7DA0` | AI_MainCoordinator    | 429 bytes | —          | Dispatch + wait orchestrator     |
| `0x008C7BD0` | AI_Dispatcher2        | 418 bytes | —          | Alternative dispatcher           |
| `0x008C7290` | AI_CoordinatorCaller  | —         | —          | Calls both coordinators          |
| `0x008C79E0` | AI_Dispatch           | 70 bytes  | thiscall   | SetEvent for AI thread           |
| `0x008C7A70` | AI_Wait               | 41 bytes  | thiscall   | WaitForSingleObject for AI       |
| `0x008C80E0` | AI_StartFrame         | 46 bytes  | cdecl      | Sets DAT_011dfa18 flag           |
| `0x008C78C0` | AI_ResetEvents        | 198 bytes | fastcall   | ResetEvent on all AI events      |
| `0x008C7990` | AI_PostRender         | 72 bytes  | fastcall   | Post-render AI signal            |

### AI Processing

| Address      | Name                  | Size      | Convention | Description                      |
|--------------|-----------------------|-----------|------------|----------------------------------|
| `0x0096C330` | AIProcess_Main        | 991 bytes | fastcall   | Raycasting, physics queries      |
| `0x0096CB50` | AIProcess_Secondary   | —         | fastcall   | Additional AI processing         |

### PPL Task Group Functions (Audio)

PPL (Parallel Patterns Library) is Microsoft's C++ concurrency framework, part of
the MSVC Concurrency Runtime. FNV uses `Concurrency::task_group` objects for audio
streaming work — queuing decode/playback tasks that run on the CRT's thread pool.

**These are NOT related to AI threads.** AI coordination uses a completely separate
mechanism (Windows Events + Semaphores, see Section 4). This distinction matters
because draining PPL task groups (via `TaskGroupDrain`/`TaskGroupWait`) only
affects audio tasks. It does NOT pause or synchronize AI Linear Task Threads.

| Address      | Name                  | Size      | Convention | Description                      |
|--------------|-----------------------|-----------|------------|----------------------------------|
| `0x00AD88F0` | TaskGroupDrain        | 51 bytes  | fastcall   | Drain PPL task group             |
| `0x00AD8D10` | TaskGroupWait         | 66 bytes  | fastcall   | Wait for PPL task completion     |
| `0x00AD8DA0` | TaskGroupWaitTimeout  | 60 bytes  | thiscall   | Wait with timeout                |

### SBM Maintenance (Left Alive)

| Address      | Name                  | Size      | Convention | Description                      |
|--------------|-----------------------|-----------|------------|----------------------------------|
| `0x00AA6F90` | PurgeUnusedArenas     | 157 bytes | fastcall   | Purge unused SBM arenas          |
| `0x00AA7290` | DecrementArenaRef     | 110 bytes | cdecl      | Arena reference counting         |
| `0x00AA7300` | ReleaseArenaByPtr     | 106 bytes | fastcall   | Release arena by pointer         |
| `0x00AA68A0` | SBM_ResetStats        | 125 bytes | —          | Calls GameHeap::Free on pools    |

### SpeedTree / BSTreeManager

| Address      | Name                  | Size      | Convention | Description                      |
|--------------|-----------------------|-----------|------------|----------------------------------|
| `0x0043DA00` | TreeMgr_AddTree       | 149 bytes | fastcall   | Add tree to BSTreeManager        |
| `0x0043DAC0` | TreeMgr_RemoveOnState | 53 bytes  | thiscall   | Remove tree if state > 3         |
| `0x00664840` | TreeMgr_GetOrCreate   | 37 bytes  | cdecl      | Lazy-init BSTreeManager          |
| `0x00664870` | TreeMgr_Create        | 199 bytes | cdecl      | Allocate + construct manager     |
| `0x00664940` | TreeMgr_Destroy       | 71 bytes  | —          | Cleanup + set singleton=NULL     |
| `0x00664990` | TreeMgr_Cleanup       | 44 bytes  | thiscall   | Internal cleanup via FUN_00664740|
| `0x00664F50` | TreeMgr_FindOrCreate  | 874 bytes | thiscall   | Find/create tree by reference    |
| `0x00665B80` | TreeMgr_RemoveEntry   | 95 bytes  | thiscall   | Remove entry from map            |
| `0x00665BE0` | TreeMgr_RemoveByKey   | 99 bytes  | thiscall   | Remove from treeNodesMap by key  |
| `0x00666650` | BSTreeModel_Ctor      | 372 bytes | —          | BSTreeModel constructor          |
| `0x00666800` | BSTreeModel_Init      | 261 bytes | —          | BSTreeModel initialization       |
| `0x0066B120` | BSTreeNode_Ctor       | 1161 bytes| —          | BSTreeNode constructor/update    |
| `0x0066B6C0` | BSTreeNode_Init       | 264 bytes | —          | BSTreeNode setup                 |

### PDD Queue Destructors

| Address      | Name                  | Size      | Convention | Queue | Description                |
|--------------|-----------------------|-----------|------------|-------|----------------------------|
| `0x00418D20` | NiNode_Release        | 44 bytes  | thiscall   | 0x08  | NiRefObject release+free   |
| `0x00418E00` | Texture_Release       | 44 bytes  | thiscall   | 0x04  | Texture/material release   |
| `0x00868CE0` | Anim_ClearFlag        | 39 bytes  | fastcall   | 0x02  | Clear bit 0x40000000       |
| `0x00401970` | Havok_Release         | —         | —          | 0x20  | Havok wrapper release      |
| `0x00868250` | PDD_TryLock           | 21 bytes  | fastcall   | 0x08/04/01 | Try-lock for queue     |
| `0x0078D1F0` | PDD_FormLock          | 15 bytes  | —          | 0x10  | Lock for form queue        |

### Misc Utilities

| Address      | Name                  | Size      | Convention | Description                      |
|--------------|-----------------------|-----------|------------|----------------------------------|
| `0x0040FBF0` | EnterLock             | —         | fastcall   | Custom lock acquire              |
| `0x0040FBA0` | ReleaseLock           | —         | fastcall   | Custom lock release              |
| `0x0040FC90` | GetCurrentThreadId    | —         | —          | Wrapper                          |
| `0x0040FCA0` | Sleep                 | —         | —          | Wrapper                          |
| `0x0044EDB0` | GetMainThreadId       | —         | —          | Reads offset 0x10 from param     |
| `0x00401020` | GetGameHeapSingleton  | —         | —          | Returns &DAT_011f6238            |

---

## 13. Ghidra Analysis Scripts

All scripts are located in `analysis/ghidra/scripts/`. Analysis outputs are in
`analysis/ghidra/output/memory/`.

### Scripts

| Script                          | Purpose                                            |
|---------------------------------|----------------------------------------------------|
| `heap_accounting.py`            | Decompile HeapCompact and FallbackAllocator         |
| `find_unhooked_free_paths.py`   | Find all callers of unhooked free functions         |
| `deep_heap_compact.py`          | Recursive decompilation of HeapCompact (3 levels)   |
| `ai_thread_sync.py`            | AI thread sync model and PDD callers                |
| `ai_sync_primitives.py`        | AI thread wait/signal primitives + cell transition  |
| `ai_thread_deep.py`            | Deep dive into AI thread sync mechanism             |
| `find_deferred_safe_point.py`  | Find safe frame points for PDD                      |
| `decompile_0086f940.py`        | Decompile the safe hook point                       |
| `havok_direct.py`              | Decompile Havok/music stop/start functions           |

### Analysis Outputs

| Output File                     | Content                                             |
|---------------------------------|-----------------------------------------------------|
| `disasm_gheap.txt`              | GameHeap functions decompilation                    |
| `disasm_callers.txt`            | Callers of heap functions                           |
| `deep_heap_compact.txt`         | HeapCompact full call tree                          |
| `unhooked_free_paths.txt`       | Unhooked free path analysis (proved no missing hooks)|
| `ai_thread_sync.txt`           | AI thread sync model                                |
| `ai_sync_primitives.txt`       | AI primitives decompilation                         |
| `ai_thread_deep.txt`           | Deep AI thread analysis                             |
| `find_deferred_safe_point.txt` | Safe point analysis                                 |
| `safe_hook_point.txt`          | Hook point decompilation                            |
| `havok_direct.txt`             | Havok/music functions                               |
| `speedtree_cache.txt`          | BSTreeManager, PDD queues, gate function, locks     |
| `speedtree_cache2.txt`         | Queue gate, destructors, tree manager CRUD, locks   |

---

## 14. Key Lessons Learned

### 1. The 500MB Budget Was a Synchronization Barrier

The original 500MB heap budget was not just a memory limit. When the heap filled up,
HeapCompact would run on the main thread, which naturally serialized with AI threads
(Stage 5 only runs on main thread, Stage 8 makes non-main threads sleep). By removing
this budget (replacing with mimalloc's much larger address space), we removed an
implicit synchronization mechanism. The pressure relief system is our replacement for
that mechanism.

### 2. FUN_008324e0 Is the Music System, Not Havok

Misidentifying `FUN_008324e0` as a Havok physics function wasted significant analysis
time. The PPL task groups it drains are audio streaming groups, and calling
`FUN_008324e0(1)` to "restart physics" actually tries to restart music playback with
a NULL path, causing a crash.

### 3. AI Threads Do Not Call GameHeap::Allocate During Raycasting

This was verified by tracing `AIProcess_Main` (`0x0096C330`) at depth-2. The raycasting
code accesses `hkBSHeightFieldShape` objects directly from loaded cells without going
through the game allocator. This means an allocation-barrier approach (blocking AI
threads when they try to allocate during pressure relief) cannot work.

### 4. Selective PDD Is Possible via DAT_011de804 Skip Mask

Full PDD from our hook is unsafe, but **selective PDD** works by writing to the
skip mask at `DAT_011de804` before calling PDD. The gate function `FUN_00869180(flag)`
checks `(DAT_011de804 & flag) != 0` to skip queues. Currently we skip only 0x08
(NiNode queue) as the minimum viable skip.

Skipping additional queues (0x20, 0x04) was tested but caused FASTER crashes.
The hypothesis is that the game's internal state management expects objects to be
processed from those queues, and leaving them orphaned creates inconsistencies.

### 5. FindCellToUnload Is Safe Post-Render

FindCellToUnload works safely at our hook position (post-render, line 486) because:

- SpeedTree draw lists have been consumed by the render pass
- Physics objects are queued for deferred destruction, not immediately removed from
  the Havok world
- AI threads do not directly reference cell array entries by index

**However:** Too-aggressive cell unloading (cooldown < 2000ms, > 20 cells/cycle)
causes AI thread crashes. AI threads hold references to entities in cells beyond
the frame boundary — not just heightfields, but placed objects, navmesh data, etc.

### 6. PPL Task Groups in FUN_008324e0 Are Audio, Not AI

The two PPL Concurrency Runtime task groups (`DAT_011dd5bc`, `DAT_011dd638`) drained
by the cell transition handler are audio streaming groups. AI thread coordination uses
Windows Events and Semaphores, not PPL task groups.

### 7. Never Use .unwrap()/.expect() in NVSE Plugins

Rust panics in an NVSE plugin context kill the game process with no diagnostic output.
All fallible operations must use graceful error handling (match, if-let, unwrap_or).

### 8. Per-Allocation Atomic Counters Destroy Performance

A single `AtomicU32::fetch_add(1, Relaxed)` on every allocation causes 5-7 FPS
regression due to cache line bouncing between CPU cores. The solution is thread-local
counters that are only checked periodically, with zero cross-core contention.

### 9. TLS Cleanup Flag Controls Immediate vs Deferred Destruction

The TLS flag at `_tls_index + 0x298` is a per-thread toggle:
- **Flag = 0:** Objects destroyed immediately when refcount hits 0
- **Flag = 1:** Objects queued into deferred destruction lists

Setting flag to 0 during `FindCellToUnload` causes BSTreeNodes to be freed
immediately (bypassing the deferred queue), which makes our PDD skip mask
useless. The SpeedTree cache still holds pointers to the now-freed nodes.
**Always keep TLS flag at 1 (default).**

### 10. mi_collect(true) Is Thread-Unsafe

`mi_collect(true)` forces mimalloc to purge segments across ALL threads. If an
AI thread is actively allocating from a segment being purged by the main thread,
the result is a use-after-free inside mimalloc itself. Crash manifests as
`EXCEPTION_ACCESS_VIOLATION` inside `psycho_nvse` DLL on AI thread stack.
**Only use `mi_collect(false)` (thread-local collection).**

### 11. BSTreeManager Global Cache Holds Cross-Frame References

The `BSTreeManager` singleton at `DAT_011d5c48` maintains:
- `treeModelsMap` (offset 0x00): `TESObjectTREE*` → `BSTreeModel*`
- `treeNodesMap` (offset 0x1C): `TESObjectREFR*` → `BSTreeNode*`

Key functions:
- `FUN_00664f50`: Find/create tree in manager (874 bytes)
- `FUN_00665b80`: Remove tree entry (95 bytes)
- `FUN_00665be0`: Remove by key from treeNodesMap (99 bytes)
- `FUN_00664940`: Full cleanup — calls `FUN_00664990(1)` then sets singleton to NULL
- `FUN_0043dac0`: Removes tree from manager when state > 3 (being unloaded)

The SpeedTree render cache is NOT rebuilt every frame. BSTreeNode pointers persist
across frames in the model cache. Destroying a BSTreeNode without first removing
it from the cache leaves stale pointers.

### 12. Skipping More PDD Queues Makes Things Worse

Counter-intuitively, skipping more queues (0x08 | 0x20 | 0x04) caused FASTER
crashes than skipping only 0x08. The game's internal state management likely
expects that PDD eventually processes all queues. Orphaning objects in multiple
queues creates cascading inconsistencies (e.g., a form references a texture
that should have been freed, or a physics wrapper references a collision shape
that's in a stale state).

---

## 15. SpeedTree Cache Analysis

### BSTreeManager Singleton

**Address:** `DAT_011d5c48` | **Size:** 0x20 bytes

The BSTreeManager owns all active SpeedTree vegetation instances. It is created
lazily by `FUN_00664870` and destroyed by `FUN_00664940`.

### Functions Referencing BSTreeManager

| Address      | Name / Action                  | Size      | Description                           |
|--------------|--------------------------------|-----------|---------------------------------------|
| `0x0043DA00` | Add tree to manager            | 149 bytes | Lock → find/create → insert           |
| `0x0043DAC0` | Remove tree on state change    | 53 bytes  | If state > 3: remove from treeNodesMap|
| `0x00664840` | Get/create manager             | 37 bytes  | Lazy init, returns DAT_011d5c48       |
| `0x00664870` | Create manager                 | 199 bytes | Allocates 0x20 bytes, constructs      |
| `0x00664940` | Destroy manager                | 71 bytes  | Calls cleanup(1), sets singleton=NULL |
| `0x00664990` | BSTreeManager cleanup          | 44 bytes  | Calls FUN_00664740, optionally frees  |

### BSTreeModel / BSTreeNode Vtable Functions

| Address      | Vtable         | Size       | Description                             |
|--------------|----------------|------------|-----------------------------------------|
| `0x00666650` | BSTreeModel    | 372 bytes  | BSTreeModel constructor                 |
| `0x00666800` | BSTreeModel    | 261 bytes  | BSTreeModel setup / initialization      |
| `0x0066B120` | BSTreeNode     | 1161 bytes | BSTreeNode constructor / update         |
| `0x0066B6C0` | BSTreeNode     | 264 bytes  | BSTreeNode setup                        |

### Pre-Destruction Setup (FUN_00878160)

**Address:** `0x00878160` | Called before PDD during cell transitions.

```c
void FUN_00878160(int param_1, char param_2, char param_3, char param_4) {
    FUN_00c3e310(DAT_01202d98);          // Havok world lock?
    // ... state setup ...
    FUN_008781e0(0x7fffffff);            // Set DAT_011a95fc = MAX
    FUN_00703980();                       // Pre-destruction call
}
```

`FUN_00703980` calls `FUN_007160b0` conditionally — this may be the scene graph
invalidation that makes queue 0x08 safe during cell transitions. We have NOT
been able to safely call this from our hook position.

### Open Problem: NiNode Queue Accumulation

Without processing queue 0x08, NiNode/BSTreeNode objects accumulate in
`DAT_011de808` indefinitely. During sustained cell loading (stress test),
this is the primary source of memory growth leading to OOM.

#### Attempted: Scene Graph Invalidation (FAILED)

Ghidra analysis (`bstree_ninode_drain.py`) revealed that the game's 5
normal-gameplay PDD callers ALL call `FUN_00878160` (pre-destruction setup)
which calls `FUN_00703980` → `FUN_007160b0` (scene graph invalidation)
before `DeferredCleanup_Small`. This rebuilds SpeedTree draw lists.

We attempted to call this from our post-render hook:
```
FindCellToUnload → ProcessPendingCleanup
  → SetDistanceThreshold(INT_MAX) → FUN_00703980()  // scene graph invalidation
  → ProcessDeferredDestruction(1)  // all queues
```

**Result: CRASH.** Two failure modes:

1. **Main thread crash in scene graph cull/update** — `FUN_007160b0` calls
   `vtable+0x1c()` which traverses the scene graph and accesses heightfield
   data (`hkBSHeightFieldShape`) from cells we just freed via
   `FindCellToUnload`. The game's own callers run BEFORE cell unloading
   (lines 271, 347), when the scene graph is still consistent.

2. **AI thread crash (hkBSHeightFieldShape)** — Full PDD processes queue
   0x20 (Havok wrappers), freeing heightfield shapes that AI threads hold
   live references to during raycasting.

**Key finding:** Scene graph invalidation CANNOT be called after
`FindCellToUnload` — the cull/update accesses freed cell data. And it
cannot be called before either — the draw lists would still reference
the about-to-be-destroyed BSTreeNodes.

The game's safe PDD callers work because they run early in the frame
(lines 271, 347) where no cells have been freed and the scene graph is
consistent. The draw lists are rebuilt, PDD destroys nodes, and later
render (line 486) uses the fresh draw lists.

#### Current approach: Multi-layer pressure relief

Deep research (`two_phase_hook_research.py`, `ai_pause_mechanism.py`,
`commit_growth_analysis.py`, `heapcompact_trigger.py`) revealed multiple
mechanisms that work together.

**Layer 1: Post-render cell unloading + selective PDD (FUN_008705d0 hook)**

Our primary hook at line ~904. After render completes:
1. `FindCellToUnload` × 20 cells max
2. `ProcessPendingCleanup(manager, 0)`
3. Selective PDD (skip queue 0x08, NiNode)
4. Trigger HeapCompact for next frame: `*(0x011F636C) = 5`
5. `mi_collect(false)`

**Layer 2: Boosted per-frame NiNode drain (FUN_00868850 hook)**

Hook at line ~802, BEFORE AI dispatch and render. The game's own
per-frame queue processor drains 10-20 items per call. Under pressure,
we call it 20× total (1 normal + 19 extra). Stops when queue 0x08
empties to avoid over-draining Havok queue 0x20.

Safe because:
- AI threads are idle (not yet dispatched)
- Render hasn't built draw lists (destroyed BSTreeNodes won't appear)
- The game itself runs this function here every frame

**Layer 3: HeapCompact trigger (heap_singleton + 0x134)**

The game's own cleanup mechanism, re-enabled by writing one integer.

```
FUN_00878110(heap) → return *(heap + 0x134)   // read trigger
FUN_00878130(heap) → *(heap + 0x134) = 0      // reset after run
FUN_00401020()     → return &DAT_011F6238     // heap IS DAT_011F6238
Trigger address:     0x011F6238 + 0x134 = 0x011F636C
```

Writing `5` to `0x011F636C` causes FUN_00878080 at line ~797 to run
HeapCompact stages 0-5 on the NEXT frame:
- Stage 0: Reset + ProcessPendingCleanup
- Stage 1: SBM arena teardown (RET-patched → no-op)
- Stage 2: Cell/resource cleanup
- Stage 3: Async queue flush
- Stage 4: PDD with global lock
- Stage 5: **TLS=0 → FindCellToUnload → ProcessPendingCleanup → TLS=1 → full PDD**

Stage 5 is the key: with TLS=0, BSTreeNodes are freed IMMEDIATELY during
FindCellToUnload. The immediate destruction triggers TreeMgr_RemoveOnState
(vtable), which removes the BSTreeNode from BSTreeManager's treeNodesMap.
When render runs later at line ~904, it builds draw lists from the map —
the freed nodes are already gone. No stale draw list pointers.

This runs at the game's native safe position: BEFORE AI dispatch (line ~855),
BEFORE render (line ~904). The game itself uses this exact mechanism when
the original heap budget is exhausted.

#### Attempted and rejected approaches

**DAT_011a95fc cleanup rate boost (REJECTED):**
Boosting the cleanup dispatch rate limiter accelerates `FUN_00a61cd0`,
which finalizes texture/IO objects faster than the async IO system
(`IOManager`, `LockFreeQueue<IOTask>`) can process them → QueuedTexture
vtable call through freed memory. The game's default rate exists to
prevent IO races.

**Async queue flush FUN_00c459d0 (REJECTED):**
Flushing the async queue disrupts NVTF's Geometry Precache Queue thread —
completing IO operations that NVTF's background thread depends on →
NiGeometryBufferData UAF crash. The JIP PlayingSoundsIterator UAF from
BSAudioManager stale refs is a rare mod-specific issue.

**Scene graph invalidation FUN_00703980 (REJECTED):**
Cannot be called after FindCellToUnload — the cull/update (vtable+0x1c)
accesses hkBSHeightFieldShape data from cells we just freed.

**Aggressive tuning 600MB/30cells (REJECTED):**
More cells per cycle causes BSTreeNode UAF faster than the per-frame drain
can handle. 700MB/20cells is the sweet spot.

#### Key discoveries from deep research

**HeapCompact trigger mechanism (`heapcompact_trigger.py`):**
`FUN_00878110` reads `*(heap + 0x134)` — the "compact request" field.
`FUN_00878130` resets it to 0 after completion. HeapCompact Stage 8
(non-main thread) writes `6` here to request cleanup from the main thread.
Writing any value N causes stages 0..N to run from FUN_00878080 at
line ~797 on the next frame. ONE INTEGER WRITE re-enables the game's
entire native cleanup mechanism.

**FUN_00868850 (per-frame queue processor, 1166 bytes):**
Runs every frame at line ~802, processes ALL PDD queues with limited
batch sizes. Uses priority order: 0x08 first, then 0x04, 0x02, 0x01,
0x20. Batch size = `local_1c × N` where N varies per queue (10 for
0x08, 5 for 0x20). `local_1c` = 1 normally, 2 when `FUN_00878360`
returns true (heap headroom check: tight headroom → 2× drain).

**DAT_011a95fc (cleanup rate limiter):**
Controls `FUN_00a61cd0` loop bound. Set to INT_MAX by pre-destruction
setup. Default is small. Boosting causes QueuedTexture IO races — the
game's default prevents this.

**AI thread lifecycle:**
AI threads use Event/Semaphore, NOT PPL. `DAT_011dfa18` = dispatch
flag. `DAT_011dfa19` = active flag (1 = active, 0 = idle between
frames). AI dispatch is conditional — when `bVar1` is false (loading
screens, menus), AI threads are never dispatched.

**BSAudioManager stale reference problem:**
`soundPlayingObjects` (NiTPtrMap at manager+0x84) maps sound keys to
`NiAVObject*` pointers. These persist after cell unloading. JIP LN
NVSE's `PlayingSoundsIterator` iterates `playingSounds` map, looks up
`soundPlayingObjects`, then calls `GetParentRef()` which walks the
NiNode parent chain → UAF. Async queue flush fixes this but breaks
NVTF. HeapCompact Stage 3 handles it naturally via its own async flush.

#### Tuning experiments

| Config | Drain | HeapCompact | Other | Result |
|--------|-------|-------------|-------|--------|
| 700/2s/20 | None | No | — | OOM ~1.7GB, ~3min |
| 700/2s/20 | 10× | No | — | 40 reliefs, ~4min, OOM |
| 700/2s/20 | 20×+guard | No | — | 55 reliefs, ~4.5min, OOM |
| 600/2s/30 | 20×+guard | No | — | Faster crash (BSTreeNode) |
| 700/2s/20 | 20×+guard | No | Rate boost | QueuedTexture IO race |
| 700/2s/20 | 20×+guard | No | Async flush | NVTF geometry crash |
| 700/2s/20 | 20×+guard | **Yes (5)** | — | **46 reliefs, 500 cells, less stutters, OOM ~1.6GB** |

#### Remaining limitation: 32-bit VA ceiling

Under extreme stress (max-speed flying across entire map), commit
eventually reaches ~1.6-1.7GB and OOM crashes. This is the fundamental
32-bit virtual address space limit (~1.8GB usable with LAA). The crash
manifests as QueuedTexture NULL vtable (`eip=0x00000000`) — the IO system
tries to load a texture but allocation fails or returns just-freed memory.

Normal gameplay is completely stable (~760MB idle, ~1.0-1.1GB moving).
The OOM only occurs under artificial extreme stress that no real player
would sustain.

---

## Appendix: Build Notes

The psycho-nvse plugin must be built with:
```
--target i686-pc-windows-gnu
```
This is a 32-bit Windows target cross-compiled from Linux.

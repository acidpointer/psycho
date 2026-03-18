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

FNV uses a multi-threaded AI system with Windows Events and Semaphores for
synchronization.

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

## 5. ProcessDeferredDestruction

**Address:** `0x00868D70` | **Size:** 1037 bytes | **Convention:** cdecl

This function batch-destroys queued game objects from multiple internal lists. It is
the game's primary mechanism for safely deferring object destruction to a controlled
point in the frame.

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

### Why We Cannot Call It From Our Hook

ProcessDeferredDestruction destroys Havok physics wrappers (bit 0x20). If called at
the wrong time:

- **Pre-render:** Destroys NiNode trees -> BSTreeNode use-after-free (SpeedTree
  has cached draw list pointers)
- **Post-render:** AI threads may hold references to Havok heightfield shapes
- **Any time:** Havok physics world may internally reference objects being destroyed
  -> crash with exception code C0000417

The game calls it conditionally at specific frame points with specific state guards.
Our hook does NOT call it; we rely on the game's own deferred destruction schedule.

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
  | (hkBSHeightFieldShape)     | heightfields while AI threads raycast     | (concurrent)     |
  |                            | against them                              |                  |
  +----------------------------+-------------------------------------------+------------------+
  | Render crash               | FindCellToUnload destroys BSTreeNodes     | Pre-render       |
  | (BSTreeNode UAF)           | while SpeedTree has cached draw list      | (0x0086F940,     |
  |                            | pointers to them                          |  0x0086FF70)     |
  +----------------------------+-------------------------------------------+------------------+
  | Havok allocator crash      | ProcessDeferredDestruction destroys       | ANY position     |
  | (C0000417)                 | Havok objects still internally referenced | (unconditional   |
  |                            | by the physics world                      |  PDD call)       |
  +----------------------------+-------------------------------------------+------------------+
  | OOM crash                  | 32-bit VA space exhaustion at ~1.8GB      | Post-render      |
  | (fatal in exception        | commit. Deferred objects pile up without  | (no PDD)         |
  | handler)                   | ProcessDeferredDestruction                |                  |
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
                +-- SetTlsCleanupFlag(0)         -- enable immediate cleanup
                |
                +-- Loop (up to 20 iterations):
                |     FindCellToUnload(manager)
                |     if returned 0: break        -- no more cells
                |
                +-- ProcessPendingCleanup(manager, 0)
                |
                +-- SetTlsCleanupFlag(1)          -- restore deferred mode
                |
                +-- mi_collect(false)             -- nudge mimalloc to decommit
    ...
```

### What We Do NOT Do

We do **NOT** call `ProcessDeferredDestruction`. The game's own deferred
destruction runs at controlled points:

- Line 271-273: `FUN_008782b0` -> `ProcessDeferredDestruction(1)` (loading state)
- Line 273: `FUN_0086f940` -> `FUN_0093bea0` -> `ProcessDeferredDestruction(1)`
  (cell transitions)
- Line 347: `FUN_004556d0` -> `FUN_00878250` -> `ProcessDeferredDestruction(1)`

Calling it ourselves risks destroying Havok objects or NiNode trees at unsafe times.

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

### Synchronization

| Address                  | Description                                    |
|--------------------------|------------------------------------------------|
| `DAT_011DE70C`           | HeapCompact retry counter                      |
| `DAT_011DFA18`           | AI frame dispatch flag                         |
| `DAT_011DFA19`           | AI frame active flag                           |
| `DAT_011F11A0`           | Global lock for deferred destruction           |
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

### 4. ProcessDeferredDestruction Cannot Be Safely Called From Any Hook Position

| Position    | Problem                                                        |
|-------------|----------------------------------------------------------------|
| Pre-render  | BSTreeNode use-after-free (SpeedTree cached draw list pointers)|
| Post-render | AI threads may hold references to Havok heightfield shapes    |
| Pre-AI      | Same as pre-render                                             |
| Any         | Havok world may internally reference objects being destroyed   |

The game calls PDD conditionally at specific points with specific state guards. Our
hook relies on the game's own PDD schedule.

### 5. FindCellToUnload Is Safe Post-Render

FindCellToUnload works safely at our hook position (post-render, line 486) because:

- SpeedTree draw lists have been consumed by the render pass
- Physics objects are queued for deferred destruction, not immediately removed from
  the Havok world
- AI threads do not directly reference cell array entries by index

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

---

## Appendix: Build Notes

The psycho-nvse plugin must be built with:
```
--target i686-pc-windows-gnu
```
This is a 32-bit Windows target cross-compiled from Linux.

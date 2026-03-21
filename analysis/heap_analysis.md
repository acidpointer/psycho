# Fallout New Vegas Game Heap -- Complete Analysis

All addresses target the Steam GOG/retail executable (FalloutNV.exe).
Calling conventions follow MSVC x86: thiscall = ECX, fastcall = ECX+EDX, cdecl = stack-only.

---

## Table of Contents

### PART 1: QUICK START
- [Executive Summary](#executive-summary)
- [How the Game Manages Memory](#how-the-game-manages-memory)
- [What psycho-nvse Replaces and Why](#what-psycho-nvse-replaces-and-why)
- [Architecture Diagram](#architecture-diagram)

### PART 2: THE GAME ENGINE
- [Chapter 1: Memory Architecture](#chapter-1-memory-architecture)
- [Chapter 2: The Main Loop](#chapter-2-the-main-loop)
- [Chapter 3: Thread Model](#chapter-3-thread-model)
- [Chapter 4: Object Lifecycle](#chapter-4-object-lifecycle)
- [Chapter 5: HeapCompact](#chapter-5-heapcompact)

### PART 3: THE REPLACEMENT
- [Chapter 6: Hook Architecture](#chapter-6-hook-architecture)
- [Chapter 7: The Pre-Destruction Protocol](#chapter-7-the-pre-destruction-protocol)
- [Chapter 8: Pressure Relief System](#chapter-8-pressure-relief-system)
- [Chapter 9: Delayed Free Quarantine](#chapter-9-delayed-free-quarantine)
- [Chapter 10: SBM Patches](#chapter-10-sbm-patches)

### PART 4: CRASH ANALYSIS
- [Chapter 11: Crash Types and Root Causes](#chapter-11-crash-types-and-root-causes)
- [Chapter 12: Key Lessons Learned](#chapter-12-key-lessons-learned)
- [Chapter 13: Tuning Experiments](#chapter-13-tuning-experiments)

### PART 5: REFERENCE TABLES
- [Chapter 14: Function Address Map](#chapter-14-function-address-map)
- [Chapter 15: Global Address Map](#chapter-15-global-address-map)
- [Chapter 16: Ghidra Scripts and Outputs](#chapter-16-ghidra-scripts-and-outputs)
- [Appendix: Build Notes](#appendix-build-notes)
- [Glossary](#glossary)

---

# PART 1: QUICK START

---

## Executive Summary

> **TL;DR:** psycho-nvse replaces Fallout New Vegas's original 500MB game heap with
> mimalloc, a modern allocator. The hard part is not the allocation itself -- it is
> safely coordinating with the game's deferred destruction system, AI threads, render
> pipeline, and IO manager to prevent use-after-free crashes under memory pressure.

Fallout New Vegas allocates all game objects through a singleton `MemoryHeap` backed
by a pool allocator (SBM) for small objects and CRT malloc for everything else, with
a hard 500MB budget. When allocation fails, a multi-stage state machine called
`HeapCompact` progressively reclaims memory -- unloading cells, flushing queues,
destroying deferred objects.

psycho-nvse replaces this entire allocation layer with mimalloc (512MB reserve,
immediate purge). The replacement hooks five allocator entry points and disables
the SBM pool system. To prevent 32-bit address space exhaustion (~1.8GB usable),
a pressure relief system monitors commit size and triggers coordinated cleanup using
the game's own Pre-Destruction Protocol (hkWorld_Lock + SceneGraphInvalidate + PDD).

A delayed-free quarantine protects against use-after-free from the IO thread and NVSE
plugins by holding freed pointers in per-thread ring buffers for 30 frames before actual
deallocation.

---

## How the Game Manages Memory

1. All allocations flow through `MemoryHeap` singleton at `DAT_011F6238`
2. Small allocations go to the SBM pool allocator; large ones go to CRT `_malloc`
3. Objects are never freed immediately -- they are queued for ProcessDeferredDestruction (PDD)
4. PDD maintains 6 typed queues (forms, NiNodes, textures, animations, generics, Havok wrappers)
5. PDD runs at synchronized frame points where no other thread holds references
6. AI threads (2x "AI Linear Task Thread") use Windows Events, NOT PPL -- they raycast against Havok collision shapes from loaded cells
7. The IO thread loads textures asynchronously via a lock-free queue -- it holds raw pointers to queued tasks between dequeue and completion
8. SpeedTree caches BSTreeNode pointers across frames in BSTreeManager -- destroying nodes without invalidating the cache crashes the renderer
9. When allocation fails, HeapCompact stages 0-8 attempt progressively aggressive reclamation
10. The 500MB budget doubles as an implicit thread synchronization barrier -- when full, HeapCompact serializes everything on the main thread

---

## What psycho-nvse Replaces and Why

1. **Allocator swap:** MemoryHeap's alloc/free/realloc/msize are hooked to route through mimalloc -- better fragmentation behavior, no 500MB ceiling
2. **SBM disabled:** The pool allocator is RET-patched out; mimalloc's size classes handle small allocations natively
3. **Pressure relief:** Replaces the implicit synchronization of the 500MB budget ceiling with explicit monitoring (700MB threshold, 2s cooldown, 20 cells/cycle)
4. **Pre-Destruction Protocol adopted:** We call the game's own PreDestructionSetup/PostDestructionRestore around cleanup, making ALL PDD queues safe from our hook position
5. **Quarantine system:** Per-thread ring buffers delay actual `mi_free()` by 30 frames, protecting the IO thread from use-after-free on QueuedTexture objects

---

## Architecture Diagram

```
  ORIGINAL ALLOCATOR                    OUR REPLACEMENT
  ==================                    ===============

  GameHeap::Allocate ─────────────────> mimalloc (mi_malloc)
       |                                     |
       +── SBM pool (small)  [DISABLED]      +── 512MB VA reserve
       +── CRT _malloc (large)               +── purge_delay=0
       +── HeapCompact retry                 +── eager_commit=0
                                             |
  GameHeap::Free ─────────────────────> Quarantine Ring Buffer
       |                                     |
       +── SBM arena free    [DISABLED]      +── per-thread, lock-free
       +── CRT _free                         +── 30-frame delay
                                             +── mi_free() after delay
                                             |
  HeapCompact (500MB budget) ─────────> Pressure Relief System
       |                                     |
       +── stages 0-8                        +── 700MB threshold
       +── implicit thread sync              +── BSTaskManagerThread guard (TES+0x77c)
                                             +── Two-hook architecture (defer to AI join)
                                             +── Loading state counter
                                             +── PreDestruction Protocol
                                             +── FindCellToUnload x20
                                             +── HeapCompact trigger (stages 0-2)
```

---

# PART 2: THE GAME ENGINE

---

## Chapter 1: Memory Architecture

> **TL;DR:** FNV uses a singleton MemoryHeap with a Small Block Manager (SBM) for pool
> allocation and CRT malloc as fallback. The 500MB budget is both a memory limit and
> an implicit synchronization mechanism.

### Allocator Functions

| Address | Name | Convention | Description |
|---------|------|------------|-------------|
| `0x00AA3E40` | GameHeap::Allocate | thiscall | Main entry point (HOOKED) |
| `0x00AA4060` | GameHeap::Free | thiscall | Main free (HOOKED) |
| `0x00AA4150` | GameHeap::Realloc1 | thiscall | Realloc variant 1 (HOOKED) |
| `0x00AA4200` | GameHeap::Realloc2 | thiscall | Realloc variant 2 (HOOKED) |
| `0x00AA44C0` | GameHeap::Msize | thiscall | Size query (HOOKED) |
| `0x00AA4290` | FallbackAlloc | cdecl | 39 bytes, calls CRT `_malloc()` |
| `0x00AA42C0` | FallbackFree | cdecl | 25 bytes, calls CRT `_free()` |

### Allocation Flow

```
  GameHeap::Allocate(size)
       |
       +── size <= SBM_THRESHOLD?
       |     YES ──> SBM_GetPool(size) ──> SBM_ArenaAlloc(pool)
       |                                        |
       |                                   success ──> return ptr
       |                                   fail ──────> fall through
       |     NO ───+
       |           |
       v           v
  FallbackAlloc(size) ──> _malloc(size)
       |
       +── success ──> return ptr
       +── fail ──────> HeapCompact retry loop (stages 0-8, up to 15000x)
```

### Small Block Manager (SBM)

The SBM divides memory into fixed-size arenas, each serving a specific size class.

| Address | Name | Convention | Description |
|---------|------|------------|-------------|
| `0x00AA4960` | SBM_GetPool | cdecl | 238 bytes, finds pool for size |
| `0x00AA6AA0` | SBM_ArenaAlloc | fastcall | 462 bytes, allocate from arena |
| `0x00AA6C70` | SBM_ArenaFree | thiscall | 138 bytes, free to arena |
| `0x00AA45A0` | FindAllocator | thiscall | 99 bytes, resolve allocator |
| `0x00AA4610` | FindAllocator2 | thiscall | 137 bytes, resolve allocator |

Since mimalloc handles all allocations, most SBM functions are RET-patched
(see [Chapter 10](#chapter-10-sbm-patches)).

### The 500MB Budget as Synchronization

The original 500MB budget was not just a memory limit. When the heap filled up,
HeapCompact ran on the main thread, which naturally serialized with AI threads
(Stage 5 is main-thread-only, Stage 8 makes non-main threads sleep). By replacing
the allocator with mimalloc's larger address space, we removed this implicit
synchronization. The pressure relief system is our replacement.

---

## Chapter 2: The Main Loop

> **TL;DR:** The main loop (`0x0086E650`, 2272 bytes, fastcall) runs once per frame.
> Understanding the exact sequence is essential for knowing where cleanup hooks are safe.

### Frame Flow

```
  FUN_0086e650 (MainLoop) -- ONE FRAME
  |
  |  0x0086e897: FUN_00c3dbf0              -- IOManager task processing
  |  0x0086e987: FUN_004556d0              -- Game's own PDD
  |  0x0086eac9: FUN_00878080              -- HeapCompact stages 0-2
  |  0x0086eadf: FUN_00868850              -- Per-frame queue drain
  |
  |  ============ AI DISPATCH ==================
  |  0x0086ec78: FUN_008c80e0              -- AI dispatch prep
  |  0x0086ec87: FUN_008c78c0              -- AI threads START (DAT_011dfa19 = 1)
  |
  |  ============ RENDER + HOOK 1 ==============
  |  0x0086ede8: FUN_0086ff70              -- Render
  |  0x0086edf0: FUN_008705d0              -- HOOK 1: pressure detect + defer
  |
  |  ============ AI JOIN + HOOK 2 =============
  |  0x0086ee4e: FUN_008c7990              -- HOOK 2: AI join + deferred unload
  |                                           (DAT_011dfa19 = 0)
  |
  |  ============ POST-AI ======================
  |  0x0086ee62: FUN_0086f6a0              -- Post-AI cleanup
  |
  |  END FRAME
```

### AI Thread Activity Windows

```
  Frame timeline:
  ──────────────────────────────────────────────────────────────────────>
  |            |            |            |          |          |        |
  HeapCompact  QueueDrain   AI START    RENDER     HOOK 1     HOOK 2   END
  0x0086eac9   0x0086eadf  0x0086ec87  0x0086ede8 0x0086edf0 0x0086ee4e

  AI threads:   IDLE────────|ACTIVE──────────────────────────|IDLE─────
                             ^                                ^
                          dispatch                       join+unload
                          DAT_011dfa19=1                 DAT_011dfa19=0
```

**Key Takeaway:** AI threads are ACTIVE from dispatch (0x0086ec87) until join (0x0086ee4e). Hook 1 detects pressure and defers cell unloading via the deferred_unload flag. Hook 2 wraps FUN_008c7990 -- after the original joins AI threads, it runs the deferred destruction protocol. This ensures cell unloading ONLY happens when AI threads are idle.

---

## Chapter 3: Thread Model

> **TL;DR:** FNV has three thread groups that matter: the main thread (frame loop,
> render, PDD), AI threads (raycasting, pathfinding via Windows Events), and the IO
> thread (async texture loading via lock-free queue). PPL task groups are audio only.

### AI Linear Task Threads

FNV uses 2 dedicated AI threads ("AI Linear Task Thread 1" and "2").

**Synchronization:** Windows Events + Semaphores -- NOT PPL. The main thread dispatches
via `SetEvent` and waits via `WaitForSingleObject`. This is entirely separate from
the PPL Concurrency Runtime used for audio.

**AI Thread Main Loop** (`0x008C7720`, 111 bytes, fastcall):

```
  while (!shutdown) {
      WaitForSingleObject(event, INFINITE);     // blocked here most of the time
      if (!shutdown) {
          vtable[4]();                           // execute task
          ReleaseSemaphore(semaphore, 1, 0);     // signal completion
      }
  }
```

**Dispatch and Wait:**

```
  Main Thread                          AI Thread(s)
  ───────────                          ────────────
       |                                    |
       |  AI_Dispatch (0x008C79E0)          |
       |  SetEvent(handles[group][phase])   |
       | ──────────────────────────────────>|
       |                                    |  Execute vtable[4]()
       |                                    |   -> AITask_FrameUpdate
       |                                    |      -> FUN_0096c330 (raycasting)
       |                                    |      -> FUN_0096cb50 (AI processing)
       |  AI_Wait (0x008C7A70)              |
       |  WaitForSingleObject(semaphore)    |  ReleaseSemaphore()
       |<──────────────────────────────────|
```

**Critical finding:** AI threads do NOT call `GameHeap::Allocate` during raycasting
(verified at call-depth 2). They access `hkBSHeightFieldShape` objects directly from
loaded cells. An allocation-barrier approach for AI synchronization will not work.

### IO Thread

The `BSTaskManagerThread` (`0x00C42DA0`) processes async IO tasks via
`LockFreeQueue<IOTask>`. Tasks are dequeued with `InterlockedCompareExchange`-based
state transitions (state 1->3). Between dequeue and completion, the IO thread holds
a raw pointer to the task object -- this is why the quarantine exists.

### PPL Task Groups (Audio Only)

`DAT_011DD5BC` and `DAT_011DD638` are `Concurrency::task_group` objects for audio
streaming. They are drained by `FUN_008324e0` (the music system).

**`FUN_008324e0` is the MUSIC system, NOT Havok.** This was a major source of
confusion during analysis. The PPL task groups are audio groups. Draining them
has zero effect on AI threads.

### Havok Memory System

Havok's memory allocator (`hkFreeListAllocator` at `0x01204454`, `hkLargeBlockAllocator`
RTTI `0x010D7C34`) has ZERO direct references in game code. All Havok allocations go
through Bethesda's wrapper which calls `GameHeap::Allocate` (`FUN_00aa3e40`) and
`GameHeap::Free` (`FUN_00aa4060`). This means our quarantine covers 100% of Havok
allocations. Confirmed by:

- `bhkCollisionObject_dtor` calls `FUN_00aa4060` (`GameHeap::Free`)
- `hkWorld_RemoveEntry` (`FUN_00c41fe0`) calls `FUN_00aa4060`
- `hkAllocate_Dispatcher` (`FUN_00c3e1b0`) dispatches through vtable to `GameHeap`

**Havok OOM retry loop:** `hkMemory_Manager` (`FUN_00c3dfa0`, 513 bytes) has an internal
retry loop with `Sleep(0x32)` (50ms sleep) when allocation fails. It keeps retrying until
memory becomes available. At the 32-bit VA ceiling (~1.8GB), this retry eventually fails,
leaving Havok's internal state corrupted. The next broadphase raycast (pathfinding or AI)
then crashes.

---

## Chapter 4: Object Lifecycle

> **TL;DR:** Game objects are never freed immediately. They are queued into 6 typed
> PDD queues and processed at safe frame synchronization points. Each queue targets
> a different object type and has different thread-safety constraints.

### ProcessDeferredDestruction (PDD)

**Address:** `0x00868D70` | 1037 bytes | cdecl

```rust
unsafe extern "C" fn ProcessDeferredDestruction(blocking: u8);
// blocking=0: EnterCriticalSection (waits)
// blocking=1: TryEnterCriticalSection (skip if busy)
```

The engine queues objects for destruction instead of freeing immediately because
multiple subsystems hold live pointers concurrently:

- **Render pipeline** caches NiNode/BSTreeNode pointers in draw lists across frames
- **AI threads** hold Havok collision shape pointers for raycasting
- **IO Manager** holds QueuedTexture pointers during async loading

### Destruction Queues

| Bit | Queue Address | Destructor | Content | Safety from post-render |
|-----|---------------|------------|---------|-------------------------|
| 0x10 | DAT_011DE828 | Queue flush | Pending form deletions | SAFE |
| 0x08 | DAT_011DE808 | FUN_00418d20(1) | NiNode / BSTreeNode | UNSAFE without protocol |
| 0x04 | DAT_011DE910 | FUN_00418e00(1) | Texture/material refs | UNSAFE without protocol |
| 0x02 | DAT_011DE888 | FUN_00868ce0 | Animation/controller | SAFE |
| 0x01 | DAT_011DE874 | vtable+0x10(1) | Generic ref-counted | UNSAFE without protocol |
| 0x20 | DAT_011DE924 | FUN_00401970 | Havok physics wrappers | UNSAFE without protocol |

**With the Pre-Destruction Protocol** (hkWorld_Lock + SceneGraphInvalidate), ALL queues
become safe. See [Chapter 7](#chapter-7-the-pre-destruction-protocol).

### Why Each Unsafe Queue Crashes (Without Protocol)

**Queue 0x08 (NiNodes/BSTreeNode):**
BSTreeManager at `DAT_011D5C48` caches BSTreeNode pointers across frames.
Destroying nodes leaves stale draw list pointers. Next render dereferences freed memory.

**Queue 0x20 (Havok physics):**
AI threads raycast via `FUN_0096c330` against `hkBSHeightFieldShape` from loaded cells.
Destroying wrappers frees shapes while AI threads hold live references.

**Queue 0x04 (Textures):**
IOManager loads textures via `LockFreeQueue<IOTask>`. Destroying texture refs
invalidates objects the IO system is actively processing.

**Queue 0x01 (Generic):**
Calls virtual destructor on arbitrary NiRefObject subclasses. Combined with
other unsafe operations, causes cascading failures.

### PDD Synchronization

- **Global lock:** `DAT_011DE8E0` critical section
- **Reentrancy guard:** `DAT_011DE958` prevents recursive calls
- **Queue skip mask:** `DAT_011DE804` -- bits set = queues skipped
- **TLS deferred flag:** `_tls_index + 0x298` -- flag=1 means deferred (default), flag=0 means immediate

**The TLS flag is critical.** Setting it to 0 causes objects to be freed immediately
during FindCellToUnload, bypassing deferred queues entirely. This makes our PDD
skip mask useless. **Always keep TLS flag at 1.**

### Callers of PDD (6 total)

| Address | Name | Notes |
|---------|------|-------|
| `0x0045DFE0` | Big update function (8357 bytes) | From FUN_00450770 |
| `0x0084C5A0` | Savegame/load related (1572 bytes) | From FUN_0084be40 |
| `0x00866A90` | HeapCompact (stages 4 and 5) | Memory pressure recovery |
| `0x008774A0` | CellTransitionHandler (561 bytes) | Cell transition cleanup |
| `0x00878250` | DeferredCleanupSmall (86 bytes) | 5 callers (see protocol chapter) |
| `0x0093BEA0` | CellTransition_Conditional (832 bytes) | Cell transition path |

### Cell Transition Handler

**Address:** `0x008774A0` | 561 bytes | thiscall

This function orchestrates cleanup during cell transitions (entering buildings, fast
travel). It does NOT use the Pre-Destruction Protocol because it quiesces the entire
game state first:

```
  CellTransitionHandler (0x008774a0)
  |
  |  1. Save state (FUN_004f1540, FUN_004f15a0)
  |  2. Wait for player ready (FUN_00877700, 1000ms timeout)
  |  3. Set render flags (FUN_007d6bd0)
  |  4. Pre-cleanup (FUN_00453a70)
  |  5. Stop MUSIC system (FUN_008324e0(0)) -- NOT Havok!
  |       -> Drains PPL audio task queues
  |  6. Process player state
  |  7. Force unload cell (FUN_004539a0, FUN_007037c0, FUN_0061cc40)
  |  8. BLOCKING PDD: FUN_00868d70(0)
  |  9. BLOCKING async flush: FUN_00c459d0(0)
  | 10. Restore state
```

### FindCellToUnload

**Address:** `0x00453A80` | 824 bytes | fastcall

```rust
unsafe extern "fastcall" fn FindCellToUnload(manager: *mut c_void) -> u32;
// Returns 1 if a cell was found and destroyed, 0 otherwise
```

Parameter: TES manager singleton (`DAT_011DEA10`).

```
  FindCellToUnload(manager)
  |
  |  PHASE 1: Buffer cells (manager+0x38) -- iterate backwards
  |    Check FUN_004511e0(cell) -- loadable?
  |    Check FUN_00557090(cell) -- in use?
  |
  |  PHASE 2: Grid cells (manager+0x3c) -- exclude player cell
  |    Same checks
  |
  |  Found? -> FUN_00462290(cell) -> return 1
  |  None?  -> return 0
```

**What DestroyCell frees:** BSTreeNodes, NiTriShapes, hkBSHeightFieldShape,
bhkCollisionObject, landscape textures, placed object references, navmesh data.

**Safe post-render** because SpeedTree draw lists have been consumed, physics objects
are queued for deferred destruction, and AI threads don't index cell arrays directly.
**Not safe pre-render** because SpeedTree caches raw BSTreeNode pointers.

---

## Chapter 5: HeapCompact

> **TL;DR:** HeapCompact is a multi-stage state machine invoked on allocation failure.
> Stages 0-2 do lightweight cleanup. Stages 4-5 are aggressive (full PDD, cell unloading).
> Stage 8 is a non-main-thread sleep loop. We trigger stages 0-2 from pressure relief
> but exclude 3-5 because they are incompatible with mimalloc.

**Address:** `0x00866A90` | 602 bytes | thiscall

```rust
unsafe extern "thiscall" fn HeapCompact(
    this: *mut c_void,
    param_1: u32,
    stage: i32,
    done_flag: *mut u8,
) -> i32;
```

### Stage Diagram

```
  HeapCompact(stage)
  |
  +-- Stage 0: RESET
  |     Set DAT_011de70c = 0
  |     If main thread: ProcessPendingCleanup(manager, 0)
  |
  +-- Stage 1: SBM ARENA TEARDOWN
  |     DeallocateAllArenas() [RET-patched -> no-op]
  |
  +-- Stage 2: CELL/RESOURCE CLEANUP
  |     BSA/texture cache cleanup via FUN_00650a30
  |
  +-- Stage 3: ASYNC QUEUE FLUSH
  |     FUN_00c459d0(1) with TryEnterCriticalSection
  |     Non-blocking IO queue drain
  |
  +-- Stage 4: DEFERRED DESTRUCTION           *** EXCLUDED ***
  |     Full PDD(1) -- processes queue 0x20 (Havok)
  |     Unsafe: AI threads may be active from post-render
  |
  +-- Stage 5: CELL UNLOADING                 *** EXCLUDED ***
  |     Main thread only
  |     Sets TLS[0x298] = 0 (immediate destruction)
  |     Incompatible with mimalloc (freed memory overwritten)
  |
  +-- Stage 6: GLOBAL CLEANUP
  |     PurgeUnusedArenas [RET-patched -> no-op]
  |
  +-- Stage 7: GIVE UP SIGNAL
  |     Main thread: signal recovery failed
  |
  +-- Stage 8: NON-MAIN THREAD RETRY
        Sleep(1) loop, up to 15000 iterations
```

### Main Thread Detection

HeapCompact checks `GetCurrentThreadId() == *(DAT_011dea0c + 0x10)`.
Stages 5 and 7 are main-thread-only.

### HeapCompact Trigger Mechanism

The game reads `*(heap + 0x134)` via `FUN_00878110`. Writing value N to
`0x011F636C` (= `0x011F6238 + 0x134`) causes stages 0..N to run from
FUN_00878080 at line 379 on the next frame. `FUN_00878130` resets it to 0
after completion. One integer write re-enables the game's native cleanup.

**Key Takeaway:** We trigger stages 0-2 by writing `2` to `0x011F636C`.
Stage 3 is excluded because its async flush from check() ran on any thread without synchronization, causing NiPixelData/NiSourceTexture UAF.
Stages 4-5 are excluded because Stage 4's full PDD frees Havok wrappers
during potential AI post-render activity, and Stage 5's TLS=0 mode causes
BSTreeNode data to be immediately overwritten by mimalloc (the original SBM
kept "zombie" data intact until arena purge).

**Note:** check() (called every 50K allocs from any thread) no longer writes the trigger. It only sets `requested=true`. The trigger is written from relieve() on the main thread after the full destruction protocol.

---

# PART 3: THE REPLACEMENT

---

## Chapter 6: Hook Architecture

> **TL;DR:** We hook at `FUN_008705d0` (line 486, post-render). This is the only safe
> position -- render has consumed SpeedTree draw lists. AI threads are still active
> at this position — we join them via FUN_008c7990 before cell unloading. Every other tested position crashed.

### Hook Position Analysis

```
  Frame Timeline with Hook Positions Tested:

  ──[setup]──[line 273]──[line 379]──[line 431]──[line 440]──[line 485]──[line 486]──[line 497]──
              ^                       ^            ^           ^           ^
              |                       AI START     AI DONE     |           |
              FUN_0086f940                                FUN_0086ff70  FUN_008705d0
              CRASH: BSTreeNode                   CRASH: BSTreeNode    SAFE (chosen)
```

| Position | Address | Line | Result |
|----------|---------|------|--------|
| PreAI_CellHandler | `0x0086F940` | 273 | CRASH -- BSTreeNode UAF, render uses cached tree draw lists |
| PreRender_Maintenance | `0x0086FF70` | 485 | CRASH -- BSTreeNode UAF, render hasn't consumed tree data |
| RenderUpdate | `0x008705D0` | 486 | SAFE for cell unloading; render done, trees consumed |

### What the Hook Does

```
  OUR_HOOK(param_1)
       |
       +-- Call original FUN_008705d0(param_1)     // render first
       |
       +-- Check thread-local allocation counter
       |     counter < 50,000?  -> return
       |     counter >= 50,000? -> reset, proceed
       |
       +-- Query process commit size
       |     commit < 700MB?    -> return
       |
       +-- Check cooldown timer
       |     elapsed < 2000ms?  -> return
       |
       +-- === PRESSURE RELIEF ===
       |     (see Chapter 8)
```

### Two-Hook Architecture for Cell Unloading

Cell unloading cannot run from Hook 1 (FUN_008705d0) on multi-threaded systems because AI threads are active at that position. FUN_008c7990 (AI thread join) cannot be called directly -- it consumes a counting semaphore (WaitForSingleObject) that the game's own join at 0x0086ee4e needs. Calling it causes deadlock/corruption on the next frame.

Solution: two hooks with a deferred flag.

```
Hook 1 (FUN_008705d0, post-render — existing):
  → on_frame_tick() (quarantine, pressure detection)
  → Check DAT_011dfa19 (AI active flag):
    - If 1 (AI active): set deferred_unload flag, skip cell unloading
    - If 0 (AI idle): run destruction protocol directly
  → HeapCompact trigger + mi_collect always run

Hook 2 (FUN_008c7990, AI thread join — NEW):
  → Call original (AI threads join, DAT_011dfa19 = 0)
  → Check deferred_unload flag:
    - If set: re-check TES+0x77c (BSTaskManager guard)
    - Run full destruction protocol
    - Clear flag
```

DAT_011dfa19 lifecycle:
- Set to 1 by FUN_008c78c0 (AI Start, called at 0x0086ec87)
- Set to 0 by FUN_008c7990 (AI Join, called at 0x0086ee4e)
- At Hook 1 position: 1 when AI threads dispatched, 0 when not

Hook 2 only fires on multi-threaded systems (processor count > 1). On single-threaded systems, AI threads don't exist, DAT_011dfa19 stays 0, and Hook 1 handles everything directly.

### Hook Rollback Guard

install_game_heap_hooks() uses a HookGuard that tracks all enabled hooks. If any hook enable fails, the guard's Drop impl disables all previously-enabled hooks in reverse order, preventing split-heap corruption (e.g., alloc→mimalloc but free→original SBM). SBM patches are applied AFTER hook commit — they only execute when all hooks are confirmed working.

---

## Chapter 7: The Pre-Destruction Protocol

> **TL;DR:** ALL 5 normal-gameplay PDD callers wrap cleanup in a 3-step protocol:
> (1) lock Havok world + invalidate scene graph, (2) run PDD + async flush,
> (3) unlock + restore state. This is THE critical discovery that makes all PDD
> queues safe from our hook. Without it, AI threads crash on Havok shapes and
> SpeedTree crashes on stale draw lists.

### Step 0: Loading State Counter (DAT_01202d6c)

**Address:** `0x01202D6C`
**Type:** `i32` (InterlockedIncrement/Decrement counter)
**Rust:** `AtomicI32::fetch_add(1, AcqRel)` / `AtomicI32::fetch_sub(1, AcqRel)`

When this counter is > 0, the game is in a loading/destruction state. Actor processing during cell destruction (FUN_0054af40 → FUN_0096e150) skips event dispatching. This prevents NVSE plugins (JohnnyGuitar HandlePLChangeEvent, Stewie's Tweaks LowProcess__Func011F) from firing event handlers on mid-destruction objects (refcount 0, partially freed).

**Note:** Ghidra audit shows DAT_01202d6c has only 4 references, all in FUN_0043b2b0. No vanilla game code checks this counter for event suppression. The suppression behavior is implemented by NVSE plugins (JohnnyGuitar, Stewie's Tweaks) that check this counter in their event handlers.

Discovery: DestroyCell (FUN_00462290) calls FUN_0044ada0(1) at start and FUN_0044ada0(0) at end — this sets DAT_01202df0 (a separate destruction-in-progress flag). But the EVENT SUPPRESSION is controlled by DAT_01202d6c, set by FUN_0043b2b0:
```c
void FUN_0043b2b0(char param_1) {
    if (param_1 == 0)
        InterlockedDecrement(&DAT_01202d6c);
    else
        InterlockedIncrement(&DAT_01202d6c);
    if (DAT_01202d6c < 0) DAT_01202d6c = 0;
}
```

The game's PDD caller FUN_004556d0 sets this to 1 before cleanup. CellTransitionHandler runs during loading screens where this is already > 0. HeapCompact Stage 5 runs in the allocation retry loop where events don't fire naturally.

### Full Protocol Sequence

The complete pre-destruction protocol with the loading state counter:
```
0. InterlockedIncrement(DAT_01202d6c)  — enter loading state (suppress events)
1. PreDestructionSetup                  — hkWorld_Lock + SceneGraphInvalidate
2. FindCellToUnload × 20               — cells freed (quarantine holds zombies)
3. DeferredCleanupSmall                 — full PDD + blocking async flush
4. PostDestructionRestore               — hkWorld_Unlock + restore
5. InterlockedDecrement(DAT_01202d6c)  — exit loading state
6. HeapCompact trigger (stages 0-2)
7. mi_collect(false)
```

### Discovery (Protocol Pattern)

Every caller of `DeferredCleanupSmall` (`0x00878250`) follows an identical pattern.
The protocol locks Havok to block AI raycasting, and invalidates the scene graph to
rebuild SpeedTree draw lists, creating a safe window for full PDD.

### The Three Steps

```
  STEP 1: PreDestructionSetup (0x00878160, 113 bytes)
  +---------------------------------------------------------------+
  |  hkWorld_Lock(DAT_01202d98)          // block AI Havok access  |
  |  Save cell lock state to state+5                               |
  |  Optionally flush texture queue      // FUN_004a0370           |
  |  Save cleanup rate to state+8                                  |
  |  SetDistanceThreshold(INT_MAX)       // DAT_011a95fc = MAX     |
  |  SceneGraphInvalidate()              // FUN_00703980            |
  |    -> FUN_007160b0                   // rebuild draw lists     |
  |    -> ProcessPendingCleanup          // flush cleanup queue    |
  +---------------------------------------------------------------+
                          |
                          v
  STEP 2: DeferredCleanupSmall (0x00878250, 86 bytes)
  +---------------------------------------------------------------+
  |  ProcessDeferredDestruction(1)       // ALL queues, non-block  |
  |  FUN_00b5fd60(mgr)                  // flush resources         |
  |  AsyncQueueFlush(0)                  // BLOCKING IO drain      |
  |  Optional BSA cleanup                                          |
  |  Lock release                                                  |
  |  ProcessPendingCleanup               // FUN_00452490            |
  +---------------------------------------------------------------+
                          |
                          v
  STEP 3: PostDestructionRestore (0x00878200, 80 bytes)
  +---------------------------------------------------------------+
  |  Calls FUN_00a5b460, FUN_00aa7030 (GlobalCleanup, RET-patched)|
  |  Restore cell manager lock from state+5                        |
  |  Restore distance threshold from state+8                       |
  |  hkWorld_Unlock(DAT_01202d98)        // unblock AI access      |
  +---------------------------------------------------------------+
```

**PostDestructionRestore confirmed:** 80 bytes, state struct is 12 bytes.
Game callers use `local_10[5] + local_b` pattern. Calls hkWorld_Unlock
(`FUN_00c3e340`) at the end.

### hkWorld_RemoveEntry (FUN_00c41fe0, 122 bytes)

```c
void FUN_00c41fe0(void *this, undefined4 *param_1) {
    (**(code **)(*(int *)this + 0x28))(*param_1, param_1[1]);  // removes from broadphase
    FUN_00aa4060(&DAT_011f6238, param_1);                       // GameHeap::Free
}
```

The vtable+0x28 call removes the entity from the Havok world's broadphase BEFORE
freeing memory. This is called during PDD queue 0x20 processing inside our
hkWorld_Lock, so no concurrent raycasting can access stale broadphase entries.

### Function Signatures

```rust
/// Lock Havok world, invalidate scene graph, prepare for safe PDD.
/// `state`: caller-allocated buffer (12+ bytes) for saving/restoring state.
unsafe extern "C" fn PreDestructionSetup(
    state: *mut c_void,
    flush_textures: u8,
    param_3: u8,
    save_cell_lock: u8,
);

/// Restore state saved by PreDestructionSetup.
unsafe extern "C" fn PostDestructionRestore(state: *mut c_void);

/// PDD(1) + AsyncFlush(0) + ProcessPendingCleanup.
unsafe extern "C" fn DeferredCleanupSmall(param_1: u8);
```

### All 5 Callers Follow the Protocol -- Proof

| # | Caller | Name | Pattern |
|---|--------|------|---------|
| 1 | `0x004556D0` | Big update (3611 bytes) | `FUN_00878160(local_48,1,1,1)` ... `FUN_00878250(local_43)` ... `FUN_00878200(local_48)` |
| 2 | `0x008782B0` | CellTransition_SafePoint (130 bytes) | `FUN_00878160(local_10,1,1,1)` ... `FUN_00878250(local_b)` ... `FUN_00878200(local_10)` |
| 3 | `0x0093CDF0` | Fast travel (1779 bytes) | `FUN_00878160(local_48,1,1,1)` ... `FUN_00878250(local_43)` ... `FUN_00878200(local_48)` |
| 4 | `0x0093D500` | Cell load (352 bytes) | `FUN_00878160(local_18,0,1,0)` ... `FUN_00878250(local_13)` ... `FUN_00878200(local_18)` |
| 5 | `0x005B6CD0` | Cleanup helper (70 bytes) | `FUN_00878160(local_10,1,1,1)` ... `FUN_00878250(local_b)` ... `FUN_00878200(local_10)` |

### Why CellTransitionHandler Doesn't Need the Protocol (WRONG — See Bug Fix Below)

~~CellTransitionHandler (`0x008774A0`) quiesces the entire game state first -- AI threads
are stopped, render is stopped, IO is blocked.~~ This was our original assumption but it
is WRONG. CellTransitionHandler runs at main loop line 273, BEFORE AI threads are idle.
AI threads from the previous frame's post-render signal may still be raycasting. See
[CellTransitionHandler Engine Bug Fix](#celltransitionhandler-engine-bug-fix) below.

### Why HeapCompact Stage 5 Doesn't Need the Protocol (in the original game)

Stage 5 sets TLS[0x298] = 0 for immediate destruction. The original SBM allocator
keeps freed memory as "zombies" (data intact until arena purge), so BSTreeNode data
remains readable after free. With mimalloc, `mi_free()` returns memory immediately
and data is overwritten, breaking this assumption.

### hkWorld_Lock Mechanism

The Havok world singleton at `DAT_01202D98` uses InterlockedIncrement/Decrement
on `world+0x48` with spin-wait on `world+0x44`:

| Offset | Type | Description |
|--------|------|-------------|
| +0x44 | LONG | Worker count (spin-wait target) |
| +0x48 | LONG | Lock count (InterlockedIncrement/Decrement) |
| +0x4C | uint | Number of physics workers |
| +0x50 | ptr | Array of worker thread handles |
| +0x7C | ptr | Lock callback |
| +0x80 | ptr | Unlock callback |

### SceneGraphInvalidate Is Exterior Only

`FUN_009373f0` checks byte at offset 0 of the scene root -- returns 0 for interior
cells. SceneGraphInvalidate (`FUN_00703980`) skips the cull/update for interiors.
This is safe from post-render because render has already consumed the draw lists.

### Why the Per-Frame Drain Doesn't Need the Protocol

The per-frame queue processor `FUN_00868850` runs at line ~802, BEFORE AI dispatch
and BEFORE render. AI threads are idle, render hasn't built draw lists, and the
function drains small batches (10-20 items). No concurrent system holds references.

### CellTransitionHandler Engine Bug Fix

CellTransitionHandler (FUN_008774a0, 561 bytes) is the ONE function in the game that calls BLOCKING PDD (FUN_00868d70 with param=0) WITHOUT locking the Havok world first.

**The bug:** CellTransitionHandler runs at main loop line 273 (via FUN_0086f940 → FUN_0093bea0). AI threads from the PREVIOUS frame's post-render signal (line 497) may still be active doing physics raycasting. The BLOCKING PDD frees hkpSimulationIsland data while AI threads are reading it → EXCEPTION_ACCESS_VIOLATION on AI Linear Task Thread.

**Why the original game doesn't crash:** SBM keeps zombie data. The AI thread reads freed-but-intact simulation island data → continues without crashing. With mimalloc, freed data is recycled → AI thread reads garbage → crash.

**All PDD callers comparison:**

| Caller | PDD mode | hkWorld_Lock? | Safe? |
|--------|----------|---------------|-------|
| 5 normal PDD callers | try-lock (1) | YES (PreDestructionSetup) | YES |
| DeferredCleanupSmall | try-lock (1) | YES (called inside protocol) | YES |
| HeapCompact Stage 4/5 | try-lock (1) | NO but threads sleeping (Stage 8) | YES |
| CellTransition_Conditional | try-lock (1) | NO but non-blocking | OK |
| Save/load functions | blocking (0) | NO but during loading (AI idle) | OK |
| **CellTransitionHandler** | **blocking (0)** | **NO — AI may be active** | **BUG** |

**The fix:** We inline-hook CellTransitionHandler and wrap it with hkWorld_Lock/Unlock + loading state counter:

```rust
pub(super) unsafe extern "thiscall" fn hook_cell_transition_handler(
    this: *mut c_void, param_1: u8,
) {
    // Lock Havok world — blocks AI raycasting
    let world = *(0x01202D98 as *const *mut c_void);
    if !world.is_null() {
        hkWorld_Lock(world);  // FUN_00c3e310
    }
    // Suppress NVSE events
    loading_counter.fetch_add(1, AcqRel);

    original(this, param_1);  // game's CellTransitionHandler

    loading_counter.fetch_sub(1, AcqRel);
    if !world.is_null() {
        hkWorld_Unlock(world);  // FUN_00c3e340
    }
}
```

Hook address: 0x008774A0 (standard prologue: PUSH EBP; MOV EBP,ESP; SUB ESP,0x20).
Only 1 caller: FUN_0086a850 at 0x0086b664.

---

## Chapter 8: Pressure Relief System

> **TL;DR:** When process commit exceeds 700MB, we run the full Pre-Destruction Protocol:
> lock Havok, invalidate scene graph, unload up to 20 cells, run full PDD,
> trigger HeapCompact stages 0-2 for next frame. Cooldown is 2 seconds.
> Thread-local counters avoid atomic contention on the hot path.

### Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| THRESHOLD | 700 MB | Commit size that triggers pressure check |
| MAX_CELLS_PER_CYCLE | 20 | Maximum cells unloaded per relief cycle |
| COOLDOWN_MS | 2000 ms | Minimum time between relief cycles |
| Check interval | 50,000 | Allocations between pressure checks (thread-local) |

### Why Thread-Local Counters

Per-allocation `AtomicU32::fetch_add` causes 5-7 FPS regression from CPU cache line
bouncing. Thread-local counters have zero cross-core contention.

### Full Relief Sequence

```
  PRESSURE RELIEF (two-hook architecture):
  |
  HOOK 1 (FUN_008705d0, post-render):
  |
  +-- Check commit > 700MB threshold
  +-- Check cooldown (2000ms)
  +-- Check TES+0x77c (BSTaskManagerThread guard)
  |     If != -1: skip this cycle
  |
  +-- Check DAT_011dfa19 (AI active flag)
  |     If 1 (multi-threaded, AI active):
  |       Set deferred_unload = true
  |       Skip cell unloading → proceed to HeapCompact trigger
  |     If 0 (single-threaded or AI not dispatched):
  |       Run destruction protocol directly (steps 0-5 below)
  |
  +-- HeapCompact trigger: *(0x011F636C) = 2
  +-- mi_collect(false)
  |
  HOOK 2 (FUN_008c7990, AI thread join — multi-threaded only):
  |
  +-- Call original (waits for AI threads via WaitForSingleObject)
  +-- Check deferred_unload flag
  |     If not set: return
  +-- Re-check TES+0x77c
  +-- Run destruction protocol (steps 0-5):
  |
  |  Step 0: InterlockedIncrement(DAT_01202d6c) — loading state
  |  Step 1: PreDestructionSetup — hkWorld_Lock + SceneGraphInvalidate
  |  Step 2: FindCellToUnload × 20
  |  Step 3: DeferredCleanupSmall — PDD + async flush
  |  Step 4: PostDestructionRestore — hkWorld_Unlock
  |  Step 5: InterlockedDecrement(DAT_01202d6c)
```

### Why Quarantine Is NOT Flushed During Pressure Relief

The quarantine is NOT flushed after DeferredCleanupSmall. Although the blocking async flush drains currently-queued IO tasks, BSTaskManagerThread can immediately pick up NEW tasks (e.g., QueuedTexture, ExteriorCellLoaderTask) that reference memory still in quarantine. Flushing would free that memory via mi_free, causing use-after-free. The 30-frame natural expiration handles cleanup safely.

### AsyncQueueFlush Mechanism

`FUN_00c459d0` (172 bytes, cdecl): Acquires `DAT_01202E40` lock (blocking when
param=0), enters critical section `lpCriticalSection_011f4380`, calls `FUN_00c46080`
and `FUN_00c45a80` to drain the IO queue, decrements `DAT_01202E44` counter.

### DeferredCleanupSmall Full Chain

PDD(1, try-lock) -> `FUN_00b5fd60` -> AsyncFlush(0, BLOCKING) -> optional BSA
cleanup -> lock release -> ProcessPendingCleanup. The BLOCKING async flush drains
all stale IO tasks.

### Multi-Layer Approach

**Layer 1: Post-render protocol-based cleanup (FUN_008705d0 hook)**

The primary mechanism described above.

**Layer 2: Boosted per-frame NiNode drain (FUN_00868850 hook)**

At line ~802, BEFORE AI dispatch and render. Under pressure, call the per-frame
queue processor 20x total (1 normal + 19 extra). Stops when queue 0x08 empties
to avoid over-draining Havok queue 0x20. Safe because AI threads are idle and
render hasn't built draw lists.

**Layer 3: HeapCompact trigger**

Writing `2` to `0x011F636C` triggers stages 0-2 next frame: reset, SBM teardown
(no-op), BSA/texture cache cleanup.

### mimalloc Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Reserve | 512 MB | Pre-reserved VA space |
| purge_delay | 0 | Immediate decommit of freed pages |
| retry_on_oom | 0 | Let pressure relief handle OOM |
| eager_commit | 0 | Do not eagerly commit reserved pages |

### Remaining Limitation: 32-bit VA Ceiling

Under extreme stress (max-speed flying across map), commit climbs to ~1.6-1.7GB
and eventually OOMs. This is the fundamental 32-bit limit (~1.8GB usable with LAA).

Normal gameplay is completely stable (~760MB idle, ~1.0-1.1GB moving). The OOM only
occurs under artificial extreme stress that no real player would sustain.

All PDD queues drain to 0 but commit still climbs -- the remaining growth is from
LIVE cell data (newly loaded cells) and mimalloc page fragmentation. This is
irreducible: the game loads cells faster than they can be unloaded during extreme
traversal.

---

## Chapter 9: Delayed Free Quarantine

> **TL;DR:** Per-thread ring buffers hold freed pointers for 30 frames before actual
> mi_free(). This protects the IO thread from use-after-free on QueuedTexture objects.
> No locks, no atomics, no syscalls on the hot path.

### Architecture

```
  GameHeap::Free(ptr) -- our hook
       |
       v
  Per-Thread Ring Buffer
  +--------------------------------------+
  | [frame N] [frame N] [frame N-1] ... |
  | <-- push here       pop from here -->|
  +--------------------------------------+
       |
       v (after 3 frames)
  mi_free(ptr) -- actual deallocation
```

### Design Decisions

**Per-thread ring buffers:** Zero contention on the hot path. No locks, no atomics,
no cache line bouncing.

**30-frame delay measured in frames, not wall-clock time:**
- `now_ms()` requires a syscall per free -- catastrophically expensive
- Frame-based delay aligns with the game's rendering/AI cycle
- Objects freed in frame N are safe by frame N+30

**Loading screen detection via stale push counter:**
During loading screens, no frames complete but allocation continues. If push_counter
hasn't changed for several check intervals, flush immediately to prevent OOM.

**No immediate flush after DeferredCleanupSmall:** Originally flushed quarantine immediately after PDD. Removed because BSTaskManagerThread picks up new IO tasks referencing quarantined memory between async flush and mi_free. The 30-frame natural expiration is always respected.

### Why Quarantine Protects the IO Thread

The IO thread is the most vulnerable to use-after-free:

1. It runs asynchronously via `WaitForSingleObject` on a semaphore
2. It processes `LockFreeQueue<IOTask>` entries referencing game objects
3. Tasks are dequeued with `InterlockedCompareExchange` (state 1->3)
4. Between dequeue and completion, the IO thread holds a raw pointer

```
  IO thread loop (0x00C410B0, 633 bytes):

  while (!shutdown) {
      WaitForSingleObject(event, INFINITE);
      InterlockedDecrement(count);
      task = dequeue();                              // raw pointer
      if (InterlockedCompareExchange(task+3, 3, 1) == 1) {
          vtable_process(task);                      // CRASH if freed
          vtable_complete(task);
      }
  }
```

Without quarantine: PDD destroys QueuedTexture while IO thread holds it -> NULL
vtable call (`eip = 0x00000000`).

With quarantine: memory stays valid for 30 frames, giving the IO thread time to
complete processing.

### Quarantine Coverage: Complete

Ghidra audit of 1036 callers of `GameHeap::Free` proves no bypass path exists:

- `CommonDelete(0x00401030)` calls `GameHeap::Free` -- ALL NiObject deletions
- `FallbackFree(0x00AA42C0)` is only called from inside `GameHeap::Free` body (3 calls) and one SBM destructor at shutdown
- CRT `_free` callers are all CRT internals (locale, file streams, thread data)
- Havok uses `GameHeap::Free` (`bhkCollisionObject_dtor` at line 567)

No game code bypasses the quarantine.

### Performance: Counter-Based Staleness

Early implementations called `now_ms()` or `mi_process_info()` on every free --
caused severe frame drops. The solution: increment a per-thread push counter on
each push, compare counters across frames to determine staleness.

---

## Chapter 10: SBM Patches

> **TL;DR:** SBM pool functions are RET-patched since mimalloc handles all allocations.
> Three SBM functions are left alive for pre-hook pointer cleanup. Scrap heap (sbm2)
> is separately hooked.

### RET-Patched (Disabled)

| Address | Name | Purpose |
|---------|------|---------|
| `0x00AA6840` | SBM statistics reset | SBM accounting |
| `0x00866770` | SBM config table init | Size class config |
| `0x00866E00` | SBM-related init | Subsystem init |
| `0x00866D10` | Get SBM singleton | Singleton accessor |
| `0x00AA7030` | GlobalCleanup | PurgeUnusedArenas for all pools |
| `0x00AA5C80` | DeallocateAllArenas | Bulk arena deallocation |
| `0x00AA58D0` | Sheap SBM cleanup | Scrap heap SBM interaction |

### Left Alive (Needed)

| Address | Name | Size | Why Needed |
|---------|------|------|------------|
| `0x00AA6F90` | PurgeUnusedArenas | 157 bytes | May be called for existing arenas |
| `0x00AA7290` | DecrementArenaRef | 110 bytes | Reference counting for live arenas |
| `0x00AA7300` | ReleaseArenaByPtr | 106 bytes | Pointer-based arena release |

### NOP-Patched Call Sites

| Address | Context |
|---------|---------|
| `0x0086C56F` | Heap construction double-check |
| `0x00C42EB1` | CRT heap initialization |
| `0x00EC1701` | CRT heap initialization |

### Scrap Heap (sbm2) Hooks

| Address | Name | Convention |
|---------|------|------------|
| `0x00AA53F0` | SheapInitFix | fastcall |
| `0x00AA5410` | SheapInitVar | fastcall |
| `0x00AA54A0` | SheapAlloc | fastcall |
| `0x00AA5610` | SheapFree | fastcall |
| `0x00AA5460` | SheapPurge | fastcall |
| `0x00AA42E0` | SheapGetThreadLocal | cdecl |

### sbm2 Region Overlap Bug (FIXED)

The bump allocator's `new_offset` didn't account for alignment padding.
`new_offset = old_offset + align_up(size+4, align)` was wrong -- it computed the
new offset from the old offset plus aligned total size, but the actual data
address could be shifted forward by alignment. The correct formula is
`new_offset = (data_addr + size) - start_addr`, which accounts for the actual
position of the allocated block. This caused memory corruption in the scrap heap
when consecutive allocations overlapped.

---

# PART 4: CRASH ANALYSIS

---

## Chapter 11: Crash Types and Root Causes

> **TL;DR:** Every crash we encountered falls into one of these categories. Each has
> a specific root cause and a specific fix. The Pre-Destruction Protocol eliminated
> most of them.

| Crash Type | Symptom | Root Cause | Fix |
|------------|---------|------------|-----|
| AI thread (hkBSHeightFieldShape) | EXCEPTION_ACCESS_VIOLATION on AI thread | PDD destroys heightfields while AI threads raycast | Pre-Destruction Protocol (hkWorld_Lock) |
| Render (BSTreeNode UAF) | Crash during render pass | FindCellToUnload destroys BSTreeNodes pre-render | Hook at post-render position (line 486) |
| SpeedTree post-render | C0000417, BSTreeNode RefCount:0 | PDD queue 0x08 destroys nodes; cache holds cross-frame refs | Pre-Destruction Protocol (SceneGraphInvalidate) |
| SpeedTree TLS=0 | C0000417, BSTreeNode RefCount:0 | TLS flag=0 causes immediate destruction during FindCellToUnload | Keep TLS flag at 1 (default) |
| Texture IO race | NULL vtable (eip=0x00000000), QueuedTexture on stack | PDD destroys texture refs while IOManager loads async | Quarantine system (30-frame delay) |
| mi_collect(true) race | EXCEPTION_ACCESS_VIOLATION inside psycho_nvse | Forced cross-thread segment purge races with AI allocations | Only use mi_collect(false) |
| OOM | Fatal in exception handler at ~1.8GB | 32-bit VA space exhaustion | Pressure relief system (irreducible at extreme stress) |
| Havok Broadphase OOM | EXCEPTION_ACCESS_VIOLATION on main thread, stack: PathingSearchRayCast → hkp3AxisSweep → hkLargeBlockAllocator | At 1.4-1.5GB commit, Havok's internal allocator (backed by GameHeap → mimalloc) fails at VA ceiling. Broadphase (hkp3AxisSweep) data structures corrupted from failed allocations. hkpWorldRayCaster → hkpClosestRayHitCollector crashes. | Irreducible 32-bit VA limit — cannot be fixed by allocator replacement |
| Aggressive cell unload | AI thread crash on hkBSHeightFieldShape | Cooldown < 2000ms or > 20 cells causes AI to access unloading cells | Conservative tuning (2s/20 cells) |
| Music broken | Crash on NULL music path in FUN_008300c0 | Misidentified FUN_008324e0 as Havok instead of music | Don't call FUN_008324e0(1) |
| sbm2 region overlap | Memory corruption in scrap heap | Bump allocator new_offset didn't account for alignment padding | Fixed offset calculation |
| NVSE event dispatch during cell destruction | EXCEPTION_ACCESS_VIOLATION in nvse_stewie_tweaks LowProcess__Func011F or johnnyguitar HandlePLChangeEvent | FindCellToUnload triggers actor process changes during cell destruction, which fires NVSE plugin event handlers (PLChangeEvent). These handlers access objects mid-destruction (refcount 0). | Set loading state counter DAT_01202d6c > 0 before FindCellToUnload |
| CellTransitionHandler AI thread crash (ENGINE BUG) | EXCEPTION_ACCESS_VIOLATION on AI Linear Task Thread, hkpSimulationIsland / hkScaledMoppBvTreeShape with ecx=NULL | Game's own CellTransitionHandler runs BLOCKING PDD without hkWorld_Lock. AI threads from post-render signal race with freed physics data. | Hook CellTransitionHandler, wrap with hkWorld_Lock/Unlock + loading state counter |
| AI thread join semaphore | Havok world corruption, ragdoll crash on next frame | Calling FUN_008c7990 from our hook consumes the completion semaphore; game's own join deadlocks | Two-hook architecture: defer cell unloading to Hook 2 (AI join wrapper) instead of calling join directly |

### NVSE Event Dispatch During Cell Destruction (Detail)

- **Crash:** EXCEPTION_ACCESS_VIOLATION in nvse_stewie_tweaks LowProcess__Func011F or johnnyguitar HandlePLChangeEvent
- **Stack shows:** psycho_nvse → FindCellToUnload → DestroyCell → actor cleanup → event dispatch → NVSE handler → access refcount-0 object
- **Cause:** FindCellToUnload triggers actor process changes during cell destruction, which fires NVSE plugin event handlers (PLChangeEvent). These handlers access objects mid-destruction.
- **Fix:** Set loading state counter DAT_01202d6c > 0 before FindCellToUnload. Actor processing skips event dispatching when this counter is set.
- **Why original game doesn't crash:** HeapCompact Stage 5 runs in allocation retry loop (no events). CellTransitionHandler runs during loading (counter already set).

### Final Crash Resolution Summary (Updated 2026-03-21)

| Crash | Fix | Status |
|-------|-----|--------|
| QueuedTexture NULL vtable (IO) | IO dequeue lock + quarantine bypass fix | FIXED |
| BSFile::Read NULL (NiSourceTexture) | IO dequeue lock + semaphore probe + dead set | FIXED |
| Texture cache stale entries | Dead set (ClashMap) + NiSourceTexture dtor hook | FIXED |
| hkBSHeightFieldShape UAF (AI) | hkWorld_Lock in protocol | FIXED |
| BSTreeNode RefCount:0 (SpeedTree) | SceneGraphInvalidate + post-render position | FIXED |
| NVSE PLChangeEvent (plugins) | Loading state counter DAT_01202d6c | FIXED |
| mimalloc corruption (mods) | encoded_freelist MI_SECURE=2 | MITIGATED |
| HeapCompact Stage 4/5 unsafe | Trigger limited to stages 0-2 | FIXED |
| Quarantine OOM during loading | Stale push bypass with loading flag check | FIXED |
| OOM during cell transition | purge_delay=0 + quarantine | FIXED |
| sbm2 region overlap | new_offset = actual consumed | FIXED |
| CellTransitionHandler AI crash (engine bug) | Hook with hkWorld_Lock + loading counter | FIXED |
| CellTransitionHandler IO crash | IO lock + FUN_00448620 task cancellation | FIXED |
| PDD queue cross-dependency | Removed queue skip, process all queues together | FIXED |
| Destruction during loading screen | DAT_011dea2b guard in run_deferred_unload | FIXED |
| Havok broadphase NULL entity | Partially mitigated by post-render position | UNDER INVESTIGATION |
| Extreme stress crash (225+ cells) | Dead set + all above fixes | UNDER INVESTIGATION |

Stress test result (latest): 27 reliefs, 225 cells unloaded, ~2 minutes extreme traversal.
Crash with "Fatal error in exception handler" (no stack trace). Likely Havok broadphase
or other stale-reference crash type not yet covered by dead set.

---

## Chapter 12: Key Lessons Learned

> **TL;DR:** 23 hard-won lessons from development. The most important: the 500MB budget
> was a synchronization barrier, the Pre-Destruction Protocol is mandatory for safe PDD,
> per-allocation atomics destroy performance, NVSE plugins require event suppression
> during cell destruction, CellTransitionHandler is a genuine Bethesda engine bug, and
> AI thread join consumes counting semaphores that cannot be called from our hook.

### 1. The 500MB Budget Was a Synchronization Barrier

By removing this budget (replacing with mimalloc's larger address space), we removed
an implicit synchronization mechanism where HeapCompact naturally serialized the main
thread with AI threads. The pressure relief system is our replacement.

### 2. FUN_008324e0 Is the Music System, Not Havok

Misidentifying this function wasted significant time. The PPL task groups it drains
are audio streaming groups. Calling `FUN_008324e0(1)` to "restart physics" crashes
on a NULL music path.

### 3. AI Threads Do Not Call GameHeap::Allocate During Raycasting

Verified at call-depth 2 via `AIProcess_Main` (`0x0096C330`). They access
hkBSHeightFieldShape directly. An allocation-barrier approach cannot work.

### 4. Selective PDD via Skip Mask

The gate function `FUN_00869180(flag)` checks `(DAT_011de804 & flag) != 0`.
With the Pre-Destruction Protocol, selective PDD is no longer needed -- all queues
are safe.

### 5. FindCellToUnload Is Safe Post-Render

SpeedTree draw lists consumed, physics objects deferred, AI threads don't index
cell arrays. But too-aggressive unloading (< 2s cooldown, > 20 cells) still
causes AI crashes.

### 6. PPL Task Groups Are Audio, Not AI

The two PPL groups drained by the cell transition handler are audio streaming.
AI coordination uses Windows Events and Semaphores.

### 7. Never Use .unwrap()/.expect() in NVSE Plugins

Rust panics kill the game with no diagnostic output. Use match, if-let, unwrap_or.
Propagate Results; match+log at hook boundaries.

### 8. Per-Allocation Atomic Counters Destroy Performance

A single `AtomicU32::fetch_add(1, Relaxed)` on every allocation causes 5-7 FPS
regression. Thread-local counters have zero contention.

### 9. TLS Cleanup Flag Controls Immediate vs Deferred Destruction

Flag=0 at `_tls_index + 0x298` bypasses deferred queues entirely, making PDD skip
masks useless. Always keep at 1.

### 10. mi_collect(true) Is Thread-Unsafe

Forces cross-thread segment purge. Races with AI allocations.
Only use `mi_collect(false)`.

### 11. BSTreeManager Holds Cross-Frame References

The singleton at `DAT_011D5C48` maintains `treeModelsMap` and `treeNodesMap`.
The SpeedTree render cache is NOT rebuilt every frame. Stale pointers persist.

### 12. Skipping More PDD Queues Makes Things Worse

Skipping 0x08+0x20+0x04 caused FASTER crashes than skipping only 0x08.
The game's state management expects PDD to eventually process all queues.

### 13. PreDestruction Protocol Is REQUIRED for Safe PDD from Non-Native Positions

All 5 DeferredCleanupSmall callers use it. Without it: AI crashes (hkWorld not
locked) and SpeedTree crashes (scene graph not invalidated).

### 14. ALL Game Object Frees Go Through GameHeap::Free

1036 callers audited. CommonDelete is the universal NiObject delete. FallbackFree
is only called from inside GameHeap::Free. Quarantine coverage is complete.

### 15. Quarantine Must NOT Flush During Pressure Relief

Originally we flushed quarantine after DeferredCleanupSmall for immediate memory reclaim. This caused BSTaskManagerThread to crash on QueuedTexture UAF — new IO tasks pick up references to quarantined memory between async flush return and mi_free. The quarantine now always respects its 30-frame window.

### 16. now_ms()/mi_process_info on Every Free Is Catastrophic

Syscalls per free cause severe frame drops. Use counter-based staleness instead.

### 17. Havok Uses GameHeap for ALL Allocations

The `hkFreeListAllocator` at `0x01204454` has zero references in game code. All Havok
memory operations go through Bethesda's wrapper (`FUN_00c3e1b0`) which calls
`GameHeap::Allocate`/`Free`. This means our quarantine covers 100% of Havok allocations
— no bypass paths exist. The Havok-related crashes during stress testing are purely OOM
at the 32-bit VA ceiling, not quarantine coverage gaps.

### 18. FindCellToUnload Triggers NVSE Event Dispatching

FindCellToUnload → DestroyCell triggers actor process changes on creatures in the unloading cell. This fires NVSE event handlers (PLChangeEvent, OnCellDetach) that access mid-destruction objects (refcount 0). The game's own callers avoid this because they run in contexts where event dispatching is naturally suppressed (HeapCompact retry loop, loading screens). Our post-render hook runs during normal gameplay where the event system is active. Fix: set DAT_01202d6c > 0 (loading state counter) to suppress events.

### 19. QUARANTINE_FRAMES Must Be Large Enough for NVSE Plugins

NVSE plugins like Stewie's Tweaks hold references to game objects for many frames after those objects are freed (e.g., dead creature's weapon reference persists for dozens of frames after HAVOK_DEATH). The original SBM kept zombie data forever. A 3-frame quarantine (initial value) was insufficient — increased to 30 frames (0.5 second at 60fps). The quarantine always respects its 30-frame window, including during pressure relief.

### 20. purge_delay Must Be 0 for Cell Transitions

purge_delay=500ms caused old freed pages to stay committed for 500ms during cell transitions. Old pages + new cell data = double VA usage, pushing commit from 1.3GB to 1.5GB+ → OOM. With purge_delay=0, empty pages are decommitted immediately (cheap within pre-reserved arena), preventing VA pressure during rapid cell transitions.

### 21. CellTransitionHandler Is the Only PDD Caller Without hkWorld_Lock

Out of 8 PDD callers in the game, CellTransitionHandler is the only one that calls BLOCKING PDD while AI threads may be active AND without locking the Havok world. The 5 normal callers use PreDestructionSetup. HeapCompact has implicit synchronization (Stage 8 sleeping). Save/load runs during loading (AI idle). CellTransition_Conditional uses non-blocking PDD. Only CellTransitionHandler is genuinely buggy — a Bethesda engine bug masked by SBM zombies for 15+ years.

### 22. FUN_008c7990 (AI Join) Consumes a Counting Semaphore

The AI completion mechanism uses Windows counting semaphores (ReleaseSemaphore/WaitForSingleObject). FUN_008c7990 waits on each AI thread's completion semaphore, consuming the count. Calling it from our hook steals the signal that the game's own join at 0x0086ee4e needs — causing deadlock or frame corruption on the next frame. Solution: hook FUN_008c7990 itself and run cell unloading AFTER the original returns.

### 23. DAT_011DFA19 Is the Reliable AI Active Flag

The game sets DAT_011dfa19 = 1 when AI threads are dispatched (FUN_008c78c0 at 0x0086ec87) and clears it to 0 when joined (FUN_008c7990 at 0x0086ee4e). Reading this byte at our Hook 1 position reliably indicates whether AI threads are active. This is more reliable than reading the processor count (which requires calling FUN_0043d4d0, a settings getter — direct pointer dereference reads wrong values).

---

## Chapter 13: Tuning Experiments

> **TL;DR:** The best configuration is 700MB/2s/20 with protocol-based PDD, boosted
> drain, and HeapCompact stages 0-2. Normal gameplay is stable. OOM at ~1.65GB only
> under artificial extreme stress.

### Pressure Relief Tuning

| Threshold/Cooldown/Cells | PDD Mode | Result |
|--------------------------|----------|--------|
| 700MB / 2s / 20 | None | OOM at ~1.8GB, ~3min |
| 700MB / 2s / 20 | Skip 0x08 only | Best pre-protocol stability, OOM ~1.7GB |
| 700MB / 2s / 20 | Full (all queues) | AI thread crash (hkBSHeightFieldShape) |
| 700MB / 2s / 20 | Skip 0x08+0x20+0x04 | FASTER crash |
| 512MB / 500ms / 30 | Skip 0x08+0x20 | AI crash (too aggressive) |
| 512MB / 500ms / 30 | Skip 0x08+0x20+0x04 | Texture NULL vtable crash |

### Multi-Layer Tuning

| Config | Drain | HeapCompact | Other | Result |
|--------|-------|-------------|-------|--------|
| 700/2s/20 | None | No | -- | OOM ~1.7GB, ~3min |
| 700/2s/20 | 10x | No | -- | 40 reliefs, ~4min, OOM |
| 700/2s/20 | 20x+guard | No | -- | 55 reliefs, ~4.5min, OOM |
| 600/2s/30 | 20x+guard | No | -- | Faster crash (BSTreeNode) |
| 700/2s/20 | 20x+guard | No | Rate boost | QueuedTexture IO race |
| 700/2s/20 | 20x+guard | No | Async flush | NVTF geometry crash |
| 700/2s/20 | 20x+guard | Yes (5) | -- | 46 reliefs, 500 cells, C0000417 (TLS=0) |
| 700/2s/20 | 20x+guard | Yes (4) | -- | Fast crash, Stage 4 PDD frees Havok |
| 700/2s/20 | 20x+guard | Yes (3), skip 0x08 | -- | Fast crash, post-render PDD Havok |
| **700/2s/20** | **20x+guard** | **Yes (3), skip 0x28** | -- | **57 reliefs, 627 cells, 3+min, OOM ~1.65GB** |
| **700/2s/20** | **20x+guard** | **Yes (2)** | **AI join + IO guard** | **Current: AI-safe cell unloading** |

### Final Stress Test Results (Best Configuration)

- 57 reliefs, 627 cells unloaded over 3+ minutes of extreme stress
- Commit plateau at ~1.3-1.5GB (vs monotonic climb to 1.7GB without system)
- All PDD queues consistently drained to 0
- HeapCompact confirmed running every frame
- Less stutters than baseline during stress testing
- Crash at ~1.65GB -- pure VA ceiling
- Normal gameplay completely stable (~760MB idle, ~1.0-1.1GB moving)

### Rejected Approaches

**DAT_011a95fc cleanup rate boost:** Accelerates texture/IO finalization faster
than the async IO system can process them -> QueuedTexture vtable UAF.

**Async queue flush FUN_00c459d0 alone:** Disrupts NVTF's Geometry Precache Queue
thread -> NiGeometryBufferData UAF.

**Scene graph invalidation without hkWorld_Lock:** Cull/update accesses heightfield
data from freed cells, and AI threads race on Havok access.

**Aggressive tuning 600MB/30cells:** More cells per cycle causes BSTreeNode UAF
faster than per-frame drain can handle.

### sbm2 Region Overlap Bug (FIXED)

The scrap heap's bump allocator had a memory corruption bug in `region.rs`. The
`new_offset` calculation used `old_offset + align_up(size + 4, align)` which didn't
account for alignment padding between `old_offset + 4` and the actual aligned data
address. This caused subsequent allocations to overlap previous ones when alignment
padding was needed. Fixed by computing `new_offset = (data_addr + size) - start_addr`
— using the actual allocated position instead of an independent reservation calculation.
This was likely the root cause of the documented "sbm2 region offset leak" bug.

---

# PART 5: REFERENCE TABLES

---

## Chapter 14: Function Address Map

> **TL;DR:** Complete map of every reverse-engineered function with address, size,
> calling convention, and Rust FFI signature.

### Heap Functions

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00AA3E40` | GameHeap::Allocate | -- | thiscall | `fn(this: *mut c_void, size: u32) -> *mut c_void` |
| `0x00AA4060` | GameHeap::Free | 236b | thiscall | `fn(this: *mut c_void, ptr: *mut c_void)` |
| `0x00AA4150` | GameHeap::Realloc1 | -- | thiscall | `fn(this: *mut c_void, ptr: *mut c_void, size: u32) -> *mut c_void` |
| `0x00AA4200` | GameHeap::Realloc2 | -- | thiscall | `fn(this: *mut c_void, ptr: *mut c_void, size: u32) -> *mut c_void` |
| `0x00AA44C0` | GameHeap::Msize | -- | thiscall | `fn(this: *mut c_void, ptr: *mut c_void) -> u32` |
| `0x00AA4290` | FallbackAlloc | 39b | cdecl | `fn(size: u32) -> *mut c_void` |
| `0x00AA42C0` | FallbackFree | 25b | cdecl | `fn(ptr: *mut c_void)` |
| `0x00AA45A0` | FindAllocator | 99b | thiscall | `fn(this: *mut c_void, ptr: *mut c_void) -> *mut i32` |
| `0x00AA4610` | FindAllocator2 | 137b | thiscall | `fn(this: *mut c_void, ptr: *mut c_void) -> *mut i32` |
| `0x00AA4960` | SBM_GetPool | 238b | cdecl | `fn(size: u32) -> *mut c_void` |
| `0x00AA6AA0` | SBM_ArenaAlloc | 462b | fastcall | `fn(pool: *mut c_void) -> *mut c_void` |
| `0x00AA6C70` | SBM_ArenaFree | 138b | thiscall | `fn(this: *mut c_void, ptr: *mut c_void)` |
| `0x00401030` | CommonDelete | 21b | cdecl | `fn(ptr: *mut c_void)` |

All Rust FFI signatures are `unsafe extern "<conv>"`.

### Pre-Destruction Protocol Functions

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00878160` | PreDestructionSetup | 113b | cdecl | `fn(state: *mut c_void, flush_textures: u8, param_3: u8, save_cell_lock: u8)` |
| `0x00878200` | PostDestructionRestore | 80b | cdecl | `fn(state: *mut c_void)` |
| `0x00878250` | DeferredCleanupSmall | 86b | cdecl | `fn(param_1: u8)` |

### Havok World Lock Functions

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00C3E310` | hkWorld_Lock | 43b | fastcall | `fn(world: *mut c_void)` |
| `0x00C3E340` | hkWorld_Unlock | 49b | fastcall | `fn(world: *mut c_void)` |
| `0x00C3E750` | hkWorld_Lock_Inner | 124b | fastcall | `fn(world: *mut c_void) -> u32` |
| `0x00C3E7D0` | hkWorld_Unlock_Inner | 134b | fastcall | `fn(world: *mut c_void) -> u32` |

### Havok Memory and Broadphase Functions

| Address | Name | Size | Conv | Rust FFI Signature | Description |
|---------|------|------|------|--------------------|-------------|
| `0x00C3E1B0` | hkAllocate_Dispatcher | 352b | thiscall | `fn(this: *mut c_void, param_1: i32, param_2: i32)` | Dispatches Havok allocations through vtable |
| `0x00C3E420` | hkWorld_AllocateInternal | 97b | thiscall | `fn(this: *mut c_void, param_1: *mut i32) -> u32` | Internal allocation dispatch |
| `0x00C3E860` | hkFreeList_CountEntries | 71b | thiscall | `fn(this: *mut c_void, param_1: u32) -> i32` | Counts entries in free list |
| `0x00C3DFA0` | hkMemory_Manager | 513b | thiscall | `fn(this: *mut c_void, param_1: i32)` | Memory pool manager with retry loop |
| `0x00C41FE0` | hkWorld_RemoveEntry | 122b | thiscall | `fn(this: *mut c_void, param_1: *mut c_void)` | Removes entity from broadphase, frees via GameHeap |
| `0x00C696D0` | hkWorld_CastRay | 656b | thiscall | `fn(this: *mut c_void, param_1: *mut f32)` | Broadphase raycast entry point |
| `0x006E6320` | Pathfinding_RayCast | 1960b | thiscall | `fn(this: *mut c_void, param_1: *mut i32, param_2: *mut c_void) -> u32` | Pathfinding raycasting |

All Rust FFI signatures are `unsafe extern "<conv>"`.

### Cleanup Functions

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00866A90` | HeapCompact | 602b | thiscall | `fn(this: *mut c_void, p1: u32, stage: i32, done: *mut u8) -> i32` |
| `0x00868D70` | ProcessDeferredDestruction | 1037b | cdecl | `fn(blocking: u8)` |
| `0x00869180` | PDD_QueueGateCheck | 16b | cdecl | `fn(flag: u32) -> u32` |
| `0x00869190` | SetTlsCleanupFlag | 29b | cdecl | `fn(value: u32)` |
| `0x00453A80` | FindCellToUnload | 824b | fastcall | `fn(manager: *mut c_void) -> u32` |
| `0x00452490` | ProcessPendingCleanup | 85b | thiscall | `fn(manager: *mut c_void, param: u8)` |
| `0x004539A0` | ForceUnloadCell | 196b | thiscall | `fn(this: *mut c_void, p1: u8, p2: u8)` |
| `0x00462290` | DestroyCell | 341b | cdecl | `fn(cell: *mut i32)` |
| `0x00C459D0` | AsyncQueueFlush | 172b | cdecl | `fn(try_lock: u8)` |
| `0x00703980` | SceneGraphInvalidate | 45b | cdecl | `fn()` |
| `0x007160B0` | SceneGraph_CullUpdate | 60b | fastcall | `fn(scene: *mut c_void)` |
| `0x008781E0` | SetDistanceThreshold | 13b | cdecl | `fn(value: u32)` |
| `0x008781F0` | GetDistanceThreshold | 10b | cdecl | `fn() -> u32` |

### Loading State and Cell Destruction Functions

| Address | Name | Size | Conv | Rust FFI Signature | Description |
|---------|------|------|------|--------------------|-------------|
| `0x0043B2B0` | SetLoadingState | 69b | cdecl | `unsafe extern "C" fn(param_1: u8)` | Increments/decrements DAT_01202d6c loading counter |
| `0x0044ADA0` | SetDestructionFlag | 13b | cdecl | `unsafe extern "C" fn(param_1: u8)` | Sets DAT_01202df0 destruction-in-progress flag |
| `0x0054AF40` | CellCleanup_ActorProcess | 53b | thiscall | `unsafe extern "thiscall" fn(this: *mut c_void, param_1: u8)` | Iterates actors in cell, triggers process changes |
| `0x0096E150` | ActorProcess_EventTrigger | 311b | thiscall | `unsafe extern "thiscall" fn(this: *mut c_void, param_1: i32, param_2: u8)` | Processes actors during cell unload, dispatches events |

### Cell Transition Functions

| Address | Name | Size | Conv | Rust FFI Signature | Description |
|---------|------|------|------|--------------------|-------------|
| `0x008774A0` | CellTransitionHandler | 561b | thiscall | `fn(this: *mut c_void, param_1: u8)` | Cell transition orchestrator. HOOKED to fix engine bug (adds hkWorld_Lock). |
| `0x00877700` | CellTransition_PreCleanup | 30b | fastcall | `fn(player: *mut c_void)` | |
| `0x008782B0` | CellTransition_SafePoint | 130b | cdecl | `fn()` | |
| `0x00878250` | DeferredCleanup_Small | 86b | cdecl | `fn(param_1: u8)` | |
| `0x0093BEA0` | CellTransition_Conditional | 832b | fastcall | `fn(param_1: *mut c_void)` | |
| `0x00552570` | DeferredRefPlacement | 312b | cdecl | `fn()` | Drains deferred ref queue (NOT AI sync) |

### Music System Functions (NOT Havok)

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x008324E0` | MusicStopStart | 184b | cdecl | `fn(start: u8)` |
| `0x008325A0` | MusicFlagSet | 13b | cdecl | `fn(value: u8)` |
| `0x008304A0` | MusicPre | 20b | -- | -- |
| `0x008304C0` | MusicPost | 46b | -- | -- |
| `0x008300C0` | MusicStepInit | 944b | cdecl | -- |
| `0x00830AD0` | MusicIsRunning | 92b | -- | -- |

### Main Loop Functions

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x0086E650` | MainLoop | 2272b | fastcall | `fn(param_1: *mut c_void)` |
| `0x0086F940` | PreAI_CellHandler | 595b | fastcall | `fn(param_1: *mut c_void)` |
| `0x0086FF70` | PreRender_Maintenance | 1616b | fastcall | `fn(param_1: *mut c_void)` |
| `0x008705D0` | RenderUpdate | 55b | fastcall | `fn(param_1: *mut c_void)` |
| `0x0086F640` | RenderUpdate_Pre | 45b | -- | -- |
| `0x0086F670` | RenderUpdate_Post | 48b | -- | -- |
| `0x0086F890` | RenderUpdate_Inner | 161b | fastcall | `fn(param_1: *mut c_void)` |
| `0x00878080` | MainLoop_HeapCompact | 137b | fastcall | `fn(param_1: *mut c_void)` |

### AI Thread Functions

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00AA64D0` | ThreadEntry | 20b | stdcall | `fn(param: *mut c_void) -> u32` |
| `0x008C7720` | AIThread_MainLoop | 111b | fastcall | `fn(param_1: *mut c_void)` |
| `0x008C7190` | AIThread_TaskDispatch | 28b | fastcall | `fn(param_1: *mut c_void)` |
| `0x008C7F50` | AITask_FrameUpdate | 346b | -- | -- |
| `0x008C7DA0` | AI_MainCoordinator | 429b | -- | -- |
| `0x008C7BD0` | AI_Dispatcher2 | 418b | -- | -- |
| `0x008C7290` | AI_CoordinatorCaller | -- | -- | -- |
| `0x008C79E0` | AI_Dispatch | 70b | thiscall | `fn(this: *mut c_void)` |
| `0x008C7A70` | AI_Wait | 41b | thiscall | `fn(this: *mut c_void)` |
| `0x008C80E0` | AI_StartFrame | 46b | cdecl | `fn(param: u8)` |
| `0x008C78C0` | AI_Start | 198b | fastcall | `fn(mgr: *mut c_void)` |
| `0x008C7990` | AIThreadJoin | 72b | fastcall | `fn(param_1: *mut c_void)` |
| `0x00713D80` | GetAIThreadManager | -- | cdecl | `fn() -> *mut c_void` |

### AI Processing

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x0096C330` | AIProcess_Main | 991b | fastcall | `fn(param_1: *mut c_void)` |
| `0x0096CB50` | AIProcess_Secondary | -- | fastcall | `fn(param_1: *mut c_void)` |

### IO Thread Functions

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00C42DA0` | BSTaskManagerThread_Main | 37b | stdcall | `fn(param: *mut i32) -> u32` |
| `0x00C410B0` | BSTaskManagerThread_Loop | 633b | fastcall | `fn(param_1: *mut c_void)` |
| `0x00C3FB50` | IOManager_ProcessTask | 299b | thiscall | `fn(this: *mut c_void, task: *mut u32) -> bool` |
| `0x00C3DBF0` | IOManager_Inner | 646b | fastcall | `fn(param_1: *mut c_void) -> u8` |

### PPL Task Group Functions (Audio)

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00AD88F0` | TaskGroupDrain | 51b | fastcall | `fn(group: *mut c_void)` |
| `0x00AD8D10` | TaskGroupWait | 66b | fastcall | `fn(group: *mut c_void)` |
| `0x00AD8DA0` | TaskGroupWaitTimeout | 60b | thiscall | `fn(this: *mut c_void, timeout_ms: u32)` |

### SBM Maintenance (Left Alive)

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x00AA6F90` | PurgeUnusedArenas | 157b | fastcall | `fn(pool: *mut c_void)` |
| `0x00AA7290` | DecrementArenaRef | 110b | cdecl | `fn(arena: *mut c_void)` |
| `0x00AA7300` | ReleaseArenaByPtr | 106b | fastcall | `fn(arena: *mut c_void)` |
| `0x00AA68A0` | SBM_ResetStats | 125b | -- | -- |

### SpeedTree / BSTreeManager

| Address | Name | Size | Conv | Rust FFI Signature |
|---------|------|------|------|--------------------|
| `0x0043DA00` | TreeMgr_AddTree | 149b | fastcall | `fn(param_1: *mut c_void)` |
| `0x0043DAC0` | TreeMgr_RemoveOnState | 53b | thiscall | `fn(this: *mut c_void)` |
| `0x00664840` | TreeMgr_GetOrCreate | 37b | cdecl | `fn() -> *mut c_void` |
| `0x00664870` | TreeMgr_Create | 199b | cdecl | `fn() -> *mut c_void` |
| `0x00664940` | TreeMgr_Destroy | 71b | -- | -- |
| `0x00664990` | TreeMgr_Cleanup | 44b | thiscall | `fn(this: *mut c_void)` |
| `0x00664F50` | TreeMgr_FindOrCreate | 874b | thiscall | `fn(this: *mut c_void) -> *mut c_void` |
| `0x00665B80` | TreeMgr_RemoveEntry | 95b | thiscall | `fn(this: *mut c_void)` |
| `0x00665BE0` | TreeMgr_RemoveByKey | 99b | thiscall | `fn(this: *mut c_void)` |
| `0x00666650` | BSTreeModel_Ctor | 372b | -- | -- |
| `0x00666800` | BSTreeModel_Init | 261b | -- | -- |
| `0x0066B120` | BSTreeNode_Ctor | 1161b | -- | -- |
| `0x0066B6C0` | BSTreeNode_Init | 264b | -- | -- |

### PDD Queue Destructors

| Address | Name | Size | Conv | Queue | Rust FFI Signature |
|---------|------|------|------|-------|--------------------|
| `0x00418D20` | NiNode_Release | 44b | thiscall | 0x08 | `fn(this: *mut c_void, flags: u32) -> *mut u32` |
| `0x00418E00` | Texture_Release | 44b | thiscall | 0x04 | `fn(this: *mut c_void, flags: u32) -> *mut u32` |
| `0x00868CE0` | Anim_ClearFlag | 39b | fastcall | 0x02 | `fn(param_1: *mut c_void)` |
| `0x00401970` | Havok_Release | 43b | fastcall | 0x20 | `fn(param_1: *mut i32)` |
| `0x00868250` | PDD_TryLock | 21b | fastcall | 0x08/04/01 | `fn(lock: *mut c_void) -> bool` |
| `0x0078D1F0` | PDD_FormLock | 15b | cdecl | 0x10 | `fn()` |

### Misc Utilities

| Address | Name | Conv | Rust FFI Signature |
|---------|------|------|--------------------|
| `0x0040FBF0` | EnterLock | fastcall | `fn(lock: *mut i32)` |
| `0x0040FBA0` | ReleaseLock | fastcall | `fn(lock: *mut u32)` |
| `0x0040FC90` | GetCurrentThreadId | cdecl | `fn() -> u32` |
| `0x0040FCA0` | Sleep | cdecl | `fn(ms: u32)` |
| `0x0044EDB0` | GetMainThreadId | cdecl | `fn(controller: *mut c_void) -> u32` |
| `0x00401020` | GetGameHeapSingleton | cdecl | `fn() -> *mut c_void` |
| `0x00401030` | CommonDelete | cdecl | `fn(ptr: *mut c_void)` |

---

## Chapter 15: Global Address Map

> **TL;DR:** Every DAT_ address referenced in this document, organized by subsystem.

### Singletons and Managers

| Address | Name | Description |
|---------|------|-------------|
| `DAT_011F6238` | GameHeap singleton | The MemoryHeap instance |
| `DAT_011DEA10` | TES game manager | Cell arrays, data handler, world state |
| `DAT_011DEA0C` | Game main controller | Thread ID at offset +0x10 |
| `DAT_011DEA3C` | TES singleton | Game world manager. TES+0x77c = pending cell load task handle for BSTaskManagerThread |
| `DAT_011DDF38` | BSRenderedLandData | Flags at offset +0x244 |
| `DAT_01202D6C` | Loading state counter | InterlockedIncrement/Decrement. When > 0, actor event dispatching is suppressed during cell destruction. Set by FUN_0043b2b0 |
| `DAT_01202D98` | Havok world singleton | hkWorld pointer for Lock/Unlock |

### Music System (NOT Havok)

| Address | Description |
|---------|-------------|
| `DAT_011DD313` | Music running flag (set by FUN_008325a0) |
| `DAT_011DD434` | Music/physics state flag |
| `DAT_011DD436` | Music stop/start guard |
| `DAT_011DD437` | Music restart condition |
| `DAT_011DD5BC` | PPL task group 1 (audio streaming, NOT AI) |
| `DAT_011DD638` | PPL task group 2 (audio streaming, NOT AI) |

### Deferred Destruction

| Address | Description |
|---------|-------------|
| `DAT_011DE804` | PDD queue skip bitmask (bit set = skip) |
| `DAT_011DE808` | PDD queue: NiNode / BSTreeNode (bit 0x08) |
| `DAT_011DE828` | PDD queue: Pending form deletions (bit 0x10) |
| `DAT_011DE874` | PDD queue: Generic ref-counted (bit 0x01) |
| `DAT_011DE888` | PDD queue: Animation/controller (bit 0x02) |
| `DAT_011DE910` | PDD queue: Texture/material refs (bit 0x04) |
| `DAT_011DE924` | PDD queue: Havok physics wrappers (bit 0x20) |
| `DAT_011DE958` | PDD reentrancy guard flag |

### SpeedTree

| Address | Description |
|---------|-------------|
| `DAT_011D5C48` | BSTreeManager singleton pointer |

### Synchronization

| Address | Description |
|---------|-------------|
| `DAT_011DE70C` | HeapCompact retry counter |
| `DAT_011DE8E0` | PDD critical section (lock object) |
| `DAT_011DFA18` | AI frame dispatch flag |
| `DAT_011DFA19` | AI active flag. Set to 1 by AI dispatch (FUN_008c78c0), cleared to 0 by AI join (FUN_008c7990). Reliable indicator of AI thread state at our hook position. |
| `DAT_011F11A0` | Global lock for deferred destruction |
| `DAT_011F4480` | Queue 0x10 lock (form deletions) |
| `DAT_01202D98` | Havok world singleton (hkWorld_Lock target) |
| `DAT_01202DF0` | Cell destruction in-progress flag. Set by FUN_0044ada0(1) at start of DestroyCell, cleared by FUN_0044ada0(0) at end |
| `DAT_01202E40` | Async queue flush lock |
| `DAT_01202E44` | Async queue counter (decremented by flush) |
| `_tls_index + 0x298` | TLS deferred cleanup flag (per-thread) |
| `_tls_index + 0x2B4` | TLS per-thread allocator pool index |

### Havok Memory and Broadphase

| Address | Description |
|---------|-------------|
| `0x01204454` | hkFreeListAllocator global (zero references — unused, all Havok allocs go through GameHeap wrapper) |
| `0x010D7C34` | hkLargeBlockAllocator RTTI |
| `0x010CD5CC` | hkp3AxisSweep RTTI (broadphase spatial data structure) |
| `0x010C3BC4` | ahkpWorld RTTI |
| `0x010CE310` | hkpClosestRayHitCollector vtable |
| `0x011AF70C` | Havok memory manager completion flag |

### Key Data Addresses

| Address | Description |
|---------|-------------|
| `0x011F636C` | HeapCompact trigger (heap + 0x134), write N for stages 0..N |
| `0x011A95FC` | Cleanup rate limiter / distance threshold |
| `lpCriticalSection_011f4380` | AsyncQueueFlush critical section |

---

## Chapter 16: Ghidra Scripts and Outputs

> **TL;DR:** All analysis scripts live in `analysis/ghidra/scripts/`, outputs in
> `analysis/ghidra/output/memory/`.

### Scripts

| Script | Purpose |
|--------|---------|
| `heap_accounting.py` | Decompile HeapCompact and FallbackAllocator |
| `find_unhooked_free_paths.py` | Find all callers of unhooked free functions |
| `deep_heap_compact.py` | Recursive decompilation of HeapCompact (3 levels) |
| `ai_thread_sync.py` | AI thread sync model and PDD callers |
| `ai_sync_primitives.py` | AI thread wait/signal primitives + cell transition |
| `ai_thread_deep.py` | Deep dive into AI thread sync mechanism |
| `find_deferred_safe_point.py` | Find safe frame points for PDD |
| `decompile_0086f940.py` | Decompile the safe hook point |
| `havok_direct.py` | Decompile Havok/music stop/start functions |
| `havok_broadphase_crash.py` | Research crash at 0x00CAFED5 — broadphase raycasting, PDD queue 0x20 destructor chain, pathfinding raycast path |
| `havok_memory_system.py` | Research hkFreeListAllocator, Havok memory wrapper, hkMemory_Manager retry loop |
| `scene_graph_post_render_safety.py` | Verify SceneGraphInvalidate safety from post-render hook position |
| `io_thread_sync_points.py` | Research AsyncQueueFlush blocking mechanism, IO thread sync primitives |
| `post_destruction_restore.py` | Decompile FUN_00878200 (PostDestructionRestore), verify hkWorld_Unlock call |
| `event_dispatch_suppress.py` | Research NVSE event dispatching during cell destruction, loading state counter DAT_01202d6c, FUN_0043b2b0 mechanism |
| `cell_transition_havok_race.py` | Research CellTransitionHandler Havok race — PDD callers, AI timing, hookability |
| `exterior_cell_loader_race.py` | ExteriorCellLoaderTask race with cell unloading — crash on BSTaskManagerThread |
| `vanillaplus_crash_geometry.py` | VanillaPlusSkin geometry crash on BSTaskManagerThread |
| `async_flush_scope.py` | AsyncQueueFlush scope — what it drains vs what it doesn't |
| `globalcleanup_and_celltransition.py` | GlobalCleanup (0x00AA7030) callers + CellTransitionHandler internals |
| `func_877700_io_wait.py` | FUN_00877700 IO wait mechanism (TES+0x77c) |
| `func_ad8da0_wait_semantics.py` | FUN_00AD8DA0 wait/timeout semantics |
| `plchange_event_dispatch.py` | PLChangeEvent dispatch path on AI threads |
| `audit_ret_patch_callers.py` | Comprehensive audit: all callers of 7 RET-patched + 3 NOP-patched functions |
| `audit_free_path_coverage.py` | Comprehensive audit: all memory free paths (100% coverage confirmed) |
| `audit_thread_safety.py` | Comprehensive audit: thread safety of all hooked functions |
| `audit_heapcompact_stages.py` | Comprehensive audit: HeapCompact stages 0-5 behavior |
| `audit_pressure_side_effects.py` | Comprehensive audit: side effects of all game functions we call |
| `audit_mainloop_timeline.py` | Comprehensive audit: exact main loop execution order |
| `audit_func_552570.py` | FUN_00552570 analysis — deferred ref placement, NOT AI sync |
| `audit_ai_join_point.py` | AI thread join point — confirmed 0x0086ee4e AFTER our hook |
| `ai_join_safety.py` | Verify AI thread join safety — semaphore mechanics, Havok world step identity |
| `post_ai_join_hook.py` | Research post-AI-join hook positions — DAT_011dfa19 lifecycle, hookability |

### Analysis Outputs

| Output File | Content |
|-------------|---------|
| `disasm_gheap.txt` | GameHeap functions decompilation |
| `disasm_callers.txt` | Callers of heap functions |
| `deep_heap_compact.txt` | HeapCompact full call tree |
| `unhooked_free_paths.txt` | Unhooked free path analysis (no missing hooks) |
| `ai_thread_sync.txt` | AI thread sync model |
| `ai_sync_primitives.txt` | AI primitives decompilation |
| `ai_thread_deep.txt` | Deep AI thread analysis |
| `find_deferred_safe_point.txt` | Safe point analysis |
| `safe_hook_point.txt` | Hook point decompilation |
| `havok_direct.txt` | Havok/music functions |
| `speedtree_cache.txt` | BSTreeManager, PDD queues, gate function, locks |
| `speedtree_cache2.txt` | Queue gate, destructors, tree manager CRUD, locks |
| `pre_destruction_protocol.txt` | Full PreDestruction protocol analysis |
| `quarantine_coverage_audit.txt` | Proof all frees go through GameHeap::Free |
| `cell_transition_free_paths.txt` | Cell transition free path analysis |
| `ai_cell_transition_race.txt` | AI thread vs cell transition race analysis |
| `io_thread_lifecycle.txt` | BSTaskManagerThread, IOManager, LockFreeQueue |
| `havok_broadphase_crash.txt` | Broadphase crash analysis, PDD destructor chain, pathfinding raycast |
| `havok_memory_system.txt` | Havok allocator analysis, memory wrapper, retry loop |
| `scene_graph_post_render_safety.txt` | SceneGraphInvalidate chain, exterior-only check |
| `io_thread_sync_points.txt` | AsyncQueueFlush mechanism, IO dequeue |
| `post_destruction_restore.txt` | FUN_00878200 decompilation, function boundary map |
| `event_dispatch_suppress.txt` | Event dispatch chain, loading counter, DestroyCell guard, ForceUnloadCell flags |
| `cell_transition_havok_race.txt` | CellTransitionHandler decompilation, all PDD callers, AI dispatch timing, hook prologue |

---

## Appendix: Build Notes

The psycho-nvse plugin must be built with:

```
--target i686-pc-windows-gnu
```

### Two-Phase DLL Initialization

DllMain (Phase 1, loader lock held) performs only: config read (no write-back), logger registration (no thread/file I/O), mimalloc config, hook installation. NO thread creation, NO disk writes.

NVSEPlugin_Load (Phase 2, loader lock released) performs: logger thread spawn + log file creation, config write-back, monitor thread spawn, NVSE services.

This prevents deadlocks from thread creation under the Windows loader lock.

---

# PART 6: BSTaskManagerThread IO SYNCHRONIZATION (Session 2026-03-21)

---

## Chapter 17: BSTaskManagerThread Race Condition

> **TL;DR:** BSTaskManagerThread processes IO tasks (QueuedTexture, QueuedModel) via a
> lock-free queue. IO tasks hold RAW POINTERS to NiSourceTexture objects without refcounting.
> When our pressure relief runs PDD, NiSourceTexture destructors zero critical fields
> (pixelData, DX9TextureData). BSTaskManagerThread reads zeroed fields → crash. The game
> never encounters this because HeapCompact Stage 5 only runs during OOM when
> BSTaskManagerThread is stuck in Stage 8's Sleep loop.

### The Original Crash

```
BSTaskManagerThread → FUN_0043c150 (QueuedTexture processing)
  → FUN_0043c4c0 (texture cache lookup)
    → FUN_0043c4f0 → FUN_00a61a60 (hash table find)
  → FUN_00c3cff0 → BSFile::Read(dest=NULL)
    → __VEC_memcpy(NULL, src, size) → CRASH at 0x00ED17A0
```

`FUN_00aa1750` (BSFile::Read, thiscall, 189 bytes) receives a NULL destination buffer.
The NULL comes from a destroyed NiSourceTexture whose pixelData was zeroed by PDD.

### BSTaskManagerThread Object Layout

```
BSTaskManagerThread struct (created by FUN_00c42dd0, 292 bytes ctor):
  +0x04: HANDLE thread_handle (CreateThread)
  +0x08: DWORD thread_id
  +0x0C: LONG pending_wake_count (InterlockedDecrement on wake)
  +0x10: HANDLE wake_semaphore (initial=0, max=0x7FFFFFFF)
  +0x14: LONG wake_sem_max (0x7FFFFFFF)
  +0x18: LONG iter_sem_count (initial=1, InterlockedIncrement after each iteration)
  +0x1C: HANDLE iter_semaphore (initial=1, max=1)
  +0x20: LONG iter_sem_max (1)
  +0x24: 0 (reserved)
  +0x28: 0 (reserved)
  +0x2C: DWORD thread_id_copy
  +0x30: ptr → IOManager/BSTaskManager (parent, set by BSTaskManagerThread_ctor)
```

### BSTaskManagerThread_Loop State Machine (FUN_00c410b0, 633 bytes)

```c
while (!shutdown) {
    WaitForSingleObject(wake_semaphore, INFINITE);  // IDLE STATE
    InterlockedDecrement(pending_wake_count);

    while ((flags & 2) == 0) {  // PROCESSING STATE
        // Flow control: check iter_semaphore
        if (WaitForSingleObject(iter_semaphore, 0) == WAIT_TIMEOUT) {
            WaitForSingleObject(iter_semaphore, INFINITE);
            InterlockedDecrement(iter_sem_count);
            SignalCompletion(0);
        }
        // Dequeue task (acquires IO dequeue lock at IOManager+0x20)
        result = IO_DequeueTask(queue_mgr, ...);
        if (result == 0) {
            SignalCompletion(0);
        } else if (task[3] == 1 && CAS(task+3, 3, 1) == 1) {
            vtable_process(task);   // ← reads NiSourceTexture
            vtable_complete(task);  // ← enters lpCriticalSection_011f4380
        }
        DecRef(task);
        ReleaseSemaphore(iter_semaphore, 1, 0);  // count → 1
        InterlockedIncrement(iter_sem_count);     // +0x18 changes
    }
    // BACK TO IDLE
}
```

### IO Dequeue Lock (IOManager+0x20)

The spin-lock at `IOManager+0x20` (counter at +0x24) is acquired by `IO_DequeueTask`
(FUN_00c40e70) during task dequeue. By acquiring this lock ourselves, we prevent
BSTaskManagerThread from dequeuing new tasks during PDD.

Lock mechanism (`FUN_0040fbf0`, 149 bytes, **non-standard ABI**):
- Calling convention: fastcall ECX + 1 stack param + **RET 0x4** (callee cleans)
- CAS with `GetCurrentThreadId()` as lock value (threadID-based, reentrant)
- Spin: Sleep(0) for first 10001 iterations, then Sleep(1)
- Counter at lock+4 tracks reentrancy

**CRITICAL:** The `RET 0x4` means the function pops 4 bytes from the stack on return.
Calling without pushing the stack parameter corrupts the return address →
`EXCEPTION_PRIV_INSTRUCTION` at garbage EIP.

### Semaphore Probe for Idle Detection

After acquiring the IO lock, we probe the iter_semaphore (+0x1C) with non-blocking
`WaitForSingleObject(handle, 0)`:

| iter_sem count | BSTaskManagerThread state | Probe result | Action |
|---|---|---|---|
| 1 | Between iterations (idle or about to dequeue) | Signaled | Release back, proceed immediately |
| 0 | Mid-iteration (processing task) | Timeout | Wait up to 5ms for iter_count change |
| 0 | Blocked on our IO lock | Timeout | 5ms timeout → proceed (safe, not processing) |

The 5ms timeout distinguishes "mid-task" (iter_count changes within ms after task finishes)
from "blocked on lock" (iter_count frozen, BSTaskManagerThread stuck in IO_DequeueTask).

**WARNING:** Using an infinite wait here causes DEADLOCK — BSTaskManagerThread is blocked
on our lock → iter_count never changes → infinite loop.

---

## Chapter 18: Texture Cache Hash Table (DAT_011f4468)

> **TL;DR:** The texture cache is a write-only hash table with no individual entry removal.
> Entries persist after NiSourceTexture destruction. The game only does full resets during
> worldspace transitions. Our pressure relief runs during normal gameplay — stale entries
> cause BSTaskManagerThread crashes. Fix: dead set tracks destroyed NiSourceTextures.

### Hash Table Structure

```
DAT_011f4468: hash table pointer
  0x3E9 (1001) buckets
  Each bucket: singly-linked chain of entries

chain_entry {
    [0]: value_ptr → wrapper object
    [4]: next_entry_ptr → next chain_entry
}

wrapper (value) {
    [0]: inner_ptr → NiSourceTexture*
    [4]: key_hash (worldspace hash)
    [8]: iter_next (iteration linked list)
}
```

### Hash Table Operations

| Address | Name | Operation |
|---------|------|-----------|
| `0x00A61A60` | Find | Traverse chain, match key at value[1], return value[0] with AddRef |
| `0x00A61920` | BucketOp | Search/add in specific bucket |
| `0x00A619B0` | Iterator | Traverse all buckets for iteration |
| `0x00A615C0` | Cleanup | Free ALL chain entries in ALL 0x3E9 buckets |
| `0x00A62030` | PreReset | Acquire lock, cleanup all entries + texture array |
| `0x00A62090` | FullReset | PreReset + free hash table + free texture array + NULL globals |

### Hash Table Lock

`DAT_011f4480` — Bethesda's spin-lock protecting the hash table. Acquired by
PreReset (FUN_00a62030), texture load/add (FUN_00a61b90), and other operations.

### Why Stale Entries Persist

1. No individual "remove entry" function exists in the game
2. Full reset (FUN_00a62090) only called during worldspace transitions from FUN_0086a850
3. Full reset is called at address `0x0086b976` in the outer update function
4. Our pressure relief (FindCellToUnload + PDD) never triggers the outer update

### NiSourceTexture Destructor (FUN_00a5fca0, 207 bytes, fastcall)

```c
void FUN_00a5fca0(undefined4 *param_1) {
    *param_1 = &PTR_FUN_0109b9ec;  // vtable (unchanged initially)
    // DecRef + zero NiDX9SourceTextureData at offset 0x3C
    param_1[0xf] = 0;
    // DecRef + zero NiPixelData at offset 0x38
    param_1[0xe] = 0;
    // ... more cleanup ...
    *param_1 = &PTR_FUN_0109b944;  // vtable CHANGED to base class
    // ... base class destructor ...
}
```

**After destruction:** vtable changed (0x0109b9ec → 0x0109b944), pixelData zeroed,
DX9TextureData zeroed, but the hash table entry still points to this object via
the wrapper's inner_ptr.

### Dead Set Fix

`ClashMap<usize, (), FxBuildHasher>` tracks destroyed NiSourceTexture addresses:

- **Insert:** NiSourceTexture destructor hook (FUN_00a5fca0) inserts `this` before original runs
- **Check:** Hash table find hook (FUN_00a61a60) checks inner_ptr against dead set
- **Clear:** `tick()` clears the dead set every frame

Fast path: if no dead entries in bucket chain → call original find directly (zero overhead).
Slow path: traverse chain skipping dead entries, handle refcount swap manually.

### Texture Cache Reset Functions

| Address | Name | Caller | When |
|---------|------|--------|------|
| `0x00A62030` | PreReset | FUN_00a62090 | Worldspace transition |
| `0x00A62090` | FullReset | `0x0086b976` in FUN_0086a850 | Worldspace transition |

FUN_00a62090 is called exactly ONCE — from the outer update function during worldspace
transitions. It destroys the entire hash table and texture array, then reallocates.
**Too heavy for per-pressure-relief use** (forces ALL textures to reload from disk → massive stutter).

---

## Chapter 19: Quarantine Stale-Push Bypass

> **TL;DR:** The quarantine's stale-push bypass (>50K pushes → mi_free) was the root
> cause of multiple crash types. Fixed by splitting behavior: mi_free during loading
> screens (AI/IO idle), oldest-bucket-flush during gameplay (AI/IO active).

### Original Bypass

```rust
if self.stale_pushes > STALE_PUSH_LIMIT {
    mi_free(ptr);  // UNSAFE during gameplay — BSTaskManagerThread active
    return;
}
```

During PDD, 20 cells × ~5K objects = ~100K frees per frame. After 50K, the bypass
fires → mi_free immediately → memory recycled → BSTaskManagerThread reads recycled
memory → crash.

### Fixed Bypass

```rust
if self.stale_pushes > STALE_PUSH_LIMIT {
    let loading = *(0x011DEA2B as *const u8) != 0;
    if loading {
        mi_free(ptr);  // SAFE: loading screen, AI/IO idle
        return;
    }
    // SAFE: flush oldest bucket (30+ frames old, no live references)
    if self.stale_pushes % STALE_PUSH_LIMIT == 1 {
        let oldest_idx = (frame.wrapping_add(1) as usize) % QUARANTINE_FRAMES;
        Self::drain_bucket(&mut self.buckets[oldest_idx]);
    }
}
```

### Why Loading Screen Bypass Is Safe

During loading screens (DAT_011dea2b != 0):
- BSTaskManagerThread is loading data for the NEW state, not referencing OLD freed objects
- AI threads are not dispatched
- The frame counter is stale (no tick() calls)
- Without bypass: quarantine grows unboundedly → OOM (D3D9 allocation failure at ~1.9GB)

### Why Gameplay Bypass Was Unsafe

During normal gameplay (DAT_011dea2b == 0):
- BSTaskManagerThread holds raw pointers to quarantined QueuedTexture objects
- AI threads reference Havok collision shapes from unloaded cells
- Texture cache hash table has entries pointing to quarantined NiSourceTextures
- mi_free recycles the memory → all readers crash

---

## Chapter 20: CellTransitionHandler IO Synchronization

> **TL;DR:** CellTransitionHandler (FUN_008774a0) does BLOCKING PDD without IO
> thread synchronization or stale task cancellation. Our hook adds both.

### CellTransitionHandler vs DeferredCleanupSmall

```
DeferredCleanupSmall:   PDD(1) → FUN_00b5fd60 → AsyncFlush(0) → FUN_00448620(cancel) → cleanup
CellTransitionHandler:  PDD(0) → AsyncFlush(0)                                        ← NO CANCEL
```

FUN_00448620 (task cancellation, 758 bytes) is called by DeferredCleanupSmall but NOT
by CellTransitionHandler. Without it, BSTaskManagerThread's `CAS(task+3, 3, 1)` succeeds
on uncancelled stale tasks → processes freed objects → crash.

### Cell-Specific Task Cancellation

`FUN_00445670(DAT_011c3b3c, cell)` — called from CellState_Change (FUN_00552bd0, 462 bytes)
inside DestroyCell. Iterates task queue (`this+8`), finds tasks where
`FUN_008d6f30(task) == cell`, calls `FUN_00445570(this, task)` to cancel.
Only 1 caller: CellState_Change.

### IO Object Cleanup

`FUN_00c5ba50(this, object)` — called 4 times from CellState_Change with different
cell objects (FUN_0054aa60, FUN_0054a050, FUN_00456fc0, FUN_00524cf0 results).
Finds matching entry in IO task array (`this+0x6c`) and calls FUN_00c5bef0 to cancel.

### Our Hook (hook_cell_transition_handler)

Wraps the original with:
1. hkWorld_Lock (FUN_00c3e310) — blocks Havok worker threads
2. Loading state counter (DAT_01202d6c) — suppresses NVSE event dispatching
3. IO dequeue lock (IOManager+0x20) — blocks BSTaskManagerThread dequeue
4. Original CellTransitionHandler call
5. FUN_00448620(DAT_011c3b3c, 1) — cancel stale tasks
6. IO dequeue lock release
7. Loading state counter decrement
8. hkWorld_Unlock (FUN_00c3e340)

---

## Chapter 21: Destruction Protocol Position Analysis

> **TL;DR:** Post-AI-join (Hook 2) is the ONLY safe position for PDD. Pre-AI (per-frame drain)
> crashes SpeedTree. The Havok broadphase lifecycle issue remains under extreme stress.

### Frame Timeline with Hook Positions

```
  HeapCompact    QueueDrain   PDD    AI_START     RENDER    HOOK1    AI_JOIN(HOOK2)
  0x0086eac9    0x0086eadf  ~987   0x0086ec87  0x0086ede8  0x008705d0  0x008c7990
                                    |           |           |           |
  PerFrameDrain position:           |           |           |           |
  SpeedTree UNSAFE (draw lists not built)       |           |           |
                                                |           |           |
                                    Hook 2 position:        |           ←
                                    SpeedTree SAFE (consumed by render) |
                                    AI SAFE (joined)                    |
                                    Havok LIFECYCLE: removal persists until next frame's step
```

### Why Per-Frame Drain Position Crashes SpeedTree

Moving destruction to per-frame drain (FUN_00868850, line ~802) runs BEFORE render.
BSTreeNode objects freed by PDD are still cached in SpeedTree draw lists. Render
accesses freed BSTreeNode → `C0000417` (CRT invalid parameter) during rendering.

The heap_analysis documented this: "PreRender position: CRASH — BSTreeNode UAF,
render hasn't consumed tree data."

### PDD Queue Cross-Dependencies (Why Queue Skip Is Wrong)

PDD queues have dependencies between each other:
- Queue 0x08 (NiNode) destructors release references to queue 0x20 (Havok) objects
- Skipping one queue but processing others creates over-decremented refcounts
- CellTransitionHandler's PDD processes all queues together for this reason
- Skipping queue 0x20 during our PDD → Havok wrapper refcount corruption →
  crash during subsequent CellTransitionHandler (free path crash in ntdll)

---

## Chapter 22: New Function Address Map

### IO Synchronization Functions

| Address | Name | Size | Conv | Description |
|---------|------|------|------|-------------|
| `0x0040FBF0` | SpinLock_Acquire | 149b | fastcall+stack+RET4 | ThreadID-based CAS spin-lock |
| `0x0040FC90` | GetCurrentThreadId_wrap | 11b | cdecl | Wraps GetCurrentThreadId |
| `0x0043B460` | InterlockedCAS_wrap | 23b | cdecl | Wraps InterlockedCompareExchange |
| `0x0040FCA0` | SpinLock_Sleep | 15b | cdecl | Sleep(param) |
| `0x0040FBE0` | SpinLock_PostAcquire | 5b | cdecl | NOP (empty function) |
| `0x00C42DD0` | BSTaskThread_init | 292b | thiscall | Creates thread + semaphores |
| `0x00C42DA0` | BSTaskThread_entry | 37b | stdcall | Thread entry point |
| `0x00C410B0` | BSTaskManagerThread_Loop | 633b | fastcall | Main task processing loop |
| `0x00C40E70` | IO_DequeueTask | 462b | thiscall | Dequeue with spin-lock |
| `0x00C42060` | IO_SignalCompletion | 111b | thiscall | Signal task completion |
| `0x00C3FC80` | IO_TaskDispatch | 26b | thiscall | vtable+4 call on task |
| `0x00C42F50` | BSTaskThread_Start | 24b | fastcall | ResumeThread |

### Texture Cache Functions

| Address | Name | Size | Conv | Description |
|---------|------|------|------|-------------|
| `0x00A61A60` | TextureCacheFind | 103b | thiscall | Hash table find (HOOKED) |
| `0x00A61920` | TextureCacheBucketOp | 137b | thiscall | Bucket search/add |
| `0x00A619B0` | TextureCacheIterator | 169b | thiscall | Iterate all entries |
| `0x00A615C0` | TextureCacheCleanup | 71b | fastcall | Free all chain entries |
| `0x00A62030` | TextureCachePreReset | 83b | cdecl | Lock + cleanup + iterate array |
| `0x00A62090` | TextureCacheFullReset | 123b | cdecl | PreReset + free + NULL globals |
| `0x00A61AD0` | TextureCacheInit | 185b | cdecl | Allocate hash table + array |
| `0x00A5FCA0` | NiSourceTexture_dtor | 207b | fastcall | Destructor (HOOKED for dead set) |
| `0x00A5FC10` | NiSourceTexture_ctor | 99b | fastcall | Constructor |

### Cell Transition Functions

| Address | Name | Size | Conv | Description |
|---------|------|------|------|-------------|
| `0x00552BD0` | CellState_Change | 462b | thiscall | Cell state transition (detach) |
| `0x00445670` | CancelCellTasks | 217b | thiscall | Cancel IO tasks for specific cell |
| `0x00C5BA50` | IOTask_CellCleanup | 129b | thiscall | Cancel IO ref for cell object |
| `0x00448620` | CancelStaleTasks | 758b | thiscall | Cancel all stale queued tasks |
| `0x0086A850` | OuterUpdate | 4532b | stdcall | Main loop outer update (huge) |

### Global Addresses

| Address | Name | Description |
|---------|------|-------------|
| `0x011F4468` | DAT_011f4468 | Texture cache hash table pointer |
| `0x011F4464` | DAT_011f4464 | Texture cache array pointer |
| `0x011F4480` | DAT_011f4480 | Texture cache spin-lock |
| `0x011C3B3C` | DAT_011c3b3c | Task queue manager singleton (20+ xrefs) |
| `0x01202D98` | DAT_01202d98 | Unified runtime manager (IOManager + Havok world) |
| `0x011DEA2B` | DAT_011dea2b | Game loading/menu state flag |

---

## Chapter 23: Ghidra Scripts Index (Session 2026-03-21)

| Script | Output | Purpose |
|--------|--------|---------|
| crash_ed17a0_analysis.py | crash/crash_00ED17A0_analysis.txt | BSTaskManagerThread __VEC_memcpy crash analysis |
| io_thread_wait_mechanism.py | memory/io_thread_wait_mechanism.txt | BSTaskManagerThread sync primitive research |
| io_thread_quiesce_mechanism.py | memory/io_thread_quiesce_mechanism.txt | IO flush chain and quiescing research |
| io_manager_singleton.py | memory/io_manager_singleton.txt | IOManager pointer chain + dequeue lock |
| verify_io_manager_ptr.py | memory/verify_io_manager_ptr.txt | Verify IOManager at DAT_01202D98 |
| verify_spinlock_ret.py | memory/verify_spinlock_ret.txt | SpinLock_Acquire RET 0x4 confirmation |
| crash_cffa08_analysis.py | crash/crash_00CFFA08_analysis.txt | Havok broadphase NULL entity crash |
| havok_broadphase_step.py | memory/havok_broadphase_step.txt | Havok step/update function research |
| crash_a61a74_bstask.py | crash/crash_00A61A74_bstask.txt | Texture cache hash table crash |
| texture_hashtable_cleanup.py | memory/texture_hashtable_cleanup.txt | Hash table cleanup mechanism |
| deep_io_lifecycle.py | memory/deep_io_lifecycle.txt | Complete QueuedTexture lifecycle |
| deep_cell_unload_flow.py | memory/deep_cell_unload_flow.txt | Cell unload reference invalidation |
| texture_cache_reset_context.py | memory/texture_cache_reset_context.txt | TextureCache_Reset call context |
| havok_ai_raycast_crash.py | crash/havok_ai_raycast_crash.txt | AI thread Havok raycasting crash |
| bstask_idle_detection.py | memory/bstask_idle_detection.txt | BSTaskManagerThread idle detection |
| hashtable_node_layout.py | memory/hashtable_node_layout.txt | Hash table node structure |

---

This prevents deadlocks from thread creation under the Windows loader lock.

---

## Glossary

| Term | Full Name | Description |
|------|-----------|-------------|
| **PDD** | ProcessDeferredDestruction | Batch object destructor at `0x00868D70`. Queues objects into 6 typed lists and processes them at safe frame points. See [Chapter 4](#chapter-4-object-lifecycle). |
| **PPL** | Parallel Patterns Library | Microsoft's concurrency framework. FNV uses it for audio streaming only -- NOT for AI threads. See [Chapter 3](#chapter-3-thread-model). |
| **SBM** | Small Block Manager | FNV's pool allocator for small allocations, replaced by mimalloc. See [Chapter 1](#chapter-1-memory-architecture). |
| **TLS** | Thread-Local Storage | Per-thread data via `_tls_index`. FNV stores deferred cleanup flags and allocator pool index in TLS slots. |
| **VA** | Virtual Address (space) | 32-bit process address space. ~2GB addressable (~3GB with LAA), OOM at ~1.8GB in practice. |

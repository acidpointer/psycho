# Vanilla Game Heap Allocation Flow

Ghidra-verified call chains for Fallout New Vegas memory management.
All function names derived from reverse engineering. Addresses are for FNV 1.4.0.525.

---

## Global State

| Address | Name | Description |
|---------|------|-------------|
| `0x011F6238` | `HEAP_SINGLETON` | MemoryHeap object (the SBM allocator instance) |
| `0x011F67B8` | `SBM_POOL_TABLE` | 256-entry pool lookup by aligned size (alloc fast path) |
| `0x011F63B8` | `SBM_ADDR_TABLE` | 256-entry pool lookup by `ptr>>24` (free fast path) |
| `0x011DE70C` | `OOM_RETRY_COUNTER` | Stage 8 retry counter (0..15000) |
| `0x011DEA10` | `TES_SINGLETON` | TES game manager (cell grid, texture cache) |
| `0x011DEA0C` | `TES_THREAD_OWNER` | Stores main thread's TES object for thread ID check |
| `0x01202D98` | `IO_MANAGER` | IOManager singleton (owns 2 BSTaskManagerThread instances) |
| `0x011F11A0` | `PROCESS_MANAGER_LOCK` | Critical section for deferred destruction |

### MemoryHeap Object Layout (`HEAP_SINGLETON`)

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x00 | byte | `initialized` | 0 = not init, use CRT fallback |
| +0x0C | ptr[] | `per_thread_heaps` | Array indexed by TLS value at +0x2b4 |
| +0x110 | ptr | `primary_heap` | Default heap (vtable-dispatched alloc/free) |
| +0x129 | byte | `small_alloc_enabled` | Fast path flag: 1=use pool table, 0=skip |
| +0x134 | u32 | `heap_compact_trigger` | Written by Stage 8, read by per-frame HeapCompact |

---

## Allocation: `FormHeap_Allocate(size)` at 0x00401000

```
FormHeap_Allocate(size):                         // 0x00401000, 21 bytes
    heap = GetHeapSingleton()                     // 0x00401020 -> returns &HEAP_SINGLETON
    return MemoryHeap_Allocate(heap, size)        // 0x00aa3e40
```

### `MemoryHeap_Allocate(heap, size)` at 0x00aa3e40 (486 bytes)

This is the main allocator entry point. ALL game `operator new` calls end up here.

```
MemoryHeap_Allocate(heap, size):
    // --- Guard: not initialized ---
    if heap.initialized == 0:
        return CRT_malloc(size)                   // 0x00aa4290 -> _malloc

    primary = heap.primary_heap                   // heap + 0x110
    if primary == NULL:
        return CRT_malloc(size)

    // --- Size alignment ---
    if size < 9: size = 8
    else: size = (size + 3) & ~3                  // align to 4 bytes

    // --- Get per-thread heap index from TLS ---
    tls_index = TLS[0x2b4]                        // FS:[0x2c] -> TLS array -> offset 0x2b4
    per_thread = heap.per_thread_heaps[tls_index] // heap + tls_index*4 + 0x0C

    // ==========================================================
    // FAST PATH: SBM Pool Direct Allocation (bypasses vtable!)
    // ==========================================================
    if heap.small_alloc_enabled != 0:             // heap + 0x129
        if size < 0x3FD (1021):                   // small allocation
            pool = SBM_POOL_TABLE[size]           // DAT_011f67b8[size]
        else:
            pool = NULL

        if pool == NULL:
            pool = SmallAllocOptimizer(size)      // 0x00aa4960, tries aligned lookups

        if pool != NULL:
            result = SBM_PoolAlloc(pool)          // 0x00aa6aa0
            if result != NULL:
                return result                     // <<< RETURNS HERE, NO VTABLE CALL

    // ==========================================================
    // SLOW PATH: Vtable-dispatched allocation + OOM retry loop
    // ==========================================================
    give_up = false
    stage = 0

    do:
        // Try per-thread heap first, then primary
        preferred = per_thread if per_thread != NULL else primary
        ptr = preferred.vtable.alloc(size, 0)     // vtable offset +8
        if ptr == NULL and preferred != primary:
            ptr = primary.vtable.alloc(size, 0)   // fallback to primary

        if ptr == NULL:
            // Run cleanup stage, advance stage counter
            stage = OOM_StageExec(heap, preferred, stage, &give_up)  // 0x00866a90
            if give_up:
                ptr = CRT_malloc(size)            // last resort

    while ptr == NULL                             // NEVER returns NULL (loops forever)

    return ptr
```

### `SmallAllocOptimizer(size)` at 0x00aa4960 (238 bytes)

Fallback pool lookup when `SBM_POOL_TABLE[size]` is NULL. Tries rounded sizes.

```
SmallAllocOptimizer(size):
    if size < 300:
        return SBM_POOL_TABLE[(size + 15) & ~15]     // round to 16-byte
    elif size < 512:
        pool = SBM_POOL_TABLE[(size + 15) & ~15]     // try 16-byte
        if pool == NULL:
            pool = SBM_POOL_TABLE[(size + 31) & ~31] // try 32-byte
        return pool
    elif size < 576:
        return DAT_011f69f8                           // large pool slot
    else:
        return NULL
```

---

## Free: `FormHeap_Free(ptr)` at 0x00401030

```
FormHeap_Free(ptr):                              // 0x00401030, 21 bytes
    heap = GetHeapSingleton()                     // 0x00401020
    MemoryHeap_Free(heap, ptr)                    // 0x00aa4060
```

### `MemoryHeap_Free(heap, ptr)` at 0x00aa4060 (236 bytes)

```
MemoryHeap_Free(heap, ptr):
    if ptr == NULL: return

    // --- Guard: not initialized ---
    if heap.initialized == 0:
        CRT_free(ptr)                             // 0x00aa42c0
        return
    if heap.primary_heap == NULL:
        CRT_free(ptr)
        return

    // ==========================================================
    // FAST PATH: address-based pool lookup (bypasses vtable!)
    // ==========================================================
    high_byte = (ptr >> 24) & 0xFF
    pool = SBM_ADDR_TABLE[high_byte]              // DAT_011f63b8[high_byte * 4]

    if pool != NULL:
        pool_base = pool + 0x04                   // arena base address
        pool_end  = pool_base + pool.arena_size   // pool + 0x50
        if pool_base <= ptr < pool_end:
            SBM_PoolFree(pool, ptr)               // 0x00aa6c70
            return                                // <<< RETURNS HERE, NO VTABLE CALL

    // ==========================================================
    // SLOW PATH: find which heap owns this pointer
    // ==========================================================
    owner_heap = FindHeapForPtr(heap, ptr)         // 0x00aa45a0
    if owner_heap == NULL:
        CRT_free(ptr)                              // not in any game heap
    else:
        owner_heap.vtable.free(ptr, 0)             // vtable offset +0x0C
```

---

## SBM Pool Internals

### Pool Object Layout

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x04 | ptr | `arena_base` | VirtualAlloc'd base address |
| +0x08 | ptr | `freelist_head` | Head of doubly-linked free list |
| +0x20 | LONG | `spinlock` | Acquired via InterlockedCompareExchange |
| +0x24 | int | `lock_depth` | Reentrancy counter, 0 = unlocked |
| +0x40 | u32 | `block_size` | Allocation size for this pool |
| +0x48 | ptr | `page_refcounts` | Array of short: per-page active block count |
| +0x4C | u32 | `page_count` | Number of entries in page_refcounts |
| +0x50 | u32 | `arena_size` | Total reserved arena size |
| +0x54 | int | `freelist_count` | Number of blocks on free list |
| +0x58 | int | `committed_pages` | Pages committed so far |

### `SBM_PoolAlloc(pool)` at 0x00aa6aa0 (462 bytes)

```
SBM_PoolAlloc(pool):
    AcquireSpinlock(pool + 0x20)

    if pool.freelist_head == NULL:
        // No free blocks -- commit a new page
        page_idx = FindFreePage(pool)                 // 0x00aa6db0
        if page_idx == -1: return NULL (release lock)

        // Commit one 4KB page via VirtualAlloc
        page_addr = SBM_ArenaAllocPage(pool, page_idx)  // 0x00aa6610
        // VirtualAlloc(arena_base + page_idx*0x1000, 0x1000, MEM_COMMIT)

        pool.page_refcounts[page_idx] = 0
        // Carve page into blocks and add to freelist
        for i in 0 .. (0x1000 / pool.block_size):
            FreelistInsert(pool, page_addr + i * block_size)  // 0x00aa6e00
        pool.committed_pages++

    // Pop head from freelist
    block = pool.freelist_head
    pool.freelist_head = block.next                   // block[1] = next ptr at offset +4
    FreelistRemove(pool, block)                       // 0x00aa6e60, unlinks from doubly-linked list

    // Increment page refcount
    page_idx = (block - pool.arena_base) >> 12
    pool.page_refcounts[page_idx]++

    ReleaseSpinlock(pool + 0x20)
    return block
```

### `SBM_PoolFree(pool, ptr)` at 0x00aa6c70 (138 bytes)

```
SBM_PoolFree(pool, ptr):
    if ptr == NULL: return

    AcquireSpinlock(pool + 0x20)

    FreelistInsert(pool, ptr)                         // 0x00aa6e00

    // Decrement page refcount
    page_idx = (ptr - pool.arena_base) >> 12
    pool.page_refcounts[page_idx]--

    ReleaseSpinlock(pool + 0x20)
```

### Freelist Node Layout (inside freed blocks)

```
offset 0: prev pointer (or 0 if head)
offset 4: next pointer (or old head address)
```

### `FreelistInsert(pool, block)` at 0x00aa6e00 (86 bytes)

```
FreelistInsert(pool, block):
    block[0] = 0                              // prev = NULL (new head)
    block[1] = pool.freelist_head             // next = old head
    if pool.freelist_head != NULL:
        pool.freelist_head[0] = block         // old head.prev = block
    pool.freelist_head = block                // head = block
    pool.freelist_count++
```

### `FreelistRemove(pool, block)` at 0x00aa6e60 (72 bytes)

```
FreelistRemove(pool, block):
    if block[0] != 0:                         // has prev?
        block.prev.next = block.next          // prev[1] = block[1]
    if block[1] != 0:                         // has next?
        block.next.prev = block.prev          // next[0] = block[0]
    pool.freelist_count--
```

---

## SBM Arena Management

### `SBM_ArenaInit(pool)` at 0x00aa65b0 (86 bytes)

Reserves VAS for a pool at a predictable address (enables the `ptr>>24` free fast path).

```
SBM_ArenaInit(pool):
    for high_byte = 1 to 254:
        if pool.arena_base != NULL: return     // already reserved
        pool.arena_base = VirtualAlloc(
            high_byte << 24,                   // target address: 0x01000000, 0x02000000, ...
            pool.arena_size,                   // from pool config
            MEM_RESERVE,                       // reserve only, no commit
            PAGE_READWRITE
        )
```

### `SBM_ArenaAllocPage(pool, page_idx)` at 0x00aa6610 (60 bytes)

Commits one 4KB page within a reserved arena.

```
SBM_ArenaAllocPage(pool, page_idx, out_addr):
    *out_addr = pool.arena_base + page_idx * 0x1000
    result = VirtualAlloc(*out_addr, 0x1000, MEM_COMMIT, PAGE_READWRITE)
    return result != NULL
```

---

## OOM Recovery: `OOM_StageExec(heap, active_heap, stage, give_up)` at 0x00866a90

Called from `MemoryHeap_Allocate` retry loop when allocation fails.

```
OOM_StageExec(heap, active_heap, stage, give_up):
    *give_up = 1                              // default: give up
    current_tid = GetCurrentThreadId()         // 0x0040fc90
    main_tid = GetMainThreadId(TES_THREAD_OWNER)  // 0x0044edb0
    is_main = (current_tid == main_tid)

    switch(stage):

    case 0:  // Reset + Texture Cache Flush
        OOM_RETRY_COUNTER = 0
        if is_main:
            TextureCacheFlush(TES_SINGLETON, 0)   // 0x00452490
        break

    case 1:  // Free Cached Geometry
        cache = GetGeometryCache()                // 0x00866d10
        DeallocateAllArenas(cache)                // 0x00aa5c80
        //   Iterates cache arenas, calls VirtualFree(MEM_RELEASE) on each
        break

    case 2:  // Menu Cleanup (main thread only)
        mgr = GetMenuManager()                    // 0x00652110
        if mgr != NULL and CanCleanup(mgr):
            if GetActiveMenuCount() == 1:
                CloseMenu(mgr, 0)                 // 0x00650a30
            FinalizeCleanup()                      // 0x00652190
        break

    case 5:  // Cell Unload (main thread only, falls through to 4 then 3)
        if !is_main: break
        SetPDDGuard(0)                            // 0x00869190
        found = FindCellToUnload(TES_SINGLETON)   // 0x00453a80
        if found:
            UnloadCell(...)                        // 0x004539a0
        else:
            stage--                                // retry as stage 4
        TextureCacheFlush(TES_SINGLETON, 0)
        SetPDDGuard(1)
        PDD_Purge(force=true)                     // 0x00868d70
        // FALL THROUGH to case 4

    case 4:  // PDD Purge (falls through to 3)
        acquired = TryAcquire(PROCESS_MANAGER_LOCK)  // 0x0078d200
        if acquired:
            PDD_Purge(force=true)                 // 0x00868d70
            Release(PROCESS_MANAGER_LOCK)         // 0x0040fba0
        // FALL THROUGH to case 3

    case 3:  // Havok GC / Async Queue Flush
        AsyncQueueFlush(force=true)               // 0x00c459d0
        break

    case 6:  // Allocator Defragmentation (main thread only)
        if is_main:
            SBM_GlobalCleanup()                   // 0x00aa7030
            //   Iterates 256 SBM pools
            //   For each pool: SBM_PurgeUnusedArenas(pool)  // 0x00aa6f90
            //     Finds arenas with page_refcount==0, decommits via VirtualFree(MEM_DECOMMIT)
        break

    case 7:  // Give-Up Check
        if *give_up == 0 and is_main:
            *give_up = 1
            break
        // else FALL THROUGH to case 8

    case 8:  // Worker Thread Sleep + Retry
        if !is_main:
            heap.heap_compact_trigger = 6         // tell main thread to run HeapCompact
            if OOM_RETRY_COUNTER < 15000:
                // Release BSTaskManager semaphores if we own them
                for i in [0, 1]:
                    owner = BSTask_GetOwner(IO_MANAGER, i)    // 0x00866da0
                    if owner == current_tid:
                        BSTask_Release(IO_MANAGER, i)         // 0x00866dc0
                        BSTask_Signal(IO_MANAGER, i)          // 0x00866de0
                Sleep(1)                           // 0x0040fca0
                OOM_RETRY_COUNTER++
                stage--                            // retry previous stage
            else:
                if *give_up == 0:
                    *give_up = 1                   // give up after 15 seconds

    return stage + 1
```

---

## Per-Frame HeapCompact: `HeapCompact_PerFrame(mgr)` at 0x00878080

Called every frame from Phase 6 of the main loop.

```
HeapCompact_PerFrame(mgr):
    if !TryAcquire(mgr + 0x14): return

    heap = GetHeapSingleton()
    trigger = ReadTrigger(heap)               // 0x00878110: return heap.heap_compact_trigger

    if trigger != 0:
        give_up = true
        for stage = 0 to trigger:
            heap = GetHeapSingleton()
            OOM_StageExec(heap, NULL, stage, &give_up)    // runs each stage 0..trigger

        ResetTrigger(heap)                    // 0x00878130: heap.heap_compact_trigger = 0

    Release(mgr + 0x14)
```

Note: `OOM_StageExec` is called with `active_heap = NULL (0)`. Stages that use the heap parameter
(like vtable dispatch) would get NULL, but per-frame HeapCompact only runs cleanup stages (0-6),
not allocation retry. The allocation retry is in `MemoryHeap_Allocate`'s do-while loop.

---

## Per-Frame Arena Management (patched by NVHR, now by us)

At address `0x0086EED4` in the main loop (after AI_JOIN), the game runs a per-frame SBM arena
refcount sweep. We patch this with `JMP +0x55` to skip it.

```
// Original code at 0x0086EED4 (inside per-frame function FUN_0086e650):
if condition_met or timer_elapsed:
    timer = 0
    index = rotating_counter                  // DAT_011deef5, wraps 0..255
    rotating_counter++
    if rotating_counter == 256: rotating_counter = 0
    SBM_DecrementArenaRef(index)              // 0x00aa7290
```

This cycles through all 256 SBM pool slots once every 256 frames (~4 seconds at 60fps),
decrementing arena reference counts. With SBM disabled, this operates on stale data.

---

## Main Loop Phase Order (Ghidra-verified)

```
PHASE 4: Pre-frame cleanup (async flush, texture cleanup)
PHASE 5: Process manager + Havok lock
PHASE 6: HeapCompact per-frame dispatcher      <<< reads heap_compact_trigger
PHASE 7: Per-frame PDD drain (our hook point)  <<< FUN_00868850
PHASE 8: AI dispatch (AI_START)
PHASE 9: Render (while AI runs in parallel)
PHASE 10: AI join (AI_JOIN)
PHASE 11: Post-render maintenance
```

HeapCompact (Phase 6) runs BEFORE our Phase 7 hook. This means:
- When we write to `heap_compact_trigger` in Phase 7, it's consumed NEXT frame in Phase 6.
- When Stage 8 (worker OOM) writes trigger=6, it's consumed on the next main loop iteration.

---

## Cell Unload Flow (Stage 5)

```
FindCellToUnload(tes):                            // 0x00453a80, 824 bytes
    // Searches the cell grid for a cell eligible for unloading.
    // Checks cell arrays at tes+0x38 (worldspace cells) and
    // tes+0x3c (interior cells). For each candidate:
    //   - FUN_004511e0: check if cell is unloadable
    //   - FUN_00557090: additional eligibility check
    // When found: removes from grid array, calls FUN_00462290 to unload.
    // Returns 1 if a cell was unloaded, 0 if none eligible.

UnloadCell(tes, param1, param2):                  // 0x004539a0, 196 bytes
    linked_list = GetCellLinkedList(tes)           // 0x0045bb80
    ClearLinkedList(linked_list)                   // 0x00470470
    //   Iterates list, reads freed nodes at offset+4 (next ptr),
    //   calls DecRef on each node
    ResetCellGrid(tes)                             // 0x00453940
    UpdateLoadedCells()                            // 0x00453a70
    ProcessCellChange()                            // 0x00483710
    ReleaseCellData(tes, param1, 0)                // 0x00455200
    // ... additional cleanup for worldspace transitions
```

---

## PostDestruction: `PostDestruction_Shutdown(state)` at 0x00878200

Called from FastTravel (0x0093cdf0) and CellTransition (0x0093d500) handlers.

```
PostDestruction_Shutdown(state):
    FUN_00a5b460()                            // pre-cleanup (trivial wrapper)
    SBM_GlobalCleanup()                       // 0x00aa7030 (ret-patched by us)
    if state.flag_at_5:
        FinalizeMenuCleanup()                 // 0x00652190
    FUN_008781e0(state.field_at_8)            // state-specific cleanup
    if state.flag_at_3:
        settings = GetSettings()              // 0x0043c4b0
        ApplySettings(settings)               // 0x004a03c0
    BSTask_StopAll(IO_MANAGER)                // 0x00c3e340
```

---

## SBM_GlobalCleanup at 0x00aa7030 (ret-patched by us)

In vanilla, this is the primary mechanism for returning committed memory to the OS.

```
SBM_GlobalCleanup():                              // 136 bytes
    InitCriticalSectionOnce()
    EnterCriticalSection(SBM_CLEANUP_CS)

    for pool_idx = 0 to 255:
        pool = SBM_POOL_TABLE[pool_idx]            // DAT_011f67b8
        if pool != NULL:
            SBM_PurgeUnusedArenas(pool)            // 0x00aa6f90

    LeaveCriticalSection(SBM_CLEANUP_CS)
```

### `SBM_PurgeUnusedArenas(pool)` at 0x00aa6f90 (157 bytes)

```
SBM_PurgeUnusedArenas(pool):
    AcquireSpinlock(pool + 0x20)
    compacted = false

    for page_idx = 0 to pool.page_count:
        if pool.page_refcounts[page_idx] == 0:     // page has zero live blocks
            if !compacted:
                SBM_CompactArena(pool)              // 0x00aa7260, reorganize freelist
                compacted = true
            SBM_RemoveArenaPage(pool, page_idx, 0)  // 0x00aa6eb0
            //   Eventually calls VirtualFree(page_addr, 0x1000, MEM_DECOMMIT)

    ReleaseSpinlock(pool + 0x20)
```

**This is where vanilla actually reduces commit**: pages with zero live allocations are
decommitted via `VirtualFree(MEM_DECOMMIT)`. The VAS reservation stays (for `ptr>>24` lookup)
but physical memory is returned to the OS.

We ret-patched this function. Nothing replaces its commit-reduction role.

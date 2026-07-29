# Gheap large-modlist compatibility contract

## Status and support claim

This audit covers `psycho-engine-fixes` allocator mode `2` on Fallout: New
Vegas 1.4.0.525 under Proton/Wine, with emphasis on large texture packs and
large streamed-content setups. Its dynamic-actor retirement fix applies in
allocator modes `2`, `1`, and `0`. The audit combines source inspection,
existing runtime logs, static analysis of the supported executable, and
Microsoft D3D9/Win32 contracts.

The result is bounded support, not a claim that every possible modlist can
work. A 32-bit process has finite virtual address space (VAS), D3D9 managed
textures retain system-memory backing, arbitrary plugins can collide at the
same hook sites, and malformed or mutually incompatible content remains
outside allocator control. No allocator can make an unbounded working set fit
or make every engine caller handle final allocation failure.

Within those limits, mode `2` owns the complete game/CRT allocation surface
transactionally, preserves large low/mid VAS holes where its tier placement
allows, grows small classes exactly instead of collapsing into the global
medium tier, leaves freed pool/block bytes readable until reuse, and diagnoses
both total free VAS and contiguous-hole pressure. This audit corrected one
confirmed Proton/Wine VAS-accounting defect. An adversarial runtime stress run
is still required before calling a particular extreme modlist validated.

Mode `1` remains the broad-compatibility choice: it replaces the temporary
scrap heap but leaves the game's main object heap intact. Mode `0` is the
allocator-free diagnostic control.

## Executable and API identity

Static conclusions below apply to the repository's current
`fnv_reverse/FalloutNV.exe`:

- file size: 16,084,808 bytes;
- SHA-256: `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`;
- PE32 i386, image base `0x00400000`;
- file characteristics `0x0122`, including large-address-aware;
- game version reported in supplied CrashLogger evidence: 1.4.0.525.

Microsoft's `MEMORYSTATUSEX` contract says `ullAvailVirtual` is unreserved and
uncommitted space in the calling process. The supported Proton/Wine runtime can
nevertheless report a value that disagrees with the regions enumerated by
`VirtualQuery`; this is demonstrated in the runtime evidence below. The policy
therefore uses the `VirtualQuery` region walk, which also exposes the largest
and second-largest holes.

Authoritative API references:

- [MEMORYSTATUSEX](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex)
- [32-bit virtual address space](https://learn.microsoft.com/en-us/windows/win32/memory/virtual-address-space)
- [D3DXCreateTextureFromFileInMemory](https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dxcreatetexturefromfileinmemory)
- [D3DPOOL](https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dpool)
- [EvictManagedResources](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-evictmanagedresources)

## Allocator ownership and startup order

Syringe activates mode `2` at the pre-CRT barrier. The heap-replacer preflight
validates the raw patch manifest and prepares every required trampoline before
reserving allocator VAS. Runtime initialization then creates lazy pool
descriptors, enables the lazy block tier, and caches pre-hook heap ownership.
One modification transaction enables matching free/size/reallocate consumers
before allocation producers, replaces the scrap TLS provider, and disables the
obsolete SBM provider boundaries. A required conflict rolls the transaction
back rather than leaving mixed allocation domains. The first GameHeap realloc
entry is the sole optional entry because its vanilla body still delegates
through mandatory owned operations.

Source ownership:

| Area | Files | Contract |
|---|---|---|
| Activation | `heap_replacer/install.rs`, `manifest.rs` | Preflight, initialize, then transactionally publish all allocation domains. |
| Small objects | `gheap/pool.rs` | 34 exact size classes through 3584 bytes; 69 base and 181 dormant overflow descriptors; lazy 8 MB user reservations with separate metadata. |
| Medium objects | `gheap/block.rs` | On-demand independent 16 MB reservations, 1 MB progressive commit, exact 16-byte alignment, split/coalesce metadata outside user bytes, 64-slot ceiling. |
| Huge objects | `gheap/va_alloc.rs` | Page-rounded reserve+commit above 16 MB; exact side-table ownership; release on free; one retry after retiring fully empty VA-backed medium blocks. |
| Dispatch | `gheap/allocator.rs` | Size-only tier selection; pool failure may use blocks; final failure returns `NULL`. |
| Pressure | `gheap/vas.rs`, `watchdog.rs`, `pressure.rs` | `VirtualQuery` total/holes, commit growth, tier occupancy, fallback/failure counters. No routine cleanup is initiated by the watchdog. |
| Lifetime safety | pool/block metadata and targeted engine guards | Free does not overwrite pool/block payload bytes. Reuse is immediate; only proven stale-reader families receive targeted guards. |

Mimalloc is CRT/pre-hook ownership fallback only; it is not a normal game-object
tier. The vanilla Default and File SBM constructors are suppressed in mode `2`.
The July 20 runtime log confirms both heap pointers were `NULL`, so their tail
adoption/reclamation paths had no backing to recover in that run.

## Large-texture allocation path

Radare2 analysis establishes the following path in
`NiDX9SourceTextureData` at `0x00E68A80`:

1. The source file reports its byte length at `0x00E68B8D`.
2. `0x00E68BA9` calls general allocation wrapper `0x00AA1070` for the complete
   encoded file buffer.
3. The wrapper dispatches through `BSNiAllocator`. Its allocation method at
   `0x00AA2240` reaches `0x00AA4030`, which calls GameHeap allocation
   `0x00AA3E40`. Mode `2` hooks that entry, so large source buffers belong to
   gheap and requests above 16 MB use `va_alloc`.
4. The file is read into that buffer and
   `D3DXGetImageInfoFromFileInMemory` is called at `0x00E68BCD`.
5. When the engine strips top mip levels, `0x00E68D64` allocates a second,
   smaller DDS buffer through `0x00AA3E40`, copies the header/data at
   `0x00E68D72` and `0x00E68DA8`, frees the original through `0x00AA4060`, and
   passes the rewritten buffer onward.
6. Texture creation calls are `0x00E68DCD` (2D), `0x00E68DF3` (cube), and
   `0x00E68E18` (volume). `0x00E68E2B` frees the encoded source buffer through
   `0x00AA10F0`, whose `BSNiAllocator` free method reaches hooked GameHeap free.

The simple D3DX texture API is explicitly equivalent to the extended API with
`D3DPOOL_MANAGED`. Managed resources retain a system-memory copy and are copied
to driver-accessible memory as needed. Evicting managed resources removes only
the driver/default copy; the system-memory backing remains. Therefore:

- gheap owns the encoded source buffer and any transient mip-rewrite buffer;
- D3D9 owns the decoded/created managed resource and its system-memory backing;
- the driver may own a second device-accessible copy;
- source and managed-resource overlap is normal engine/D3DX behavior, not
  evidence that gheap permanently duplicates textures;
- physical RAM or VRAM abundance cannot repair a missing contiguous process
  VAS hole.

Two allocation callsites in this function do not establish a final-OOM safety
contract. The initial source allocation is consumed by the file read without a
local `NULL` branch, and the mip-rewrite allocation is followed immediately by
`memcpy` and header writes. Gheap retries a failed huge direct allocation after
retiring empty medium blocks, but if all owned tiers still fail it returns
`NULL`. Patching these sites to fabricate success would corrupt ownership;
changing them requires a separately proven failure branch and runtime behavior
for a missing texture. This remains a hard boundary, not a solved guarantee.

Existing raw evidence remains in:

- `analysis/ghidra/output/perf/texture_d3dx_path_audit.txt`;
- `analysis/ghidra/output/memory/gheap_default_heap_indirect_dispatch_audit.txt`;
- `analysis/ghidra/output/memory/gheap_heap_domain_and_tail_reachability_audit.txt`;
- `analysis/ghidra/output/memory/gheap_patch_manifest_audit.txt`.

### Texture-size lower bounds

The following values are payload lower bounds for a square 2D texture with a
complete mip chain. They exclude DDS headers, allocator rounding, D3DX decode
scratch, resource objects, alignment/pitch, and any driver copy.

| Dimension/format | Base level | Full mip chain |
|---|---:|---:|
| 4096 BC1/DXT1 | 8 MiB | about 10.7 MiB |
| 4096 BC2/BC3/BC5 | 16 MiB | about 21.3 MiB |
| 4096 RGBA8 | 64 MiB | about 85.3 MiB |
| 8192 BC1/DXT1 | 32 MiB | about 42.7 MiB |
| 8192 BC2/BC3/BC5 | 64 MiB | about 85.3 MiB |
| 8192 RGBA8 | 256 MiB | about 341.3 MiB |

A cube texture has six faces before overhead. Several uncompressed 8K managed
textures can therefore exhaust a 32-bit process regardless of heap quality.
Compressed DDS assets with valid mip chains are materially less demanding, but
their aggregate live set is still finite.

## Runtime evidence

### Fixed-pool capacity collapse, July 13

`.reports/psycho-engine-fixes-latest--unplayable-but-loads.log` predates exact
overflow descriptors. Its 69 base pools reached the complete 552 MB capacity.
Pool fallback then grew by 331,956 events and medium blocks grew to 44 slots.
At the last cited sample, total free VAS was still about 1069 MB and the largest
hole about 784 MB. This was not a texture allocation failure or total VAS OOM;
it was a small-class capacity/performance collapse into the globally locked
medium tier. The current exact overflow design addresses that failure mode.

### Current overflow design and content surge, July 20

`.reports/psycho-engine-fixes-2026-07-20-191754.log` shows:

- more than 5.35 million live pool cells;
- 218 MB committed pool cells, 344 MB user VAS reserved, and 40/4 MB overflow
  user/metadata reservations before the final surge;
- no pool-exhaustion, block-failure, or direct-VA-failure report;
- six medium blocks and 170 MB of live direct VA before a streamed-content
  burst, followed by rapid growth to 29 medium-block reservations;
- immediately before that burst, about 870 MB total free VAS and a 637 MB
  largest hole.

The paired CrashLogger file reports exception `C0000417` at `0x00EC7C62`, only
about 1.05 GiB process virtual usage, 2.14 GiB of 14.94 GiB local graphics
memory, 1,445 loaded textures (3 up to 8192), and 15,195 process-list entries.
That crash is not evidence of VAS/VRAM exhaustion. Its worker/SpeedTree content
path is being addressed by the separate, currently dirty IO/SpeedTree work and
must not be attributed to gheap without new evidence.

This run does prove that exact overflow avoided the old fixed-pool saturation
during the observed interval. It does not prove a long-session plateau or all
texture packs.

### Confirmed VAS-accounting defect

At `16:17:02`, the July 20 `VirtualQuery` watchdog measured 1157 MB total free
VAS, 2139 MB reserved, and 799 MB committed (approximately the complete 4 GiB
map after rounding). Three seconds later the old baseline used
`GlobalMemoryStatusEx::ullAvailVirtual` and logged 3441 MB free. The difference
was about 2.28 GiB. A threshold based on the latter could admit overflow
reservations while the actual process was already near failure.

The correction is:

- `allocator::current_free_vas` returns the `VirtualQuery` summary total;
- baseline and pool-overflow admission share that source;
- the watchdog takes one region sample and reuses it for total-free and
  largest-hole state, rather than mixing counters;
- a failed region walk skips VAS calibration/admission enforcement instead of
  converting an unknown value into a false OOM;
- overflow admission preserves the existing 400 MB total-free threshold plus
  the requested user/metadata reservation;
- huge-allocation telemetry now records live, peak-live, and maximum
  single-allocation bytes; block telemetry distinguishes live from committed
  bytes.

The 400 MB threshold is a reserve policy, not proof that a request will fit.
Large allocations need one hole at least as large as the request. Conversely,
falling below the threshold does not prove immediate OOM. Both total and
largest-hole signals must be inspected.

### Dynamic actor container retirement corruption, July 24

The preserved evidence for this crash is:

- `.reports/CrashLogger-2026-07-24-012706-actor-container.log`, SHA-256
  `96bbbe1f0fc7a28a2828fc84585403346dd9b7d284aa408fabf1a8f73f50a261`;
- `.reports/psycho-engine-fixes-2026-07-24-actor-container.log`, SHA-256
  `cdf5a55d91534ad26bb8eb8913278e791f1957cbe5d5a241c2b6ec9c5290d9a2`;
- `.reports/nvse-2026-07-24-actor-container.log`, SHA-256
  `f2b44ff0d1320ec8796c33510b5d478f946c094a5c1b6ea7ae09778d9a3b1022`.

The CrashLogger call chain is
`0x0063F7B7 -> 0x004816EF -> 0x004816BE -> 0x005F7875 ->
0x00601556 -> 0x0060137F -> 0x0042B8A7`. The object at `0xCF825D00` is
a 640-byte, exact-start gheap allocation for runtime TESNPC `FF002E2B`.
Its `TESContainer` is at `+0x64` and its embedded `tList<FormCount>` head
is at `+0x68`. That head contains `0x01017720`, an image vtable rather than
a `FormCount*`. The allocator log from the same failure reports an attempted
free of `0xD0AC000D`, five bytes into exact 8-byte cell `0xD0AC0008`.
Subpool 1 is the 8-byte class, which exactly matches a 32-bit `tList` node's
`{ data, next }` layout.

This was not an OOM boundary. The last complete watchdog sample reported about
930 MB total free VAS, a 168 MB largest hole, no allocation failure, and about
2.35 million live 8-byte cells. NVSE recorded `DoPreLoadGameHook:
autosave.fos` without the corresponding completed-load hook. The autosave had
completed earlier, so the failure occurred while loading a save over a live
game, not while writing the file.

Radare2 analysis of the executable identified above proves the following
native contract:

- `0x0063F7B0` is the generic embedded-head list removal helper. When a
  successor exists it copies the successor's data and next words into the
  embedded head, clears the successor's next word, and frees that 8-byte node.
  It has hundreds of callers and is not a safe global hook point. Existing raw
  disassembly and decompilation are also recorded in
  `analysis/ghidra/output/crash/radio_station_reconciliation_contract.txt`
  and
  `analysis/ghidra/output/crash/crash_20260712_mod_independent_chain_contract_audit.txt`.
- `0x00481700` clears a `TESContainer`: it destroys each 12-byte `FormCount`
  through `0x00481760`, then removes the list head through `0x0063F7B0`.
  Its ownership callers are the container destructor at `0x004816E0` and
  copy assignment at `0x00481C80`.
- A `FormCount` is `{ count +0x00, form +0x04, extra +0x08 }`; clone code at
  `0x00481A90` allocates 12 bytes. The optional extra allocation at
  `0x00481540` is also 12 bytes. This binary fact overrides the stale xNVSE
  header declaration that makes its final field a `double`.
- Shared `TESActorBase::~TESActorBase` at `0x005F77B0` destroys the
  `TESContainer` at `+0x64`. Both the TESCreature destructor
  (`0x005F7900`) and TESNPC destructor (`0x006013C0`) reach this boundary.
- Changed-form dispatch at `0x00428150` handles ExtraLeveledCreature records
  as type `0x2E`. It clones a replacement dynamic base at `0x0047D130`,
  deep-copies the container through `0x00481C80`, and retires the previous
  `FFxxxxxx` base through its virtual destructor at `0x0042B8A5`. The
  ExtraLeveledCreature destructor does not own its referenced form pointers.

The vanilla allocator contract needed by modes `0` and `1` is preserved in
`analysis/ghidra/output/memory/sbm_freelist_byte_layout.txt`. The current
executable indexes the SBM pool table at `0x011F63B8` by pointer high byte.
Each pool records its arena base at `+0x04`, free-list head at `+0x08`, cell
size at `+0x40`, per-page live-count array at `+0x48`, and arena size at
`+0x50`. Cells begin at exact size-class intervals within each 4 KiB page.
Free at `0x00AA6C70` reaches `0x00AA6E00`, which overwrites the freed cell's
first two words with previous/next free-list links and updates the old head's
backlink. Allocation and free acquire the reentrant pool lock at `+0x20`
through `0x0040FBF0`; the function takes the lock in `ECX`, one diagnostic
label on the stack, and returns with `ret 4`. Page purge at `0x00AA6EB0`
unlinks all cells, calls the decommit helper at `0x00AA6650`, and then writes
`0xFFFF` to the page count. A zero page count therefore proves every cell on a
committed page is free, while `0xFFFF` proves that the page cannot be read. On
a mixed page, matching the pool head or a predecessor's backlink proves an
individual cell is free. The classifier holds the same native lock across the
metadata snapshot and all requested field reads, so purge cannot create a
classification/read race. SBM has no per-cell bitmap, so an exact cell not
found through those links remains structurally plausible rather than proven
live. Non-SBM allocations are classified through cached process-heap ownership
and `HeapValidate`/`HeapSize`.

The direct, proven root cause is therefore a malformed dynamic actor
`TESContainer` reaching its normal retirement destructor. A stale/reused list
node propagated by embedded-head promotion explains both captured pointer
states and is a strong inference. The original writer is not proven: it may be
an engine stale reference, a reuse race, an overwrite, or an external plugin.
No evidence justifies calling this a global allocator defect. The reported EIP
is in the middle of pristine `0x0063F7B0` instructions; without runtime bytes,
the exact reason CrashLogger selected `0x0063F7B7` also remains unresolved.

The engine-fix installer now installs a targeted hook at `0x005F77B0` after
allocator selection, independently of `memory.allocator`. The native
destructor owns a live `this` pointer before any actor subobject is destroyed,
so the shared rejection path reads only the embedded form ID directly. It
performs no WinAPI readability probe, allocator lock, allocation, logging, or
list traversal for ordinary non-runtime forms. This invariant is important
under Wine: the first vanilla/scrap-heap compatibility implementation routed
that embedded read through `IsBadReadPtr`, whose Wine implementation installs
an SEH probe and touches the requested range. That unconditional probe is the
only compatibility work that ran before allocator-mode dispatch and matches
the observed drop from more than 100 FPS to about 20 FPS even in mode `2`.
The code-level regression mechanism and user-reported change boundary agree;
restoration of the original frame rate still requires playtesting the
corrected build.

`IsBadReadPtr` is not marked with a compiler deprecation attribute in the
supported MinGW headers. Microsoft's precise documentation term is
"obsolete," followed by "should not be used." `VirtualQuery` is not a
drop-in validity check: it reports page state and protection, not whether an
address is a live allocation start or whether another thread can retire the
object after the query. Neither API appears anywhere in this guard or its
allocator classifier. The replacement is an ownership chain: native
destructor ownership for embedded actor fields; exact allocator metadata for
gheap and Windows-heap allocations; one locked geometry/count/free-list
snapshot for vanilla pools; and engine registry identity for referenced forms.
This is both cheaper on the ordinary path and stronger than a page-readability
guess.

The nested form proof uses the supported executable's loaded-form resolver at
`0x004839C0`. It is a cdecl function taking one 32-bit form ID and returning
the live pointer from the registry rooted at `0x011C54C0`. The guard first
proves at least 16 bytes of allocator-owned form storage, reads `refID` at
`+0x0C` under that allocator/lifetime proof, and accepts the pointer only when
`LookupFormByID(refID)` returns the same address. Form creation dispatch at
`0x00465110` allocates its produced TESForm objects through FormHeap. A plugin
form is therefore compatible when it follows the engine contract: allocate it
through FormHeap, give it a valid ID, and publish it in the live-form registry.
An arbitrary foreign-heap object that merely resembles TESForm is rejected;
page readability alone would not make such an object valid.

For an `FFxxxxxx` actor, the two embedded container-head words use the same
native-lifetime ownership proof. In mode `2`, the actor must additionally be an
exact live gheap allocation before the guard reads that head. In modes `0` and
`1`, the native destructor call supplies actor lifetime ownership and the guard
classifies every separately allocated container member through the vanilla
allocator contract before invoking vanilla:

- an empty head requires both words to be zero;
- every `FormCount`, optional extra, and successor node must be an exact live
  gheap/Windows-heap allocation or an exact structurally plausible vanilla SBM
  cell with at least 12, 12, and 8 usable bytes respectively;
- gheap pool interior, free, unissued, and uncommitted states are distinct from
  unowned memory; emergency block and direct-VA fallback allocations are also
  recognized;
- vanilla SBM interiors, cells on completely free pages, and cells identified
  by the free-list head or a verified predecessor backlink are rejected; exact
  remaining cells on mixed pages stay provisional because SBM has no per-cell
  bitmap;
- every `FormCount` must contain an aligned, allocator-owned TESForm of at
  least 16 bytes whose embedded form ID resolves back to that exact pointer in
  the engine's live-form registry;
- successor nodes require non-null data, and a bounded allocation-free Brent
  walk rejects cycles and lists beyond 65,536 entries.

Valid lists pass to vanilla unchanged. If any check fails, the guard logs
bounded allocation-state evidence, zeros both embedded head words, and then
calls the original destructor. It does not dereference or free the uncertain
members, round an interior pointer down, attempt partial repair, or reject the
save. This intentionally leaks only the detached corrupt list while its actor
owner is already retiring. A stable free vanilla cell on a mixed page is
rejected through its free-list head/backlink before its fields are trusted.
Complete structure validation remains the fail-closed second layer for a
provisional cell. Hook preparation and activation use one modification
transaction owned by this engine fix. A hook conflict disables only the guard
and is logged; it cannot partially publish the guard or alter the selected
allocator.

Source ownership is
`engine_fixes/actor_container_guard.rs` for the engine contract, validation,
and transactional publication; `heap_replacer/allocation_state.rs` for
mode-independent dispatch and vanilla classification; and
`gheap/allocator.rs` plus its tier modules for exact gheap classification.
`[engine_fixes].actor_container_retirement_guard` owns activation and defaults
to `true`. Disabling it skips only this hook for conflict isolation.
`memory.allocator` still selects only the classification backend, so an enabled
guard installs in modes `2`, `1`, and `0`. The xNVSE helper edits this
restart-only setting and reports the core's installed-state bit; it never
installs the hook or initializes the core.

## Compatibility boundaries

### What is supported by design

- Large plugin/content counts whose live allocations remain within the 4 GiB
  process map and available commit.
- Large compressed texture packs whose encoded buffers, managed backing, and
  active driver resources fit concurrently.
- Small-object populations beyond the original 552 MB fixed base capacity,
  within the per-class overflow descriptor counts and VAS admission policy.
- Medium streamed allocations up to 16 MB in as many as 64 on-demand blocks,
  subject to actual VAS and commit.
- Huge allocations above 16 MB through exact direct reservations, including
  one recovery retry after safe retirement of fully empty VA-backed blocks.
- Pre-hook pointers from recognized ownership domains, which free/size/realloc
  route back to their original heap.

### What cannot be guaranteed

- An unbounded or literally arbitrary modlist. The executable is 32-bit and
  large-address-aware, not unlimited.
- Success when total free VAS is high but every contiguous hole is smaller than
  the texture/decompression/D3D request.
- Success after final OS allocation failure at engine sites that dereference
  `NULL` without a proven failure branch.
- Coexistence with another component that must own the same mandatory allocator
  entrypoint or raw instruction role. Startup rejects incompatible surfaces;
  it cannot merge arbitrary allocator semantics.
- Safety for every unknown stale pointer retained by arbitrary engine/plugin
  code. Pool/block free preserves bytes, but the address can be reused
  immediately. Targeted guards cover proven families only.
- Valid behavior from corrupt DDS/NIF/BSA data, unsupported GPU formats or
  dimensions, driver bugs, script runaway allocation, or mutually incompatible
  content plugins.
- Texture capacity inferred from VRAM alone. Managed D3D9 textures also consume
  process-visible system backing.

## Three-way acceptance gate

### OOM and VAS recovery

The correction improves admission and diagnostics by using actual process
holes. Progressive commit and huge-allocation empty-block retirement are
unchanged. No broad synchronous cleanup was added: re-entering vanilla SBM
recurses through hooked CRT allocation, and arbitrary cleanup from allocation
threads violates Havok/IO ownership. Cost: under true low-VAS pressure, an
overflow class may reach the emergency block fallback sooner. This favors
address-space reserve over peak small-allocation throughput but cannot by
itself guarantee later D3D success. In all three allocator modes, the
actor-container guard does not alter allocation, reclamation, routing, or retry
policy. On the exceptional corrupt-retirement path only, it trades a bounded
leak of uncertain list members for process safety.

### UAF protection

No reuse timing or cleanup stage changed. Pool/block metadata remains outside
user bytes, and a focused regression test proves block free does not overwrite
payload. Immediate address reuse still exists and requires the established
targeted engine guards. Empty-block emergency retirement applies only when the
block has no live allocations; it does not make zombie pointers valid. The
atomic address-page directory publishes a slot only after the block is fully
initialized and locked consumers revalidate every possibly owned pointer, so
lock-free rejection does not weaken retirement safety. Dynamic actor
retirement now validates exact allocation starts against gheap or Windows-heap
ownership, or exact structurally plausible vanilla SBM cells, and detaches a
malformed container before vanilla's promotion/free helper can consume it.
Modes `2`, `1`, and `0` therefore protect the same proven family without
changing global reuse timing or pretending to identify the original stale
writer.

### Performance

There is no new routine per-allocation scan, allocation, log, or lock. A free
or size query for a page definitely outside the medium tier now returns after
one atomic directory load instead of acquiring the medium heap mutex. Owned or
ambiguous pages still take the mutex and revalidate against the live slot;
medium allocation behavior is unchanged. The
watchdog retains a light five-second process-accounting poll for commit growth
and failed-reservation retry state. Full `VirtualQuery` enumeration, allocator
snapshots, class sorting, and detailed log writes run once per 60 seconds,
during baseline calibration, on an explicit dashboard request, or on a lazy
overflow reservation attempt. Normal dashboard chart sampling reads the
published VAS and process caches without starting either operation.
Pressure-state output is
diagnostic only; allocator admission still samples actual VAS when it needs a
decision. Peak/max telemetry adds relaxed atomics only to allocations larger
than 16 MB. The block allocator remains a global mutex and is an emergency path
for small pool failures, not a scalable steady state for millions of small
objects.

When opt-in hitch profiling is enabled at process startup, its compact span
report measures the active portion of the five-second light memory poll
(`memWd`, including detailed work on each twelfth poll). It also records medium
heap alloc/free/size call counts, mutex wait and operation duration, reservation
attempts/failures, commits/failures, and new blocks. Timers aggregate through
atomics and are drained once per hitch window; there is no per-allocation log or
allocation. Hitch and watchdog block snapshots use `try_lock`, marking a miss
instead of waiting behind allocation. The profiled mutex wrapper is a cold,
non-inlined path. With profiling disabled, each medium operation takes one flag
branch directly into the original lean mutex path; QPC calls, 64-bit timing
atomics, and their error handling are absent from the normal i686 code path.

These changes improve contention and attribution without altering OOM cleanup,
VAS placement, commit policy, emergency retirement, or freed-byte readability.
Runtime evidence must still select any larger synchronization redesign; the
global medium-heap mutex is intentionally retained until its measured wait time
justifies the additional lifetime risk.

The actor guard adds one form-ID read to actor destruction. Only retiring
`FFxxxxxx` actors walk their containers. One allocator inspection reads all
needed fields from each FormCount or list node; it does not reclassify the
allocation once per field. Mode `2` takes the existing gheap metadata locks for
exact ownership. Modes `0` and `1` take the relevant native SBM pool lock only
on this cold dynamic-retirement path, read geometry, page state, local
free-list links, and requested fields in one snapshot, then use cached
process-heap validation only for non-SBM candidates. It adds no per-frame,
per-allocation, or ordinary free-path work. The walk is allocation-free and
bounded. Corruption logging is power-of-two limited.

## July 29, 2026 ScrapHeap VAS failure and reusable reserve

This incident establishes a ScrapHeap backing defect under transient 32-bit
VAS pressure and the bounded correction. It does not establish the exact
instruction that raised the final access violation.

### Evidence and classification

Inputs:

- `.reports/psycho-engine-fixes-latest--oom.log`, SHA-256
  `3fb0aa7b5d6b88f5bf31c39f0ffe107f586cf6f4b703f2e459d42e2dea9560a0`;
- `.reports/CrashLogger--OOM.log`, SHA-256
  `99726791d7471bdc7e9727c97dda6a0d65a792634283f30768c84ae3db9fd3bd`;
- supported `FalloutNV.exe`, 16,084,808 bytes, SHA-256
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`;
- `analysis/ghidra/output/memory/audio_playback_lifetime_audit.txt`;
- `analysis/ghidra/output/memory/scrap_heap_identity_thread_contract.txt`;
- `analysis/ghidra/output/crash/crash_00559506_oom_null_audit.txt`.

Proven runtime facts:

- the process repeatedly fell from roughly 840-930 MB free VAS to 76 MB,
  47 MB, and 34 MB, with largest holes of 25 MB, 15 MB, and 1 MB;
- each sampled collapse recovered on the next minute, so the existing
  60-second full `VirtualQuery` interval cannot exclude a shorter collapse;
- the last complete sample, 57 seconds before the crash, had 911 MB free and
  a 175 MB largest hole;
- at `2026-07-29T01:02:31.032Z`, one 128 KB ScrapHeap region exhausted both
  mimalloc's attempt and Psycho's direct `VirtualAlloc` attempt, then used one
  precommitted emergency region;
- at least four more 128 KB mimalloc attempts failed in the following two
  milliseconds while their direct `VirtualAlloc` fallbacks succeeded;
- the report contains no ScrapHeap final-OOM line, gheap pool/block fallback,
  or gheap direct-VA failure. Every allocator failure visible in the log
  recovered;
- CrashLogger recorded `C0000005` on `[FNV] LibAudioUpdate` and Win32 error 8,
  then failed in its own exception handler before writing EIP, registers, or a
  stack.

The `Cannot create a copy of DbgHelp.dll, error: Access denied` line is not a
new deployment failure. Earlier complete CrashLogger reports in the same
writable `Crash Logs` directory contain the same warning and continue through
their calltrace and registry sections. No repository or game-install
permission change is justified by this incident; the material difference is
that the OOM report stopped immediately afterward with `Fatal error in
exception handler`.

The configuration reserved a 16 MB mimalloc arena but set
`mi_option_arena_max_object_size` to 64 KB. Mimalloc v3 routes a 128 KB request
around that arena to its direct OS allocator. `Region::new` then tried a second
fresh OS mapping. The normal ScrapHeap path therefore depended on obtaining
new VAS precisely during VAS collapse. The eight 128 KB emergency mappings
were removed from their reserve when leased and released on purge rather than
returned, so every recovered use permanently reduced future protection.

Win32 last-error is thread-local and a failed `VirtualAlloc` can set error 8.
The CrashLogger value is consistent with the recovered failure, but it is not
proof that the game later received `NULL`. The audio worker's direct static
allocation references use GameHeap; no direct ScrapHeap allocation is proven
in its top-level update functions. An indirect virtual callee remains possible.
Without the missing EIP and stack, the final AV could be an unchecked later
allocation, a stale object, or an unrelated consumer reached during the same
pressure event. No audio hook is justified by the thread name alone.

### Corrected ownership and allocation order

ScrapHeap now owns a protected reusable reserve independent of mimalloc:

- target capacity is sixteen 128 KB regions, or 2 MB committed at startup;
- startup falls back to eight regions, or 1 MB;
- allocator activation fails transactionally if the 1 MB minimum cannot be
  established;
- idle slots remain committed and reserved but are `PAGE_NOACCESS`;
- acquiring a slot changes only that 128 KB range to `PAGE_READWRITE`;
- releasing it restores `PAGE_NOACCESS` and returns it at the tail of a FIFO;
- a failed protection transition permanently retires that slot;
- an `Arc`-owned slot lease prevents the backing reservation from being
  released while any `Region` refers to it.

Allocation order is existing region, standard reserve slot, exact dynamic
`VirtualAlloc`, then one reserve recheck for a concurrent return. Requests
larger than a standard region go directly to exact dynamic backing and cannot
consume the safety reserve. Only a complete acquisition failure enters the
cold OOM path. That path drains at most 32 already queued heap identities,
purges only identities whose live count is still zero, and retries three
times. It never purges a live heap, re-enters vanilla recovery, or calls
mimalloc collection.

Normal regions no longer call mimalloc. Mode `1` therefore does not initialize
or reserve a dormant mimalloc arena. Mode `2` retains mimalloc for CRT
ownership only and establishes the mandatory gheap and ScrapHeap reservations
before mimalloc takes its optional CRT arena. The 64 KB mimalloc arena ceiling
is unchanged.

### Lifetime, locking, and accounting invariants

The existing five-second collector and last-free enqueue timing remain
unchanged. A slot cannot return until `checked_purge` has rechecked a zero live
count while holding that heap's state lock, unpublished `hot_region`, cleared
the region pool, and advanced the generation. This preserves the prior
post-purge invalidation boundary. `PAGE_NOACCESS` gives an idle reserved slot
the same invalid-access behavior as the previous released mapping. FIFO reuse
extends the interval before the same address is selected again.

Lock order is heap-map lookup, one heap's state lock, then the reserve lock.
Reserve acquisition and release never hold the reserve lock while walking or
purging another heap. Existing-region allocation adds no reserve access,
VirtualProtect call, scan, allocation, or log. New-region lifecycle replaces
routine mimalloc/VirtualAlloc/VirtualFree churn with one cold reserve lock and
two protection transitions.

Live ScrapHeap accounting still counts only region capacity currently
published to heaps. Separate counters expose reserve total/usable/in-use/high
water, reserve misses, retired slots, protection failures, dynamic live/total
regions, dynamic failures recovered by the reserve recheck, bounded reclaim,
and final failures. A dynamic mapping failure captures Win32 error, thread ID,
ScrapHeap identity, requested size/alignment/capacity, tick, and a synchronous
`VirtualQuery` summary. VAS summaries also separate committed private, mapped,
image, and unknown bytes. Failure logs remain power-of-two gated; normal
allocation does not log.

### Three-way acceptance

OOM safety improves because up to 1-2 MB of normal ScrapHeap growth no longer
requires a new mapping during a VAS collapse. Oversized and reserve-overflow
requests retain their previous dynamic coverage and honest final `NULL`.

UAF behavior does not make idle ScrapHeap bytes readable. A released slot is
protected before it becomes available, protection failure removes it from
service, live-count and generation gates remain, and FIFO avoids immediate
same-slot reuse. Gheap pool/block zombie readability is outside this change
and remains unchanged.

Performance cost is 1-2 MB of early committed VAS, one reserve lock only when a
new standard region is required or purged, and cold `VirtualProtect`
transitions. Existing-region bump allocation and free are unchanged. The
eliminated per-region OS allocation and release calls should reduce mapping
churn, but runtime hitch evidence remains required.

Validation completed on `i686-pc-windows-gnu`:

- 11 focused ScrapHeap tests passed, covering reserve return, idle
  `PAGE_NOACCESS`, bounded exhaustion, high-water accounting,
  protection-failure retirement, live-count purge exclusion, oversized
  dynamic backing, concurrent shared-identity allocation/free, bounded queued
  reclaim, forced reserve-plus-dynamic failure evidence, and preservation of
  reserve capacity for oversized requests;
- all 111 `psycho-engine-fixes` tests and its doctest target passed, including
  rejection of a non-advancing `VirtualQuery` walk before partial VAS totals
  can be published;
- all 12 `libpsycho` unit tests passed, including memory-type classification;
- the full supported release build passed for `syringe`,
  `psycho-engine-fixes`, `psycho-engine-fixes-helper`, and `omv` before
  concurrent OMV depth-provider edits appeared in the worktree;
- after the documentation and VAS forward-progress regression were added, the
  release build passed again for `syringe`, `psycho-engine-fixes`, and
  `psycho-engine-fixes-helper`; the combined command is currently blocked only
  by unrelated, concurrently changing OMV depth-provider compilation errors;
- private-item rustdoc generation completed for `psycho-engine-fixes` and
  `libpsycho`; remaining warnings come from unrelated existing documentation;
- targeted `rustfmt --check` for every allocator-touched Rust source and
  `git diff --check` passed; the repository-wide formatting check currently
  reports only the concurrent unformatted OMV depth-provider files.

The crate-wide `libpsycho` doctest command still has one unrelated existing
failure: logger documentation uses unsuffixed `0xDEADBEEF`, which overflows
`i32` on the supported 32-bit target. That source was not changed as part of
this allocator correction. Extreme-modlist runtime validation and a complete
CrashLogger stack remain pending.

## Validation matrix for an extreme setup

Static proof cannot certify runtime resource capacity. Validate a candidate
modlist with the same save, route, graphics settings, Proton/Wine build, and
plugin order in allocator modes `2`, `1`, and `0`. Use fresh processes between
modes.

Minimum stress in each allocator mode:

1. Load the heaviest exterior save ten times from a fresh main menu.
2. Traverse dense exterior cells for at least 60 minutes, including repeated
   fast travel between distinct worldspaces and returns to the original cells.
3. Exercise interiors, combat, ragdolls, save creation, and immediate reload so
   IO, AI, Havok, PDD, and texture-cache lifetimes all cycle.
4. Use a texture workload containing many 4K and several 8K BC-compressed
   assets. Add an uncompressed/high-footprint profile only as an explicit limit
   test, not as an expected universally supportable pack.
5. Repeat the route with maximum content/LOD density and both parallel IO
   workers. Preserve Psycho and CrashLogger logs from every mode.

Acceptance requires all of the following:

- selected allocator startup succeeds and the log reports
  `[ACTOR_CONTAINER] Dynamic actor retirement guard active` with the expected
  `gheap + scrap_heap`, `scrap_heap`, or `vanilla` backend;
- no `[VA] alloc failed`, block reserve/commit failure, or monotonically
  cascading block-overflow counter;
- ScrapHeap reports at least eight usable reserve regions, returns unused
  regions after the collector runs, and records no retired slot, protection
  failure, or final allocation failure;
- any reserve miss or dynamic ScrapHeap failure identifies its thread, heap
  identity, request, Win32 error, and failure-time VAS classes;
- exact overflow absorbs class growth without the prior six-figure sustained
  pool-fallback pattern;
- pool committed/reserved bytes, medium live/committed bytes, block slots, and
  direct-VA live/peak bytes reach repeatable plateaus after returning to the
  same cells;
- total free VAS and the largest hole recover after transient texture/load
  peaks and do not trend downward each cycle;
- no `NULL`-consumer, stale-reuse, double-free, SpeedTree, Havok, IO, or texture
  cache crash signature;
- repeated load-over-live cycles complete without the `0x0063F7B7` actor
  container signature; a guard warning is acceptable only when the load
  completes and its counter does not cascade;
- with the guard enabled, steady-state FPS returns to the pre-compatibility
  baseline within normal run-to-run variance in modes `2`, `1`, and `0`;
- mode `2` is not materially slower or hitchier than mode `1` after warm-up;
- texture appearance is checked in game. Compilation and allocation logs do
  not prove image correctness or that D3DX accepted every asset.

If mode `2` alone fails while mode `1` and mode `0` complete the identical run,
the setup is not validated for full gheap. Classify the failure from its last
actual total/largest-hole sample, tier failure counters, request size, crash
site, and pointer ownership. Do not label every location-specific failure OOM,
and do not label every high-memory failure UAF.

## Build and test evidence

Validation completed on `i686-pc-windows-gnu`:

- focused dynamic-actor guard and configuration run: 11 passed, covering
  direct unaligned reads of destructor-owned actor fields, empty and valid
  multi-item lists, both captured corruption signatures, free/undersized/nested
  allocation failures, cycles and bounded walks, exact FF form filtering,
  live-form registry identity, two-word detachment, acceptance of a
  structurally valid vanilla list, and structural rejection of a
  free-list-shaped vanilla cell;
- exact pool-state regression: passed, proving that live, interior `+5`, and
  free cells remain distinct;
- vanilla SBM classifier regressions: 6 passed, proving exact-cell acceptance,
  observed `+5` interior rejection, completely free-page and `0xFFFF`
  uncommitted-page rejection, and free-list head/predecessor detection on
  mixed pages;
- configuration regression: passed, proving the guard defaults on and honors
  an explicit `false`;
- release disassembly of `hook_actor_base_dtor` reads `this + 0x0C`, compares
  the `FF` prefix, and exits to the original destructor before any function
  call for ordinary forms; the dynamic head reads are direct `this + 0x68` and
  `this + 0x6C` loads;
- complete `psycho-engine-fixes` library tests: 59 passed; doctests: passed;
- complete `psycho-engine-fixes-helper` library tests: 12 passed, including
  restart-only setting serialization;
- release build: passed for `psycho-engine-fixes` and
  `psycho-engine-fixes-helper`;
- `git diff --check`: passed.

Until the runtime matrix completes, the honest status is "statically hardened
and build-tested, extreme-modlist playtest pending," not "supports any setup."

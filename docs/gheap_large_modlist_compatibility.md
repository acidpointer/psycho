# Gheap large-modlist compatibility contract

## Status and support claim

This audit covers `psycho-engine-fixes` allocator mode `2` on Fallout: New
Vegas 1.4.0.525 under Proton/Wine, with emphasis on large texture packs and
large streamed-content setups. It combines source inspection, existing runtime
logs, static analysis of the supported executable, and Microsoft D3D9/Win32
contracts.

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
itself guarantee later D3D success.

### UAF protection

No reuse timing or cleanup stage changed. Pool/block metadata remains outside
user bytes, and a focused regression test proves block free does not overwrite
payload. Immediate address reuse still exists and requires the established
targeted engine guards. Empty-block emergency retirement applies only when the
block has no live allocations; it does not make zombie pointers valid.

### Performance

There is no new routine per-allocation scan, allocation, log, or lock. The
watchdog retains a light five-second process-accounting poll for commit growth
and failed-reservation retry state. Full `VirtualQuery` enumeration, allocator
snapshots, class sorting, and detailed log writes run once per 60 seconds,
during baseline calibration, on an explicit dashboard request whose cache has
expired, or on a lazy overflow reservation attempt. Pressure-state output is
diagnostic only; allocator admission still samples actual VAS when it needs a
decision. Peak/max telemetry adds relaxed atomics only to allocations larger
than 16 MB. The block allocator remains a global mutex and is an emergency path
for small pool failures, not a scalable steady state for millions of small
objects.

When opt-in hitch profiling is enabled at process startup, its existing compact
span report also measures the active portions of the five-second light memory
poll (`memWd`, including the detailed work on each twelfth poll) and scrap-heap
reclamation cycle (`scrapGc`). The sleep intervals are excluded. These counters
establish temporal correlation with a reported frame-hitch window; because the
jobs run on background threads, they do not by themselves prove that either job
blocked the main thread. With hitch profiling disabled, each cycle pays only
the existing configuration check and does not query the performance counter.

## Validation matrix for an extreme setup

Static proof cannot certify runtime resource capacity. Validate a candidate
modlist with the same save, route, graphics settings, Proton/Wine build, and
plugin order in allocator modes `2`, `1`, and `0`. Use fresh processes between
modes.

Minimum mode `2` stress:

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

- transactional allocator startup succeeds with no mandatory hook conflict;
- no `[VA] alloc failed`, block reserve/commit failure, or monotonically
  cascading block-overflow counter;
- exact overflow absorbs class growth without the prior six-figure sustained
  pool-fallback pattern;
- pool committed/reserved bytes, medium live/committed bytes, block slots, and
  direct-VA live/peak bytes reach repeatable plateaus after returning to the
  same cells;
- total free VAS and the largest hole recover after transient texture/load
  peaks and do not trend downward each cycle;
- no `NULL`-consumer, stale-reuse, double-free, SpeedTree, Havok, IO, or texture
  cache crash signature;
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

- focused gheap run: 4 passed, covering the overflow reservation boundary,
  unknown-sample fail-open behavior, medium-block split/free/coalescing, and
  block free preserving zombie payload bytes;
- complete `psycho-engine-fixes` library tests: 9 passed;
- release build: passed for `psycho-engine-fixes`;
- `git diff --check`: passed.

Cargo's separate doctest phase still fails on three pre-existing assembly
snippets in untouched `engine_fixes/havok.rs` and `engine_fixes/navmesh.rs`;
their untyped fences are parsed as Rust. This is unrelated to gheap and was not
changed in this scoped audit.

Until the runtime matrix completes, the honest status is "statically hardened
and build-tested, extreme-modlist playtest pending," not "supports any setup."

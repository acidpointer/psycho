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
- [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
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
| Small objects | `gheap/pool.rs` | 34 exact size classes through 3584 bytes; 552 lazy 1 MiB base slabs and 181 dormant 1 MiB overflow slabs with separate metadata. Reservation and commit units match. |
| Medium objects | `gheap/block.rs` | Four shards; exhausted pool classes use dedicated 1 MiB exact-spill extents, 3,585-byte through 1 MiB requests use bounded segregated variable extents, and larger requests use 64 KiB-rounded request-sized extents; fixed availability indexes and 64 KiB-page ownership dispatch cover 1024 lazy extent slots. |
| Huge objects | `gheap/va_alloc.rs` | Page-rounded reserve+commit above 16 MiB; exact side-table ownership; release on free. Final failure enters coordinated native recovery. |
| Dispatch | `gheap/allocator.rs`, `gheap/memory_lifecycle.rs` | Size-only tier selection; pool capacity grows through its matching exact-spill class, while exact resource failure enters native cleanup/retry without contaminating variable extents or re-entering the hooked GameHeap allocator. |
| Pressure | `gheap/vas.rs`, `watchdog.rs`, `pressure.rs`, `memory_lifecycle.rs` | `VirtualQuery` total/holes, commit growth, tier occupancy, and failure counters. Proven VAS pressure is forwarded to one barrier-protected native reclamation transaction; the watchdog never mutates engine or allocator state. |
| Lifetime safety | pool/block metadata, `memory_lifecycle.rs`, and targeted engine guards | Ordinary free does not overwrite pool/block payload bytes. Independently reserved empty medium extents are released only inside the coordinated IO/Havok/scene destruction boundary. |

Controller-sequence IDTag retirement is a separate engine-object contract, not
an allocator policy. The August 17 report had ample VAS and an exact
640-byte gheap slot, but one record contained an unresolved legacy string
offset where native teardown required a fixed-string pointer. The focused
final-owner containment and its allocator-mode acceptance matrix are documented
in `docs/crash_20260817_controller_sequence_idtag_retirement.md`.

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
`memcpy` and header writes. Gheap now retries a failed allocation through the
engine's native cleanup stages and coordinated empty-extent release, but if
those mechanisms cannot produce a suitable hole it still returns `NULL`.
Patching these sites to fabricate success would corrupt ownership; changing
them requires a separately proven failure branch and runtime behavior for a
missing texture. This remains a hard boundary, not a solved guarantee.

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

### Dynamic actor container live-load corruption, August 15

The preserved evidence for the second crash in this family is:

- `.reports/CrashLogger-2026-08-15-023303-actor-container-load-crash.log`,
  SHA-256
  `0964c2fe47a61ecf12b3badb48b249e764cae28ef9a6661dd07e13d58367ab0b`;
- `.reports/psycho-engine-fixes-2026-08-15-023303-actor-container-load-crash.log`,
  SHA-256
  `f916dae2b1397d15e1c04f2e7123021746afdccf9a9e7d218fbcf5bde432c2fc`;
- `.reports/nvse-2026-08-15-023303-actor-container-load-crash.log`,
  SHA-256
  `b5ef6d9e5d9db834d47acf0382c506c3cff097efcacc62c818ac450be87faab7`;
- `.reports/omv-2026-08-15-023303-actor-container-load-crash.log`,
  SHA-256
  `b0f8f9ce0a0780c259102401d5625791970a26a33731e9bd7b2c1cec1e5e5ce5`.

The executable is the same supported FalloutNV 1.4.0.525 image documented
above, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Radare2 analysis of that exact image proves the following access chain and
ABI:

- `0x005629A0` is the Character load owner. Its two direct calls at
  `0x00562B8C` and `0x00562B98` place a live `Character*` in `ECX`, push byte
  modes zero and one respectively, and call `0x00574920` with thiscall ABI.
- `0x00574920` obtains `ExtraContainerChanges::Data*` through `0x004BF220`.
  At `0x005749D1` it calls `0x004D1440`; the observed return address is
  `0x005749D6`.
- `ExtraContainerChanges::Data.owner` is at `+0x04`. `0x004BFFB0` follows
  that owner to its base `TESActorBase` and `0x00717E50` returns the embedded
  `TESContainer` list head.
- `0x004D1440` iterates `tList<TESContainer::FormCount>`. A node is
  `{ data +0x00, next +0x04 }`; `FormCount` is
  `{ count +0x00, form +0x04, extra +0x08 }`. `0x006815C0` returns the
  current node, while `0x00726070` returns its successor.
- At `0x004D1509` vanilla executes `cmp dword [edx+4], 0`, treating `EDX` as
  `FormCount*` before checking whether that allocation exists. Form type
  `0x34` is `TESLevItem`, which this function expands into live inventory.

The CrashLogger frame and stack establish the exact failing values. The
Character is reference `1A03E26B` (`TwigBagREF`) with runtime TESNPC base
`FF00185C`. The `ExtraContainerChanges::Data*` local is `0xF9B4DED8`. The
embedded-head entry completed, the loop index reached one, and the second
list-node local became `0x90000000`. That readable node supplied
`FormCount* 0x452BEF94`; dereferencing its `form` field caused the access
violation at `0x004D1509`. `BGSLoadFormBuffer`, `BGSLoadGameBuffer`, and the
`BSFile` path identify `quicksave.fos` as the active input.

This is not an OOM or rendering boundary. The last allocator sample reported
870 MB total free VAS and a 383 MB largest hole without an allocation failure.
OMV reached 174,000 Presents with zero world-pipeline failures immediately
before the load. The Psycho frames at `0x100BE6FF` and `0x100A69AA` are return
addresses immediately after calls to the original changed-form and top-level
load owners; neither wrapper had begun post-call work. Repeated xNVSE cosave
warnings also occurred on earlier completed loads and do not match this native
call chain.

The direct root cause is proven: a malformed live dynamic-actor container
reached vanilla's unchecked leveled-inventory expansion. The original writer
is not proven. The serialized save may already contain bad state, the
ExtraLeveledCreature clone/copy route may propagate a stale node, a later
engine overwrite may corrupt it, or an external plugin may write it. The
content plugin owning `TwigBagREF` is identity evidence, not attribution.
Likewise, the numeric value `0x90000000` is not evidence about the component
that wrote the node.

The July retirement guard cannot cover this boundary: its actor is dying, so
detaching an uncertain list is behavior-neutral. Here the actor remains live
and owns meaningful inventory. Repair, individual-item skipping, or head
detachment would silently change game state and is therefore prohibited.

The load-time correction is owned by `engine_fixes/save_integrity.rs` because
only its active changed-form owner can reject partial mutation. It adds two
ownership-aware direct-call hooks at `0x00562B8C` and `0x00562B98`. Exact
prefix, inter-call, and suffix fingerprints prove the Character pointer,
mode-byte arguments, and surrounding branch roles. Each hook captures and
chains the existing direct target rather than claiming shared function
`0x00574920`. Both callsites activate in the same rollback transaction as the
changed-record readers and load owner. The owner remains last, so no load can
enter with only part of the policy active.

On the active load-owner thread, the hook reads `Character.baseForm` at
`+0x20` under the native callsite's `this` lifetime. The shared validator in
`engine_fixes/actor_container_guard.rs` then uses one allocator-owned snapshot
to read the base form's `typeID` at `+0x04`, `refID` at `+0x0C`, and embedded
container head at `+0x68`. Non-runtime forms return immediately. A runtime
form must be TESNPC type `0x2A` or TESCreature type `0x2B`, resolve back to the
same pointer through `LookupFormByID` at `0x004839C0`, and pass the complete
container contract established by the retirement guard.

If validation succeeds, the captured predecessor runs exactly once with the
original Character and mode. If it fails, Psycho does not call
`0x00574920`, marks the active changed record with the engine's rejection bit,
latches the whole-load error, and lets the enclosing Character loader unwind.
The general load owner then preserves error bit `0x80` at `+0x244` and returns
zero. No live list word is changed, and no member rejected by the allocation
classifier is read, freed, or leaked by this path. A bounded diagnostic records
Character, changed record, phase, mode, allocator state, actor identity, head
words, and the first failed validation role.

Character loads outside the active owner thread bypass validation and call
their captured predecessor unchanged. This is both an ownership rule and a
compatibility boundary: no global `0x00574920` hook is installed, and no
unrelated load is made to borrow a changed-record pointer. The Windows heap
cache is initialized idempotently by either guard, so disabling the retirement
setting cannot leave save-integrity validation without its allocation
classifier. Configuration layout and defaults are unchanged. The load guard
is controlled by the existing `engine_fixes.save_integrity_fix`; the existing
`actor_container_retirement_guard` continues to control only destructor-time
detachment.

The valid-path cost exists only during a tracked save load. Each Character
performs one base pointer read and one allocator snapshot; non-dynamic bases
stop there. A dynamic base performs the bounded, allocation-free list walk and
registry checks already documented above. No per-frame work, file I/O, OS
readability probe, new thread, blocking render lock, or diagnostic allocation
is added. The exceptional log and terminal rejection are cold-path work.

Regression coverage includes the captured shape with a valid first
`FormCount`, readable successor node `0x90000000`, and invalid nested
`FormCount* 0x452BEF94`; the validator rejects that nested allocation before a
form read. Tests also prove valid multi-item lists, non-runtime bypass,
dynamic type and registry identity, callsite source order, and that a failed
preflight never calls the predecessor while an accepted preflight calls it
once. Required validation is the complete explicit-target crate suite, release
build, formatting, and diff checks.

Validation recorded on 2026-08-15:

- focused actor-container tests: 13 passed, 0 failed;
- focused actor-inventory save-integrity tests: 2 passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib`:
  175 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p
  psycho-engine-fixes`: passed;
- crate-local Clippy with warnings denied passed after allowing the seven
  pre-existing diagnostics outside this change; the unrestricted run remains
  blocked by those diagnostics and three additional `libpsycho` diagnostics;
- the release DLL SHA-256 is
  `f15bee5d6473ecdbd442ec9c42f251119a455c5056f1dc9483549250c00ca70f`;
- the complete imported DLL/symbol sequence is unchanged from the pre-change
  deployment: 368 entries before and after;
- `.tls` remains eight bytes and its four callback symbols remain
  `std::sys::thread_local::guard::windows::tls_callback`,
  `__dyn_tls_pthread`, `__dyn_tls_dtor`, and `__dyn_tls_init`;
- both compiled thiscall wrappers consume their one-byte stack argument with
  `ret 4`.

This patch adds two callsite-hook statics and two pre-owner instruction writes
to the established pre-Deferred core activation. It adds no PE import, TLS
callback, configuration field, worker, file scan, or dependency. Static tests
and PE comparison do not establish loader compatibility: BaseObjectSwapper
must remain installed for repeated cold launch-to-gameplay and quickload
acceptance. The corrupt save must either load safely if a future producer fix
prevents the state or fail through the controlled load-error path without
`0x004D1509`. To identify the original writer, the next rejection must preserve
the failing `.fos`, adjacent `.nvse`, and preceding good save before another
save rotates them.

## Compatibility boundaries

### What is supported by design

- Large plugin/content counts whose live allocations remain within the 4 GiB
  process map and available commit.
- Large compressed texture packs whose encoded buffers, managed backing, and
  active driver resources fit concurrently.
- Small-object populations beyond the original 552 MB fixed base capacity,
  first through per-class overflow descriptors and then dedicated exact-spill
  extents, subject to VAS, commit, and the shared extent-slot bound.
- Medium streamed allocations up to 16 MiB through 1 MiB small extents or
  request-sized large extents, subject to actual VAS and commit.
- Huge allocations above 16 MiB through exact direct reservations and the
  coordinated native cleanup/retry policy.
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
  code. Pool/block free preserves bytes and FIFO increases pool reuse distance,
  but an address can still be reused without a proven engine epoch. Targeted
  guards cover proven families only.
- Valid behavior from corrupt DDS/NIF/BSA data, unsupported GPU formats or
  dimensions, driver bugs, script runaway allocation, or mutually incompatible
  content plugins.
- Texture capacity inferred from VRAM alone. Managed D3D9 textures also consume
  process-visible system backing.

## Three-way acceptance gate

### OOM and VAS recovery

Admission uses actual process holes. Pool reservation now matches its 1 MiB
commit unit, medium placement separates small survivors from large transients,
and final failure enters the engine's native cleanup stages without re-entering
vanilla SBM. Proven process pressure can run one coordinated PDD/async/model
transaction and release empty medium extents. This cannot guarantee success
when no resulting hole fits an external D3D or native request. In all three
allocator modes, the actor-container guard does not alter allocation,
reclamation, routing, or retry policy. On the exceptional corrupt-retirement
path only, it trades a bounded leak of uncertain list members for process
safety.

### UAF protection

Pool/block metadata remains outside user bytes, and block free does not
overwrite payload. FIFO returned-cell queues increase exact-class reuse
distance, but reuse still exists and requires the established targeted engine
guards. Pool slabs remain mapped. An empty medium
extent is released only while the IO dequeue barrier, worker drains,
AI/Havok stop, and native pre-destruction ownership are active. The atomic
address-page directory publishes an extent only after initialization and
locked consumers revalidate every possibly owned pointer. Dynamic actor
retirement validates exact allocation starts against gheap or Windows-heap
ownership, or exact structurally plausible vanilla SBM cells, and detaches a
malformed container before vanilla's promotion/free helper can consume it.

### Performance

There is no routine per-allocation scan, metadata allocation, or log. A free or size
query for a page outside the medium tier returns after one atomic directory
load. Owned pages take only their encoded shard lock and revalidate the live
extent. Medium allocation begins in one shard and uses fixed two-level bitmaps
instead of scanning historical blocks or allocating collection nodes under a
global mutex.
The watchdog retains a light five-second process-accounting poll for commit growth
and failed-reservation retry state. Full `VirtualQuery` enumeration, allocator
snapshots, class sorting, and detailed log writes run once per 60 seconds,
during baseline calibration, on an explicit dashboard request, or on a lazy
overflow reservation attempt. Normal dashboard chart sampling reads the
published VAS and process caches without starting either operation.
Pressure-state output also forwards one request to the main-thread lifecycle;
allocator admission still samples actual VAS when it needs a decision.
Peak/max telemetry adds relaxed atomics only to allocations larger than 16
MiB. Pool exhaustion stays in a matching fixed-size spill extent; if both exact
tiers encounter a resource failure, native cleanup/retry runs instead of
mixing that lifetime into a variable extent. Four shards prevent unrelated
worker traffic from serializing globally.

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

These changes improve contention, placement, and native OOM recovery while
preserving ordinary freed-byte readability. Cleanup and mapping release remain
cold and barrier-protected; runtime evidence must still establish their hitch
cost on the supplied workload.

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

## August 22, 2026 retained-medium-block OOM candidate

This incident proves 32-bit process VAS exhaustion and a gheap recovery
coverage gap. It does not identify the final native allocation owner or faulting
instruction. The preserved CrashLogger report is
`.reports/CrashLogger.2026-08-22-20-01-46.log`; the live Psycho log was
inspected before a later game launch replaced the `latest` file.

### Runtime evidence

The mode-2 session started with 1,004 MB free VAS. A startup/load burst grew
the medium tier from five to 27 independent blocks, and it later reached 32
blocks. Immediately before the crash:

- the medium tier held 154 MB live in 512 MB committed across 32 slots;
- direct VA had no live allocation, and pool, block, and direct-VA counters
  were stable or decreasing;
- total free VAS fell from 196 MB to 43 MB in one minute;
- the largest free hole fell from 15 MB to 1 MB;
- process commit rose by 325 MB and private commit rose by 328 MB while mapped
  and image commit were effectively stable; and
- CrashLogger ended with access violation `C0000005`, Win32 error 8, and no
  usable instruction or stack because its exception handler also failed.

The final surge therefore occurred outside the logged gheap tiers. The thread
label `LibAudioUpdate` does not prove audio ownership, and save activity near
the end does not prove a save allocation caused the surge. The current
ScrapHeap reusable reserve reported no final failure, so this is not a repeat
of the July 29 ScrapHeap backing defect.

Normal medium frees coalesce cells but retain every 16 MB reservation and its
committed prefix. Before this correction, the only empty-block release was
reachable after Psycho's own direct-VA allocation failed. A D3D, audio, or
other Win32 consumer could therefore exhaust process VAS without entering that
recovery path even when gheap owned completely empty medium blocks.

### Bounded correction

This August 22 candidate released an empty block directly from Phase 10. The
August 29 evidence below proved that empty-block retirement alone did not
address the dominant partially-live pinning pattern. It is superseded by the
barrier-protected lifecycle and extent placement contract in the next section.

The watchdog remains diagnostic-only with respect to mutation. On its existing
detailed cadence, an actual `VirtualQuery` sample publishes an allocation-free
request only when total free VAS is at or below 200 MB or the largest hole is
at or below 96 MB. Commit growth alone cannot publish a request.

The existing Phase 10 pressure span consumes the latest request on the main
thread. It tries the block mutex without waiting; contention leaves the request
pending for the next frame. One successful consumption may release every
fully empty, independently VirtualAlloc-backed medium block. It never releases
a block with a live allocation or an adopted Default-heap tail, and it never
calls PDD, Havok, cell unloading, IO cleanup, or a vanilla OOM stage. A
`VirtualFree` failure preserves the block and ownership map. The next detailed
high-pressure sample may publish another request, which bounds retirement to
at most one attempt per detailed sample instead of coupling it to `free`.

Cold snapshots now distinguish empty/reclaimable VirtualAlloc slots from
committed slack stranded inside partially live blocks. If reporter evidence
shows few or no empty blocks during pressure, this candidate cannot recover
the retained VAS. Allocation placement or an exact-size transient lane then
requires a separately captured size/lifetime trace; no threshold or placement
change is authorized by the aggregate incident counters alone.

### Three-way tradeoff and acceptance

- **OOM recovery:** external Win32 consumers can now benefit from empty gheap
  reservations before their own allocation fails. The correction cannot move
  live cells or recover slack inside a partially live block.
- **UAF protection:** normal and watch-pressure frees remain readable and
  unchanged. During proven high VAS pressure, stale pointers into a completely
  empty retired block become unreadable. This is the same last-resort tradeoff
  already made after a direct-VA failure, but it can occur before Psycho sees
  an allocator failure.
- **Performance:** allocation and free placement are unchanged. Detailed
  sampling extends an existing non-blocking snapshot; Phase 10 uses `try_lock`
  and does no work without a pending request. Retirement is bounded by the
  watchdog cadence, preventing the prior rapid retire/recommit cycle.

The candidate is offline-qualified only after the production block path proves
that empty VirtualAlloc slots return to `MEM_FREE` while live and Default-tail
blocks remain valid, the affected tests and supported release build pass, and
the startup footprint checks pass. Runtime acceptance still requires the same
modlist, save, route, settings, and Proton/Wine workload to pass its previous
failure point with a recorded pressure request/recovery outcome and without an
OOM, UAF, or allocator-hitch regression.

## August 29, 2026 transition-retention and native-retry correction

This is the current allocator and engine-memory lifecycle contract. The
preserved combined report is `.reports/mixed-logs-crash.txt`; native proof is
in `analysis/ghidra/output/memory/gheap_oom_deferred_retry_contract.txt`, with
the IO ownership constraints in `docs/parallel_io_engine_contract.md`.

### Runtime root cause

The report proves allocator retention rather than a growing live medium
working set. At `05:18:57`, 30 fixed 16 MiB blocks held 323 MiB live and 474
MiB committed, leaving 150 MiB stranded in partially live blocks. Before the
final failure, the tier had grown to 47 blocks while live bytes had fallen to
233 MiB; commit had risen to 752 MiB and stranded committed bytes to 502 MiB.
Almost every block was partially live, so empty-block pressure retirement
normally had nothing to release. Small survivors and transition-sized buffers
shared the same fixed extent and made the transient reservation lifetime equal
to the survivor lifetime.

The small tier independently retained reservation tails. The final stable
sample reported 543 MiB committed inside 672 MiB of pool user reservations.
The former 8 MiB reservation paired with 1 MiB progressive commit, so each
active class/subpool could retain up to 7 MiB of unusable uncommitted tail.

These two Psycho-owned mechanisms consumed about 630 MiB of address space
beyond then-live allocator payload at the last sample: 502 MiB of committed
medium slack and 129 MiB of pool reservation-over-commit. The final minute also
contained a separate process-wide burst: free VAS fell from 641 MiB to 225 MiB
while the logged pool was stable and the medium tier added only one 16 MiB
block. At the failed 22,369,768-byte direct allocation, 202 MiB remained free
but the largest hole was only 21 MiB. The report therefore proves both
Psycho-owned long-session fragmentation and a final external/native allocation
burst. It does not identify the owner of that final burst; D3D, a plugin, or a
specific content package remains unresolved.

### Allocator correction

Pool reservation and commit are now both 1 MiB. Each class advances to another
slab only after the current slab is full, bounding uncommitted user tail to
less than one slab per active class instead of less than 8 MiB. Address
classification expands from 8 MiB `u8` slots to 1 MiB `u16` slots because the
same configured capacity now has 733 lazy descriptors. Pool frees remain
out-of-band and pool slabs remain mapped, preserving the established readable
zombie contract.

Medium requests are separated by lifetime/size geometry:

- requests through 1 MiB share independently reserved 1 MiB extents;
- larger requests receive request-sized, 64 KiB-rounded extents and never
  share with small survivors;
- four shards replace the process-wide allocator mutex;
- each shard owns fixed two-level availability bitmaps for small and large
  extents;
- one process-wide 64 KiB-page table gives constant-time shard/extent dispatch
  for free, size, and pointer validation; and
- ordinary variable free coalesces preallocated metadata without overwriting
  payload or releasing address space.

This placement makes a transition-sized allocation independently reclaimable
after its own lifetime ends. Fully empty VirtualAlloc extents are released
only from the coordinated engine-memory lifecycle. Adopted Default-heap tail
space is never independently released.

### Native cleanup and retry contract

The supported executable's `GameHeap::Allocate` at `0x00AA3E40` owns a
synchronous allocate/cleanup/retry loop through the stage executor at
`0x00866A90`. Replacing that entry with pure tier dispatch had removed the
engine recovery policy. The stage executor is shared by GameHeap, the
per-frame HeapCompact consumer at `0x00878080`, and two other native heap
paths, so the correction remains at this shared provider boundary rather than
patching consumers or identifying mods.

Final gheap failure now retries the allocation after each native main-thread
stage 0 through 6. Stage 5 may repeat while native cell eviction succeeds.
Worker failures retain native stage 8: publish trigger 6 for the main thread,
release only a semaphore proven to be owned by the current worker, wait one
millisecond, and retry up to the native 15-second bound. A process-wide owner
prevents cleanup allocations from recursively starting another recovery.
Valid calls to the shared stage hook chain its captured predecessor.

Stages that may destroy ownership run only after all required barriers:

1. acquire the IOManager dequeue lock at `+0x20` with the engine's reentrant
   lock ABI (`0x0040FBF0`/`0x0040FBA0`);
2. drain each native IO worker and the BackgroundCloneThread iteration
   semaphore; preventative pressure cleanup never waits for a busy worker,
   while final allocation failure has one 500 ms aggregate emergency budget;
3. stop and drain AI/Havok task groups;
4. enter native pre-destruction setup at `0x00878160`;
5. run the native stage or the pressure transaction at `0x00878250`;
6. release wholly empty gheap extents while those owners remain quiescent;
7. restore native state at `0x00878200`, restart Havok, then release the IO
   dequeue lock.

A detailed watchdog sample at or below the established VAS thresholds forwards
one request to this transaction at Phase 10. It is production pressure relief,
not a diagnostic-only mode. It performs the engine's full PDD, async/model
cleanup, pending cleanup, and allocator extent retirement once per request. It
does not enable periodic PDD, run unconditional cleanup after every load, hook
destructors, change reference counts, classify modules, or patch another mod.

### Three-way acceptance and unresolved runtime gate

- **OOM/VAS:** 1 MiB pool slabs eliminate 7 MiB first-use tails; size-banded
  extents prevent small survivors from pinning transition-sized allocations;
  the native allocate/cleanup/retry policy is restored; and pressure cleanup
  can release empty extents before an external consumer exhausts the process.
- **UAF:** ordinary pool and medium frees still leave payload readable. Empty
  medium mappings become unreadable only while native IO, AI/Havok, scene,
  PDD, and model ownership are quiescent. Pool slabs and Default-tail extents
  are never released by this policy.
- **Performance:** small-pool hot allocation still begins at one class hint;
  medium allocation takes one shard lock and bounded bitmap/list work, and
  pointer dispatch is constant-time. The costs are more lazy 1 MiB OS
  reservations, about 64 KiB more initialized block-directory storage plus
  7.5 KiB more heap-owned pool-directory storage, and cold native cleanup only
  on proven pressure or allocation failure.

Two executable regressions cover the allocator mechanisms. Against the old
production code, one 3,584-byte allocation committed 1 MiB but reserved 8 MiB;
the corrected path reserves exactly 1 MiB. A transition workload containing
12 small survivors and 12 nearly-16-MiB transient allocations previously left
all 12 large reservations pinned; the corrected path retires all 12 large
extents while retaining the survivors in bounded 1 MiB extents.

The final native/D3D burst owner, the exact lifetime of every small survivor,
and gameplay hitch/plateau behavior remain unresolved by static evidence. The
change alters pre-DeferredInit storage and allocator descriptor ownership, so
the representative Proton load-to-gameplay startup gate also remains required.
The supported release artifact retains the baseline imported capability set,
TLS section size, and TLS callback names; no configuration layout or startup
callback was added. This static comparison does not replace the startup gate.
Until the supplied transition-heavy route confirms stable gameplay, at least
one pressure or OOM recovery when exercised, and a non-degrading VAS plateau,
this is an offline-qualified production candidate rather than runtime-accepted
support.

## August 31, 2026 save-load placement regression

The reporter's immediate load test of the preceding candidate did not reach
gameplay. The live `psycho-engine-fixes-latest.log` records 220 small and 17
large medium extents between `22:19:59.097` and `22:22:42.249`. Long contiguous
runs place successive extents about 0.50-0.55 seconds apart. Every logged
extent landed in low/mid VAS through the normal `VirtualAlloc` fallback; none
used the attempted high candidate. The main-loop watchdog then reported a
46,117 ms stale heartbeat while the save remained in load state 5 at
`changed-form-owner-enter`.

This failure precedes the new reclamation policy. At the watchdog samples,
total free VAS remained 942 MiB and then 845 MiB, the largest hole remained
637 MiB, no allocator reserve failed, `heap_trigger` was zero, all PDD queues
were empty, and no `[MEMORY] Native reclamation` transaction ran. The load was
therefore not blocked by pressure cleanup, PDD, an IO barrier, or an exhausted
VAS hole.

The allocator path establishes the cause. Each of four medium shards started a
manual `VirtualQuery` walk at `0xFE000000`. Pool slabs are independent 1 MiB
reservations growing down from the same range, so a new extent revisited those
mappings and then attempted an exact address that could race further pool
growth. When that placement did not succeed, the shard retained its original
scan start and repeated the work for its next extent. Splitting former 16 MiB
blocks into 1 MiB extents correctly removed survivor pinning, but multiplied
this preexisting unbounded placement work from tens of block creations to
hundreds of extent creations. The resulting delay accounts for the observed
load stall; the VAS and lifecycle counters exclude the alternative new paths.

The correction retains the size-banded allocator and native lifecycle:

- frequent 1 MiB extents go directly to normal OS placement, which the failed
  run already demonstrated clusters adjacent low/mid reservations;
- rarer request-sized large extents use one `VirtualAlloc` reservation with
  `MEM_TOP_DOWN`, which Microsoft defines as selecting the highest possible
  address, and fall back once to normal placement if necessary;
- the pool's cold high-address search consults the medium tier's published
  64 KiB ownership directory, avoiding repeated failed exact reservations for
  top-down large extents; and
- no pool/block free, readable-zombie, pressure threshold, native cleanup,
  barrier, or tier-dispatch behavior changes.

The deterministic work bound is now one reservation call for a new small
extent and at most two for a new large extent. It contains no `VirtualQuery`
loop and no per-shard high-scan restart. The three-way impact is:

- **OOM/VAS:** small reservations retain the observed adjacent OS clustering;
  large transition buffers still prefer high VAS, remain independently
  releasable, and cannot be pinned by small survivors.
- **UAF:** payload readability and barrier-protected empty-extent retirement
  are unchanged.
- **Performance:** hot allocation/free and shard locking are unchanged. Cold
  extent growth is constant-work with respect to process mapping count; the
  pool avoids syscalls for published medium-range collisions. Microsoft notes
  that top-down placement can be slower with many allocations, which is why it
  is excluded from the high-count 1 MiB path.

The reporter subsequently confirmed good results with the corrected candidate
on the affected save-load workload. This closes the immediate blocked and slow
load regression for that artifact and setup. No post-fix log or timing was
supplied, so exact load duration and the long-session VAS plateau remain
unquantified.

Because medium allocation is already active before `DeferredInit`, this is
also startup-sensitive. Relative to the deployed failing candidate, the
reviewed release DLL has the same import sequence and eight-byte TLS section;
the correction adds no configuration, static owner, callback, or worker. The
successful reporter run reached the affected gameplay load, providing the
required startup observation for this correction without proving unrelated
future footprint changes safe.

## September 1, 2026 bounded-metadata and reuse-distance candidate

The accepted August 31 placement correction removed the save-load stall. Its
post-fix allocator log also exposes the next bounded costs rather than another
VAS collapse. Near the end of the supplied session, the pool held about
325-326 MiB, the block tier had 281 slots with 118 empty, and approximately
147 MiB live occupied 345 MiB committed. About 167 MiB was immediately
reclaimable and only about 30 MiB was stranded inside partially live extents.
The process still had about 625 MiB free VAS with a 454 MiB largest hole. This
is materially different from the August 29 failure, where partially live
blocks stranded 502 MiB and the largest hole fell below the failed request.

One remaining cross-tier defect is direct: pool class 21, the exact 448-byte
class, used all thirteen configured slabs and then recorded 983 refusals. The
accepted allocator routed each refusal into the general variable block tier.
That preserved allocation success but mixed a sustained small-object lifetime
back into the tier whose reclaimability depends on whole 1 MiB extents. The
source also performed routine `BTreeMap`, `BTreeSet`, `HashMap`, and nested
`Vec` mutation for variable-block placement, and request-sized large extents
paid that general metadata cost despite holding only one live allocation.

The correction is allocator policy, not a diagnostic build:

- after the configured pool slabs refuse a class, that class receives a
  dedicated 1 MiB exact-spill extent with an out-of-band FIFO and no unrelated
  allocation sizes;
- a completely empty variable extent is converted to the needed exact class
  before any new reservation is made, preserving the existing VAS map when
  possible;
- exact resource failure enters the established native cleanup/retry path
  instead of falling back into a variable extent;
- variable extents use 32 subdivisions per power-of-two range, fixed bitmaps,
  intrusive free links, and an exact-start table allocated once when the
  extent is created; request rounding remains below 3.125 percent;
- shard-level small and large availability uses fixed bitmaps and intrusive
  slot links, so allocation does not create or destroy collection nodes;
- request-sized large extents keep only their live/usable-size state and do
  not allocate variable-cell metadata;
- pool and exact-spill returned cells are reused in release order. This keeps
  immediate capacity availability and readable freed bytes while maximizing
  reuse distance within the active class; it is not an epoch quarantine; and
- once the block address directory publishes ownership, a retirement race
  remains fail-closed for free, size, and live-state consumers. A missing or
  replaced slot cannot fall through into the vanilla or CRT allocator domain.

### Three-way effect

- **OOM/VAS:** exact spill prevents observed 448-byte overflow from seeding
  general variable extents and reuses an empty extent first. It still consumes
  one 1 MiB reservation when no reusable extent exists, remains subject to the
  shared slot bound, and is retired only by the existing barrier-protected
  lifecycle. No pressure threshold, PDD stage, worker barrier, or mapping
  release rule changes.
- **UAF:** FIFO increases the number of same-class releases before an address
  is reused, while all free paths continue to leave payload bytes untouched.
  It does not prove arbitrary stale-pointer safety; targeted engine guards
  remain required. The ownership-race correction only changes invalid-input
  dispatch from foreign fallthrough to the allocator's existing fail-closed
  result.
- **Performance:** initialized pool allocation/free remains constant work under
  the existing per-pool lock. Exact spill uses one class head, variable and
  shard availability use bounded bitmap operations, and large extents avoid
  general cell maps. Variable metadata is preallocated for at most 292 cells
  and 512 exact-start slots; creation failure returns allocation failure rather
  than publishing a partially initialized extent. The cost is bounded
  per-extent side metadata and at most 3.125 percent variable-tier internal
  size rounding.

Offline regressions execute the production pool and block paths. They preserve
the original failures for reverse-order pool reuse and post-retirement owner
fallthrough, then require FIFO order and fail-closed ownership. Further
coverage fills and reopens an exact extent, proves exact spill can convert an
empty variable extent without mixing sizes, preserves freed payload, exercises
all variable size bands through repeated split/coalesce churn without metadata
growth, and proves large extents omit variable metadata.

This changes pre-Deferred allocator storage. The representative Proton/Wine
run started with this artifact, reached sustained gameplay, completed repeated
saves, and continued for approximately 50 minutes. The observed 448-byte
burst entered exact spill during initial loading, a later 192-byte burst also
entered its own exact class, and barrier-protected VAS reclamation completed
without an extent-release failure. The owner accepted the runtime result and
approved the commit after that session. No configuration, engine cleanup call,
module classification, or third-party compatibility branch is added.

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

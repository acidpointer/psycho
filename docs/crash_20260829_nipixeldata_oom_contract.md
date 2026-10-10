# NiPixelData final-OOM containment contract

## Status and authorization

This covers the August 29 crash in `.reports/combined-logs-crash.txt`,
byte-identical to `.reports/mixed-logs-crash.txt`. The owner confirmed that
the reporter's workload and contact with the reporter are unavailable, then
explicitly instructed: "This is exception! You must proceed!" That
incident-specific instruction authorizes implementation, including the proven
native owner cleanup, without the otherwise required fail-first game run.

The expanded implementation remains an unreleased defensive candidate.
Static proof and Rust support checks do not establish gameplay, image,
native-hook integration, retry behavior under the modded workload, or startup
acceptance. The original reporter-validation and representative Proton
load-to-gameplay release gates remain unfulfilled. The owner subsequently
requested a commit of this incident candidate. That authorizes recording these
scoped changes; it does not establish runtime acceptance or authorize
deployment, packaging or release.

## Evidence and executable identity

Runtime evidence: [combined report](../.reports/combined-logs-crash.txt).

Native proof applies to `fnv_reverse/FalloutNV.exe`, Fallout: New Vegas
1.4.0.525, PE32 i386, preferred image base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

The radare2 MCP is the primary research interface. Retained raw evidence:

- [Fault and initial propagation](../analysis/radare2/output/fnv_nipixeldata_oom_failure_propagation_contract_20261010.txt).
- [Factory and resolver contracts](../analysis/radare2/output/fnv_nipixeldata_oom_texture_factory_plan_contract_20261010.txt).
- [Cleanup and all conversion consumers](../analysis/radare2/output/fnv_nipixeldata_oom_cleanup_and_consumer_contract_20261010.txt).
- [Supplemental exact PE references](../analysis/radare2/output/fnv_nipixeldata_oom_exact_pe_references_20261010.txt).

The earlier [Ghidra output](../analysis/ghidra/output/crash/oom_memset_crash_analysis.txt)
remains unchanged. Generated prototypes and xref annotations alone are not
ABI or ownership proof; the contracts below follow the actual instructions.

## Runtime proof and root cause

The process used 3.80 of 4.00 GiB virtual address space, or 95.07%. Before the
failure, the medium tier reported 233 MB live, 752 MB committed, and 502 MB
stranded in partial blocks. Pressure retirement released its one provably
empty 16 MB block; the other blocks were not eligible for safe retirement.

At 05:58:21 the 22,369,768-byte request (`0x015555E8`) failed after rounding
to 22,372,352 bytes. Total free VAS was reported as 202 MB and the largest
hole as 21 MB. Whole-MiB logging truncation prevents establishing the exact
hole size or proving it was strictly smaller than the rounded request.

The zero-allocation provider returned NULL for that request. CrashLogger then
recorded `C0000005` on `BSTaskManagerThread` at `0x00EC452A`,
`rep movsd`. The return address `0x00A7C34C` identifies the constructor's
first metadata copy, called at `0x00A7C347`. EDI and EBX were
`0x01555554`; ECX was 12 dwords.

The backing helper `0x00A8F010` computes:

`faces * align4(payload_per_face) + mip_count * 12 + 4`

It stores the allocation result at object `+0x50`, then derives width,
height and offset pointers at `+0x54/+0x58/+0x5C` without testing NULL.
Twelve mip levels require 148 metadata bytes. The observed address equals
`0x015555E8 - 0x94 = 0x01555554`, the payload offset added to NULL.
The constructor then copies into that derived invalid destination.

This proves unchecked allocation-failure propagation at the native consumer.
Returning NULL from the zero-allocation provider prevents its own unchecked
memset but cannot alone protect the constructor. Physical RAM, VRAM,
`blackscorpion.nif`, the mod list, and stack annotations do not identify an
allocator defect, leak owner, lifetime race, corrupting writer or responsible
mod. Attribution and the precise reason the allocation could not succeed
remain unresolved. This change does not alter allocator placement or memory
retirement policy.

## Scoped constructor and disposal contract

`0x00A7A280` owns a private 116-byte conversion destination allocated at
`0x00A7A3DA`, constructs it at `0x00A7A403`, and dispatches the current
converter slot `+0x30` at `0x00A7A412`. Its native false branch at
`0x00A7A482` releases its three source/temporary references and returns
NULL. It does not dispose of the destination, so merely returning early from
the constructor would retain one 116-byte allocation per backing failure.

The retained allocation bridge at `0x00A7C331` calls the original helper.
For NULL backing it admits early return only when the existing Win32 TLS
scope identifies exactly the constructor's EBP destination. This bypasses all
three copies before `+0x68` is marked initialized. Other constructor callers
retain their original behavior. The scope nests and restores per thread; it
adds no PE TLS callback and does not transfer ownership between threads.
The wrapper restores the previous scope before logging or native disposal,
so reentrant providers cannot admit a recycled failed destination address.

The constructor ABI is thiscall: destination in ECX, five four-byte stack
arguments, pointer result in EAX, `ret 0x14`. Its frame saves EBX, EBP, ESI
and EDI above `0xC4` local bytes. The existing bridge discards its own return
and three helper arguments, restores that frame, and returns the destination
to the scoped Rust wrapper.

Before this failure point:

- Base constructor `0x00A5D3A0` sets refcount `+4` to zero and increments
  global NiObject accounting at `0x011F4400`.
- The native constructor sets its vtable and palette `+0x4C` to zero.
- The allocation helper writes backing `+0x50` to NULL.

Native delete `0x00A7C450`, thiscall with one stack flag argument, invokes
destructor `0x00A7C390`; flag bit 1 frees the 116-byte object through
`0x00AA1460`. The destructor reads the initialized palette, calls
`0x00A8F060` for backing disposal, and runs base destructor
`0x00A5D3D0` to balance accounting. It never reads the uninitialized
completion flag or consumes derived metadata. `0x00AA10F0` returns for
NULL before loading or dispatching any allocator, proving native free(NULL)
is allocator-mode agnostic.

The scoped wrapper now invokes that native delete exactly once for the known
private backing failure and returns NULL. The converter guard rejects NULL
with AL=0, allowing the existing local source cleanup to run. Arbitrary
unreadable/malformed destination rejection remains rejection only: it does
not authorize disposal. Successful construction returns its original result;
valid conversion invokes the live installed slot-`0x30` provider once with
unchanged destination, source and mip arguments.

## Complete native conversion-consumer coverage

The supported image contains one absolute reference to `0x00A7A280`, in
converter vtable `0x0109D9C4` slot `+0x14`, and no direct branch to it.
All ten native calls to getter `0x00A76640` were inspected. They divide
into file loaders using slot `+0x0C`, format admission using `+0x10`,
and the four conversion consumers below.

Exact references to converter global `0x011F4A7C` were also checked:
the getter, initialization/replacement at `0x00A76AB0/0x00A76B60`,
shutdown at `0x00A76B30`, and final release at `0x00FDB060`.
The latter also only decrements/releases; it is not another conversion
consumer. Native slot-`0x14` consumption is:

| Native owner | Conversion call | Containment |
|---|---|---|
| 2D factory `0x00E68EF0` | `0x00E6934A` | Guard the shared result continuation at `0x00E6934E` |
| Cube factory `0x00E8ABF0` | `0x00E8AF5B` | Preserve its native error fallback; guard the final result at `0x00E8AF90` |
| 2D refresh `0x00E689D0` | `0x00E68A3C` | Guard before upload and generation stamp at `0x00E68A3E` |
| Cube refresh `0x00E8B0C0` | `0x00E8B115` | Guard before face reads/upload and generation stamp at `0x00E8B117` |

This coverage concerns the supported native image. It does not enumerate or
classify third-party modules, rewrite their hooks, or guarantee an unknown
external consumer's behavior.

## Factory ownership and failure propagation

Both factories are cdecl with source texture and renderer stack arguments,
caller argument cleanup, and pointer result in EAX. They publish a successful
texture to source `+0x24`; rejecting an unpublished candidate must not
execute that store.

The 2D factory's 132-byte outer allocation at `0x00E68F33` could return
NULL and continue into dereferences. The new bridge at `0x00E68F3D`
returns NULL before construction, restoring EDI/EBP/ESI/EBX and the
`0x28` local frame. There is no constructed owner or held pixel reference
to dispose at this boundary.

At the conversion-result boundary, ESI is the pixel result and EBP is the
fully constructed, unpublished texture owner. The original source-reuse
branch at `0x00E69330` jumps directly to `0x00E6934E`. Patching from
`0x00E6934C` across this branch target would corrupt that path. The patch
therefore starts at the common `0x00E6934E` instruction. Non-NULL input
replays its resource comparison and selects the original create/upload path.

For NULL, the bridge calls native delete `0x00E68EA0` with flag 1.
Its palette release and base teardown `0x00E8A2B0` own any native resource
detach/COM release and balance base accounting. The pixel reference retained
at native `[esp+0x28]` is then released exactly once via the existing
NiPointer destructor `0x00B66F20`. That destructor admits NULL and owns
the InterlockedDecrement and live virtual final release. Rust does not rewrite
engine reference counts. The retained pixel stays alive throughout texture
deletion. The bridge restores the native frame and returns NULL without
publication or success-only callbacks.

The cube factory also needed containment for its 136-byte allocation at
`0x00E8AC3C`. The `0x00E8AC4A` bridge restores EDI/EBP/ESI and
`0x1C` locals on NULL; EBX has not yet been saved at this site.

Cube conversion already tests NULL and invokes native error callback
`0x00A62A10`. The installed callback's result can be NULL; the original
code then dereferences it. The new `0x00E8AF90` guard preserves that
fallback invocation and sends its final NULL to the already existing
`0x00E8B0A7` delete-and-NULL epilogue. This precedes upload, temporary
pixel-reference acquisition, memory-accounting publication and source
publication. Cube native delete `0x00E8AA40` and teardown
`0x00E68830/0x00E8A2B0` own the fully initialized outer object.

The exact PE scan and MCP disassembly establish all native direct factory
callers, with no absolute pointer reference to either factory:

| Factory call | Existing/result handling |
|---|---|
| `0x00E6DC5F` | Renderer releases its critical section and converts NULL to false |
| `0x00E90B68` | New guard cleans two factory arguments, then uses existing `0x00E90BAA` unlock/NULL return before setting the construction output |
| `0x00E90CB3` | New guard cleans two arguments, then uses existing `0x00E90CFC` unlock/false return |
| `0x00E68F71` | 2D factory cube dispatch propagates the cube result to those callers |
| `0x00E6DCE4` | Cube renderer releases its critical section and converts NULL to false |

Resolver vtable `0x010F086C` already exposes NULL/false results and
initializes failure output flags. Those failure continuations restore their
native frames and release the held lock once. No new result encoding is
invented. Successful bridges replay the displaced argument cleanup, output
store and continuation unchanged.

## Refresh state and ABI invariants

NULL conversion in either refresh method now uses the existing void-return
epilogue, before result dereferences or uploads and before updating
generation `+0x7C` (2D) or `+0x84` (cube). The prior published resource
and generation stamp remain available for the native later-update check.
Palette handling that precedes conversion stays native and is not rolled back.

These are instruction-level JMP bridges, with no extra return address. Each
failure path uses its verified native saved-register layout. Success replays
the comparisons whose flags remain live through subsequent moves/copies.
EAX is dead or immediately overwritten at every chosen jump continuation.
Diagnostic cdecl calls preserve native registers with pushad/popad. No
destructor is hooked; cleanup executes synchronously on the original thread
and only for locally owned unpublished objects.

## Implementation, installation and costs

The existing `memset_null_dst_guard` key/default and core activation owner
are retained. `memset.rs` owns zero-allocation providers, TLS construction
scope, allocation bridge and local conversion guard.
`pixel_texture_failure.rs` owns native consumer bridges, owner cleanup,
fingerprints and failure counters.

Preflight verifies every owned patch and the constructor initialization,
cleanup routines, accounting, held-reference and native return contracts
before writes. Foreign changes to those contracts or either original
zero-allocation slot cause installation failure, without identifying a mod.
Valid dynamic converter providers remain native policy.

One `ModificationTransaction` installs resolvers and refresh consumers
before factories, then local converter/allocation/constructor guards and both
zero-allocation slots. Installed state is published only after commit.
Rollback restores only modifications still owned by Psycho. A failed
transaction can reuse the already prepared process-lifetime Win32 scope slot.

The diagnostic ownership result covers all eleven required instruction
patches. Counters distinguish zero-allocation NULL, backing failure,
conversion rejection, outer allocation failure, factory abort, resolver
failure and refresh rejection. Existing logger output uses the stable
`[OOM]` tag and samples first/power-of-two failure counts.

Successful paths add bounded result checks and the existing per-thread scope
work. Replacement storage is fixed; new consumer diagnostics require no
heap allocation. Failure performs native teardown and sampled logging.
There is no new per-frame polling, worker, setting, module inspection,
allocator ownership classification or global memcpy interception.

The change adds core code, fixed patch owners and zero-initialized counters
at the existing pre-Deferred activation boundary. It does not change the
configuration layout, dependencies, helper ownership or startup phase.
Those static/code-layout deltas still require the startup contract's runtime
acceptance. A preserved pre-change build can support an import/TLS/ABI
comparison; it is not a substitute for the recorded accepted startup artifact
or a representative Proton run.

## Qualification and unrun behavior

The existing production destination-reader and Win32 TLS support tests run
outside the game. They check that actual Rust admission and nested/thread
scope behavior execute as intended; they do not reproduce native construction,
resource upload, teardown, publication, or the reporter's crash. No mock,
copied formula, fake vtable, reconstructed shader or source assertion was
added as a substitute.

Required static checks are the focused support checks, affected crate suite,
supported `i686-pc-windows-gnu` release build, formatting, diff check and
compiled bridge/ABI review. Qualification results are reported with the
implementation handoff; they do not promote it to runtime acceptance.

The focused support checks and complete affected crate suite passed through
Wine with serialized test execution. The initial parallel run failed the
allocator's released-region memory-state assertion; that unchanged test
passed alone and in the complete serialized suite. The precise parallel
failure cause was not established; allocator production code and tests were
not changed for this incident.

The supported 32-bit release build, compiled bridge/cleanup ABI review,
changed-file formatting and diff checks passed. Whole-workspace formatting
still fails on untouched `omv/src/backend/fnv/owned_depth.rs`. That repository
formatting gate is not reported as passed. Imports, exports, TLS storage and
TLS callback identities match the preserved pre-change core artifact. That
comparison does not establish agreement with the unavailable accepted
startup artifact or prove startup behavior.

The unavailable game acceptance cases remain: reported backing failure,
both outer-object failures, resolver lock/output behavior, 2D/cube refresh
failure and retry, fallback failure, repeated rejection without leaked owners,
successful provider/rendering behavior, concurrent/nested loading,
disabled/rejected installation, allocator modes 0/1/2, and representative
Proton load-to-gameplay startup. No gameplay/FPS or runtime leak-freedom claim
follows from static qualification.

Other constructor callers, general conversion-provider false-result ownership,
preexisting native error-fallback paths before the guarded conversion
boundary, the allocator/VAS layout cause and third-party integration remain
outside the proven incident scope. This is scoped native OOM containment,
not a general memory-exhaustion recovery guarantee.

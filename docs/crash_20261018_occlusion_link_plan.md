# 2026-10-18 occlusion linked-pointer crash investigation

Status: an unreleased defensive candidate is implemented as a separate engine
fix. It rejects unreadable native plane ranges before compound construction.
The writer, allocation history and recurrence on the current build remain
unresolved. Gheap corruption is not established. The owner requires static
research, forbids debug-only builds and requires the occlusion-planes module
to remain untouched.

## Evidence and scope

The sole incident input is `CrashLogger.2026-10-18-22-39-21.log`, preserved
under `.reports/20261018-occlusion-plane-crash/`. Its SHA-256 is
`840de2770f9c6526235baff5d4a8f2554af2c77cdf26afede07df1a8d6a82139`.
There is no corresponding Psycho log, configuration, dump, allocation history
or reproducible workload. Current logs/configuration are not evidence for this
older session and were not used.

The archive time is 22:39:21. The header's 22:37:41 is the session start;
playtime is 00:01:39. The player was in FairfaxRuinsExterior01, cell
`06001165`, world `0607EA1F`, at approximately
`(-19144.60, -49009.26, 13048.51)`. This is location context, not proof
of which cell or plugin owns the invalid link.

[Native disassembly, caller references and ownership evidence](../analysis/radare2/output/crash_20261018_occlusion_link_contract.txt)
were collected against `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, image base `0x00400000`. The executable beside the discovered
archive has the same hash. The report identifies FalloutNV 1.4.0.525 and the
same image base. It does not contain executable hashes or in-memory code bytes;
the incident's exact patch state and Psycho source revision remain unknown.

## Established fault

The access violation is at `0x00C33887`:

```text
0x00C3387B  mov [ebp-0x1B8], ecx
0x00C33881  mov eax, [ebp-0x1B8]
0x00C33887  movzx ecx, byte [eax+0xE5]
```

EAX and ECX are `0xA5000000`. The supported instruction therefore reads
`0xA50000E5`: the dirty byte of an invalid occlusion-plane object.
This is an invalid non-null `this` pointer, not a null allocation result or
a fault inside an allocator operation.

The function is the camera-dependent plane-cache producer. Its layout and
normal operation are documented in
[runtime visibility research](fnv_runtime_visibility_injection_research.md).
Checking only the dirty byte is already too late to recover safely: the method
also needs the plane's geometry, cached planes and camera coordinates.

## The failing argument is a linked plane

The two reliable native return addresses distinguish the objects:

| Evidence | Meaning in the verified executable |
| --- | --- |
| `0x00B5F285` -> return `0x00B5F28A` | Scene visibility builder calls `0x00C47D20`, passing ESI as its plane argument. |
| ESI `0xD01A9900`, decoded as `BSOcclusionPlane` | The source plane being processed; a recognizable header does not prove lifetime. |
| `0x00C47E41` -> return `0x00C47E46` | The earlier cache call uses the source plane itself. This is not the reported failing call. |
| `0x00C47EAB` / `0x00C47EAE` -> return `0x00C47EB3` | Load the linked-pointer local `[EBP-4]` into ECX and call the cache producer. This is the failing call. |

At `0x00C47DBE`, that local receives a selected source-plane link from
the four DWORD slots at `+0xEC, +0xF0, +0xF4, +0xF8`.
`0x00C35980` selects the occupied link axis; the following branches select
one occupied slot. The builder checks the selected link only for null before
its cache call; it does not acquire ownership of the linked target.

The function's decoded instructions contain only one direct assignment to
`[EBP-4]`, at `0x00C47DBE`. The intervening native calls prepare the
source frustum, rectangle and plane-side comparison. The report establishes
the invalid value at the linked-plane call boundary. It does not capture the
four source slots, so it cannot independently distinguish a bad stored link
from corruption of the local after it was loaded.

The frame arithmetic independently agrees with the call path:

- Fault EBP `0x0170F5D0` minus `0x1BC` locals and eight saved-register
  bytes equals recorded ESP `0x0170F40C`.
- The saved `this` at EBP minus `0x1B8` is ESP plus 12, stack slot
  `03`, which also contains `0xA5000000`.
- Caller EBP `0x0170F75C` minus its `0x174` locals, 16 cache-call
  argument bytes and eight call/frame bytes equals `0x0170F5D0`.

The source slot index, source reference/FormID, linked target identity, and
both objects' allocation and retirement states are absent. Other recognizable
planes and terrain/water LOD nodes on the stack are context, not identification
of the offending allocation.

## The unwind warning is not heap-corruption proof

The optimized caller `0x00B5F170` saves EBP and then executes
`mov ebp, ecx` at `0x00B5F19D`. EBP is its context pointer, not a
frame pointer. The next reported EBP, `0xFE506400`, is consistent with
that register use. Following it as another stack frame produces the subsequent
unreliable addresses.

Consequently `(Corrupt stack or heap?)` is an unwind diagnostic, not
independent evidence of heap or stack corruption. This does not rule out a
corrupting write; it removes that label as proof of one. The DbgHelp
`Access denied` message concerns the logger's symbol-helper setup and does
not identify the write that supplied the bad object pointer.

## Link publication and native ownership

Static research establishes a narrower ownership contract than a generic
scene-list failure:

- Default plane constructor `0x00C335D0` clears all four link slots at
  `0x00C336FD`. Missing initialization of those slots is not present in
  that constructor.
- Setter `0x004181C0` is thiscall `(plane, index, linked_plane)`,
  `RET 8`. It stores the supplied pointer at `plane+0xEC+4*index`.
  It performs no retain, release or incoming-link bookkeeping.
- Its discovered direct caller is `0x00417714`, in native reference
  post-load fixup. That path iterates indices 0 through 3, resolves linked
  references, obtains their planes and publishes the links.
- Getter `0x00422120` obtains extra-data type `0x71`
  (`ExtraOcclusionPlane`) and reads its plane pointer at `+0x0C`.
- Setter `0x00422150` manages that extra's pointer through
  `0x0066B0D0`, which releases the old plane and retains the new one.
  The extra is therefore a strong owner; the four plane links are raw borrows.
- Extra teardown `0x00435740` destroys that owning pointer through
  `0x0045CEC0`. Plane destruction `0x004A6110` -> `0x004A7090`
  delegates to the reference-object base and frees a `0xFC`-byte object.
  Those inspected routines do not repair incoming plane links.

This proves where a lifetime invariant must exist. It does not prove that the
engine's complete surrounding cell/reference lifecycle fails to maintain it,
or that a target retirement caused this incident. Direct-call references are
not a claim of complete indirect-call or plugin-write coverage.

The current Psycho runtime factory also uses the zeroing constructor and then
sets size, position, rotation and the side-test byte. Its ordinary factory path
does not create non-null plane links. Current code does not establish that the
feature was enabled, that this source object was injected, or that the same
implementation was installed during the incident. Do not attribute the crash
to generated planes from the class name alone.

## Assessment of the gheap hypothesis

The report says a custom heap replacer was detected and lists the Psycho core.
It does not establish allocator mode 2, successful gheap activation, the
allocation tier of either pointer, or a free/reuse event.

The reported 1.39 GiB virtual usage out of 4 GiB is not an allocation-failure,
commit-limit or largest-free-hole measurement. It neither proves OOM nor rules
out a transient allocation failure. No allocation-failure record is supplied.

The current gheap implementation stores pool free-list links in side metadata
and leaves freed payload bytes intact. Its production pool free path does not
write an `0xA5` poison pattern. A plane is `0xFC` bytes; a recognizable
header and an address aligned like a pool cell still cannot prove ownership,
live allocation state, or the identity of a reused object. These are current
source facts, not reconstruction of the incident's allocator state.

Accordingly, stale reference use, target retirement/reuse, an unrelated
overwrite, invalid publication, and corruption of the caller's local remain
unresolved alternatives. None can be selected solely from `0xA5000000`.
Changing gheap reuse order, quarantine, pool sizes, payload clearing or pressure
cleanup would not be an evidence-backed fix for this report.

## Existing fix history

The follow-up history check compares commit `4f70a6c` (2026-10-18 22:17
+0300) with `5e35ab7`. The earlier commit is a source comparison baseline,
not an identification of the DLL installed during the incident.

| Change | Relationship to this report |
| --- | --- |
| `e5777cb`, openings and cached neighbors | Changes geometry coverage, alpha-property recognition and neighbor selection. No linked-plane ownership repair is established. |
| `f53398b` / `353bc83`, generation and merge budgets | Bound frame workload; no guard at the reported linked-plane consumer. |
| `efb4f11`, fade linked-owner guard | Guards `BSFadeNode +0xCC` at actor-alpha callsite `0x00B4E772`; this is a different object and consumer. |
| `5e35ab7`, radio null-base correction | Guards reference/base reads in radio candidate enumeration; it does not cover this non-null plane argument. |

Between those endpoints, the heap-replacer tree and
`multibound_vertex_setup.rs` have no changes. The runtime plane creation,
retain, release, deletion and list-unlink function bodies are also unchanged.
The injection/diff flow has been reorganized, but this does not establish a
repair of the reported invalid argument.

No matching targeted fix was found. Because the original writer and deployed
revision are unknown, an incidental upstream correction cannot be excluded.
Keep this as an unresolved historical report; neither current recurrence nor
an already-fixed disposition is proven. History alone does not establish an
upstream ownership or allocator correction.

## Authorized separate engine fix

The owner explicitly requested implementation of this incident's correction as
a separate engine fix, with no edits to the occlusion-planes module. This
permits the scoped, unreleased defensive candidate under the
[reporter-only exception](psycho_engine_fix_exception.md). It does not establish
the writer or permit an allocator/ownership repair without further proof.

[occlusion_link_guard.rs](../psycho-engine-fixes/src/mods/engine_fixes/occlusion_link_guard.rs)
is installed from the existing engine-fix startup owner. It operates in every
allocator mode and independently of runtime plane generation.
`[engine_fixes].occlusion_link_guard` defaults on; false skips the installer on
the next full launch. The helper exposes the restart-only **Occlusion link
guard** checkbox. There is no new dependency, worker, event callback or TLS
owner. The runtime occlusion-planes module and its native object factory are
unchanged.

### Intervention, ABI and fail-closed behavior

[Additional native boundary evidence](../analysis/radare2/output/crash_20261018_occlusion_guard_boundary.txt)
records the full argument setup and continuation of all six discovered direct
callers: `0x00B5F285`, `0x00B5F353`, `0x00B5F5BB`, `0x00B5F6D3`,
`0x00B5F822`, and `0x00B5F8EF`. Each passes the context in ECX and one plane
pointer on the stack. The builder returns with `RET 4`; every caller ignores
the return registers. They continue their native list/program processing.

The builder has a native path which contributes no output. After the initial
linked-plane comparison, `0x00C4809A` dispatches on the native link-axis result.
A result of 2 reaches `0x00C480B9` and jumps directly to the epilogue at
`0x00C487EE`. No compound instructions or plane count were appended on this
path. Thus an omitted contribution is already tolerated, including within the
caller's enclosing program markers. Returning before builder entry on an
unreadable input uses this existing void/no-contribution result; it does not
invent frustum coefficients or report fabricated clipping success.

Each game-owned callsite has its own captured provider. Installation checks
its complete argument setup and three following instructions, while the E8
callee remains dynamic. The shared builder entry, provider modules and plane
objects are not patched. No module identity or provider/vtable allowlist is
used. Readable inputs forward the original context and plane exactly once.

### Admission and ownership

The guard uses the existing core-only `ReadProcessMemory` wrapper, without
directly dereferencing engine storage. It copies the source's complete
`0xFC`-byte range and selects the first non-null link in native slot order
0, 2, 1, 3 from `+0xEC..+0xF8`. It then checks only that target's complete
`0xFC`-byte range. All-null links remain native absence. End-address overflow,
failed copies and partial transfers reject the contribution before any builder
output changes. The source and target ranges cover the native cache, rectangle
and linked-plane fields, including the
reported dirty-byte read.

The native axis helper `0x00C35980` and selection at
`0x00C47D3A..0x00C47DBE` establish this priority. The later axis-1 lookup at
`0x00C486CF` consumes the same selected slot under the native link-stability
contract. Unselected targets are never probed: an unreadable unused link must
not suppress an otherwise admissible contribution. An unreadable selected
target rejects rather than falling back to a lower-priority link.

Selection completes before the same stack buffer is reused to validate the
target. Snapshots and pointer values remain local to the call. Rejection does
not clear links, free objects, retain references, change ownership, classify
allocator membership or alter engine lists. The first rejection emits the
ordinary release warning `[OCCLUSION_LINK]`; normal calls log nothing. Guard
reads and rejection logging preserve the incoming Win32 last-error value.
After forwarding, the provider's own error state is left intact.

Guarded copies establish readability at the copy boundary only. They do not
prove object identity, pin allocations, prevent a concurrent writer, detect a
readable reused object, or close post-copy invalidation. Readable inputs keep
the installed provider's native lifetime and threading preconditions. This
candidate rejects a source or selected target already unreadable at entry.
The report does not prove whether its invalid argument existed at that earlier
boundary. The unknown lifetime/overwrite defect has not been repaired.

### Installation and performance costs

Installation stays at the existing quiescent pre-CRT engine-fix boundary.
All caller contexts are verified and all predecessors published before the
first write. One ownership-aware transaction activates the six calls; only
then does admission become active. Failed initialization retains native calls.
A failed rollback survivor has admission disabled and forwards its already
published predecessor. Captured providers and hook state remain process-owned.
The configured wrapper returns installation errors through the core startup
`Result` and owns the disabled and post-success `Guard active` messages. The
hook module owns only runtime rejection reporting.

Admission uses one `0xFC`-byte stack buffer and one selected integer pointer.
It performs one or two guarded copies per builder call, at most 504 copied
bytes, with no routine allocation, timer, pointer cache, allocator query or
Rust lock. Runtime copy cost and game frame-time impact are unmeasured. This
bounded overhead is the containment cost, not an FPS improvement claim.

### Qualification and remaining gate

The release regressions execute the actual production admission and all six
production rejection bridges against real readable/no-access OS pages. They
exercise null sources, each of the four link slots, native selection priority,
unreadable unused links, partial-page ranges, address overflow, unchanged source
bytes and last-error preservation. The selection regression failed against the
original all-links admission and passes with selected-link admission. Native
providers are unpublished, so an accidental forward of a rejected input fails
instead of passing a mock. Byte buffers expose read ranges; they are not
substitute native objects or a reconstructed clipping test.

The focused regressions, affected crate release suite, supported 32-bit release
build, scoped formatting and diff checks pass. Release disassembly confirms
that all six bridges retain ECX context, one stack argument and `RET 4`;
rejection returns before the provider call. Core/helper import sequences,
delay imports, TLS state and CRT initializer identities match the preserved
startup baseline. This comparison does not certify startup. The owner explicitly
authorized committing this unreleased candidate after static qualification.
No game run, debug-only build or deployment was performed. Gameplay rejection
and continuation, valid clipping output, runtime cost and startup acceptance
remain unverified. The candidate remains unreleased until the reporter and
startup gates are met.

## Upstream repair boundaries

A durable owner repair still requires identification of the invalidating
operation. Trace the `ExtraOcclusionPlane` replacement/removal callers and
reference/cell fixup around `0x00417714` and `0x00422150`; establish when linked
owners coexist, when links are cleared or rebuilt, and which thread owns each
transition. If stale topology is proven, remove a borrow before its target can
retire and rebuild the correct relationship when available. If an overwrite or
overlapping allocation is proven, correct that writer or allocation operation.
The present report cannot select between them.

An allocator proposal must also satisfy the
[gheap OOM, stale-reader and performance gates](../psycho-engine-fixes/src/mods/heap_replacer/gheap/AGENTS.md).
Changing reuse order, quarantine, payload clearing or pool sizes cannot be
called a root-cause correction without the missing write/retirement evidence.

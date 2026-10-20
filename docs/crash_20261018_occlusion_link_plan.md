# 2026-10-18 occlusion linked-pointer crash investigation

Status: an unreleased defensive candidate is implemented as a separate engine
fix. It rejects unreadable native plane ranges before compound construction.
The writer, allocation history and recurrence on the current build remain
unresolved for the October 18 report. The October 21 follow-up below verifies
a related failure through a readable code address while this guard is active;
the original writer remains unknown. Gheap corruption is not established. The
owner requires static research, forbids debug-only builds and requires the
occlusion-planes module to remain untouched.

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

This section records the original October 18 readability-only candidate. The
October 21 follow-up below extends its admission to the native cache writes.

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

## October 21 follow-up: readable linked pointer, forbidden cache write

Status: an unreleased defensive candidate extends the existing guard's
admission to native cache-write permissions. The owner reports "Just walking"
and subsequently authorized proceeding with the proposed October 21 plan.
This is incident-specific authorization under the reporter-only exception.
No game execution, debugging, debug-only build or deployment is authorized or
claimed; local qualification uses release-profile offline tests and builds.

### Incident evidence and identity

The complete Crash Logger report and matching Psycho log are preserved in
[the incident archive](../.reports/20261021-occlusion-cache-write/inputs.txt),
together with the discovered configuration and deployed core DLL. The crash
archive is named `CrashLogger.2026-10-21-00-50-10.log`; its header's
`00:42:58` is the session start, matching the Psycho startup at
`2026-10-20T21:42:58Z`. Reported playtime is `00:07:11`. The player was in
`FFRaiderCamp05`, cell `06002C86`, Capital Wasteland, at approximately
`(-91257.80, -53345.41, 16226.68)`.

The Psycho log identifies source revision `3de831c4b7e73303239781247671e07576d2f396`.
It records successful startup, gheap/scrap activation, the occlusion-link guard
and runtime plane generation. The discovered configuration agrees:
`memory.allocator = 2`, `engine_fixes.occlusion_link_guard = true`, and
`performance.occlusion_planes = true`. Neither source identity nor the
currently installed files capture all in-memory patches at the instant of
failure. The deployed core's two return addresses additionally match the
reported stack exactly, as detailed below.

The installed game executable and research executable are byte-identical:
FalloutNV 1.4.0.525, PE32 x86, base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
This was rechecked before reusing the addresses. Raw evidence:

- [Complete camera-cache producer](../analysis/radare2/output/crash_20261021_linked_plane_cache.txt).
- [Complete rectangle getter and writeback](../analysis/radare2/output/crash_20261021_linked_plane_writeback.txt).
- [Independent instruction, frame, code-address and deployed-guard verification](../analysis/radare2/output/crash_20261021_occlusion_write_verification.txt).

### Verified immediate failure

At `0x00EC456C`, bytes `88 07` execute `mov byte [edi], al`.
EDI is `0x004F00F5`, ESI is `0x0170F478`; the preceding source read has
already completed. The supported copy routine takes destination, source and
length as three cdecl stack arguments. Report stack slots `04`, `05`, `06`
contain those same pointers and length `0x30` respectively. This is a write
fault during rectangle-cache publication, not a failed source read or a null
allocation result.

The reliable native chain is:

| Reported return | Verified call and argument ownership |
| --- | --- |
| `0x00C35DE9` | `0x00C35DE4` copies 48 bytes from the caller's rectangle buffer into `this + 0xA8`. |
| `0x00C33963` | `0x00C3395E` calls rectangle getter `0x00C35C10` with the camera-cache producer's saved plane and its local four-corner output. |
| `0x00C47EB3` | `0x00C47EAE` calls camera-cache producer `0x00C33870` with the selected linked plane from `[EBP-4]`. |
| `0x10082B49` | Deployed `occlusion_link_guard::dispatch`, immediately after forwarding to its captured provider. |
| `0x1006EB81` | Deployed `occlusion_link_guard::build::<0>`, immediately after calling dispatch; this bridge returns with `RET 4`. |
| `0x00B5F28A` | Game-owned first builder callsite, matching that bridge. |

The plane is therefore `0x004F00F5 - 0xA8 = 0x004F004D`.
There are independent checks beyond this subtraction:

1. Getter EBP `0x0170F2D8` minus its `0x114`-byte frame puts its saved
   `this` at `0x0170F1C4`. That is report ESP plus seven DWORDs, stack slot
   `07`, which independently contains `0x004F004D`.
2. Producer EBP `0x0170F4A8` minus `0x30` is `0x0170F478`, exactly the
   reported rectangle source. Frame sizes, saved registers and call arguments
   also reproduce both intervening EBP values and the fault ESP.
3. radare2 exact disassembly and GNU objdump independently agree on the store,
   the `this + 0xA8` destination and both native caller continuations. Deployed
   DLL disassembly independently resolves both Psycho frames to the guard.

`0x004F004D` and its complete `0xFC`-byte range lie in the game's readable,
executable `.text` section. They are instruction bytes, not a plane allocation.
The apparent dirty bytes at `this + 0xE4/+0xE5` are both `0xCC` in the
verified file, consistent with entering both recomputation paths and reaching
the observed writeback. Those file bytes corroborate the path; they are not a
dump of the incident's memory protections or patch state.

This verifies an invalid linked-plane pointer reaching mutable native cache
code. It does **not** identify the original corrupting writer or prove a
particular use-after-free, allocator defect, race, injected plane or plugin.

### Why the existing guard permits this failure class

The deployed bridge copies the source, chooses one link in priority order
0, 2, 1, 3, copies that target, then forwards the original pointers. Its
`copy_plane` checks address overflow and a complete `ReadProcessMemory`
transfer only. It does not check whether the target's native cache is writable.
A pointer into readable executable bytes satisfies that admission contract.
The log records guard activation, and the deployed return addresses prove the
guard was on this call path. The report does not retain its earlier snapshot,
so it cannot prove whether the bad value already existed at admission or
changed before the linked-plane call.

The native methods require mutation, even though callers request geometry:

| Plane-relative bytes, inclusive | Native write |
| --- | --- |
| `+0xA8..+0xD7` | Rectangle getter publishes four corners at `0x00C35DE4`. |
| `+0xE4` | Rectangle getter clears its dirty byte at `0x00C35DF2`. |
| `+0xD8..+0xE3` | Camera-cache producer stores camera XYZ at `0x00C33CB7..0x00C33CC2`. |
| `+0x44..+0xA7` | Camera-cache producer publishes 25 DWORDs at `0x00C33CD6`. |
| `+0xE5` | Camera-cache producer clears its dirty byte at `0x00C33CDE`. |

Thus successful reads alone cannot establish the input contract. The previous
guard's documented readable-invalid-object limitation is now observed as a
concrete write fault on its forwarded path. Writable memory alone would still
not prove object identity or lifetime.

### Attribution limits

The report does not capture the source plane pointer, four source link slots,
selected index, source reference, target allocation history or invalidating
operation. The native builder loads its selected link into `[EBP-4]`; the
report establishes the bad value at its later consumer, not the original
publication. The verified raw setter `0x004181C0` still stores a borrowed
pointer at `+0xEC+4*index` without retaining it. The earlier ownership research
defines a possible lifetime boundary, not proof that retirement caused this
incident. Indirect/plugin writes and concurrent changes remain unclassified.

Runtime plane generation was active. Its factory calls the native zeroing
constructor, which clears link slots at `0x00C336FD`; ordinary creation does
not establish a non-null link. The incident cannot identify the source as an
injected or authored plane. Charon's script and terrain nodes on the stack do
not establish ownership of the offending link.

The allocator log reports pool fallbacks, memory growth and other guards'
rejections. It does not connect them to this plane. The recorded fallback
sample has no block or virtual-allocation failures; the last VAS sample has
560 MB free with a 425 MB largest hole. These earlier samples neither prove
OOM nor exclude a later transient failure. The copy has a non-null code
destination and no allocation on its failing path. There is no evidence-backed
allocator correction for this incident.

The optimized visibility owner uses EBP as a context pointer at `0x00B5F19D`.
The later unwind warnings and DbgHelp copy failure do not independently prove
heap corruption. Trace attribution stops at the reliable frames above.

### Containment correction and acceptance gates

The correction is contained in the existing `occlusion_link_guard.rs`, before
builder output changes:

1. Keep the full `0xFC`-byte guarded read for the source and the selected
   target. Additionally require their proven mutable cache range
   `[plane+0x44, plane+0xE6)` to be committed, writable and unguarded across
   every intersected region, using the existing `libpsycho` WinAPI wrappers.
   Check arithmetic and reject a query failure. Never probe writability by
   writing, change page protection, or permit code-memory mutation.
2. Preserve all-null absence, selection priority and untouched unused links.
   Reject an inadmissible selected target without trying another slot. Keep
   the existing native no-contribution return, original provider capture,
   exact-pointer forwarding and Win32 last-error contract. Do not rewrite or
   clear links, alter refcounts, blacklist addresses or vtables, change the
   allocator, or disable occlusion.
3. Use fresh mapping checks per invocation. No persistent permission cache,
   new worker or ownership inference is supported. Mapping checks establish
   permissions only at admission; they cannot close a later lifetime race or
   reject a writable reused object. Measure added query cost before making
   performance claims. If broader lifetime repair is proposed, first obtain
   direct evidence of the writer or target retirement and its synchronization.
4. The actual incident boundary is the game-owned builder call through the
   guard, with its actual linked plane and native cache writes. Valid authored
   and generated clipping must remain correct; invalid input must return
   before any builder output or plane mutation. Real OS protection tests of
   the production admission/bridges can support this gate, including a
   read-only selected target, read-only source cache, boundary-crossing cache,
   inaccessible unused links and unchanged source/context on rejection. They
   do not replace the native clipping/incident test. Do not create source
   assertions, a reconstructed shader/geometry model or a fake provider.
5. The owner's "proceed with plan" authorizes this scoped defensive candidate
   under `psycho_engine_fix_exception.md`. The report supplies the native
   failure; the exception overrides only the unavailable fail-first/same-game
   test and no-production-edit gates. Release-profile offline tests exercise
   the production memory-admission and rejection bridges. Native clipping,
   continued gameplay, timing and startup acceptance remain unverified.
   No release, packaging, deployment or commit is authorized by this request.

The production guard queries each mapping intersecting the mutable cache
before its existing guarded read. Region arithmetic is checked, and queries
must make forward progress. A failed query, nonwritable/guarded/uncommitted
mapping, overflow or incomplete read rejects the contribution. Permissions
outside `[+0x44,+0xE6)` need only support the original complete object read.
For example, a readable nonwritable header does not reject an otherwise
writable cache. Source and selected-target snapshots stay call-local; no
mapping or permission result is cached between calls.

This adds mapping queries to the existing one-or-two-copy admission cost.
The checked cache is 162 bytes; a query is repeated only when that span crosses
a returned mapping boundary. There is no new allocation, lock, worker,
configuration field, dependency, callback, TLS owner or startup activation.
The setting retains its name, type and position. Log and dashboard text now
describe read/cache-write admission. No runtime occlusion-generator, native
provider, engine list or object ownership logic changes.

### Offline qualification and remaining acceptance

The release-profile regression failed against the unchanged production guard:
an actual read-only OS page was readable and was incorrectly admitted. It
passes after the cache-permission correction. The focused regressions also
exercise all selected slots, the exact last writable cache byte at a mapping
boundary, read-only bytes outside the cache, fresh permissions after restoration,
unused read-only links, address overflow and inaccessible ranges. All six
production bridges reject read-only or guarded source/selected-target storage
before an unpublished provider can be called, preserve source links and Win32
last-error, and leave the page's guard bit intact. These are real memory-access
and rejection-path observations, not execution of native clipping or proof of
the original invalidating writer.

The affected core/helper release-profile suites and complete supported
`i686-pc-windows-gnu` release build pass. Scoped formatting, documentation links
and diff checks pass. The build retains existing unrelated warnings.
[Qualification logs and startup comparison](../.reports/20261021-occlusion-cache-write/implementation/affected-suites.log)
are preserved beside the fail-first result, focused results, release build and
`startup-footprint.json`.

[Compiled candidate disassembly](../analysis/radare2/output/crash_20261021_occlusion_guard_compiled_abi.txt)
confirms cache mapping checks precede the guarded read, both admission failures
return before provider dispatch, and all six bridges retain their original
thiscall argument and `RET 4` shape. The import sequences, delay-import state,
TLS callback/shape and CRT initializer identities agree with the preserved
pre-edit artifacts. The core's TLS template bytes move only with the relocated
pointer to the existing `_mi_thread_locals_empty` symbol. The core baseline is
the incident artifact that reached gameplay; the helper baseline is the
pre-edit local artifact, whose deployed identity was not established. This
comparison does not certify startup, and binary layout still moves.

The candidate is unreleased and not deployed. No game run,
debugging or debug-only build was performed. Native clipping output, continued
gameplay after a real rejection, startup and frame-time cost remain unverified.
Under the reporter-only exception, release acceptance still requires reporter
evidence of a rejection followed by continued gameplay; startup acceptance also
remains a release gate. This is a reporter-validation candidate only.

The immediate invalid-pointer/cache-write mechanism and the guard's missing
writability contract are additionally verified, and that admission gap is
covered by the candidate. The original bad publication
or invalidation remains unresolved. A complete root-cause ownership repair
cannot be specified from this report alone; existing memory evidence showing
the source slots and their writer or retirement history would be needed. This
research does not request a debugging run or relax the owner's restrictions.

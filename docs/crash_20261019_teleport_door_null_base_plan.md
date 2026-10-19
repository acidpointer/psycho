# 2026-10-19 teleport-door null-base crash investigation and fix plan

Status: unreleased defensive candidate implemented at the statically proven
Psycho radio consumer boundary. Offline qualification is recorded below;
gameplay acceptance remains unverified. The upstream writer is unresolved.
The owner requires static evidence collection and forbids debug-only builds.

## Report and preserved evidence

The owner reported a crash while walking in the Capital Wasteland, without a
specific interaction or reproducible route. Crash Logger archived the incident
as `CrashLogger.2026-10-19-17-40-19.log`. Its header time, `17:23:53`, is the
session start; reported playtime is `00:16:25`. Psycho's timestamps are UTC,
three hours behind the reported local times.

The complete Crash Logger and Psycho logs, the configuration read during this
investigation, and provenance are retained in
`.reports/20261019-teleport-door-crash/`. The configuration was copied after the
incident; its identity with the session-start configuration is not independently
proven. Runtime logs establish allocator mode 2, two-worker IO, and active radio
expansion optimization. No process dump was found immediately under the
discovered game root. No unchanged local reproduction was run.

Current binary evidence:

- [Faulting enumerator, bytes, lock and compiled caller](../analysis/radare2/output/crash_20261019_teleport_door_null_base_fault.txt).
- [DLL references after `aar`](../analysis/radare2/output/crash_20261019_teleport_door_dll_callers.txt).
- [Native enumeration, accessors, lock and dispatch](../analysis/radare2/output/crash_20261019_teleport_door_native_contract.txt).
- [Native references after `aar`](../analysis/radare2/output/crash_20261019_teleport_door_game_callers.txt).
- [Caller recovered from the installed release DLL and captured stack](../analysis/radare2/output/crash_20261019_teleport_door_release_caller.txt).
- [Native reference and cell membership owners](../analysis/radare2/output/crash_20261019_teleport_door_native_owners.json).
- [Native recursive lock protocol](../analysis/radare2/output/crash_20261019_teleport_door_native_lock.txt).
- [Complete enumerator, lock wrappers and append instruction contracts](../analysis/radare2/output/crash_20261019_teleport_door_enumeration_contract.json).
- [Compiled inlined append body and its game-entry installation](../analysis/radare2/output/crash_20261019_teleport_door_append_inline_contract.json).
- [Emitted release candidate ABI and rejection branch](../analysis/radare2/output/crash_20261019_teleport_door_candidate_abi.txt).

The supported executable and the executable beside the live log have SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`:
FalloutNV `1.4.0.525`, PE32 x86, image base `0x00400000`. The inspected installed
pathing DLL is identified in the fault audit. No dump establishes that its
on-disk bytes equal the incident's in-memory bytes. The source location, module
extent, offsets and register state agree with the inspected implementation.

## Established failure

Crash Logger reports `EXCEPTION_ACCESS_VIOLATION`, EIP `0x0A6FC36C`, in
`TESObjectCELL__GetTeleportDoors+0x4C`. The module load base is `0x0A6D0000`,
so the fault RVA is `0x2C36C`, preferred VA `0x1002C36C`.

The inspected instructions are:

```text
0x1002C369  mov eax, [ecx+0x20]       ; reference baseForm
0x1002C36C  cmp byte [eax+4], 0x1C  ; base form type == door
```

The captured EAX is zero. This instruction therefore reads address `0x4`.
There is no null-base check between the load and dereference. The enumerator
reached a reference in the cell object list whose base-form value was null at
that read. The missing check is the immediate consumer defect. Whether this
was a live incomplete reference, a stale reference, or another corruption is
unresolved; a readable reference prefix is not lifetime proof.

EDI is `0xFC423EE0`, identified by Crash Logger as cell `000846EA`, Wilderness
in `WastelandNV` (`000DA726`), state Not Loaded. The player is in a different
world: cell `060017BC`, world `0607EA1F`. The radio search reached a remote
cell. Its caller is established by the physical stack proof below, rather than
by the remote location or the optimization's activation log.

Crash Logger omits ECX. Consequently the offending reference pointer/FormID is
unknown. Its generic unwind fails, but the recorded stack and exact compiled
prologue suffice to recover the caller without another runtime capture.
The listed door `00116C66` has an identified base form; its stack presence does
not establish it as the offending reference. Likewise, a cell's last-modifier
plugin does not identify the writer of a runtime null base.

EBP is `0x007CB2E0`, exactly the append-function address deliberately loaded
into EBP by this optimized enumerator. It is not a frame pointer here. The
logger's next-frame label, `(Corrupt stack or heap?)`, does not independently
prove stack or heap corruption.

## Caller recovered without a diagnostic build

The enumerator saves four registers and makes no further persistent stack
adjustment before the fault. Its return address is therefore `[ESP+0x10]`,
stack slot `04`: `0x76C0124E`. Psycho's recorded module base `0x76BA0000`
maps that address to RVA `0x6124E`, preferred VA `0x1006124E` in the installed
release DLL. The actual instruction at `0x1006124C` is `CALL ESI` (`FF D6`);
its exact return address is `0x1006124E`. The existing COFF symbol identifies
the containing function as `radio::provider::dispatch_body`, with `expand`
inlined into it. No source-level debug information or new build is needed.

The saved registers independently confirm the match:

| Captured value | Compiled meaning |
| --- | --- |
| Stack `00`, `0x0170CED0` | Caller EDI, live `TeleportDoorSearch` query. |
| Stack `01`, `0x0A6FC320` | Caller ESI, the faulting enumerator's entry. |
| Stack `02`, `0x0170CDB8` | Caller EBP, exactly matching the compiled frame size. |
| Stack `03`, `0x0106D8FC` | Caller EBX, the query vtable. |
| Enumerator EBX, `0x0170EF74` | Query `0x0170CED0 + 0x20A4`, the candidate output array. |

The full stack equation also agrees: caller EBP minus 12 bytes of saved
registers, `0x24` bytes of locals, the four-byte output argument, four-byte
return address, and 16 enumerator-save bytes equals captured ESP `0x0170CD70`.

The instructions before this call require the active provider-bearing radio
context, matching provider and query vtable, null actor, and one of
`(mode,disposition) = (0,3), (1,1), (2,1)`. The individual tuple is not
recorded. Both direct-cell and worldspace-cell branches merge at this call.
The original-provider fallback has a different return address. Thus this
incident executed Psycho's admitted radio expansion, not an unidentified AI
caller. The first investigation's caller uncertainty is superseded by this
static proof.

## Ownership, locking, ABI and coverage

The enumerator receives the cell in ECX and output array on the stack, ignores
EDX, preserves EBX/EBP/ESI/EDI, and returns with `RET 4`. It acquires the
recursive cell lock at `cell+0x80`, walks the embedded list at `cell+0xAC`, and
releases the lock after enumeration. List nodes contain a reference at `+0`
and the next link at `+4`. This layout and lock address are corroborated by
native accessors and `CellRefLockEnter`/`CellRefLockLeave`, not only headers.
Native enumeration also skips null reference payloads at `0x0054DB83` and
advances the iterator. The owned traversal does the same, including a null
payload with a non-null next link. The embedded `{null, null}` empty sentinel
terminates through its null next link.

For each candidate, the helper reads reference flags at `+8`, skips disabled
(bit 11) and deleted (bit 5), reads base form at `+0x20`, tests base type at
`+4` for `0x1C`, checks teleport-presence bit `reference+0x51 & 8`, and appends
the reference through `0x007CB2E0`. It neither repairs nor owns the references
or base forms. Holding the cell-list lock proves this reader's locking; it
does not prove that every reference/base-form writer obeys that lock.

Static caller coverage establishes:

- One DLL direct call at `0x1002C569`, in neighbor provider `0x1002C530`.
- One DLL installation reference at `0x1002DF1A`, which redirects game
  callsites `0x00588291` and `0x006F373D` to this same enumerator.
- The original game enumerator `0x0054DB50` has those two direct callers:
  worldspace enumeration through `0x00588270` and native neighbor expansion
  through `0x006F36D0`. Indirect or runtime-generated callers remain possible.

Native `0x0054DB50` also assumes a non-null base: getter `0x007AF430` returns
`reference+0x20`, then `0x00401170` reads its type without a null check. Merely
restoring vanilla enumeration cannot establish safety. Its extra sentinel and
teleport-data filters also differ from the installed helper's filters.

Before this correction, Psycho's
[radio adapter](../psycho-engine-fixes/src/mods/perf/radio/provider.rs) retained
the captured enumerator at both calls in `expand`. Its capability check compared
the provider body but checked only one executable mapped byte at the captured
enumerator entry. It did not validate that helper's full filters, locking or
input checks. The installed helper and both calls in Psycho's own expansion
are statically mapped. The correction now owns those two calls and admits the
complete enumeration contract. Other native/provider uses of the same helper
are separate exposure; this is not a global lifetime repair.

The targeted native-owner audit establishes that reference constructor
`0x0055A2F0` writes zero to `reference+0x20` at `0x0055A37C`, and then clears
`parentCell` at `+0x40`. This proves a null-base construction state, not that
this particular object was published too early. Canonical cell insertion
`0x00548230` acquires/releases `CellRefLock` around physical publication.
Reference teardown `0x0055A430` calls cell removal `0x0054CA90`; that owner
removes the primary list entry through `0x00905330` while holding the same
lock. These instructions do not establish which writer produced this
incident's null base. A constructor state or another incident's render-list
retirement defect is not authority to change these owners here.

Native lock entry `0x0040FBF0` and the inspected enumerator's lock helper use
the same owner-thread word and recursion-count word. Native leave
`0x0040FBA0` decrements that count and clears the owner only at zero. The
existing cell wrappers `0x00541AC0/0x00541AE0` apply this protocol at cell
`+0x80`. They provide a game-owned locking boundary for an owned enumerator;
there is no need to patch or call a private provider lock helper.

The complete instruction audit closes the replacement's admission inputs:
the retained enumerator is 127 bytes through `RET 4`; its lock-call rel32
operand at `+0x0D` is extracted separately. Its list offsets, every
branch/filter, append address and release instructions are fixed. The lock
helper is 91 bytes; native cell-lock wrappers are 30 and 25
bytes. Native append `0x007CB2E0` is 69 bytes through `RET 4`. Full bytes and
instructions are retained in the enumeration-contract evidence. These are
research inputs for implementation, not a source-text or compilation test.

The installed binary also supplies a complete 22-byte append body. Its
compiled installation loads that exact template and copies all 22 bytes to
game entry `0x007CB2E0`. It preserves the array in ECX across the original
`0x00761540` call, writes the supplied reference at the returned index in
array `+4`, and returns with `RET 4`. Admission accepts this complete body or
the complete original body; an original-only check would reject a proven
installed ABI. Both cases call the actual game entry without replacing its
implementation. This is code-capability admission, not module detection.

The Psycho log previously reported uncertain cell membership at the same cell
address at `14:25:03.634Z`. This does not identify the offending reference or
prove a causal relationship. Allocator fallbacks and pressure warnings likewise
do not establish an allocation failure causing this fault: the last memory
sample reports free address space and no recorded block/virtual allocation
failures. Neither allocator corruption nor OOM is established or ruled out.

## Fix plan and acceptance

1. Use the preserved failure and the now-complete compiled caller/helper
   contracts as the incident evidence. The exact helper/lock data covers the
   two-word list layout, termination, disabled/deleted/type/teleport filters,
   append ABI and release edge. Extend `radio/provider_contract.rs` and
   `provider.rs::discover` to compare that behavior before substituting owned
   enumeration. Keep admission based on code capability; no module-name/version
   allowlist or provider DLL modification. A mapped helper byte alone is
   insufficient.
2. Replace both captured-helper invocations in Psycho's admitted `expand`
   with an owned cell enumerator. Acquire the existing native cell lock once,
   retain it for one traversal, and release it with RAII. Preserve the original
   list termination, live traversal order, flags, type `0x1C`, teleport bit,
   and native append operation. Skip null list payloads before reading flags,
   as the native iterator does. Read `baseForm` once and, when it is null,
   continue to the next entry before reading its type. A missing base cannot
   satisfy a door-type test. Do not remove/free the reference, invent a base,
   cache engine pointers, or add game-state mutations.
3. Preserve query admission, all three actor-free tuples, worldspace and
   direct-cell routing, count reset ownership, native node/queue operations,
   geometry and costs. Do not replace helper semantics with vanilla filters or
   skip entire unloaded cells/worldspaces. Unrecognized provider/helper
   contracts retain dynamic dispatch. Leave the existing game-owned dispatch
   hook as the intervention; no additional hook in another module is needed.
   Document coverage as the confirmed radio path, with no claim to fix every
   other consumer of the external helper.
4. Keep this a production correction in the existing radio implementation and
   contract data. Add no debug-only DLL, diagnostic game build, tracing phase,
   new configuration switch, polling or routine per-candidate logging. Preserve
   the single traversal and existing native append allocation behavior; add no
   routine allocation, page-query loop or additional lock pass. Read the
   startup contract before implementing changes that affect hooks/statics or
   lifecycle, and preserve the existing installation phase.
5. Qualification is separate from static evidence collection. Use production
   paths and release artifacts only: applicable behavioral regressions, the
   affected crate suite with
   `cargo test --release --target i686-pc-windows-gnu -p psycho-engine-fixes`,
   formatting, supported 32-bit
   release build, `git diff --check` and final diff review. Do not invent a
   mocked enumerator or fabricated object graph as gameplay proof. Any later
   game acceptance uses the normal release candidate and observes candidate
   filtering, valid-door output/order, query completion and lock balance on
   both cell routes. No debug build or new capture is a research prerequisite.
   Deployment and packaging remain owner-only.

## Implemented candidate and authorization

After requiring static evidence collection, the owner explicitly instructed
`proceed with plan` for this incident. This authorizes the scoped unreleased
defensive candidate under the
[reporter-only engine-fix exception](psycho_engine_fix_exception.md). The
supplied game failure and exact binary contracts replace a new fail-first
game run for this candidate; no diagnostic build or capture phase is added.
The existing radio capability mechanism remains the admission boundary. There
is no module identity, mod/version allowlist, external patch, destructor hook,
ownership mutation or allocator classification.

The new
[candidate enumerator](../psycho-engine-fixes/src/mods/perf/radio/provider/candidates.rs)
holds one native CellRefLock recursion level through one traversal, releases it
with RAII, and preserves valid flags/type/teleport filters, live next-link
reads and native append. It skips null reference payloads before reading
flags; its nullable type reader rejects the captured zero base before pointer
arithmetic or dereference. These checks do not prove the lifetime of non-null
pointers. Both cell routes in `expand` use it. Candidate count reset, all three
query tuples, geometry, cost arithmetic, native node/queue operations and
dynamic fallback are kept.

The first null-base rejection produces the ordinary release warning
`[RADIO] Ignored a candidate with a missing base form; door search continues`.
It logs after the cell lock has been released. A zero-initialized atomic flag
limits this to once per process and is touched only on rejection; normal
candidate traversal adds no allocation, page query, timing or logging.

Admission compares the complete candidate loop and recursive lock instruction
shape, resolving the relative lock call and ignoring its two relocated
import-slot operands. The private helper is never called; probing its imports
does not validate the native functions used by the owned traversal. Admission
checks the full native cell-lock wrappers and either complete proven append
body. These checks run at existing capability publication and once per outer
radio scan, not per node or candidate. Unknown or changed contracts retain the
actual installed provider. No new hook, dependency, TLS, configuration field,
startup phase or worker is introduced. The warning flag
and read-only instruction data are the intentional static storage additions.

## Qualification and remaining gate

The focused release regression executes the production nullable type reader
on the captured zero input. It constructs no substitute cell/reference graph
and does not claim to execute full game enumeration. Static compiled-code review establishes
the native ABI and checks the rejection branch before the type read.

The focused regression, affected crate release suite, supported 32-bit release
build, scoped formatting and diff checks pass. An earlier parallel allocator
test failed, passed in isolation, and passed in a complete-suite rerun;
allocator code and assertions were not changed.
The release disassembly confirms the null branch advances to the next list
entry before any type read, both cell routes reach the owned enumerator, and
the warning is called only after native lock release. No surrogate engine
graph was used for qualification.

Offline checks do not certify gameplay or startup. The local build also
contains concurrent workspace changes outside this correction. The startup
and reporter-validation gates remain separate from offline checks.

The offending reference identity and upstream writer remain unknown. The
evidence supports this local null-base correction, not an allocator, IO
scheduling, cell retirement or save-data repair. Non-null stale pointers and
later engine mutations are outside its proven rejection contract. Reporter
confirmation of a rejection and continued gameplay, plus ordinary startup
acceptance for the release artifact, remain unverified. No game run,
deployment or packaging is performed by this work.

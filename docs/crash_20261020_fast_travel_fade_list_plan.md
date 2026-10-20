# Fast travel crash in BSFadeNode list destruction

Status: immediate failure confirmed; corrupting writer and root ownership
defect unresolved. The owner reports successful runtime containment, supported
by a saved guard rejection followed by continued session activity. Leak amount
and broader runtime coverage remain unverified. The fix remains unreleased.

Scope: static research only. No diagnostic playtests, instrumented runs or
owner-operated captures are requested or planned. A supplied save or replay
is not a prerequisite for this investigation.

Last updated: 2026-10-20.

## Incident and preserved evidence

The owner reports attempting fast travel, tentatively to "cudesac house maybe,
from regulators mod". The destination identity and starting save are not yet
established. This report does not attribute the defect to that mod.

CrashLogger records the player in exterior cell `06001242`
(`SpringvaleBanditHouse`), Capital Wasteland. Its header is the session start,
`03:13:50` local; the archived crash filename is
`CrashLogger.2026-10-20-03-33-30.log`, with playtime `00:19:39`. Psycho's
matching session starts at `2026-10-20T00:13:50Z` and ends at `00:33:30Z`.

Complete CrashLogger, Psycho, OMV and Atom logs and the deployed Psycho
configuration are retained in `.reports/20261020-fast-travel-fade-list/`.
`evidence-manifest.json` records the resolved sources and timestamps. Discovery
initially missed the game directory; resolving the existing log symlinks
located it. Both the installed and research executables have SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`:
FalloutNV `1.4.0.525`, PE32 i386, image base `0x00400000`.

[Raw radare2 evidence](../analysis/radare2/output/crash_20261020_fast_travel_fade_contract.txt)
retains the commands, bytes, disassembly, decompiler output and scope limits.
No game run, deployment or packaging was performed.

## Confirmed failure

The engine faults while traversing an invalid link in the first embedded list
of a `BSFadeNode` during destruction. This is a corrupt-list consumption
failure; the available evidence does not identify the write that created it.

| Boundary | Captured value or verified operation |
|---|---|
| EIP | `0x00B4DF43` |
| Fault instruction | `mov ebx, dword [eax + 4]`, bytes `8B 58 04` |
| EAX | `0x51BB72C9` |
| Attempted read | `0x51BB72CD` |
| Last load before the fault | `mov eax, [esi + 4]` at `0x00B4DF40` |
| Stack object | `0xC393B000`, reported `BSFadeNode`, `GR_destroyed01` |
| Destructor continuation on stack | `0x00B4E225`, immediately after clearing the list at node `+0xD4` |

The list routine at `0x00B4DF30` takes its list address in ECX, preserves ESI,
EBX and EDI, and returns with plain `ret`: a thiscall method with no stack
arguments. It loads the next link from list `+4`, reads that link's own `+4`,
severs the link, clears/frees the detached list entry through game heap
`0x011F6238` / `0x00AA4060`, and advances. It finally zeros the head payload.
The routine does not release a payload object. Its recursive call follows
the explicit severing of the detached entry's next link.

The original `BSFadeNode` constructor at `0x00B4E150` zeros both embedded
eight-byte list heads at `+0xD4/+0xD8` and `+0xDC/+0xE0`. The destructor at
`0x00B4E1E0` clears both before invoking the base destructor. The failing
continuation identifies the first list; it does not establish whether the bad
pointer was in the embedded head or a later allocated list entry. CrashLogger
does not record ESI or a complete list snapshot.

## Native release path and lifetime limits

The captured stack and verified executable establish this consuming path:

1. `0x00878270` calls `0x00C459D0` with stack argument zero, returning to the
   captured `0x00878275`.
2. `0x00C459D0` acquires engine lock `0x01202E40`, tries critical section
   `0x011F4380`, and calls array clear `0x00C46080` at `0x00C45A4A` with ECX
   `0x01202E20`. The return address is the captured `0x00C45A4F`.
3. Array clear assigns NULL to each occupied slot through `0x00C46270` at
   `0x00C46109`, returning to the captured `0x00C4610E`.
4. The assignment decrements the old object's reference count at `+4`. A zero
   result calls its vtable `+4` method. `0x00CFCC20` dispatches the deleting
   destructor through vtable `+0`, with flag 1; `0x00CFCC2C` is on the stack.
5. `BSFadeNode` deleting destructor `0x00B4ED40` calls `0x00B4E1E0`, returning
   to the captured `0x00B4ED48`. The latter calls list clear at `0x00B4E220`,
   returning to the captured `0x00B4E225`, and list traversal faults.

The zero reference count reported for this node is consistent with the
verified final-reference release. It does not independently establish a
premature deletion or use-after-free. The deleting destructor's subsequent
object deallocation has not yet executed on this call.

The queue clear owns reference release; the fade destructor owns its list
entry cleanup. The list payload type, insertion/removal owners, allocation
history, earlier deletions and synchronization with writers are unresolved.
The observed locks protect the drain path; their coverage of every list writer
and the crashing thread's identity are not established. Existing gheap names
such as `HAVOK_GC` are not evidence of a physics-only contract: this verified
path releases scene objects. That naming is not proof of this incident's cause.

An `aar; axt` query finds ten direct calls and one jump to list clear. The
static follow-up classifies their immediate operations:

| References | Verified operation |
|---|---|
| `0x00B4DF56` | Recursive clear after severing a detached entry's next link |
| `0x00B4E220`, `0x00B4E22D`, `0x00B4E239`, `0x00B4E245` | Fade-destructor member cleanup |
| `0x00B4E140` | Tail jump to the shared clear routine |
| `0x00F26CC1`, `0x00F26CCF` | Unwind cleanup through that wrapper for members `+0xD4` and `+0xDC` |
| `0x00F30F39`, `0x00F31219` | Unwind cleanup through the wrapper for a different owner's `+0x648` member |
| `0x00C706D1`, `0x00C70C3A` | Cleanup/removal involving that `+0x648` list |
| `0x00CBC85D`, `0x00CBC88C` | List-entry removal: relink, sever, clear, free |
| `0x00CBC9D4` | Clear/free after an empty-list test |

This is a shared list primitive, not a fade-only destructor. Object types
behind all non-fade lists, indirect references and runtime providers are not
exhaustively established. Its eight-byte list layout and cleanup operations
provide the shared containment seam. A live writable head and exclusive chain
lifetime remain native caller preconditions; the guard cannot establish
allocation identity or synchronization from a pointer snapshot.

## Static construction and writer audit

[Follow-up raw evidence](../analysis/radare2/output/crash_20261020_fade_static_followup.txt)
records the constructor references, class methods, stream and clone dispatch,
field-address candidates, list consumers and bounded installed-module checks.
Raw byte/offset matches are candidates, not typed-object or writer proof.

The native constructor has eleven discovered direct callers. Ten allocate
`0xE4` bytes through `0x00AA13E0` before passing the allocation to
`0x00B4E150`: `0x0049E741`, `0x004A5348`, `0x004A644B`, `0x004A76B2`,
`0x004E4EA3`, `0x0050D3E3`, `0x0050FF34`, `0x005E7FDF`, `0x00B4E432`,
and `0x00B4EAE0`. The eleventh, `0x0066B14B`, initializes the base of
`BSTreeNode`: RTTI at vtable `0x010668E4` establishes that identity, and
`0x0066A0E3` requests `0xF8` bytes before calling its constructor
`0x0066B120`. No undersized allocation is demonstrated at these native sites.

The fade clone at `0x00B4E3F0` constructs a fresh object, invokes base copy
`0x00A5DC80`, then copies only fade fields `+0xAC`, `+0xB0` and `+0xC4`.
Its direct fade-specific work does not copy either list from the source.
The inherited transform copy at `0x00A5ACB1..0x00A5ACBC` copies thirteen
dwords starting at `+0x34`; it does not reach the lists. Other clone work
includes map/property/controller and child callbacks, whose complete write
effects are not established by this bounded audit.

The fade vtable routes native stream load through `0x00B4DEE0` to
`0x00A5DD40`, and link through `0x00A9A730` to `0x00A5E9D0`. The inspected
load/link bodies do not directly deserialize the two list heads. Child
linking uses the separate array at `+0x9C`, with its data at `+0xA0` and
virtual assignment through vtable `+0xF8`. The verified fade target is
`0x00A93EA0`, which dispatches to `0x00A5EE30` through vtable `+0xF4`.
Those bodies maintain the child array and child ownership; they contain no
direct stores to the fade tail lists. This is not an asset validation result
or a proof that every invoked provider is harmless.

Within the inspected fade-class method block, direct references to the two
list heads are their zero initialization and destruction. Executable-wide
searches also find the same displacements in unrelated colors, shader
parameters, stream versions and larger object layouts. Such matches cannot
be treated as writes to this node. Absence of another direct displacement
match would not exclude a computed pointer, bulk write or external provider.

The bounded on-disk plugin search found fade-vtable references in JIP code
that compare object type and read linked owner `+0xCC`; these instructions
do not write the failing lists. No direct constructor/destructor/list-clear
address constant was found in the searched module candidates. Raw immediate
searches cannot exclude relative branches, computed addresses or indirect
hooks, and matching a loaded basename does not independently establish the
session's DLL identity. No plugin attribution follows from this search.

The static result is narrower than a root-writer diagnosis: the invalid link
is confirmed, but missing list initialization, a shallow tail-list copy and
an undersized allocation are not demonstrated in the audited native paths.
Neither a particular corrupting write nor a root ownership repair has been
proved. Containment of a provably invalid successor does not depend on
identifying that writer.

## Related observations and unresolved attribution

Allocator mode 2 was active. The latest detailed sample, about 38 seconds
before the fault, records 569 MB free VAS and a largest hole of 278 MB.
CrashLogger reports 1.39 GiB virtual usage. These snapshots do not establish
memory exhaustion at the crash; no failed allocation is tied to the bad link.

The earlier scene-owner guard was active and rejected an unreadable base-form
type at `00:32:45.657Z`, for node `0xC3910300`. This is a different address
from the reported crashing node. The logs do not establish a common writer or
a causal relationship between these incidents. An autosave completed near
the crash time; that marker does not change the observed failing consumer.

No evidence identifies a defective mesh, particular plugin, allocator reuse,
buffer overrun, double deletion or race as the corrupting mechanism. Readable
memory alone would not prove a list entry's allocation identity or lifetime.
Installed on-disk executable identity and matching stack continuations support
the static path; live process instruction bytes were not independently saved.

## Requested containment and limits

The owner requests a universal corrupt-link containment even when the writer
could be an unknown mod. The implemented scope is the shared list-clear primitive
at `0x00B4DF30`, across its native callers on the supported executable. It is
independent of mesh names, object-vtable allowlists, mod identity and allocator
mode. Universal here means a shared consumer fix; it does not mean recovery
from every possible memory corruption.

The native routine already accepts a NULL next link, clears the head payload,
and returns void. It owns list-entry cleanup, not the payload objects. Cutting
an invalid incoming edge to NULL can therefore expose the same empty-list
endpoint while retaining native cleanup of the remaining reachable prefix.
The rejected pointer must never be dereferenced, passed to the heap or used
to invent another successor. This is containment, not a root-writer repair.

| Condition | Candidate behavior |
|---|---|
| Empty list or intact finite chain | Chain the installed native provider once, with the original head |
| Proven inaccessible or non-writable successor entry | Sever only its incoming link from a verified writable predecessor; chain native cleanup on the retained prefix |
| Link returns to the embedded head | Cut the incoming edge before native cleanup can free the embedded head |
| Verified cycle among successor entries | Locate and cut the cycle's back edge before any entry is freed; retain every unique reachable entry once |
| Accessible bytes resembling an entry but belonging to another live object or a freed allocation | No allocation-identity guarantee; accessibility alone must not be described as ownership proof |
| Concurrent mutation or invalidation | No race-repair claim; pointer snapshots do not retain storage |

Once a corrupt edge loses the address of its real successor, the inaccessible
tail cannot be reconstructed. Any allocations reachable only through that lost
edge may remain allocated. This has no proven size bound and repeated damage
could accumulate leaks. Arbitrary memory scanning or speculative freeing would
turn containment into a risk of freeing unrelated objects. Healthy chains must
retain their full native cleanup; truncation is permitted only for demonstrated
invalid structure, never a depth or work-budget limit.

## Candidate implementation and lifecycle

`psycho-engine-fixes/src/mods/engine_fixes/list_cleanup_guard.rs` owns the
shared-entry hook and preflight. Installation runs at the existing quiescent
Syringe pre-CRT boundary, before core initialization completes. It compares the
entire 71-byte native routine, including its recursive call, game heap-free
call and plain return. A mismatch leaves this fix inactive and logs the reason;
other fixes continue. It never overwrites an alternate provider or hooks an
individual object destructor. The trampoline is published before transactional
activation so a rollback survivor can still forward.

[Qualification bytes](../analysis/radare2/output/crash_20261020_list_clear_qualification_20261020.txt)
record the exact executable body. The accepted user plan explicitly permits
severing corrupted list edges for this incident; that intervention does not
change reference counts or replace the native allocator.

The hook reads the live caller-supplied head under the native precondition.
For a nonempty chain, the existing libpsycho guarded reader copies successor
links after checking the full eight-byte entry for writable committed memory.
Checked arithmetic admits entries spanning distinct writable regions and
rejects wraparound. No alignment or address-pattern heuristic is applied.
Page capability is cached only within that invocation; it does not pin storage.

Brent cycle detection uses constant storage and linear traversal, without a
healthy-list size cap. A head alias is cut at its incoming edge. For a longer
cycle, a second pass finds its entry and exact back edge before any free.
The mutation rechecks the predecessor's writable storage and expected link.
If recovery or revalidation fails, the guard abandons the entire suffix at
the live head. This fallback can leak more entries; it is not concurrent
mutation recovery. An invalid head or lost exclusive lifetime remains outside
the native and candidate contracts.

Native clear receives the original head exactly once after preflight. It
retains payload writes and entry deallocation. Its internal recursive clear
reenters with an already-detached empty successor and bypasses all OS queries.
Guard work saves/restores last-error state; native provider changes remain
visible. Calls allocate and lock nothing. Only the first repair logs its reason
and the possibility of an unreachable-tail leak.

## Configuration and helper ownership

`[engine_fixes].list_cleanup_guard` defaults to `true`; setting it to `false`
skips installation. The helper exposes **List cleanup guard** on Configuration
and saves it for the next launch, using the existing restart-only workflow.
Core parsing, shipped TOML, helper defaults, read/write ownership and dashboard
ordering include the setting. Its plain-language explanation states both the
broken-link handling and possible damaged-tail leak.

The configuration fields are appended to existing structures. The helper's
core-loading policy and exported diagnostic ABI are unchanged. Hook storage
adds a lazy inline-hook container and zero-initialized atomics; it adds no
worker or TLS owner. Installation stays in the existing startup phase. Static
footprint comparison cannot establish Proton startup acceptance.

## Offline qualification and remaining limits

The focused tests execute the actual production preflight with owned entry
storage and real Windows page protections under Wine. They verify intact
chains through 32,768 entries, the reported inaccessible successor
`0x51BB72C9`, head aliases, successor self cycles, longer cycles with different
entry points, distinct writable regions, read-only and inaccessible successor
storage, and checked-address overflow. Intact payloads and links remain
unchanged; a repair changes only the rejected incoming edge or exact cycle back
edge. Tests use existing libpsycho wrappers, including `with_virtual_protect`
for temporary protections. Core parsing and helper roundtrip tests exercise the
toggle. No native free/provider is simulated.

The affected core and helper suites, full supported 32-bit release build,
formatting and diff checks pass. The core/helper comparison against the
preserved on-disk deployment retains their import sequences, export names and
ordinals, TLS templates and callback identities. Code/data layout changes
remain startup-relevant. Local qualification output is retained in
`.reports/20261020-fast-travel-fade-list/implementation/`.

An ignored benchmark measures the optimized production preflight under Wine,
separately from native cleanup. Five rounds over an intact 32-successor chain
measure a median 6.09 microseconds per call (range 6.06-6.17); a
32,768-successor chain measures 5.22 milliseconds (range 5.21-5.24).
Each invocation resets the page cache. This demonstrates the cost of the
additional traversal on those offline workloads; native cleanup, hook entry,
actual game list lengths and game performance are not measured.

The offline checks do not reproduce native game teardown, exercise live hook
activation, prove allocator ownership of readable storage, or validate Proton
startup. The owner subsequently reports successful containment as recorded
below; broader runtime coverage and root-writer attribution remain unresolved.
No diagnostic playtest or owner-operated capture is requested. No agent
deployment or release is claimed.

## Runtime rejection and leak-recovery follow-up

The owner reports that the fix worked and asks whether the rejection can
support safer reclamation. The saved session contains this event at
`2026-10-20T11:08:50.036Z`:

```text
Cut Inaccessible link; head=0xc36186d4, predecessor=0xC36186D4, rejected=0xC5C74048
```

The complete logs and deployed configuration are preserved in
`.reports/20261020-fast-travel-fade-list/followup-20261020T112335Z/`, with a
source/hash manifest. Later save activity and memory samples continue through
`11:22:43Z`; this agrees with the owner's successful-containment report. It
does not establish the return state of every native cleanup call or universal
runtime correctness. No agent-operated game run was performed.

The production guard establishes these precise conclusions:

- `head == predecessor` means the first successor failed admission, before
  any allocated successor was retained for native cleanup. The cut was at
  head `+4`, address `0xC36186D8`.
- `Inaccessible`, rather than `ChangedChain`, means the final predecessor
  check still read the rejected pointer before the cut. It does not prove
  that no concurrent writer existed elsewhere.
- The eight-byte candidate at `0xC5C74048` neither wraps the address space nor
  spans a normal page boundary. Its aligned appearance is not ownership proof.
- The reason combines a failed page query, insufficient writable/committed
  capability and a failed guarded next-word copy. The record cannot distinguish
  those causes; it must not be described as proof of an unmapped or freed cell.
- `0xC36186D4` is consistent with a fade object's `+0xD4` head at object
  address `0xC3618600`. The shared entry also serves other owners. With no
  native caller or object identity captured, that interpretation is unproven.
- At that revision only the first repair logged. One warning is not evidence of only one repair,
  nor does its warning establish any leaked allocation or leaked-byte count.

[Fresh native evidence](../analysis/radare2/output/crash_20261020_list_cleanup_leak_followup.txt)
rechecks the supported executable through r2mcp and a relocation-enabled CLI
capture. Compatible insertion at `0x00CBC7B0` requests eight bytes from
GameHeap at `0x00CBC7C3..0x00CBC7CA`, then stores the payload at `+0` and
the sole next link at `+4`. Removal at `0x00CBC810` uses that layout and
calls the same clear primitive before freeing a detached entry. This proves
a native eight-byte allocation path for this list representation, not that it
inserted the reported fade object's entries. No back link or owner identifier
is stored in those entries by this insertion path.

Clear itself only zeros payload words and frees entries. It invokes no
payload destructor or reference-count release. In the original fade destruction
path, continuing past clear also allows base destruction and the deleting
destructor's `0xE4` object deallocation at `0x00B4ED4F..0x00B4ED55` to
proceed. Containment does not skip that destruction path. This evidence gives
no basis to describe the warning as retaining an entire mesh, texture or fade
object. The direct potential loss is disconnected list-entry storage; the
number, actual allocation sizes and wider consequences of the original
corruption are unknown. The lost tail may already have been freed or may never
have been a real chain, in which case the cut adds no allocation leak.

Existing reclamation already keeps every admitted prefix entry and, for a
verified cycle, cuts the exact back edge so every unique reachable entry can
be freed natively. For this event there was no admitted allocated prefix and
no validated successor beyond the rejected entry. The supplied log has no
independent address from which to resume traversal.

Gheap's pool implementation preserves freed user bytes and does not decommit
active slabs; `Pool::free` changes out-of-band link metadata. Consequently an
ordinary free of an eight-byte cell in a still-active slab does not by itself
explain this admission failure. The log does not establish that the rejected
pointer belonged to such a slab, so it does not exclude other stale-pointer,
reuse, allocation-domain or corruption mechanisms.

The existing allocation-state classifier can distinguish exact live, free,
interior, unissued and uncommitted owned allocations. It does not record list
membership, a missing successor or allocation generation history. A live
eight-byte allocation is not proof that it belongs to this list. Its current
pool query also acquires a pool lock, so calling it from every shared cleanup
or an arbitrary repair callback requires a separate lock-order proof.

## Evidence-backed rejection diagnostics

The follow-up identified more precise rejection evidence as the next useful
code change, without changing cleanup policy:

1. Preserve the actual admission failure: query error, mapping state and
   protection, or guarded-copy error, using the values already obtained at the
   failing check. Record the failed address/range and accepted-prefix length.
   Do not infer object identity from the numerical head offset.
2. Count repairs separately from the first detailed warning and report bounded
   aggregate counts. Preserve the distinction between cycles, invalid links
   and failed revalidation. Do not label repair counts as leaked nodes/bytes.
3. Keep the valid/empty paths allocation-free, retain last-error preservation,
   and use existing libpsycho OS wrappers. Exercise the actual production
   admission path offline with owned mappings for each observable failure;
   no debug playtest is needed or requested for this research proposal.

These details would distinguish an uncommitted/unmapped target from a
capability rejection or copy failure during ordinary owner gameplay. Optional allocator
classification is useful only after proving a nonblocking, reentrancy-safe
query at this boundary; it must not turn allocator mode into a fix requirement.

No further automatic reclamation is justified by the current record. Reading
past an unvalidated entry, making unknown pages writable, scanning unrelated
live allocations for lookalikes, or freeing the rejected pointer cannot recover
lost ownership safely. A root-writer correction could remove the need for
containment; selective tail recovery would require an independently validated
successor and native lifetime ownership. Neither is supplied by this event.
The subsequent [native-list candidate](native_list_hardening_plan.md) implements
the retained failure evidence and sparse per-reason counters. Its successful
traversal-step count can include repeats during cycle detection and is not a
leaked-node count. Cleanup and reclamation policy remain unchanged.

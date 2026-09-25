# Fallout New Vegas Radio Scan Hitch Evidence

## Status

The [synchronous candidate](#synchronous-radio-candidate) is the current source
implementation. It is offline-qualified, with owner-reported normal operation,
and remains unreleased. The [rework plan](#radio-playback-rework-contract-and-plan) records
its scope and remaining performance gate. The
[implementation contract](#implementation-readiness-and-remaining-evidence)
records the implemented provider-dispatch contract. Older scheduling sections describe
retired implementations and do not establish playback correctness.

## Synchronous radio candidate

The owner explicitly approved a radio-specific exception allowing implementation
from verified source/native contracts and offline tests/build without first
reproducing the silent-music incident. The owner subsequently reported that it
appears to work normally and explicitly approved committing the radio changes.
This does not establish measured performance, a complete runtime acceptance
matrix, or release/packaging approval. Native-contract proof and the prohibition
on changes to another mod remain in force.

### Implemented ownership and behavior

`psycho-engine-fixes/src/mods/perf/radio.rs` now calls the original periodic
scanner synchronously. The mode-0 distance call, both connected-query calls,
and both result destructors remain native instructions. The scanner's provider
selection, result arrays, post-filters, and station output are therefore owned
and consumed in their original call. There is no absent/pending answer to turn
into signal loss, and no previous-generation answer to reuse after movement.
Native negative results and actual signal loss remain effective.

Removed radio-owned machinery includes the generation pipeline, prepared engine
objects, tasklet/group allocation, queue priority, worker-priority changes,
completion polling, frame pacing, capacity fallback, query/destructor handoffs,
and world-lifetime joins. The cooperative game-thread fallback was removed too;
it had the same deferred-answer contract. The core retains its shared event ABI
and helper forwarding. Radio handles only its idempotent DeferredInit setup.

The periodic station fast path still skips only empty inactive native entries.
Selected stations, entries owning audio nodes, and list reset continue through
`0x00834260`. Playback sequencing, track selection, music/voice decoding, and
native audio ownership are unchanged. This is structural evidence for removing
the known pending-as-failure route, not an observed cure of the reported audio
transition.

### Engine-owned policy optimization

The native optimization owns two calls inside the native provider:
`0x006F3879 -> 0x00501D20` and `0x006F389A -> 0x00502450`. The constructor
adapter reads the actual query from native caller `EBP-0x80`, admits the three
proven actor-free radio tuples, and initializes only the temporary's cleanup
pointer at `+0x08`. Its paired accessibility adapter returns the exact native
null-actor result, false with output flag zero. If pairing exists but admission
changes, it constructs the complete temporary before chaining accessibility.
All minimum-use penalties, geometry, native results, and cleanup remain native.
Both bridges explicitly align their internal Rust calls and preserve the
original thiscall stack cleanup.

`radio/provider.rs` owns the five-byte neighbor dispatch at `0x006F40D0`.
For the complete verified inlined contract, it performs the equivalent radio
expansion with unused policy preparation/access/cleanup omitted. It retains
the installed enumerator and math helper, live geometry callbacks, native node
allocation/relaxation, neighbor append order, and the outer native queue and
result consumers. Its numeric bridge preserves the compiled scalar SSE order
and unordered radius comparisons. Connected modes retain their minimum-use
penalty. No provider DLL or vtable slot is modified.

`radio/provider_contract.rs` contains complete admission bytes, not executable
copies. Six explicitly bound call/relocation operands are the only variable
bytes. DeferredInit discovers the capability through the actual native vtable;
outer scans revalidate its code and constants. Nested scans restore their prior
context, and each expansion checks its actual incoming target. Unrecognized or
changed providers execute their original dynamic callback. The dispatcher
chains directly for other vtables or unpublished capabilities.

The adapter stores only immutable code addresses across scans. Candidate arrays,
query nodes, station state, and results retain native ownership and lifetime.
Steady-state admission uses bounded comparisons/page queries without allocating
buffers, logging, or timing. It does not add a graph cache, query pool, worker,
or new TLS owner. The existing scan TLS owner now also carries the admitted
capability and native-policy flag. Native allocations and helper locks remain.

### Installation and startup footprint

The scan/station bridges and optional optimization bridges install at the
existing pre-CRT boundary, in separate ownership-aware transactions. Policy
accessibility is installed before constructor interception, and every optional
bridge initially chains original computation. Successful transaction completion
is recorded separately from capability readiness. DeferredInit performs only
contract verification and publication, with no executable-memory writes.
Each outer scan rechecks the owned native policy callsites and admitted windows.
A failed optional install or mismatched contract leaves synchronous native
computation available; rollback never overwrites a later owner's hook.

The core's existing pre-CRT barrier requirement supplies the quiescent code-write
boundary. The helper, event ABI, configuration layout, dependencies, and worker
lifecycle are unchanged by the adapter. The new dispatch patch, small immutable
capability storage, expanded existing scan context, and earlier dormant policy
bridges change the core's loader-visible footprint. An available pre-change DLL
is only an offline comparison reference, not an accepted Proton startup baseline.
The startup-safety runtime gate remains open.

### Qualification and remaining work

The native graph/scan path cannot execute in the offline test process. The
owner's explicit authorization permits this unreleased implementation from the
retained runtime evidence and verified engine contracts. Surviving production
station-predicate and bounded-report tests cover only their own behavior; no
mocked graph, copied reference solver, source-text assertion, or synthetic audio
result substitutes for actual native traversal or music playback.

The final core tests, supported release build, emitted bridge/numeric ABI audit,
formatting, and diff inspection qualify only the offline candidate. Evidence is
retained in
[the adapter qualification audit](../analysis/ghidra/output/perf/radio_provider_adapter_qualification.txt).
No DLL was deployed or packaged by this work. The owner's qualitative normal-
operation report supports the commit authorization; it does not identify the
tested artifact or establish the full playback/provider/startup matrix or
affected-machine scan/frame times. The 120 FPS performance gate remains open.

The deterministic work reduction is the removed asynchronous machinery and
unused policy object lifetime. For admitted inlined expansions there is no
policy setup, policy allocation/free, ownership/rank/global lookup, or access
predicate call. Required teleport lookup, enumeration, native graph work, and
station post-filters remain. Existing safety guards still handle the required
calls. Unknown providers receive no promised acceleration, and static work
reduction is not an FPS or elapsed-time result. The candidate remains unreleased.
Existing policy-bypass counters describe the paired native callsites only;
the inlined adapter adds no new per-door instrumentation.

## Synchronous cost analysis

Focused radare2 verification against the same executable identity recorded below
is preserved in
[the cost audit](../analysis/ghidra/output/perf/radio_synchronous_cost_radare2_audit.txt).
This establishes the work performed by the native code, not the elapsed time of
the current candidate or the reporter's machine.

### Repeated searches and discarded setup

The scanner constructs a fresh query for each station that needs a path. The
connected-query wrapper at `0x006D4D20` constructs its stack-owned search at
`0x006D4D72`, dispatches at `0x006D4DBF`, and destroys it on success and failure.
The query constructor initializes its own search table and queue. Searches do
not share a completed traversal across stations. Each expanded node dispatches
the active provider through vtable `+0x04` at `0x006F40D3`; candidate processing,
distance evaluation, node lookup/creation, and queue updates repeat in each
search. There is no elapsed-time budget in the native traversal loop.

The station-mode number and internal query-mode number are different:

| Station mode | Native scanner call | Query mode | Maximum cost | Actor | Disposition |
| --- | --- | --- | --- | --- | --- |
| 0, distance | `0x004FF397` via distance wrapper | 0 | Native radius argument | null | 3 |
| 2, worldspace and connected interiors | `0x004FF4C6` | 1 | 0.0 | null | 1 |
| 3, interiors | `0x004FF645` | 2 | 0.0 | null | 1 |

Zero maximum cost disables distance pruning in the provider
(`0x006F399D` through `0x006F39E1`). Thus the connected searches have no radius
cutoff. The traversal continues until goal success, queue exhaustion, or its
existing predecessor-cycle failure; disconnected queries can exhaust the
allowed reachable graph. Mode-specific worldspace restrictions still apply.
Success also produces a native path chain which the scanner post-filters; a
replacement boolean reachability result is not an equivalent contract.

Every candidate that passes the provider's initial filters reaches temporary
door-policy construction at `0x006F3879` before distance pruning and node
lookup. Construction resolves lock and ownership data and can allocate/copy
temporary lock data even if the later radius or node-cost checks reject that
candidate. The result is passed to accessibility at `0x006F389A` and then cleaned
up. This is repeated per candidate, per expansion, per station query.

An important correction to the historical explanation: the native accessibility
function itself does **not** perform actor/crime/ownership predicates for these
radio tuples. At `0x0050246A`, a null actor branches directly to the return at
`0x0050253C`, producing false and an output flag of zero without reading the
prepared policy object. The expensive avoidable work is its preceding setup
and associated cleanup; the historical combined bypass timing does not provide
separate setup/accessibility timings.

The provider examines disposition only after this call. Disposition 0 rejects
inaccessible doors, disposition 2 adds a penalty, and dispositions 1 and 3
continue with zero accessibility penalty. Therefore the prepared accessibility
data is discarded for the connected radio tuples as well as distance queries.
However, the subsequent minimum-use door check at `0x006F38FB` through
`0x006F3926` applies a penalty for disposition 1. It must remain intact along
with geometry, ordering, parent links, and result production. Broadly skipping
all door policy would change the connected-query contract.

### Evidence and limits

The historical measured mode-0 workload already isolates the dominant avoidable
cost: candidate memoization left scans at 42-44 ms, while bypassing 7,746 paired
setup/accessibility calls reduced the recorded average from 42,756 us to
5,202 us. That was the previously instrumented replacement-provider workload,
not a measurement of today's candidate. Its source likewise prepares policy
before calling native accessibility, but its private setup is outside the
current engine-owned callsites.

The [supplied interior log](../.reports/psycho-engine-fixes-latest--interior-stutters.log)
records a 112,712 us game-thread scan and 10,504 us
total mode-0 worker execution spread over 438 ms. It does not contain per-mode
timings for the remaining synchronous queries. The binary now establishes why
those connected searches can be expensive, but does not assign the 112,712 us
between them or prove they alone explain that interval. Nor does static work
count establish an allocator stall, a CPU-specific fault, or an FPS gain.

The tasklet design adds a separate correctness problem: deferred answers can
reach native availability consumers as failure before completion. Moving these
searches back into the scanner removes that pending-answer route but preserves
their computational cost. It is not sufficient to meet the lightweight-radio
requirement.

### Implemented cost reduction

The paired temporary setup bypass now includes radio query modes 1 and 2 with
null actor and disposition 1, preserving the minimum-use branch and every native
result consumer. Actual-caller admission, paired cleanup safety, signature
checks, and predecessor chaining remain required.

That extension alone cannot recover the historical improvement for a provider
which performs its own private setup. The dispatch contract below supplies
the selected game-owned intervention for the verified inlined implementation.
Arbitrary provider behavior is preserved by ordinary dispatch, with no promised
acceleration. Patching another provider, assuming graph equivalence, reusing
stale results, or turning unfinished work into unavailable stations remains
outside the design.

## Implementation readiness and remaining evidence

The focused follow-up is preserved in
[the implementation-gap audit](../analysis/ghidra/output/perf/radio_implementation_gap_radare2_audit.txt).
It reuses the executable identity above and the earlier complete provider,
constructor, accessibility, and destructor listings. The findings below are
implementation contracts and explicit limits, not a declaration that the full
performance requirement is ready or accepted.

### Native optimization contract

The radio-owned native change has a concrete scope:

- Admit the actual caller's live query only within the synchronous scan, with
  the native query vtable, null actor, and one of `(mode, disposition)` equal
  to `(0, 3)`, `(1, 1)`, or `(2, 1)`. Query setup stores these at `+0x2098`,
  `+0x20A0`, and `+0x20B4`. Do not admit unrelated actors or modes.
- Omit only the temporary constructor at `0x006F3879`. Its thiscall adapter
  receives `ECX=data`, one stack door argument, returns `data` in EAX, and
  returns with `RET 4`. The native frame owns a 24-byte temporary; initialize
  only its cleanup pointer at `+0x08` to null.
- Keep the owned accessibility callsite paired with that omission. Return
  the exact native null-actor result, **false with output flag zero**, instead
  of an equivalent disposition-only result of true.
  If the pair cannot be admitted, reconstruct the temporary before chaining
  the captured accessibility target. Nonmatching setup calls chain normally.
- Preserve the minimum-use check, distance/radius checks, query-private node
  relaxation, parent selection, path extraction, scanner post-filters, and all
  native temporary cleanup paths. No result object moves between queries.
- Prepare optional code interceptions transactionally at the existing pre-CRT
  boundary, initially chaining originals. DeferredInit validates and publishes
  optimization admission without writing executable instructions. Declining
  optimization must never report an unavailable station. See the installation
  contract below; DeferredInit no longer writes these instructions.

The native null-actor branch offers a possible further simplification: after
writing zero to the flag, `0x0050246A` jumps to `0x0050253C` and returns without
reading any field of the temporary or door. Between the constructor and this
call, the provider only prepares arguments; it invokes no intervening callback.
The destructor reads only `temporary+8`. For the unchanged executable, omitting
construction and calling native accessibility is sufficient, with no fake
accessibility result or pairing state.

That observation does not prove that a subsequently replaced accessibility
consumer would accept a partially initialized temporary. The existing paired
callsite design retains ownership of that consumer boundary. Keep it for the
implementation; removing it requires an additional consumer-stability
contract and is not needed to remove the measured preparation cost. This
separates the verified native data-flow simplification from a compatibility
claim about hooks installed later.

### Shared preparation costs and safety dependencies

The historical replacement provider's source does not call native constructor
`0x00501D20`. It prepares the fields privately and only then calls
`0x00502450`. Therefore hooking the latter cannot recover already-spent setup
work. Its private setup and allocation cannot be removed by the native
constructor callsite optimization.

The shared callees are concrete, but do not carry the same dead-data contract:

| Boundary | Actual input/behavior | Consequence |
| --- | --- | --- |
| `0x00567790`, ownership resolution | Receives a reference, follows reference/linked-door/zone/cell precedence, and includes a virtual call. | It receives no radio query or disposition. Returning an invented owner inside a scan would affect any provider that actually uses ownership. |
| `0x00567D20`, encounter-zone resolution | Receives a reference, resolves reference/cell/worldspace state. | A whole-resolver cache also needs all source, lifetime, and mutation dependencies; radio scope alone supplies none of these. |
| `0x00410220`, extra-data lookup | Receives list and type; presence test, TLS cache, then locked linked-list traversal on a miss. | It is shared by required teleport geometry and optional policy data. Skipping all extra-data work would change adjacency. |
| `0x0040FBF0`, extra-list lock acquisition | Receives a lock object and diagnostic label. It waits/retries for ownership and supports recursion. | Removing the lock or returning early violates reader/writer protection; its presence is not evidence that a particular scan waited. |

Current Psycho code adds work at these shared boundaries. With a non-null,
valid ownership extra and owner, `extraownership::scrub_extraownership` calls
`VirtualQuery` for the extra, owner, and vtable: three queries per such access.
Null owner and absent-extra paths do less work. With a valid non-null encounter
zone, `encounter_zone::validate_encounter_zone` checks readable storage and
resolves its FormID to verify live pointer identity. Invalid paths can repair
storage and record diagnostics. Neither guard is a pure cached getter that may
be silently bypassed; both remain required for calls which still execute.

The latest local log at inspection recorded both guards active and the
synchronous radio scanner/native mode-0 optimization active. It contained no
`[RADIO_SCAN]` attribution. Activation is observed; playback, lower-CPU scan
cost, and the division of cost between these callees remain unmeasured. These
newly identified guard costs are not retrospectively assigned to the older
42.8 ms or 112.7 ms measurements.

### Cache and scheduling limits

Native extra-data caching already uses one list owner per thread, a 147-entry
type array, and a global invalidation counter at `0x011C38E4`. Changing owners
clears 588 bytes at `0x0040FA6E`. A list-cache miss can traverse under lock
`0x011C3920`; its acquisition loop calls the native sleep wrapper with zero,
then one after repeated failures. This is a concrete possible cost, separate
from graph traversal's optional 50-node yield; no new lock profiling is needed
to select the already-measured policy omission.

This counter is **not** a radio graph generation. Native removal invalidates
cached extra pointers; native add at `0x0040FF60` links an extra and updates its
presence bit without incrementing that counter. A cache of prior absent
values keyed only by this counter can therefore miss a later addition. More
generally, reference positions, flags, teleport payload contents, cell links,
and worldspace fields are not covered by an extra-node removal counter.
The existing graph-invalidation gap cannot be closed by reusing this value.

The retired worker ran complete queries under `ThreadPriority::Idle`, and
these queries can acquire the same extra-list lock used by other engine work.
Consequently lowering the worker's priority is not proof that it cannot delay
the game thread: a preempted lock holder remains its owner. This is a structural
contention route, not an observed priority-inversion event in the supplied log.
The synchronous candidate removes the radio-owned idle-worker participant;
it does not establish that all remaining native lock waits vanish.

### Selected game-owned expansion boundary

The owner declined further profiling. The retained removal experiment already
selects the material work: bypassing 7,746 setup/access pairs reduced that
workload's average scan from 42,756 us to 5,202 us. Separating the preparation's
lookup, guard, allocation, and lock costs is not an implementation prerequisite.
No additional telemetry, profiling capture, or profiling dependency is planned.
The historical measurement is not a timing result for the new candidate.

The remaining provider boundary is now identified in
[the provider-dispatch audit](../analysis/ghidra/output/perf/radio_provider_dispatch_radare2_audit.txt).
The game dispatches each expansion at `0x006F40D0`:

```text
ECX = live query; EDX = its actual vtable
stack arguments = current node, caller-owned neighbor array
006F40D0  mov eax, [edx+4]    ; 8B 42 04
006F40D3  call eax           ; FF D0
006F40D5  continuation
```

These five bytes form one replaceable call window. A Psycho adapter can select
an equivalent expansion before private preparation begins, without changing
the vtable slot, provider DLL, candidate enumerator, or search algorithm.
The dispatch shim must preserve the original ECX/EDX arguments, both stack
arguments, nonvolatile registers, AL result, and `RET 8` stack cleanup. Its Rust
body needs an explicitly aligned stack; ordinary Rust entry at an arbitrary
native stack alignment is not an ABI proof. Audit the emitted shim after build.
Fallback must invoke the target from the actual incoming vtable, including its
original EDX value, rather than a cached default provider.

Keep the non-radio fast path in the shim: a nonmatching vtable or unpublished
capability chains through the original `mov eax, [edx+4]` and tail jump with
the original stack. It must not enter Rust profiling or provider-validation
code for every unrelated engine expansion.

The comparison binary was read from the local Stewie installation. Its identity,
complete provider bytes/disassembly, setup, enumerator, and math-helper evidence
are retained in the audit. This establishes a compiled contract; it does not
identify which DLL is mapped into a currently running game. No mod name,
version, file hash, or private address becomes a runtime allowlist.

The selected expansion adapter has two paths:

1. Native provider: continue through the installed provider and the paired
   native callsite optimization described above. Extend its admission to all
   three proven radio tuples and return exact null-actor accessibility output.
2. Verified inlined provider: execute Psycho's equivalent neighbor expansion
   at the game-owned dispatch. Omit only the discarded temporary preparation,
   accessibility call, and its allocation cleanup. Retain the original
   enumerator and math helper, and all required native operations below.

An unrecognized provider always executes normally. This preserves station
coverage; it does not promise acceleration of arbitrary replacement code.
Do not replace an unknown provider with vanilla enumeration. The inspected
inlined enumerator has different filters from vanilla, so that substitution
would change adjacency even though both functions enumerate teleport doors.

### Inlined expansion equivalence contract

The source comparison covers the relevant `Pathing.cpp` blocks from 9.90, 9.95,
and 10.00. The latter renames the ownership call, but its implementation still
calls game ownership resolver `0x00567790`. Source similarity alone does not
admit another compiled provider; runtime admission uses the complete compiled
contract below.

| Operation | Required implementation behavior |
| --- | --- |
| Query admission | Active synchronous radio scope, actual query vtable `0x0106D8FC`, null actor, and exactly `(mode, disposition) = (0,3), (1,1), (2,1)`. Read the current query, not an outer query's cached decision. |
| Candidates | Reset only the live query's candidate count at `+0x20AC`; call the captured enumerator with the same cell and array at `+0x20A4`. Preserve candidate order, live count reads, disabled checks, and cell locking in that helper. |
| Teleport geometry | Call the existing `0x00410220` lookup for type `0x2B`. Preserve linked-door parent-cell/child-cell resolution, virtual callbacks, worldspace selection, and descriptor key, including the original null-key path. |
| Mode filters | Mode 1 admits interior links or links in the source worldspace at `+0x205C`; mode 2 excludes worldspace links. Mode 0 retains its distance/radius behavior. |
| Policy omission | Null-actor accessibility does not read the prepared object. Dispositions 1 and 3 discard its decision. Remove the whole unused preparation lifetime, not individual shared getters or safety guards. |
| Minimum-use door | Preserve the base-door flag at `+0x84`, bit 3. Disposition 1 still adds 409600; disposition 3 does not. Connected queries are not blanket zero-penalty queries. |
| Position | Invoke the same door virtual `GetPos` slot `+0x1F4`. Select node teleport position `+0x18` when node `+0x24` is nonzero, otherwise query source position `+0x2068`. |
| Arithmetic | Preserve the compiled scalar SSE sequence: squared Y plus squared X, then squared Z; invoke the captured XMM0-in/XMM0-out math helper; preserve cost addition order and the actual unordered/zero/radius branches. Do not substitute Rust `sqrt`, native-provider x87 arithmetic, reassociation, or an approximate distance. |
| Node ownership | Call installed game entry `0x006F3E30` as thiscall `(query, key, cost, out_node)`, `RET 12`. Return 0 initializes domain descriptor and heuristic 1.0; return 1 updates link data; return 2 skips the candidate. Retain native hash, allocation, relaxation, and queue-removal behavior. |
| Neighbor output | Preserve door pointer and teleport destination writes, then call `0x007CB2E0` as thiscall `(array, pointer_to_node_pointer)`, `RET 4`, in the original order. Do not clear the caller's array again or retain nodes outside the query. |
| Completion | Return AL=1 with the original stack cleanup. The outer native traversal continues goal checks, queue insertion, predecessor assignment, cycle handling, extraction, and destruction. |

The retained math helper performs double-precision square root and converts
back to scalar float on its ordinary path. Its alternate branch is also
retained by calling the helper itself. The original expansion's exact
floating-point comparisons, including unordered handling, matter for node
relaxation and ties. A mathematically similar rewrite is insufficient.

Calling the native node and queue operations preserves the inspected provider's
separate hash and queue patches. Returning a direct connectivity boolean,
recomputing distance from node cost, caching a graph, or sharing nodes between
stations would discard those contracts and is outside this implementation.
Required extra-data operations continue through installed safety guards.
Omitted unused policy lookups no longer invoke those guards; this is part of
removing their unused callers, not a global guard bypass.

### Capability admission, lifetime, and installation

Admission must validate the whole reachable provider body, not its historical
short entry signature. The comparison body is 766 bytes, ending after `RET 8`.
Normalize only the three relative call operands and the three relocated data
addresses. Bind each operand explicitly:

- provider `+0x39`: original candidate enumerator;
- provider `+0x12B`: preparation routine, whose full 389-byte body must match
  the proven discarded-data contract;
- provider `+0x1FA`: original math helper;
- provider `+0x170` and `+0x185`: the same 409600.0 constant;
- provider `+0x20D`: positive zero used by the original comparison.

All other bytes, branch destinations, native callees, field offsets, and
constants remain significant. Validate readable/executable ranges and checked
address arithmetic before reading code or publishing bindings. The two
retained helpers are invoked with their original physical ABIs; their behavior
is not reimplemented. A mismatch means complete provider fallback, never a
partial optimization or a guessed nearby helper. This is a bounded contract
check reached from the actual vtable slot, not a module search or version list.

At each outer scan, recheck that the bound provider/setup code and constants
still match, using bounded storage and the existing WinAPI page-query wrapper.
Do not use allocating `read_bytes` in this recurring path. Publish admission
only for that synchronous scan; nested scans restore the previous scope.
Each expansion also compares the actual target before using captured helpers.
An in-place change detected between scans, changed slot, or failed check takes
the original dynamic target. Do not rescan signatures per door or per node.
No log, timer, heap allocation, or blocking lock is introduced by normal
expansion admission. Native traversal allocations and helper locks remain.

xNVSE's `PluginManager.cpp` unloads failed plugins during load and successful
plugins in `DeInit`; its inspected normal operation retains loaded plugins.
Bind helpers only after successful plugin loading, at DeferredInit. Captured
code is valid under that normal plugin lifetime, and is used only while the
same provider remains installed. This is not support for concurrently unloading
or rewriting executable code during an active native call; the original
provider has no such lifetime guarantee either. No engine object or helper
result is retained across scans, loads, or world teardown.

`OwnedCodePatch` can own the exact five-byte dispatch replacement and participate
in `ModificationTransaction`. That transaction explicitly does not suspend
threads or make code writes atomic. Therefore install the dispatch and paired
native callsite bridges, initially forwarding, at the existing pre-CRT core
boundary. `entry.rs` refuses core activation without that barrier, and
`startup.rs` already installs scan/station hooks there. This avoids assuming
that all traversal workers are quiescent at DeferredInit.

DeferredInit becomes verification and capability publication only. Recheck
ownership of the installed game callsites after plugins load. If another
component changed an interception, do not overwrite it or enable a dependent
constructor omission. Publish immutable bindings/readiness only after all
checks pass; retain original computation when they do not. Install optional
optimization as a separate transaction so failure does not undo synchronous
scan correctness. Rollback must remain ownership-aware.

This changes the early hook footprint. Keep it confined to
the core and existing radio lifecycle; add no dependency, worker, new TLS owner,
config field, helper forwarding, or shared-library redesign. Follow
[the startup-safety contract](nvse_startup_phase_safety.md) for the resulting
artifact. Static installation proof does not close the Proton startup gate.

### Implementation and acceptance limits

The implemented candidate follows this sequence for the native and proven
inlined provider contracts:

1. Keep synchronous scan results and native station/audio ownership. Extend
   native policy admission to the two connected modes, preserving minimum-use
   penalties and exact null-actor output.
2. Add the bounded provider-contract admission and equivalent expansion behind
   the game-owned dispatcher. Keep the engine boundary and unsafe ABI code in
   a focused radio-owned module; do not build a generic provider framework.
3. Install dormant bridges at pre-CRT, then verify and publish capabilities at
   DeferredInit. Preserve original dynamic dispatch for every unsupported case.
4. Audit the emitted i686 bridges and numeric sequence against the retained
   binary proof. Run surviving applicable production behavior tests, the core
   crate suite, one supported release build, formatting, and diff review.
   Do not introduce a mocked graph or copied reference algorithm as proof of
   native traversal equivalence.
5. Report the result only as an unreleased offline-qualified candidate under
   the owner's existing authorization. Playback, provider equivalence in the
   actual game, startup compatibility, and elapsed scan/frame times remain
   unverified until real-runtime evidence exists. No new profiling work is a
   prerequisite for implementing this candidate.

The owner set 120 FPS: `1000 / 120 = 8.333... ms` is the entire frame budget.
Each synchronous scan must be strictly below it, with enough remaining time
for the rest of the frame. This is an acceptance ceiling, not a guaranteed
execution deadline or permission for radio to consume the whole frame. Do not
average a slow scan across its refresh interval. If exact work exceeds the
budget, retain its correct result and report the performance requirement unmet;
never truncate search, drop a station, or turn pending work into failure.

The technical selection no longer depends on identifying which policy getter
accounts for which fraction of the historical cost. The selected optimization
removes their entire unused caller lifetime. Unknown-provider acceleration,
a universal millisecond bound, and the cause of every possible audio failure
are not proven by this contract. The actual reported speech-to-music outcome
and 120 FPS target remain runtime results, not conclusions of static analysis.

## Historical tasklet implementation (superseded)

This report records the radio hitch investigation begun on 2026-07-16 and the
cooperative and native-tasklet scheduling changes implemented on 2026-07-22
and 2026-07-23.
Runtime proved that repeated door-policy work in the installed Stewie Tweaks
provider caused the original 42.756 ms burst. The exact policy optimization
reduced that installed-provider case to about 5-7 ms.

The radio bridge intercepts the game-owned mode-0 distance wrapper call at
`0x004FF397`, independently of the vtable provider. A periodic scan consumes
the last complete distance generation while the next generation is recomputed
through the original engine wrapper. The first implementation ran at most one
opaque query per presented frame on the game thread. Runtime proved all 12
queries still consumed 6.870 ms total and produced the reported 250 ms
frame-pacing sawtooth.

The first 2026-07-23 native implementation removed those provider calls from
the presentation thread for the exactly verified vanilla and Stewie 9.95
providers, but submitted the entire generation as one worker task. Runtime
proved that this merely moved the periodic burst: 12 queries still executed
back-to-back for 5.840 ms on a tasklet worker. The user's frame-pacing chart
remained unchanged.

The paced revision submitted exactly one query per cadence slot. Runtime then
proved that all 12 calls were spread over 231 ms with a 1.351 ms maximum
worker call, but the user's chart was still unchanged. This disproves the
worker-burst explanation for the remaining sawtooth.

The current revision preserves that pacing, corrects a separate native
completion race, and fixes the worker scheduler class. An ordinary frame polls
the tasklet group's engine-owned submitted/completed counters and cannot enter
the native infinite wait before the manager has completed the task. More
importantly, Psycho no longer leaves its group at the constructor's priority
zero. Disassembly proves that zero is the first tasklet bucket examined, while
63 is the last. Every activated radio group is now assigned priority 63 before
submission. The radio callback also caps only its current worker at Win32
idle priority, then restores the exact preceding priority before returning to
the engine.

Worker use is gated at the game-owned virtual ABI rather than by provider
identity. `FUN_006F3D90` asks the tasklet manager whether the current thread is
one of its workers and stores the answer at query `+0x2054` before
`FUN_006F3FB0` invokes virtual provider slot `+0x04`. Startup requires only
that the current slot target is executable; a later replacement is checked
the same way before the next submission. No DLL name, version, or provider
byte signature gates the native backend.

The first corrected-resolver playtest remained stable but did not materially
change the reported sawtooth. That run had hitch profiling disabled, and its
startup record proved only that the callsite patches installed. It did not
prove that the frame event and radio scan shared a thread, that a generation
was collected and published, or how much one scheduled provider call cost.
The implementation therefore emits bounded first-use evidence: one delayed
fallback record if scheduling is unavailable, one collection record, and one
publication record containing the first generation's job count and total/max
query time. There is no interval logger. Query timing stops permanently after
the first successful publication.

That evidence proved the cooperative path was active on the same thread and
did not fall back: 12 requests were collected in 51 us and all 12 provider
calls completed in 5.929 ms total, with a 1.293 ms maximum individual call.
However, those calls occupied 12 consecutive presented frames over 156 ms.
The resulting loaded-frame block followed by an idle block explains why a
rolling frame-time graph could retain a sawtooth despite removal of the old
single 42-45 ms scan burst.

The scheduler now measures the preceding radio-scan interval and releases the
same jobs uniformly across that interval. The first scan and intervals outside
16-500 ms use the proven 250 ms engine cadence so startup/loading gaps cannot
poison pacing. A delayed frame may leave multiple nominal slots overdue, but
each frame callback still executes at most one job; subsequent frames catch up
one job at a time. Both the native tasklet path and the compatibility fallback
use this release schedule; only the execution thread differs.

The focused 32-bit tasklet-layout, cadence, native-completion, tasklet-priority,
and Win32 priority-restoration regressions pass. Full suite and release
validation are recorded below. The scheduler correction is statically proven
and fail-closed; final frame-time and gameplay acceptance still requires one
runtime pass of this corrected build.

## Radio playback rework contract and plan

Status: the synchronous candidate above implements the source-backed portion
under the owner's explicit offline-candidate exception. Runtime acceptance and
the additional query-cost reduction remain open. The owner reports radio silence, including announcer
speech followed by missing music, and identifies Psycho's tasklet-based radio
handling as the area to rework. This investigation does not require a CPU
classification. The exact reported transition has not been captured or run
here. The reporter-only crash exception does not apply to this incident.

### Proven implementation problems

The pre-change production path was in
`psycho-engine-fixes/src/mods/perf/radio.rs`:

- `cooperative_distance_body` maps a missing published result to the engine's
  failure distance. `cooperative_connected_body` maps it to unavailable.
  Pending computation and a completed negative query are indistinguishable
  to the scanner. This also applies to the first asynchronous generation.
- `QueryPipeline::complete` publishes only after every serial request finishes.
  One incomplete request withholds all new answers. While executing,
  `begin_scan` cannot collect a replacement batch and `observe_query` cannot
  add newly encountered requests.
- `schedule_tasklet_generation` submits at most one job per frame callback and
  never overlaps jobs. Queue priority is 63; `radio_tasklet_execute` temporarily
  lowers the shared worker to idle priority. There is no completion deadline
  or overdue-query recovery. The frame-event timeout checks callback delivery,
  not worker progress. The source therefore provides no one-refresh upper
  bound on answer age.
- Published lookup uses reference FormIDs, query kind, and radius bits or the
  expected worldspace FormID. It does not key the actual endpoint positions,
  cells, or graph revision. Failed preparation retains the previous snapshot.
  These facts do not prove a particular stale playback event, but prevent a
  claim that every consumed answer describes the current query.
- Query timing ends after the first successful publication. Existing first-use
  logs cannot establish progress at a later speech-to-music failure.

### Native consequence and evidence boundary

The current `fnv_reverse/FalloutNV.exe` identity matches the existing radio
audits: SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Focused radare2 reconfirmation is retained in
[the playback-boundary audit](../analysis/ghidra/output/perf/radio_tasklet_playback_boundary_radare2_audit.txt).
The complete historical caller and station-update listings are in
[the station contract](../analysis/ghidra/output/crash/radio_station_post_load_stale_entry_contract.txt).

1. `0x004FF397` consumes the distance result; `0x004FF77F` adds a station to
   the scanner output only when the local availability predicate succeeds.
2. `0x00833D00` immediately consumes those caller-owned output lists. When a
   refresh does not find a registered station, `0x008340CB` calls
   `0x00834210(1)` with `ECX = wrapper + 4`, setting flag mask `0x04` at
   wrapper `+0x18`.
   `0x008340D8` then calls `0x00458B30(0)`, setting wrapper `+0x15` to zero.
   The matched branch clears the flag at `0x00833FAA`.
3. The current-station path in `0x008331C0` reads that same flag through
   `0x00833BC0`. Its loss branch names `UIRadioSignalLost`, saves the selected
   wrapper to `0x011DD430`, and calls `0x008324E0(0)` at `0x008332C3`.
   Outside radio-list reset, that deactivation path clears current station
   `0x011DD42C` and invokes the native audio cleanup routines.
4. `0x008341B4` still calls the station update on its original caller thread.
   Psycho's empty-inactive fast path excludes the current station, audio-bearing
   entries, and list reset. Native instructions at `0x008342F7..0x00834397`
   reconfirm the original inactive-empty return predicate.

Thus pending availability can enter the native signal-loss/deactivation
protocol. That is a statically established consequence of the current design,
not merely a slow discovery list. It does not prove which request was pending
in the reporter's run, whether a previously published answer existed, or why
that run specifically retained speech but lost music. No new music-decoder,
allocator, or mod attribution follows from this evidence.

### Recommended design

Remove deferred tasklet generations from authoritative radio availability.
Keep discovery, signal decisions, station transitions, and playback updates
in the engine's existing order. Every consumed answer must be computed for
that scan through the active provider, or obtained through an optimization
whose exact equivalence has been proved. A negative answer must represent an
actual negative query, never unscheduled, pending, aborted, or timed-out work.

This removes the batch-completion dependency by design. It does not establish
that synchronous queries are cheap. Historical runs still spent about 5-7 ms
on the optimized query set, and connected-interior work previously produced
a much larger stall. Returning the same expensive work to one frame is not a
finished performance solution. Query-cost reduction and playback correctness
are joint acceptance requirements.

Do not replace this with another background thread, higher worker priority,
an arbitrary grace period, indefinite last-known-good answers, or a synchronous
timeout that can overlap a still-running native query. Partial publication
alone also leaves cold misses and stale-input validity unresolved. An async
accelerator would require a complete invalidation and ownership contract plus
an exact timely consumer path; the existing audits do not prove that contract.

The intended steady-state ownership is simpler: caller-owned scan containers,
query/result storage with native construction and destruction in the same
call, and no cross-frame engine pointers, native group waits, or scheduler
mutexes in the radio decision path. Preserve the installed provider ABI,
distance/range semantics, connected-path post-filters, and all station modes.
Keep the proven empty-inactive station fast path. Do not rewrite the music or
dialogue player without evidence of a separate defect there.

### Full change set

The implementation target is a synchronous, optimized engine scan followed by
the original station update. This is a cold-start DLL replacement, not a live
switch between schedulers. No native tasklet may survive a runtime unpatch;
live unpatching is outside this plan.

| Owner | Planned change |
|---|---|
| `psycho-engine-fixes/src/mods/perf/radio.rs` | Remove asynchronous query and publication machinery; retain a minimal synchronous scan scope, native station fast path, verified engine-owned optimizations, and opt-in attribution. |
| `psycho-engine-fixes/src/mods/perf/mod.rs` | Update lifecycle documentation and retain DeferredInit routing for optional radio optimization setup. |
| `psycho-engine-fixes/src/startup.rs` | Keep the existing install phase; update capability/error messages to describe the installed synchronous behavior accurately. |
| `psycho-engine-fixes/src/host_events.rs`, `events.rs` | Preserve exported ABI, numeric event IDs, and dispatch to other engine fixes. No event deletion is required. |
| `psycho-engine-fixes-helper/src/events.rs` | Preserve shared forwarding, DeferredInit gating, and dashboard events. Radio no longer using frame events is not authority to remove them. |
| `psycho-engine-fixes/src/config.rs` and shipped TOML | Preserve configuration layout and obsolete-field handling. Reuse existing diagnostic controls; no scheduler tuning settings or schema migration. Update comments only if diagnostic output changes. |
| `libpsycho/src/os/windows/winapi.rs` | Stop importing the scoped priority API from radio; leave the shared API in place. No unrelated shared-library cleanup. |
| Radio tests and this document | Replace the retired scheduler's assertions with the actual new acceptance evidence; document final ownership, hooks, costs, and limits. |

#### 1. Establish the regression and measurement boundary

The original plan required a preserved run of the speech-to-music failure
before production edits. The owner waived that prerequisite for this unreleased
candidate; a runtime comparison remains necessary for acceptance. Use the actual affected assets and workload.
This is a playback regression, so compilation, synthetic audio, a state-machine
test, and first-use tasklet logs cannot substitute for that run.

If additional observation is needed, add only opt-in, behavior-neutral
instrumentation under the existing diagnostic controls. Capture selected
station identity, query mode, missing versus completed result, job age and
completion, native loss state, and the station/audio transition. Reconfirm
additional native fields, caller ownership, and ABIs before touching them.
Keep counters bounded; use the established logger for transition records and
aggregates. Do not log each frame/query or allocate on every event. Record
diagnostic saturation explicitly rather than inventing missing events.

Keep three measurements separate: total radio CPU work, elapsed scan/query
time, and time until the next playable audio item. Existing stopwatch values
are wall time. CPU attribution needs an actual thread CPU measurement or
profiler; do not relabel wall duration. Fix the route, station set, settings,
and audio assets for before/after comparison, and measure instrumentation cost
with the controls disabled as well.

#### 2. Replace the authoritative query path

Remove these radio-owned mechanisms together:

- `QueryPipeline`, `QueryWork`, `QueryRequest`, `QueryKey`, `PublishedResult`,
  deferred `QueryValue` publication, and their generation/capacity bookkeeping;
- `EngineTasklet`, `TaskletHandle`, `PreparedQuery`, `PreparedBatch`,
  `RadioTasklet`, `SharedRadioTasklet`, `TaskletBackend`, their unsafe sharing
  implementations, native group APIs, and lazy task storage;
- frame-paced scheduling, cadence normalization, frame-thread admission,
  priority lowering/restoration, completion polling, group joins, and the
  cooperative main-thread fallback, which still delays answers;
- `PendingConnectedResult`, query/destructor handoff TLS, and the naked
  asynchronous query/destructor bridges;
- scheduler-only FormID re-resolution, reconstructed endpoint/result storage,
  capacity fallback, first-publication telemetry, constants, and imports.

Remove storage helpers only when they have no remaining production consumer.
The replacement should not reconstruct native path result objects merely to
reduce them back to booleans. Let the original scanner own those objects and
execute its existing post-filters and destructors.

`RadioScanScope` becomes a scope for synchronous radio identification and
optional measurements. It retains balanced nesting and policy-pair cleanup on
all exits, but does not collect, publish, reset, or lock a generation. Preserve
`RADIO_SCAN_DEPTH` or an equivalent existing scoped marker: the traversal
optimization tests `radio_scan_active()`, and deleting that scope would
silently remove a real cost reduction. Worker-only `RadioPathQueryScope` can
then disappear. Avoid adding TLS or eager runtime owners.

The query-callsite disposition is explicit:

| Callsite | Planned disposition |
|---|---|
| `0x00833D86 -> 0x004FF1A0` | Retain a thin periodic scan scope/profiling bridge; call the original scanner once and return its native lists. |
| `0x004FF397 -> 0x006D4EB0` | Stop installing the cooperative distance replacement. Preserve the native x87 result and caller-owned locations. |
| `0x004FF4C6`, `0x004FF645 -> 0x006D4D20` | Stop installing the connected-query replacements. Execute native success/failure and parent-space filtering within the scan. |
| `0x004FF561`, `0x004FF73D -> 0x006F4930` | Stop installing destructor bridges. Restore normal native cleanup by leaving the original calls intact at startup. |
| `0x008341B4 -> 0x00834260` | Retain the proven empty-inactive fast path; every current/audio-bearing/reset case reaches native update. |
| `0x006F3FB0` | Retain radio-scoped traversal interception only if needed by the verified cost optimization or enabled diagnostics. |
| `0x006D4D20`, `0x0056B210` profiling hooks | Keep optional attribution; preserve all original arguments and results. |

Any additional query hook requires a measured optimization and its own native
contract. No change to station cadence, signal interpolation, playlist timing,
audio handles, dialogue ownership, or music request ordering is part of the
correctness repair. A genuine native failed query retains its original result.

#### 3. Deliver actual query-cost reduction

Scheduler removal eliminates Psycho's queue/group/lock/preparation overhead,
but the historical remaining traversal cost must also be addressed. Performance
work must cover distance and both connected-query branches, including branches
that bypass pathfinding already. Preserve these native fast paths rather than
forcing every station through one general algorithm.

Use the retained path-query, discarded-door-policy, and geometry-invalidation
audits before new research. For each candidate, record the measured cost,
input/output equivalence, side effects, ownership, ABI, fallback, and native
behavioral comparison before selecting it:

| Work | Decision and evidence needed |
|---|---|
| Empty inactive station update | Retain the already-proven no-effect branch. It must never suppress current-station progression. |
| Disposition-3 door policy | Preserve the proven semantics of discarded policy work through a verified game-owned boundary; recheck scope and cleanup under synchronous execution. |
| Connected query traversal | Use the subsequently proven mode-1/mode-2 contracts above. Omit only dead policy setup; retain their minimum-use penalties, filters, and predecessor-chain semantics. |
| Repeated endpoint/setup work | Consider only if measured material and all inputs, getter side effects, lifetime, and same-call reuse are proved. No cross-scan pointer cache. |
| Query-private allocation/reset | Consider only with a complete constructor/reset/destructor and ownership contract. Existing evidence does not authorize object pooling. |
| Scanner bookkeeping and diagnostics | Remove scheduler-only work; avoid resetting large profiling state, timer reads, and statistic updates when profiling is off. Retain the minimal policy scope required for correctness. |

The existing `resolve_policy_setup_target`/`verify_inlined_policy_provider`
path can derive a setup target in the replacement provider's allocation, then
`install_door_policy_bypass_hooks` hooks that target. It is not an exclusively
game-owned optimization. Do not carry that private-provider interception into
the replacement or expand its signature catalogue. Replace it with a proven
engine-owned boundary that preserves the installed provider's behavior.
Unrecognized/unsupported optimization cases must execute the original provider
normally. Removing that acceleration alone is not a performance solution;
installed-provider workloads must pass the same cost gate.

Do not select a TTL cache, reverse multi-source search, Euclidean substitute,
shared query nodes, or reused graph snapshot without the missing equivalence
and invalidation proofs. Previous failed optimizations remain failed evidence;
do not repeat them without a new measured condition. If the remaining exact
work cannot meet the performance gate, keep the candidate unreleased and close
that specific cost contract. Increasing radio delays or dropping stations is
not an allowed fallback.

#### 4. Make installation and lifecycle deterministic

Prepare and verify retained hooks before enabling dependent interceptions.
Use the existing ownership-aware callsite/inline containers and
`ModificationTransaction` rather than extending raw patch ownership logic.
For every dependency group, failed activation must restore its prior provider
or leave an independently correct synchronous path. Do not overwrite a hook
installed by another component during rollback.

Independent optional optimization failure leaves native behavior available and
logs the concrete fallback. Hook ownership loss or incomplete rollback is an
error, not a successful install. Publish capability messages only after the
corresponding transaction commits. Remove messages describing tasklet capacity,
worker priority, generations, or cooperative fallback from the final design.

Keep the accepted early scan/station installation boundary. The subsequent
dispatch contract above places dormant optional code bridges at that quiescent
boundary too; DeferredInit verifies them and publishes capabilities without
code writes. `radio::observe_event` handles only the
setup/lifecycle work still needed; `OnFramePresent` and world teardown no longer
schedule or join radio jobs. `perf::observe_event` remains for DeferredInit.
Do not delete shared event IDs, forwarding, dashboard calls, or other fixes'
handlers. DeferredInit remains idempotent, and unsupported signatures fail to
the original native behavior rather than disabling radio.

Follow [the startup-safety contract](nvse_startup_phase_safety.md): identify
the last accepted load-to-gameplay artifact before implementation and review
the resulting imports/TLS/static/hook footprint against it. Code and TLS
removal can change that footprint too. No loader-lock work, new worker,
configuration layout change, helper initialization, or cross-DLL relocation is
needed by this design. The final artifact still requires representative Proton
load-to-gameplay acceptance.

#### 5. Qualify behavior and cost at the real boundary

Define each expected outcome before implementing its change. The owner's
radio-specific authorization permits the unreleased candidate without a new
failure reproduction or profiling capture. The runtime matrix remains the
acceptance contract, not a completed result or an implementation prerequisite:

| Case | Required observation |
|---|---|
| Reported announcer-to-music failure | The intended music becomes audible and subsequent transitions continue through the original reproduction interval. |
| Music-to-music, tuning, off/on | Normal playback progression; no reset loop, skipped native progression, or permanently silent selected station. |
| First scan and newly discovered station | Actual scan-time availability; no artificial unavailable interval while waiting for a generation. |
| Genuine signal loss/recovery | Native range/domain decisions, fade/stop/reacquisition behavior preserved; no forced always-available station. |
| Interior/exterior and connected stations | Native distance and both connected-query predicates agree; native no-query branches remain intact. |
| Stationary and moving player/station | Each decision uses current native inputs; no previous-position or previous-cell result reuse. |
| Save/load, new game, fast travel, menu return | Normal playback and discovery resume; no radio worker join or stale published state. |
| World radios and Pip-Boy radio | Active/audio-bearing station work remains native, including cleanup and changes of selected station. |
| Tasklet congestion and delayed frame delivery | No radio availability dependency on Psycho tasklet completion or Present-event frequency; inspect actual playback, not only counters. |
| Installed provider and native-provider comparison | Correct behavior with each supported environment, without provider-name allowlists or private-provider patches. |
| Unsupported optional optimization | Original query behavior and valid radio playback remain available. |

The eventual performance acceptance evidence must cover total radio CPU per
refresh, maximum scan wall time, and frame-time tails on the same workload.
Steady play and transitions are separate cases so averages cannot hide a
periodic stall. The selected ceiling is the owner's 120 FPS frame budget,
8.333... ms, with room for the game's other work. The final result must
reduce actual radio work and must not restore the previous periodic hitch;
no CPU/FPS improvement is claimed by static removal of tasklet machinery.

Retire tests whose production scheduler, tasklet ABI, or connected-result
handoff is removed. This is removal of the obsolete mechanism, not permission
to weaken the playback gate. Retain applicable behavior tests for surviving
production functions. Add only tests that execute changed shipped behavior,
with evidence-backed inputs, alongside the real runtime regression. Do not
add source assertions, synthetic engine graphs, mocked music/provider output,
or object-layout tests as substitutes for playback and cost measurements.

Run focused behavior checks, then the affected crate suite and one release
build with the explicit supported target:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib
cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo fmt --all -- --check
git diff --check
```

If implementation changes helper/shared-library code, add the affected suites
and final DLL builds; the current plan does not require those edits. Complete
the real playback/performance matrix and applicable startup gate before
packaging or calling the fix complete. No commit is authorized by this plan.

### Execution order and completion criteria

1. Use the retained failing/timing evidence and the owner's authorization for
   an unreleased candidate; retain the startup-baseline qualification limit.
2. Implement against the completed source/binary contracts in the subsequent
   implementation-readiness section above. No new profiling is required.
3. Implement synchronous results, selected cost reductions, hook transactions,
   and lifecycle cleanup as one coherent candidate. Keep unrelated dirty work.
4. Run focused and affected-suite checks, build once, inspect the final diff,
   then repeat playback, performance, and startup acceptance on that artifact.
5. Update the current-behavior sections of this document, replacing obsolete
   generation guarantees with the accepted synchronous contract and measured
   limits. Retain raw historical evidence without duplicating it.

The planning deliverable covers the full affected surface. Implementation is
done only when playback works and the cost gate passes together; a scheduler
deletion that fixes silence but restores hitches is an intermediate candidate.

The remaining acceptance gates are the captured playback comparison and a
measured, equivalent reduction of the expensive native query work. The source and binary
evidence are sufficient to reject the current pending-as-failure contract and
to choose the synchronous correctness boundary. They are not sufficient to
claim a fully lightweight replacement algorithm or accepted playback fix.
The historical complete-generation requirement elsewhere in this document
describes the retired implementation, not a constraint on this rework.

## 2026-07-27 Interior Connected-Path Coverage Gap

The new report
`.reports/psycho-engine-fixes-latest--interior-stutters.log` was produced by
commit `ac99b5de144910aba81e7bc2a97380658319864e`. It identifies a second,
interior-specific radio hitch surface that the mode-0 cooperative bridge does
not cover.

### Direct runtime evidence

The report proves that all existing mode-0 safeguards were active:

```text
[RADIO] Game-owned radio bridge active:
  scan=0x00833D86 query=0x004FF397 station_update=0x008341B4 capacity=512
[RADIO] Native tasklet query backend active:
  provider=nvse_stewie_tweaks.dll!... queue_priority=63 worker_priority=idle
[RADIO] Exact mode-0 dead door-policy bypass active: ...
```

The first cooperative scan in the affected interior then reported:

```text
requests=31 cadence/spacing=250/8ms
scan_us=Some(112712) state=Executing thread=0x00003700
results=31 jobs=31 worker_wall_total/max=10504/2340us
game_thread_prep_total/max=55/3us latency_ms=Some(438)
worker_thread=0x00003F18
```

This directly proves:

- the periodic scanner occupied 112.712 ms of wall time on its game thread;
- the 31 intercepted mode-0 queries ran on a different tasklet worker;
- all 31 worker calls together occupied 10.504 ms spread over 438 ms, with a
  2.340 ms maximum call;
- game-thread endpoint preparation totaled only 55 us;
- no cooperative fallback, capacity failure, or native-backend failure was
  logged.

The 112.712 ms scanner interval therefore cannot be the worker-side mode-0
query generation. It is synchronous work still retained inside
`FUN_004FF1A0`.

Hitch profiling was disabled in this report, so it does not provide the
per-mode `query1` and `query2` counters. The exact split of the 112.712 ms
between the two connected-interior callsites remains to be measured in one
focused reproduction. That missing split does not change the uncovered
callsite contract below.

### Current-executable static contract

New static research used radare2 against the repository's current
`fnv_reverse/FalloutNV.exe`:

```text
size:   16084808 bytes
sha256: 42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c
```

`FUN_004FF1A0` has three path-query callsites:

```text
0x004FF397 -> 0x006D4EB0  mode-0 distance/range query
0x004FF4C6 -> 0x006D4D20  mode-1 connected-interior query
0x004FF645 -> 0x006D4D20  mode-2 connected-interior query
```

Production code replaces only `0x004FF397`. Radare2 xrefs prove that the two
generic calls above are the only `0x006D4D20` calls in the radio scanner; the
other callers are `0x006D4F01` and `0x0079DD11` and are outside this fix.

The mode-1 branch constructs a caller-owned result at `[EBP-0x68]`, constructs
both `PathingLocation` arguments, and calls `0x006D4D20` at `0x004FF4C6` with
the seven cdecl arguments `(station, current, result, 1, 0.0, 0, 1)`. It
destroys both locations before inspecting the result. On query success it sets
availability `[EBP-0x0D]` and the connected signal value `[EBP-0x14]`, then
walks every result element. A non-null worldspace at element `+0x04` rejects
the station unless it is pointer-identical to the station worldspace held at
`[EBP-0x30]`. The result destructor call is `0x004FF561 -> 0x006F4930`; the
following five-byte jump reaches the common consumer at `0x004FF77F`.

The mode-2 branch constructs its result at `[EBP-0xAC]`. When both endpoints
already have the same non-null parent domain, `0x004FF5B3` accepts them without
calling the generic query. Otherwise `0x004FF645` calls `0x006D4D20` with
`(station, current, result, 2, 0.0, 0, 1)`. On query success, every result
element must have a null worldspace. Its result destructor call is
`0x004FF73D -> 0x006F4930`; its following jump is only the two-byte
`0x004FF742 -> 0x004FF77F`. The early same-domain path also reaches that
destructor with no generic call, so it must remain wholly vanilla.

The common consumer at `0x004FF77F` tests availability first. It passes
`[EBP-0x14]` onward only when availability is true. A cooperative result
therefore needs to retain only the final accepted boolean; the connected
signal value needs to be written only for a true result.

The generic result contract is also exact:

- `0x006F48B0` is a thiscall constructor for a 0x38-byte, four-byte-aligned
  object. It constructs dynamic arrays at `+0x00` and `+0x10` and two
  12-byte values at `+0x20` and `+0x2C`.
- `0x006D4D20` is cdecl with seven 32-bit arguments. It clears the supplied
  result through `0x006F4990`, owns its 0x20C4-byte query object on its own
  stack, and returns success in `AL`.
- `0x0044DDC0` returns the first array's count at result `+0x08`.
  `0x006A7AF0`/`0x006A1440` returns data `+ index * 0x0C`, establishing a
  12-byte parent-space element whose worldspace field is at `+0x04`.
- `0x006F4930` destroys the result's two dynamic arrays. The thread that
  constructs and queries the result must also reduce and destroy it; no array
  pointer or result storage may be published to the game thread.

These branches explain the location boundary. Entering an interior activates
two generic path-query paths which are still synchronous, while the mode-0
work is demonstrably on a tasklet worker. Prior runtime work measured ordinary
station enumeration and residual scan logic at roughly 57-73 us once query
cost was removed. The uncovered mode-1/mode-2 calls are therefore the only
known scanner operations with the contract and scale to account for the
112.712 ms interval.

The root-cause classification is:

> The cooperative radio implementation has incomplete callsite coverage. It
> moves mode-0 distance queries off-thread, but leaves the vanilla
> connected-interior mode-1 and mode-2 queries synchronous. The periodic
> scanner reaches those branches in interiors and stalls the game thread.

This classification is a reasoned conclusion from the direct runtime timing
and the static call graph; the supplied run did not enable the per-mode timer,
so it does not directly assign milliseconds between mode 1 and mode 2.
Resolving the mode-1 worldspace FormID back to its canonical loaded form on
the game thread is likewise an implementation inference. The bridge must
round-trip that FormID through `0x004839C0` and require pointer identity with
the scanner's `[EBP-0x30]` value before using the cooperative path. A null or
non-canonical resolution must fall back rather than weaken the engine's
pointer-identity predicate. No runtime observation of the proposed fix exists
yet.

This is distinct from the five-second scrap-heap GC and memory-watchdog
cadences visible in the same log. Both run on background threads, and the
logger queues records asynchronously. Neither explains the directly measured
112.712 ms inside the game-thread radio scanner or its interior-only branch
boundary.

### Safe intervention

Returning cooperative success directly from either generic-query replacement
is incorrect. The vanilla caller would then inspect the still-empty
caller-owned result and accept a fabricated path. Replacing a broad branch
region is also unnecessary, and the mode-2 cleanup tail is too short for a
five-byte jump without overwriting the next switch case.

The minimal safe surface is four existing five-byte `CALL` instructions:

```text
0x004FF4C6 -> connected-query bridge       mode 1
0x004FF561 -> result-destructor bridge      mode 1
0x004FF645 -> connected-query bridge       mode 2
0x004FF73D -> result-destructor bridge      mode 2
```

The query bridge captures the scanner's EBP and the original seven arguments.
On a normal fallback it clears any pending override, calls `0x006D4D20`, and
returns its result unchanged; the caller's post-filter and cleanup remain
vanilla. On a cooperative hit it records a typed request, places the complete
published boolean in thread-local pending state, and returns false. Returning
false skips the caller's path-inspection loop without claiming that its empty
result is valid.

Each destructor bridge receives the result in ECX and captures the scanner's
EBP. It calls the original `0x006F4930` first. It then consumes only a pending
override of the matching mode, writes `[EBP-0x0D]`, and writes the vanilla
value from `0x01012054` to `[EBP-0x14]` only when true. With no matching
override it is behavior-neutral. The mode-2 early same-domain path therefore
passes through unchanged.

Pending state is game-thread TLS, is cleared before every bridge decision and
at outer scan entry/exit, and is consumed once. A mismatch fails closed to the
false value already returned by the query bridge rather than leaking an
override into another station.

### Full change plan

All implementation work belongs in
`psycho-engine-fixes/src/mods/perf/radio.rs`; this document remains the durable
engine contract. No configuration or helper-DLL change is required.

1. Add exact addresses, function types, layouts, and signatures for
   `0x006D4D20`, `0x006F48B0`, `0x006F4930`, the two query calls, and the two
   destructor calls. Define four-byte-aligned 0x38-byte result storage and a
   12-byte parent-space node. Verify every target and surrounding instruction
   window before changing any call displacement.
2. Generalize the fixed-capacity pipeline from distance-only values to typed
   scalar requests/results. The key contains query kind, station FormID,
   current-reference FormID, and a kind-specific word: radius bits for mode 0,
   expected station-worldspace FormID for mode 1, and zero for mode 2. The
   result tag must match the key so a distance can never alias an availability
   result. Mode 0, mode 1, and mode 2 publish atomically as one complete
   generation.
3. Extend `PreparedQuery` with a transient expected-worldspace pointer and a
   typed output. Continue resolving endpoint FormIDs and constructing both
   `PathingLocation` values on the game thread. For mode 1, resolve the
   expected worldspace FormID there as well and retain that pointer only while
   the native tasklet group owns the prepared query. The existing pre-load,
   exit-to-menu, and shutdown barriers must join the group before any prepared
   pointer or location can outlive the world.
4. Dispatch by query kind in the existing one-query native tasklet. Mode 0
   retains `0x006D4EB0`. Modes 1 and 2 construct a fresh result on the worker,
   call the original `0x006D4D20`, reduce its parent-space array with the exact
   pointer predicates above, and destroy the result on that same worker before
   publishing one boolean. Keep bucket 63, scoped Win32 idle priority, serial
   pacing, the provider capability check, and the current no-overlap rule.
5. Add one naked seven-argument query thunk and two naked destructor thunks,
   with small Rust bodies for request extraction, TLS state, fallback, and
   caller-local updates. Both query callsites may share the query body because
   the verified mode argument identifies the request; the destructor thunks
   pass their expected mode to one common body. Validate fixed arguments
   `(mode, 0.0, 0, 1)`, the mode-specific result-local address, caller EBP,
   and live FormIDs before using the cooperative path. Mode 1 must also
   require `LookupFormByID(station_worldspace_form_id) == [EBP-0x30]`.
6. Install the neutral destructor bridges before their query bridges.
   Preflight all four target/signature checks and retain original
   displacements for rollback if a later patch fails. This ordering ensures
   that even a partial write cannot suppress a vanilla query without its
   matching completion bridge. Do not patch the short tail jumps or the
   shared `0x006D4D20` entry.
7. Preserve existing failure semantics precisely. If cooperative scheduling
   is unavailable at scan entry, or a query does not match the exact caller
   contract, call the complete original query and post-filter synchronously.
   Before the first publication, return conservative unavailable values just
   as mode 0 currently returns its failure distance. An incomplete/aborted
   worker generation never publishes; the last complete snapshot survives.
   World transitions reset the snapshot. Capacity failure disables later
   cooperative scans and restores the original path; it must never publish a
   partial generation.
8. Extend bounded diagnostics rather than adding a hot-path logger. The first
   collection/publication records should include total and per-kind request
   counts. Existing `[RADIO_SCAN] query1/query2` timings remain the proof that
   no generic connected query executed synchronously on the scan thread.
9. Add focused regressions for typed-key/value separation, per-kind
   deduplication, atomic mixed-generation publication, aborted-generation
   retention, capacity handling, mode-1 null-or-expected reduction, mode-2
   all-null reduction, TLS one-shot/mode matching, the mode-2 early-path
   pass-through, result/node/tasklet layouts, pacing, and world-lifetime
   reset. Inspect optimized i686 disassembly for the naked thunks, 32-byte
   copied-argument cleanup, ECX/EBP capture, caller-owned stack cleanup, and
   original destructor invocation.
10. Run the focused radio tests, the affected crate suite, `git diff --check`,
    and the supported release build:
    `cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes`.
    Then replay the supplied interior with hitch profiling enabled. Acceptance
    requires a complete mixed generation, no synchronous `query1`/`query2`
    calls after warm-up, no recurring scanner-sized frame spike, unchanged
    station decisions across modes 0-4, and clean interior/exterior,
    load/save, exit-to-menu, and shutdown transitions.

### Implementation and static validation

The full change above was implemented on 2026-07-27 in
`psycho-engine-fixes/src/mods/perf/radio.rs`. The forwarding event API in
`psycho-engine-fixes/src/mods/perf/mod.rs` also received lifecycle
documentation. No configuration or helper-DLL change was required.

The implementation provides:

- typed `Distance`, `NullOrStationWorldspace`, and `InteriorOnly` keys and
  scalar values in one fixed-capacity atomic generation;
- game-thread FormID and canonical worldspace resolution, with live pointers
  confined to a world-lifetime-protected prepared tasklet;
- worker-local generic result construction, exact mode-specific parent-space
  reduction, and same-worker result destruction;
- verified query and destructor bridges at all four exact radio callsites,
  installed with complete-call rollback;
- a one-shot, mode-matched TLS handoff that never presents a fabricated path
  to vanilla and leaves the mode-2 early same-domain branch unchanged;
- first-use diagnostics reporting distance/mode-1/mode-2 request counts; and
- focused regressions for typed alias prevention, mixed-generation
  publication, failure retention, capacity, result layout/reduction, TLS
  consumption, pacing, tasklet layout, priority, and world lifetime.

Validation evidence:

```text
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes \
  mods::perf::radio::tests
25 passed; 0 failed

cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
84 passed; 0 failed

cargo build --release --target i686-pc-windows-gnu \
  -p psycho-engine-fixes
passed

git diff --check
passed
```

The optimized i686 DLL was disassembled after the release build. The generic
query thunk copies original stack arguments `+0x04` through `+0x1C`, pushes
scanner EBP, calls the Rust body, adds exactly 32 bytes, and returns so the
engine still owns its original 28-byte cleanup. The two destructor thunks push
ECX, EBP, and their constant mode, call the shared body, add 12 bytes, and
return. The shared body moves the result into ECX and calls `0x006F4930`
before reading TLS; only a matching handoff writes `[caller_ebp-0x0D]`, and a
true result also copies `0x01012054` to `[caller_ebp-0x14]`.

This is static and automated validation, not a runtime acceptance result. The
same interior reproduction and transition matrix below still require a
playtest.

An optional pre-change profiling replay can quantify the 112.712 ms split
between mode 1 and mode 2, but it is not an implementation prerequisite: both
uncovered callsites share the proven ownership defect and both must be fixed.

Do not fix this by throttling radio refreshes, globally caching path results,
disabling connected-interior radios, returning a fabricated path, patching
the shared generic-query entry, or widening the hook to unrelated callers.

## 2026-07-23 Unchanged-Chart Runtime Correction

The startup-corrected native build reached gameplay and supplied the evidence
that the initial worker design was still bursty:

```text
[RADIO] Native tasklet query backend active:
  provider=nvse_stewie_tweaks.dll!0x066FADB0
[EVENT] Game engine ready
[RADIO] Cooperative collection verified:
  requests=12 cadence/spacing=250/20ms scan_us=Some(61)
  thread=0x00000640
[RADIO] Native tasklet generation verified:
  results=12 jobs=12 worker_total/max=5840/1619us
  game_thread_prep=29us latency_ms=Some(80)
  worker_thread=0x00000614
```

Direct conclusions:

- startup passed the former pre-Deferred crash point;
- the verified Stewie native backend was active;
- endpoint preparation cost only 29 us on the game thread;
- provider execution occurred on a different thread;
- all 12 calls still formed one 5.840 ms worker callback, completing only
  80 ms after collection despite the measured 20 ms release spacing.

The unchanged chart proves that moving the 5.840 ms block to one worker
callback was insufficient. It does not by itself prove whether the visible
stall was CPU competition, contention on the provider's per-cell reference
locks, or both. The provider's proven lock scope makes lock pressure a credible
mechanism, but that attribution remains inference.

The corrective intervention is therefore scheduling, not another hook:

- task storage contains exactly one prepared query;
- `QueryPipeline::take_next` is the sole release path for both native and
  fallback work, so the measured cadence is enforced rather than diagnostic;
- a native group is closed and completed before its endpoint objects are
  destroyed or another query is submitted;
- results remain private until all requests in the generation complete.

This structurally removes the 12-query worker burst while retaining the
already-proven native ABI and ownership boundaries.

The next runtime used that paced implementation:

```text
[RADIO] Cooperative collection verified:
  requests=12 cadence/spacing=250/20ms scan_us=Some(59)
  thread=0x000001CC
[RADIO] Native paced tasklet generation verified:
  results=12 jobs=12 worker_total/max=7266/1351us
  game_thread_prep_total/max=37/4us latency_ms=Some(231)
  worker_thread=0x00000384
```

Direct conclusions:

- the installed build was the paced build;
- all 12 provider calls were released across nearly the full 250 ms cadence;
- no individual first-generation worker call approached the reported 6 ms
  chart spike;
- the first collection scan occupied only 59 us;
- the user's chart remained unchanged.

That result rejects both the single worker burst and the first collection scan
as the remaining cause. A later fresh run reconfirmed that conclusion over a
longer measured cadence:

```text
[RADIO] Cooperative collection verified:
  requests=12 cadence/spacing=493/41ms scan_us=Some(52)
  thread=0x00000770
[RADIO] Native paced tasklet generation verified:
  results=12 jobs=12 worker_total/max=8211/1651us
  game_thread_prep_total/max=41/5us latency_ms=Some(472)
  worker_thread=0x000007D4
```

The user's chart was still unchanged. The log proves that the bridge was
active, the scanner itself occupied only 52 us, no single provider call
approached the roughly 6 ms spike, and the calls were spread across 472 ms.
It therefore rules out another query-burst or scan-body change as the
corrective direction.

Static research found one real main-thread blocking hazard in Psycho's native
adapter:

- worker dispatch calls task execution at `0x00B02588`;
- only after execution returns does it call the task finish slot, clear task
  group/claim ownership at `0x00B025D0` and `0x00B025DA`, and call group
  completion at `0x00B025E4`;
- `0x00B02670` increments completed count `+0x38` under the group critical
  section, compares it with submitted count `+0x34`, and signals completion;
- `0x00B02920` compares those counters and performs an infinite semaphore wait
  while they differ;
- Psycho previously set its callback-done atomic inside task execution, before
  every native completion step above. An ordinary frame could therefore enter
  the infinite wait during that gap.

The current implementation mirrors the engine's own unlocked counter check and
calls `0x00B02920` on ordinary frames only after nonzero submitted/completed
counts are equal. World-lifetime barriers retain the intentional blocking wait.
Whether this race caused the observed Proton frame spike is a reasoned
hypothesis, not yet runtime proof.

New radare2 analysis then exposed the remaining scheduler error:

- the group constructor at `0x00B0283D` initializes group `+0x30` to zero;
- enqueue at `0x00B02159` reads that field, clamps values at or above 64 to
  63, and selects manager queue `+0x6C + priority * 4`;
- worker dispatch at `0x00B024C7` starts with bucket zero and advances by one
  until the first nonempty queue is found;
- Psycho never changed the constructor value, so every paced radio query was
  still inserted into the engine's first, highest-service bucket.

This explains why spreading the calls did not isolate frame-critical engine
work: the radio callback remained eligible ahead of every lower-service
tasklet on each release. The actual correction assigns group priority 63 after
every successful activation and before submission. In addition, the callback
temporarily caps the worker at Win32 idle thread priority, allowing the normal
game/render threads to preempt its CPU work. The exact previous tasklet-worker
priority is restored before the callback returns.

Startup verifies the constructor layout, enqueue calculation, and ascending
dispatcher bytes before enabling the native backend. Failure to lower or
restore the worker priority aborts that result, disables the native backend,
quiesces the group, and restores the already-correct cooperative fallback.
No new periodic diagnostic hook is installed.

## 2026-07-23 Pre-Deferred Startup Crash Correction

The first worker-backed build crashed during game-data startup at
2026-07-23 14:10:20. The new native tasklet path did not execute.

Direct runtime evidence:

- `psycho-engine-fixes-latest.log` records the early radio bridge installation
  at 14:10:10 but contains neither `[EVENT] Game engine ready` nor
  `Native tasklet query backend active`.
- `nvse.log` reaches `init complete` but contains no later DeferredInit
  activity.
- `CrashLogger.log` faults at BaseObjectSwapper
  `ConditionalInput::IsValid + 0x88` (`0x0BFC4990`) and reports corrupt
  stack/heap-shaped return entries immediately below the two external-plugin
  frames.
- Tasklet API verification, tasklet allocation, group creation, submission,
  and the new policy-hook installation all begin only from radio DeferredInit.
  None could have run in the observed process.

This is the same external fault signature and startup phase recorded in
`docs/graphics_fnv_atmosphere_startup_crash_errata.md`. That erratum proves
that this modpack is sensitive to new owner initialization during plugin/data
loading; BaseObjectSwapper also contains an independent uninitialized-member
hazard. It does not prove that Psycho wrote into BaseObjectSwapper.

The worker implementation had nevertheless introduced two pre-Deferred
perturbations: its 0xE01C-byte tasklet/batch object was embedded eagerly in the
DLL image, and newly forwarded world-lifetime messages could initialize radio
`LazyLock` owners before DeferredInit. Those are the only worker-branch changes
that could precede the missing DeferredInit record. Treating them as the
trigger is a reasoned inference from phase and A/B scope, not a direct
attribution of the external fault.

The correction restored the established startup phase boundary:

- the DLL embeds only a two-word lazy owner; tasklet state is allocated once
  after DeferredInit and after every tasklet capability signature succeeds;
- the helper does not forward the newly added `PreLoadGame`,
  `ExitToMainMenu`, or `NewGame` messages until it has forwarded DeferredInit;
- the core independently ignores those barriers until radio DeferredInit has
  completed;
- the already-tested early radio callsite hooks are unchanged.

Focused tests reject both an eagerly embedded batch and a pre-Deferred
world-lifetime barrier. The subsequent run passed the former BaseObjectSwapper
crash point, logged `[EVENT] Game engine ready`, and enabled the native tasklet
backend. Transition and frame-time acceptance remain required below.

## 2026-07-23 Native Tasklet Contract

New radare2 research against the current executable closed the earlier
parallel-traversal knowledge gap.

Direct static proof:

- `0x006D4D20` builds the 0x2058-byte A* query on the calling thread.
  `0x006F3D90` asks `BSWin32TaskletManager` whether the current thread is one
  of its workers and stores the result at query `+0x2054`. Traversal therefore
  has an explicit native tasklet execution mode; it is not main-thread-only
  code.
- The existing tasklet crash audit proves real engine navmesh/path work runs
  through `0x00B023F0 -> 0x00B02460 -> 0x00B02588` on
  `[FNV] BSWin32TaskletManager - Tasklet N`. The same path calls the loaded
  FormID resolver `0x004839C0`.
- `0x00B00A00` returns the manager singleton at `0x011F8270`.
  `0x00B00A80`, `0x00B00AE0`, `0x00B00B40`, and `0x00B00BC0` are the
  game-owned group create, activate, submit, and close wrappers.
- Group creation reaches manager virtual `0x00B02010`, allocates the exact
  0x3c-byte `BSWin32TaskletGroupData`, and constructs its critical section and
  completion semaphore. Activation reaches `0x00B020A0`; submission reaches
  `0x00B02220`; close reaches `0x00B02310`.
- The group constructor at `0x00B027C0` writes priority zero at group `+0x30`
  (`0x00B0283D`), submitted count zero at `+0x34`, and completed count zero at
  `+0x38`.
- Enqueue at `0x00B02159` reads group `+0x30`, clamps values at or above 64 to
  63, and uses manager bucket `+0x6C + priority * 4`. Dispatcher
  `0x00B024C7` scans those 64 buckets in ascending order beginning with zero.
  Bucket zero therefore has first service and bucket 63 has last service.
- Worker completion at `0x00B02670` increments the group's completed count and
  signals its semaphore after submissions are closed. Group virtual
  `0x00B02920` waits when submitted and completed counts differ, consumes the
  signal, and makes the group reusable.
- The manager-owned task layout is 0x18 bytes: vptr `+0x00`, requeue byte
  `+0x04`, group `+0x08`, readiness byte `+0x0C`, claim word `+0x10`, and
  queue link `+0x14`. Worker dispatch optionally calls vtable `+0x04`, calls
  execution at `+0x08`, then calls completion at `+0x00` before clearing the
  group and claim fields.

Provider boundary and reasoned inference:

- `0x006F3D99 -> 0x00B00A00` obtains the tasklet manager and
  `0x006F3DAF` calls its worker-identity virtual method. The result is stored
  at query `+0x2054` at `0x006F3DB7`.
- The same traversal then invokes the query's current virtual provider slot
  `+0x04` at `0x006F40D0 -> 0x006F40D3`. Provider replacement is therefore a
  replacement of an interface which the engine itself places in tasklet mode,
  not a private Stewie entry point.
- Psycho validates that current slot target as executable at DeferredInit and
  after any later slot change. It does not inspect the target's module name,
  version, or implementation bytes.
- No live reference pointer crosses to the worker. The game thread resolves
  the station and current-reference FormIDs, constructs both 0x28-byte
  `PathingLocation`s, and retains them until native group completion. The
  worker receives only those owned endpoint values, the radius, and the scalar
  generation key.
- The worker runs every request through the original `0x006D4EB0` wrapper.
  It neither replaces the A* algorithm nor shares query-owned nodes.

No static callsite in vanilla submits the radio wrapper itself as a tasklet.
Worker safety is therefore a reasoned inference from the provider virtual
ABI's explicit tasklet mode, existing path/navmesh tasklet execution,
tasklet-aware scrap allocation, and the absence of cross-thread live-reference
ownership. The fix does not assume provider internals.

World lifetime:

- xNVSE `PreLoadGame` is dispatched immediately before Fallout reads the new
  save. `ExitToMainMenu` is dispatched before the game processes the exit
  flag. Both now reach the core, close the radio group, wait for completion,
  destroy endpoints on the game thread, and reset the result pipeline.
- `NewGame` also resets through that barrier. Loading-frame observation
  quiesces any remaining task, and the worker checks the engine loading flag
  before its single query so it does not begin provider work during a
  transition.
- Waiting can consume the remaining worker time only at a world-lifetime or
  loading boundary. Normal presented frames poll the native group's
  submitted/completed counters and call the group wait only when the counts
  are already equal, so the native infinite-wait branch cannot execute.

The fixed Rust task storage is 0x8c bytes after DeferredInit: one 0x18-byte
engine task header, a count, and one 0x70-byte prepared query. The generation
pipeline still has fixed capacity for 512 scalar requests and results. The
native manager additionally owns one 60-byte tasklet group. The path performs
no routine Rust heap allocation, file I/O, overlapping provider call, or wait
for provider work on the render path. The provider's existing query
allocations occur on an engine-initialized tasklet worker and are freed before
that worker callback returns. Each activation sets the group to the verified
last-service bucket 63 before submission. Only the duration of Psycho's
callback is capped at Win32 idle priority; a non-send scoped guard
restores the worker's exact prior priority before control returns to the
engine.

## 2026-07-22 Save-Load Crash and Resolver Correction

The first cooperative runtime crashed immediately after the save finished
loading. `CrashLogger.log` proves this was introduced by the cooperative frame
callback:

```text
falloutnv                 0x004F9620
psycho_engine_fixes       0x100BE4B0
psycho_engine_fixes_helper
nvse_1_4 DisplayFrameHook<0>
ECX = 0
```

The initial implementation incorrectly treated `0x004F9620` as runtime
`LookupFormByID`. Radare2 proves `0x004F9620` is actually an instruction inside
the thiscall constructible-object method beginning at `0x004F95A0`; it reads
the object through `ECX`. The cooperative code passed a FormID on the cdecl
stack and left `ECX` null, causing the observed access violation before any
path-provider query ran.

The bad address came from reading the `#elif EDITOR` definition in xNVSE's
`GameAPI.cpp` as though it applied to the runtime build. The runtime section
implements `LookupFormByID` against the live forms map instead. The equivalent
game-owned runtime resolver is `0x004839C0`, already used by
`engine_fixes/extraownership.rs` and documented by
`analysis/ghidra/output/crash/entrydata_formref_resolver_contract_audit.txt`.

Radare2 reconfirmed the runtime resolver contract in the current executable:

- cdecl one-argument ABI: reads the FormID at `[EBP+8]` and returns with plain
  `RET`;
- returns the resolved TESForm in `EAX` or null;
- reads live map owner `0x011C54C0` and supplies it as `ECX` to the map lookup;
- has 974 static call references in the executable.

The cooperative implementation now calls `0x004839C0` and verifies its exact
18-byte entry signature before installing either radio callsite patch. A
signature mismatch fails closed at startup. Because the crash occurred inside
the first resolver call, it supplies no evidence of a path-provider or
`OnFramePresent` phase failure; those paths were never reached in the crashed
run.

The latest branch telemetry disproved the proposed mode-0 immediate-goal fast
path. Do not implement that fast path from the earlier Ghidra audit hypothesis.

## Generation Scheduling Contract

`FUN_00833D00` calls the periodic scanner at `0x00833D86` and immediately
iterates its returned station list after the call. Its caller-owned output
containers cannot survive a return, so the whole scanner cannot simply resume
on a worker or later frame. `FUN_004FF1A0`, however, has one independently
replaceable expensive boundary: the mode-0 call at `0x004FF397` to
`FUN_006D4EB0`.

The implementation has three phases:

1. During a periodic scan, each mode-0 call returns the matching result from
   the last fully published generation, or the engine's exact failure sentinel
   when no prior result exists. The scan records only the station FormID,
   current-reference FormID, radius, and query key.
2. `OnFramePresent` event 6 first proves it is on the periodic scanner's game
   thread. When the next cadence slot is due, the game thread resolves
   both references and constructs one fresh endpoint pair on that thread,
   activates a native tasklet group, writes its priority to bucket 63, and
   submits one query. The worker temporarily caps only itself at idle
   priority, calls the original `0x006D4EB0` wrapper once, then restores its
   exact prior priority. No second query can overlap it. The active provider
   remains opaque and is reached only through the original game wrapper.
3. The worker writes only its one-query task storage and completion atomics; it
   never locks or mutates the generation pipeline. After native group
   completion, the game thread records that result and destroys its endpoints.
   The complete result array is published in one state transition only after
   the last serial request completes. The next periodic scan consumes that
   coherent generation.

No reference, iterator, provider object, stack frame, query node, or
caller-owned output list survives without a proven owner. Plain FormIDs,
radius values, and completed floats persist in the generation pipeline.
Prepared `PathingLocation`s persist only inside fixed task storage while the
native group owns the worker task. An unresolved FormID aborts the building
generation and retains the last complete snapshot.

Missing, stale, or foreign-thread frame events cause the scanner to use the
original synchronous wrapper. Capacity overflow also restores that exact
fallback. A null or non-executable provider target fails closed to the same
path.

The normal station refresh cadence remains unchanged. A newly computed
generation becomes visible on a following radio refresh. With 12 requests and
the observed 250 ms cadence, nominal release spacing is 20 ms and the final
query becomes eligible around 220 ms after collection. A slow or delayed frame
can defer completion to the next refresh. The first asynchronous scan
deliberately reports no mode-0 station until its first full generation
completes.

The exact disposition-3 door-policy bypass remains a capability-gated optional
accelerator for the already-proven layouts. It reduces total CPU work when its
signatures match, but never gates the provider-agnostic scheduling fix.
Unrecognized provider layouts retain their behavior and are still submitted
through the original virtual ABI. Accelerator recognition is also
capability-based: it compares code shape and allocation ownership, not a DLL
name or version.

## Root Cause

The missing runtime provider is Stewie Tweaks 9.95, not vanilla
`FUN_006F36D0`. With Stewie's pathing tweaks enabled, it writes
`TeleportDoorSearch__GetNodeConnections` to vtable cell `0x0106D900`. That
explains why the old hook on the vanilla function recorded zero calls while all
12 mode-0 queries still traversed the graph.

TTW's `TTW_EnableRadioFix 1` changes the branch displacements at `0x004FF2F8`
and `0x004FF300`. The patch removes the player-worldspace exclusion and sends
the affected stations through the expensive mode-0 teleport-door search. The
runtime pattern is 12 synchronous queries per periodic scan, with 11 failures
and one non-source success, costing approximately 42-45 ms at roughly four
scans per second. This is not an allocator or scheduler-yield stall.

The scan-local candidate memo proved that enumeration is not the expensive
part. In active mode it eliminated 1,456 repeated enumerations and replayed
6,253 cached door pointers per scan, but scan time remained 42-44 ms. Every
scan still performed 1,941 Stewie provider expansions. That runtime result
supersedes the earlier candidate-boundary optimization hypothesis.

Stewie's provider prepares door policy and calls accessibility for every accepted
door candidate before constructing the query-local path node:

1. `TeleportDoorData__Setup` resolves lock data, linked-door ownership, rank,
   encounter-zone state, and global data, including temporary game-heap
   allocation/copy when lock data exists.
2. Game `FUN_00502450` receives that data. The current static cost audit proves
   that radio's null actor makes it return immediately, without evaluating its
   actor, ownership, crime, and rank predicates. The preparation is discarded;
   the historical combined bypass measurement does not time these two calls
   separately.

The focused Ghidra audit proves the radio query tuple is exactly:

```text
query mode       = 0      query +0x2098
actor data       = null   query +0x20A0
lock disposition = 3      query +0x20B4
```

For disposition 3, both accessibility success and failure continue with zero
penalty; the minimum-use penalty is also explicitly excluded. The setup output
is consumed only by that accessibility predicate. Therefore both operations
are observationally dead for this exact query tuple, while linked-worldspace
resolution, live door positions, distance/cost pruning, query-node creation,
predecessor links, and output ordering remain required and untouched.

Primary proof:

```text
analysis/ghidra/output/perf/radio_teleport_door_candidate_boundary_audit.txt
analysis/ghidra/output/perf/radio_mode0_discarded_door_policy_audit.txt
analysis/ghidra/output/perf/radio_vanilla_provider_independence_audit.txt
.research/Stewie Tweaks 9.95 Source/code/Features/Inlines/Pathing.cpp
.research/ROOGNVSE/ttw_nvse/ttw_nvse.h
```

## Prior Exact Policy Optimization and Single-Run Validation

`psycho-engine-fixes/src/mods/perf/radio.rs` also scopes an optional bypass
through the actual traversal query. It activates only while a periodic or
cooperatively scheduled radio query is running and the query vtable and three
fields match the tuple above. It supports both the original game provider and
the analyzed Stewie 9.95 provider after exact provider, branch, setup, cleanup,
and game-function signatures match. It has no ROOG dependency and is not a
prerequisite for cooperative scheduling.

Each skipped setup is paired to the immediately following accessibility call
using both the stack-data pointer and door pointer. The accessibility hook
writes the same successful/no-flag result that reaches disposition 3's
zero-penalty continuation. All nonmatching calls execute the original code.
That optional policy optimization caches no path result, door list, node, or
game state. The separate cooperative layer retains only complete float result
generations and stable scalar query keys as described above.

The affected-save validation recorded 134 scans:

```text
[RADIO] Exact mode-0 dead door-policy bypass active: provider=nvse_stewie_tweaks.dll!...
baseline: 68 active candidate-cache scans, average 42756 us
fixed:   134 dead-policy bypass scans, average 5202 us, range 5001-5872 us
[RADIO_SCAN] ... policy=query:12/setup:7746/access:7746 ...
```

The first validated state remained `11` null traversal results and one
non-source result for 12 queries. A later station-set change produced 13
queries, 12 null results, and one non-source result. Setup/access counts matched
on every scan.

Vanilla uses the same dead disposition-3 policy branch but its setup normally
initializes temporary `lockData`. The generic bypass writes that sole cleanup
field (`+0x08`) to null. Ghidra proves all three vanilla cleanup sites call a
43-byte destructor that reads and optionally frees only this field. Unknown or
modified providers fail signature checks and retain their original behavior.

## Required Behavior

Any final fix must preserve all of these properties:

- Every vanilla radio refresh still runs at the original cadence.
- Station availability is recomputed continuously and a result set is exposed
  only after its complete cooperative generation finishes.
- Every mode-0 path distance and failure result comes from the original active
  provider; only its consumption is delayed by one coherent generation.
- Modes 2 and 3 retain their path-chain filtering semantics.
- No engine pointer or partial result generation is reused across scans.
- No global feature disable, station exclusion, or refresh throttle is
  acceptable as the fix.
- The active runtime path provider must be respected rather than bypassed with
  an assumed vanilla implementation.

## Runtime Environment

The reproductions were made in TTW under Proton/Wine with a large mod list.
The latest session used `memory.allocator = 2`, meaning gheap plus Psycho's
scrap-heap replacement.

Relevant latest-log startup facts:

- `psycho-engine-fixes-latest.log:10`: allocator mode 2.
- `psycho-engine-fixes-latest.log:11`: the scrap TLS accessor already had a
  provider from `nvse_stewie_tweaks.dll`; Psycho replaced that provider.
- `psycho-engine-fixes-latest.log:179-186`: radio query, traversal, static
  expansion entry, and station mode profiling hooks initialized and enabled.

The latest runtime log is the symlink:

```text
psycho-engine-fixes/psycho-engine-fixes-latest.log
```

At the time of this report it resolves to:

```text
/data/storage0/Games/FalloutNV_TTW/FalloutNV/psycho-engine-fixes-latest.log
```

## Engine Call Chain

The periodic radio path is:

```text
0x00833D86 -> 0x004FF1A0  periodic nearby-radio scan
0x004FF397 -> 0x006D4EB0  mode-0 radio distance wrapper
0x006D4F01 -> 0x006D4D20  generic path-query wrapper
0x006D4DBF -> 0x006F34E0  query setup and dispatch
0x006F36A0 -> 0x006F3D00  source seed insertion
0x006F36B5 -> 0x006F3D90  goal search and result owner
0x006F3DC0 -> 0x006F3FB0  graph traversal
```

Other radio query callsites are:

```text
0x004FF4C6 -> 0x006D4D20  station mode 2, query mode 1
0x004FF645 -> 0x006D4D20  station mode 3, query mode 2
```

The radio query vtable is statically located at `0x0106D8FC`:

```text
+0x00 -> 0x006F3430  destructor/provider entry
+0x04 -> 0x006F36D0  neighbor expansion provider
+0x08 -> 0x006F3B00  goal predicate
```

Source: `radio_one_to_many_path_search_contract_audit.txt:1862-1866`.

## Stable Runtime Reproduction

### Original hot-path attribution

The first detailed profiling session produced 68 consecutive slow scans. The
pattern was stable:

```text
station_modes=15/23/2/4/0+0
query0=12
query1=0
query2=0
traversal=12
static expansion hook calls=0
residual_us approximately 57-73
```

Representative final scan:

```text
total_us=42278
query0=12/42212/8382
traversal=12/41581/8332
expansion=0/0/0
residual_us=66
```

Source: the previous runtime log recorded in the investigation summary, ending
with sequence 68 at approximately `2026-07-16T15:44:16Z`.

The scan runs approximately four times per second. Each scan costs roughly
`41-45 ms`, causing the recurring visible frame-time spike.

The twelve mode-0 queries consume approximately 99.8 percent of the scan. The
traversal calls consume approximately 98 percent. Station enumeration, mode 1,
modes 2/3, and residual radio logic are not material in this reproduction.

### Latest branch-classification session

The diagnostic build intentionally made no performance change. It recorded the
queue and return state around otherwise vanilla traversal.

Across all 49 recorded scans, the branch pattern was identical:

```text
branch=m0:12/vtable:12/empty:0/missing:0/first:12/goal:0/parent0:12/result0:11/source:0/other:1
```

Representative scan from `psycho-engine-fixes-latest.log:364`:

```text
total_us=45745
query0=12/45672/9333
traversal=12/45055/9283
branch=m0:12/vtable:12/empty:0/missing:0/first:12/goal:0/parent0:12/result0:11/source:0/other:1
expansion=0/0/0
residual_us=73
```

The same branch values continue through
`psycho-engine-fixes-latest.log:443`.

This proves the following for every scan in that session:

- All 12 traversals are mode 0.
- All 12 query objects have vptr `0x0106D8FC`.
- None begins with an empty priority queue.
- All 12 have a non-null stored source at query `+0x2050`.
- The first queued node is that stored source in all 12 cases.
- None of those source descriptors matches the statically decoded mode-0 goal
  fields.
- All 12 source nodes have a null parent at `+0x24` before traversal.
- Raw `FUN_006F3FB0` returns null for 11 queries.
- Raw `FUN_006F3FB0` returns a non-source node for one query.
- Raw traversal never returns the stored source.

The latest scan cost remains roughly `42-45 ms`. This was expected because the
build was diagnostic-only.

## Disproven Immediate-Goal Hypothesis

The earlier static audit was created to test this hypothesis:

> The first source node immediately satisfies the goal, and the recurring cost
> is redundant traversal scope setup/cleanup.

The audit file header still contains the older premise that expansion executes
zero times:

```text
analysis/ghidra/output/perf/radio_mode0_immediate_goal_scope_cost_audit.txt:3-8
```

That premise is superseded by the later branch telemetry. It must not be treated
as a proven runtime fact.

The proposed fast path would have:

1. Popped the source.
2. Written it to query `+0x204C` and `+0x2048`.
3. Returned it without running traversal.

That patch is invalid. The runtime evidence proves `goal:0` for all sources,
`result0:11`, `source:0`, and `other:1`. The fast path would convert 11 genuine
failures into successes and replace the one real non-source result with the
wrong source result. It would corrupt station availability and distance.

## Traversal Contract

`FUN_006F3FB0` performs these relevant operations:

1. Constructs a 20-byte traversal-local output scope with `FUN_006F45C0`.
2. Saves the previous query `+0x204C` value.
3. Pops the first node from the 20-bucket priority queue with `FUN_006F46F0`.
4. Writes the popped node to query `+0x204C`.
5. Writes the current/best node to query `+0x2048`.
6. Calls vtable slot `+0x08` as the goal predicate.
7. On a predicate miss, clears the output scope and calls vtable slot `+0x04`
   to produce query-specific neighbor nodes.
8. Sets predecessor links, inserts returned nodes into the query's priority
   queue, and continues until success or queue exhaustion.

Sources:

- `radio_mode0_immediate_goal_scope_cost_audit.txt:427-515`
- `radio_mode0_immediate_goal_scope_cost_audit.txt:1665-1831`

The priority queue pop at `FUN_006F46F0`:

- Scans 20 bucket heads.
- Removes the first node.
- Repairs the successor backlink.
- Clears popped-node links `+0x28` and `+0x2C`.

Source: `radio_mode0_immediate_goal_scope_cost_audit.txt:694-724`.

## Goal Predicate Contract

For modes other than 3, static `FUN_006F3B00` compares:

```text
node byte +0x08 == query byte +0x208C
node dword +0x10 == query dword +0x2094
node dword +0x0C == query dword +0x2090
```

Source: `radio_mode0_immediate_goal_scope_cost_audit.txt:370-412` and
`radio_one_to_many_path_search_contract_audit.txt:2132-2174`.

The current `TraversalProbe` mirrors these comparisons. Runtime recorded zero
matches for all 12 source nodes on every latest-session scan.

## Traversal Scope Contract

The traversal scope itself is well understood:

- `FUN_006F45C0` constructs the local scope.
- `FUN_00401020` is a 10-byte pure getter returning the memory-heap singleton
  at `DAT_011F6238`.
- `FUN_00AA42E0` gets or creates the current thread's scrap heap in vanilla.
- `FUN_006B3EB0(0, 0)` zeros scope fields `+4`, `+8`, and `+0x0C`; it does not
  allocate for zero sizes.
- Scope field `+0x10` receives the scrap-heap pointer.
- `FUN_006F4690` and base destructor `FUN_006F4640` call `FUN_008454F0(1)`.
- `FUN_008454F0` only destroys or frees storage when scope `+4` is non-null.
- On a path that never populates the output vector, cleanup has no allocation,
  ownership-transfer, lock, or task-stack side effect.
- `FS:[0]` manipulation is MSVC exception registration, not game-state TLS.

Sources:

- `radio_mode0_immediate_goal_scope_cost_audit.txt:603-674`
- `radio_mode0_immediate_goal_scope_cost_audit.txt:739-815`
- `radio_mode0_immediate_goal_scope_cost_audit.txt:926-1053`
- `analysis/ghidra/output/memory/bulletproof_alloc_paths.txt:115-137`

This contract made a scope bypass plausible only under the now-disproven
immediate-goal branch. It does not authorize bypassing legitimate expansion.

## Static Vanilla Expansion Contract

Static vtable slot `+0x04`, `FUN_006F36D0`, is not a query-independent adjacency
lookup. It performs query-specific node relaxation.

Its observed contract is:

1. Clear the caller-owned output vector.
2. Select candidate collection behavior from the current node descriptor.
3. Populate or update query state around `query + 0x20A4`.
4. Enumerate candidates.
5. Reject invalid candidates.
6. Apply mode-specific exterior/interior and world/cell filtering.
7. Apply query behavior/filter checks and penalties.
8. Obtain candidate positions through virtual calls.
9. Calculate geometric edge cost.
10. Apply query-specific accumulated-cost and maximum-cost pruning.
11. Call `FUN_006F3E30` against the current query's private node table.
12. Create or relax query-owned nodes.
13. Fill node descriptor, candidate object, transition metadata, and cost.
14. Return those query-owned node pointers through the output vector.

Sources:

- `radio_one_to_many_path_search_contract_audit.txt:527-695`
- `radio_one_to_many_path_search_contract_audit.txt:1912-2080`

Important fields and operations include:

- Query mode at `+0x2098`.
- Maximum cost at `+0x209C`.
- Query-specific filter/context at `+0x20A0`.
- Behavior at `+0x20B4`.
- Current node accumulated cost at node `+0x00`.
- Query-private node table insertion/relaxation through `FUN_006F3E30`.
- Returned node parent later written by traversal at node `+0x24`.

Cached expansion output pointers cannot be transferred between queries. They
belong to the originating query's node table and carry query-specific state.

## Expansion Attribution Contradiction

The static entry hook on `0x006F36D0` recorded zero calls, but latest branch
telemetry proves that the source predicate misses all 12 times and vanilla
traversal returns 11 failures plus one non-source success.

Given the audited traversal control flow, a source predicate miss proceeds to
the virtual slot `+0x04` expansion dispatch before the next queue pop. Therefore
`expansion=0` cannot safely be interpreted as "no expansion happened."

What is proven:

- The query object vptr remains `0x0106D8FC`.
- The statically addressed `0x006F36D0` entry hook does not observe the runtime
  work.
- Traversal nevertheless follows outcomes that require the virtual expansion
  path.

What is not proven:

- The runtime value currently stored in vtable cell `0x0106D900`.
- Whether another component rewrites that cell.
- Whether an earlier detour causes the virtual dispatch to bypass the static
  entry hook.
- Whether the static expansion profiler's physical ABI or hook placement is
  incorrect.
- Which implementation performs the active expansion work.
- Whether the active implementation exactly preserves vanilla expansion
  semantics.

Do not attribute the contradiction to any specific mod without direct evidence.
The startup log's Stewie Tweaks provider message concerns the scrap TLS accessor
`0x00AA42E0`, not the radio query vtable.

## Result and Ownership Contract

`FUN_006F3D90` owns traversal result handling:

- Non-null traversal return marks query success.
- Null traversal return with its fallback flag set may still use query
  `+0x2048` for best-so-far result extraction while returning false.
- If a node is selected, `FUN_006F4230` copies its predecessor chain into the
  result object.

Source: `radio_mode0_immediate_goal_scope_cost_audit.txt:317-351`.

`FUN_006F4230`:

- Counts the chain through node `+0x24`.
- Resizes result positions to the node count.
- Resizes transition/edge metadata to node count minus one.
- Copies node position and transition fields.

Source: `radio_mode0_immediate_goal_scope_cost_audit.txt:544-585`.

The query retains ownership of search nodes. `FUN_006F4230` copies data; it does
not transfer node ownership. Query destruction still runs through
`FUN_006F3460` and `FUN_006F3C80`.

Sources:

- `radio_mode0_immediate_goal_scope_cost_audit.txt:1269-1362`
- `radio_mode0_immediate_goal_scope_cost_audit.txt:1483-1532`

Mode-0 radio distance is then recomputed by `FUN_006F49C0` from the copied path,
endpoint transforms, and transition geometry. It is not simply the traversal
node's accumulated cost.

Source: `radio_mode0_immediate_goal_scope_cost_audit.txt:1364-1427`.

## Rejected Approaches

### Unbounded or TTL result cache

Rejected and removed. The engine graph identity, generation, and invalidation
contract is incomplete. An arbitrary TTL can serve multiple stale refreshes
and alter station availability or distance without a bounded recomputation
contract. This is distinct from the implemented double buffer: every radio
refresh either collects a fresh full generation or allows one already in
flight to finish, and only a complete generation is published.

Removed elements included whole-result TTL caching, pointer snapshots, replay,
loading suppression, and related configuration.

### Refresh throttling

Rejected. It changes vanilla update cadence and serves stale state.

### `Sleep(0)` suppression

Implemented as a radio-scoped experiment and then removed. Runtime recorded
`suppressed_yields=0`. The traversal's 50-node yield path was not responsible
for this reproduction.

### Immediate-goal source bypass

Rejected by the latest branch telemetry. All source goals miss, 11 traversals
return null, and one returns a different node.

### Reverse one-to-many shortest-path tree

Rejected. Radio mode-0 searches are station-source to player-goal. Reversing
them requires proof that adjacency, filters, weights, transition metadata, and
the active runtime provider are reversible. That proof does not exist.

Modes 2 and 3 also consume selected predecessor chains, so a generic batching
replacement must preserve chain-domain semantics.

Source: `radio_one_to_many_path_search_contract_audit.txt`.

### Reusing expansion output pointers

Rejected. Expansion returns nodes owned by the current query's private node
table. They include query-specific accumulated cost, filters, descriptors, and
transition metadata.

### Sharing candidate enumeration

Rejected by runtime timing. The boundary and replay equivalence were valid,
but eliminating 1,456 repeated enumerations and replaying 6,253 door pointers
did not reduce the 42-44 ms scan. The implementation was removed. This result
isolated the cost to per-door provider work after enumeration.

### Direct geometric distance

Rejected. `FUN_006F49C0` consumes the extracted path and transition geometry.
Straight-line or node-cost substitution would change exact results.

### Reusing one query object

Rejected. Constructor, query-private node state, queue state, and destruction
have no proven complete reset contract.

### Parallel traversal

The earlier generic proposal was rejected because engine thread safety,
shared candidate state, TLS/scrap state, and arbitrary provider reentrancy were
unproven. The 2026-07-23 tasklet research resolves serial worker execution at
the game-owned provider ABI: the engine sets the query's tasklet-mode byte
before invoking virtual provider slot `+0x04`. The implementation uses an
initialized engine tasklet thread, native group completion, and game-thread
endpoint ownership. It still never overlaps two provider calls.

### Failed-result extraction micro-optimization

Potentially possible only at the radio callsite because the mode-0 wrapper
returns a failure sentinel when the generic query returns false. It cannot fix
the hitch: all query setup, result extraction, and teardown outside traversal
total only about `0.6 ms` per scan.

### Globally disabling mode-0 radio checks

Rejected. It would remove intended station behavior rather than fix it.

## Separate Post-Load Result

The radio hitch is independent of the post-load frame spike investigation.

The successful-load reconciliation prepass calls only:

```text
FUN_00455490(DAT_011DEA10)
```

after successful `FUN_00850760`. It does not invoke the unsafe broader
`FUN_0086F670` frame-global reset sequence.

Latest timing:

```text
psycho-engine-fixes-latest.log:361
[POST_LOAD] reconciliation_prepass_us=193
```

Earlier sessions measured approximately `216-279 us`. The previous first-frame
post-load spike was absent. This fix should remain separate from radio work.

## Previous Code State (superseded)

At the time of the branch-classification session, the implementation was:

```text
psycho-engine-fixes/src/mods/perf/radio.rs
```

That diagnostic version:

- Installs only when hitch profiling is enabled.
- Wraps the periodic call at `0x00833D86` to create a scan-local TLS scope.
- Profiles `FUN_006D4D20`, `FUN_006F3FB0`, static `FUN_006F36D0`, and station
  mode `FUN_0056B210`.
- Records station mode distribution, query timings, traversal timings, static
  expansion timings, and branch classification.
- Leaves every query and scan result vanilla.
- Does not cache, throttle, suppress, bypass, or modify path results.

The branch classifier reads:

```text
query +0x2098  mode
query +0x2050  stored source
query +0x1FF8..+0x2044  priority bucket heads
query +0x208C/+0x2090/+0x2094  goal descriptor
node +0x08/+0x0C/+0x10  node descriptor
node +0x24  predecessor
```

No attempted runtime-provider instrumentation patch was applied. The
`apply_patch` operation was aborted before changing files.

The supported build passed after branch classification was added:

```text
cargo fmt --all -- --check
git diff --check
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

## Current Implementation Ownership and Validation

The executable contract was reconfirmed against `FalloutNV.exe` with SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The existing focused output under `analysis/ghidra/output/perf/` remains the
durable disassembly/decompilation evidence; the 2026-07-22 radare2 session
reconfirmed the same addresses and call shapes in the current executable. The
2026-07-23 radare2 session additionally proved the group priority layout,
enqueue bucket selection, and ascending dispatcher order used by the final
scheduler correction.

### Game-owned empty-station fast path and worker isolation

Fresh runtime evidence from the 2026-07-23 15:31 build reported:

```text
requests=12 cadence/spacing=468/39ms scan_us=Some(58)
results=12 jobs=12 worker_total/max=8050/1654us
game_thread_prep_total/max=43/4us latency_ms=Some(497)
```

The `8,050 us` value is the sum of stopwatch wall durations around 12 separate
worker calls to `0x006D4EB0` over 497 ms. It is not one 8 ms frame stall and is
not a CPU-time measurement. The log field is now named
`worker_wall_total/max` to make this distinction explicit.

The same executable contains a separate game-thread cost outside the 58 us
scanner measurement. `FUN_00833D00` iterates the registered station list and
calls the 5,097-byte `FalloutRadio::UpdateStation` routine at `0x008341B4 ->
0x00834260` for every non-null wrapper. Radare2 reconfirmed the exact
provider-independent early-return branch in `FUN_00834260`:

1. `0x008342F7` compares the wrapper against current station
   `0x011DD42C`.
2. `0x00834363` rejects the fast path while radio-list reset flag
   `0x011DD436` is set.
3. For an inactive entry, `0x0083437B` passes the embedded list at wrapper
   `+0x1C` to `FUN_008256D0`.
4. `FUN_008256D0` returns true only when both list words are null: wrapper
   `+0x1C` at `0x008256E5` and wrapper `+0x20` at `0x008256DC`.
5. That case performs only profiler-scope closure and returns at
   `0x00834397`; it does not mutate station, audio, UI, or global radio state.

The callsite bridge now applies that predicate before entering the large
routine. Current stations, entries with any audio node, list-reset operation,
and every ambiguous case still call the original function. The bridge verifies
the original relative call plus its prefix and suffix before installation.
Null wrappers and wrappers with a null station form also retain the original
immediate-return behavior. This removes only work on proven no-effect branches
and therefore does not change station timing or mechanics.

This intervention is owned entirely by `FalloutNV.exe`. It does not inspect,
patch, call into, or identify Stewie Tweaks or any other mod. The Stewie source
under `.research/` was used only to compare the active opaque path provider.
The production station fast path remains valid with vanilla or any replacement
provider because it is downstream of provider dispatch.

Unavoidable provider queries remain opaque. They now execute at Win32 idle
priority as well as native tasklet queue priority 63, with checked restoration
of the shared worker's previous priority. Lowering priority may increase the
reported wall duration when a query is preempted; that is expected and is not a
regression. The intended result is that radio work yields CPU time to game and
render threads while retaining complete-generation publication and original
provider results.

Static proof:

- `0x00833D86 -> 0x004FF1A0` owns caller-local output lists which
  `FUN_00833D00` iterates immediately after return.
- `0x008341B4 -> 0x00834260` owns the periodic per-entry update call. The
  inactive/empty predicate above is an exact precondition for the original
  function's side-effect-free early return.
- `0x00440DA0` is a pure form-flag read and `0x0083C820` is a pure nested-list
  getter. These are the only non-profiler calls skipped before the empty
  inactive branch.
- At `0x004FF397`, outer `EBP-0x24` is the station reference and `EBP+0x08`
  is the current reference. The cdecl argument stack is station location,
  current location, radius, null actor data, and disposition 3.
- `0x006D4EB0` returns a float in x87 `ST(0)` and uses the value at
  `0x01016970` on failure.
- `0x006DCD70` constructs a 0x28-byte `PathingLocation` from a live reference;
  `0x004FF7E0` is its destructor. TESForm FormID is at `+0x0C`, and the cdecl
  runtime helper `0x004839C0` resolves a FormID back to a live form.
- `0x006D4EB0` dispatches through the current path-query provider, so calling
  that original wrapper preserves provider replacement rather than assuming
  vanilla `0x006F36D0`.

Source ownership:

- `psycho-engine-fixes/src/mods/perf/radio.rs` owns the verified callsite
  bridges, empty inactive-station predicate, generation state machine,
  endpoint preparation, native tasklet adapter, group lifetime, original
  fallbacks, optional exact policy fast path, and tests.
- `psycho-engine-fixes/src/events.rs` owns the core event IDs for
  `DeferredInit`, `OnFramePresent`, `PreLoadGame`, `ExitToMainMenu`, and
  `NewGame`.
- `psycho-engine-fixes-helper/src/events.rs` forwards those xNVSE messages
  through the late-bound core ABI. The helper never loads or initializes the
  core DLL.
- `libpsycho/src/os/windows/winapi.rs` owns the non-send scoped current-thread
  priority guard. It records the exact prior Win32 priority and supports
  explicit checked restoration plus a final best-effort restoration in
  `Drop`.

Startup first verifies the periodic and mode-0 relative call targets plus the
surrounding mode-0 bytes. The mode-0 bridge is installed before the periodic
scope hook; if the latter cannot install, the bridge sees no cooperative scope
and calls the original wrapper. Deferred initialization separately verifies
the current provider target is executable, verifies the tasklet API, group
priority layout, enqueue bucket calculation, and dispatcher scan order before
enabling worker submission, then installs the optional exact policy hooks.
Provider identity and version are not consulted.

The bridge's release codegen was inspected in the i686 DLL. It copies the five
original cdecl arguments, adds outer `EBP` as a sixth internal argument, calls
the Rust body, removes exactly 24 bytes, and returns without disturbing the
x87 float. The original game caller still removes its own 20 argument bytes.

Focused validation completed on 2026-07-23:

```text
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes radio::tests
  18 passed
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes-helper \
  world_lifetime_messages_reach_the_core_barrier
  1 passed
```

The complete affected suites and supported release build also passed:

```text
cargo test --target i686-pc-windows-gnu -p libpsycho --lib
  9 passed
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib
  36 passed
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes-helper --lib
  12 passed
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
  finished release profile
```

Post-build i686 disassembly confirms that the tasklet `ready`, `execute`, and
`finish` callbacks return with plain `RET`, `execute` receives the task pointer
in `ECX`, and the emitted four-entry vtable points to those callbacks in the
verified order. The release PE contains only the two-word `RADIO_TASKLET` lazy
owner rather than eager task storage. The layout test confirms that the
deferred constructor produces the verified task header, zeroed queue/group
fields, readiness byte 1 at `+0x0C`, one 0x70-byte prepared-query slot, and a
total 0x8c-byte task object. The final release PE also contains the direct
`mov dword [group + 0x30], 0x3f` after successful activation, calls the scoped
priority setter before `0x006D4EB0`, and calls checked priority restoration
before the tasklet callback's plain `RET`. `radio_tasklet_execute` passes enum
discriminant 3 and the priority helper's release jump table selects
`0xFFFFFFF1`, Win32 `THREAD_PRIORITY_IDLE`.

The station-update bridge release body returns directly only for a null
wrapper, null station form, or the exact inactive/not-resetting predicate with
both `[wrapper+0x1C]` and `[wrapper+0x20]` zero. Every other branch is a tail
jump to `0x00834260`, preserving the original cdecl caller cleanup. Provider
validation compiles to `VirtualQuery` plus committed, accessible, executable
page checks; it contains no provider module or version comparison. Release DLL
SHA-256:

```text
361bf55d7f80be9a9b8195ef67db8e33699c5d3974ea9e4009e692af8af89bdd
```

The tests reject partial publication, loss of a prior snapshot after a failed
generation, duplicate work, release of more than one overdue query per frame,
native worker work before its cadence slot, burst-sized task storage,
incorrect `PathingLocation` or tasklet layouts, missing world-lifetime event
forwarding, eager tasklet storage, pre-Deferred lifetime handling, use of any
tasklet bucket other than 63, failure to restore the worker's prior Win32
priority, and diagnostic aggregation regressions. Required gameplay acceptance
remains:

1. Startup reports `Native tasklet query backend active` for the installed
   provider, followed by
   `Native paced tasklet generation verified` with a non-main worker thread
   ID.
2. Existing and newly entered radio stations appear and disappear correctly,
   allowing for one refresh of detection latency.
3. Loading, fast travel, save load, interiors/exteriors, and menu transitions
   do not retain invalid results or crash.
4. Frame-time telemetry no longer shows the roughly 6 ms / 250 ms radio
   sawtooth. The first tasklet report should retain the expected query count,
   approximately the same aggregate provider CPU time off-thread, and a
   generation latency near the cadence rather than the prior 80 ms burst.
5. Station count and the success/failure distribution match the preceding
   exact-policy run.
6. A null or non-executable replacement of the provider slot fails closed
   before worker submission.

## Crash Logger Note

The latest `CrashLogger.log` contains only:

```text
Exception: EXCEPTION_ACCESS_VIOLATION (C0000005)
```

There is no stack or module attribution. It may be a forced-exit artifact, but
the evidence is insufficient to classify it. Do not attribute it to radio or
the allocator from this truncated log.

## Previous Knowledge Gaps

The earlier report required at least one of these contracts to be proven:

1. Exact active runtime target and implementation of query vtable slot `+0x04`
   at `0x0106D900`.
2. A query-independent candidate enumeration boundary that can be shared within
   one fresh scan while retaining all dynamic filters and node creation.
3. Edge reversibility, cost symmetry, filter symmetry, and transition-chain
   equivalence sufficient for a player-rooted one-to-many traversal.
4. A complete graph generation/invalidation contract sufficient for safe
   longer-lived caching.
5. A direct engine API that tests the current interior/exterior connectivity
   domain with exactly the same semantics as mode-0 traversal.

The provider-boundary follow-up resolved items 1 and 2, but runtime proved item
2 is not a useful performance boundary. The optional CPU optimization uses the
exact disposition-3 dead-policy contract. Cooperative scheduling treats the
provider as opaque and does not depend on the still-unproven broader contracts
in items 3-5.

## Previous Next Research Direction

Do not repeat the TTL cache, yield suppression, immediate-goal, or generic
one-to-many experiments.

The prescribed static/runtime-provider work was:

1. Resolve the actual callable target used by vtable cell `0x0106D900` in the
   affected runtime.
2. Identify why the static `0x006F36D0` entry hook sees zero calls despite the
   mandatory virtual expansion branch.
3. Analyze the active provider implementation and ownership contract.
4. Locate a pure candidate-enumeration or connectivity-index boundary, if one
   exists.
5. Implement a fresh scan-local optimization only after proving output and
   invalidation equivalence.
6. Keep every failed guard on a complete vanilla fallback.

Steps 1-5 were completed at the candidate boundary, and runtime disproved that
optimization. The discarded-policy audit then identified the next exact
boundary. Runtime validation still must confirm unchanged station counts and
success/failure distribution while measuring whether scan time drops.

## Profiling output cost

Hitch profiling still records every slow scan in TLS, but it no longer submits
one file-flushed log record per scan. Slow scans are accumulated into a
one-second window and one `[RADIO_SCAN]` record reports the window's count,
average/maximum total and residual time, summed branch/provider counters, and
summed/max query and traversal timings. The first slow scan starts the window;
no timer or aggregation runs when hitch profiling is disabled.

This changes diagnostics only. Scan cadence, query inputs, station results,
door-policy guards, and fallback behavior are untouched. The aggregation is
important because the crash-safe logger flushes every record and the observed
radio cadence can otherwise create up to four diagnostic file flushes per
second while investigating a frame-pacing problem.

## Evidence Inventory

Primary runtime evidence:

```text
psycho-engine-fixes/psycho-engine-fixes-latest.log
psycho-engine-fixes/CrashLogger.log
```

Primary focused Ghidra output:

```text
analysis/ghidra/output/perf/radio_mode0_immediate_goal_scope_cost_audit.txt
analysis/ghidra/output/perf/radio_one_to_many_path_search_contract_audit.txt
analysis/ghidra/output/perf/radio_path_query_cache_key_contract.txt
analysis/ghidra/output/perf/radio_path_graph_generation_invalidation_audit.txt
analysis/ghidra/output/perf/radio_path_geometry_identity_followup.txt
analysis/ghidra/output/perf/radio_path_component_identity_contract.txt
analysis/ghidra/output/perf/radio_geometry_cache_contract_audit.txt
analysis/ghidra/output/perf/radio_signal_scan_fix_surface_audit.txt
analysis/ghidra/output/perf/radio_geometry_invalidation_followup.txt
analysis/ghidra/output/crash/crash_0069083a_navmesh_tasklet_audit.txt
analysis/ghidra/output/memory/scrap_heap_shared_identity_worker_audit.txt
```

The 2026-07-23 radare2 MCP session reconfirmed the tasklet manager call chain,
group lifecycle, callback layout, and query tasklet-awareness directly in the
current executable. The Ghidra files above remain the durable raw evidence for
the already-established pathing and worker call chains; they were not
regenerated or rewritten.

Related post-load evidence:

```text
analysis/ghidra/output/perf/phase10_post_load_spike_deep_audit.txt
psycho-engine-fixes/src/mods/perf/post_load.rs
```

Focused Ghidra script that generated the latest static audit:

```text
analysis/ghidra/scripts/radio_mode0_immediate_goal_scope_cost_audit.py
```

Current implementation:

```text
psycho-engine-fixes/src/mods/perf/radio.rs
```

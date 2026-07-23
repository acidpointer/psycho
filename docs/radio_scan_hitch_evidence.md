# Fallout New Vegas Radio Scan Hitch Evidence

## Status

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

Stewie's provider performs two expensive policy operations for every accepted
door candidate before constructing the query-local path node:

1. `TeleportDoorData__Setup` resolves lock data, linked-door ownership, rank,
   encounter-zone state, and global data, including temporary game-heap
   allocation/copy when lock data exists.
2. Game `FUN_00502450` evaluates door accessibility using actor, ownership,
   crime, and rank predicates.

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
0x004FF4C6 -> 0x006D4D20  mode 2
0x004FF645 -> 0x006D4D20  mode 3
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

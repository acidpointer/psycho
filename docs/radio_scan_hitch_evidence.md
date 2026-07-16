# Fallout New Vegas Radio Scan Hitch Evidence

## Status

This report records the radio hitch investigation on 2026-07-16. Runtime has
now disproved both the scheduler-yield and candidate-enumeration fixes. The
current root cause is repeated door-policy work inside Stewie Tweaks' active
teleport-door provider. Runtime validation confirms the replacement reduced
the scan from a 42.756 ms baseline average to 5.202 ms without changing the
observed station/path result distribution.

The latest branch telemetry disproved the proposed mode-0 immediate-goal fast
path. Do not implement that fast path from the earlier Ghidra audit hypothesis.

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

## Implemented Fix and Single-Run Validation

`psycho-engine-fixes/src/mods/perf/radio.rs` now scopes the bypass through the
actual traversal query. It activates only while the periodic radio scan is
running and the query vtable and three fields match the tuple above. It supports
both the original game provider and Stewie 9.95 after exact provider, branch,
setup, cleanup, and game-function signatures match. It has no ROOG dependency.

Each skipped setup is paired to the immediately following accessibility call
using both the stack-data pointer and door pointer. The accessibility hook
writes the same successful/no-flag result that reaches disposition 3's
zero-penalty continuation. All nonmatching calls execute the original code.
No path result, door list, node, or game state is cached.

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
- Station availability is recomputed from current game state.
- Mode-0 path distance and failure behavior remain exact.
- Modes 2 and 3 retain their path-chain filtering semantics.
- No result is reused across scans without a complete engine invalidation
  contract.
- No global feature disable, station exclusion, refresh throttle, or stale
  result fallback is acceptable as the fix.
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

### Cross-scan result cache

Rejected and removed. The engine graph identity, generation, and invalidation
contract is incomplete. A TTL still serves stale gameplay state and can alter
station availability or distance.

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

Rejected. Engine thread safety, shared candidate state, TLS/scrap state, and
query provider reentrancy are unproven.

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
2 is not a useful performance boundary. The current implementation instead
uses the exact disposition-3 dead-policy contract and does not depend on the
still-unproven broader contracts in items 3-5.

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
```

Related post-load evidence:

```text
analysis/ghidra/output/perf/phase10_post_load_spike_deep_audit.txt
psycho-engine-fixes/src/mods/perf/post_load.rs
```

Focused Ghidra script that generated the latest static audit:

```text
analysis/ghidra/scripts/radio_mode0_immediate_goal_scope_cost_audit.py
```

Current runtime instrumentation:

```text
psycho-engine-fixes/src/mods/perf/radio.rs
```

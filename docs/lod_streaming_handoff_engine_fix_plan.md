# LOD streaming and handoff engine-fix plan

## Goal

Ship one allocator-independent LOD subsystem in `psycho-engine-fixes` with two
separately installable but complementary changes:

1. Request terrain, object, and tree LOD before the vanilla visibility boundary
   and retain loaded blocks across small camera reversals.
2. Replace the broken lifetime-total handoff gate with current-generation,
   reference-identity readiness.

The implementation must keep the native LOD task constructors, dependency
graph, IO manager, completion queue, main-thread publication, scene roots, and
fade/retirement phase. It must not add a custom loading thread, uncap the
global completed-task budget, or patch generic NiLOD, NiRangeLODData,
NiScreenLODData, NiSwitchNode, or BSFade behavior.

The xNVSE helper remains optional and does not install, own, or initialize the
fix.

## Implementation status

The initial implementation is present and has entered runtime stress
validation. The three original Ghidra audits closed the LOD producer,
scheduler, task ABI, reference publication, counter lifetime, cell transition,
and generic scene-graph virtual gaps needed for that implementation.

The first high-speed stress test exposed a pre-existing BSTree destruction
lifetime failure and an independent handoff-ledger resynchronization gap. The
three crash audits prove the native SpeedTree clone-lifecycle race, the exact
unlocked owner-vector and shared-refcount mutations, and the complete scalar
destruction/free edge.

The crash fix is now implemented in the core DLL. Clone construction at
`0x00B036D0` and scalar destruction at `0x00666910` are serialized by the
engine's reentrant SpeedTree critical section at `0x011F8BC4`. The destructor
validates clone membership under that lock and skips the complete scalar
destructor, including physical free, if the object is already corrupt. Hook
installation is transactional and prefetch remains vanilla if the lifetime
hooks cannot be owned. The supported i686 release build passes.

The later priority and two-worker performance extension exposed a separate
constructor ABI defect in Psycho's hooks during save-load terrain creation.
The native object, tree, and terrain task constructors return the constructed
task in `EAX`; their callers publish that exact return value into an intrusive
holder and immediately increment `task + 0x08`. Psycho originally declared
the three detours as returning `void`, so the priority call was allowed to
replace `EAX` with an incidental value. The save-load crash at `0x0040B467`
was the holder attempting `InterlockedIncrement` through that corrupted
return value. The hook types and implementations now preserve and return the
constructor result after applying priority. Priority remains enabled at the
proven state-zero key-update point, and both IO workers remain enabled.

The next save-load stress crash is a distinct `C0000417` contract failure.
The final coverage audit proves that no SpeedTree constructor, scalar
destructor, owner insertion, or owner erase path remains outside the lifetime
lock. The remaining historical worker signature reaches the secure CRT read
at `0x00ECB144` from `BSFile` open-state initialization at `0x00AFF490`.
That initializer allocates an optional file cache and passes it to the raw
read at `0x00AA1570` without checking for a null allocation. The two-worker
configuration raises concurrent cache pressure but does not invalidate file
ownership.

The parallel-IO transaction now replaces that initializer with the same
native state machine plus the missing allocation branch. Successful caches
and whole-file preloads are unchanged. If only the optional cache allocation
fails, the hook sets cache capacity to zero and retains the valid `FILE*`;
the audited native buffered-read path then performs direct reads. Loading,
priority, and both workers remain active. The transaction will not publish
the worker-count patch unless this fallback and all three TLS-capacity hooks
are owned together.

The first non-crashing two-worker build exposed a distant-geometry regression:
terrain, object, and tree LOD tasks were assigned priority `255`. The final
queue audit proves that the engine orders each native task chain in ascending
packed-key order and workers consume the first entry, so lower numeric
priority values execute first. Blocking load drains also partition the queue
into four buckets per priority and reject a task whose decoded priority lies
above the active load boundary. `255` was therefore an out-of-contract
deprioritization, not a boost. Psycho now assigns native priority `0`, keeping
the priority feature and dependency propagation active while restoring LOD
eligibility during load and normal worker service.

The following exterior stress crash exposed the remaining generic-worker
contract. `ExteriorCellLoaderTask` publishes its active cell through the
process-global pointer at `0x011C3F30`. Two instances could overlap on the two
workers, allowing one task to clear that pointer after another task's null
check but before its reload at `0x004686F4`. Psycho now serializes only the
`ExteriorCellLoaderTask` execute method at `0x00527CB0`. Terrain, object, tree,
and other safe IO work still use both workers.

Release acceptance remains blocked on runtime stress validation and the
separate handoff-ledger resynchronization work. Runtime tuning is no longer
the only remaining work.

## Evidence baseline

### Streaming demand

`BGSTerrainManager` loads `Data\LODSettings\%s.DLODSettings` during
construction. If the settings object is absent, the distant manager remains
inert and Psycho must preserve that behavior.

The camera/worldspace update owner at `0x006FCA90` dispatches:

- terrain updates through `0x006FDAA0`;
- distant object updates through `0x006FDFC0`;
- distant tree updates through `0x006FE330`;
- worldspace reset through `0x006FCE00` and `0x00572160`;
- the post-update phase through `0x006FCDB0` and `0x006FEA70`.

Object and tree blocks use the same predicate to create and release their
native block objects. There is no prefetch boundary or retention hysteresis:

- object demand is `0x006FE620`, using `fBlockLoadDistance` at `0x011D877C`;
- object quality selection is `0x006FE6D0`, using the separate
  `fBlockLoadDistanceLow` at `0x011D8724`;
- tree demand is `0x006FE780`, using `fTreeLoadDistance` at `0x011D8788`;
- terrain demand is `0x006FE550`, using the per-node threshold at `+0x44`.

The shared metric at `0x006FE830` is a two-dimensional point-to-square
distance. A block requested at the vanilla boundary must still pass through
dependency loading, IO completion, and main-thread publication. This explains
late appearance without requiring a slow or broken global scheduler.

### Native task pipeline

Terrain, object, and tree producers construct their native block and task,
publish the intrusive task pointer, and invoke task slot 8. The proven phase
sequence is:

```text
LOD producer
  -> task slot 8: create dependencies
  -> task slot 10: dependency-ready scheduling
  -> IOManager +0x48: insert into priority queue
  -> task slot 1: load/file work
  -> task slot 2: finalize and publish completion
  -> completed-task queue
  -> main-frame drain at 0x00C3DBF0
  -> task slot 5
```

The global completed-task drain is called every frame from `0x0086E650` and
has a time budget. Psycho must move LOD demand earlier instead of increasing or
removing that global budget.

Real-reference publication uses a distinct `AttachDistant3DTask` contract.
`0x00440310` attaches directly only on the owning thread; otherwise slot 5 at
`0x0043FC40` performs the real main-thread publication. Cancellation or
failure receives no ready credit.

### Broken cell handoff

`TESObjectCELL +0xA8` is the current 16-bit VWD total. It is incremented during
reference insertion at `0x00548230` and decremented during removal at
`0x0054CA90` or the alternate helper `0x0055E1D0`.

`TESObjectCELL +0xAA` is a 16-bit successful-real-3D counter. Its only
increment is `0x00452390`, called from `0x004520C4` after successful VWD real
3D publication. It is reset only during construction or reload and is never
decremented when a ready reference is removed.

The gate at `0x005495A0` is only:

```text
cell.vwd_total <= cell.vwd_ready_total
```

Both gate callers additionally require `ready_total > 0`, then arm the timed
transition at `0x00557AA0`. The per-frame cell update at `0x00551890` later
retires the distant representation when the timer expires.

This allows stale success credit to retire a later population. For example:

```text
ready reference present:       total=1 ready=1
ready reference removed:       total=0 ready=1
different reference inserted:  total=1 ready=1
```

The different reference has not published real 3D, but vanilla considers the
cell ready. Conversely, one slow, cancelled, or failed current reference can
hold the cell-wide distant representation indefinitely. Keeping distant
coverage is the only safe terminal-failure fallback exposed by the audited
contract; forcing retirement would create a visible hole.

## Public configuration

Add a dedicated additive section:

```toml
[lod]
enabled = true
prefetch_enabled = true
handoff_fix_enabled = true

object_prefetch_multiplier = 1.35
object_retention_multiplier = 1.50

tree_prefetch_multiplier = 1.35
tree_retention_multiplier = 1.50

terrain_prefetch_multiplier = 1.10
terrain_retention_multiplier = 1.20
```

Add one default-off diagnostic option:

```toml
[diagnostics]
lod_streaming_trace = false
```

Configuration is resolved once at startup. Hot paths must not query global
configuration or parse settings.

Validation rules:

- reject non-finite values;
- clamp multipliers to `1.0..=2.0`;
- require each retention multiplier to be at least its prefetch multiplier;
- replace invalid values with defaults and emit one startup warning;
- keep terrain margins smaller because recursive quadtree expansion grows
  work and memory faster than object/tree block expansion.

The values above are initial profiling values. Final release defaults must be
chosen from runtime timing and memory telemetry. The two subordinate enable
switches are diagnostic A/B controls, not alternate fixes.

## Change 1: native LOD prefetch and retention

### Demand hooks

Install three pure predicate hooks:

| Contract | Address | Native loaded/pending field |
|---|---:|---:|
| Terrain chunk demand | `0x006FE550` | node `+0x10` |
| Distant object-block demand | `0x006FE620` | node `+0x14` |
| Distant tree-block demand | `0x006FE780` | node `+0x18` |

Each detour performs this sequence:

1. Call the captured predecessor.
2. Return true immediately when the predecessor already requests the node.
3. Validate the node, camera coordinates, live base threshold, and configured
   multiplier.
4. Reproduce the audited two-dimensional point-to-square metric.
5. Use the prefetch threshold when the native block pointer is NULL.
6. Use the farther retention threshold when the block is loaded or pending.
7. Return the predecessor result for unsupported, unreadable, or non-finite
   state.

The resulting state is:

```text
inside vanilla distance     -> native demand
outside vanilla, prefetch   -> start the native task early
outside prefetch, retained  -> keep the existing task/block
outside retention           -> allow native release
```

Object and tree thresholds are derived from the live engine settings so INI
and compatible setting owners retain authority. Terrain derives its threshold
from the current node. `fBlockLoadDistanceLow` remains unchanged because it is
an object quality-tier selector, not a prefetch distance.

The predicate detours must be allocation-free and lock-free. They must not
invoke task constructors, attach scene nodes, or perform IO themselves. Their
only behavioral change is returning true earlier or retaining a native block
longer.

### Reset behavior

Observe the distant-manager worldspace reset at `0x006FCE00`. It clears LOD
diagnostic epochs and all handoff sidecar state before chaining the native
reset. No prefetched task is directly cancelled or released by Psycho; native
worldspace teardown retains ownership.

## Change 2: identity-correct real-object handoff

### Sidecar state

Add a sparse map keyed by `TESObjectCELL*`:

```text
CellState
  generation: monotonically increasing integer
  certain: whether exact current membership is known
  references: map<TESObjectREFR*, Pending | Ready>
```

Engine pointers are identity keys only. Never retain an engine intrusive
reference or dereference a key after its engine callback ends.

Use one `parking_lot::Mutex` around the sparse ledger. Never hold it while
calling an engine predecessor. Streaming demand does not use this lock.

### Membership hooks

Hook reference insertion at `0x00548230`:

1. Read cell `+0xA8`.
2. Call the predecessor with the exact `thiscall` ABI.
3. Read `+0xA8` again.
4. Add the supplied reference as `Pending` only if vanilla incremented the VWD
   total.

Hook reference removal at `0x0054CA90` similarly. Remove the exact reference
only if vanilla decremented `+0xA8`. Measuring the native counter transition
preserves vanilla VWD and exclusion semantics without duplicating hidden
eligibility predicates.

The alternate decrement at `0x0055E1D0` supplies a cell but no reference
identity. It occurs on an InitItem/error path. Increment that cell's
generation, clear its membership, mark it uncertain, and keep its distant
representation. Do not guess which identity disappeared.

### Successful ready publication

Redirect the sole ready call at `0x004520C4` through an i686 naked thunk. The
audited callsite contract is:

- `[EBP+0x08]`: real `TESObjectREFR*`;
- `[EBP+0x0C]`: owning `TESObjectCELL*`;
- `ECX`: the cell argument for `0x00452390`.

The thunk preserves the original register and stack contract, calls the
captured executable predecessor, then marks that exact cell/reference ready.
If the reference is absent, removed, uncertain, or belongs to an older
generation, ignore it and count a stale publication.

Recording readiness at this callsite guarantees that state is published after
successful real 3D creation and before the caller can invoke a cell update or
retirement gate.

### Correct gate

Hook `0x005495A0`. Call the predecessor for diagnostics, but return sidecar
readiness instead of trusting lifetime totals.

Retirement is allowed only when:

- the cell has tracked state;
- membership is certain;
- the current reference set is non-empty;
- every current reference is `Ready` in the same generation.

Missing or uncertain state returns false. The native `+0xA8` and `+0xAA`
counters remain untouched for compatibility, but no longer authorize
retirement.

Keep the existing `0x00557AA0` transition timer and the per-frame retirement
logic at `0x00551890`. Psycho corrects the readiness decision, not the native
fade/state transition.

### Reload, teardown, and pointer reuse

- At `0x005508B0`, advance and clear the cell generation before vanilla
  rebuilds its counters and references.
- At `0x0054CD20`, erase the cell entry during teardown so a reused cell
  address cannot inherit readiness.
- At `0x006FCE00`, advance the global epoch and clear every cell entry before
  the native worldspace reset.

A cancelled or failed current reference remains pending. Prefetch gives normal
slow work more lead time, while terminal failure safely retains distant
coverage.

## Runtime patch manifest

Keep all addresses, expected instruction states, and hook containers together
in `engine_fixes/statics.rs`. Keep exact function signatures in
`engine_fixes/types.rs`.

| Contract | Address | Intervention |
|---|---:|---|
| Terrain demand | `0x006FE550` | predecessor-chaining predicate hook |
| Object demand | `0x006FE620` | predecessor-chaining predicate hook |
| Tree demand | `0x006FE780` | predecessor-chaining predicate hook |
| Worldspace LOD reset | `0x006FCE00` | clear sidecar, then chain |
| Cell reference insertion | `0x00548230` | observe native counter delta |
| Cell reference removal | `0x0054CA90` | observe native counter delta |
| Identity-less decrement | `0x0055E1D0` | mark cell uncertain, then chain |
| Ready publication call | `0x004520C4` | exact `E8 rel32` thunk patch |
| Readiness gate | `0x005495A0` | sidecar decision hook |
| Cell reload reset | `0x005508B0` | advance generation, then chain |
| Cell teardown | `0x0054CD20` | erase identity, then chain |

Do not hook `0x006FCA90`, the LOD block constructors/finalizers, task vtables,
the IO manager, the global completed queue, `0x0043FC40`, or generic scene
graph virtuals. Those are contract landmarks, not required intervention
points.

## Installation and compatibility

Install two independent `ModificationTransaction` groups:

1. Streaming: terrain, object, and tree predicates plus worldspace reset.
2. Handoff: insertion, removal, alternate decrement, ready callsite, gate,
   reload reset, teardown, and worldspace reset observation.

Prepare every member of a group before enabling any member. Verify the
supported FalloutNV `1.4.0.525` instruction or callsite state, publish callable
predecessors before activation, and chain existing executable owners where the
contract remains compatible.

If any member fails preparation or activation, roll back that entire group.
A partially installed identity ledger must never control the readiness gate.
The other independent group may remain active and its state must be reported
clearly.

No new WinAPI calls are required. If installation later needs a missing OS
operation, add a `libpsycho::os::windows::winapi` wrapper instead of calling
WinAPI directly.

## Failure behavior

- Disabled configuration installs no hooks and preserves vanilla behavior.
- A missing `.DLODSettings` object remains inert.
- Invalid camera, node, setting, or multiplier state returns the predecessor
  demand result.
- A streaming-hook conflict disables and rolls back the whole streaming group.
- A handoff-hook conflict disables and rolls back the whole handoff group.
- Missing, uncertain, or stale identity state keeps distant coverage.
- Cancelled or failed real-reference publication does not receive synthetic
  readiness.
- Psycho never forces a timeout retirement without proven real coverage.
- No terminal error path frees, retries, duplicates, or attaches an
  engine-owned object.

## Diagnostics

Expose a compact `PsychoInfo`/hang-report snapshot containing:

- installation state for both transaction groups;
- predecessor addresses and callsite ownership;
- native and extended terrain/object/tree demand decisions;
- retention decisions and native releases;
- current and peak tracked cells and references;
- membership inserts and removals;
- successful, duplicate, and stale ready publications;
- sidecar gates allowed and blocked;
- vanilla/sidecar gate disagreements;
- prevented stale-credit retirements;
- uncertain InitItem/error cells;
- reloads, teardowns, and worldspace resets;
- oldest pending-reference age;
- maximum observed ledger-lock duration.

The optional fixed ring retains the last 256 meaningful events with event
kind, cell, reference, generation, native counts, sidecar counts, tick, and
thread ID. It is disabled by default. Normal operation logs only installation,
summary, anomalies, and power-of-two sampled failures.

## Performance and memory contract

The implementation is acceptable only with all of these properties:

- no custom worker, queue, or global IO-manager hook;
- no change to the global completed-task frame budget;
- no allocation or lock in the three streaming predicates;
- no engine call while the handoff ledger lock is held;
- no per-frame scan of every tracked cell or reference;
- spatially bounded residency through finite request and retention distances;
- immediate sidecar erasure on cell/worldspace teardown;
- no verbose log on a valid hot path.

Prefetch intentionally trades additional temporary RAM/VRAM and IO work for
lead time. Object/tree coverage grows approximately with the square of the
distance multiplier, while terrain can grow faster through recursive splits.
Release defaults must therefore be conservative and validated on a huge
modpack.

OOM risk increases with the retained LOD ring and must be measured. UAF safety
must not regress because native task and scene ownership are unchanged and raw
pointers are stored only as non-dereferenced identities. Performance improves
when IO and completion work are moved before visible demand, but overly large
distances can replace late loading with sustained memory pressure or IO
backlog.

Reject release defaults that cause unbounded VAS growth, prevent memory from
returning to a stable plateau after transitions, or measurably worsen normal
frame pacing.

## Implementation order

1. Add `LodConfig`, raw deserialization, validation, defaults, and TOML
   documentation.
2. Add audited ABIs, addresses, hook containers, and installation snapshots.
3. Implement allocation-free distance and threshold helpers.
4. Install and validate object/tree prefetch and retention.
5. Add terrain prefetch with its smaller independent limits.
6. Implement the generation/membership ledger without engine calls under its
   lock.
7. Add insertion, removal, alternate decrement, reset, and teardown tracking.
8. Add the ready-publication thunk and predecessor chaining.
9. Replace the readiness gate and add vanilla/sidecar disagreement counters.
10. Add aggregate diagnostics and the optional trace ring.
11. Install each subsystem transactionally and verify rollback behavior.
12. Format and build the supported i686 release target.
13. Complete the staged runtime matrix before selecting final defaults.

## Verification

Build only the supported target:

```bash
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Run runtime validation in this order.

### Handoff with prefetch disabled

1. Remove a ready VWD reference and insert a different not-ready reference.
   The stale credit must not arm retirement.
2. Dynamically enable, disable, move, create, and remove references through
   normal engine and xNVSE paths.
3. Remove a reference while its AttachDistant3DTask is pending. A late
   completion must be ignored.
4. Reload a save, fast travel, cross worldspaces, and revisit unloaded cells.
   No generation may inherit state.
5. Exercise an InitItem/error decrement. The cell must become uncertain and
   retain distant coverage.
6. Confirm a fully ready current population arms the native transition no
   later than the next normal cell update.

### Object and tree prefetch

1. Walk, sprint, teleport, and use high-speed free camera toward unloaded
   regions.
2. Oscillate around the vanilla boundary. Blocks must not repeatedly
   construct and release.
3. Reverse direction abruptly and confirm retention remains bounded.
4. Exercise missing LOD assets and task cancellation without forced holes.
5. Confirm the native priority queue, task dependencies, main completion
   queue, and slot-5 publication remain the only owners.

### Terrain prefetch

1. Traverse long exterior routes and high-altitude views.
2. Repeatedly cross adjacent-cell and terrain split boundaries.
3. Enter an interior and change worldspaces; terrain memory must return toward
   a stable plateau.
4. Compare terrain task counts, completion backlog, frame-time percentiles,
   RAM, VRAM, and VAS before and after each multiplier change.

### Compatibility matrix

1. Allocator modes `0`, `1`, and `2`.
2. Lightweight and huge modpacks.
3. Helper present and absent.
4. Queued-task lifetime guard enabled.
5. Worldspaces with and without valid `.DLODSettings`.
6. Full feature disabled, prefetch-only, handoff-only, and both enabled.
7. Earlier compatible hooks and deliberate instruction conflicts to verify
   predecessor chaining and transaction rollback.

## Acceptance criteria

- No removed reference can contribute ready credit to a later population.
- No old-generation completion can authorize current retirement.
- Distant coverage retires promptly after every current eligible reference is
  ready.
- Missing real coverage never produces a forced visibility hole.
- Object, tree, and terrain tasks start before vanilla visible demand.
- Small boundary reversals do not destroy and recreate the same blocks.
- The global IO completion budget and generic task behavior are unchanged.
- Memory reaches a bounded plateau and recedes after cell/worldspace teardown.
- Fixed-camera median and 99th-percentile frame time do not regress outside
  measurement noise.
- Disabling the feature restores vanilla behavior.

## Stress-test crash follow-up: 2026-07-19

### Confirmed failure boundary

The crash is not OOM. CrashLogger reports `C0000417` at `0x00EC7C62` with
1.31 GiB of 4 GiB VAS in use. Psycho telemetry immediately before the crash
reports about 1.1 GiB commit, 1.0 GiB total free VAS, and a 637 MiB largest
free region. No OOM cleanup stage ran, and periodic blocking PDD purge was
disabled.

The main-thread call chain is:

```text
FUN_0086FF70
  -> FUN_00C458F0 completed-task processing
  -> completed-task array release
  -> BSTreeNode deleting destructor 0x0066B680
  -> BSTreeModel deleting destructor 0x006667D0
  -> core SpeedTree destructor 0x00B03B30
  -> registration-container erase helper 0x00B0DF00
  -> CRT invalid-parameter failure 0x00EC7C62
```

The destroyed node is `\WastelandUndergrowth01.spt`; CrashLogger shows the
`BSTreeNode` and several `NiRefObject` instances at reference count zero. This
is the exact asset and crash family already documented beside gheap's
zero-cooldown LIFO reuse path. The 80-byte pool used by `BSTreeModel` also
expanded during the final high-churn interval.

The first crash audit proves the exact immediate violation. The core SpeedTree
object has non-null payload field `+0x34` and owner field `+0x38`, but its
address is absent from the owner's pointer vector at `[owner+0x0C,
owner+0x10)`. `0x00B03B30` searches that vector, receives the end iterator,
and unconditionally passes it to erase helper `0x00B0DF00`. The helper detects
`erase(end)` and reaches the CRT invalid-parameter failure. The destructor's
other, global-registry branch checks for end before erasing; this per-owner
branch does not.

The normal release chain is also proven. Completed-task processing releases a
`BSTreeNode`; destruction of its arrays releases `BSTreeModel`; field `+0x0C`
then releases the nested core SpeedTree allocation. `0x0066AC40` constructs a
base core object for first load and destroys it only on load failure before
publishing it into `BSTreeModel`; it is not a live-model replacement path.

The follow-up audits prove that the base core constructor `0x00B02EF0` sets
payload `+0x34` to zero. The crashing nonzero-payload state therefore comes
from clone constructor `0x00B036D0`, reached through allocation wrapper
`0x00B05210` by `BSTreeModel` clone path `0x0066A650`.

The clone constructor copies the base object's shared refcount pointer `+0x30`
and shared owner pointer `+0x38`, pushes the clone into the owner's vector with
`0x00B0DDC0`, increments the shared refcount, allocates payload `+0x34`, and
increments the global tree count. None of those operations is locked. The
clone destructor performs the inverse shared-refcount decrement, vector
search/erase, payload free, and global-count decrement without a lock. The
generic vector insertion helper has only two callers: locked base-registry
insertion and this unlocked clone insertion. The erase helper has only the two
destructor branches. The base branch uses SpeedTree critical section
`0x011F8BC4` and checks for end; the clone branch uses neither protection.

The root defect is therefore a native SpeedTree clone-lifecycle race. Worker
model loading can publish a clone while main-thread completed-task processing
destroys clones sharing the same owner vector and refcount. The crash is the
clone destructor observing a missing member and passing `end` to erase. Gheap
zero-cooldown reuse and increased LOD churn shorten the timing window and add
an ABA risk, but they are amplifiers of the missing engine synchronization,
not justification for an allocator-wide quarantine or an `erase(end)` patch.

The LOD handoff ledger is not the direct corruptor. It stores engine pointers
only as integer identities, never releases them, and fails closed when state is
uncertain. Its warnings can retain distant coverage but cannot invoke the
BSTree destructor. The audited distant-tree task vtable loads and owns only a
`BGSDistantTreeBlock`; it has no path to `BSTreeManager`, `BSTreeModel`, or
`.spt` ownership. Prefetch can amplify native task and allocator churn but is
not the corruptor and must not be disabled as the fix.

### Research gate result

The three crash audits close the constructor, insertion, refcount, owner,
destructor, physical-free, task-release, and distant-tree separation gaps. No
additional static audit is required before implementation.

Do not patch the missing end check. Skipping erase while continuing to free
payload `+0x34` can double-free a stale clone or free payload belonging to a
reused live clone.

### Fix plan

1. Add a small `speedtree_lifetime` owner to `psycho-engine-fixes` core. Hook
   clone constructor `0x00B036D0` and the only core scalar-destruction wrapper
   `0x00666910`. Install both hooks atomically; refuse this fix if either target
   is already owned or either trampoline is unavailable.
2. Extend the engine's existing SpeedTree critical section at `0x011F8BC4`
   over the whole clone constructor and whole scalar destructor. Use
   `BorrowedCriticalSection`; the native critical section is reentrant, so the
   base destructor may safely enter it again. This covers owner-vector
   insertion/removal, shared-refcount increment/decrement, payload
   publication/free, last-owner cleanup, and the global tree count as one
   lifecycle transaction.
3. In the scalar-destructor hook, while holding the same lock, validate clone
   owner-vector bounds and membership before calling vanilla. Valid objects
   always take the original path. If a clone is already absent, fail closed by
   skipping the entire scalar destructor, including its physical free, and
   emit a power-of-two diagnostic. Leaking one already-corrupt clone is safer
   than guessing ownership; this guard is a last-resort safety net, not the
   synchronization fix.
4. Record sampled proof counters: clone constructs, clone destroys, maximum
   owner-vector length, missing-member rejects, invalid bounds, and lock wait
   time. When gheap is active, include `ptr_info` state only before native
   destruction. Do not dereference or inspect the object after the original
   destructor returns.
5. Keep the DTL predicate, native task graph, completed-task budget, and LOD
   multipliers unchanged. Tree prefetch increases load but does not own `.spt`
   clones and must not be disabled as the fix.
6. Do not change gheap reuse policy in the first fix. If synchronized stress
   runs still produce a missing-member reject and telemetry proves a free or
   reused gheap cell, design a second, tree-provenance quarantine around the
   exact 80-byte `BSTreeModel` and 160-byte core clone lifetimes. Do not add a
   size-class-wide cooldown, global quarantine, or PDD freeze.
7. Repair the separate handoff resynchronization gap. An identity-less
   decrement currently makes a cell uncertain and later produces stale-ready
   and removal-mismatch bursts. Re-establish certainty only at a proven full
   membership rebuild boundary; never guess a missing reference identity or
   fall back to lifetime totals.
8. Remove proof-only verbose telemetry after the lifetime assertion stays
   clean, retaining aggregate and power-of-two diagnostics.

### Engineering balance

- UAF protection is the primary objective. The native SpeedTree lock closes
  the partial-construction, vector mutation, shared-refcount, and last-owner
  windows without relying on reuse timing.
- OOM safety is improved relative to quarantine proposals: normal objects are
  never retained. Only an already-corrupt clone rejected by the safety guard
  leaks, with an explicit counter. Any later quarantine requires separate
  proof and a finite release boundary.
- Performance cost is limited to tree clone construction and destruction.
  There is no per-allocation, render-callback, generic IO, or completed-task
  overhead. One native critical section is simpler and safer than a per-owner
  lock map whose keys have the same lifetime problem.

### Validation matrix for the crash fix

1. Reproduce the original high-speed Wasteland route with allocator mode `2`,
   full LOD, and trace enabled for proof runs.
2. Repeat with tree multipliers `1.0/1.0` while object, terrain, and handoff
   remain enabled. This measures workload amplification without presenting a
   disable as the fix.
3. Repeat with allocator modes `1` and `0` using the same LOD settings to
   isolate gheap physical reuse from the native ownership path.
4. Oscillate across tree and cell boundaries, then allow queues and memory to
   settle. Require zero missing-member rejects, zero invalid vector bounds,
   balanced clone construction/destruction after settling, bounded retained
   memory, and no PDD or task-drain hang.
5. Run substantially longer than the 4:10 failing playtime on both lightweight
   and huge modpacks. Acceptance requires no `C0000417`, no stale BSTree
   destructor telemetry, a stable VAS plateau, and preserved early LOD/handoff
   behavior.
6. Compare fixed-camera and high-speed-route frame time before and after the
   lock. Lock contention must remain negligible outside load bursts, and no
   render callback may block on this critical section.

## Save-load cache-allocation follow-up: 2026-07-19

### Proven contract

- `0x00AFF300` successfully opens the CRT `FILE*` at `BSFile + 0x24` before
  calling the open-state initializer at `0x00AFF490`.
- A cache capacity of `0xFFFFFFFF` requests a whole-file cache. The initializer
  obtains the concrete file size through vtable slot `+0x1C`, allocates that
  size through `GameHeap::Allocate`, and stores the result at `BSFile + 0x20`.
- Vanilla does not test that result before calling `0x00AA1570`. A null cache
  becomes a null `_DstBuf` in `_fread_s`, whose invalid-parameter path raises
  `C0000417` at `0x00ECB144`.
- The object is still inside its open transaction, so its `FILE*` has not been
  published to another task and cannot be concurrently closed. With element
  size one, multiplication overflow is also excluded. The missing allocation
  check is the failing contract.
- The native read function at `0x00AA1750` explicitly uses direct `fread` when
  the cache capacity at `+0x10` is smaller than the requested transfer. A zero
  capacity with null cache is therefore the class's supported unbuffered mode,
  not a skipped model or failed task.

### Implemented fix

1. Hook `0x00AFF490` in the same transaction as all three LockFreeMap capacity
   hooks and the exact two-worker instruction patch.
2. Preserve native open-state, dynamic file-size resolution, cache allocation,
   whole-file preload, short-read rejection, and game-heap ownership.
3. On cache allocation failure only, clear cache capacity/fill/cursor while
   keeping the open flag and `FILE*`. Later reads continue through the native
   direct-IO branch.
4. Count direct-cache fallbacks in `PsychoInfo`. Do not log or allocate on the
   allocation-failure branch.
5. Keep two workers, LOD task priority, prefetch, handoff, and SpeedTree
   lifetime synchronization enabled.

### Engineering balance

- OOM recovery improves: an optional read cache no longer converts recoverable
  pressure into a fatal CRT exception.
- UAF protection is unchanged: the fix neither extends object lifetime nor
  changes publication or destruction ownership.
- Performance is unchanged while cache allocation succeeds. Under allocation
  pressure only, the affected file uses slower direct reads instead of losing
  the task or process. No generic allocation or steady-state read hook is
  added.

### Runtime acceptance

1. Repeatedly load saves while traversing LOD-heavy exterior cells with both
   workers active. Require no `C0000417` and no task-constructor ABI crash.
2. Verify `PsychoInfo` reports two active workers and file-cache fallback `ON`.
3. If the fallback counter rises, require successful completion of the same
   save load and continued LOD publication. A rising counter without memory
   pressure requires a fresh allocation-size audit.
4. Repeat with allocator modes `0`, `1`, and `2`. The fallback must remain
   allocator-domain independent and every successful cache must still be
   freed by the game heap.

## BSTree TLS-slot exhaustion follow-up: 2026-07-19

### Proven contract

- The crash at `0x006EC846` is a null scratch-map dereference reached from
  `0x00449530` after `0x00449F80` fails to register the calling thread.
- `BSTreeManager` constructs its map at `BSTreeManager + 0x1C` through the
  private constructor at `0x00665CB0`, passing a per-thread capacity of two.
  This specialization does not call either generic LockFreeMap constructor
  already hooked by the parallel-IO transaction.
- The only two direct callers of the tree find/load owner at `0x00664F50` are
  queued tree execution at `0x0043DA00` and main-thread QueuedReference
  completion at `0x0050F810`.
- With two IO workers, both workers can occupy the two native slots before
  main-thread save-load completion registers. The third registration returns
  null and the native caller dereferences it. This is capacity exhaustion,
  not a missing tree key, stale model, or allocator ownership failure.

### Implemented fix

1. Hook private constructor `0x00665CB0` and expand its per-thread capacity by
   exactly one, changing the native BSTree map from two slots to three.
2. Own this hook in the same transaction as both generic capacity hooks, the
   BSFile fallback, and the exact two-worker instruction patch. Any failure
   rolls the complete parallel extension back to the native one-worker path.
3. Refuse installation if either IOManager at `0x01202D98` or BSTreeManager at
   `0x011D5C48` already exists. Recheck both owners immediately before commit
   so no manager can publish a map built with old capacity.
4. Expose private BSTree-map expansions separately in `PsychoInfo`. Do not add
   a null guard at the crash site, skip tree loads, or disable a worker.

### Engineering balance

- UAF protection is unchanged: no object lifetime, reuse, or free edge moves.
- OOM cost is bounded to one additional 12-byte BSTree scratch record and its
  constructor-owned slot metadata. No allocator-wide retention is added.
- Performance keeps both IO workers and removes the failed-registration path.
  Constructor interception has no per-load overhead after the map is built.

### Runtime acceptance

1. Start a fresh process and verify `PsychoInfo` reports two active workers,
   one Tree TLS map expansion, and zero capacity failures.
2. Repeatedly load saves while both worker threads process exterior tree LOD.
   Require no `0x006EC846` crash and continued real-tree publication.
3. Stress cell transitions and rapid save-load cycles longer than the prior
   failing runs. Require stable queue drain, no SpeedTree ownership rejects,
   and no growth in scheduler failures.
4. Repeat with allocator modes `0`, `1`, and `2`; the result must be independent
   of allocator domain and preserve the two-worker throughput improvement.

## Missing distant-geometry priority regression: 2026-07-19

### Proven contract

- The task key stores priority as an unsigned byte at bits 16-23. Runtime
  priority replacement at `0x00C3DF40` updates that exact field and preserves
  the task class, secondary key, and sequence.
- The queue comparator at `0x00C3F6B0` reports the first existing key greater
  than or equal to the requested key. Insertion at `0x00C3FFB0` places the new
  node at that predecessor edge, producing ascending key order.
- Worker traversal at `0x00C40E70` begins at the first queue bucket, and
  `0x00C42380` returns the first live node. Smaller numeric priority values are
  therefore serviced before larger values when the surrounding key fields
  match.
- Blocking load ownership at `0x00C3E1B0` starts after `state * 4 + 3` and
  stops when a decoded task priority exceeds the active load state. The
  companion count at `0x00C3E860` covers exactly the buckets through that
  boundary.
- Native LOD priority is normally `1` or a bounded dynamic archive priority
  plus four. Psycho's value `255` was outside the scheduler's active priority
  contract and could leave all three LOD task types unserviced across load.
- Terrain, object, and tree demand predicates, resource lookup, worker loads,
  completed-task drain, and main-thread publication remain intact. The
  regression is shared scheduler eligibility, not missing LOD data or a
  publication hook failure.

### Implemented fix

1. Change the LOD boost from priority `255` to native priority `0`.
2. Continue calling the engine's dependency-aware update at `0x00C3CAE0`, so
   the task and its dependencies move together and queued state still uses the
   native remove-and-requeue transaction.
3. Preserve both IO workers, all three TLS-capacity expansions, the BSFile
   fallback, early demand, handoff state, and SpeedTree lifetime locking.
4. Report the installed numeric priority in the startup log and retain the
   per-type boost counters in `PsychoInfo`.

### Engineering balance

- Performance is corrected: LOD work receives the engine's actual highest
  scheduling priority instead of being placed behind eligible native work.
- UAF protection is unchanged: no task, model, tree clone, or scene object
  lifetime edge moves.
- OOM behavior is unchanged: queue nodes, cache allocation, direct-read
  fallback, and allocator ownership are untouched.

### Runtime acceptance

1. Start a new process and require the log to report priority `0`, two workers,
   three TLS capacity families, and the BSFile fallback installed.
2. Load the save that showed flying grass. Require distant terrain first, then
   object and tree LOD, without waiting for a cell reload or console command.
3. Traverse exterior cells at speed and repeat save-load cycles. Require rising
   terrain/object/tree boost counters, continued publication, and no scheduler
   or capacity failures.
4. Repeat the prior crash stress route. Acceptance requires both corrected LOD
   visibility and no return of the constructor ABI, `C0000417`, or BSTree TLS
   crashes.

## Exterior-cell global-owner stress crash: 2026-07-19

### Proven contract

- The crash is `C0000005` on a `BSTaskManagerThread` executing an
  `ExteriorCellLoaderTask`. The chain ends at `0x0044DDC0`, which reads
  `ECX + 8`, with `ECX = 0`.
- `0x005516C0` forwards its own `this` pointer unchanged to that leaf. At the
  crashing call site, `0x004686F4` loads `this` from global `0x011C3F30` and
  `0x004686FA` calls `0x005516C0`.
- The same caller checks `0x011C3F30` for null at `0x004686D3`, but reloads it
  later. This is a concrete check/reload race, not a corrupt task pointer or
  allocator failure.
- Per-form loader `0x00550500` writes the current cell to `0x011C3F30` at
  `0x0055065D`, performs form construction, then clears the global at
  `0x00550862`. The owner is process-global, not TLS or task-local, and the
  audited call path has no enclosing lock.
- Exterior demand owner `0x00452580` may submit multiple cell tasks while
  crossing a grid edge. Generic dispatch at `0x00C3FC80` sends independently
  dequeued tasks to either worker, so two execute bodies can overlap.
- Vanilla passes exactly one worker at `0x00C3DA7A`. The execute method at
  `0x00527CB0` is the only vtable entry that reaches the shared form-loading
  path, and it performs no wait on another IO task. Serializing this method
  restores the native ordering without changing task creation, queue
  ownership, completion, or destruction.

### Implemented fix

1. Hook `ExteriorCellLoaderTask::execute` at `0x00527CB0` and hold one blocking
   worker mutex across the complete original method.
2. Keep the task payload processing and its final native release in the
   original method. Do not replace, cancel, delay-publish, or destroy a task.
3. Own the serialization hook in the same all-or-nothing transaction as the
   three TLS-capacity hooks, BSFile fallback, and two-worker patch. Failure to
   own any contract retains vanilla one-worker IO.
4. Report installation, executed cell tasks, and contended entries in
   `PsychoInfo`.
5. Preserve priority `0`, both workers, early LOD demand, identity handoff,
   SpeedTree lifetime locking, and direct-read fallback.

### Engineering balance

- UAF protection improves because two cell loaders can no longer overwrite or
  clear each other's process-global form owner.
- OOM behavior is unchanged. The mutex has no per-task allocation and no
  queue, payload, cache, or allocator ownership changes.
- Performance retains two workers. Exterior-cell form parsing runs at its
  vanilla concurrency of one, while terrain, object, tree, model, and safe file
  tasks remain eligible on the other worker.

### Runtime acceptance

1. Start a new process and require the startup log to include serialized
   exterior-cell loading with two workers and priority `0`.
2. Repeat the exact exterior stress route. Require rising cell-loader runs;
   waits may rise during grid transitions and are expected.
3. Require no `0x0044DDC0` crash, no `0x011C3F30` null-owner signature, and no
   return of the prior save-load or BSTree failures.
4. Confirm distant terrain, objects, and trees remain visible and all three
   priority counters continue rising.

## LandLOD static vertex-buffer lifetime crash: 2026-07-19

### Proven contract

- The crash at `0x00E8C00D` occurs before Direct3D `Lock`. The instruction
  dereferences the first argument passed to `0x00E8BFF0`; that argument is
  `NiVBChip + 0x08`, and it is null while the `NiVBChip` itself is non-null.
- `0x00E941A0` does not allocate a Direct3D resource. It only initializes the
  static block usage and mode fields. The actual `CreateVertexBuffer` call is
  in `0x00E94580`, which returns null when the HRESULT reports failure.
- `0x00E98660` constructs a non-null chip by copying the parent block's
  Direct3D buffer from block `+0x08` to chip `+0x08`. It does not validate the
  copied pointer.
- `NiStaticGeometryGroup` allocation at `0x00E94C20`, retirement at
  `0x00E94770`, its block map, sorted free list, chip pool, accounting, and COM
  release path own no lock. Terrain worker execution can enter renderer
  prepacking, so two IO workers expose this shared lifetime race.
- The common wrapper at `0x00E8BFA0` retires the old stream, allocates a new
  chip, publishes it, and returns success based only on the chip pointer. The
  shader-declaration caller then reads chip `+0x08` without another guard.
- A genuine `CreateVertexBuffer` failure has a second native bug:
  `0x00E94C20` dereferences the null chip at `0x00E94CDD` instead of returning
  allocation failure to `0x00E8BFA0`.
- Vanilla `NiGeometryBufferData::IsVBChipValid` at `0x00E8EEB0` checks every
  stream and requires both a chip and chip `+0x08`. Stewie's rendering inline
  checks only stream zero, so it can admit partially invalid multi-stream
  geometry.

### Implemented fix

1. Serialize `NiStaticGeometryGroup` allocation and retirement with one
   reentrant lock. The outer `0x00E8BFA0` transaction holds the same lock for
   static geometry, while direct slot calls are also covered.
2. Patch the null return at `0x00E94CDB` to unwind the existing stack frame and
   return null. The common wrapper and all audited callers then use their
   native deferred-pack path, so the next request retries allocation.
3. Validate the published stream chip and chip `+0x08` before reporting
   success. Retire an invalid publication immediately while the static
   lifetime lock is still held, then return false for a clean retry.
4. Restore all six audited call sites to vanilla `0x00E8EEB0` all-stream
   validation, including when Stewie's weaker rendering inline is active.
5. Keep two IO workers, priority zero, all terrain/object/tree tasks, early
   demand, handoff, and renderer features enabled. Only the unsafe shared
   static vertex-buffer allocator is serialized.
6. Report lifetime-guard state, transactions, allocations, retirements, and
   safe create/publication retries in the compact `PsychoInfo` report.

### Engineering balance

- UAF/race protection improves because static block, free-list, chip, and COM
  lifetime transitions are one transaction and invalid resources are never
  exposed to pack callers.
- OOM behavior improves because Direct3D allocation failure becomes a
  retryable deferred pack instead of a null dereference. No geometry or LOD
  category is removed.
- Performance retains both IO workers. Safe file, model, cell, object, tree,
  and terrain work remains parallel; only the proven non-thread-safe static VB
  ownership path is serialized.

### Runtime acceptance

1. Start a new process and require the LOD startup line to report `vb=true`,
   priority zero, and two workers. `PsychoInfo` must show the lifetime guard ON.
2. Repeat the long exterior stress route beyond the prior crash time. Require
   no `0x00E8C00D` null-VB fault and no `0x00E94CDD` null-chip fault.
3. Require distant terrain, objects, and trees throughout the run. A rising
   safe-retry counter is acceptable; missing distant geometry is not.
4. Repeat save-load and rapid cell-transition stress. Require stable worker
   counts, continued LOD priority activity, and no return of the prior
   exterior-owner, BSTree TLS, or SpeedTree failures.

## Research authority

- `analysis/ghidra/output/perf/lod_streaming_pipeline_contract_audit.txt`
- `analysis/ghidra/output/perf/lod_replacement_visibility_contract_audit.txt`
- `analysis/ghidra/output/perf/lod_handoff_scheduler_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_bstree_crash_ownership_audit.txt`
- `analysis/ghidra/output/crash/bstree_speedtree_owner_registration_followup_audit.txt`
- `analysis/ghidra/output/crash/bstree_speedtree_clone_registration_final_audit.txt`
- `analysis/ghidra/output/crash/lod_multiworker_save_load_ownership_final_audit.txt`
- `analysis/ghidra/output/crash/lod_save_load_c0000417_origin_and_coverage_audit.txt`
- `analysis/ghidra/output/crash/lod_bstree_tls_slot_exhaustion_root_cause_audit.txt`
- `analysis/ghidra/output/perf/lod_missing_distant_geometry_regression_audit.txt`
- `analysis/ghidra/output/perf/lod_priority_queue_boundary_final_audit.txt`
- `analysis/ghidra/output/crash/lod_exterior_cell_multiworker_null_owner_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_landlod_vertex_buffer_lifetime_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_vertex_buffer_geometry_group_allocation_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_allocation_failure_final_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_creation_leaf_retry_audit.txt`

The matching source scripts are:

- `analysis/ghidra/scripts/lod_streaming_pipeline_contract_audit.py`
- `analysis/ghidra/scripts/lod_replacement_visibility_contract_audit.py`
- `analysis/ghidra/scripts/lod_handoff_scheduler_followup_audit.py`
- `analysis/ghidra/scripts/lod_bstree_crash_ownership_audit.py`
- `analysis/ghidra/scripts/bstree_speedtree_owner_registration_followup_audit.py`
- `analysis/ghidra/scripts/bstree_speedtree_clone_registration_final_audit.py`
- `analysis/ghidra/scripts/lod_multiworker_save_load_ownership_final_audit.py`
- `analysis/ghidra/scripts/lod_save_load_c0000417_origin_and_coverage_audit.py`
- `analysis/ghidra/scripts/lod_bstree_tls_slot_exhaustion_root_cause_audit.py`
- `analysis/ghidra/scripts/lod_missing_distant_geometry_regression_audit.py`
- `analysis/ghidra/scripts/lod_priority_queue_boundary_final_audit.py`
- `analysis/ghidra/scripts/lod_exterior_cell_multiworker_null_owner_crash_audit.py`
- `analysis/ghidra/scripts/lod_landlod_vertex_buffer_lifetime_crash_audit.py`
- `analysis/ghidra/scripts/lod_vertex_buffer_geometry_group_allocation_followup_audit.py`
- `analysis/ghidra/scripts/lod_static_vertex_buffer_allocation_failure_final_audit.py`
- `analysis/ghidra/scripts/lod_static_vertex_buffer_creation_leaf_retry_audit.py`

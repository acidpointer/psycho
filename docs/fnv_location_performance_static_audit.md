# Fallout New Vegas location performance static audit

Research date: 2026-10-06. Candidate implementation: 2026-10-07.

Fallout New Vegas contains native CPU work whose size depends on scene objects,
candidate lights, render-pass entries, and actively processed actors. Low
triangle counts, small textures, and an absence of combat do not bound those
costs. The clearest algorithmic inefficiencies identified here are a quadratic
lighting-property sorter that repeatedly calculates light-distance scores and
scene-light scans that repeatedly restart from a linked-list head.

These are verified mechanisms, not measured attribution of the reported FPS
loss. The audit does not establish one universal bottleneck, the relative cost
of the mechanisms, or the size of an achievable FPS improvement.

The optimization objective is to remove every proven source of avoidable work
that can be changed while preserving engine behavior. Identifying the dominant
consumer in a slow frame is not a prerequisite. Static instruction and loop
analysis can establish redundant work and a reduced operation budget even when
elapsed time cannot be measured. Candidate selection follows that evidence;
accepted engine fixes still require complete ownership, lifetime, ABI, math,
synchronization, and provider contracts. The owner subsequently requested
implementation of the two unreleased candidates after the remaining gaps were
reported. Both now have real reduced-work paths, independent default-on
switches, and native/provider fallbacks. Their conditional static qualification
does not close the engine ownership gaps or establish runtime acceptance.

## Reported behavior and research boundary

The owner reports substantial FPS differences between locations, including
both vanilla and modded locations, without intense combat. No specific location
pair or reproducible workload was supplied. The research covers native work
that scales with location content even when the visuals appear simple. The
owner's clarified objective is broad removal of verified inefficiencies,
without requiring attribution to a particular location or dominant consumer.

The investigation and native qualification remain static only. They do not
depend on gameplay profiling, a debug build, or an instrumentation build.
The later authorized candidate implementation is described in
[Implemented unreleased candidates](#implemented-unreleased-candidates).

The engine audit covers the main frame's lighting/rendering ordering, native
light assignment and sorting, ordinary batch dispatch, scene updates and
culling, and the actor worker pipeline. It is not an exhaustive audit of every
script, physics operation, shader, plugin, or Proton/Wine interaction.

Three evidence classes must remain distinct:

- **Owner observation:** FPS varies across locations and does not require combat.
- **Static proof:** verified instructions, call sites, virtual-table entries,
  field accesses, update gates, and loop structure in the supported executable.
- **Unresolved attribution:** actual invocation frequencies, scene population,
  elapsed time, installed hook providers, and contribution to a particular slow
  frame.

Historical runtime measurements in other repository documents describe their
own workloads. They are not measurements of this report.

## Executable identity and evidence interpretation

All addresses are virtual addresses in
[`fnv_reverse/FalloutNV.exe`](../fnv_reverse/FalloutNV.exe), the repository's
supported FalloutNV 1.4.0.525 executable. Its format is PE32 x86 and its image
base is `0x00400000`. The executable SHA-256 verified for this audit is
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The same identity is recorded in the
[parallel IO engine contract](parallel_io_engine_contract.md#executable-identity).
Addresses must be reverified before reuse against another executable.

Radare2 MCP was the primary binary interface. Existing authoritative text in
`analysis/ghidra/output/` supplied retained comparison evidence; it was not
regenerated. Decompiled argument names and inferred function boundaries are
not authoritative where they disagree with native instructions. Call sites,
register use, stack arguments, and virtual-table targets resolve those cases.

The evidence ledger below distinguishes retained output from direct binary
checks performed during this audit. The original audit's radare2 checks were
summarized without a separate raw transcript. The continued lighting-contract
audit preserves its tool output in
[native lighting update evidence](../analysis/radare2/output/fnv_location_lighting_update_contract_20261006.txt).
The follow-up is preserved in
[light scan and cache evidence](../analysis/radare2/output/fnv_location_light_scan_cache_contract_20261006.txt).
The planned fixes' subsequent contract checks are preserved in
[lighting qualification evidence](../analysis/radare2/output/fnv_location_lighting_qualification_contract_20261006.txt).
These captures identify corrected instruction windows and exploratory probes
that began inside instructions or had an incorrect initial label. Use the
aligned instructions and corrected receiver provenance as evidence.
Reinspect the binary before a patch; this prose is not patch authority.

## Costs that scale with location content

| Native mechanism | Quantity controlling admitted work | Existing gate or optimization | What remains unknown |
|---|---|---|---|
| Geometry/pass dispatch | Number of geometry/pass entries | Pass grouping and shader/state reuse | Entries and CPU time in the reported locations |
| Light assignment | Updated geometry and its candidate-light lists | Update queues, spatial-parent lists, bound tests | Update cadence and candidate populations |
| Render-time light maintenance | Scene light entries, admitted dynamic enqueues, and geometry memberships on transitions | Root/light admission, position comparisons, visibility/dimmer transition tests | Light populations, traversal frequency, and transition frequency |
| Property light sorting | Lights in a property list at each sort | Cached pass state and material/property gates | List sizes and sort frequency |
| Indexed scene-light scans | Candidate prefix visited by each admitted scan | Shadow admission, primary-light brightness, accepted-light limits | Prefix lengths, admitted calls, and CPU time |
| Scene traversal | Visited nodes and child-array entries | Selective update flags, bounds, and culling | Admitted traversal size in each location |
| Actor processing | Actors admitted to active processing | Actor state gates, workers, and task dispatch | Actor counts and remaining wait time |

The quantities above are not interchangeable with polygon count. A geometry
can be cheap to rasterize while retaining a lighting property, scene-graph
node, shader callbacks, and one or more render-pass entries.

## Main frame ordering and concurrency

The relevant main-loop entry is `0x0086E650`. Its inspected call sequence is:

```text
0x0086ED90 -> 0x00B60040  native lighting maintenance
0x0086EDE8 -> 0x0086FF70  path containing world rendering
0x0086EDF0 -> 0x008705D0  subsequent frame maintenance
0x0086EE4E -> 0x008C7990  conditional actor-worker join
```

The world-rendering chain within that path is:

```text
0x0086FF70 -> 0x008706B0
                  -> 0x00870A00 -> 0x00873200
                  -> 0x00870BD0 -> 0x00873200
```

These are direct calls in the inspected rendering path. They do not introduce
a worker dispatch at those boundaries. The two branches represent alternate
world-rendering routes; they are not evidence that both execute every frame.
The continued caller audit also establishes a third admitted route through
`0x008707C0`, which calls shadow preparation at `0x00870851`. That route is
not proof of another call to `0x00873200`; its inspected body instead calls
other rendering helpers. The concurrency closure below records this distinction.

The lighting call is unconditional at this main-loop site, but its callee
contains queues and conditional processing. An unconditional maintenance call
does not establish an unconditional complete lighting rebuild.

Actor workers can overlap work in the rendering interval. The main-loop join
occurs afterward and is itself gated by frame state and the processor setting.
Consequently, rendering time and actor-worker time cannot simply be added.
The frame may have to wait for unfinished actor work, but the wait duration is
not established by the presence of a wait instruction.

Relevant retained evidence is the main-loop call list in
[combat performance analysis](../analysis/ghidra/output/perf/combat_perf_analysis.txt),
the `0x0086FF70` body in
[AI thread deep analysis](../analysis/ghidra/output/memory/ai_thread_deep.txt),
and the worker-join section in
[combat performance deep analysis](../analysis/ghidra/output/perf/combat_perf_deep_dive.txt).
The main-loop call ordering and the join call site were rechecked in the binary.

## Native light assignment

### Update ownership and candidate sources

`0x00B60040` visits up to four non-null ShadowSceneNode roots in the global
range `0x011F91C8` through `0x011F91D4`. It calls `0x00B5FD60` for each admitted
root. That routine processes light/object update lists and invokes conditional
light traversal and object lighting updates.

`0x00B5DAC0` selects between geometry/subtree update paths. It recognizes
spatial-parent types through RTTI and chooses candidate sources accordingly.
The verified sources include:

- A general scene light list at scene-node `+0xB4`.
- A spatial-parent candidate array at `+0xE0`, with count at `+0xE4`.
- Another spatial-parent candidate array at `+0xB4`, with count at `+0xB8`.

In one admitted branch, it allocates a scratch pointer array, tests candidate
lights against the object's bound, scores accepted candidates, sorts them
through `0x00EC6F20` with comparator `0x00B5AA70`, applies the resulting list
recursively, and frees the scratch storage. This array-sort path is distinct
from the property linked-list sorter discussed below.

The retained `0x00B5DAC0` decompile appears in
[disassembled callers](../analysis/ghidra/output/memory/disasm_callers.txt).
Allocator call sites are also retained in the
[scrap heap identity contract](../analysis/ghidra/output/memory/scrap_heap_identity_thread_contract.txt).

### Geometry against candidate lights

`0x00B5B260` obtains the geometry's shader property at `+0xA8`, admits supported
property types, establishes a property-list marker, and scans the applicable
candidate-light source. It calls `0x00B9DAE0` for bound/light intersection and
`0x00B9F480` for accepted membership. It finishes through `0x00B71600`.

The recursive variants `0x00B5C490` and `0x00B5C5C0` walk node child arrays,
skip null entries and rejected bounds/flags, and apply lighting updates to
admitted geometry. The tests do not depend on mesh triangle counts.

For admitted geometries with candidate counts `L_i`, the scan visits candidates
according to the sum of those counts. A branch using a shared list of `L`
candidates for `G` admitted geometries therefore contains `G * L` candidate
visits. This is conditional operation counting, not a claim that every scene
executes that branch or that all loaded objects are updated every frame.

The bound/light test has its own type-specific behavior. In the inspected
non-directional path it calculates center distance and compares the light
radius against distance minus the scaled bound radius. This introduces CPU
distance work before any triangle rasterization.

### Membership searches and the fence qualification

`0x00B9F480` searches a light's geometry membership list for the current
geometry. `0x00B71560` also uses `0x00B70340` to search the property's light
membership list. These are linked-list searches.

However, `0x00B9FBA0` inserts a fence object and establishes a cursor. Existing
entries are moved relative to that marker through `0x00B702E0`. This matters:
when traversal order repeats, the cursor can keep searches short. Different
orders can require substantially longer scans, but an unconditional quadratic
steady-state membership cost was not established.

`0x00B71600` removes stale property memberships after the marker and dirties
the property on membership changes. Node insertion/removal involves existing
reference ownership and pooled-list handling. These lists are not disposable
scratch structures that a performance patch may freely replace.

The direct binary checks for this section covered `0x00B60040`,
`0x00B5FD60`, `0x00B5B260`, `0x00B9DAE0`, `0x00B9F480`,
`0x00B9FBA0`, `0x00B70340`, `0x00B702E0`, and `0x00B71600`.
Complete membership ownership and every mutation/caller contract remain
outside the qualification of this research.

### Queue producers and draining

The continued audit verifies these update boundaries. All new native output
for this section is preserved in
[native lighting update evidence](../analysis/radare2/output/fnv_location_lighting_update_contract_20261006.txt).

| Scene-node field | Queue role | Verified producer or consumer behavior |
|---|---|---|
| `+0xE4` | Light additions | The consumer chooses `0x00B5ECA0` or `0x00B5CD00` according to the light's shadow flag |
| `+0xF0` | Light removals | `0x00B5CFF0` appends here when its pointer and scene `+0x1FC` gate permit |
| `+0xFC` | Light updates | `0x00B5D270` appends; the consumer selects `0x00B5D930` for dynamic lights and `0x00B5D300` otherwise |
| `+0x108` | Object updates | `0x00B5D9F0` appends here for its false mode argument; the consumer calls `0x00B5DAC0` with active-only mode false |
| `+0x114` | Object updates for active lights | `0x00B5D9F0` appends here for its true mode argument; the consumer calls `0x00B5DAC0` with active-only mode true |

The queue-role names agree with the read-only
[ShadowSceneNode reference header](../.research/fnv-vanilla-plus-ao-main/VanillaPlusAO/internal/Game/Bethesda/ShadowSceneNode.hpp).
The reference name `abIsMoving` for the object producer's boolean is not a
replacement for its verified downstream active-only behavior.

The object producer uses ECX for the scene node, two stack arguments for the
object pointer and boolean, and returns with `RET 8`. It admits a non-null
object, enters the existing queue synchronization helper, retains the object,
appends a node through `0x00A5A310`, and releases its temporary reference.
The dynamic light producer uses ECX for the scene node, one stack light pointer,
and `RET 4`; it also retains, appends, and releases the temporary reference.

`0x00A5A310` acquires a list node through `0x0043A010`, assigns its reference,
links it at the tail, and increments the list count. It does not scan existing
entries for identity. The object and dynamic-light enqueue boundaries therefore
have no duplicate suppression. This proves an admission property, not actual
duplicate requests in a reported frame. Node acquisition is not proof of a
fresh heap allocation on every call.

After visiting all five queues, `0x00B5FD60` clears each through `0x00E74D40`
at call sites `0x00B5FFC0`, `0x00B5FFCB`, `0x00B5FFD6`,
`0x00B5FFDD`, and `0x00B5FFE8`. Requests do not remain in these queues forever
merely because the maintenance routine is called every frame.

There are other drain call sites in loading/maintenance paths. Accordingly,
the interval between enqueue and consumption must be described as the next
admitted drain, not as a guaranteed one-frame delay.

### Recurring dynamic light admission and the movement gate

The render-time root path `0x00B5E870` scans the scene's general light list
when scene-node byte `+0x130` permits. For the inspected branch it admits a
non-null native light at wrapper `+0xF8` whose reference count at native-light
`+0x04` is not one. A nonzero wrapper byte `+0xFC` causes an enqueue through
`0x00B5D270` at `0x00B5E8F3`.

The producer does not test position before appending. Thus an admitted
stationary dynamic light still incurs queue-node and reference work for that
root traversal. The render-time producer follows the main-loop lighting drain
in the inspected frame ordering; consumption occurs at a later admitted drain.
The number of root traversals per frame is not established by the call graph.

The consumer's dynamic wrapper `0x00B5D930` supplies an important filter:

- Wrapper byte `+0xF4` and dynamic byte `+0xFC` must be nonzero, and shadow byte
  `+0xEC` must be zero for the inspected reassociation path.
- APP_CULLED on the native light takes a separate membership-clearing path.
- Otherwise, cached position at wrapper `+0x100`, `+0x104`, and `+0x108` is
  compared against native-light position at `+0x8C`, `+0x90`, and `+0x94`.
- Reassociation requires an unequal position and wrapper status `+0x110`
  different from `0xFF`. `0x00B5A9D0` updates the cached position before the
  call to `0x00B5D300` at `0x00B5D9DE`.

`0x00439090` negates the result of `0x004390C0`, whose three component
comparisons use ordered floating-point equality. For ordinary finite
coordinates there is no displacement tolerance: any unequal component admits
the changed-position branch. Exceptional floating-point values must retain
their actual native comparison behavior.

Consequently, a queued stationary dynamic light is not proof of repeated full
reassociation. Conversely, the movement test is exact rather than a spatial
threshold. A new epsilon, rate limit, or earlier producer-side position test
would need an equivalence proof; none is justified here.

### Property dirtying does not mean membership changed

The property list's verified fields are head `+0x60`, tail `+0x64`, count
`+0x68`, dirty byte `+0x74`, and fence pointer `+0x78`.

`0x00B71560` has two different invalidation contracts:

| Property fence state | Search result | Native result |
|---|---|---|
| Fence present | Existing light | Moves the existing node before the fence; returns without setting dirty in this helper |
| Fence present | Absent light | Inserts a node before the fence and sets dirty at `0x00B715AE` |
| Fence absent | Existing or absent light | Sets dirty at `0x00B715DB`; also clears cache key `+0x38` when the light's shadow byte is nonzero |

The fence-absent dirty write is unconditional after the search. It occurs even
when membership already exists. This corrects any interpretation that the
dirty byte denotes only changes in membership identity.

The native existing-membership branch in `0x00B9F480` still calls this helper
at `0x00B9F5A0`. Therefore, finding the geometry already in a light's list does
not skip property invalidation. The new-membership call is at `0x00B9F559`.

Object-driven refreshes begin a property fence through `0x00B718B0`. That
routine acquires a marker node with special light identity `0x011FA310` and
places it at the list head. `0x00B71600` dirties when stale entries remain past
the marker, removes those entries, then removes the marker and clears `+0x78`.
An unchanged object refresh still performs marker acquisition/removal, but the
inspected existing-member branch need not dirty the property.

Light-driven scene traversal uses a different fence on the light's geometry
list. That fence is not the property's `+0x78` marker. The light-driven chain
`0x00B5D300 -> 0x00BA0110 -> 0x00B9F6A0 -> 0x00B9F480`
can therefore reach properties without active property fences and dirty them
even while their light identities remain unchanged. Traversal has bound,
object-type, and flag gates; not every scene geometry is admitted.

This invalidation cannot be classified as redundant solely from unchanged
membership. A light's changed position can change score ordering and staged
selection without adding or removing an identity. Skipping the dirty write on
identity equality is not a qualified fix.

The separate removal helper `0x00B717A0` sets dirty after its unfenced removal
attempt and clears the key for shadow lights. Its contract likewise cannot be
reduced to an identity-change signal without further proof.

### Render time visibility and dimmer transitions

`0x00B5E870` also calls `0x00B9E970` for admitted lights. That routine handles
light visibility/frustum evaluation and distance/fade state. The inspected
frustum branch visits up to six planes; another branch uses a native camera
test. Distance processing includes a square-root helper. Shadow and ordinary
lights have different additional conditions.

This per-light render-time work is separate from the queued movement path.
An unchanged queue or stationary light does not by itself bypass it. Its work
grows with the general light list and admitted branches rather than mesh
triangle count.

The updater compares old/new `+0x110` visibility state against `0xFF` and
old/new dimmer/fade values at `+0xD0` and `+0xD4`. Admitted visibility or
zero/positive dimmer transitions enter a walk of the light's geometry list at
`+0xE0`. For each supported geometry property it sets property `+0x74` at
`0x00B9EEA9`, without requiring membership to change.

It does not unconditionally perform this geometry fan-out on every fade
change or every traversal. The exact floating-point transition gates remain
part of the native behavior. One admitted light transition visits its geometry
memberships, so multiple admitted transitions add work according to the sum
of the affected list lengths. Actual transition frequency and list lengths
remain unknown.

## Actor producers of object lighting updates

The actor loops `0x0096C860` and `0x0096C970` are not unconditional lighting
enqueue loops. Beyond actor/node admission, they require actor byte `+0x14E`
and the node-update result. The accessor `0x0096C950` reads that byte. After
enqueueing, `0x00496960(0)` clears it. The verified setters call
`0x00496960(1)` in model attachment/update paths at `0x00496840` and
`0x00496E10`. All possible direct writes to the byte have not been enumerated.

At `0x0096CAB1`, assembly verifies the false mode argument to
`0x00B5D9F0`, so this path queues the root in scene `+0x108`. The true/false
mode must not be reconstructed from decompiler stack-variable names, which
overlap in this capture.

There is also a separate actor path at `0x0088B150`, called from
`0x00888B50` and `0x008ABFE0`. It has three object-lighting call sites at
`0x0088B391`, `0x0088B471`, and `0x0088B4C5`, controlled by actor/node state
and a byte at actor `+0x18E`. This path does not use the same `+0x14E` admission
test. Consequently, the cleared flag proves a gate for the two specific actor
loops, not a global prohibition on further actor lighting requests.

Assembly verifies true mode at `0x0088B391` and `0x0088B471`, followed by
clearing actor `+0x18E`; the fallback at `0x0088B4C5` uses false mode and sets
that byte. The virtual node getter does not consume the mode argument. Actor,
Character, and Creature slot `+0x1D0` resolve to `0x0043FCD0`, which takes no
stack argument and returns with plain `RET`. The mode pushed before that getter
remains on the stack for `0x00B5D9F0`. This binary ABI check is necessary to
interpret the producer call sites correctly.

The semantics and cadence of every branch in this separate actor path remain
unresolved. It would be incorrect to label every actor lighting request either
per-frame animation work or a rare model-attachment event on the evidence here.
The producer bodies, call sites, flag accessor, setters, and direct-producer
xrefs are preserved in
[native lighting update evidence](../analysis/radare2/output/fnv_location_lighting_update_contract_20261006.txt).

## Quadratic indexed scene-light scans

### Indexed access restarts at the head

`0x00B5AC20` is a thiscall indexed accessor for the scene's general light
list. ECX supplies the scene, one stack argument supplies the unsigned index,
EAX returns the light wrapper or zero, and `RET 4` removes the argument.
It checks the index against scene count `+0xBC`, then reloads head `+0xB4`.
For an in-range index `j`, its loop at `0x00B5AC46` executes `j` iterations
to retrieve that entry. It carries no traversal cursor between calls.

Consequently, successive in-range lookups with indices `0` through `q - 1`
execute exactly this many iterations inside the accessor:

```text
indexed-access traversal iterations = 0 + 1 + ... + (q - 1)
                                    = q * (q - 1) / 2
```

This is an instruction-derived count, independent of triangles, texture size,
light influence, or draw submission. It describes the requested index range,
not a measured scene population. A caller's extra look-ahead lookup can add
further traversal. Index narrowing and termination must be preserved; the
formula does not assume an arbitrarily large valid native list.

### Shadow preparation uses repeated indexed access

The admitted world-render branches call `0x00871290`, which iterates the
scene's shadow-light list. For an eligible entry, the call at `0x0087183E`
invokes `0x00B9D150` with a **null lighting-property argument** and three
position floats by value. ECX is the selected light wrapper. The callee
returns with `RET 0x10`; decompiler stack recovery obscures these arguments,
so the native pushes and stack cleanup are the contract.

The null argument selects the primary scene through `0x011F91C8` and the
indexed accessor. The first lookup is at `0x00B9D2B9`; successive lookups
are at `0x00B9D3E1`. A nonnull property instead selects the property iterators
`0x00B70600` and `0x00B70700`, which advance their stored cursor. The two
branches therefore have different traversal costs.

The first influence scan stops at list termination or forty accepted entries.
The accepted counter is EBX, checked at `0x00B9D2C6` and incremented at
`0x00B9D3A9`. The candidate index is separately incremented at
`0x00B9D3C4` and passed through `MOVZX EAX, DI` to the indexed accessor.
Entries are rejected when the wrapper shadow byte `+0xEC` is nonzero, the
native light is APP_CULLED, or the native dimmer `+0xC4` fails the positive
comparison. Rejection skips the accepted increment but still advances the
candidate index. **Forty accepted entries do not bound this scan to forty
candidate entries.**

Accepted entries also execute distance arithmetic and a square-root call at
`0x00B9D356`, followed by radius-based weighting. A subsequent admitted
accumulation branch starts enumeration again at `0x00B9D529` and makes
successive indexed calls at `0x00B9D8B4`. Its iteration counter and termination
are different from the first scan; do not treat it as an identical second
full scan or silently replace its candidate-to-weight correspondence.

The routine changes native light state: the inspected tail writes the light's
local position at `+0x58`, color/radius-related fields, and increments its
counter at `+0xA8`. It is not
a read-only visibility query. Removing its calculations or reusing results
across entries requires proving their inputs and observable effects.

This path remains conditional. `0x00871290` has native admission checks,
including a bool read through `0x00871A10` from the setting object at
`0x011C74D4`, a selected-shadow budget, and per-entry object-state checks at
`0x008717BE` through `0x008717E9`. The exact setting name is not established
here. The expensive calculation precedes the following per-entry
visibility/dimmer decision at `0x0087184A` through `0x00871879`; that later
decision cannot avoid work already performed. The evidence does not establish
that shadow preparation executes in every reported slow location.

### A separate camera-dependent scan repeats the same traversal

The world-render function `0x00873200` also has two verified camera-lighting
call sites, `0x00874277` and `0x0087432D`, both targeting `0x00B803B0`.
Each passes the camera obtained from the world scene graph through
`0x006629F0`. The retained
[camera contract output](../analysis/ghidra/output/perf/graphics_fnv_ao_temporal_camera_contract_audit.txt)
records this provenance; the new native capture rechecks both call sites.

`0x00B803B0` passes the primary scene in ECX to `0x00B5BCA0` at
`0x00B803F0`, with camera position, a camera-derived direction, and an output
vector as its three stack arguments. `0x00B5BCA0` returns a bool in EAX and
cleans those arguments with `RET 0x0C`. The caller consumes the result and
updates globals beginning at `0x011FED90`. This is a separate consumer from
the per-shadow routine; the downstream visual use of every output global
is outside the closed contract.

This helper initially calls `0x00B5AC20(0)` at `0x00B5BE2B`. For subsequent
entries it contains an **inlined copy of the indexed traversal**:

- `0x00B5C03A` increments the candidate index and `0x00B5C03B` narrows it to
  sixteen bits.
- `0x00B5C042` checks the narrowed index against scene count `+0xBC`.
- `0x00B5C04A` reloads list head `+0xB4`.
- `0x00B5C05B` through `0x00B5C065` walk from that head to the indexed entry.

Successive candidates therefore repeat the triangular traversal work even
though the external accessor has only one direct call in this helper.
Optimizing the accessor alone would leave this inlined consumer untouched.

The loop checks a scratch offset against `0x4B0` at `0x00B5BE4B` and adds
`0x0C` at `0x00B5C017` for an accepted entry. That permits one hundred accepted
entries. APP_CULLED lights branch at `0x00B5BE63` directly to candidate
advancement at `0x00B5C036`, bypassing the scratch increment. Again, the
accepted limit does not cap the number of candidates traversed.

The main admission gate differs from shadow admission. Before this scan,
`0x00B5BCA0` calculates the mean of primary native light `+0xC4` multiplied
by its three `+0xD4`/`+0xD8`/`+0xDC` components. For finite values greater
than the native threshold at `0x010228A0`, it takes a directional fallback
instead of enumerating the general list. Values at or below the threshold
admit the scan. The actual threshold, scene inputs, and branch use in the
reported locations are not established as workload facts. The two world
call sites are not proof of two expensive scans in every frame.

### Consequence and remaining contract

These two consumers prove a second concrete algorithmic inefficiency beyond
property sorting: repeated indexed retrieval from a linked list. The relevant
cost is the visited candidate prefix, multiplied by admitted consumer calls.
Large prefixes of rejected entries still cost CPU traversal. Neither the
source property's shader-light staging limit nor the number of triangles
places a bound on these loops.

A sequential traversal could remove head restarts, but this is only a research
target. Before any replacement, close list lifetime and mutation/concurrency,
null-entry termination, sixteen-bit index behavior, candidate order, both
accepted limits, arithmetic and side effects, every caller, and the installed
provider. No such replacement is implemented or qualified here. Actual prefix
lengths and elapsed cost remain unknown.

Native accessor, consumer, caller, gate, and tail output is preserved in
[light scan and cache evidence](../analysis/radare2/output/fnv_location_light_scan_cache_contract_20261006.txt).

## Quadratic lighting property sorting

### Verified loop structure

`0x00B70390` sorts the property's doubly linked light list at `+0x60`.
For each current entry, it starts a search at the list head, calculates scores
for preceding entries, and inserts the current entry before the first strictly
greater score. Equal scores preserve their order under the native comparison.

The current entry's score is calculated at `0x00B703CE`; preceding entries'
scores are recalculated at `0x00B703FE`. Both calls target `0x00B9DBE0`.
That scoring path performs vector-distance arithmetic, a square-root helper,
bound-radius subtraction, and light-radius division, and writes the resulting
score into the light object at `+0x0C`.

For an already ordered list of `k` entries, the current entry has to pass every
preceding entry. The exact loop counts are:

```text
preceding-entry comparisons = k * (k - 1) / 2
score evaluations          = k + k * (k - 1) / 2
                           = k * (k + 1) / 2
```

Thus already sorted input retains quadratic work. These counts follow the
instructions; they do not assume an actual list size or translate into FPS.
Small or infrequently sorted lists could make the total cost modest.

The retained proof includes the sections `PPLighting light-list sorter` and
`RAW FUNCTION: PPLighting light-list sorter` in the
[light selection continuity closure](../analysis/ghidra/output/perf/graphics_fnv_pbr_light_selection_continuity_closure.txt).

### Score input and terminology

In `0x00B67BE0`, the sphere supplied to the sorter is copied from the geometry's
bound pointer at geometry `+0x20`, with the native fallback when absent.
Camera-distance calculations elsewhere in that updater are separate.

The earlier
[light and shadow continuity plan](graphics_fnv_pbr_light_shadow_continuity_fix_plan.md)
describes the sorter as performing camera-distance ordering. For this audit,
use the actual bound argument and scoring instructions as the contract; do not
replace that argument with camera position on the basis of the earlier wording.

### Invocation gates and cache behavior

The verified sorter call sites are:

| Caller entry | Sort call site |
|---|---|
| `0x00B67BE0` | `0x00B6823E` |
| `0x00BB4740` | `0x00BB4F0E` |
| `0x00C058F0` | `0x00C06075` |

The inspected `0x00B67BE0` path can bypass the rebuild when the property cache
key at `+0x38` matches, the relevant caller mode permits reuse, and the dirty
byte at `+0x74` is clear. Material/property conditions further gate the sorter
call. Sorting a changed order clears the cache key at `+0x38`.

Shader staging has a bound of eight slots and native render-pass storage has
ten light entries in the retained contract. Neither bound caps the linked
source list before this sorter traverses it. Those storage bounds must not be
used as proof that sorting considers only the lights ultimately staged.

The other two callers have a different immediate contract. At `0x00BB4EDA`
and `0x00C0603D`, a nonzero property dirty byte admits sorting before the
subsequent cache-key decision. If sorting changes order, the sorter clears the
key. If the key still matches and the property is dirty, these callers can
walk existing pass records and refresh their light identities or counts;
that refresh can itself force rebuilding when pass requirements no longer
match. Dirty therefore does not necessarily mean discarding every cached pass.

These gates are preserved in
[native lighting update evidence](../analysis/radare2/output/fnv_location_lighting_update_contract_20261006.txt)
and the retained continuity closure. The three callers do not have identical
reuse behavior. No claim of sorting every object every frame is supported.

### Score inputs and ABI constraints

The score helper `0x00B9DBE0` is a thiscall boundary: ECX supplies the light
wrapper, one stack argument supplies the bound pointer, the return is in x87
ST0, and `RET 4` removes the argument. The decompiler's inferred `void` return
is incorrect for the inspected native caller usage.

In addition to bound center/radius and native-light position/radius, the helper
reads the primary scene's lighting offset through `0x011F91C8` and scene fields
`+0x1E4`, `+0x1E8`, and `+0x1EC`. It rounds translated position components,
deltas, the squared-distance sum, the square-root result, and the final score
through single-precision stack storage at the inspected instruction boundaries.
The final single-precision score is reloaded to ST0 and written to wrapper
`+0x0C` at `0x00B9DCA3`.

`0x00B70390` is also thiscall with one stack bound-pointer argument and
`RET 4`. It preserves EBX, ESI, EDI, and EBP, relinks existing list nodes,
and does not change the list count or acquire new nodes. Ordered equal keys
are not moved; the comparison branch also does not move an entry for an
unordered comparison. Replacing that comparison with a generic total ordering
would require a separate equivalence argument.

The distinct array branch in `0x00B5DAC0` already calculates each admitted
candidate's score before sorting. Its comparator `0x00B5AA70` reads stored
`+0x0C` scores and orders them in the opposite direction for ordinary finite
scores: it returns negative when the first score exceeds the second. It is
not an interchangeable replacement for the ascending property-list sorter.
Its native sort also does not provide the property sorter's stable equal-key
contract merely because both consume the same score field.

These facts close the immediate scoring ABI and comparison direction. They do
not prove immutability of every scoring input throughout all callers, exclusive
ownership of the shared `+0x0C` scratch field, or complete thread/lifetime safety.

### Shared-score lifetime and additional cache gates

The light wrapper constructor `0x00B9FDA0` initializes `+0x0C` to zero with
`FLDZ` followed by `FST [ESI + 0x0C]` at `0x00B9FEC2`. The scoring helper
subsequently overwrites that field with a score for its supplied bound. The
array comparator's reads at `0x00B5AA7A` and `0x00B5AA83` remain verified
consumers. These checks do not enumerate every possible reader or writer;
the field's reference-header name, `fLuminance`, does not prove an additional
native luminance calculation or a bound-independent cached value.

Radare2 reports a spurious comparator xref from `0x00B5C505`. The actual
instruction calls the separate child-accessor function `0x00B5AA40`, which
ends before the comparator's entry. The aligned native window distinguishes
the two. Automatic xref output cannot be used as complete consumer coverage
without checking the referenced instruction and function boundary.

Additional verified cache behavior narrows the earlier invalidation question:

| Native boundary | Proven cache-key behavior | Work it does not eliminate |
|---|---|---|
| Fade staging `0x00BA8AB0` | For finite inputs, clears `+0x38` when old/new fade cross between `< 1.0` and `>= 1.0`; otherwise stores fade `+0x28` without clearing the key | The call and preceding fade/distance preparation still occur |
| Material flag updater `0x00B68B10` | Clears `+0x38` when its derived `+0x20` bit `0x1` changes, or when bit `0x100` is set; clears bit `0x100` before return | Its admitted texture/material scan and per-entry byte updates remain |
| Dirty cached-pass refresh in `0x00BB4740` | Matching key plus dirty byte admits a walk of existing pass entries, then clears dirty at `0x00BB50B1`; a still-matching key returns without rebuilding at `0x00BB50BC` | Sorting and any admitted light-list scans have already occurred |

The fade result is a category-transition gate, not evidence of invalidation
on every continuous fade change. The material updater similarly tests state
before clearing the key; its mere invocation does not imply a rebuild.

The dirty cached-pass refresh has additional size-dependent work. For pass
IDs `0x17F` through `0x1BA`, it scans the eligible property lights once to
count them (`0x00BB4F87`/`0x00BB4F99`) and starts another traversal to fill
the pass's light-pointer array (`0x00BB4FCC`/`0x00BB4FFA`). It can grow that
array through `0x00BA8C30` and `0x00BA8C00` when recorded capacity is too small.
This occurs inside a loop over cached pass entries; cache reuse can therefore
retain repeated list scans without constructing a new pass collection.
It is conditional on dirty state and the relevant pass IDs, not the cost
of an ordinary clean cache hit.

Those property iterators advance an existing cursor and test wrapper
visibility `+0x110`, native APP_CULLED, and shadow byte `+0xEC`. A small number
of eligible lights does not imply a small traversal prefix, but this cursor
path does not have the indexed head-restart cost described above.

These are proven additional writers and reuse paths, not complete enumeration
of cache invalidation. Controller/material writes, property sharing/copying,
all scoring-input mutations, and concurrent field access remain unresolved.
Both score and cache checks are retained in
[light scan and cache evidence](../analysis/radare2/output/fnv_location_light_scan_cache_contract_20261006.txt).

### Potential intervention and unresolved contracts

The smallest identifiable opportunity is to avoid recalculating each score
inside the predecessor loop. A different stable sorting algorithm could also
reduce comparison growth. Neither design is approved or qualified here.

A later implementation must preserve score side effects, native x87 rounding
and comparison behavior, equal-key ordering, unordered/exceptional values,
list node identity and ownership, cache invalidation, and all caller contracts.
Scratch allocation costs also matter for small lists. Persistent score caching
requires proving every input invalidation and lifetime; this audit does not
provide that proof. Changing selection, imposing a new candidate cap, or
adding comparator hysteresis would change behavior rather than merely remove
redundant work.

## Geometry and render pass dispatch

The ordinary batch drain at `0x00B9A120` visits render-pass entries and calls
`0x00B994F0` for each entry. That dispatcher publishes current-pass state and
enters `0x00B98E80`, which prepares geometry buffers through `0x00E88DC0` and
executes the relevant shader callbacks.

The inspected callback path includes shader setup slots `+0x78` and `+0x7C`,
conditional additional setup, draw at shader slot `+0x6C`, a geometry callback
at `+0xE0`, and shader teardown at `+0x8C`. Pass-specific branches differ.

The engine caches shader/state information; it does not blindly repeat every
possible state change. Ordinary pass registration at `0x00B99B00` also appends
entries without a quadratic insertion search. Those are existing optimizations.

Nevertheless, grouping geometry/pass records does not itself coalesce their
geometry. The verified ordinary path still dispatches individual records.
This is not a claim that every native path lacks instancing, or that one record
always maps to exactly one terminal D3D draw call.

The resulting CPU work depends on geometry/pass entries and their setup, even
if each mesh has few triangles. Microsoft's
[D3D9 performance guidance](https://learn.microsoft.com/en-us/windows/win32/direct3d9/performance-optimizations)
treats primitive batching and reducing state changes as separate performance
concerns. That guidance explains the mechanism; it does not measure FNV.

Retained native evidence is in the
[selector and draw identity bridge](../analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_selector_vtable_draw_identity_bridge_audit.txt)
and the `current draw apply dispatcher` section of the
[close terrain pass entry contract](../analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_entry_runtime_contract.txt).
The ordinary batch loop and dispatch were also checked directly in the binary.

The native pass map's small bucket count was considered, but reference source
already contains bucket-size tuning. Its keys are pass categories, not an
unbounded object-identity set. Current installed overrides and collision cost
were not established. It is not identified as a newly discovered major root
cause or a justified compatibility intervention.

## Scene updates and visibility traversal

The verified NiNode virtual-table mapping at `0x0109B5AC` includes:

| Slot | Native target | Inspected behavior |
|---|---|---|
| `+0xA4` | `0x00A5DD70` | Full downward update |
| `+0xA8` | `0x00A5DED0` | Selective downward update |
| `+0xAC` | `0x00A5E1F0` | Rigid downward update |
| `+0xD4` | `0x00A5DBE0` | Visibility traversal |

The child-array pointer is at `+0xA0`; traversal uses the extent at `+0xA6`
and skips null children. Full update can run controller/world-data operations,
visit children, and merge bounds. Selective and rigid variants test flags for
controller, transform, descendant, and bound work rather than running every
operation unconditionally. The fixed-bound flag suppresses relevant merges.

The visibility path visits admitted children through `0x00A59E00`, where
APP_CULLED and the culling process participate. Native frustum and
portal/multibound paths also exist. Their presence does not establish that all
potentially expensive objects are rejected early enough to avoid other phases.

The verified cost is traversal over admitted scene structure, independently
of triangle count. It is not proof that every hidden object updates controllers,
transforms, and bounds every frame. These virtual-table targets and flag gates
were direct binary checks. Reference names/layouts came from the read-only
[NiAVObject header](../.research/fnv-depth-resolve-main/DepthResolve/internal/Game/Gamebryo/NiAVObject.hpp).
Related retained culling evidence is in the
[frustum and LOD culling audit](../analysis/ghidra/output/perf/graphics_fnv_taa_frustum_lod_culling_contract_audit.txt).

## Actor work outside combat

The worker setup at `0x008C7290` selects one AI linear worker for the lower
processor-setting branch, or two AI linear workers with entries
`0x008C7DA0` and `0x008C7F50` for the higher branch. This describes these
particular workers, not a global two-thread limit: other task and IO systems
exist, and some actor paths can dispatch additional tasks.

The two-worker pipeline uses stage events and cross-worker waits through
`0x008C7A70`. The join at `0x008C7990` walks the two worker slots and calls
`0x008C7490`, which reaches `0x004424E0` and waits for worker completion.
The relevant waits use `WaitForSingleObject` with an infinite timeout.
Infinite timeout means waiting until completion; it does not imply a hang or
prove a large normal wait duration.

`0x0096DB30` walks the actor processing range and invokes virtual slot
`+0x348` for actors admitted by state checks. Binary virtual-table reads verified
`0x00886CB0` at that slot for Actor, Character, and Creature. The actor update
body includes animation/movement/physics-related branches without a blanket
combat gate.

`0x0096C330` also walks an active actor range and contains player-related
detection work with state and timer conditions. This inspection did not prove
a universal all-actors-against-all-actors quadratic detection loop.

More admitted actors means more iterations of these particular loops. The
stage dependencies can constrain progress, and the frame eventually joins
remaining work. These facts explain why absence of combat does not eliminate
simulation costs. They do not identify the actor pipeline as the measured FPS
bottleneck in a particular location.

Retained evidence is in the worker/stage sections of
[combat performance deep analysis](../analysis/ghidra/output/perf/combat_perf_deep_dive.txt),
the actor loops in
[AI thread deep analysis](../analysis/ghidra/output/memory/ai_thread_deep.txt),
and `AIWorker_FUN_0096db30` in
[AI and main thread parallel work](../analysis/ghidra/output/memory/ai_main_thread_parallel_work.txt).

## What occlusion can and cannot avoid

Low polygon counts do not make occlusion inherently ineffective. Rejecting an
object before expensive downstream preparation can avoid CPU dispatch work as
well as GPU work. The relevant question is which operations rejection prevents
and how much the additional culler costs.

A visibility rejection in the world draw cannot retroactively avoid lighting
maintenance performed earlier in the main-loop sequence. Nor does dropping a
draw automatically eliminate actor simulation. Moving rejection earlier would
require proving which skipped updates affect lighting, animation, ownership,
and later visibility; this audit does not authorize that change.

The inspected workspace contains a vendored IntelMOC library, but an integration
path sufficient to establish its rejection placement and avoided native work
was not identified. Its net performance benefit or loss remains unknown.
Library presence is not evidence of an active runtime path.

Native culling and selective updates already remove some work. Additional
occlusion must address work still admitted by those mechanisms. A second
visibility test alone does not prove a gain, and rejecting objects by a new
heuristic is not an equivalent optimization.

## Other explanations and limits

Streaming and cell transitions can create location-dependent work, but some
inspected cell-update paths are gated by movement/coordinate changes. Their
existence is not proof of a sustained stationary FPS loss. The existing
[parallel IO engine contract](parallel_io_engine_contract.md) owns the detailed
IO and loading contracts; this audit does not propose worker-topology changes.

GPU shader work, shadow rendering, transparency/overdraw, scripts, and
Proton/Wine or driver synchronization remain outside the attributed results.
Low texture resolution and simple meshes do not statically exclude them.
No verified synchronous occlusion-query stall was found that would justify
calling GPU readback the root cause.

Current Psycho optimizations improve several existing subsystems, but their
presence does not establish that these native loops are cheap or that the
reported locations still use every unmodified native provider. Read-only
reference mod source likewise cannot establish which hooks are installed in
the owner's running game. A future intervention must preserve the active
provider and capability-based compatibility rather than identify or patch mods.

## Static research priorities and implementation boundary

The following order reflects specificity of the evidence and remaining gaps
in correctness contracts. No measured ranking of FPS impact is required to
advance a candidate. Actual populations and timings affect the size of a
possible benefit, not whether proven redundant operations are a valid target.

1. **Lighting-property sorting:** the immediate scoring ABI, offset inputs,
   stored score, comparison direction, and alternate dirty gates are established.
   Next close all shared-score consumers, input mutation/threading, list
   ownership, and the full invalidation contract. The redundant score evaluations
   remain the smallest concrete algorithmic target.
2. **Indexed scene-light consumers:** head restarts are proven in both the
   shadow-influence routine and the separate camera-dependent helper. Close
   the list's mutation/lifetime/threading contract, index narrowing and
   null-entry behavior, all consumer gates, and output dependencies before
   considering cursor traversal. The inlined consumer must be included;
   replacing only `0x00B5AC20` would leave its quadratic loop intact.
3. **Light assignment and pass invalidation:** the key enqueue boundaries,
   dynamic movement filter, unfenced dirtying, and visibility-transition fan-out
   are established, along with additional fade/material invalidators and
   dirty-cache light refresh. Next close remaining actor/direct queue producers,
   candidate populations, shared-property lifetimes, and all cache-key writers.
   Duplicate suppression or narrowed invalidation must preserve update order,
   final lighting inputs, and the active provider; neither is qualified here.
4. **Geometry/pass dispatch:** trace actual terminal submissions and native
   state reuse for the affected pass families. Removing callbacks or merging
   records requires proving material, transparency/order, buffer, resource,
   and ownership equivalence.
5. **Actor stages:** close which stage inputs and ownership dependencies impose
   the waits. Thread count changes or removed barriers are not justified by the
   existence of parallelism limits.

No safe patch point is fully qualified by this audit. Native light lists and
render-pass caches remain engine-owned. Actor stages remain subject to their
existing synchronization. The documented addresses and partial ABI/layout
facts are research anchors, not complete hook contracts.

The conclusion is limited to static identification of scaling mechanisms and
redundant algorithmic work. Root-cause attribution to a reported
location, runtime equivalence of a future optimization, and an FPS improvement
remain unproven. Profiling or debug builds are not requested as prerequisites
for preserving or continuing this static research.

## Planned Psycho engine-fix changes

Original plan status: the owner authorized proceeding with this plan and explicitly approved
unreleased, statically qualified candidates without a real-runtime baseline
on 2026-10-06. Native-contract closure remains a prerequisite for production
edits. Ownership, ABI, lifetime, math, synchronization, and compatibility proofs
are not waived. Unknown FPS attribution is not an implementation blocker.
The plan extends the static evidence above and keeps unresolved contracts
explicit. It does not claim that either consumer explains the reported FPS loss.

The later instruction to implement candidates, given after the unresolved
contracts were reported, supersedes this original pre-edit gate for the two
default-off unreleased experiments. The implementation section below records
what now executes, its exact admission limits, and what remains unproved.
The original plan's complete contract requirements remain acceptance criteria
for promoting an experiment to an accepted engine fix.

The implementation below is split into two independent deliveries. Contract
closure is a prerequisite for the affected production edit, not a substitute
for that edit. Once admitted, each delivery must execute its reduced-work path;
adding settings and permanently forwarding every call is not completion.

### Ownership, configuration, and integration

Both optimizations belong in the early-loaded core DLL's existing `mods::perf`
subtree. They must remain independently selectable and independently
transactional. OMV, shader code, D3D resources, allocator topology, and actor
worker topology are outside these changes.

| Planned file | Change and purpose |
|---|---|
| `psycho-engine-fixes/src/mods/perf/light_property_scores.rs` (new) | Own the sorter contract, native score adapter, optimized operation, provider admission, and installation for fix 1 |
| `psycho-engine-fixes/src/mods/perf/scene_light_scan.rs` (new) | Own the two native consumers, cursor lifetime, loop bridges, and one complete installation transaction for fix 2 |
| [Performance module](../psycho-engine-fixes/src/mods/perf/mod.rs) | Declare the modules and integrate their installation/publication with existing performance lifecycle routing |
| [Core startup](../psycho-engine-fixes/src/startup.rs) | Integrate preparation at the established core startup boundary without reordering existing fixes |
| [Core configuration](../psycho-engine-fixes/src/config.rs) | Extend `PerformanceConfig`, `RawPerformanceConfig`, defaults, and raw-to-runtime conversion for the two independent switches |
| [Shipped TOML](../psycho-engine-fixes/config/psycho_engine_fixes.toml) | Document restart-only switches and native fallback behavior |
| This document | Retain final binary contracts, chosen patch windows, evidence, and qualification status |

Proposed setting names are `performance.light_property_score_reuse` and
`performance.scene_light_sequential_scan`. Both should default to false while
the candidates are unqualified. Existing configurations must retain all
current defaults and legacy-key behavior. A default-on release decision is
separate from this plan. Settings are read once at startup, with full restart
required; no frame polling or live executable-memory writes are planned.

The helper does not own or install either fix. Its current
[configuration editor](../psycho-engine-fixes-helper/src/dashboard_config.rs)
clones the parsed TOML document and updates recognized keys, preserving unknown
keys and comments. Therefore the initial core/TOML options do not require a
helper change merely to survive a dashboard save. Adding visible dashboard
controls is outside this initial core plan. Preserve the existing event ABI,
helper load behavior, and core/helper ownership boundary.

### Fix 1: reuse scores inside one native property sort

**Target behavior.** Preserve the light list produced by `0x00B70390` and its
cache effects while eliminating repeated predecessor scoring. Keep the
existing ascending stable insertion behavior; comparison growth remains
quadratic. This change targets expensive score calculations, not comparison
count or light selection.

**Preferred algorithm.** Retain the current-entry call to native score helper
`0x00B9DBE0`, corresponding to `0x00B703CE`. The helper already stores the
rounded result in the wrapper at `+0x0C`. During predecessor comparison, use
the score written when that predecessor was processed earlier in this same
sort, rather than repeating the helper call corresponding to `0x00B703FE`.
Retain the native comparison, relinking rules, moved flag, and conditional
cache-key clear at `0x00B70480`.

Use a private, compiled x86 assembly sorter entered through the three caller
bridges below. Preserve the verified native control flow and frame layout.
Its current-entry scoring call invokes the qualified native scorer. Replace
only its predecessor-scoring operation with a private thiscall adapter that
loads wrapper `+0x0C` into ST(0) and returns with `RET 4`. The pushed bound
argument is therefore consumed exactly as in the original operation. Retain
the native `FCOMP`, `FNSTSW`, and comparison branch after that call. Rust owns
installation, admission, and failure reporting; it does not calculate distance
or implement a different sort. Use the existing `#[unsafe(naked)]` /
`naked_asm!` pattern for these native boundaries.

Do not patch the shared native sorter body. This keeps unadmitted callers on
their captured provider and avoids a global optimization mode or per-thread
sort context. A single private assembly implementation serves all three
admitted bridges; their predecessor targets remain separate.

This design needs no separate precomputation pass, score array, lookup map,
cross-frame cache, or new per-thread owner. Each current entry still executes
the real native scoring helper. The field's use as invocation-local scratch
must be proven; existing field presence alone is not permission to reuse it.

The necessary invariant is that every compared predecessor has already been
scored for the same bound during this invocation and its stored score has not
changed since then. The native traversal establishes the processed-prefix
part under an intact-list/no-external-mutation condition, as detailed below.
Close the remaining conditions against reentrancy, shared-light access,
and all readers/writers of wrapper `+0x0C`. Also prove stability of
native-light position/radius, primary-scene offsets, and the bound throughout
the operation. If this cannot be proved, the preferred algorithm is blocked;
do not introduce persistent caching to bypass the gap.

**Intervention scope.** The preferred admission boundaries are the three
verified sort callers:

| Native caller | Sort call site | Existing target |
|---|---|---|
| `0x00B67BE0` | `0x00B6823E` | `0x00B70390` |
| `0x00BB4740` | `0x00BB4F0E` | `0x00B70390` |
| `0x00C058F0` | `0x00C06075` | `0x00B70390` |

Prefer an ownership-aware caller bridge that captures the installed target
and invokes the optimized sorter only for a proven native contract. Preserve
the caller's existing dirty/material/cache gates. A different or modified
provider must continue through its captured target unchanged; do not bypass
it by calling a hard-coded vanilla address. Full caller coverage and entry/body
ownership still need qualification before fixing the exact hook layout.

The optimized sorter must preserve thiscall ECX, its single bound-pointer
stack argument, `RET 4`, nonvolatile registers, node identities, head/tail,
count, reference counts, fence state, dirty state, and native cache-key rules.
It must preserve x87 stack balance, control-word assumptions, single-precision
score rounding, equal/unordered comparison behavior, and all externally
observable score/math side effects. Do not replace the native scorer with a
Rust distance formula. Verify compiled ABI and generated instructions for the
actual 32-bit adapter; select a small assembly boundary if the required ABI or
comparison cannot be guaranteed by the compiled Rust path.

Any exceptional-value or unsupported-provider fallback must be chosen before
list mutation and must execute the original operation, not skip sorting.
Do not discover an unsupported case halfway through mutation and then call
the original against altered state without a proven equivalent handoff.

**Work budget.** For an admitted stable-input list of `k` entries, the proposed
score-call count is `k`, compared with `k * (k + 1) / 2` for the native ordered
case. Native predecessor comparisons and relinks remain unchanged. A bridge
adds dispatch/admission cost; it must not add routine allocation, blocking
locks, file I/O, or per-call logging. These are conditional operation budgets,
not a claim of measured CPU-time or FPS improvement.

### Fix 2: traverse each admitted scene-light scan sequentially

**Target behavior.** Preserve the candidate sequence, filtering, accepted
limits, influence arithmetic, and output side effects of both identified
consumers while removing repeated traversal from the list head.

The scope includes all repeated enumeration in `0x00B9D150` and the inlined
enumeration in `0x00B5BCA0`. Changing only indexed accessor `0x00B5AC20` is
insufficient and is not the planned fix.

| Consumer | Existing traversal | Planned intervention |
|---|---|---|
| `0x00B9D150`, null-property first scan | Index zero at `0x00B9D2B9`, subsequent indices at `0x00B9D3E1` | Invocation-local cursor over the primary scene's general light list |
| `0x00B9D150`, admitted subsequent accumulation | Restarts at `0x00B9D529`, then indexed calls at `0x00B9D8B4` | Reset the cursor at this scan's own start; preserve its distinct iteration/weight correspondence |
| `0x00B5BCA0` | Initial indexed call at `0x00B5BE2B`, repeated inlined head walk at `0x00B5C04A` through `0x00B5C065` | Cursor advancement inside this consumer's existing loop |

Prefer narrowly bounded native loop bridges that retain the native arithmetic
and output blocks. Do not rewrite the complete shadow/camera lighting functions
as a first implementation. Do not replace the global indexed accessor's
contract for unrelated callers.

Cursor state must belong to one invocation and one enumeration pass, with no
retained node beyond that pass. Nested or concurrent calls need separate
state. A stack/register location and bridge resume point must be selected from
complete native liveness and control-flow proof; no unused slot, spare
register, enlarged frame, or scratch-field owner is assumed by this plan.
If a safe local intervention cannot be established, stop this design rather
than adding an unsynchronized global cursor or new TLS cache.

Prove the list's writer coverage, retirement ownership, and synchronization
across each enumeration. The engine's repeated lookup re-reads the head/count;
a sequential cursor is equivalent only under a proven mutation contract.
Retaining a node pointer or adding a reference count is not a substitute for
that proof. Neither extra retains nor new locks are planned.

Preserve null-payload termination, count checks, look-ahead behavior,
original traversal order, and distinct accepted counters. The first shadow
scan and the camera scan narrow lookup indices to sixteen bits; the shadow
accumulation scan passes a full thirty-two-bit index. At a narrowed-index
wrap, preserve the native head restart or use an evidence-backed admission
policy that falls back before modifying state. Do not narrow the second scan.
Rejected candidates must continue to advance. Forty accepted entries
in the shadow routine and one hundred accepted entries in the camera-dependent
routine are unchanged. Preserve primary-light brightness/shadow admission,
the nonnull-property iterator branch, and native position/color/radius/counter
writes. Output selection and accumulation order must remain identical.

The proposed traversal budget is linear in the visited candidate prefix per
enumeration, replacing its triangular head-walk work. Resetting for another
native enumeration is intentional; this plan does not assume two scans consume
identical candidates or permit reusing one scan's outputs in another.

Treat the two consumer modifications and their required bridges as one complete
fix-2 transaction. A failed signature, ownership, or bridge check must leave
the original paths intact or roll back the owned changes. Do not report the
fix as installed if the inlined consumer remains unhandled.

### Concrete patch and bridge layout

Fix 1 installs three `Rel32CallHookContainer` instances, one at each sorter
CALL listed above, in one transaction. Before any hook can execute, publish
its captured predecessor. The dispatch boundary selects either the private
assembly sorter or that exact predecessor before scoring or relinking begins.
It must not recover a missing predecessor by calling a hard-coded vanilla
entry. An installation error leaves the affected option unavailable and the
native/provider operation intact.

Fix 2 installs these eight interventions in one separate transaction:

| Site | Mechanism | Bridge responsibility |
|---|---|---|
| `0x00B9D2B9` | Five-byte CALL hook | Reset first shadow cursor; retrieve index zero |
| `0x00B9D3E1` | Five-byte CALL hook | Advance first cursor, preserving narrowed-index head resets |
| `0x00B9D529` | Five-byte CALL hook | Reset accumulation cursor independently; retrieve index zero |
| `0x00B9D8B4` | Five-byte CALL hook | Advance accumulation cursor with the full-width index |
| `0x00B5BE30` | Six-byte owned patch | Initialize camera cursor after the existing native lookup; replay wrapper store and comparison |
| `0x00B5BE69` | Six-byte owned patch | Transfer camera cursor to the brightness temporary; replay argument load and x87 pop |
| `0x00B5BED2` | Six-byte owned patch | Transfer camera cursor back; replay direction store and native zero load |
| `0x00B5C04A` | Six-byte owned patch | Retrieve the next candidate sequentially or perform the complete native head walk |

The CALL adapters retain ECX as scene receiver, one stack index, EAX as wrapper
result, and `RET 4`. Their cursor is at adapter-entry `ESP + 0x70` before any
adapter saves. The camera patches use an instruction-aligned `JMP rel32` plus
padding to occupy six bytes, with checked encoding into module-owned storage
that lives for the process. Use `OwnedCodePatch` for exact native windows;
reject a foreign window rather than constructing an unproven trampoline.
The displaced instructions and exact resume addresses are recorded in the
cursor-storage closure below. The head-walk replacement resumes at
`0x00B5C067`; its native-mode branch must reproduce the entire displaced walk,
not only the first head load.

The camera's initial getter CALL at `0x00B5BE2B` remains in place. Qualification
must establish that its active target is the expected native accessor before
connecting its result to a retained head node. Keep the two native shadow
passes independent, with their distinct null handling and weight counters.
Do not alter accepted caps, output scratch addresses, candidate filtering, or
lighting arithmetic.

**Invocation admission.** Establish one mode at the start of each enumeration,
before a retained node can be read. For a qualified native frame, a zero
cursor can represent native mode; a nonzero cursor represents the admitted
node. Initialize shadow state at each index-zero boundary and camera state at
`0x00B5BE30`. A native-mode lookup invokes that call site's captured accessor
or the original camera head walk. Reset on each native pass and preserve the
first/camera index wrap. No cursor survives the pass.

The camera transfers must preserve the native-mode marker as well as an active
cursor across accepted candidates. Otherwise a native vector float could be
misread as a node after the vector overwrites `C + 0x64`. The APP_CULLED path
skips both transfers and retains the existing marker. Check count admission
before any retained-node dereference. Preserve all live registers, flags, and
x87 values when performing integer bookkeeping.

These bookkeeping writes are allowed only for the proven native frame and
dead-temporary intervals. A foreign consumer/frame must receive the unchanged
displaced/provider operation without new frame writes. Before implementation,
prove how all bridges observe the same invocation admission, including an
inert invocation spanning readiness publication and any provider mismatch.
Global readiness by itself is not that proof; re-evaluating it independently
at every bridge can admit an uninitialized cursor. The plan permits no TLS,
global cursor, new lock, or extra retain to conceal this gap.

### Capability checks and work budgets

Each module owns an explicit table of contract-bearing native ranges and its
installed bridge bytes. Produce that table from the supported executable
before production edits, with a reason for each range. Fix 1 includes the
sorter, scorer, admitted CRT route, and the caller slices that establish bound
ownership and dispatch. Fix 2 includes both complete native consumers, the
accessor, the relevant iterator/normalizer callees, and every patched window.
Do not accept a changed body because its entry address or first instructions
still match. Account explicitly for Psycho's own installed CALL/JMP bytes.

Prepare and validate these ranges at startup, then recheck applicable ownership
at the operation's admission boundary or prove its immutable-provider lifetime.
The module must also exclude provider/body replacement during an admitted
invocation. No signature check is a synchronization primitive. Final range
coverage and provider lifetime remain pre-code contract deliverables.

Existing `CodeSignature::read()` produces a `Vec`, and hook-container ownership
queries acquire a read lock. They are suitable for setup, not per-light work.
The hot admission check must compare qualified, process-lifetime mapped ranges
without allocation, blocking locks, logging, or repeated WinAPI queries. Keep
that mechanism local to these modules; no shared-library redesign is planned.
The compiled assembly boundary must preserve live engine x87 state around any
Rust dispatch, with its alignment and register contract established explicitly.

For fix 1, settle the math domain before relinking: the candidate native
control word is `0x027F`, with valid x87 stack/exception state and finite stable
scoring inputs as described below. A qualification prewalk, if selected, may
read inputs but must not score or modify the list. Its existence does not prove
exclusivity. Unsupported input or provider uses the full predecessor operation
before optimized mutation; no halfway fallback is planned.

Report three separate deterministic budgets: admission work, scalar scoring,
and list traversal/comparisons. Fix 1 must retain `k` native current-score calls
for an admitted `k`-entry list and remove predecessor helper calls; comparisons
remain quadratic. Fix 2 must advance once per successive admitted candidate
within each index cycle, with the native resets and separate passes retained.
Include the cost of signature checks, any input prewalk, and bridge transfers.
No arbitrary small-list threshold or elapsed-time/FPS benefit is assumed.

### Installation, compatibility, and failure containment

Reuse the existing core primitives where their contracts fit:
[direct-call hooks](../libpsycho/src/os/windows/hook/callsite.rs),
[owned code patches](../libpsycho/src/os/windows/patch.rs), and
[modification transactions](../libpsycho/src/os/windows/hook/transaction.rs).
They provide ownership-aware restoration, but do not establish quiescence,
native ABI, object lifetime, or correctness of a proposed patch window.

The current core installs performance hooks from `install_runtime_hooks`
during startup, and performance lifecycle notifications already arrive through
`PsychoEngineFixes_NotifyEvent`. The initial lifecycle design is to prepare
any required inert bridges at the established quiescent pre-CRT boundary,
then qualify ownership and publish optimization admission through the existing
DeferredInit notification. Until admission, installed bridges must preserve
native/provider behavior. Prove that the chosen call sites are quiescent;
neither the event name nor a transaction makes executable writes atomic.
Final installation/publication details remain a contract deliverable.

Each option has its own transaction and readiness state. Complete signature
and branch/relocation checks precede activation. Failure of one option must
preserve native behavior and the other option's valid state. Committed bridge
storage is process-owned; no gameplay reinstallation or teardown race is
introduced. Use the established logger for startup/deferred status and failure
messages, without hot-path diagnostics or new profiling infrastructure.

Compatibility decisions use the proven native capability and owned bytes.
Do not identify, inspect, patch, or allowlist third-party modules. Preserve
foreign providers and later owners. Close the provider-change lifecycle and
admission policy; checking only a CALL opcode or entry prologue is insufficient
to establish the body contract. No generic promise of compatibility with
arbitrary future code replacement is made.

Both module/statics additions and the proposed configuration fields affect
the pre-Deferred footprint. Follow the complete
[startup safety contract](nvse_startup_phase_safety.md), preserve the accepted
core/helper boundary, and qualify the smallest necessary startup delta.
Avoid new imports, dependencies, TLS, workers, eager scratch buffers, or
configuration migrations. Deferring execution does not establish startup
safety by itself.

### Delivery order and acceptance

1. **Finish the pre-code safety contracts.** Close shared score/input ownership
   for fix 1 and node/scene retirement exclusion for fix 2. Complete the native
   capability tables, math effects, provider lifetime, and invocation-admission
   proof. Reuse the established stack/window evidence rather than restarting
   that audit. Do not treat the semaphore release as an exclusion barrier.
2. **Define acceptance under the owner's candidate authorization.** Preserve
   the native output/state contracts below using direct executable evidence
   and exercise applicable actual production behavior offline. A real-engine
   baseline is explicitly waived for implementing these unreleased candidates;
   unavailable runtime outputs must remain unmeasured. Preserve the accepted
   startup architecture. Startup and gameplay acceptance remain separate from
   static qualification. FPS profiling, a debug build, and identification of a
   dominant consumer are not prerequisites.
3. **Implement fix 1 as one coherent change.** Add its module and compiled
   sorter/adapters, all three ownership-aware caller hooks, the independent
   configuration field, and its startup/DeferredInit routing. Preserve legacy
   configuration defaults. Qualify its actual production path and work budget.
4. **Implement fix 2 as one coherent change.** Add its module, four shadow CALL
   adapters, four camera bridges, independent configuration field, and complete
   transaction. Qualify all scans together, including their native-mode routes.
   Fix 1's successful delivery does not depend on completing fix 2.
5. **Qualify coexistence and failure behavior.** Cover both switches off, each
   individually on, and both on. Failed preparation must leave the other option
   valid; a provider mismatch must execute the full provider operation. Check
   pass reset, nested/concurrent invocation ownership, and engine transitions
   against the real boundary. Do not introduce unsupported states to fill a
   test matrix.
6. **Run the affected supported-target checks once changes stabilize.** Run
   meaningful available production-path tests and the affected crate suite,
   then the release build, formatting, diff checks, and final ABI/startup review.
   Do not package, deploy, or create a commit as part of this implementation
   plan. Default-on release remains a separate qualified decision.

The native behavior to preserve is the actual resulting node/light order and
selection, score/cache/list state, shadow/camera lighting outputs, and valid
provider execution. Empty/single-entry lists, ordered/reverse/equal-score
cases, native exceptional values, rejected/null candidates, accepted-limit
boundaries, successive scan resets, concurrent/nested admission, and fallback
must be covered by evidence-backed behavioral cases where those inputs are
valid at the real boundary. Do not manufacture unsupported engine states.

The owner's exception removes the real-runtime baseline as an implementation
gate for these two unreleased candidates. Preserve native behavior through
direct binary/source contracts and execute actual production behavior offline
where available. A future real-engine behavioral comparison must use the same
workload/settings. If elapsed-time performance comparisons become available,
they must use an explicit metric;
profiling is not required to select these targets or establish their static
work reduction. Native instruction-derived budgets support the design but
cannot prove runtime equivalence or elapsed-time improvement. An offline test of an
actual production helper can provide supporting evidence if that behavior is
executable outside the game; a mirrored sorter/scorer, synthetic native
stand-in, source assertion, or build is not engine acceptance.

For future code changes, run the affected behavioral regressions and crate
suite, the explicit `i686-pc-windows-gnu` release build for
`psycho-engine-fixes`, formatting, diff checks, and final ownership/startup
review. The owner authorized static candidate qualification, not runtime or
startup acceptance. The representative Proton startup gate still applies to
release of a changed pre-Deferred footprint. No runtime result is claimed.

The affected commands are:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo fmt --all -- --check
git diff --check
```

Use existing configuration parsing/round-trip tests for the two new settings
as support for candidate qualification. Execute an actual
production helper offline wherever its real behavior can run there. Compiled
bridge disassembly supports ABI qualification; neither it nor a synthetic
engine list/scorer supplies the required native behavioral oracle. Logs are
limited to normal installation/readiness/fallback summaries through the
existing logger. No FPS telemetry or debug-only build is planned.

The owner explicitly answered yes to implementing unreleased candidates after
complete native-contract proof, qualifying them statically, and leaving runtime
acceptance unclaimed. This is the task-specific exception to AGENTS.md's
real-runtime implementation gate for the two fixes; it does not supply any
missing native contract. No profiling or debug build, runtime run, release,
packaging, deployment, or commit is authorized by that exception. Candidate
qualification and runtime acceptance remain separate.

## Contract qualification after authorization to proceed

The following findings extend the two planned fixes rather than establish a
new FPS attribution. Raw checks are retained in
[lighting qualification evidence](../analysis/radare2/output/fnv_location_lighting_qualification_contract_20261006.txt).
The executable identity was reverified against the SHA-256 above. No production
module, configuration field, hook, or shipped binary was changed.

### Fix 1: processed-prefix proof and its boundary

The complete retained assembly of `0x00B70390` establishes the traversal
invariant for an intact, finite, properly linked native list with no external
mutation during the operation:

1. The first outer iteration starts at the head (`0x00B7039B`). It scores that
   current entry, then the head/current comparison at `0x00B703D7` bypasses
   predecessor comparison. The initial processed prefix contains one node.
2. Each iteration saves the current node's original next pointer at
   `0x00B703C0` and retains it through `0x00B703CA`. The next outer iteration
   uses that saved pointer at `0x00B703B2`; it does not advance through the
   current node's newly assigned next link after a move.
3. Predecessor traversal starts at the head and stops when it reaches the
   current node. The checks at `0x00B703D7` and `0x00B70462` prevent comparing
   the current node as a predecessor. Every compared node lies in the already
   visited prefix.
4. The only relink removes the current node and inserts it before a compared
   predecessor (`0x00B70412` through `0x00B70458`). It preserves the unvisited
   suffix and its saved first node. Whether the current entry moves or stays,
   the processed prefix gains exactly that entry.

This proves predecessor visit order, not stored-score exclusivity. The native
sorter itself has no intervening call other than the score helper, and its own
relinks write list links/head/tail rather than wrapper `+0x0C`. Nevertheless,
scoring can enter CRT exception machinery, and concurrent access to the shared
wrappers has not been excluded. The proof does not exclude either source of
external mutation.
Complete shared-field reader/writer and thread ownership coverage is still
required before replacing predecessor calls with loads.

The helper's result is rounded through a single-precision stack store at
`0x00B9DC9B`, reloaded at `0x00B9DC9F`, and stored into wrapper `+0x0C` at
`0x00B9DCA3`. Consequently the cached field and native returned score have the
same single-precision source value when no intervening writer changes it.
That closes the stored-value precision question under those conditions; it
does not prove the equivalence of removing the helper's other effects.

### Fix 1: square-root calls are not universally side-effect-free

`0x00B9DC83` calls `0x00EC6040`. This wrapper stores the x87 input as a double,
classifies it through `0x00ED2808`, then calls `0x00EC605D`. Its native paths
include the following behavior:

| Native location | Proven effect |
|---|---|
| `0x00EC605E` / `0x00EC605F` | Wait for pending x87 work and save the control word |
| `0x00EC6068` through `0x00EC6070` | Compare the saved control word with `0x027F`; a different word invokes `0x00ED2795` |
| `0x00ED2795` | Form and load a temporary control word from the saved precision bits and constant `0x007F` |
| `0x00EC607C` | Execute native `FSQRT` on the admitted nonnegative finite-input path |
| `0x00ED281E` / `0x00ED282B` | Restore the saved control word as needed; the latter also checks precision/inexact state |
| `0x00EC60B2` / `0x00EC60F3` | Route exceptional classifications or domain handling through CRT helpers |
| `0x00ED2737` -> `0x00EE1B04` | Build and process a math exception record, then restore/load the returned value and control state |
| `0x00ED554A` -> `0x00ED5255`, call at `0x00ED5479` | Reach the imported `RaiseException` boundary on the corresponding unmasked-exception path |
| `0x00ED5736` | Write `0x21` for error type 1, or `0x22` for types 2/3, through the address returned by `0x00EC85E3` |

The built-in `0x00EE0A3A` math-handler function is simply `XOR EAX,EAX; RET` in
this executable. That does not eliminate the separate `RaiseException` path,
nor establish ownership of a provider installed in the running process.

For a nonnegative finite square-root input and control word `0x027F`, the
inspected square-root path reaches `FSQRT` and the common return without the
error dispatcher. This is a conditional branch proof. Actual control words,
pending exceptions, native input ranges, later divide behavior, and external
handlers in the owner's workload are unknown. Do not assume this branch covers
every sort or generalize it to the entire scorer being pure.

The plan must either prove its admitted executions preserve relevant math
effects or define a pre-mutation admission/fallback contract that does so.
No such admission policy has been selected. A field load plus the same compare
is therefore still insufficient patch authority, even after the traversal and
score-rounding facts are established.

### Fix 2: addition queues, list mutation, and node retirement

Native receiver provenance distinguishes queued requests from mutations of
the list being scanned:

| Path | Proven receiver/operation |
|---|---|
| `0x00B5C940` | Its append at `0x00B5CA18` uses scene `+0xE4`, selected at `0x00B5CA0A`; this enqueues an addition |
| `0x00B5FD60` -> `0x00B5ECA0` | The ordinary-light consumer searches scene `+0xB4` by underlying NiLight identity; if absent it appends to that general list at `0x00B5ED1E` |
| `0x00B5FD60` -> `0x00B5CD00` | The shadow-light consumer appends to the distinct scene `+0xC0` list |
| `0x00B5EF90` | Chooses `+0xB4` or `+0xC0` from wrapper `+0xEC`; it can remove by identity via `0x00B9FCC0` or by found node via `0x00B5D040` |
| `0x00B5E870` | Can remove from the general list directly at `0x00B5E9AF`, or via `0x00B5D040` at `0x00B5E9F9` when its native ownership condition permits |
| `0x00B5D040` -> `0x00B9EFA0` | Chooses the actual scene list and unlinks a supplied node, including existing membership cleanup |
| `0x00B5D180` | Walks general lights to enqueue removals in `+0xF0`, then clears the separate shadow list at `0x00B5D238`; it is not an unconditional general-list clear |

The helper originally described in comparison material as light
"find/create/associate/insert", `0x00B5C940`, has thirteen verified direct
call sites. They are addition-queue producers, not thirteen newly proven
immediate general-list writers. `0x00B5ECA0` and `0x00B5CD00` have the
identified direct calls from the drain; indirect writer coverage remains open.

Removal ultimately reaches `0x00E6E830`, including through the native head and
tail helpers `0x00B9E7C0` / `0x00B9E850`. It decrements the payload reference,
clears node `+0x08`, clears the previous link, and links the node into the
free-node pool headed by `0x011C5F58` (`0x00E6E867` through `0x00E6E87E`).
This proves that a removed node's links/payload are repurposed. Holding a light
payload reference alone does not preserve the enumeration node.

The drain acquires the native owner/count lock at `0x011F9EA0` through
`0x0040FBF0` at `0x00B5FD90`. Queue producers use the same owner/count state.
The drain also acquires `0x011F9EC0` before its object-update queues. The lock
primitive has an existing-owner recursion branch and a compare/exchange
acquisition loop; its busy path yields through `0x0040FCA0`.

Scene switching through `0x00B5DDF0` takes both locks, clears pending queues,
releases them, schedules removal through `0x00B5D180`, and publishes scene
`+0x1E0` at `0x00B5E06E`. Those locks do not by themselves establish protection
of either proposed cursor. The scans' inspected bodies contain no call to
`0x0040FBF0`, and the direct render-maintenance removal path does not establish
the same drain-lock contract. Whether a caller owns a suitable lock or a frame
barrier across each entire scan is unresolved. A new lock is not planned.

### Fix 2: distinct lookup widths and bridge liveness

The aligned candidate-advance windows close a width distinction that matters
for any sequential replacement:

- The first shadow scan increments EDI at `0x00B9D3C4` and uses
  `MOVZX EAX,DI` at `0x00B9D3DD`. Its next lookup index is the low sixteen bits.
- The camera scan increments its full stored counter, then uses
  `MOVZX EDX,AX` at `0x00B5C03B`. It checks that narrowed index against scene
  `+0xBC` before walking from `+0xB4`.
- The second shadow scan increments EBX and pushes EBX unchanged at
  `0x00B9D8B2` / `0x00B9D8B3`. It has no corresponding sixteen-bit narrowing.

Thus, if a first-scan/camera iteration reaches a narrowed index of zero after
wrap, the native lookup starts again at the head. A cursor that always advances
would change that behavior. The accepted caps do not prove wrap unreachable:
rejected entries still advance those candidate indices. This is a compatibility
contract, not an observation that such a list occurs in the owner's game.

The camera loop reuses EBX and EBP for candidate/vector values and EDI for its
output scratch cursor. Its wrapper local feeds subsequent arithmetic, and its
index local remains live through the increment/narrow sequence. The shadow
loop likewise keeps counters and the nonnull-property iterator state live.
These facts rule out treating those values as an already proven free cursor
slot. The continuation below identifies conditional storage in the shadow
iterator local and two camera temporaries with disjoint native live intervals.
Those storage/window proofs do not qualify a compiled bridge or exclude native
node retirement during a scan.

## Continued static closure of the two fix contracts

Raw output for this continuation is retained in
[lighting closure evidence](../analysis/radare2/output/fnv_location_lighting_closure_contract_20261006.txt).
The executable SHA-256 was rechecked and matches the identity above. radare2
remains the primary interface. Supplementary reads of this same PE file record
literal function pointers and exact window bytes; complete objdump decoding of
the two consumers supplements truncated function listings. None of these
checks executes the engine or a proposed replacement.

The new result is a concrete storage and instruction-window design for fix 2,
plus narrower caller, retirement, input, and math contracts. Shared-state
exclusivity and full provider qualification remain material unknowns. These
are not silently replaced with assumptions about engine thread names.

### Indirect caller coverage and another retirement path

Direct references alone miss the actual virtual dispatch of the sort callers.
The retained selector-vtable audit and new reads of the supported PE establish
these table entries:

| Vtable base | Slot | Native target |
|---|---|---|
| `0x010AE0F4` | `+0x7C` | `0x00B67BE0` |
| `0x010B8354` | `+0x7C` | `0x00B67BE0` |
| `0x010B935C` | `+0x7C` | `0x00B67BE0` |
| `0x010B94B4` | `+0x7C` | `0x00B67BE0` |
| `0x010B9934` | `+0x7C` | `0x00BB4740` |
| `0x010BAC1C` | `+0x7C` | `0x00BC3E40` |
| `0x010BCB84` | `+0x7C` | `0x00C058F0` |

`0x00B98E80` loads slot `+0x7C` at `0x00B98FDB` and invokes it at
`0x00B98FE1`. The additional delegate `0x00BC3E40` can call `0x00B67BE0`
at `0x00BC3EC9` after its native flag admission. Its path is therefore already
covered by the latter's sorter call site; it is not a fourth direct call to
`0x00B70390`. This closes those concrete indirect routes, not all computed
function-pointer provenance or thread ownership throughout the engine.

The scene constructor is `0x00B5E0F0`; it assigns vtable `0x010ADCF8`.
That table's `+0xD4` entry contains `0x00B5F9B0`, which calls the immediate
scene-maintenance/removal routine `0x00B5E870` at `0x00B5F9E7`. Thus missing
direct xrefs to `0x00B5F9B0` do not make maintenance exclusively reachable
through the two previously identified direct rendering sites.

`0x00B5E5A0` is the scene destructor, reached from its deleting wrapper
`0x00B5F980`. It compares the indexed scene registration against this object
and clears a matching registration through `0x00B4F2F0` at `0x00B5E5EF`.
After queue and shadow-list cleanup, it selects scene `+0xB4` at
`0x00B5E836` and calls the list-clear helper `0x00E74D40` at `0x00B5E841`.
This is a general-list retirement path in addition to individual removals.
The previously proven free-pool behavior makes retaining a node across this
clear unsafe unless scene destruction is excluded for the entire cursor life.

The supplemental literal-pointer search found no non-code-section absolute
pointer to the sorter or the two scan entries. It did find the table entries
above. A literal-pointer search does not cover computed dispatch, copied
pointers, aliases, or code installed by plugins. It is recorded as bounded
discovery evidence, not an exhaustive caller or writer proof.

### Fix 1: bound ownership and a narrower math domain

All three inspected native sorter sites pass a caller-local sphere snapshot.
The first caller's geometry-bound copy is documented above. The other two
copy four dwords immediately before sorting: `0x00BB4EEC` through
`0x00BB4F0A`, and `0x00C06053` through `0x00C06071`. Each passes the address
of that local copy rather than the source object's bound pointer. The score
helper reads its four sphere fields and contains no store through this bound
pointer. On the native path without an external callback or mutation, later
geometry-bound changes do not alter that already copied sort input.

The primary-scene offsets read by scoring are initialized from
`0x011F426C`, `0x011F4270`, and `0x011F4274`, with the actual scene stores at
`0x00B5E47C`, `0x00B5E487`, and `0x00B5E493`. A decoded operand inventory
records literal `+0x1E4`, `+0x1E8`, and `+0x1EC` uses. It includes unrelated
object types and does not cover adjusted-pointer or copy aliases. Constructor
initialization is proven; global immutability of those scene fields is not.

The original unrestricted math-purity premise can be replaced with a narrower
conditional contract for further qualification:

- The actual native scorer and its inspected CRT math path must be owned.
- The x87 control word must equal `0x027F`, with no pending unmasked exception
  or stack fault, and with the valid native x87 stack state preserved.
- The scene offsets, light world-position components, light radius, and all
  four bound values must be finite and remain identical between each current
  score and its predecessor uses. This also requires stable pointers/lifetime.

Under those conditions, the actual scorer's translated components and deltas
are rounded to floats, then squared and added. Its square-root input is
nonnegative or positive infinity if float rounding overflows. The finite
nonnegative route reaches `FSQRT`; the positive-infinity classification takes
`0x00EC60B9` through `0x00EC60CC` to the common return. With the saved control
word `0x027F`, both common tails return without the error dispatcher, including
the `0x00ED2833` branch to `0x00ED2853`. This narrows the native CRT callback
question for those admitted executions. It does not cover NaN input, a
different control word, a changed math provider, or changed input data.

The final subtraction/division still uses the original x87 instructions.
Finite input screening does not prove a finite score: zero radius or overflow
can produce exceptional results. Preserve native rounding and unordered
comparison; do not substitute zero, clamp the score, change radius admission,
or clear exception flags.

Intel documents cumulative x87 exception flags and compare-defined condition
codes in Volume 1, sections 8.1.3.2-8.1.3.3. With unchanged inputs/control and
no intervening flag clearing, a repeated identical calculation cannot add a
new exception bit after its first execution. The retained `FCOMP` defines
comparison flags. These architectural facts support the conditional argument;
they do not prove shared-input stability or identical saved FPU diagnostic
environment for a replacement. See the
[Intel architecture manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf).

This is a candidate math-domain contract, not a selected or implemented
admission policy. A finite-value prewalk observes values at one time; it does
not stop another owner from changing a position, radius, scene registration,
or wrapper `+0x0C`. The other native score consumer remains `0x00B5DAC0`.
Complete ownership exclusion is still needed before score reuse can qualify.

### Fix 2: shadow scan storage and boundary ABI

Let `S` be ESP after the shadow routine's `SUB ESP,0xC0` and four saved-register
pushes. During the scan loops, `S` equals entry ESP minus `0xD0`. This definition
uses actual stack adjustments rather than the tool's inconsistent variable
names.

The dword at `S + 0x68` is the existing property iterator location. The native
nonnull-property branches pass its address to `0x00B70600` / `0x00B70700` at
`0x00B9D2A3`, `0x00B9D3C9`, `0x00B9D517`, and `0x00B9D89E`. Those helpers
store only one node pointer through that iterator address. In the null-property
branches, none of these calls executes.

The complete native scan bodies have no other access to that dword in either
enumeration interval. The other passed vector addresses are `S + 0xAC`,
`S + 0x30`, and `S + 0xA0`, with three-float extents. The verified normalizer
`0x004A0C10` writes only its supplied vector's three components; its length
callee `0x00457990` reads those components and passes a scalar onward. These
native aliases do not reach `S + 0x68`.

This establishes invocation-local cursor storage for the native null-property
branch. It does not make the nonnull branch available for reuse. Reset at each
scan's own index-zero call, preserve the nonnull branch unchanged, and stop
owning the slot when that enumeration ends. Saved-register pops at
`0x00B9D901` through `0x00B9D903` change ESP afterward; later similarly named
locals must not be interpreted using the earlier `S`.

| Call to replace conditionally | Exact five native bytes | Resume |
|---|---|---|
| `0x00B9D2B9` | `E8 62 D9 FB FF` | `0x00B9D2BE` |
| `0x00B9D3E1` | `E8 3A D8 FB FF` | `0x00B9D3E6` |
| `0x00B9D529` | `E8 F2 D6 FB FF` | `0x00B9D52E` |
| `0x00B9D8B4` | `E8 67 D3 FB FF` | `0x00B9D8B9` |

Each adapter receives the native ECX scene and one pushed index. At adapter
entry, the return address and index place the iterator at adapter-entry
`ESP + 0x70`; any bridge register saves must adjust that access accordingly.
EAX supplies the wrapper result, `RET 4` removes the original argument, and
native nonvolatile registers and x87 state must be retained. A count-rejected
lookup must return zero before dereferencing a retained node. Preserve the
native next-node look-ahead and the first scan's sixteen-bit head reset.

The two null behaviors differ. The first scan's `TEST EAX,EAX` at
`0x00B9D2BE` exits on zero. The second scan's zero candidate at
`0x00B9D540` skips accumulation and reaches advancement at `0x00B9D89A`.
Its iteration counter still advances at `0x00B9D8B9`, and its bound comes from
the native saved first-pass count at `S + 0x54`. It must retain this behavior
and the full thirty-two-bit candidate index; a common iterator that terminates
both scans on null would change native results.

There is also an owner distinction: the second scan's first receiver comes
from the scene loaded into ESI at `0x00B9D3FA`, while later calls reload the
primary global at `0x00B9D8AC`. A single node slot cannot prove that these
receivers remain the same. Primary-scene replacement must be excluded by the
admitted lifetime contract; stack locality alone does not solve this gap.

### Fix 2: camera cursor storage in dead temporary intervals

Let `C` be ESP in the camera collection loop, after `SUB ESP,0x58` and four
register saves; `C` equals entry ESP minus `0x68`. No permanently unused
local/register is selected. The native live intervals instead allow these
two temporary dwords to exchange cursor ownership:

| Local | Native live interval relevant to the collection loop |
|---|---|
| `C + 0x64` | Initial value last read at `0x00B5BE01`; accepted candidates write vector Z at `0x00B5BEA9`, normalize it, and last read it at `0x00B5BECC` |
| `C + 0x30` | Candidate brightness is first written at `0x00B5BF4F`, multiplied at `0x00B5BFE2`, rewritten at `0x00B5BFE6`, and last loaded at `0x00B5BFEA` |

Initialize the retained node in `C + 0x64` after the initial native index-zero
lookup, only for an admitted scan. Before an accepted candidate overwrites
the vector, transfer the node from `C + 0x64` to `C + 0x30`. After the last
vector-Z read and before the brightness write, transfer it back. The normalizer
receives `C + 0x5C`, so its three-float write span includes the vector slot but
does not touch the temporarily owned cursor at `C + 0x30`.

The APP_CULLED branch at `0x00B5BE63` skips both transfers and goes directly
to advancement. It therefore leaves the retained cursor in `C + 0x64`.
Collection exit is `0x00B5C073`; the later accumulation does not read that
old temporary. The fallback overwrites vector Z at `0x00B5C301` before using
it. No extra restore of a dead native float is required on these native paths.

The initial `MOV [ESP+0x30],ESI` at `0x00B5BE27` executes while the getter
argument is pushed. It addresses `C + 0x2C`, the candidate-index local, rather
than `C + 0x30`. This stack adjustment is essential to the storage proof.

The instruction-aligned candidate windows are:

| Window | Exact six native bytes | Displaced native work | Resume |
|---|---|---|---|
| `0x00B5BE30` | `89 44 24 1C 3B C6` | Store wrapper, compare it with zero in ESI | `0x00B5BE36` |
| `0x00B5BE69` | `8B 44 24 6C DD D8` | Load camera-position argument, pop x87 accumulator | `0x00B5BE6F` |
| `0x00B5BED2` | `D9 5C 24 14 D9 EE` | Store direction dot result, load native zero | `0x00B5BED8` |
| `0x00B5C04A` | `8B 83 B4 00 00 00` | Load general-list head before native indexed walk | `0x00B5C067` after equivalent cursor retrieval |

The first three bridges must replay their complete displaced instructions.
Cursor transfers can use integer moves with exact register preservation; they
must not consume/change the live x87 accumulator, numerical inputs, control
word, or native flags. Temporary register saves below `C` do not authorize
changing the retained frame layout. The last bridge replaces the head walk:
the existing count comparison at `0x00B5C042` remains, index zero after narrowing
must reload the head, and other admitted successive indices advance once.
At `0x00B5C067`, ECX must be the selected payload, EAX its next-node pointer,
and EDX zero as after the native walk. The following native payload test and
loop/cap logic remain in place, including the look-ahead after a capped entry.

No incoming edge to an interior displaced instruction appears in the analyzed
xrefs, and the complete decoded native consumer shows linear entry to these
windows. That validates the inspected native control-flow windows. It does
not admit arbitrary foreign branches or prove a generated adapter's ABI.
The camera cursor design is conditional on the original accessor/body and
the stable-list contract, exactly as the shadow design is.

### Thread ordering: the semaphore release is not a completion barrier

The continuation verifies all three routes from `0x008706B0`: calls to
`0x008707C0`, `0x00870A00`, and `0x00870BD0`. Their shadow preparation calls
are respectively `0x00870851`, `0x00870A74`, and `0x00870C3C`. Native scene
maintenance is also virtual, as described above. These are concrete caller
routes, not a declaration that every engine lighting consumer runs exclusively
on one thread.

The following synchronization distinction is now closed by actual imports and
instructions:

| Native operation | Actual effect |
|---|---|
| Main call `0x0086EC78`, argument 1 to `0x008C80E0` | Sets byte `0x011DFA18`; does not wait or release at this mode |
| `0x008C80E0(0)` when the byte is set | Clears it and calls `0x008C80C0` |
| `0x008C80C0` -> `0x00442550`, object `0x011DFAFC` | Calls imported `ReleaseSemaphore` at `0x00442562`, then increments bookkeeping through `0x0040B460` |
| `0x008C80D0` -> `0x008C80B0` -> `0x004424E0` | Calls imported `WaitForSingleObject` with infinite timeout at `0x004424F0`, then decrements bookkeeping |

The worker wait occurs at `0x008C7D18` in `0x008C7BD0` and at
`0x008C7EFF` in `0x008C7DA0`. These bodies perform earlier actor/process
work before that wait, including `0x0096C7C0` and other actor update calls.
Thus the wait cannot by itself exclude those earlier operations during the
render interval. Conversely, this does not prove those operations mutate the
specific scene nodes or score inputs being used by a renderer.

In `0x00873200`, the conditional release at `0x008743BC` follows both
camera calls (`0x00874277` / `0x0087432D`), but precedes later native work.
The third render route calls shadow preparation before its conditional release
at `0x0087089D`. This orders release sites; it does not turn them into a
main-thread wait for all actor work. The separate phase wait `0x008C7A70`
really does invoke `WaitForSingleObject`. Its inspected main-side wrapper
`0x00713C70` waits for worker 0, phase 1, under its own conditions; that is not
proof of completion of all later phases or of a scene-wide mutation barrier.

The existing global actor lock `0x011F11A0` is acquired/released in worker
and main paths, but the inspected main frame releases it before lighting and
rendering. The small `0x0040FBE0` calls in render preparation are plain return
stubs; they do not acquire it. Do not add a new lock, move a phase, or change
worker topology on the basis of this research.

The pre-implementation trace distinguishes worker callbacks from main-thread
barriers. The installer `0x008C7290` selects `0x008C7BD0` for its lower
processor-setting branch, or `0x008C7DA0` and `0x008C7F50` for the higher
branch. Its callback registrations are at `0x008C7364`, `0x008C7316`, and
`0x008C733C`. The waits at `0x008C7F6E`, `0x008C7FB4`, `0x008C8029`,
`0x008C8069`, `0x008C8093`, and `0x008C80A3` belong to the second worker's
body. They are cross-worker ordering, not additional main-render barriers.
The automatic NULL xref from `0x008C7D13` to `0x008C7F50` is rejected;
the actual call targets `0x008C7D80`.

`0x008C7D80` writes the supplied phase to manager `+0x0C + 4 * worker_index`
at `0x008C7D90`, then returns. It does not signal an event or wait. The
full-worker call at `0x008C7D13` stores index 1 / phase 6 immediately before
the semaphore wait. A phase counter is therefore distinct from the event
wait helper; its value alone does not establish the complete lifetime/input
exclusion required by either fix. In both worker-0 bodies, phase 1 is signaled
before the later actor-processing calls. Main wrapper `0x00713C70` waiting for
that phase is not proof that those later calls have completed.

Additional drain callers `0x00453DC0`, `0x0093C200`, and `0x00878250` were
traced. Their shared entry helper `0x00871DC0` can itself call rendering at
`0x008721A4`; it is not an established completion barrier. The cleanup wrapper
`0x008782B0` is called by the main frame at `0x0086E758`. These observations
expand call coverage but do not exhaustively prove the thread/alias ownership
of all drain, scene-switch, destructor, light-transform, and radius writers.

The array scorer's direct caller coverage remains exactly two sites in
`0x00B5FD60`, at `0x00B5FF3F` and `0x00B5FF9F`. That drain has the four
inspected direct callers listed earlier. The continued upstream search adds
seven direct calls to alternate drain consumer `0x0093C200`, including its
calls from `0x0094DBE0` and `0x0093DB60`. Those bodies contain additional
conditional engine operations; their source-level receiver types and complete
thread provenance are not established. This does not close score-field writer
exclusivity. New native output is appended to the lighting closure evidence
as entries 108-122, with interior-address probes explicitly rejected.

### Installation boundary and provider limits

The actual executable entry `0x00FDE590` reaches CRT startup through
`0x00ECC4DB` and `0x00ECC35D`. The first `GetStartupInfoA` call is
`0x00ECC372`, through IAT slot `0x00FDF190`; initializer-array processing
at `0x00ECCD4A` / `0x00ECCD6B` and game entry `0x0086A850` at `0x00ECC46B`
follow it. Together with Syringe's existing
[startup barrier](../syringe/src/startup_barrier.rs), this establishes the
normal executable ordering for inert bridge preparation before game startup.
It does not establish startup compatibility of a newly compiled DLL footprint
or authorize patching from the asynchronous fallback worker.

The existing core
[performance lifecycle router](../psycho-engine-fixes/src/mods/perf/mod.rs)
and radio implementation demonstrate preparation at the pre-CRT boundary and
one-time DeferredInit capability publication with no code writes at that event.
The direct-call hook captures the target currently encoded by all five bytes;
its activation/restoration checks ownership. Owned patches and transactions
restore only owned changes. These source contracts support a prospective
installation mechanism; they do not prove the proposed native capability.

The three sorter CALL windows and four shadow CALL windows are complete
five-byte instructions. The four camera windows are complete six-byte
instructions/sequences. Admission still needs every contract-bearing body,
callee, branch, and owned bridge to match the qualified native operation.
A prologue, CALL opcode, executable-address check, or successful transaction
is insufficient. Captured foreign providers must execute unchanged.

A DeferredInit check also says nothing about later provider replacement.
The admission mechanism must recheck applicable owned capability at entry or
have a separately proven immutable-provider lifetime. It must not allocate or
lock in the hot path. Neither current process providers nor their later writes
are facts contained in the on-disk executable; no module classification or
third-party patch is permitted to fill this gap. Full provider predicates and
compiled bridge behavior remain unqualified.

### Native transform ownership continuation

The owner's approval removes the runtime-baseline implementation gate. The
following findings continue the native correctness work under that approval.
They are retained as entries 123-186 of the
[lighting closure evidence](../analysis/radare2/output/fnv_location_lighting_closure_contract_20261006.txt).
The same executable identity was checked for the supplementary virtual-table
reads. No replacement code or runtime measurement is represented by this
evidence.

**The inspected world-update branch is serial.** `0x00C50610` initializes
its tasklet-selection local at `[EBP - 0x11]` to zero at `0x00C5064C`.
The inspected body does not change that local. Its branch at `0x00C5065D`
therefore reaches the serial path at `0x00C50737`. In its child loop it calls
child virtual slot `+0xA4` at `0x00C5080F`, with the native update-data argument
and flags zero. The exit at `0x00C5081C` bypasses the tasklet cleanup route;
the parent operation at `0x00C5090E` and return at `0x00C5091E` complete the
inspected function. Its two previously verified calls from `0x0086FC60` are
`0x0086FD4A` and `0x0086FD5C`.

This closes the scheduling choice inside this particular native function.
It does not show that every world transform or light update uses this entry,
that actor workers are idle, or that a shared score is exclusively owned.

**The actual light-position writer is identified.** The point-light factory
at `0x00A7D6E0` assigns virtual table `0x0109DD0C` at `0x00A7D703`. Its
verified slots include:

| Slot | Target | Relevant native behavior |
|---|---|---|
| `+0xA4` | `0x00A59F90` | Conditional controller/property dispatch through `0x004EFF50`, then virtual `+0xB8` and `+0xBC` |
| `+0xA8`, `+0xAC` | `0x00A59FD0` | Controller/property dispatch and native flag tests before those virtual calls |
| `+0xB8` | `0x00A7D7A0` | Calls `0x00A68C60`, then increments this light's `+0xA8` counter |
| `+0xBC` | `0x00A29680` | Return stub in this table |

`0x00A68C60` dispatches through another object's `+0x90` slot when the
light's `+0x1C` field is nonzero. Otherwise it calls `0x00A68BF0`.
Do not describe `+0x1C` as the parent: the fallback actually reads the parent
input at `+0x18`. The reference header distinguishes those fields, and the
decoded native operands are the operative contract.

`0x00A68BF0` writes thirteen dwords beginning at receiver `+0x68`, through
`+0x98`. This span contains the score helper's position reads at `+0x8C`,
`+0x90`, and `+0x94`. With no parent, it copies from receiver `+0x34`.
With the inspected identity flag it copies from parent `+0x68`. Otherwise
it calls `0x0062C250` with parent `+0x68` and receiver `+0x34`, then copies
the returned transform. This is concrete writer provenance, rather than
inferring a write from an update-method name. Other direct callers of this
writer exist; the captured xrefs do not prove that all their receiver objects
are lights or that all their threading contracts are covered.

The generic helper `0x004EFF50` also performs indirect controller/property
dispatch. It is not evidence that every callback is side-effect free. Its
presence prevents claiming input immutability from a short downward-update
body alone. Likewise, empty virtual methods in the point-light table do not
remove the actual inherited transform writes or the separate-object dispatch.

**Two actor transform branches have a real deferral guard.** The inspected
Actor, Character, and Creature tables map slot `+0x348` to `0x00886CB0`.
Its two relevant branches call predicate `0x008C7AA0` at `0x008876F7` and
`0x00887955`. A false result runs `0x00C6C3D0` immediately. A true result
calls `0x0087AB50`, which records the supplied pair in the native queue at
`0x011DF244` when its setting permits. The immediate route reaches
`0x00C6C110`, which can call `0x00A68BF0` at `0x00C6C13D` and recurse
over children at `0x00C6C1A1`. Thus this actor path can reach the concrete
position writer; whether it does so immediately is a native policy decision.

The relevant predicate contract is now more precise:

- `0x008C7AA0` first gates its thread/phase checks on the native processor
  setting being greater than one and `0x00713D90` returning nonzero.
- `0x00713D90` reads byte `0x011DFA19`. The inspected dispatcher
  `0x008C78C0` sets it at `0x008C7947`; the analyzed join routine has a
  clearing store at `0x008C79CD`, after its worker waits. Its inner operation
  `0x008C7490` calls the already verified `WaitForSingleObject` wrapper
  `0x004424E0`. This byte differs from `0x011DFA18`.
- It obtains the current thread ID through `0x0040FC90`, whose actual import
  is `GetCurrentThreadId`, and compares it with the value returned by
  `0x0044EDB0` for global receiver `0x011DEA0C`; that accessor reads `+0x10`.
- On the unequal-thread route, a nonzero `0x011DFA18` immediately sets the
  predicate's deferral result. With that byte clear, the route tests the native
  phase value against six. The equal-thread route has different phase tests
  against eleven and seven. Additional actor-state/thread conditions can
  also force deferral.

Consequently, under the verified processor/active-dispatch conditions, an
unequal-thread invocation of these two guarded branches during the flagged
render interval does not take their immediate transform recursion. This
narrows a real concurrency concern. It is not a scene-wide completion barrier:
it covers the inspected guarded branches, not every actor callback, unguarded
writer, queue drain, scene transition, IO task, or foreign provider. Disabling
the queue through its setting also does not turn a deferred branch into the
immediate path; the operation and setting must be described as observed.

**The actor scene-record call is not a proven light-list mutation.** In
`0x00886CB0`, the call at `0x0088717E` reaches `0x00B65F60` using the
receiver obtained from `0x00B4F5C0`. The complete inspected callee operates
on receiver `+0x140`, `+0x144`, and `+0x148`, and on its own record fields.
That is a distinct span from the general-light list at `+0xB4`/`+0xB8`/
`+0xBC`. Its record `+0x0C` is not established as the light-wrapper score
field. Neither the caller's actor context nor a repeated numeric offset
establishes that identity.

**An additional wait does not close the render ownership gap.** The worker
operation `0x0087A6D0` loads the first pointer from its receiver and calls
`0x0086CDD0`. That delegate passes receiver `+0x14` to the verified wait
wrapper `0x004424E0`. In the full-worker body this occurs at `0x008C7D41`,
after the separate semaphore wait at `0x008C7D18`. In the split bodies its
calls are at `0x008C7EDA` and `0x008C8059`; those bodies have distinct phase
and semaphore ordering. Do not treat these object-specific waits as evidence
that a lighting consumer has joined every worker.

The additional calls to `0x0086CDD0` at `0x0086CC59` / `0x0086CC64` belong
to `0x0086C880`. Its analyzed direct caller `0x0086BF40` invokes that body
and conditionally frees its receiver, a deleting-wrapper contract. These calls
are not newly established per-frame lighting barriers. Likewise, the worker's
pre-phase-one operation `0x0086FD70` calls `0x007027E0`, `0x00702810`, and
`0x00702840`; without their contracts it is not evidence that all light-input
writers completed before the phase-one signal. The retained decompiler output
and decoded wait operand distinguish the concrete operations from those
unresolved receiver/callee semantics.

Immediate ordinary-light removal `0x00B5EF90` has the two analyzed direct
calls from `0x00B5FD60`; render-time maintenance `0x00B5E870` has direct
calls from `0x008707C0`, `0x00873200`, and the virtual maintenance wrapper
`0x00B5F9B0`. The scene destructor still has its deleting-wrapper route.
These facts refine concrete caller coverage but do not exhaust indirect
aliases or exclude node recycling during each optimized scan.

The implementation consequence is specific: do not treat either the serial
world-update body or the actor deferral predicate as complete admission for
cached scores or retained enumeration nodes. Fix 1 still needs ownership of
the shared score and every input until reuse; fix 2 still needs exclusion of
each retiring/mutating owner throughout its exact scan. Those questions do
not require identifying an FPS consumer or collecting profiling data.

### Contract disposition before candidate implementation

| Deliverable | Qualification status |
|---|---|
| Fix 1 predecessor visit order | Proven for the intact native list without external mutation |
| Fix 1 cached/returned score precision | Proven at the helper's final rounding/store boundary |
| Fix 1 shared-field/input exclusivity and math effects | Caller-local bound copies and conditional masked/finite CRT route proven; complete shared-input/score ownership and replacement math effects remain incomplete |
| Fix 1 indirect callers | Concrete shader vtable dispatch and inherited delegate closed; exhaustive computed/thread provenance remains incomplete |
| Fix 2 queued versus immediate mutation | Proven for inspected paths, now including virtual maintenance and destructor clearing; exhaustive alias/writer coverage remains incomplete |
| Fix 2 node retirement | Proven pool recycling and general-list destructor clear; exclusion during each scan remains incomplete |
| Fix 2 width/reset semantics | Proven first/camera sixteen-bit versus second-shadow thirty-two-bit distinction |
| Fix 2 cursor storage and native windows | Conditional shadow slot and camera temporary transfers established; coherent invocation admission and actual relocated/compiled bridges remain unqualified |
| Synchronization | Semaphore release/wait sides, serial world-update branch, and two guarded actor transform-deferral branches proven; complete mutation exclusion remains incomplete |
| Installation and provider lifecycle | Normal pre-CRT ordering and existing ownership mechanisms proven; full capability predicates and later-provider lifetime remain incomplete |
| Real shipped-path behavioral baseline | Not available; owner explicitly waived it as an unreleased candidate implementation gate, not as runtime acceptance |

The remaining native research is specific: trace every alias-capable writer of
wrapper score/light transform/radius and scene-list membership through worker
and transition routes, establish phase ownership across each exact invocation,
and finish capability predicates against every body/callee used by a bridge.
The newly closed actor branches need not be researched again. The concrete
next boundaries are the other callers of `0x00A68BF0`, the alternate drains
through `0x0093C200` and `0x00453DC0`, the primary-scene registration/destructor
routes, and shared-score writers relative to the shader dispatch at
`0x00B98FE1`. The actor deferral guard applies only under its inspected
conditions and cannot be extended across the later semaphore release without
proving that ordering for the particular sorter or scan.
Fix 2 also requires one coherent invocation-admission and native-mode contract
across initial lookup, temporary transfers, and subsequent cursor use.
The inspected semaphore is not the missing exclusion proof. An unchanged
head/count, finite-input prewalk, payload retain, or same-thread label cannot
replace it. Unknown providers must retain their complete operation.

Static analysis can establish executable contracts and conditional work counts.
It cannot establish the owner's actual scene populations, input/control-word
distribution, running plugin providers, elapsed CPU/GPU contribution, or which
consumer dominates the reported slow frames. Population, timing, and dominance
are attribution unknowns, not prerequisites for optimizing a verified
inefficiency. They do not need to be resolved to pursue the two planned fixes
or additional targets. Unknown input/provider conditions must instead remain
covered by a proven admission and unchanged-provider fallback contract.
No performance root-cause attribution or FPS estimate is made, and neither is
an acceptance requirement for the static work-budget argument.

An unresolved material correctness contract prevents implementing its
production intervention. For fix 1, the immediate issue is whether an earlier
score and its inputs remain valid until reuse. For fix 2, it is whether a
retained node remains valid and corresponds to the native indexed result.
These are behavior-preservation questions, independent of FPS attribution.
The owner's explicit exception removes the unchanged real-engine baseline as
an implementation gate for these two unreleased, statically qualified candidates.
It does not relax the native correctness contracts or establish runtime/startup
acceptance. No runtime baseline is invented.

At this stage no production implementation or runtime acceptance was claimed. Document checks
qualify only the saved research. This authorization does not establish that
either mechanism dominates slow frames or that a fix will produce a specified
FPS increase.

## Implemented unreleased candidates

The owner requested implementation after the unresolved contracts above were
reported. This delivery implements both experiments on the Psycho core side.
It does not describe their native runtime behavior as accepted or their
performance as measured. No deployment, packaging, or commit accompanies it.

### Configuration and lifecycle

Both restart-only settings live in `[performance]` and default to `true` at
the owner's subsequent request. Explicit settings, including `false`, take
precedence over defaults. Existing configurations are not migrated or rewritten
by the core; an existing explicit `false` remains disabled until edited.

```toml
light_property_score_reuse = true
scene_light_sequential_scan = true
```

The runtime struct, raw TOML parser, serialization, and shipped configuration
all own these switches. Existing RNG, zlib, post-load, and legacy defaults are
preserved. These defaults control configuration fallback, not engine admission:
the existing capability checks and native/provider fallback still apply to
every enabled candidate. Default-on is the owner's configuration preference,
not runtime acceptance or a release decision. The helper and its
loading/forwarding boundary are unchanged.

The two installers run independently from the established performance setup
path, after the existing post-load preparation. They require
`has_pre_crt_startup_boundary()` and reject the compatibility-worker route.
Complete native signatures are validated before code changes. Captured targets
and immutable replacement expectations are published before activation. Each
candidate has its own `ModificationTransaction`; failure invokes the existing
ownership-aware rollback and leaves that candidate unadmitted. Partial hook
container preparation is process-owned and is never retried during gameplay.
Rollback itself is best-effort under the existing primitive's contract; it
cannot overwrite a later owner or promise recovery from an OS write failure.
Any scan installation error permanently latches native mode after the rollback
attempt, so a retained next/transfer bridge cannot read an uninitialized slot
when its initial bridge was removed or never installed.

The bridges are inert until the existing core DeferredInit notification
publishes their admission state. That event performs no executable writes.
Fixed bridge/signature storage lasts until process exit; no gameplay uninstall
or reinstallation is introduced. The source adds no dependency, WinAPI import
declaration, TLS owner, startup callback, worker, or third-party inspection.
The added statics/configuration/code nevertheless change the pre-Deferred
footprint. The startup document's real load-to-gameplay acceptance remains
unperformed and no startup compatibility acceptance is claimed.

### Implemented score reuse

[light_property_scores.rs](../psycho-engine-fixes/src/mods/perf/light_property_scores.rs)
installs all three planned caller hooks. Its private sorter follows the native
`0x00B70390` control flow. Current entries still call actual `0x00B9DBE0`;
predecessors load the rounded wrapper `+0x0C` through a private
`FLD [ECX+0x0C]; RET 4` adapter. Native comparison, strict movement, relinks,
head/tail handling, and conditional cache-key clearing remain in that sorter.
There is no separate score array or precomputation pass.

Admission checks the captured provider, the complete sorter/scorer/qualified
CRT ranges, and the applicable caller slice with Psycho's owned CALL overlay.
The incoming FXSAVE image must show control word `0x027F`, empty x87 tags, and
no stack-fault/error-summary state. The integer-only prewalk requires finite
bound components, primary-scene offsets, positions, and radii, with a chain
whose count, previous links, terminal next, and tail agree. It performs no
scoring or list writes. Unsupported admission tail-dispatches the exact
captured provider before any optimized mutation. There is no midway fallback
after a relink.

The prewalk follows the native caller's valid mapped-object contract. It is
not a generic invalid-pointer guard and does not query/pin each engine object.
Finite-input and chain checks do not establish exclusivity. An earlier stored
score can be reused correctly only while the input bound, wrapper score,
light position/radius, primary scene, and list remain stable under the native
invocation. Exhaustive writer/reentrancy/lifetime exclusion remains unproved.
Exceptional results produced by admitted arithmetic retain the native current
scorer and comparison route; arbitrary initial NaN/Inf inputs or other control
words use the full provider operation. Matching code does not prove all
diagnostic/math side effects or exclude a provider change during sorting.

### Implemented sequential scans

[scene_light_scan.rs](../psycho-engine-fixes/src/mods/perf/scene_light_scan.rs)
implements the four shadow CALL bridges and four camera patches together.
The first lookup in each null-property shadow pass initializes `S+0x68`, then
executes its captured index-zero getter unchanged. Subsequent admitted lookups
retain the native scene-count check and follow one next link. The first scan's
native narrowed index and the accumulation scan's full-width index remain in
the original consumers; index zero restarts the head, including native wrap.
Nonnull-property iterator paths remain native and own their existing slot.

The camera's initial getter CALL stays native. The `0x00B5BE30` bridge
initializes `C+0x64`, replays the wrapper store/comparison, and resumes at
`0x00B5BE36`. The two transfer bridges move the cursor or zero native-mode
marker through `C+0x30` and back, preserving the proven temporary liveness
intervals. They replay the native argument load/x87 pop and direction store/
zero load at their exact resume addresses. APP_CULLED bypasses both transfers.
The next bridge preserves the existing count gate and returns the native
payload/next-link register outputs at `0x00B5C067`. Native mode executes the
complete original indexed head walk. Filtering, accepted limits, lighting
arithmetic, output order, scratch writes, and downstream counters remain in
the original functions.

A pass receives one mode at its initial bridge: zero for native mode or a
head node for admitted mode. Even an inert native pass initializes/carries
zero, so DeferredInit publication cannot promote an uninitialized in-flight
pass. Readiness is not reevaluated to promote a subsequent lookup. A permanent
process-wide rejection latch suppresses cursor reads/transfers after a
consumer/provider/callee signature mismatch; initial rejection writes no new
data into the rejected frame. The per-advance integer-only checker covers all
54 getter bytes and latches native mode on replacement. Camera fallback replays
its complete inline walk; shadow fallback tail-jumps its captured provider
with the original incoming registers, flags, stack, and floating-point state.

The latch is an admission mechanism, not a node owner or synchronization
barrier. Concurrent code mutation, arbitrary changed control flow entering a
bridge without its native initial path, node retirement, and primary-scene
replacement during a pass remain unresolved. No new retain or lock attempts
to conceal them. Cursor storage is invocation-local, but that alone does not
prove that its pointee or scene remains valid.

### Exact capability ranges and bridge ABI

Immutable bytes in
[lighting_signatures](../psycho-engine-fixes/src/mods/perf/lighting_signatures/)
were extracted from the verified executable above. Runtime expectations
overlay only the candidate's owned CALL/JMP windows; an arbitrary current body
is never learned as a native contract. The local
[lighting_contract.rs](../psycho-engine-fixes/src/mods/perf/lighting_contract.rs)
validates mappings at preparation and uses integer volatile byte/DWORD
comparisons without hot allocation, locks, WinAPI queries, or diagnostics.
These are exact code checks, not module/version detection.

| Candidate | Exact range, end exclusive | Contract checked |
|---|---|---|
| Scores | `0x00B70390..0x00B70490` | Complete native sorter |
| Scores | `0x00B9DBE0..0x00B9DCAD` | Current score, final rounding and wrapper store |
| Scores | `0x00EC6040..0x00EC6054`, `0x00EC605D..0x00EC60FA` | Native sqrt entry/body |
| Scores | `0x00ED2808..0x00ED281E`, `0x00ED281E..0x00ED2855` | Classifier and admitted control/return route |
| Scores | `0x00B681CF..0x00B68243` | First caller's native gates and local-bound argument dispatch |
| Scores | `0x00BB4EDA..0x00BB4F13`, `0x00C0603D..0x00C0607A` | Other caller gates, bound copies and dispatch |
| Scans | `0x00B9D150..0x00B9DADF`, `0x00B5BCA0..0x00B5C357` | Complete shadow/camera consumers, frame and transfer paths |
| Scans | `0x00B5AC20..0x00B5AC56` | Complete indexed scene getter |
| Scans | `0x00B70600..0x00B7067D`, `0x00B70700..0x00B70783` | Existing nonnull-property iterators and slot use |
| Scans | `0x004A0C10..0x004A0C86`, `0x00457990..0x004579D5` | Normalizer and vector-length access to native temporaries |
| Scans | `0x004579E0..0x004579F4`, `0x004019B0..0x004019C4` | Fixed scalar-by-value sqrt wrappers, not a pure FSQRT leaf |

Ranges are not an exhaustive immutable-world proof. In particular, the first
sort caller's earlier bound-copy path, upstream dispatch, other arithmetic
callees, external alias writers, and code changes after admission are not
made immutable by these checks. The original native invocation contracts and
remaining concurrency conditions still apply to the experimental paths.

Compiled production bridge inspection established the emitted stack offsets,
`RET 4` cleanup, saved nonvolatile registers, and exact resume instructions.
The native and compiled sorter instruction streams have identical non-call
operations and branch destinations by instruction ordinal. The only two CALL
differences are the retained native current scorer through its immutable
pointer and the compiled predecessor load adapter; their targets were checked
in the actual compiled image.
Admission bridges preserve flags/all GPRs and the complete x87/SSE state via
a 16-aligned 512-byte FXSAVE/FXRSTOR image before tail dispatch or replay.
Per-candidate advances/transfers execute integer bookkeeping and the displaced
native x87 instructions, without a Rust dispatch or FPU save on each advance.
The raw
[implementation evidence](../analysis/radare2/output/fnv_location_lighting_candidate_implementation_20261007.txt)
retains the new primary MCP wrapper output, bounded native supplements,
signature bytes, and compiled production ABI evidence. This is instruction
qualification; it is not an executed native behavioral test.

### Conditional work budget and qualification boundary

| Work | Native mechanism | Implemented candidate, under stable native invocation |
|---|---|---|
| Property score calls | Ordered case `k*(k+1)/2` | `k` native current calls, cached predecessor loads |
| Property comparisons/relinks | Insertion comparisons can be quadratic | Same comparisons/relinks; no comparison-complexity improvement |
| Score admission | No candidate guard | One FXSAVE/FXRSTOR, 715 common signature bytes plus 57/61/116 caller bytes, and an O(k) finite/chain prewalk |
| Scene enumeration | Repeated indexed head walks | One initial native lookup; linear cursor advances with native reset/wrap rules |
| Scan admission | No candidate guard | One FXSAVE/FXRSTOR per pass start; 2984 shadow or 2256 camera signature bytes, plus provider/scene checks |
| Scan advances | Head/count plus indexed chain work | Integer bridge saves, one 54-byte getter check, native count gate and bounded next-link/payload reads |
| Camera accepted candidate | Native temporary writes | Two integer cursor/zero-marker transfers plus replayed native operations |

For indices `0..m-1`, the indexed getter/inline walk reads a next link
`m*(m+1)/2` times including native look-ahead reads. An admitted shadow pass
uses its initial native look-ahead and one link per positive successive
lookup. The camera fast path retains a next-link output as well as cursor
advance, so it has up to two link reads per positive successive lookup.
Narrowed-index head restarts begin another native index cycle. Count-rejected
lookups do not dereference a retained node. Signature/admission work and bridge
saves can outweigh removed work on small lists; no threshold or elapsed-time
benefit has been assumed. These budgets do not estimate FPS.

The affected core suite, supported
`i686-pc-windows-gnu` release build, formatting, and diff checks passed.
The compiled native bridges were inspected against the bounded executable
instructions. Native sorter/scan equivalence, nested/concurrent engine
execution, transition/retirement behavior, real provider coexistence,
load-to-gameplay startup, images, and elapsed performance were not run.
No mirrored sorter, mocked native provider, or fabricated scene is presented
as behavioral acceptance. These are implemented default-on experiments with
static qualification and explicit unresolved native conditions; they are not
accepted or released engine fixes.

### Owner-started playtest: activation check

The owner reported a started playtest on 2026-10-07. The observed session's
startup completed at `2026-10-06T22:43:48.731Z` (01:43:48 local time).
Both switches in the deployed `FalloutNV/syringe/psycho_engine_fixes.toml`
were `false`, and the current log contained zero `[LIGHT_SCORES]` and zero
`[SCENE_LIGHTS]` messages. This session does not exercise either candidate.
The bounded
[activation evidence](../.reports/fnv_lighting_candidate_activation_20261007.txt)
preserves the configuration values, session timestamps, and absence of
preparation/admission messages without attributing unrelated log warnings.

Testing these candidates requires explicitly setting the selected switch to
`true` in the deployed configuration before a full restart. A successful
enabled startup must report bridge preparation and DeferredInit admission
under the corresponding subsystem tag. Those messages establish preparation
and admission at that time; the implementation has no per-operation optimized,
fallback, score-call, traversal, or timing counters. The messages therefore
cannot prove actual optimized-path use, subsequent rejection, native output
equivalence, or a performance improvement. No such result is recorded here.

### Owner-started enabled playtest: one admitted candidate

The subsequent session started at `2026-10-06T22:52:12.473Z` with both
deployed settings `true`. Score bridges prepared at `22:52:12.479Z` and scan
bridges at `22:52:12.480Z`. At DeferredInit (`22:52:36.194Z`), score reuse
reported enabled, while sequential scanning reported
`Native contract changed; indexed providers retained`. The core then logged
`[EVENT] Game engine ready`. The observed log continued to `22:58:00.269Z`;
CrashLogger contained only its session header and no captured crash trace.
The raw
[enabled-playtest evidence](../.reports/fnv_lighting_candidate_enabled_playtest_20261007.txt)
preserves these messages and the owner's responsiveness observation.

This distinguishes configured enablement from admitted optimization. Fix 1
passed its DeferredInit capability check, but its per-operation guards can
still dispatch to captured providers. No operation/hit/fallback counters exist
to determine how often optimized sorting executed. Fix 2 installed its inert
bridges but rejected optimization admission; its monotonic rejection latch
retains native/indexed traversal for this session. The warning covers either
an earlier rejection latch or a failed consumer/callee/provider qualification.
It does not identify the failed range, observed bytes, or earlier rejection
point. The log therefore does not prove a particular incompatible provider,
engine change, or bug in the candidate's own expected bytes. The targeted
repository source search found no other direct patch at the guarded addresses;
that search is not exhaustive runtime ownership evidence.

The owner reports that a difference is hard to estimate but the game feels
more responsive. Record this as subjective runtime observation, not measured
latency/FPS or attribution to fix 1. Sequential scanning was not optimized in
this run, so the report cannot validate its reduced-work path. A precise
rejection diagnostic is needed to close that activation failure; the guard
must remain intact rather than be weakened to admit unknown native code.
No production changes, hook changes, or new instrumentation accompanied this
log inspection, and no new startup baseline or release acceptance is declared.

### Sequential-scan rejection follow-up: missing runtime contract evidence

The requested correction starts from the owner's observed admission failure
above. Its exact failing range remains unknown. The subsequent static audit
used the mandatory radare2 MCP against the supported executable and the
deployed Psycho DLL, restricted to the admission functions, integer getter
checker, and native-range data needed to investigate this failure. The raw
[rejection audit](../analysis/radare2/output/fnv_scene_light_scan_rejection_audit_20261007.txt)
preserves the instruction evidence.

The deployed integer getter checker has all fourteen correct comparison
immediates for the complete 54-byte native getter. The deployed nine immutable
range addresses, lengths, and byte arrays equal the verified native extracts.
The compiled admission and initialization paths confirm that rejection may be
latched before DeferredInit. These checks do not expose the installed process's
owned overlay buffers or current engine bytes. They therefore do not prove
which runtime range changed, that Psycho encoded an incorrect overlay, or that
another provider caused the rejection. No such cause is assigned.

Narrow rejection instrumentation now runs only after the existing DeferredInit
admission check rejects scanning. It reports whether the latch was already set,
then compares the current two consumers and seven callees with their existing
exact expectations, including Psycho's own overlays. Each failed range reports
its name, the first mismatched address, and the expected and observed byte.
Unreadable ranges report their read failure. Captured getter mismatches report
the CALL address and captured target. All reports use the established logger
and `[SCENE_LIGHTS]` tag.

This is evidence collection, not a traversal correction or runtime acceptance.
The native assembly bridges, cursor layout, exact signatures, provider chaining,
monotonic rejection policy, configuration, and startup installation order are
unchanged. The report may allocate a bounded read buffer for each known range
on this cold failure path; it adds no work to successful admission or scan
advances. No new global owner, TLS, worker, dependency, or configuration field
is introduced. A later matching snapshot cannot reconstruct a transient earlier
rejection; that case is reported explicitly as unresolved, and traversal stays
native. The instrumentation itself has not been observed in the owner's game.

The affected suite and supported 32-bit release build qualify the diagnostic
change only. At that stage, the exact rejection address/bytes were missing.
The subsequent static comparison below establishes a concrete compatibility
defect without requiring another startup. A rejection snapshot would still
identify the first failed contract in that particular session; it is not
available here. Relaxing or learning unknown code is not authorized by the
generic warning. No new startup baseline, accepted scan behavior, performance
result, or released correction is claimed.

### Static compatibility cause: post-load math replacements

The concrete defect in Psycho's admission policy is requiring three math
routines to remain byte-for-byte vanilla even when the installed optimization
path supplies verified replacements. The mandatory radare2 MCP inspected the
actual installed Stewie DLL, its callback dispatch and write instructions,
the complete replacement leaves, and the supported native executable. The
[math compatibility contract](../analysis/radare2/output/fnv_scene_light_scan_math_compatibility_contract_20261007.txt)
retains the raw instructions, exact payload bytes, source comparison, options,
phase chain, and unresolved runtime conditions. This is a scan-admission cause,
not proof of a fundamental engine-wide FPS cause.

| Guarded native entry | Installed implementation | Write length | Vanilla first byte | Replacement first byte |
|---|---|---|---|---|
| `0x004A0C10` | SSE vector normalizer | 100 bytes | `55` | `66` |
| `0x00457990` | SSE vector magnitude with x87 return | 49 bytes | `55` | `51` |
| `0x004579E0` | `FLD [ESP+4]; FSQRT; RET` | 7 bytes | `55` | `D9` |

Each replacement necessarily fails the current signature at its first byte.
`qualified()` checks all seven shared callees for both shadow and camera
consumers. Consequently either misc math write alone, or the rendering
magnitude write alone, is sufficient to reject both scan paths. DeferredInit
then leaves `READY` false and sets the shared process-lifetime `POISON` latch.
An earlier pass can also latch rejection. Once rejected, both paths continue
using indexed providers for that process.

The actual `nvse.log` records successful loading of Engine Optimizations,
Stewie Tweaks, and NVTF. The inspected Stewie INI selects `[Inlines] bMisc = 1`
and `bRendering = 1`. In the reference source, when custom controller mode is
off, Engine Optimizations module presence enables vanilla inlining; the
installed DLL contains the corresponding module lookup, flag store, option
reads, and branches. The module lookup is evidence of the existing writer's
selection mechanism, not a proposed Psycho compatibility check.

The installed listener is registered at preferred DLL address `0x10073AC0`.
Message type 9, PostPostLoad, resolves through its actual dispatch tables to
`0x10073F44`. The inline-enable branch at `0x10073F87` reaches the misc and
rendering installers after checking that byte `0x006FA89E` is `E8`. Verified
copy instructions write the three payloads above; bounded PE extraction
matched their complete bytes to the reference literals. xNVSE dispatches
PostPostLoad after normal plugin loading. Psycho prepares the native ranges
at the earlier pre-CRT barrier and checks them again at DeferredInit. This
establishes the exact phase relationship that permits preparation to succeed
and later qualification to reject the changed math bodies.

The supported vanilla executable has `E8` at the writer's conflict gate, but
the historical live byte and inline-enable flag were not captured. Loaded
modules and selected options do not prove that this gate ran successfully in
that particular session. The proven result is deterministic incompatibility
with these installed replacements whenever they execute. Which contract
rejected first in the owner's recorded session remains unknown; another
changed consumer or provider is not excluded by this audit.

The complete leaf instructions also close the relevant cursor-overwrite gap:

- The normalizer reads/writes only the three float components at `ECX+0/4/8`.
  It has no external call, stack write, scene/node access, or x87 traffic.
- Magnitude reads the same three components. It reserves one private word
  below entry `ESP`, writes the SSE result there, loads it into `ST0`, restores
  `ESP`, and returns. It does not write the caller's frame or vector.
- The scalar wrapper reads only its by-value argument at `ESP+4`, returns its
  square root in `ST0`, and performs no memory write or external call.

These leaves do not reach the shadow or camera cursor slots established in
the existing closure evidence. Their numerical behavior is not asserted to
equal vanilla: SSE arithmetic, rounding and square-root exception paths can
differ. A scan correction must keep calling the installed math bodies and
preserve their existing results.

The bounded correction is capability-based admission of vanilla or each exact
verified math implementation. Alternatives must be supported both during
initial preparation and subsequent qualification. A full-range alternative
must include the unchanged native tail beyond the copied leaf; arbitrary
unverified tail bytes must not be admitted. Consumer windows, getter,
property iterators, captured providers, cursor ownership, and monotonic
rejection remain enforced. Existing score reuse guards different math entry
points, so this specific scan incompatibility does not imply that score reuse
also rejected.

No module/version identification, learned signatures, wildcard admission,
other-mod patch, loader reordering, arithmetic replacement, or rejection reset
is needed or justified. Hot qualification must retain its existing allocation,
lock, and logging constraints. This research does not resolve scene/node
retirement or thread exclusion, execute a corrected scan, or establish an FPS
gain. No production code changed in this research pass.

### Implemented correction: exact math alternatives

Sequential-scan preparation and qualification now accept vanilla or the three
complete verified math replacements described above. `NativeRange` owns one
optional immutable alternative in addition to its established native/owned
expectation. Only the normalizer, vector magnitude and scalar wrapper use it.
The alternative files retain all native bytes beyond the installed leaf:
18 bytes for the normalizer, 20 for magnitude, and 13 for the scalar wrapper.
These bytes remain guarded even though the replacement returns earlier.
The [implementation contract](../analysis/radare2/output/fnv_scene_light_scan_math_admission_implementation_20261007.txt)
records input derivation, executable acceptance evidence, bounded work costs,
startup scope, and compiled qualification instructions.

Preparation validates equal range lengths, prohibits combining a math
alternative with an owned overlay, and accepts either complete body. Runtime
qualification retains both immutable choices, so seeing vanilla at the
pre-CRT barrier does not prevent admitting a verified later replacement.
The cold rejection report also accepts either complete supported snapshot.
For an unsupported body with the alternative's entry byte, it reports the
actual differing instruction or tail byte against that alternative.
No arbitrary live code is learned, no module is identified, and no installed
math implementation is rewritten.

The consumer overlays, getter/property contracts, all captured-provider checks,
cursor bridges, native arithmetic, readiness publication and monotonic
rejection latch retain their existing behavior. A previously rejected pass or
process is never promoted by this correction. Scene/node lifetime and exclusion
of concurrent engine/code writers remain the earlier candidate conditions;
accepting known math code does not prove them.

The offline regression executes actual production preparation, volatile
comparison and diagnosis in the supported Wine test process. Its owned code
mapping contains the verified executable bytes or installed leaf plus native
tail; a test-only seam relocates the production contract's address. Both
already-installed preparation and post-preparation replacement admission failed
before the correction and pass afterward for all three bodies. Vanilla
restoration also passes. Mutation of every byte in each accepted complete
input rejects, including all untouched tails. These are memory-admission
results; the test does not model or execute native traversal or math.
The affected core suite and supported 32-bit release build also pass.

The hot checks retain integer volatile reads with no allocation, blocking lock,
logging or FP arithmetic. Since the verified alternatives differ in their first
aligned DWORD, successful admission adds one failed native DWORD read per
installed alternative, at most three additional engine DWORD reads per pass.
The per-advance bridges add no work. Compiled qualification and its sole range
comparator were inspected completely through radare2 and contain no FP register
use or allocation/library calls. These bounds are not an FPS measurement.

The startup delta is private core static layout plus three small immutable byte
arrays and admission code. Bounded inspection found the core imports and TLS
extent/callback identities unchanged from the deployed artifact. Preparation
order, owners, config layout, workers, dependencies and lifecycle callbacks are
retained. Code/static addresses can still move, so this does not establish a
new startup baseline. Offline qualification does not establish native gameplay
equivalence, representative Proton load-to-gameplay acceptance or performance.
The following runtime inspection records the owner's subsequent deployment;
no release, packaging or commit acceptance is declared.

### Runtime inspection after the math admission correction

The 2026-10-07 session begins at `00:47:47.309Z`. Both deployed switches are
true. At inspection, the installed core file equals the corrected workspace
release DLL; this is an on-disk comparison, not a live-process memory read.
Raw core/CrashLogger snapshots and selected world-rendering records are retained
in `.reports/fnv_lighting_math_compatibility_playtest_20261007.txt` and its
`_core.log`/`_crash.log` companions.

Score bridges prepared at `00:47:47.315Z` and scan bridges at
`00:47:47.316Z`. Both features report `Candidate enabled; runtime equivalence
unvalidated` at `00:48:13.215Z`, immediately followed by the engine-ready
marker. Sequential scanning therefore passed both consumer/shared-callee and
captured-provider qualification with no earlier rejection latch at that
boundary. The prior startup rejection is absent in this session. Score reuse
also passed its own code/provider qualification. The log does not identify
which supported math alternative matched.

OMV's same-session world transaction and later reliability reports demonstrate
actual world rendering after DeferredInit. The retained final report at
`00:58:57.951Z` records 54,600 Presents and 48,794 applied world transactions;
its `failures=0` belongs to the OMV world pipeline, not these lighting features.
The core snapshot continues to `00:59:02.350Z`. CrashLogger contains its
startup header only, with no recorded exception stack. These observations
show admission followed by world rendering, not visual equivalence or a
performance comparison.

Per-operation usage remains unobserved. Score selection may silently forward
to the captured provider for unsupported code, x87 state or input/list data.
Scan passes may silently latch native traversal after a later contract change,
and null/empty or property-owned paths retain their existing native behavior.
Neither feature logs optimization hits, fallback counts, visited light counts,
score-call counts or CPU time. Consequently successful admission cannot prove
that every eligible operation used an optimized path or quantify its benefit.

The snapshot also contains a heartbeat warning at `00:57:47.905Z`: age
33,651 ms, `loading=true`, with AI/Havok start/join counters balanced and
neither reported active. A later focus-regain message and further world
Presents are recorded. The warning has no fault stack or lighting-path marker;
its cause and any relation to these changes remain unknown. This single run
does not establish unrestricted traversal correctness, repeated startup safety
or an FPS improvement. No production change accompanied the log inspection.

## Evidence ledger

| Evidence | Retained content used here | Additional direct binary checks |
|---|---|---|
| [Main frame analysis](../analysis/ghidra/output/perf/combat_perf_analysis.txt) | `0x0086E650` and its lighting/rendering call list | `0x0086ED90`, `0x0086EDE8`, and `0x0086EE4E` ordering |
| [AI thread deep analysis](../analysis/ghidra/output/memory/ai_thread_deep.txt) | `0x0086FF70`, worker body, actor loops | Rendering branch call chain and worker waits |
| [Combat performance deep analysis](../analysis/ghidra/output/perf/combat_perf_deep_dive.txt) | Worker creation references, stages, and `0x008C7990` | Setup branch, join target, and infinite waits |
| [AI and main thread parallel work](../analysis/ghidra/output/memory/ai_main_thread_parallel_work.txt) | `0x0096DB30` actual actor loop | Actor/Character/Creature slot `+0x348` targets |
| [Light selection continuity closure](../analysis/ghidra/output/perf/graphics_fnv_pbr_light_selection_continuity_closure.txt) | Sorter assembly, three call sites, updater gates, staging bounds | Sorter/scoring path and `0x00B681CF` through the sorter call |
| [Disassembled callers](../analysis/ghidra/output/memory/disasm_callers.txt) | `0x00B5DAC0` candidate-array/subtree branches | Geometry candidate scan and light/property membership helpers |
| [Scrap heap identity contract](../analysis/ghidra/output/memory/scrap_heap_identity_thread_contract.txt) | Allocator call sites in `0x00B5DAC0` | Candidate scratch lifetime in the admitted branch |
| [Selector and draw identity bridge](../analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_selector_vtable_draw_identity_bridge_audit.txt) | Dispatcher references and current-pass ownership bridge | Ordinary `0x00B9A120` drain and native state reuse |
| [Close terrain pass entry contract](../analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_entry_runtime_contract.txt) | `0x00B98E80` geometry/shader callback path | Draw-dispatch instructions |
| [Frustum and LOD culling audit](../analysis/ghidra/output/perf/graphics_fnv_taa_frustum_lod_culling_contract_audit.txt) | Native world culling/frustum route | NiNode virtual table, downward updates, and visibility traversal |
| [Native lighting update evidence](../analysis/radare2/output/fnv_location_lighting_update_contract_20261006.txt) | New radare2 output for queue producers/drains, movement gates, actor flags, property markers/dirtying, visibility/dimmer fan-out, scoring ABI, and alternate sort gates | Executable identity rechecked against the same SHA-256 |
| [Camera contract output](../analysis/ghidra/output/perf/graphics_fnv_ao_temporal_camera_contract_audit.txt) | World camera provenance at both `0x00B803B0` call sites | Camera inputs and primary-scene receiver rechecked in native instructions |
| [Light scan and cache evidence](../analysis/radare2/output/fnv_location_light_scan_cache_contract_20261006.txt) | New radare2 output for indexed linked-list access, shadow and camera-dependent scan callers/gates, inlined head restarts, shared-score initialization, fade/material invalidators, and dirty-cache refresh | Executable identity rechecked against the same SHA-256 |
| [Lighting qualification evidence](../analysis/radare2/output/fnv_location_lighting_qualification_contract_20261006.txt) | Processed-prefix supporting contracts, CRT math exception/control paths, addition/retirement receivers, queue locks, pooled node retirement, and distinct scan index widths | Executable identity rechecked against the same SHA-256; exploratory labels/probes corrected in the capture |
| [Lighting closure evidence](../analysis/radare2/output/fnv_location_lighting_closure_contract_20261006.txt) | Scene constructor/destructor and registration, alternate drain routes, indirect dispatch, caller bound snapshots, complete consumer/normalizer liveness, candidate window bytes, semaphore release/wait distinction, worker phases, serial world-update branch, actual light-transform writer, actor transform deferral, and normal pre-CRT installation ordering | Same executable identity; raw native output and bounded PE/objdump supplements distinguish proof from discovery and mark rejected exploratory probes |
| [Candidate implementation evidence](../analysis/radare2/output/fnv_location_lighting_candidate_implementation_20261007.txt) | Scalar wrapper MCP output, bounded caller supplements, embedded signature byte verification, compiled bridge/cdecl ABI, and actual sorter instruction-flow comparison | Same executable identity; compiled instructions provide static qualification only, with native runtime behavior unaccepted |
| [Scan rejection audit](../analysis/radare2/output/fnv_scene_light_scan_rejection_audit_20261007.txt) | Native getter, deployed admission/initialization contract, compiled range comparison, and the nine deployed immutable native ranges | Getter comparison immediates and deployed native extracts agree; exact runtime rejection remains unknown |
| [Scan math compatibility contract](../analysis/radare2/output/fnv_scene_light_scan_math_compatibility_contract_20261007.txt) | Actual installed callback dispatch, configuration and writer gates, three complete math payloads, copy instructions, native first bytes, and leaf memory/stack contracts | Exact replacements necessarily reject vanilla-only shared admission; historical gate execution and first mismatch remain unobserved |
| [Scan math admission implementation](../analysis/radare2/output/fnv_scene_light_scan_math_admission_implementation_20261007.txt) | Complete compiled qualification/comparator instructions, full-range alternative derivation, fail-first/passing production admission regressions, bounded memory-read costs and startup scope | Known math alternatives admit at preparation and after replacement; unknown bytes reject; full native traversal/startup remain untested |

The original ledger's direct checks are summaries of the initial radare2
session. The native lighting captures preserve the continued audit's raw
tool output. Existing retained text is linked rather than duplicated. The
executable remains the primary source for any address-sensitive follow-up.

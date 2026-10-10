# Fallout New Vegas location performance static audit

Research date: 2026-10-06. Candidate implementation and Fairfax follow-up:
2026-10-07. Further loop-contract research and six-site implementation:
2026-10-10.

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
both vanilla and modded locations, without intense combat. The later Fairfax
Ruins report identifies a drop from approximately 80-100 FPS to 30 FPS. A
specific comparison position, camera direction, and loaded scene inventory
were not supplied. Turning the camera away restores some FPS; facing the
opposite direction and moving the actor slightly forward restores FPS,
according to the owner's follow-up. Stationary duration remains unspecified.
After the existing optimization work, the owner reported approximately
10 FPS gained in some places and 3-4 FPS in others with OMV absent. The
comparison baseline, exact deployed feature set, positions and settings were
not specified. This is a gameplay observation of an improvement, not a
controlled per-feature measurement or identification of the Fairfax consumer.
The research covers native work that scales with location content even when
the visuals appear simple. The
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

- **Owner observation:** FPS varies across locations and does not require
  combat; Fairfax Ruins can drop from approximately 80-100 FPS to 30 FPS.
  Turning away partially recovers FPS, and facing the opposite direction plus
  a small forward movement restores it. The later OMV-absent observation
  reports gains of approximately 10 FPS in some places and 3-4 FPS elsewhere,
  without enough comparison detail to attribute those gains to one feature.
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

## Fairfax Ruins: remaining CPU candidates

This follow-up responds to the owner's report of approximately 80-100 FPS
falling to 30 FPS at Fairfax Ruins. Those rates correspond to approximately
10-12.5 ms and 33.3 ms per frame: the reported difference is approximately
20.8-23.3 ms. This conversion describes the observation; it does not assign
that time to CPU work, GPU work, a particular native function, or Psycho.

The executable identity was reverified before reusing addresses. New native
instructions and the limited PE pointer checks are preserved in
[Fairfax candidate evidence](../analysis/radare2/output/fnv_fairfax_performance_candidates_contract_20261007.txt).
No production source, configuration, hook, or installed binary changed in
this research pass. The current core log records both existing lighting
candidates enabled. Those lifecycle messages do not count optimized operations
or identify which path consumed a Fairfax frame.

### Candidate ranking and what the report does not establish

The following ranking is by intervention scope and proven redundant work,
not measured contribution to Fairfax's frame time.

| Candidate | Verified avoidable work | Proposed scope | Status |
|---|---|---|---|
| Property-sort ordered-prefix shortcut | The existing score-reuse candidate still walks every predecessor on ascending or equal-key input | Add one maximum-prefix comparison inside the existing private sorter; retain its ordinary insertion path | Most direct extension of the existing candidate; exact arithmetic and engine ownership qualifications still apply |
| Cached-pass refresh without a separate count walk | An admitted dirty lighting pass counts eligible lights, then enumerates them again to write the array | Optimize only passes whose existing capacity is sufficient for every list node plus the directional slot; retain native growth/overflow paths | Count widths, allocation boundary, predicates, and continuation are closed below; concurrent ownership and final bridge qualification remain open |
| Transparent-pass depth reuse | The native merge-sort comparator recalculates both camera-depth keys at every comparison | Reuse the unchanged merge head's key inside one merge run, with private local state | New mechanism independent of property-light scoring; math-state, bound lifetime, and hook admission need further closure |
| Compound-frustum snapshot allocation removal | Each object reaching the compound branch allocates and frees a plane-mask snapshot, including objects rejected by its test | Keep the exact mask snapshot/restore around native testing and child callbacks, using bounded private invocation storage for admitted capacities | Separate integer-state opportunity; native bracket and allocator boundary verified, structural lifetime and recursion budget remain open |

None of these needs a cross-frame cache, a reduced draw distance, fewer lights,
removed actors, different visibility, or changed shadow quality. None is
established as the source of the full reported loss.

Scene population remains unknown. The place name is not evidence of a large
light list, many alpha passes, a particular actor population, or missing
occlusion data. The partial recovery from turning and recovery after turning
plus moving are owner observations. Whether the loss persists after remaining
stationary is unresolved. No native path or scene object was observed during
either transition. Consequently, this research does not classify the symptom
as a stationary steady-state CPU bottleneck or exclude shader/overdraw cost,
streaming, scripts, physics, or plugin work.

The clarified symptom routes further static investigation to view-dependent
visibility and the work it admits. It does not prove that translation alone
changes FPS: the reported recovery combines translation and rotation. The
compound-frustum path below has a separate per-object allocation cost, while
transparent sorting has camera-dependent arithmetic. Lighting refresh remains
a candidate only under its actual invalidation gates. None is attributed to
Fairfax by this observation.

### Property sorting: remove the ordered-input search

The complete `0x00B70390..0x00B7048D` body was rechecked. It scores the
current node, starts comparison at the head, advances until that node, and
inserts before the first predecessor with a strictly greater score. Ordered
equal scores do not trigger insertion. The current score-reuse implementation
changes predecessor scoring into a load; it retains that entire search.

For stable ordinary finite keys, already ascending input of `n` nodes still
requires `n * (n - 1) / 2` predecessor comparisons. Equal-key input has the
same comparison count. These are exact loop budgets, not timings or a claim
that large property lists occur at Fairfax.

There is a smaller opportunity than replacing the whole sort. The processed
prefix is contiguous and sorted after each iteration. The current node's
previous link therefore identifies the last, maximum-key node of that prefix.
This follows from the native insertion/remove operations preserving the
unvisited suffix and from the saved original-next pointer controlling the
outer loop. It is conditional on the intact, stable-key list invariant already
described in [processed-prefix proof](#fix-1-processed-prefix-proof-and-its-boundary).

After the native current-score call, compare that maximum-prefix key with the
current key using the existing x87 comparison convention. If both keys belong
to the qualified ordinary domain and the maximum is less than or equal to the
current key, the native predecessor search cannot find an insertion point.
The node stays where it is; advance through the same saved original-next
pointer. Otherwise execute the existing private insertion search unchanged.
The first node has no predecessor and keeps its original path.

The shortcut must not use the property's overall tail: that tail can still
belong to the unvisited suffix. It must not compare a newly scored light
against an unrelated bound's value. Wrapper `+0x0C` remains shared engine
scratch; this design inherits the current candidate's unresolved exclusion
of external score/input mutation.

For admitted ascending or equal-key input, the new comparison budget is
`n - 1`, plus the existing one score calculation per node and admission walk.
For input requiring insertions, it adds at most one shortcut comparison per
non-first node before the retained insertion work. Worst-case insertion
complexity remains quadratic. This is not a universal `O(n log n)` sort fix.

Implementation must preserve node identity, head/tail, count, fence, dirty
state, the saved traversal successor, stable equal-key order, and conditional
cache-key clearing at `0x00B70480`. A skipped search must not clear the key.
Use a private change to the current sorter rather than modifying the shared
native sorter or capturing a new engine-wide sorting boundary.

An additional comparison is not automatically invisible. Qualify the actual
x87 stack/control/status behavior, including subnormal operands and computed
nonfinite keys; finite source coordinates alone do not prove finite scores.
Unsupported keys must keep the existing operation. The proposed shortcut is
not permission to replace x87 ordering with Rust/SSE total ordering or to
silently widen the existing candidate's arithmetic admission.

### Cached-pass refresh: exact native array contract

The existing dirty refresh in `0x00BB4740` is conditional:

1. Property `+0x38` must match the prepared key and dirty byte `+0x74` must
   be nonzero at `0x00BB4F13..0x00BB4F24`.
2. It visits the cached pass pointer array through property `+0x3C`, array
   storage `+0x04`, and array extent `+0x10`.
3. Pass IDs `0x17F..0x1BA` take the two-walk branch. Other IDs retain their
   separate handling. The reference enum names this range as 3.0 lighting
   variants; its later extension alias also assigns 383 to an unrelated name.
   The binary range is the contract, not that alias.
4. The loop eventually clears dirty at `0x00BB50B1`, checks the key again,
   and either returns the cached array or rebuilds it. Shadow-related branches
   can invalidate the key during refresh; they must remain intact.

The native pass record has these verified fields:

| Offset | Width | Native use |
|---|---|---|
| `+0x00` | Pointer | Geometry identity |
| `+0x04` | `u16` | Pass ID |
| `+0x09` | `u8` | Active staged light count |
| `+0x0A` | `u8` | Allocated pointer capacity |
| `+0x0C` | Pointer | Engine-owned light-pointer array |

Slot zero receives the pointer loaded through the active scene at
`0x00BB4F2A..0x00BB4F40`; ordinary eligible property lights occupy subsequent
slots in iterator order. Do not replace the slot-zero identity with a guessed
sun, another scene root, or a native-light pointer: the array stores the native
wrapper identities selected here.

`0x00B70600` starts and `0x00B70700` advances the property iterator. Both use
thiscall with a stack cursor-pointer argument and `RET 4`. Their complete
native bodies contain integer reads, cursor stores, and branches. They do not
allocate, acquire/release references, dispatch callbacks, or perform floating
point arithmetic. They inspect list nodes, wrapper visibility word `+0x110`,
wrapper native-light pointer `+0xF8`, APP_CULLED at native light `+0x30`, and
wrapper shadow byte `+0xEC`. A null payload terminates according to the native
iterator; it is not permission to skip ahead to a later node.

For `k` eligible ordinary lights, the count walk normally records `k + 1`,
including slot zero. No eligible lights still produces count one. The counter
is BL, so `k = 255` wraps it to zero and takes the native zero-count branch.
Larger populations have the native modulo behavior. An optimization must
neither clamp nor reinterpret those cases.

The stored property node count at `+0x68` is **32 bits**. Its small accessor
`0x00B704B0` returns only AX; that narrowed accessor is unsuitable for a
capacity proof. The full-width read at `0x00B71498`, DWORD insertion increments
in `0x00B58570` and `0x00B713C0`, DWORD marker insertion increments in
`0x00B718B0`, DWORD retirement decrements in `0x00B71600`, and DWORD reset in
`0x00B71300` verify the actual storage width and the inspected maintenance
invariant. Sorting itself does not change this count.

If capacity is insufficient, `0x00BA8C30` frees the old array through the
engine allocator and clears its pointer. `0x00BA8C00` reads a byte argument,
allocates four bytes per entry through `0x00AA3E40`, and publishes `+0x0C`.
The caller updates capacity. Neither the growth path's allocation failure nor
its allocator/provider behavior is redesigned by this candidate.

### Cached-pass refresh: preferred bounded fast path

The narrowest design removes the count walk only when allocation is already
provably unnecessary. At the two-walk branch, let `N` be the full DWORD node
count and `C` the byte capacity. Admit only an intact stable property list
with no active fence, `N <= 254`, a valid existing array, and `C >= N + 1`.
Evaluate `N + 1` after the limit check, without truncating `N` to a byte.

Every eligible light comes from one of those `N` nodes, so `k <= N` and
`1 <= k + 1 <= N + 1 <= C <= 255`; no native growth call can be required.
Start and advance the **actual native iterators** once, write slot zero and eligible identities
in their original order, and publish the resulting byte count. Leave capacity
unchanged and resume the ordinary pass-loop continuation at `0x00BB5093`.
Do not add a selection cap: the admitted population is fully enumerated, and
all other states execute the complete native branch.

The bridge needs to retain property ESI, pass EDI, the outer pass index EBP,
its stack-local copy, the slot-zero local, and any downstream-live caller
locals. The native branch uses a temporary cursor and count local at
`S + 0x1C` and `S + 0x64` after its full prologue. Establish those positions
from the caller's actual stack/register instructions, not radare2's inferred
argument labels. Resume without changing x87 state. The existing three sort
CALL overlays fall before this proposed refresh window; their published
ownership must be respected by any code admission.

This version needs no heap allocation, persistent cache, per-thread table,
additional references, or temporary pointer array. It halves eligible-list
enumerations for an admitted pass, while retaining its output writes and
native iterator calls. Its benefit depends on actual dirty-pass frequency,
list size, and retained capacity. The upper-bound capacity gate can reject
passes that have many filtered nodes; no current evidence establishes its hit
rate at Fairfax.

A broader gather-once design could preserve the count walk while recording
eligible pointers into bounded local storage, then reuse them when actual
capacity is sufficient. That would need up to 254 pointer slots and additional
stack stores. Retain native allocation followed by fresh enumeration when
growth occurs: reuse across allocator calls would introduce an unproved input
stability contract. Cross-pass or cross-frame snapshots extend lifetime still
further. These broader variants are not the preferred first implementation.

The narrowed design closes count width, eligibility predicates, overflow
exclusion, array ownership, no-growth admission, and the native continuation.
It does not prove every list/count writer, property sharing route, concurrent
mutation exclusion, foreign replacement, or the final compiled bridge. The
array-capacity check cannot pin list nodes or prove metadata consistency.

### Transparent-pass sorting: independent repeated arithmetic

New native caller and comparator evidence establishes this chain:

`0x00B65AE0` or `0x00B65DC0` -> `0x00B63A50` -> `0x00B99A10`
-> two `0x00B99630` sorts using comparator `0x00B98B20`.

The verified calls into `0x00B63A50` are `0x00B65C32` and `0x00B65E1F`.
That routine visits the accumulator's batch renderers at `+0x174`, bounded
by `+0x18C`, passing camera `+0x08` and byte mode `+0x31` to
`0x00B99A10`. The latter publishes camera global `0x011FFE38` and mode byte
`0x011FFE35`, then sorts the two group lists through renderer `+0x70` and
`+0x74`. It uses thiscall, two stack arguments, and `RET 8`.

`0x00B99630` is already a stable bottom-up merge sort. Its run width starts
at one and doubles. At `0x00B996B7` it calls the supplied cdecl comparator
with pointers to the two nodes' payload fields. A positive comparison takes
the right node; a nonpositive comparison takes the left. Equal keys therefore
keep their native order. It preserves node identities and rebuilds links,
head, and tail. Replacing this with merge sort again is not an optimization.

The payload is a render-pass record: its first pointer leads to geometry,
whose `+0x20` leads to the world bound. This is verified by comparator reads,
the pass record layout, list insertion through `0x00B9ABC0`/`0x00B99840`, and
subsequent draw dispatch through `0x00B99990`. Treating the payload itself as
geometry would read the wrong fields.

The comparator has no calls or non-stack stores. On every comparison it
reloads camera matrix components `+0x68`, `+0x74`, and `+0x80`, resolves both
geometry bounds (or native fallback `0x011F4288`), and computes both depths.
The mode branch additionally subtracts each bound radius. Native intermediate
stores round to single precision before comparison; the radius branch has
an additional rounded intermediate. The final x87 `FUCOMP`/`FCOMPP` branches
return zero, positive one, or negative one. Unordered behavior is not a
generic total ordering and must be retained through native fallback.

If a merge run makes `c` comparisons, native arithmetic computes `2c` depth
keys. Between successive comparisons within that run, exactly one selected
head advances. A local key for the unchanged head avoids recomputing that
operand: at most `c + 1` keys are needed for `c >= 1`, provided camera, mode,
bound identity/value, and qualified arithmetic remain unchanged. Reset both
keys at every new merge pair/run and invocation. This offers bounded local
state and avoids a heap-backed map or storing scores in engine objects.
It leaves merge comparisons and `O(n log n)` list work intact.

Computing each record's key once for an entire sort could reduce arithmetic
further to `n` keys, but requires per-node private storage and more lifetime,
allocation, and failure handling. It is a different design, not a property of
the two-head proposal. Small merges with one comparison save no keys, so the
additional branches/copy cost also needs an executable work-budget comparison.

Preserve the native `0x00B63E90` cleanup before each sort. It returns spare
nodes to the global pool and cuts the active tail's next link; skipping that
work changes ownership. Preserve the final draw ordering and cleanup as well.
`0x00B650C0` merges/drains alpha work using `0x00B98C80` and `0x00B9AF60`;
the inspected head-depth selector does not restart a full object-list scan.
It is not a proven additional quadratic loop.

Ordinary pass registration was separately rechecked. `0x00B99A90` prepends
and `0x00B99B00` appends in constant time, with native node acquisition only
when their spare list is empty. The new opportunity is comparator arithmetic,
not changing their insertion order or imposing a new batching scheme.

### Visibility: actual admission and existing optimization overlap

The new native visibility capture verifies this entry chain:

`0x00A59E00` -> culler slot `+0x44` -> native BSCullingProcess
`0x00C4EE90` -> object slot `+0xD4` when admitted.

`0x00A59E00` rejects APP_CULLED first and tail-dispatches the culler. PE
vtable `0x0101E2EC + 0x44` resolves to `0x00C4EE90`. This proves the shipped
dispatch, not the currently installed culler provider. Mode at culler `+0x90`
and object flags `+0x30` select materially different admission routes:

| Native condition | Work performed |
|---|---|
| Mode 1 | Dispatch object `+0xD4` without the ordinary sphere/compound test |
| Mode 2 | Return without that dispatch |
| Object flag `0x1000`, with `0x100000` clear | Dispatch object `+0xD4` directly |
| Ordinary route, no active compound program or mode 3 | Dispatch directly when object flag `0x800` is set or the remaining plane mask is zero; otherwise call `0x00A694E0` |
| Active compound program, without the direct-admission condition | Snapshot masks, run `0x00C491A0`, conditionally dispatch `+0xD4`, restore masks and free the snapshot |

The base sphere test at `0x00A694E0` already saves its active mask, tests only
active planes, removes fully containing planes before child traversal, and
restores the parent's mask afterward. It stops at rejection. A proposal to
invent hierarchical plane-mask reuse would duplicate this existing mechanism.
An admitted large node can expose a child traversal, but the binary does not
establish which nodes or flags Fairfax actually supplies.

Native BSMultiBoundNode visibility is `0x00C46F60`, verified at vtable
`0x010C1D14 + 0xD4`. It checks child population, reads the multibound through
node `+0xAC`, and can use cached shape result at shape `+0x08`. A zero result
calls shape slot `+0x9C` and records visible/rejected result 1/2. Mode 4 forces
the test rather than relying on that stored result. On admission it temporarily
sets the culler's mode from node `+0xB0`, visits non-null children through
`0x00A59E00`, and restores the prior mode. This is not an unconditional
expensive multibound retest for every child or every frame.

The native AABB predicate at `0x00C387F0`, verified at vtable entry
`0x0101E980`, does contain avoidable work. It generates eight corners through
`0x00C39270` and, for each active plane, calls `0x0049DA80` on all selected
corners. Finding a corner whose side is not 2 clears the rejection flag but
does not break that plane's inner loop. For each visited plane it makes eight
side calls, or four in the zero-Z-half-extent branch. With six active planes
and no earlier plane rejection this is 48 or 24 calls, respectively.

Boolean admission could stop that inner loop at its first non-2 result while
preserving corner order and the native side predicate. However, the retained
[Stewie rendering source](<../.research/Stewie Tweaks 10.00 Source/code/Features/Inlines/Rendering.cpp>)
already implements that shortcut and installs a replacement at `0x0101E980`.
It also replaces NiNode and BSMultiBoundNode visibility paths. Therefore this
is an existing optimization overlap, not evidence of a new saving available
in the owner's installed workload. Current replacement bytes/admission and
the omitted x87 status/exception effects would have to be qualified before
adding a Psycho-side equivalent. Do not overwrite that provider or patch the
other mod. Algebraic support-vertex tests also require a separate floating
point proof; geometric equivalence alone does not establish native decisions
near a rounding boundary.

### Compound-frustum culling: remove per-object snapshot allocation

This is a separate candidate from AABB corner testing. The complete native
`0x00C4EE90..0x00C4F06C` body verifies the bracket:

1. `0x00C4F000` calls `0x00C49050` to save compound state.
2. `0x00C4F015` calls `0x00C491A0` on the object.
3. A true result dispatches object slot `+0xD4` at `0x00C4F033`.
4. Both true and false results call `0x00C49100` at `0x00C4F042` before
   returning. Children can recurse inside step 3 before the parent restores.

The save helper uses thiscall with no stack argument and plain `RET`; the
restore helper uses thiscall with one saved-pointer argument and `RET 4`.
The relevant compound-state fields are proven by actual reads/writes:

| Compound offset | Native role in this bracket |
|---|---|
| `+0x08` | Array of frustum records, each `0x64` bytes |
| `+0x10` | DWORD frustum-array capacity used as snapshot allocation slot count |
| `+0x18` | Array of 12-byte compound-program records |
| `+0x24` | DWORD limit used by the save/restore frustum-mask loops |
| `+0x28` | DWORD program-presence/count gate |
| `+0x2C` | Initial compound-program record index |
| `+0x30` | Base frustum record |
| `+0x90` | Base record's active plane mask (`+0x30 + 0x60`) |
| `+0xA0` | Byte controlling the preliminary base-frustum test |

`0x00C49050` obtains the thread's ScrapHeap through `0x00AA42E0`, then
allocates `4 * compound[+0x10]` bytes with alignment argument loaded from
`0x010A2720` (value 4) through `0x00AA54A0`. Snapshot word zero receives
compound `+0x90`. Starting at snapshot index 1, it copies frustum
`(index - 1) * 0x64 + 0x60` while the signed index is less than both
`compound[+0x24] + 1` and `compound[+0x10]`. Preserve the signed comparisons
and arithmetic exclusions; these fields must not be silently narrowed.

The capacity provenance is also verified. Constructor `0x00C47660` passes
`(4, 1)` to `0x00C4A070` with receiver `compound + 0x04` at
`0x00C47727`. That helper stores the requested capacity at array `+0x0C`,
which is compound `+0x10`, and uses the real array allocator slot `+0x04`.
The latter resolves to `0x00C4A860` and allocates `0x64` bytes per frustum.
Thus the native initial capacity is **four**, not 1024. A type label containing
1024 is not a capacity bound. The resize helper supports later larger
capacities; neither the constructor nor that label proves Fairfax's capacity.

`0x00C49100` reverses those writes and then obtains the ScrapHeap again,
freeing the saved allocation through `0x00AA5610`. The snapshot pointer is
only a local in the inspected caller; it is not passed to the predicate or
child visibility callback. The masks, rather than snapshot identity, are the
state those consumers inspect.

The predicate is not a read-only visibility query. It copies the object's
16-byte bound into local storage, optionally tests the base frustum, and
walks the compound program through its true/false successor indices. Opcodes
7 and 8 call `0x00C4A6E0` and `0x00C4A790` on selected frustum records;
terminal opcodes 2/3 return their native result. The two plane helpers clear
active-mask bits at frustum `+0x60` when a sphere is fully contained. This
state is inherited by child callbacks and must be restored even on rejection.

For `G` calls reaching this branch, the caller invokes `G` snapshot allocations
and `G` snapshot frees, plus `2G` ScrapHeap accessors. It performs the
save/restore mask walks as well as the actual program and sphere tests. This
is an exact conditional operation count, not a measured `G` or a claim that
Fairfax uses compound-frustum culling. Culler `+0xC0` presence alone is not
enough: the active program and mode/flag gates above must also admit the branch.

The current core log records allocator mode 2 and the committed scrap-heap
replacement. Its source at
[thread identity accessor](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/mod.rs)
returns a thread-local inert identity. The native getter's GetCurrentThreadId
and map lookup therefore must not be presented as current Psycho overhead.
The native caller still requests a temporary allocation and free through those
hooked boundaries; no evidence measures their actual cost here. This candidate
does not require changing the allocator or classifying allocator ownership.

There is also directly verified Psycho-side work behind these calls.
[Runtime::alloc/free](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/runtime.rs)
can use their thread-local identity/generation cache, but a successful ordinary
allocation still enters `Heap::try_alloc_slow_with_provider`, and a valid free
enters `Heap::free`. Both take the per-identity heap-state mutex in
[heap.rs](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/heap.rs).
Thus `G` successful snapshot/free pairs entail `2G` acquisitions of that
mutex, allocation-header/count updates, and free validation/rewind work.
The cold identity-map path is not mandatory on each call. Contention, backing
acquisition, and collector work are conditional and unmeasured; the presence
of a mutex does not prove cross-thread blocking here. Removing the snapshot
allocation removes these paired operations for admitted objects without
weakening allocator locking or lifetime checks.

The proposed intervention is a private implementation of this caller's
snapshot/test/callback/restore bracket. For admitted capacities, snapshot
exactly the same DWORD masks into private invocation-local storage, invoke the
actual native predicate and visibility callback in their existing order, and
restore the masks identically. Retain the ordinary native allocation path
outside a validated local-storage budget. No persistent cache, TLS scratch
slot shared by recursive calls, global buffer, visibility-policy change, or
cross-frame lifetime is required. Each recursive invocation needs its own
snapshot; a single reused buffer would overwrite the parent's saved masks.

The narrow first design can admit exactly the verified native initial capacity
of four slots and reserve 16 mask bytes per invocation. Larger capacities keep
their complete native path. This is a bound derived from the constructor,
not a guessed typical scene size or a proposed limit on visibility coverage.
It avoids a large stack array and unbounded alloca, but does not establish the
admission hit rate or prove the stack budget of the final compiled bridge.

Structural writers that can run during traversal, supported stack headroom,
and admitted recursion cost still require closure. Do not size storage from
only the number of currently copied masks. The native restore rereads the
current limits; an implementation must prove they remain compatible with its
entry snapshot and preserve every native route. Additional capacities should
not be admitted until their own storage/recursion budget is justified.

The direct xrefs currently identify this save/restore pair only at the named
caller, and the culler has the verified vtable dispatch above. That does not
exclude computed helper calls or replacement callbacks. A whole-caller private
implementation must qualify its complete byte/ABI contract and forward unknown
providers. An isolated save-hook returning a stack pointer whose frame has
already returned is invalid; passing private storage to native restore would
incorrectly free it. Both ends must belong to the same admitted bracket.

The current result closes the native allocation reason, exact snapshot fields,
mutation/restoration requirement, immediate recursion boundary, ABI, and
allocator distinction. It does not close structural lifetime, complete provider
coverage, stack-budget admission, exceptional callback exits, or runtime
equivalence. Candidate acceptance would require actual native mask and child
admission equality on both predicate outcomes and nested traversal, with native
fallback for unsupported capacity/providers. Neither lowering mask coverage
nor removing the compound program is an optimization of this contract.

### Bound lifetime, provider compatibility, and implementation readiness

The limited PE scan found the two literal comparator addresses pushed in
`0x00B99A10`, with no additional raw pointer match for the selected sorter
or wrapper. This corroborates the inspected native routes; it does not prove
all computed callers or installed plugin providers. Property `0x00BB4740`
has a real vtable entry at `0x010B9934 + 0x7C`. Automatic xrefs alone omit
that dispatch and cannot establish complete coverage.

World bounds are mutable engine objects. The verified NiTriShape/NiTriStrips
slot `+0xBC` targets `0x00A80710`, which can create a missing bound and
updates it through native helpers using geometry data and world transform.
The setter `0x00A59DC0` can free an old bound and replace geometry `+0x20`.
Those facts rule out treating pointer identity as proof of an immutable depth
key. The existing actor deferral evidence closes only its named branches;
it is not a global render-time bound/lifetime barrier.

For each proposed optimization, remaining requirements are concrete:

| Requirement | Property shortcut | Single-walk pass refresh | Alpha depth reuse | Compound snapshot |
|---|---|---|---|---|
| Native consumer, immediate ABI, fields, and output boundary | Rechecked; existing candidate supplies the private operation | Verified native dirty branch, integer iterators, capacities, and continuation | Verified wrapper, two stable sorts, comparator, payload identity, and draw consumer | Verified save/test/callback/restore bracket, capacity provenance, mask mutation and allocator calls |
| Lifetime/concurrency | Existing wrapper-score and input ownership exclusions remain unresolved | Exclude mutation/recycling and count inconsistency for the admitted operation; array ownership alone is insufficient | Exclude camera/mode overwrites and bound replacement/value changes during a merge run; spare cleanup must finish first | Exclude structural changes/recycling during nested callbacks; each invocation owns its snapshot; qualify stack and callback exits |
| Arithmetic | Qualify the extra comparison and exceptional/subnormal fallback without widening admission | No new floating point operation is needed | Retain each exact x87 rounding site, comparison/tie behavior, stack/control/status contract, and native exceptional route | Preserve native predicate calls and signed mask-loop conditions; snapshot adds no floating point operation |
| Compatibility | Preserve current provider forwarding and owned sorter bridges | Validate complete native refresh/iterator windows and respect existing caller overlays; forward unsupported states | Admit only the proven comparator/merge provider, preserve wrapper globals and cleanup, and forward unknown providers | Qualify the complete caller and paired private save/restore; forward unsupported capacities/providers without passing private storage to native free |
| Behavioral qualification | Native list/order/cache-key equality on the actual path | Actual pointer-array/count/capacity equality, filtered/null cases, and native growth/overflow fallback | Actual node/order/cleanup equality in both groups and both depth modes, including ties and fallback | Actual child admission and parent/child mask restoration equality, including rejection and recursion |

The scoped algorithms can now be described without guessing selection policy
or storage widths. Complete accepted-fix readiness is **not established**.
No new candidate inherits the earlier implementation waiver automatically.
The repository's Psycho behavioral gate still applies to a later production
edit; compilation, a mirrored sorter, source assertions, or a fabricated
engine fixture cannot establish native runtime equivalence. This research
does not request profiling or a debug build.

Continue contract research at the named writer/ownership and arithmetic
boundaries before selecting an implementation. Of the new candidates, the
single-walk no-growth refresh has the smallest new arithmetic and ownership
footprint among the lighting extensions. The property shortcut has the largest
proved asymptotic saving on ordered input but inherits shared-score
restrictions. Alpha depth reuse opens a separate location-scaled path, with a
modest allocation-free design and a larger still-unqualified once-per-record
alternative. Compound snapshot removal is the next focused visibility
candidate: it avoids one allocation/free pair for each admitted four-slot
invocation without changing the predicate, but first needs the named callback
structure-lifetime contract. Actual invocation frequency, Fairfax attribution,
and an FPS improvement remain unknown.

## Durable Psycho optimization implementation plan

The owner requests a Psycho implementation design for every identified
candidate, including the AABB inefficiency that overlaps an existing provider.
The target is reduced work at the actual native boundary with unchanged
lighting, visibility, pass order, ownership, and failure behavior. This is a
research and implementation plan; it makes no production changes and does not
claim that the unclosed contracts below have become proven.

The [complete remaining implementation plan](#implementation-plan-complete-remaining-optimization-set)
below governs the next changes. The two AABB setup replacements and three
compound/portal vertex-setup replacements now have production implementations.
The six additional integer-reduction sites are also implemented as a separate
unreleased candidate. The five deeper designs retain explicit prerequisite
contracts; their earlier algorithm descriptions below remain applicable where
the later plan does not amend them.

Additional focused disassembly is retained in
[durable design evidence](../analysis/radare2/output/fnv_location_durable_optimization_plan_contract_20261007.txt).
The executable SHA-256 was reverified against the identity above. Current
production integration was checked in `perf/mod.rs`, `startup.rs`,
`config.rs`, `light_property_scores.rs`, and `lighting_contract.rs`.

The [additional static closure](#implementation-contracts-additional-static-closure)
below amends this design with pre-write finite-result admission, exact pass
stack locations, terminal native comparisons and concrete compound callback
mutations. Its revised work budgets and remaining gates govern implementation.
The later [ownership continuation](#ownership-contracts-and-revised-reuse-boundaries)
further revises transparent-key admission and examines a compound alternative
that does not retain private storage through child callbacks. Neither the
original whole-interval cache nor delayed allocation is qualified by default.
The [implementation-entry contracts](#implementation-entry-separate-closed-local-work-from-retained-input-designs)
separate two proven dead AABB initialization loops from the stronger plane
optimization and select the original native frame for its terminal side tests.

### Coverage, cadence, and target budgets

All five candidates remain in scope. Their cadence is conditional: property
sorting and pass refresh require native update/dirty gates, transparent sorts
require their render route, and compound/AABB tests require their visibility
route. No evidence establishes that every candidate executes in every frame.
The optimization must retain those gates rather than introduce a periodic
scan, assume a stationary scene, or infer cadence from the location name.

| Candidate | Planned durable operation | Conditional work target |
|---|---|---|
| Lighting-property sorting | Adaptive allocation-free stable linked-list merge sort, retaining native current-score generation and ordered-input detection | One score per node plus at most one terminal replay; O(n) ordered input and O(n log n) worst-case comparison/link work for qualified stable ordinary keys |
| Dirty cached-pass refresh | One eligible-light snapshot per interval without invalidating calls, reused across the relevant cached passes | One eligibility enumeration per such interval, plus the unavoidable pointer writes for each output pass; native growth/overflow routes retained |
| Transparent-pass sorting | Preserve the stable merge and revalidate the current numeric inputs before reusing each merge-head key | At most c+1 depth calculations for c comparisons with unchanged inputs; changed inputs require recalculation, up to the native 2c arithmetic budget plus guard cost |
| Compound-frustum snapshots | Qualify the four-slot local design, or a packed rejected-object path with accepted objects retaining native heap snapshots | The full local target removes an allocation/free pair; the alternative removes the pair only for qualified rejected objects. Provider recovery order and callback ownership remain material gates |
| AABB/frustum tests | First batch: replace both dead initialization loops while preserving their complete final state. Further research: stronger native-frame extreme-corner loop | Each admitted setup replacement removes 64 executed integer instructions per call with no per-call guard. The stronger path targets at most two native side calls per active plane rather than eight/four |

These are design budgets, conditional on their stated contracts. Small-input
admission cost, extra branches, guard reads, stack footprint, and native
fallback work must be counted as well. The plan provides no FPS estimate.
The compound four-slot path is deliberately bounded; larger native capacities
remain supported through their original operation. Broader allocation-free
coverage needs a separate proven storage design, not a guessed stack limit.

### 1. Lighting properties: remove quadratic comparison work

Extend the operation owned by
[light_property_scores.rs](../psycho-engine-fixes/src/mods/perf/light_property_scores.rs),
keeping its three existing caller bridges and captured providers. Do not add
another hook on the same calls or replace the engine-wide scorer.

The full design replaces insertion search with stable linked-list merging for
the qualified ordinary-key domain. It uses existing nodes and constant local
merge state, not a Vec, an engine-field extension, a global table, or allocation
per property. The ascending/equal-input path leaves links untouched.

The proposed operation has three parts:

1. Validate the entire native operation before relinking. Retain caller-local
   bound ownership, complete native/scorer/math capabilities, native list
   count/link checks, and the existing x87 admission. Close the shared wrapper
   score and light/scene-input exclusion rather than treating those checks as
   a lock. An active fence or another unsupported list state keeps the original
   operation until its precise sorting contract is qualified.
2. Generate each current key through actual `0x00B9DBE0` in original node
   order, with its exact single-precision stores and wrapper `+0x0C` output.
   Determine whether the original list contains a strict inversion. Admit the
   sufficient finite-result domain below before any score write; unsupported
   inputs retain the captured provider. Finite inputs alone are insufficient:
   radius division or overflow can otherwise produce nonfinite results.
3. For ordinary admitted keys, return without relinking if there is no strict
   inversion; otherwise perform a stable bottom-up merge, rebuilding previous
   links, head, and tail using the original nodes. Keep count, fence and dirty
   state unchanged. Clear property `+0x38` exactly when the finite native
   insertion operation would have changed order.

The proposed equivalence condition for cache-key clearing follows from the
verified strict insertion comparison: a stable ordinary-key list needs an
insertion iff its original order contains a strict inversion. It still needs
qualification against the actual native operation. Preserve signed-zero ties
and original equal-key identities; Rust `total_cmp` is unsuitable.

Pre-scoring is not a safe fallback boundary: it writes engine scratch and
changes floating point state before links change. The bounded input domain
below avoids discovering an unsupported computed key after mutation. It still
requires stable inputs and the complete scorer/math contract; a later finite
check cannot replace those prerequisites. Keep the earlier ordered-prefix
shortcut until full-sort admission and ownership are qualified. Never restart
a sort after partially relinking its nodes.

The merge must also qualify native x87 condition/status effects and caller
observability, not merely produce the same pointer order. Checked run-width
growth and exact termination are required for the full DWORD node count.
There is no small-list threshold selected from a guessed workload; select any
hybrid threshold only from executable production-path work costs.

### 2. Cached passes: share enumeration inside the dirty refresh

The stronger target extends the earlier per-pass no-growth shortcut to the
whole cached-pass refresh interval. It belongs in a new core module,
`psycho-engine-fixes/src/mods/perf/lighting_pass_refresh.rs`.

The inspected loop is `0x00BB4F40..0x00BB50AD`, after the existing sort and
after the native slot-zero pointer was obtained. `0x00BB4F40` and
`0x00BB4F44` are two four-byte instructions publishing caller locals; they
are a proposed eight-byte owned detour window, not yet a qualified patch.
The private operation would replay those publications, own the complete pass
loop, and return at `0x00BB50AD`, leaving native dirty clearing and the final
cache-key/rebuild decision in place. Full stack/register liveness and incoming
edge coverage must be proved before selecting that detour.

Use one invocation-local array with space for 254 ordinary wrapper pointers
(1016 bytes). Gather with the actual `0x00B70600`/`0x00B70700` iterators,
preserving filters, order and null termination. Do not use the narrowed AX
count accessor. Encountering a 255th eligible light selects the complete native
modulo-count operation before publication for the current pass; this is a fallback,
not a selection cap. A large total node count with few eligible lights is not
itself a reason to truncate or reject the gather.

For each pass in `0x17F..0x1BA` with a valid existing array and capacity at
least `k+1`, publish slot zero, the gathered `k` pointers in native order and
the exact active count. This removes a separate count walk and avoids repeating
eligibility tests for each already-sized output pass. Output copies remain
necessary; the operation budget is a gather plus the sum of required output
writes, not O(1) refresh.

An insufficient-capacity pass is an explicit snapshot boundary. Discard the
snapshot before its original free/allocation calls, preserve the original
growth behavior and fresh post-allocation enumeration, then gather again for
later passes if a qualified interval resumes. Never carry pointers across an
allocator/provider call on the strength of an earlier metadata check. Forward
unqualified iterators or growth providers through the original operation.

If qualification fails after earlier passes were published, resume the native
operation for the current pass and the remaining loop with the exact caller
state. Do not restart the whole refresh, replay completed passes, or roll back
valid engine arrays. An admission failure before entering the private loop
keeps the complete original loop.

Preserve the `0x1BD..0x1C3` and `0x1C4..0x1C7` branches, their native
iterator/cursor rules, shadow checks and key invalidation. Reuse across another
branch is allowed only after its calls and writes are proven unable to change
snapshot inputs or lifetime. Otherwise end the interval. No snapshot survives
this refresh, an allocation boundary, a different property or a different
frame.

The 1016-byte buffer is derived from the native byte count, not arbitrary
scene capacity. It still needs a supported stack/recursion proof. Until that
larger private loop is qualified, the earlier one-walk no-growth operation is
the narrow implementation path with no pointer buffer. The full design must
close pass-array/list aliasing, writer exclusion and provider admission in
addition to the already-proven iterator predicates.

### 3. Transparent passes: reuse arithmetic within the existing stable merge

Add `psycho-engine-fixes/src/mods/perf/transparent_pass_sort.rs`. The proposed
interventions are the two direct sorter calls at `0x00B99A31` and
`0x00B99A41`, inside the verified two-group wrapper. Capture each predecessor
through the existing callsite-hook abstraction. Retain the wrapper's native
camera/mode publication and original group order. The list receiver and cdecl
comparator argument must reach the captured thiscall/RET-4 provider unchanged
whenever admission fails.

The private operation preserves the native merge run schedule, stable tie
selection, previous/next links, list head/tail and cleanup. Its two local key
slots belong to the current merge pair. Score an operand when its head first
participates; the selected head must obtain a new key when it advances.
Revalidate both operands' current numeric inputs before every reuse, including
the unchanged head. Retain numeric copies rather than a bound pointer to
dereference later. Reset both at the next merge pair and at return. Native `0x00B63E90` spare
cleanup happens at its original boundary before active-node keys are retained.

Implement a small x87 key adapter from the verified comparator, preserving
camera components, bound fallback, addition order, every intermediate f32
rounding site, and both radius modes. The merge still uses the native decision
convention. A pair with unqualified arithmetic must take the exact native
comparator for that pair and discard its local reuse state. Do not restart an
already-mutating sort or impose a total order on NaN/Inf. Prove this mixed
comparison path's state equivalence before accepting it.

The head-key design is the allocation-free implementation target. Computing
each record once for the whole invocation is a possible stronger arithmetic
target, but is not selected now: it requires per-node private storage without
routine allocation, proven storage lifetime and a worthwhile total budget.
Do not overwrite render-pass bytes, geometry fields or pooled-node fields to
obtain that storage. The current proposal never claims n total key evaluations.

The revised [current-input design](#transparent-keys-revalidate-values-at-the-current-comparison)
removes the additional requirement that cached bound pointers remain live
between comparisons. It still requires valid current native operands,
qualified input reads and exact math state at each comparison. A no-callback
comparator and read-only prewalk do not prove those conditions. Whole-invocation
pre-scoring remains dependent on the larger ownership interval.

### 4. Compound frusta: local snapshots with recursive ownership

Add `psycho-engine-fixes/src/mods/perf/compound_frustum_culling.rs`. Target
the culler operation `0x00C4EE90`, whose exact ABI is thiscall, one object
argument, RET 4 and void return. Preserve all ordinary/direct/mode routes.
The existing mask-save/test/virtual-child/restore bracket is the only part
that changes its storage mechanism.

For the verified capacity of four DWORD snapshot slots, give each invocation
its own 16-byte local snapshot. Save exactly the base mask and the masks the
native signed loops visit, call the native predicate, dispatch the same object
callback only on the same result, and restore the same masks. Neither branch
calls a ScrapHeap accessor, allocation or free for this local snapshot. Keep
the original complete operation for larger capacities or unsupported providers.

Reentry creates another stack frame and snapshot; it must not overwrite the
parent's storage. A local pointer must never escape the bracket or reach native
`0x00C49100`, which would free it. This design requires no new TLS, arena,
allocator hook, global mutex or thread-registration mechanism.

The [packed alternative](#compound-storage-separate-the-predicate-from-child-callbacks)
below avoids keeping a larger private frame alive during child dispatch. Its
rejected-object savings are a separate bounded target; provider qualification
must settle allocation ordering before either storage design is selected.

The current constructor proof does not settle all traversal writers. Inventory
the structural writers reached by native virtual visibility callbacks, including
compound replacement and frustum resize/free, and prove stable capacity, limits,
record storage and ownership for the whole bracket. The newly checked outer
entry `0x00C4F070` establishes camera/frustum state and root dispatch but is
not a recursion or worker-lifetime barrier. Review exceptional callback exits
and native unwind behavior before introducing a private restoration guard;
Rust RAII alone does not promise native SEH cleanup.

Qualify the total compiled frame and worst supported recursive use rather than
calling a 16-byte payload proof a complete stack proof. If later evidence
supports larger bounded local snapshots, extend capacity admission with an
explicit budget and native fallback. A persistent growable arena is not the
current plan: its ownership, allocation and startup costs are not closed.

### 5. AABB frusta: own the redundant native tests and qualify stronger selection

Add `psycho-engine-fixes/src/mods/perf/multibound_frustum.rs`. The known
native predicate is thiscall, one plane-buffer argument, byte result in AL,
RET 4, with dispatch entry `0x0101E980`. The companion +0xA0 method is
`0x00C38920`. The initial native-route target is the pair of dead initialization
loops qualified in the implementation-entry contracts below. Use existing
transactional instruction-byte ownership and restoration. The selected
state-preserving baseline checks its frame and patch blocks at startup,
leaves installed dispatch and downstream providers untouched, and has no
per-call admission check.

For the stronger native loop, select the post-generation `0x00C38866`
intervention and retain the original frame and `0x00C388E8` side-call setup.
The earlier whole-predicate pointer-wrapper proposal is not the selected
native-frame mechanism: an enlarged wrapper frame does not retain terminal
FP data addresses. See the existing
[transaction](../libpsycho/src/os/windows/hook/transaction.rs) infrastructure;
the exact new bridge still needs compiled qualification.

The additional Boolean early-exit target evaluates existing generated corners
in native order and stops each plane's inner loop at the first side result other than 2.
It retains the active mask, outer-plane rejection order and zero-Z branch's
selected subset. This is an exact redundant Boolean-work target, subject to
the floating point side-effect contract. A provider that already implements
this behavior keeps its own path; Psycho must not create a slower double layer
and call that an additional optimization.

The stronger target evaluates one extreme existing corner per active plane,
then corner 7 when necessary to retain the native terminal comparison. The
additional closure below supplies a sufficient arithmetic domain and revises
the target to at most two side calls per plane. It must use the actual
generated buffer and call the native `0x0049DA80` side predicate, not
substitute a center/radius formula. New disassembly establishes
that `0x00C39270` scales three basis globals and uses sequential vector
addition/subtraction helpers. `0x0045BB20`, `0x00439E90` and `0x00439EF0`
round their component outputs to f32. A direct `center +/- extent` expression
does not have the proven native arithmetic contract.

For the stronger path, establish which actual eligible corner maximizes each
normal-weighted coordinate and whether one eligible corner contains all three
extrema. Validate that property from the produced buffer or close the native
basis/provider writer contract; do not infer it from a class name. Preserve the
zero-Z subset. If no dominating eligible corner exists, retain the ordinary
corner loop. The mathematical target is that rejection by the maximal corner
is equivalent to rejection by every eligible corner under the exact native
rounded evaluation, not just under real-number geometry.

Before admitting that selection, prove the arithmetic domain, including
cancellation, signed zero, subnormals, nonfinite intermediates, masked/unmasked
exceptions, status flags and comparison condition codes. Finite plane/corner
inputs do not exclude overflow followed by NaN cancellation. Native predicate
purity does not make omitted exception effects irrelevant. Intel specifies
these state and rounding controls in Volume 1, sections 4.8.4 and
8.1.3-8.1.5 of the
[architecture manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf).
That is a reference for the required proof, not proof that this optimization
already has the necessary domain or provider coverage.

### Core ownership, compatibility, configuration, and acceptance

All production mechanisms belong in `psycho-engine-fixes/src/mods/perf/`.
The helper, Syringe, OMV rendering pipeline, shared allocator and third-party
mods remain outside this change's ownership. No new dependency, cross-DLL ABI,
worker, global scene cache or engine reference-count mutation is needed by the
selected bounded designs.

`perf/mod.rs` exposes focused installation/event routing. `startup.rs` uses
the existing supported core preparation boundary and independent transactions;
DeferredInit publishes readiness through established routing. Every subsystem
retains its captured provider and rolls back only code/vtable bytes it owns.
Prepare complete immutable contract expectations rather than learning current
bytes as the oracle. Check complete code capability at the qualified operation
boundary. Input/state admission follows each design's actual reuse interval;
transparent head keys, for example, require current input checks at each
comparison. Include all guard reads in work budgets, and do not weaken provider
validation merely to reduce their cost.

The AABB initialization-loop baseline is the explicit exception to that
bridge/admission schedule: its full-state-preserving inline replacement needs
only cold signature ownership, with no runtime bridge or readiness publication.

Extend the existing `light_property_score_reuse` operation instead of replacing
its user setting. Retain `scene_light_sequential_scan` and its qualified math
alternatives. New proposed independent settings are
`performance.lighting_pass_refresh`, `performance.transparent_pass_sort`,
`performance.compound_frustum_culling` and
`performance.multibound_plane_tests`. The existing
`performance.multibound_frustum_tests` continues to own the implemented AABB
setup replacements; the stronger plane operation has independent ownership.
Plan new features enabled by default, consistent
with the owner's requested optimization coverage, while preserving user-set
values and missing-value parsing. Final schema integration must follow
[startup safety](nvse_startup_phase_safety.md); a few boolean fields still
change pre-Deferred configuration layout. No new TLS or lazy hot-path owner is
planned. Do not move established startup work to accommodate these features.

Config comments should describe the avoided work and user-visible behavior in
plain language. They must not contain research chronology, test instructions,
restart advice or fixed-value assertions. No test freezes shipped toggle values.

Each implementation has a concrete native behavioral boundary:

| Operation | Required equality and work observation |
|---|---|
| Property sort | Actual native node identities/order, head/tail/count/fence/dirty/cache key, score side effects and qualified math environment; ordered/reverse/equal/exceptional inputs |
| Pass refresh | Actual pass arrays/count/capacity and invalidation/rebuild behavior; empty/filtered/null/overflow/growth cases and interval invalidation; no repeated eligibility walk within a qualified interval |
| Transparent sort | Actual two-group stable order, node links, pass identities, cleanup and both depth modes; native fallback pairs and caller math state; key calculations bounded by merge-head changes |
| Compound culling | Actual child admission and parent/child masks on rejection, acceptance and recursion; original larger-capacity/provider paths; no local-snapshot allocation/free |
| AABB test | Actual native Boolean result and required math state for active masks, boundary/cancellation/degenerate/exceptional inputs; original provider chaining; reduced side-call count in admitted domains |

Use the actual supported native operation as the oracle at these boundaries.
Pure production Rust behavior can have offline tests where it actually executes,
but a mirrored native sort, synthetic engine fixture, source assertion, config
default test or compilation is not native acceptance. No debug build or profiler
is assumed. The present request authorizes research/planning; it does not erase
the current Psycho behavioral gate or extend the earlier two-candidate waiver.
Do not describe an unresolved candidate as an accepted fix.

Before production editing, close each named ownership/math/provider/stack
contract and establish the applicable acceptance authority. The AABB
initialization replacements specified in the first batch below are implemented;
use the later complete plan for the next delivery order. Continue the pass,
sort and compound contracts independently; their
integer-only components do not by themselves establish ownership or callback
safety. This order does not remove any candidate from scope. Run affected
production-path checks and crate tests, the explicit
`i686-pc-windows-gnu` core/helper release build when code changes, formatting,
diff review and the applicable startup qualification. No commit, installation,
packaging or release is authorized by this plan.

## Implementation contracts: additional static closure

This continuation resolves specific mechanism and arithmetic gaps from the
implementation plan. It does not turn unproved engine exclusivity into a
contract. The supporting [gap-closure capture](../analysis/radare2/output/fnv_location_optimization_gap_closure_20261007.txt)
preserves new radare2 instructions and xrefs, bounded executable-data checks,
and the limitations of incomplete or misaligned discovery windows. The
executable identity above was reverified.

### Cached-pass refresh: exact caller frame and continuations

Let S be ESP at `0x00BB4F40`, before any private bridge frame. The native
prologue reserves 0x4C local bytes, saves EBP/ESI/EDI, and saves EBX at
`0x00BB48A2` on the route reaching this refresh. Consequently
S = entry ESP - 0x5C. Instruction bytes, checked with bounded objdump output
after radare2 inspection, establish these locations:

| Location | Actual role |
|---|---|
| S+0x1C | Count/fill iterator cursor |
| S+0x20 | Earlier computed cache key |
| S+0x24 | Native slot-zero wrapper pointer |
| S+0x28 | Outer pass index saved across fill |
| S+0x2C | Cursor for the 0x1BD..0x1C3 branch |
| S+0x30 | Cursor for the 0x1C4..0x1C7 branch |
| S+0x60 | Original geometry argument, restored into EBP at 0x00BB50AD |
| S+0x64, low byte | Temporary count supplied to growth and fill |

The count initialization at `0x00BB4F83` writes ESP+0x68 after PUSH,
therefore S+0x64. The later count publication at `0x00BB4FA2` and growth
read at `0x00BB4FB6` use S+0x64 directly. This closes the apparent
uninitialized growth argument on the empty-iterator route: it was initialized
to one before the first call. The slot-zero read at `0x00BB4FD4` is S+0x24,
and both outer-index restoration and increment publication use S+0x28.
Radare2's overlapping inferred variable names are not the frame contract.

The proposed eight-byte window at `0x00BB4F40` is exactly
`89 44 24 24 89 6C 24 28`. It publishes the slot-zero pointer and index.
The inspected native loop returns to `0x00BB4F51`, not into that window.
A bounded raw relative-branch search found one false candidate at BB4F88:
it lies inside the displacement of the CALL at BB4F87. It is not an incoming
instruction. MCP xrefs found no incoming references to the window's entry,
second instruction or continuation. This closes the inspected direct edges;
it does not prove arbitrary computed or foreign-provider entry coverage.

At `0x00BB50AD`, the native code reloads EBP from S+0x60, clears dirty,
loads the key from S+0x20 and makes the existing cached-return/rebuild choice.
The rebuild path resets BL before its first later BL test. EAX/ECX/EDX are
overwritten by native loads/calls, and the later geometry use derives from the
reloaded EBP. A conservative bridge can preserve the incoming registers,
flags and complete math state, publish the exact affected stack locals, and
leave those native continuation instructions in place. A private ordinary
pass must also publish the count at S+0x64 and preserve the native cursor
outcome; output arrays alone are not the complete write contract.

The iterator bodies have no allocator, callback, reference operation or
floating point instruction. Array allocation is a separate four-bytes-per-
byte-count allocation at `0x00BA8C00`; freeing at `0x00BA8C30` clears
the array pointer. The no-growth interval therefore has no synchronous
allocator/callback invalidation in the inspected ordinary branch. This closes
that local call-chain question. It does not prove concurrent list/eligibility
writer exclusion or allocation/list non-aliasing for every valid owner.

### Property sorting: qualify finite results before the prepass

The earlier proposal discovered nonfinite keys after scoring had already
written wrapper scratch. A usable finite-result domain can instead be checked
before scoring. The following sufficient bounds are derived from the exact
`0x00B9DBE0` arithmetic, not Fairfax populations:

- Every scene offset, light-position component, bound-center component and
  bound radius is finite with absolute value at most 2^30.
- The native light radius is finite, with absolute value between 2^-30 and
  2^30 inclusive. Both signs remain possible; zero takes the native provider.
- The existing control-word/stack admission and complete scorer/CRT provider
  contracts hold, and these inputs remain stable for the operation.

The native stored position is light position plus scene offset. After bound
subtraction, each displacement has magnitude at most 3 * 2^30. Its sum of
squares is below 2^65, its square root is below 2^33, subtraction of the bound
radius stays below 2^34, and radius division stays below 2^64. The margins
remain inside finite f32 range at every actual store. Squared inputs to the
native square-root route are nonnegative; underflow to zero does not create
a negative argument. Thus this domain excludes computed NaN/Inf without a
post-write fallback or a reconstructed scorer. Inputs outside it retain the
captured provider before scratch or links change.

The rechecked `0x00EC6040` wrapper and finite `0x00EC605D` route confirm
that control word 0x027F reaches FSQRT and either common return without the
CRT error dispatcher or exception-flag clearing. Repeated identical score
calculations cannot add a different sticky exception bit under stable inputs
and control. Native comparisons of ordinary finite keys do not justify
replacing the final comparison condition codes with those of a different
merge comparison.

For that final-state problem, the native sorter frame is now explicit. Let T
be ESP after native alignment, 0x1C local bytes and the EBX/ESI/EDI saves:

| Location | Native sorter use |
|---|---|
| T+0x13 | Changed-order byte |
| T+0x14 | Property pointer |
| T+0x18 | Original next-node pointer |
| T+0x1C | Current f32 key |
| T+0x20 | Exact f64 copy of that f32 key for comparison |
| EBP+0x08 | Bound argument |

For stable ordinary keys, the last original node is the last outer iteration.
Its last predecessor comparison is the first sorted-prefix key strictly
greater than its key, if one exists, otherwise the last prefix key. This
identity can be found in the final stable order while excluding that original
last node. A terminal replay can call the actual scorer for that predecessor,
put the current-key f64 temporary in the native frame, and enter the original
`0x00B70403` comparison/tail with ESI equal to EBX and EDI equal to ESI.
A greater result takes the existing equal-node branch instead of relinking;
a non-greater result exits the predecessor loop. T+0x18 is zero, and the
changed byte reflects the earlier inversion result. The native cache clearing
and epilogue then remain responsible for completion.

This is a concrete terminal-state design, not a compiled bridge proof. Empty
and singleton lists need their own native no-comparison tails; the singleton
can return through the original current-key store at `0x00B703D3`.
The work target is N scorer calls plus at most one terminal replay, not exactly
N in every case. Before adopting this continuation, verify the complete
assembled frame, branch targets and admission against the actual operation.
Do not claim equality of all saved diagnostic pointers or stale empty-register
contents merely from equality of keys and scalar status.

Shared wrapper +0x0C ownership remains a separate blocker. This domain proves
a result bound only while its inputs are stable; it does not pin them or stop
another property from using the same wrapper scratch.

### Transparent sorting: close the synchronous interval

The complete `0x00B98B20` comparator has no callback, allocator, control-word
change or exception clearing. Its only discovered direct camera/mode publisher
is `0x00B99A10`, at globals 0x011FFE38 and 0x011FFE35. The native merge
performs spare cleanup once at `0x00B9963A`, then invokes only its cdecl
comparator until return. These facts close the synchronous reentry and
flag-clearing question for admitted, unchanged comparator code.

The complete `0x00B63E90` cleanup returns spare nodes to its locked global
pool, clears the spare-chain field and terminates the current tail link.
It neither frees active pass payloads nor traverses their geometry bounds.
Keep the original cleanup before retaining either local key.

Retain the comparator's complete final FUCOMP/FCOMPP/pop sequence for each
decision, including its equality and unordered branches. The native stable
merge consumes the left head when the comparator result is <= 0. A key-cache
adapter must preserve that convention and every f32 rounding site. Equality
of independently evaluated keys still needs the exact assembled adapter; the
synchronous interval above does not authorize a guessed Rust dot product.

The upstream dispatch is now explicit: accumulator finalizer
`0x00B66520` selects `0x00B65AE0` directly for stage zero or uses the
published 0x011F9F40 callback table. The inspected registered
`0x00B665A0` callback calls `0x00B65AE0` followed by its later drain;
another published route is `0x00B65DC0`. The preceding
`0x00B4F450` only writes stage/scene/callback globals. It contains no wait
or lock and is not a render/worker completion barrier.

Consequently the known camera publisher and callback-free comparator are not
a complete concurrency proof. The later current-input design replaces
cross-comparison bound retention with numeric revalidation. Current operand
ownership and input reads still need qualification; whole-sort pre-scoring
would additionally require the original longer stability interval.

### Compound snapshots: structural mutation is a concrete contract question

The supported executable's actual +0xD4 callback entries include NiNode
`0x00A5DBE0`, geometry `0x00A7FD90`, scene `0x00B5F9B0`, and
multibound node `0x00C46F60`. The native geometry method is a tail dispatch
to culler +0x4C, whose native `0x00C4F1D0` body dispatches accumulator
+0x98. Geometry is therefore not established as a callback-free leaf merely
because it has no children.

The complete scene visibility body proves more than a hypothetical writer:
it calls scene maintenance, constructs compound state, calls
`0x00B5BA80` before child dispatch, clears culler +0xC0 at
`0x00B5FB8F` and `0x00B5FC88`, and destroys a local compound before
return. `0x00B5BA80` reaches the growing/combining `0x00C48800`
operation and compound finalizers. The direct construction/copy/append/filter
routes also reach frustum resize `0x00C4A070`. Compound destruction at
`0x00C47770` resets/frees both native arrays.

This does not establish that the scene callback runs inside a particular
Fairfax snapshot bracket, or that it mutates the parent's compound instance.
It does establish that callback classification needs receiver and active-state
provenance. Neither a native module address nor the entry capacity of four is
the missing guarantee.

The original culler rereads +0xC0 after its visibility callback and restores
through that current pointer. A replacement must retain this behavior, rather
than restore through an entry pointer assumed to be immutable. Restore also
rereads the current signed limits and capacity. Once testing or child dispatch
has mutated masks, an unchanged-metadata check cannot safely choose a fresh
native call or reconstruct the entry snapshot. Close active-pointer
restoration, compatible restore indices and structural lifetime before
selecting the local bracket.

The original `0x00C4EE90` body has a 12-byte local frame plus saved EBP and
no local SEH registration. Do not add a Rust unwind guard and claim native
exception cleanup equivalence. Preserve normal-return semantics; qualify
exception propagation and the assembled persistent frame separately.
Recursive storage safety is not proven by the 16-byte payload alone.

### AABB tests: arithmetic domain and terminal comparison

The file contains canonical X/Y/Z basis values, but direct xrefs do not prove
their runtime immutability. Use the actual generated corner buffer. A
sufficient integer admission checks its Cartesian pattern: X values repeat
across indices 0..3 and 4..7; Y across 0,1,4,5 and 2,3,6,7; Z across even
and odd indices. Verify the produced values themselves, including both
opposite-axis values. This handles negative extents without an assumed sign.
The zero-Z native branch keeps only odd indices.

For a sufficient arithmetic domain, require every used corner coordinate and
active plane coefficient, including distance, to be zero or a finite normal
f32 with absolute value in [2^-30, 2^30]. Also require control word 0x027F,
a valid empty x87 stack without stack fault, and precision exception PE
already set after native corner generation. Unsupported state takes the
original plane loop with its already-generated corners; do not repeat corner
generation to obtain fallback.

Here is the conditional derivation from `0x0049DA80`, rather than a
real-number-only geometry argument. Each admitted nonzero f32 lies on a
2^-53 grid, so each product lies on a 2^-106 grid. Products have at most 48
significant bits and fit the admitted 53-bit multiplication precision.
Rounded addition/subtraction preserves that grid or rounds to a coarser one.
All intermediate magnitudes remain below 2^62, and any nonzero final value
is at least 2^-106. Therefore the native f32 store cannot overflow or
underflow. No admitted operand is denormal or nonfinite; the side helper has
no division. Its only potentially new exception is precision, already sticky
at admission. The extrema selection uses integer ordering, not additional
floating point work.

For fixed normal signs, native multiplication, addition, subtraction and
rounding are monotone on that domain. A generated corner containing the
coordinate extrema therefore maximizes the exact native rounded expression.
Native side 2 means that expression is negative. The Boolean rejection
decision can use that maximum corner, preserving active-plane order and the
eligible subset.

However, the original inner loop always ends on corner 7, including the
odd-only branch. Native `0x0049DA80` performs one or two comparisons with
zero according to that corner's value. An optimized path must finish each
visited plane with that same corner-7 predicate call when the selected corner
differs. The native comparison sequence then supplies the terminal condition
codes as well as balanced stack state. The revised budget is at most two
side calls per active plane, or one when the maximum is already corner 7.
It is not an unconditional one-call replacement.

The instruction at `0x00C38866` is a seven-byte initialization of
[EBP-0x6C]. It is a possible post-generation intervention with fallback to
the original loop; complete native caller/provider admission and the final
assembly still need qualification. Preserve the captured vtable provider as
specified above if a provider replacement is selected instead. Neither
mechanism may overwrite an unqualified installed implementation.

These arithmetic and state bounds are conditional static derivations, not
native behavioral acceptance or a measured admission rate. Keep the generated
buffer, actual side helper and full native fallback. Plane/shape ownership,
guard cost, live diagnostic-environment observations and compiled bridge
qualification remain separate from the Boolean/exception bound.

Intel's [Volume 1](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf)
sections 8.1.3 and 8.1.5 specify sticky exceptions and precision/rounding
controls. [Volume 2A](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
specifies comparison condition codes and stack pops. FNSTENV additionally
masks exceptions and leaves condition codes undefined; it is not a harmless
smaller substitute for complete admission-state preservation.

### Worker pre-phase calls: receiver and scope setup

The three `0x0086FD70` pre-phase callees, `0x007027E0`,
`0x00702810` and `0x00702840`, have now been followed through their
complete wrapper bodies. Each gets global 0x011D8A80 through
`0x004B7210`, rejects null, tests the receiver's first byte through
`0x009373F0`, then conditionally invokes its respective operation at
`0x0070B8F0`, `0x0070C4A0` or `0x00711EA0`.
The retained prefixes of those operations identify InterfaceManager.cpp in
their embedded native source-path arguments. The second prefix includes an
XInput call. These are concrete receiver/subsystem facts; the larger bodies
have not been treated as completely analyzed or callback-free.

Their shared setup at `0x00404EB0` is not a locking operation. Its complete
callee `0x00404F00` captures TLS+0x2B4 through `0x00404F50`, stores
that previous value in the caller's local object, then publishes its first
argument to the same TLS slot through `0x00404F30`. The inspected helpers
perform no lock, wait or cross-thread publication. Do not promote that scope
setup to the render-time ownership barrier needed by the optimizations.
This closes the helper's synchronization question; it does not exclude waits
inside the untraversed downstream InterfaceManager operations or prove that
every light/bound/list writer completed before rendering.

### What still prevents production implementation

| Area | Closed by this continuation | Remaining material gate |
|---|---|---|
| Property sort | Sufficient pre-write finite-result domain, callback-free admitted CRT route, exact sorter frame and a terminal-replay design | Shared wrapper/input exclusion; assembled terminal replay and diagnostic-state contract |
| Pass refresh | Exact stack locals, empty-count initialization, direct loop edges, native continuation and synchronous no-growth interval | List/eligibility writers and aliasing; complete provider/entry coverage and bounded compiled storage |
| Transparent sort | Exact synchronous comparator/cleanup interval, stable branch convention and upstream callback dispatch; later numeric revalidation removes retained-bound dereferences | Current-comparison input ownership/read equivalence; exact key-adapter and math-state qualification |
| Compound snapshots | Concrete resize/destruction/active-pointer callback routes and native reread/unwind behavior; later complete predicate separates mask writes from child callbacks | Full local design: receiver-specific restoration through recursion. Packed alternative: allocation-provider order, predicate input ownership and exact bridge |
| AABB tests | Actual-buffer extrema admission, bounded rounded arithmetic/exception argument, corner-7 terminal-state requirement; later native-frame entry closes shape retention and specifies terminal addresses | Stronger loop: plane ownership and complete bridge/provider qualification. Separate dead-loop baseline has a complete local native liveness proof |
| Acceptance | Exact native boundaries and required behavior are recorded | The current Psycho behavioral gate has no general static-only exception for these five new designs |

Compilation-dependent frame/ABI checks belong to implementation qualification;
they cannot be completed for code that does not exist yet. They are distinct
from the ownership questions that must be closed before production editing.
Do not mark an ownership gate complete because its synchronous helper has no
calls, because metadata did not change, or because a math-domain guard passed.

The retained evidence does not identify a complete worker/retirement barrier
for these exact intervals. Unknown computed/replacement callbacks are also not
made pure by the supported executable. Any further closure must supply that
specific ownership/provider evidence or change the design so it no longer
retains those inputs. An acceptance-policy exception would not itself prove
lifetime, exclusion or arithmetic correctness.

## Ownership contracts and revised reuse boundaries

This continuation follows the remaining native writers, visibility callbacks
and allocation paths. The executable identity above was reverified. Its
65 focused MCP captures and bounded executable-data supplements are retained in
[ownership evidence](../analysis/radare2/output/fnv_location_ownership_contract_20261007.txt).
This is static contract evidence. It does not attribute Fairfax's frame time
to one consumer or establish that any candidate executes there.

The important changes are a shorter transparent-key reuse contract and a
compound predicate that can be analyzed separately from child dispatch.
The same evidence rejects two tempting shortcuts: a pool mutex is not a
property-list lock, and an allocation call is not always callback-free.

### Transform writers: the actor guards do not cover every route

The previously established `0x008C7AA0` deferral checks protect particular
actor-update branches. Additional supported-executable routes reach the
actual transform writer `0x00A68BF0` without those checks in their inspected
local bodies:

| Native route | Directly established behavior | Ownership consequence |
|---|---|---|
| Collision object `0x00C65A80` | Its target at +0x08 reaches the transform writer at 0x00C65AAB; the alternate branch dispatches another collision operation | Actor-branch admission does not cover this local route |
| Collision object `0x00C65B00` | The inspected prefix writes the target transform at 0x00C65B33 before its later lock at 0x00C65BD3 | The later lock cannot establish exclusion for the earlier write |
| Blend collision `0x00C817D0` / `0x00C81890` | TLS+0x2C0 gates select direct writes, 0x00C65B00 or virtual collision updates | This TLS value is not established as a render-completion barrier |
| Special collision `0x00CB7790` | The target transform is written at 0x00CB77A1 before lock acquisition at 0x00CB77C6 | The lock around the subsequent transform copy does not protect the initial write |
| Recursive operation `0x00C8F210` | Writes the current object first, then obtains its node and visits its children recursively | Proving one actor branch insufficiently covers descendant transform writers |
| Paralysis-effect method `0x00826570` | Obtains the actor's 3D node and calls 0x00C8F210 at 0x0082659E | A concrete effect route also reaches recursive object updates |

The recursive operation has additional direct callers in the native
`0x00560530`, `0x00561860`, `0x0089D900`, `0x00920150`
and `0x00920B80` bodies. The capture records their exact call sites.
Neither the numeric addresses nor collision/effect class membership establishes
which worker or phase executes a call. The evidence therefore proves
additional writer reachability, not simultaneous execution with a Fairfax sort
and not that every receiver is a light.

The next required exclusion proof must connect these concrete routes to their
actual scheduling and receiver ownership. Reusing the two actor guards as a
universal light/bound barrier would leave uncovered paths. An unchanged bound
pointer or coordinate check is not a lifetime pin during a later dereference.

### Property lists and accumulator locks: establish the protected object

Native property removal at `0x00B71600` sets dirty +0x74 and changes list
links before acquiring the global node-pool mutex at `0x00B71658` or
`0x00B716AC`. The later locked work returns a node to the pool. Native
`0x00B718B0` inserts the marker and publishes property fence +0x78.
Insertion `0x00B713C0` likewise changes links and count. The pool mutex is
not a lock enclosing all mutations of property head/tail/count/fence.

Consequently neither taking that mutex nor comparing the list header before
and after a walk proves that cached wrapper pointers stayed live. Property
sorting still needs exclusion for shared wrapper +0x0C and light/scene inputs.
Whole-refresh pass reuse additionally needs the list, eligibility values and
output arrays to remain valid across the complete admitted interval. The
narrow no-growth per-pass operation removes a longer reuse interval, but it
still must prove its current list/input contract and output aliasing.

The accumulator's actual dispatch is now anchored in native construction,
rather than inferred from a class header. Constructor `0x00B660D0`
publishes vtable `0x010ADFF8` at `0x00B66104`; its RTTI getter
`0x00B65A80` returns `0x011FA000`. The executable pointer words prove:

- Slot +0x98 is `0x00B63F10`, the geometry registration dispatch.
- Slot +0x9C is `0x00B63B10`, a different registration operation.
- The constructor initializes the critical section at accumulator +0x200.

The complete +0x9C method locks +0x200 around list +0x1B4. The complete
+0x98 method does not take that lock: it selects the published stage callback
from `0x011F9F80`. The inspected `0x00B63F90` stage callback invokes
shader-property slot +0xA0, selects a batch through TLS+0x2BC and invokes the
batch method. This closes the concrete geometry-to-shader dispatch chain;
the existence of an accumulator critical section does not serialize all
registration, property sorting or dirty-pass refresh.

### Transparent keys: revalidate values at the current comparison

Revise the two-head design to cache numeric inputs and a numeric key. It must
never dereference an old bound, geometry or pass pointer retained solely for
key reuse. Any stored identity is only an integer lookup tag; the current
native head supplies all pointers used for the current comparison.

The complete `0x00B98B20` comparator establishes the read contract more
precisely:

1. It tests the mode once, obtains the camera once and copies camera
   components +0x68, +0x74 and +0x80 once for both operands.
2. It obtains each current payload's geometry and resolves its current +0x20
   bound, substituting `0x011F4288` for null.
3. The nonzero mode resolves geometry +0x20 separately for the center and
   radius. Two reads are intentional native behavior; merging them into one
   cached pointer requires a separate stability proof.
4. The arithmetic uses center Y, X and Z in the captured x87 order. Its f32
   stores and nonzero-mode radius subtraction precede the native comparison
   tail at `0x00B98C3B`.

For each current operand, the proposed reuse check compares the current
mode, all three camera component bits, the three center component bits and,
in the nonzero mode, the radius bits against the saved numeric tuple.
Recalculate when any input differs. Preserve the shared camera acquisition
for the pair and the two current bound reads where native code makes them.
Do not compute a cached key from one tuple and validate another tuple later.

This design removes the additional ownership interval between comparisons:
changing the camera/mode, replacing a bound or recycling an address does not
make an old pointer a future dereference target. Address equality alone
never admits reuse. An equal current numeric tuple can admit the saved
numeric key only under the qualified arithmetic/control-state contract.

It does not establish coherent current reads in the presence of arbitrary
concurrent writes. Current native operands still need their actual lifetime
contract. Reading every field once into private storage also changes the
native interleaving and must be qualified; a before/after metadata check is
not that proof. This is a bounded design change, not permission to ignore
the newly found transform writers.

Keep the native merge schedule, cleanup before key retention, stable tie
selection, links and comparator decision/pop sequence. Reset both cache
entries at each merge pair. If a comparison's math admission fails, use its
exact captured native comparator and invalidate reuse; do not restart a
partially relinked sort. Unknown comparator/provider code cannot borrow the
native purity proof.

With unchanged admitted inputs, a pair making c comparisons needs at most
c+1 key calculations instead of 2c. Changed inputs require recalculation,
up to two keys per comparison. The revised design adds input loads and
integer comparisons even on cache hits; one-comparison merges save no keys.
There is no measured net-time or FPS claim.

Within the proven unchanged native comparator interval, no callback clears
x87 sticky exceptions or changes its control word. Repeating identical
arithmetic under identical admitted state cannot introduce a previously
absent sticky exception after that arithmetic has already run. This narrows
the exception question, but does not qualify the exact key adapter, diagnostic
instruction/data-pointer observations or mixed cached/native comparisons.
Those require the actual assembly and the documented arithmetic admission;
a Rust dot-product substitute is still unsupported.

### Compound storage: separate the predicate from child callbacks

The complete native `0x00C491A0` predicate copies the object's sphere
into its own frame, tests the optional base frustum, then interprets the
compound program. Its only callees are `0x00C4A6E0` and
`0x00C4A790`; their complete bodies use the native sphere/plane helper
`0x004B6100`. The inspected admitted chain allocates nothing, invokes no
object +0xD4 callback and does not resize, free or replace compound storage.
It changes active-mask words, including record +0x60, as part of testing.
Its structural purity is proven for this native chain, not for replacements
or concurrent writers.

Child dispatch remains a separate boundary. Geometry reaches the accumulator
and shader callbacks described above. The complete multibound-node
`0x00C46F60` changes culler mode +0x90, visits children and restores the
mode on normal return. It does not directly settle the transitive lifetime
of every child callback.

Scene construction `0x00B5E0F0` sets flag 0x800 at object +0x30
(`0x00B5E41B`). That flag sends the scene's own `0x00C4EE90`
visibility entry through direct child dispatch, bypassing its own snapshot
bracket. This closes that direct receiver case. It does not prove that a
scene callback cannot occur under another object's snapshot-owning traversal,
nor that all callbacks preserve the parent's compound pointer.

An alternative bounded design is now explicit: pack the entry masks for
predicate testing, eliminate heap snapshots for qualified rejected objects,
and retain the original heap snapshot across accepted child callbacks.
It avoids private snapshot storage remaining live across arbitrary recursive
child dispatch.

For capacity four, the native save loop initializes at most four DWORDs:
the base word at compound +0x90 and the record masks admitted by its signed
limit/capacity tests. The native constructors initialize masks to 0x3F,
but constructor values do not prove all later values. Before modifying any
mask, require the upper 26 bits of every saved word to be zero. Four six-bit
masks occupy 24 bits; a two-bit saved-count-minus-one records the one-to-four
initialized words. Unsupported masks/capacity retain the original operation.

The existing `0x00C4EE90` frame offers two local words: [EBP-0x04]
contains an early object copy that is dead after `0x00C4EF0A`, and
[EBP-0x08] is the snapshot slot. A prospective bridge can use those words
for packed state and its admitted mode without adding a persistent frame
through child dispatch. Temporary helpers must return before the native
predicate call at `0x00C4F015`; this also retains its caller stack location.

The proposed rejected path restores the entry masks without child dispatch
or an allocation/free pair. The proposed accepted path reconstructs a real
native snapshot before child +0xD4, then retains the original callback and
`0x00C49100` restore/free. Both preserve the native signed loop limits
and initialized-word contract. Restore must use the current culler +0xC0,
as native code does, rather than a saved entry pointer. Unsupported input
must fall back before mask mutation; it cannot restart the predicate later.

The aligned snapshot and restore instruction windows are
`0x00C4EFF7..0x00C4F005` and `0x00C4F035..0x00C4F047`;
accepted dispatch begins at `0x00C4F021`. These establish native locations,
not fully qualified patch ownership, incoming edges or compiled bridges.
The current-input lifetime, packing ABI, fallback and native normal-return
semantics still need qualification. No new SEH or Rust-unwind claim is made.

### Allocation order: why naive compound deferral is not qualified

The original `0x00C49050` obtains a thread heap through
`0x00AA42E0`, allocates four times the capacity through
`0x00AA54A0`, and only then saves masks. The getter performs a
thread-ID map lookup and can create/publish a heap on its cold path.

For the native four-slot, alignment-four allocation, `0x00AA54A0`
has an integer-only fast route when the aligned payload end is strictly
less than heap +0x08. It updates allocation headers, the heap chain and the
cursor. Its growth route instead calls `0x00AA5E30`. On a failed
VirtualAlloc commit, that function calls engine recovery dispatcher
`0x00866A90` at `0x00AA5E78` and retries.

The retained recovery prefix contains calls to multiple engine owners,
including `0x00868D70`, `0x00C459D0` and `0x00AA7030`.
This does not prove a particular compound mutation or retirement. It does
prove that the allocation operation cannot be treated as universally
callback-free. Moving that call from before predicate testing to after it
changes when those owner calls occur relative to mask changes and the test
result. The packed alternative is therefore not ready merely because its
predicate is structurally pure.

A possible admission boundary is the actual native warm heap and proven
fast allocation route, established before changing masks. Since the admitted
native predicate allocates nothing, a same-thread native heap cursor could
remain eligible through testing. The getter's cold path, heap ownership,
checked end calculation, non-null result and installed providers must be
qualified before relying on this argument. Cold/recovery-capable and unknown
routes retain their original ordering. A post-predicate allocation failure
cannot be repaired by inventing visibility, replaying the predicate or
pretending the entry mask state is unchanged.

The current Psycho ScrapHeap provider makes native-layout admission especially
important. Its [getter and hooks](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/mod.rs)
return an inert dummy identity, while its
[runtime](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/runtime.rs)
explicitly treats that identity as opaque. Native cursor/base/committed-end
fields do not describe Psycho allocator capacity. Its visible OOM wrapper
reclaims queued regions and retries; that is a distinct provider contract
whose transitive behavior and compiled math state have not been qualified
here. An allocator configuration value or a non-null pointer is not a
capability proof. Do not classify another mod or inspect opaque heap fields.

The packed alternative removes allocation/free only on its admitted rejected
path. Accepted objects retain the pair and add bounded packing/reconstruction
work. The stronger allocation-free accepted-object target remains open; this
alternative neither removes it from scope nor claims its savings.

### Remaining contracts: narrower questions, no blanket readiness claim

| Candidate | New evidence or design closure | Exact remaining research boundary |
|---|---|---|
| Property sorting | Concrete pool-lock scope and additional transform routes rule out previously tempting exclusion shortcuts | Prove scheduling/receiver exclusion for list links, shared wrapper +0x0C and scorer inputs at the three existing sorter callers; retain the earlier prefix shortcut until then |
| Dirty-pass refresh | Accumulator +0x200 protects a different list; stage dispatch reaches shader/property work without that lock | Prove list/eligibility ownership and pass-array aliasing in 0x00BB4740; larger interval reuse also needs pointer validity through all no-growth passes |
| Transparent sorting | Numeric revalidation eliminates dereferences of cached old bounds across comparisons | Qualify current operand reads and per-comparison lifetime; derive the exact native x87 adapter/admission and retain the current merge/provider contracts |
| Compound snapshots | Complete native predicate is structurally pure; direct scene receiver bypasses its own bracket; packed rejection avoids private child-callback storage | Qualify provider allocation order and predicate input ownership for the packed variant. Full local snapshots still need receiver-specific current-pointer restoration and recursive storage qualification |
| AABB predicates | Actual shape-program dispatch at 0x00C493A0 reaches shape slots +0x9C/+0xA0; native AABB +0x9C is verified at 0x0101E980; later dead-loop baseline needs no retained scene input | Stronger loop: plane-input ownership, complete admission state and bridge/provider qualification. Use the later native-frame intervention instead of extending shape lifetime |

The compiled bridge/frame checks are implementation work after the material
native contracts close. They are not an excuse to claim that unimplemented
code already passed. The existing Psycho acceptance gate is unchanged;
this research does not create a static-only implementation exception.

The absence of a complete ownership proof is not evidence of an actual race
or an explanation of Fairfax's FPS drop. The direct findings establish where
reuse can be made shorter, which native call chains still require inspection,
and which fallback boundaries must precede mutation.

## Implementation entry: separate closed local work from retained-input designs

The [remaining-boundary capture](../analysis/radare2/output/fnv_location_remaining_boundary_contract_20261007.txt)
retains the native method bodies, caller queries, register-input follow-up and
bounded executable bytes used here. The supported executable identity was
reverified. The following conclusions amend the preceding remaining-contract
tables; they do not turn an incomplete thread graph into an ownership proof.

### AABB baseline: remove two proven dead initialization loops

Both native AABB/frustum methods execute an integer loop before generating
their corners. The loop initializes a counter to eight, initializes a pointer
to the local corner buffer, decrements the counter, and advances that pointer
eight times. It never dereferences the pointer, writes a corner, calls a
constructor, or performs floating point work. Its two private stack locals
are not consumed after the loop.

| Native method | Verified ABI/dispatch | Removed block | Native continuation | Dead locals |
|---|---|---|---|---|
| `0x00C387F0` | thiscall, one pointer argument, AL result, RET 4; AABB slot +0x9C at 0x0101E980 | 0x00C387FF..0x00C38822 | 0x00C38822, original shape/Z test | [EBP-0x7C], [EBP-0x78] |
| `0x00C38920` | thiscall, one pointer argument, AL result, RET 4; same AABB table slot +0xA0 | 0x00C3892F..0x00C38952 | 0x00C38952, original generated-buffer argument setup | [EBP-0x70], [EBP-0x6C] |

Each block executes three setup instructions, eight iterations of eight
instructions, then four exit instructions: 71 integer instructions. The
selected replacement executes seven instructions, removing 64 executed
instructions, 17 private-stack writes and all 17 private-stack reads per
admitted native call. These are decoded instruction budgets, not timing or
FPS measurements. They apply independently to each method invocation; the
evidence does not supply Fairfax invocation counts.

The exact first instructions are seven bytes:

- 0x00C387FF: `C7 45 84 08 00 00 00`.
- 0x00C3892F: `C7 45 90 08 00 00 00`.

At either location, `E9 1E 00 00 00 90 90` could bypass the block with one
instruction. The captured native liveness proof below supports that smaller
patch, but it requires qualifying downstream provider register use. Select
the following stricter replacement instead: reconstruct the original loop's
complete final state before jumping to the same continuation. This avoids
that dependency and costs six additional integer instructions.

| Method | Final EAX | Final EDX and pointer local | Final ECX and counter local |
|---|---|---|---|
| 0x00C387F0 | EBP-0x68 | EBP-0x08 | 0xFFFFFFFF |
| 0x00C38920 | EBP-0x60 | EBP | 0xFFFFFFFF |

The selected sequence is LEA EAX, LEA EDX, XOR ECX,ECX, SUB ECX,1, MOV
the counter local, MOV the pointer local, then JMP to the continuation.
SUB starts with zero, exactly as the original final iteration does. It sets
the same CF/PF/AF/ZF/SF/OF values; the following MOVs and JMP preserve them.
All other general registers, stack contents and flags are unchanged at that
boundary. Neither LEA dereferences its operand. The two original locals keep
their exact final values even though the captured native bodies never read
them again.

Replace the whole 35-byte block, using these exact 22-byte prefixes followed
by thirteen unreachable `90` bytes:

- 0x00C387FF: `8D 45 98 8D 55 F8 31 C9 83 E9 01 89 4D 84 89 55 88 E9 0D 00 00 00`.
- 0x00C3892F: `8D 45 A0 8D 55 00 31 C9 83 E9 01 89 4D 90 89 55 94 E9 0D 00 00 00`.

The proposed x86 encodings, lengths and relative branches were assembled and
decoded separately; that check is retained with the native evidence. It is
not execution or behavioral qualification. Neither patch has been installed.

The liveness proof is local and complete for the captured native bodies:

- ESP, EBP, the saved receiver and callee-saved registers are unchanged.
  Keep the existing 0x1F0 and 0x1E0 frames; shrinking either frame is outside
  this change.
- The first method overwrites EAX at 0x00C38822, replaces EFLAGS through
  its original TEST at 0x00C38833 before consuming a branch condition, and
  supplies ECX/EDX afresh before corner generation. The surviving CL use
  reads the original shape-test result; it does not consume the skipped
  counter's upper ECX bits.
- The second method supplies its original generated-buffer address and
  receiver before its original 0x00C39270 call. That generator does not
  consume incoming EDX before its captured native scale helper overwrites
  EDX at 0x0045BB52. The complete 0x0045BB20 body closes this register-input
  question; a thiscall label alone would not have done so.
- No x87 or SSE instruction is removed or introduced. Corner generation,
  every side test, active-mask read, zero-Z branch, early return and native
  floating point observation remain at their original locations and stack
  addresses. There is no new arithmetic domain, cached plane, object read,
  bound retention, allocator operation or child callback.

This baseline therefore has no new scene-input, worker-exclusion or
cross-callback lifetime requirement. Its static intervention contract is
closed for the intact admitted native route. It must not remain classified
as blocked on the stronger extreme-corner path's plane-stability contract.

Keep implementation in the planned Psycho `multibound_frustum.rs` feature.
Use two exact 35-byte `OwnedCodePatch::new` definitions and one
`ModificationTransaction`, with signature preflight for the native prologues,
saved-receiver/frame setup and original patch blocks. Install both at the
existing core startup preparation boundary; reject a changed frame or block.
Rollback only owned bytes if either installation fails. The transaction is
not thread suspension: never install or restore these blocks during gameplay.
Follow the owning startup-safety contract for the new feature/config footprint.

Do not change either vtable slot, intercept a provider, add a wrapper, publish
an admission cache, or scan code per native call. A replacement virtual method
keeps its dispatch; any downstream generation/scaling provider receives the
original state when the admitted native method reaches it. This closes the
provider-register question without identifying a mod or qualifying its body.
The saving is the seven-instruction sequence against the original 71, with no
added per-call guard. Empty xref results do not prove the absence of arbitrary
computed or foreign middle-of-block entries; the admitted entry contract is
the ordinary captured native method route.

The baseline does not replace the stronger AABB target. That target still
removes repeated plane arithmetic when its separate contract is qualified.

### Stronger AABB path: close shape retention and terminal addresses by design

Select the post-generation native window at `0x00C38866` for the
stronger loop design, rather than replacing the entire virtual predicate.
The native receiver/Z reads and `0x00C39270` generation are already
complete there. The selected corner indices refer only to the existing local
buffer at [EBP-0x68]. No further shape field or global basis dereference is
needed; the optimization does not extend the shape's read lifetime.

Keep side tests at the original call instruction `0x00C388E8`, with
the original ESP/EBP, plane ECX and local-corner argument setup at
`0x00C388D4`. Temporary admission helpers must return before that
setup; they cannot leave a larger persistent frame below the native frame.

For the previously qualified maximum-corner design, select the actual maximum
corner and then corner 7 when they differ. Reusing the original call/setup for
the terminal corner-7 test makes the native helper's last x87 instruction and
stack-data addresses identical to the original path. Combined with the
earlier admitted arithmetic/exception argument, this resolves the proposed
terminal-address mechanism without assuming that diagnostic FP pointers are
unobservable. A larger virtual-wrapper frame does not provide this property.

This is a specified bridge invariant, not a compiled bridge result. Guard
instructions must preserve admission state, including exception/control/tag
state, and the selected index/Boolean accumulator must survive the original
call. The helper/provider and arithmetic-domain requirements still apply.
Current plane coefficients must remain valid for the admitted plane interval;
that exclusion has not been established by corner-buffer ownership.

### Pass output storage: concrete allocation and retirement provenance

The actual 16-byte RenderPass initialization route is cdecl
`0x00BA8EC0`, reached by creation `0x00BA9EE0`.
It zeroes pass +0x0C, allocates four bytes per requested light identity through
`0x00AA3E40`, publishes that returned pointer at +0x0C and records
byte capacity +0x0A. It copies supplied wrapper identities into the allocated
array; it does not make a list node or a wrapper the output array.

The reuse path `0x00BA8C50` keeps that allocation when capacity is
sufficient, and otherwise frees/clears it and publishes a new allocation.
Refresh growth `0x00BA8C30`/`0x00BA8C00` follows the same separate
allocation contract. Complete array destruction `0x00BA9520` frees
each pass's +0x0C allocation before freeing its 16-byte record, then frees
the outer array storage. Container initialization `0x00BA8B80` and
`0x00BA94B0` describe that outer array, not RenderPass construction.

This establishes native allocation provenance and which owner retires the
output storage. A valid live allocation is separate from the input objects
under its allocator's nonoverlap contract. It does not prove that a pointer
was not overwritten/recycled, qualify an unknown allocation provider, or
exclude concurrent list/eligibility changes. Keep these facts separate.
The per-pass fast branch can use the already established full-DWORD N <= 254
and byte C >= N+1 bound; it needs no cross-pass pointer cache. Whole-refresh
reuse still requires the larger input interval.

The current-source provider and these native birth/death routes provide a
concrete alias/lifetime investigation boundary. They replace the earlier
unspecified request to find the pass array's owner; they do not establish a
new ownership lock.

### Property membership: remove a false writer lead

The full `0x00B71450` body builds diagnostic data containing number
of lights, active lights and Reference ID. It is not the membership-add
writer. Its DWORD read at property +0x68 remains authoritative count-width
evidence.

The actual membership writer `0x00B71560` has two direct calls from
`0x00B9F480`. It reaches append `0x00B58570` without a fence, or
`0x00B713C0` / `0x00B702E0` on the fenced route. Marker and
retirement callers lead through `0x00B5B260` and
`0x00B5B410`. Their recursive traversal roots are
`0x00B5C490`/`0x00B5C5C0` and `0x00B5DAC0`.

The other inspected reassignment routes pass through `0x00BA0110`,
whose concrete direct callers include `0x00871290` and
`0x00B5D300`. It reaches the two recursive wrapper operations
`0x00B9F5B0`/`0x00B9F6A0` or directly reaches
`0x00B9F480`. Its virtual node/geometry dispatches and complete
thread/receiver provenance are still material; the direct-call list does not
supply them. These are the specific next ownership roots, not the unrelated
diagnostic function.

### Psycho allocation: separate owned reclaim from native game recovery

The source dependency path is now followed beyond the OOM wrapper:

`hook_alloc -> Runtime::alloc -> Heap::try_alloc_slow_with_provider`
uses the explicitly supplied `Runtime::acquire_region` closure. Region
backing is a protected-reserve lease or an exact dynamic mapping. On total
failure, `alloc_oom_recovery -> reclaim_queued_regions -> checked_purge`
revalidates zero live allocations under the heap-state lock and releases
only owned backing. Region destruction and reserve return use the shared
WinAPI wrappers and accounting. Failure sampling observes the process map;
it is not native engine garbage collection.

See [runtime](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/runtime.rs),
[heap](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/heap.rs),
[region](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/region.rs)
and [reserve](../psycho-engine-fixes/src/mods/heap_replacer/scrap_heap/reserve.rs).
These source paths contain no dispatch to the native game-recovery operation
0x00866A90 or a supplied scene/actor cleanup callback. This closes that
specific source-level recovery distinction for the owned Psycho provider.
It does not qualify a native or foreign provider, guarantee allocation success,
prove its compiled FP state, or resolve compound restoration through callbacks.

For compound optimization, qualifying the actual installed provider remains
mandatory. A native-layout capacity read cannot be applied to Psycho's opaque
identity. Moving a fallible allocation after mask mutation still needs its
explicit failure and state contract, even when the provider does not invoke
game cleanup.

### Current implementation disposition

| Operation | Native contract now available | Implementation status and remaining qualification |
|---|---|---|
| Both AABB dead initialization loops | Exact byte windows and continuations; seven-instruction reconstruction preserves registers, flags, locals and native FP work; startup-only owned admission adds no per-call guard | Implemented as an owner-approved unreleased static-qualified candidate, enabled by default. Native installation/visibility, startup acceptance and performance remain untested. |
| Stronger AABB extreme-corner loop | Shape reads end before intervention; original native call/frame can preserve terminal FP addresses; earlier numeric domain remains applicable | Plane-input exclusion and complete admission-state contract |
| One-walk dirty-pass refresh | Exact capacity bound, iterator ABI and concrete pass-output allocation/retirement owner | Current input ownership and qualified live output/provider; shared refresh additionally needs its longer interval |
| Transparent numeric reuse | No retained bound dereference; current-input comparison design and native arithmetic order are recorded | Exact adapter/domain and current read/lifetime contract |
| Full property merge | Finite pre-write score domain, native scorer/terminal replay and exact mutation roots | Shared score/input and list exclusion over its changed comparison schedule |
| Compound private/packed storage | Native predicate separation, original-frame packing opportunity, native/Psycho recovery distinction | Initialized restore-index/current-pointer contract and provider-specific ordering/failure qualification |

The repository's [behavioral gate](../AGENTS.md#no-guessing-and-behavioral-test-gate)
has no general static-only Psycho exception. After reviewing the first batch,
the owner explicitly approved the two named AABB setup patches as unreleased,
statically qualified candidates without a game-runtime baseline, enabled by
default. That scoped approval permits this implementation; it does not extend
to the stronger plane loop or any unresolved pass/sort/compound design.
It does not establish runtime or startup acceptance, close another ownership
contract, authorize a commit/deployment/release, or establish an FPS gain.

## First implementation batch and deferred research

### Selected implementation: two AABB setup replacements

The current binary evidence closes the local transformation at both native
methods, `0x00C387F0` and `0x00C38920`. Treat them as two patch sites in
one cohesive feature. Replace their initialization loops with the seven
instructions specified in the
[AABB baseline contract](#aabb-baseline-remove-two-proven-dead-initialization-loops).
Retain the complete original method frames, continuations, virtual dispatch,
corner generation and plane tests.

This batch removes 64 executed integer instructions, 17 stack writes and
17 stack reads per invocation reaching either admitted block. It introduces
no runtime bridge, guard, allocation, lock, FP-state operation or scene cache.
That budget does not establish invocation frequency, elapsed time or FPS.
The stronger arithmetic optimization is a separate unqualified operation.

| Planned file | Concrete change |
|---|---|
| `psycho-engine-fixes/src/mods/perf/multibound_frustum.rs` | Add the module, two exact 35-byte original/replacement definitions, native frame signatures and startup-only installer. Document the continuation state, supported entry contract, ownership, failure and zero added per-call cost. |
| `psycho-engine-fixes/src/mods/perf/mod.rs` | Declare the module and export its installer to core startup. Its static patches need no event forwarding. |
| `psycho-engine-fixes/src/startup.rs` | Route the new setting through the existing `install_runtime_hooks` preparation boundary after logger initialization. Use a separate installation transaction; preserve existing subsystem order and failure containment. |
| `psycho-engine-fixes/src/config.rs` | Add `PerformanceConfig.multibound_frustum_tests`, its default and the matching optional raw field. Follow the current `from_raw` precedence so explicit user values are honored and missing values take the selected default. |
| `psycho-engine-fixes/config/psycho_engine_fixes.toml` | Add only `performance.multibound_frustum_tests = true`, with a short description of the redundant setup work removed. |
| This document | Record the implemented ownership/lifecycle contract and distinguish code qualification from native acceptance; retain the deferred-research table. |

The default follows the existing plan's requested optimization coverage.
Use this user-facing comment: "Removes redundant setup work when checking
object bounds against the view." Do not add runtime-test directions, restart
advice, research status or a test asserting the shipped setting value.

Do not add settings, dormant bridges or placeholder modules for the other
unresolved designs in this batch. The existing light-score reuse and
sequential scene-light features retain their current behavior and settings.
The helper, Syringe, shared patch infrastructure and allocators need no source
changes for the selected operation.

### Installation and failure contract

1. Prepare literal expectations from the retained supported-executable bytes.
   Verify both original prologues, frame allocation and receiver-save setup
   before writing either loop. Each patch window is exactly 35 bytes; use
   exact signatures without wildcard bytes or a runtime-learned oracle.
2. Preflight both `OwnedCodePatch` sites and install them using one
   `ModificationTransaction`. Reject a changed frame or conflicting block.
   The helper accepts an identical pre-existing replacement without claiming
   its rollback ownership; retain that distinction.
3. Commit the installation transaction only when both sites are available.
   If the second operation fails, restore only writes made by this attempt.
   Preserve a pre-existing matching replacement and any later foreign write.
   Report a failed restoration explicitly; do not claim full rollback when
   ownership was lost.
4. Use the existing core startup preparation boundary while affected code is
   quiescent. Neither helper makes code writes atomic or suspends execution.
   Add no DeferredInit code write, gameplay-time reconfiguration or teardown
   unpatching. Successful patches remain for the process lifetime.
5. Emit a single human-readable `[MULTIBOUND]` installation/configuration
   summary through the existing logger. Use debug for patch addresses, warn
   for a safely rejected signature and error for an installation/restoration
   failure that cannot preserve the qualified state. Add no hot-path counters
   or per-frame diagnostics.

The complete final-register/flag/local reconstruction removes the need to
qualify a downstream generation provider's scratch-register assumptions.
It does not overwrite that provider or either virtual slot. Compatibility
admission concerns the actual owned blocks and their frame, not a module name,
version or vtable allowlist. Keep the native entry scope explicit; arbitrary
foreign jumps into the interior of a rewritten block are not qualified.

### Implementation and qualification sequence

Implement the module and paired installation first, then add the one setting
and startup routing in the same coherent change. Review the compiled 32-bit
replacement against the documented seven instructions, 35-byte footprints,
branch destinations and exact final register/flag/local values. Inspect only
the affected native/code boundary; no new whole-engine analysis is needed for
this local transformation.

The native behavioral expectation is unchanged AL result, visibility and
corner/plane work for each method, with identical continuation state and
the reduced integer instruction budget. Signature conflicts must preserve
existing code; unsuccessful paired installation must restore owned writes.
These expectations define qualification, not additional claims that an
unexecuted implementation passed them.

Run available affected production tests, then the explicit supported release
build after code changes:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes -p psycho-engine-fixes-helper
cargo fmt --all -- --check
git diff --check
```

Do not create mirrored native fixtures, source/byte-presence assertions,
configuration-default tests or a synthetic sort/culling reference to claim
native behavior. An assembler/disassembler check establishes encoding and
the static work budget; tests/builds do not establish native acceptance.
The new configuration field and startup installer require the existing
[startup-safety contract](nvse_startup_phase_safety.md), including its accepted
baseline and actual startup acceptance. Preserve startup phases, dependencies,
imports and TLS ownership rather than redesigning them for this feature.

The owner subsequently approved implementation of this named static-qualified
candidate without the runtime baseline. No plane/list/child ownership gap
remains for its selected setup replacements. Native acceptance and startup
acceptance are still unclaimed; no commit, deployment, packaging or release
is part of that authorization.

### Implemented unreleased AABB setup candidate

[multibound_frustum.rs](../psycho-engine-fixes/src/mods/perf/multibound_frustum.rs)
now owns the two literal native frame signatures and the paired 35-byte
patches. Core startup calls its installer when
`performance.multibound_frustum_tests` is enabled. The runtime default and
shipped TOML both enable it; explicit user values override the default.
There is no new lifecycle event, exported ABI, dependency or runtime owner.

The installer checks the existing pre-CRT activation flag and rejects use
after successful core initialization. Both frame signatures and both patch
blocks are preflighted before writes. One `ModificationTransaction` applies
the two sites and commits only after both succeed. An identical existing
replacement is accepted without claiming rollback ownership. Application
failure emits an error and drops the transaction; restoration remains
best-effort and never overwrites foreign bytes. A signature rejection leaves
the feature unavailable and is reported by core startup. No success message
is emitted on that path.

Successful installation logs `[MULTIBOUND] Redundant bounds setup optimized
at both native sites`. Debug logging identifies the two qualified sites;
the disabled configuration and unavailable feature paths report their status
once. Native invocations have no new diagnostics, counters, guards, allocation
or synchronization.

The [implementation evidence](../analysis/radare2/output/fnv_aabb_setup_implementation_contract_20261007.txt)
retains native entry reconfirmation, the actual compiled descriptors/payloads,
their native-destination disassembly and the compiled installer. The embedded
15-byte frame expectations and 35-byte original expectations agree with the
supported executable. Each compiled replacement performs exactly the selected
seven instructions and jumps to 0x00C38822 or 0x00C38952. This is static
qualification of the production bytes, not native execution or a timing test.

The existing affected production suite and supported 32-bit core/helper
release build passed. Changed Rust files passed formatting and the diff check
passed. Workspace-wide formatting reported unrelated OMV differences; those
files were not corrected by this feature. No config-value tests, mirrored
native fixtures or source assertions were added.

The complete new pre-Deferred footprint is confined to one parsed/serialized
performance boolean, immutable patch/signature descriptors and byte arrays,
the installer in the existing startup route, its temporary transaction and
one-time logging. Core/helper ownership, existing startup phase/order,
dependencies, helper callbacks and TLS ownership are unchanged. Import and
TLS comparisons against preserved pre-build and deployed artifacts found no
changes. The current historical-playtest-to-file identity was not independently
re-established; these comparisons are not an accepted startup baseline or
load-to-gameplay acceptance. The deployed core was left untouched.

Actual native installation/rollback, visibility, startup and performance were
not run. The result remains an unreleased statically qualified candidate;
the existing startup-safety gate still governs release. The deeper designs
below remain explicitly unresolved and have no production hooks or settings
added by this batch.

The owner separately requested committing this candidate and its supporting
research. That request does not establish native/startup acceptance or
authorize deployment, packaging or release.

### Further reductions: compound and portal vertex setup

The continued plane-owner audit found three additional local reductions in
native compound/portal construction. Their instruction contracts are closed
for the original supported bodies. They are proposals; no production patch,
configuration change or deployment was made by this research.

All new native evidence is retained in the
[deferred ownership follow-up](../analysis/radare2/output/fnv_location_deferred_ownership_followup_20261007.txt).
Radare2 supplied the primary instructions and call references. Bounded reads
of the same verified PE supplied exact bytes and full native function decodes;
prospective payloads were decoded at their actual intervention addresses.
Misaligned discoveries, clipped function output and incorrect exploratory
constructor labels are explicitly excluded in the raw evidence.

The new targets are four-vertex setup loops. Each assigns a counter and local
pointer, decrements the counter five times, and advances that pointer four
times by 12 bytes. The body never dereferences the vertex buffer and calls
nothing. The subsequent native vertex operation remains outside the patch.
The reduction follows the actual instructions; it does not depend on assuming
that a vertex constructor is cheap or that an input object is immutable.

| Native owner and admission | Intervention, exclusive end | Original frame qualification | Native continuation |
|---|---|---|---|
| `0x00C47B50`, compound append after its existing capacity branches | `0x00C47BC1..0x00C47BE4`, 35 bytes | First 9 bytes establish EBP, reserve 0x6C bytes and save ECX at EBP-0x68 | `0x00C47BE4`; native vertex call remains at `0x00C47BEB` |
| `0x00C47D20`, admitted portal-construction branch | `0x00C47DD6..0x00C47E0B`, 53 bytes | First 15 bytes establish EBP, reserve 0x174 bytes and save ECX at EBP-0x16C | `0x00C47E0B`; native vertex call remains at `0x00C47E4D` |
| `0x00C33870`, plane-producer recomputation branch | `0x00C3391F..0x00C33954`, 53 bytes | First 17 bytes establish EBP, reserve 0x1BC bytes, save ESI/EDI and save ECX at EBP-0x1B8 | `0x00C33954`; native vertex call remains at `0x00C3395E` |

The respective native methods return with RET 8, RET 4 and RET 0x10.
These are instruction-window replacements within their existing frames;
they introduce no wrapper ABI and retain the original caller and return
discipline. The prospective replacement must reproduce all of the following
states before resuming, including the two local words even if later original
code does not read them:

| Intervention | EAX | ECX | EDX | Counter local | Pointer local |
|---|---|---|---|---|---|
| `0x00C47BC1` | 0xFFFFFFFF | EBP-0x10 | EBP-0x40 | [EBP-0x58] = 0xFFFFFFFF | [EBP-0x54] = EBP-0x10 |
| `0x00C47DD6` | EBP-0x10 | EBP-0x40 | 0xFFFFFFFF | [EBP-0xEC] = 0xFFFFFFFF | [EBP-0xE8] = EBP-0x10 |
| `0x00C3391F` | EBP | EBP-0x30 | 0xFFFFFFFF | [EBP-0xF0] = 0xFFFFFFFF | [EBP-0xEC] = EBP |

For each block, two LEAs construct the final addresses; XOR followed by
SUB 0,1 reconstructs the terminal counter and the original arithmetic flags;
two MOVs publish the same local words; JMP resumes the original continuation.
The final SUB matches the original terminal iteration. Subsequent MOV/JMP
instructions preserve its CF/PF/AF/ZF/SF/OF. All other registers, ESP, EBP,
non-arithmetic flags, vertex-buffer contents and x87/SSE state are unchanged
by the proposed block. The one-past pointer is never dereferenced by it.

The original executed budget is three setup instructions, four iterations of
eight instructions, and four instructions in the terminal iteration: 39.
The proposed budget is seven instructions, so each reached block saves
32 integer instructions, nine local reads and nine local writes. Padding is
jumped over. This is a deterministic instruction reduction, not an FPS or
elapsed-time estimate. `0x00C33870` already copies a cached 100-byte record
on its admitted reuse branch; the new reduction affects recomputation only
and must preserve that cache gate.

Full bounded native decodes cover `0x00C47B50..0x00C47D11`,
`0x00C47D20..0x00C487F4` and `0x00C33870..0x00C33CED`, exclusive ends.
Their internal edges enter each window only at its start or at the original
loop backedge; no indirect JMP appears in those bodies. In particular,
`0x00C47BA2` reaches the first window's start, while `0x00C33890` and
`0x00C33905` reach the third window's start. Radare2 xrefs corroborate the
identified edges but are not treated as complete arbitrary indirect-call or
foreign-provider coverage.

Native caller evidence places the first two methods below compound builder
`0x00B5F170`: four direct append calls and six direct portal-construction calls.
That builder has three discovered direct calls from `0x0045B070`, at
`0x0045B92A`, `0x0045BA08` and `0x0045BA6E`. The plane producer is also
called at `0x00C47C81` and from portal-building branches. These are concrete
construction paths, not proof of their population or frequency at Fairfax.
Do not conflate this builder with `0x00B5BA80`, the separate combination
operation reached by scene visibility callbacks.

Implementation can reuse the existing core-owned immutable instruction-patch
and transaction machinery. Prepare exact frame and complete-block signatures
for all selected sites, preflight every site before writing, apply one owned
transaction and preserve foreign code on rejection or rollback. Keep native
allocation, generation, cached publication and visibility calls at their
original addresses and stack locations. Installation remains restricted to
the core's quiescent pre-CRT activation boundary; patches would live until
process exit. No per-call guard, bridge, retained input, lock, allocation,
counter or diagnostic is required for these local reductions.

The new blocks' binary state contract does not qualify their installer or
actual native behavior. The implementation section below records the later
explicit authorization and static qualification. Qualification must
inspect the actual compiled descriptors/payloads, transactional failure and
compatibility behavior, affected tests, supported release build and startup
scope. Existing authorization for the earlier two AABB sites is not a general
waiver for these three new sites. No runtime outcome is claimed here.

### Implementation plan: three compound/portal setup reductions

This approved plan defines the implemented batch recorded below. It is limited
to the three four-vertex setup
blocks above. The native instruction-state contracts are sufficient to design
these local reductions. The broader ownership and numeric designs remain
outside this batch, with their unresolved research listed below.

**Configuration and ownership.** Add a separate core performance setting,
`performance.multibound_vertex_setup`, proposed default true. An explicit
user value must take precedence over the default. Keep the existing
`multibound_frustum_tests` setting and its two-site installer independent.
The new three-site transaction must neither own nor roll back those existing
patches. This provides independent control and prevents a conflicting portal
site from blocking the already available AABB reduction.

Append the new boolean/optional boolean to `PerformanceConfig` and
`RawPerformanceConfig`, preserving the existing fields' order and types.
Wire the established `Default` and `from_raw` paths without a migration,
legacy-key alias or additional parser. The shipped TOML description should
describe the user benefit in one sentence:

```toml
# Removes redundant setup work when building visibility bounds through portals.
multibound_vertex_setup = true
```

Do not add restart advice, testing commentary or tests that freeze this
editable value. Technical qualification belongs in this owning document.

| File | Planned change |
|---|---|
| `psycho-engine-fixes/src/mods/perf/multibound_vertex_setup.rs` | New cohesive module with three immutable frame signatures, three complete original/replacement block descriptors, state-contract comments and one startup installer |
| `psycho-engine-fixes/src/mods/perf/mod.rs` | Declare the module and expose its installer within the crate |
| `psycho-engine-fixes/src/startup.rs` | Call its installer immediately after the existing AABB setup configuration branch, at the established pre-CRT activation boundary |
| `psycho-engine-fixes/src/config.rs` | Append the setting, default and optional raw value; honor explicit false |
| `psycho-engine-fixes/config/psycho_engine_fixes.toml` | Add the setting with the concise user description above |
| This owning document and native evidence | Record the implemented scope, compiled qualification and outstanding acceptance without duplicating native dumps |

**Patch contents.** Reconfirm executable identity and address-sensitive
evidence before coding. Use the complete 35-, 53- and 53-byte original
windows at `0x00C47BC1`, `0x00C47DD6` and `0x00C3391F`.
Use the prospective seven-instruction replacements already decoded in the
raw evidence: their rel32 jumps reach `0x00C47BE4`, `0x00C47E0B`
and `0x00C33954`, respectively. Preserve the exact final-state table above.
Fill the remainder of each original window with unreachable padding; do not
execute that padding or move the native continuations.

The module documentation must identify the three owners, per-reached-block
32-instruction saving, full register/flags/local preservation, startup-only
installation, failure ownership and process lifetime. Every descriptor should
explain its distinct frame offsets and why its final SUB is necessary. No
generic assembly generator, runtime bridge, pointer cache or new shared hook
abstraction is needed. Native vertex and plane providers remain at their
original call boundaries with the same inputs.

**Admission and failure.** Reuse `CodeSignature`, `OwnedCodePatch` and
`ModificationTransaction`. Require the pre-CRT boundary and unfinished core
initialization. Preflight all three original frame signatures and all three
blocks before any write. An original block or the exact same replacement is
accepted by the established patch API; an existing replacement acquires no new
ownership. Any conflicting frame/block leaves the new group unapplied.

Apply the three patches in a single transaction and commit only after all
succeed. On a write failure, the transaction attempts to restore only this
group's acquired writes and reports restoration failure through the existing
logger. Never overwrite a changed foreign owner during rollback, promise
infallible rollback, or continue into a broader optimization as fallback.
Keep startup's established recoverable-error handling so an unavailable new
group does not prevent other independently installed performance features.

Use one stable `[MULTIBOUND_VERTICES]` tag: info for installed/disabled
configuration milestones, debug for the three qualified native addresses,
warn for a rejected group retaining existing code, and error for an application
or rollback failure. No gameplay-time logging, counters, configuration polling,
unpatching or event work belongs in this implementation.

**Qualification and acceptance.** Before production edits, establish the
new candidate's behavioral gate under root `AGENTS.md`: actual native startup,
visibility and portal traversal with the relevant workload, and the unchanged
baseline where required. Expected behavior includes normal load-to-gameplay,
the same object/portal visibility, and the existing native cached-record and
recomputation branches. The owner's general FPS observation does not establish
these new sites' baseline or acceptance. If the real boundary cannot be
exercised, implementation remains pending a separate explicit instruction
authorizing this named unreleased candidate without that baseline. Approving
this design alone must not be silently interpreted as that exception.

After authorized implementation, statically qualify the actual compiled
descriptor originals against the supported executable and decode the actual
embedded payloads at their native destinations. Confirm original frames,
complete lengths, final states, native call locations and continuations;
static decoding is not a behavioral test. Run available affected-core tests
through Wine with `--target i686-pc-windows-gnu`, then one release build for
`psycho-engine-fixes` and `psycho-engine-fixes-helper` using that explicit
target. Check formatting of changed Rust and `git diff --check`.
Do not add mirrored native fixtures, source assertions, synthetic engine
models or configuration-value tests.

The new setting, immutable descriptors and activation call are a concrete
pre-DeferredInit change. Apply the completely read
[startup-safety contract](nvse_startup_phase_safety.md): establish the
accepted artifact/source boundary and review only this batch's complete
footprint, including config layout and any import/TLS change caused by the
actual build. Keep the helper thin and dependencies, worker order and shared
library ownership intact. Static agreement does not supply its required
representative Proton load-to-gameplay acceptance.

Completion reporting must distinguish implemented/compiled qualification
from actual native startup, visibility and timing results. The operation
budget is 32 fewer integer instructions and nine fewer local reads/writes per
reached new block; do not convert it to an FPS prediction. No deployment,
packaging, release or commit is part of this planning request.

**Deferred work.** Keep the five rows in the deferred-optimization table
explicitly unresolved. Plane-loop reduction still needs receiver-specific
input exclusion and its FP adapter; pass refresh still needs list/eligibility
and output ownership; full light sorting still needs shared score/input/list
exclusion; transparent reuse still needs current bound lifetime/coherence and
numeric state equivalence; compound packing still needs initialized-prefix
compatibility, current-object lifetime and allocator-order qualification.
None is a fallback or an additional hook in this batch.

### Implemented candidate: compound/portal vertex setup

The owner approved proceeding with this named plan and explicitly requested
enabled-by-default configuration after the unreleased, static-only
implementation boundary was stated. This authorizes the three setup reductions
without a game-runtime baseline. It does not establish runtime acceptance or
authorize deployment, packaging, release or a commit.

The core now owns
[`multibound_vertex_setup.rs`](../psycho-engine-fixes/src/mods/perf/multibound_vertex_setup.rs).
`performance.multibound_vertex_setup` defaults to true in both the Rust
configuration and shipped TOML; an explicit value takes precedence. Missing
keys use the established default path. The existing two AABB setup sites and
their setting remain independently owned.

| Native owner | Complete patch window | Original continuation |
|---|---|---|
| Compound append `0x00C47B50` | `0x00C47BC1`, 35 bytes | `0x00C47BE4` |
| Portal compound builder `0x00C47D20` | `0x00C47DD6`, 53 bytes | `0x00C47E0B` |
| Portal plane producer `0x00C33870` | `0x00C3391F`, 53 bytes | `0x00C33954` |

Each embedded replacement implements the full final-state table above with
seven integer instructions, including a direct jump over unreachable padding.
It removes 32 executed instructions, nine local reads and nine local writes
per reached block. This is a deterministic instruction/memory-operation
budget, not an executable benchmark or FPS prediction. The third site's
existing cached-record branch still bypasses recomputation. Vertex generation,
plane generation and subsequent provider calls remain outside the patches.
No gameplay-time bridge, allocation, lock, telemetry or event work was added.

Installation runs after the existing AABB branch at core activation. It requires
the pre-CRT boundary and unfinished core initialization. All three exact entry
frame signatures and all three complete windows are admitted before any write.
The existing patch API accepts exact replacements without acquiring ownership;
conflicting bytes reject installation. One independent transaction owns newly
applied writes, commits only after all three succeed, and attempts reverse
ownership-aware restoration on failure. Rollback cannot promise recovery from
memory/protection failure and never overwrites a changed foreign owner. The
startup caller reports an unavailable group and continues its established
independent feature installation. Successful patches live until process exit.

**Static qualification.** Executable identity and aligned native entry/loop
instructions were reconfirmed through the radare2 MCP. The release DLL's actual
compiled frame and original-block slices match the supported executable; all
three payload lengths and decoded rel32 destinations match the table. The
complete compiled installer checks all six descriptors before its first apply
call, reaches commit only after three successful apply calls, and routes apply
errors through transaction drop. The unchanged shared patch/transaction source
supplies exact-byte admission, write revalidation and restoration ownership.
These are source/binary proofs, not exercised native failure scenarios.

The affected core suite passes through Wine, and the core/helper release build
passes for `i686-pc-windows-gnu`. Changed Rust formatting and document/diff
checks pass. No configuration-default tests, mirrored native fixtures or
synthetic engine behavior tests were added. Native reconfirmation, compiled
descriptors, payload decoding and complete installer evidence are preserved in
[implementation evidence](../analysis/radare2/output/fnv_compound_vertex_setup_implementation_contract_20261007.txt).

The new setting, immutable descriptors and activation call change the
pre-DeferredInit footprint. The helper and shared libraries were not edited.
The new core/helper artifacts retain the pre-change local artifacts' imports,
TLS callback identities/template extent, CRT initializer identities and export
names. Existing configuration fields retain their source order and types; the
new optional field uses the current parser. This comparison does not map those
local artifacts to the last accepted gameplay artifact and does not prove
startup compatibility. At implementation qualification, actual Proton
load-to-gameplay, visibility, portal traversal, native cached/recomputation
behavior and timing had not been exercised by the agent. The later
[owner session evidence](#owner-session-evidence-after-implementation) confirms
installation and continued activity, not full native equivalence or timing.
Runtime and release acceptance remain outstanding. The five broader designs
below remain deferred with their explicit ownership/numeric gaps.

### Deferred ownership: contracts narrowed by the follow-up

The broader designs below still have material gaps. This follow-up closes
specific provenance and index questions rather than classifying a whole
subsystem as immutable.

**Plane arguments and publication.** Multibound-node visibility
`0x00C46F60` passes culler +0x2C to shape slot +0x9C at
`0x00C4702A` and `0x00C47081`. Compound shape-program dispatch
`0x00C493A0` instead passes compound +0x30 for its base test, or
`compound[+0x08] + 100 * record_index` for program tests. Those records
reach +0x9C or +0xA0 depending on the program operation. The plane input is
therefore not one universal heap allocation or an assumed camera global.

`0x00C4F070` publishes camera +0x0C before calling `0x00A694A0`
at `0x00C4F0C1`, then reaches root visibility. `0x00A694A0` copies
seven camera-frustum DWORDs to culler +0x10, calls `0x00A74E10`
with output culler +0x2C, and sets its active mask at culler +0x8C to 0x3F.
The complete `0x00A74E10..0x00A755C6` body writes six plane records
through separate DWORD stores. This publisher is not an atomic snapshot or
an ownership barrier.

For compound base planes, `0x00C47980` supplies camera +0xDC and
camera +0x68 to the same publisher with output compound +0x30, then resets
compound program/count state and copies camera position to +0x94.
The admitted native `0x00C33870` paths either copy a cached 100-byte
record or write plane data and its mask into the supplied output. Compound
append/construction passes array-backed records to it. Array growth through
`0x00C4A070` can replace that backing storage. Initial allocation and
record construction do not exclude later resize or publication.

The remaining AABB ownership question is now receiver-specific: establish
exclusion from camera/culler reassignment for inline inputs, and from compound
base publication, portal-record publication and array replacement for the
compound inputs. The native call sites and producer bodies do not establish
those objects' complete scheduler ownership or all installed providers.
Do not retain plane values across the altered loop until that interval is
proven. The independent full-state setup reductions above retain none.

**Membership roots and eligibility.** `0x00B5D300` takes the scene in
ECX and a light wrapper as its one stack argument. Its inspected reassignment
paths invoke geometry/shape virtual methods and call `0x00BA0110` for
selected objects. It has five discovered direct call instructions across
four callers: shadow preparation `0x00871290`, movement-gated
`0x00B5D930`, light addition `0x00B5ECA0` twice, and drain
`0x00B5FD60`. This replaces an unspecified writer root with actual native
owners; it does not prove those callbacks or scene receivers are exclusive.

The drain enters synchronization at `0x00B5FD90` with global
0x011F9EA0 before consuming additions and updates. Its non-shadow addition
route calls `0x00B5ECA0` at `0x00B5FDBE`; its non-dynamic update route
calls `0x00B5D300` at `0x00B5FDEF`. By contrast, shadow preparation
obtains scene zero through `0x00450B80`, whose actual implementation reads
`0x011F91C8 + 4 * scene_index`, and calls reassignment at
`0x008718EC`. It can then call `0x00BA0110` at `0x0087190E`
and finalize at `0x00871916`. One synchronized caller cannot supply a lock
contract for the separate shadow-preparation caller or the pass iterator.

The actual pass iterator `0x00B70600` checks a WORD at wrapper +0x110,
the native-light pointer at +0xF8 and its APP_CULLED flag at +0x30, and
wrapper BYTE +0xEC. The constructor initializes +0x110 with a WORD store
at `0x00B9FF15`; existing visibility-update evidence supplies a later
writer. Stable list membership alone is consequently insufficient for
one-walk equivalence. Close the wrapper/native-light lifetimes and eligibility
writers as well as the list and output-array intervals. The movement helper's
different status access must not replace the iterator's actual WORD check.

**Snapshot initialized and consumed indices.** The complete save
`0x00C49050` and restore `0x00C49100` bodies now define the exact
index rule. Save allocates four times compound +0x10, writes snapshot word
zero from compound +0x90, and starts index i at one. It writes word i from
record `(i-1)` +0x60 only while both signed comparisons admit
`i < compound[+0x24] + 1` and `i < compound[+0x10]`. Both fields are
reread inside the loop. Restore writes the base word, applies the same
current signed bounds to its reads, and then frees the snapshot.

For an admitted stable domain `1 <= Q <= 4` and `0 <= L <= Q-1`,
where Q is capacity +0x10 and L is record count +0x24, exactly L+1
snapshot words are initialized. More generally, with stable positive signed
capacity and nonnegative count whose +1 does not overflow, the initialized
count is `1 + min(L, Q-1)`. Capacity alone is not initialized-word count.
For example, Q=4 and L=0 initializes only the base word; Q=4 and L=2
initializes three words. A packer must never inspect the unused allocation
tail or turn its unspecified contents into initialized mask values.

The native `0x00C47B50` append guard grows when `L+1 >= Q` before
adding its record, leaving a spare snapshot slot on its admitted arithmetic
path. This proves that writer's local bound, not every other writer's invariant.
An accepted callback may change the current compound or its bounds. A private
restore can use only indices that were saved and whose native consumption is
qualified; entry capacity four is not enough. On the isolated original rejected
predicate route, the previously proven structural purity closes synchronous
limit/pointer mutation inside that predicate, while external ownership and
installed-provider contracts remain open. Allocation deferral still needs its
separate ordering, recovery and FP qualification before any mask mutation.

### Deferred optimizations: exact research needed

These operations remain in the performance scope, but their implementation
must not be bundled into the first batch. Research may continue independently
while the proven local changes are implemented. A closed result for one row
does not qualify the others.

| Deferred operation | Evidence already usable | Research required before its production implementation |
|---|---|---|
| Stronger AABB extreme-corner plane loop | Native corner generation completes before `0x00C38866`; using the produced buffer ends shape retention. The bounded numeric domain and terminal corner-7 replay are recorded. Inline culler, compound base and array-backed plane arguments now have concrete publishers. | Close exclusion for the specific inline camera/culler inputs and compound base/portal-record/array inputs over the changed read interval, including installed providers. Qualify the exact admission-state adapter and original-frame side-call bridge at `0x00C388E8`, including x87 control/tag/exception and terminal instruction/data addresses. Validate the Cartesian pattern from actual generated corners; do not require assumed immutable basis globals. Account for guard cost. |
| One-walk dirty-pass refresh | The no-growth branch at `0x00BB4F7A..0x00BB500A`, full-DWORD property count bound N <= 254, byte capacity C >= N+1, iterator ABI and output allocation/retirement routes are known. Reassignment now has concrete shadow, movement, addition and drain callers; eligibility reads are explicit. | Establish current list/wrapper/native-light lifetime and exclusion for the admitted pass interval, including WORD status, APP_CULLED and shadow-byte writers; qualify live nonaliasing output allocation/provider. Complete receiver/scheduler provenance for the distinct writer routes. Prove slot-0 and output/count publication with the exact adapter. Sharing enumeration across multiple passes additionally requires the longer interval and 1016-byte scratch/stack contract; the narrow branch does not prove it. |
| Full lighting-property merge-sort upgrade | Actual sorter/scorer ABI, finite pre-write score admission, list/fence rules, native terminal comparison and mutation roots are recorded. | Close exclusion for shared wrapper score +0x0C, current score inputs and list membership over the altered comparison/relink schedule. Trace insertion/removal/marker paths and their scheduler ownership. The node-pool mutex and accumulator +0x200 lock do not supply that exclusion. Then qualify stable ordering, exceptional-domain fallback before mutation, terminal native math state and small-input guard cost. Preserve the existing score-reuse implementation until this is closed. |
| Transparent merge-head numeric reuse | `0x00B98B20` supplies the exact input reads and x87 order; cached numeric tuples avoid future dereferences through stale bound identities. | Prove current geometry/bound lifetimes and coherent read intervals for both depth modes. Preserve the shared camera acquisition and separate nonzero-mode bound reads. Qualify the exact key adapter, mixed cached/native comparisons, control/exception and diagnostic FP-address state, and stable merge/cleanup boundaries. Inspect guard loads versus saved arithmetic; equal numeric input bits alone do not prove the complete native state contract. |
| Compound snapshot storage and rejected-object packing | Native `0x00C491A0` predicate structural purity, mask layout, packing windows, native current-pointer restoration and native/Psycho recovery distinction are recorded. Save/restore index rules and the initialized-prefix formula are now explicit. | Close stable entry metadata and actual current culler +0xC0 restoration/lifetime, including compatibility of consumed indices with the initialized prefix across callbacks. For private storage across accepted callbacks, close structural replacement and recursion/stack bounds through the actual child/accumulator/shader routes. For rejected-object packing with allocation deferred on acceptance, qualify the actual installed allocator's ordering, cold/recovery/failure and compiled FP contract before mask mutation. Psycho heap identities are opaque; native capacity fields cannot be used for them. Accepted callbacks keep native snapshots until independently qualified. |

For these rows, preserve complete raw native bodies/caller evidence and update
the owning contracts when a named gap closes. Do not infer exclusion from an
empty xref list, a class name, a header check or an unrelated critical section.
If the proposed optimization itself causes a longer ownership interval or
changes recovery order, redesign that interval before adding a global cache
or a blocking lock.

### Loop reductions that preserve native read schedules

The [loop continuation evidence](../analysis/radare2/output/fnv_loop_optimization_continuation_20261010.txt)
closes four additional local reductions across six intervention sites. These
are new proposals, separate from the implemented vertex-setup feature. They
optimize compound-mask handling and traversal without retaining scene inputs,
replacing floating point arithmetic, moving allocator calls or changing child
dispatch.
The larger five reuse designs in the table above remain separate.

**Selection rule.** Preserve the native engine-memory read/write sequence and
the existing call boundaries. Forward values only inside an uninterrupted
integer block, through registers whose complete outgoing values are proved.
The removed loads read private locals in the current native frame; no engine
field is assumed immutable. This avoids adding the worker-exclusion and
cross-callback lifetime requirements of the broader snapshot proposals.
Native valid-object, allocation and frame contracts still apply; this is not
a guard for already-invalid engine pointers or arbitrary middle-block entry.
These are replacements inside native functions, with no new FFI bridge or
stack reservation. Save retains its no-argument RET, restore its RET 4,
sphere/plane its RET 8, and all three program dispatchers their RET 4. Their
ECX receiver, existing arguments, saved nonvolatile registers and native
cleanup discipline remain unchanged.

| Owner and intervention | Native work | Qualified prospective work | Saving per reached block |
|---|---|---|---|
| Mask save `0x00C49050`, body `0x00C490CD..0x00C490F6` | 14 integer instructions, including six stack reads | 11 instructions, three stack reads; original backedge `0x00C490A5` | Three instructions and three private-local reads |
| Mask restore `0x00C49100`, body `0x00C4914E..0x00C49177` | 14 integer instructions, including six stack reads | 11 instructions, three stack reads; original backedge `0x00C49126` | Three instructions and three private-local reads |
| Sphere/plane mask helper `0x00C4A790`, repeated comparison `0x00C4A801..0x00C4A807` | Repeats an equality comparison against private local -0x08 and executes its conditional branch | One direct jump to `0x00C4A807` using the already-established equality | One instruction and one private-local read |
| Compound program dispatchers `0x00C491A0`, `0x00C493A0` and `0x00C49560`; windows below | Recompute `12 * index` for the second and third live tag reads | Retain the invocation-local offset in EAX or EDX; preserve all three current array/tag reads | Two instructions and one private-local read when reaching the second check; four instructions and two private-local reads when reaching the third |

Range ends are exclusive. The first two windows are exactly 41 bytes; their
32-byte useful payloads end in a short backward jump, leaving nine unreachable
NOP bytes. The third window is six bytes: `EB 04 90 90 90 90`; its four NOPs
are also unreachable. Savings describe these blocks, not their complete loops
or elapsed time. If save and restore respectively visit Ks and Kr record
masks, their combined saving is `3 * (Ks + Kr)` instructions and the same
number of private-local reads. No fixed capacity, unchanged callback count,
four-slot assumption or FPS prediction is needed for that budget. The restore
stack-read totals include its unchanged snapshot-pointer argument load.
The bound dispatch window is 80 bytes, with 68 useful bytes followed by 12
unreachable NOPs. The shape and portal windows are each 83 bytes, with 71
useful bytes and the same 12-byte unreachable tail. Their combined saving is
`2 * (D2 + D3)` instructions and `D2 + D3` private-local reads, where D2 and
D3 count visits to the second and third tag checks across the three owners.
These visits need not observe the same live array/tag value.

**Mask-save state proof.** Let i be [EBP-0x0C], T be [EBP-0x24], B be
[EBP-0x04], R be `T[+0x08] + 100 * (i-1)` with native 32-bit arithmetic,
and M be `R[+0x60]`. The original body loads i twice, reloads R from
[EBP-0x1C] and reloads M from [EBP-0x20]. No call or intervening write changes
those locals. The prospective block loads i once into EAX, calculates R in
EDX, preserves the store of R to [EBP-0x1C], loads M into EDX, preserves the
store of M to [EBP-0x20], loads B into ECX and writes M to `B[i]`.

At the backedge both sequences have EAX=i, ECX=B and EDX=M. Both local stores
and the snapshot store have identical values. The nonprivate accesses remain,
in order: read T+0x08, read R+0x60, write B[i]. The final flag-writing
instruction is the same pointer ADD with the same operands; later MOVs and
JMP do not change flags. Using LEA for i-1 instead of SUB therefore changes
no outgoing flag. All other registers, ESP/EBP and floating point state are
untouched. The original increment and both signed limit/capacity comparisons
remain outside the window and continue to reread native metadata.

**Mask-restore state proof.** Let i be [EBP-0x08], B be the stack argument
[EBP+0x08], T be [EBP-0x1C], M be B[i], and R be the corresponding current
record address using the same native arithmetic. The prospective block keeps
i in EAX, obtains M in ECX and stores it to [EBP-0x18]. It then computes R
in EAX, stores R to [EBP-0x14] and writes ECX to R+0x60.
The original and proposed outgoing states are EAX=R, ECX=M, EDX=T, with both
private locals and the engine mask store preserved. The nonprivate accesses
remain, in order: read B[i], read T+0x08, write R+0x60. Their pointer ADDs
have identical operands and flags despite different destination registers.
ESP/EBP, the other registers and all floating point state remain unchanged.
The current-pointer selection in the native caller, base-mask restoration,
increment/bounds loop and final getter/free calls are unchanged.

**Repeated-comparison proof.** The first gate at `0x00C4A7F4` stores the
side helper's EAX result into [EBP-0x08], compares that local with one, and
branches from `0x00C4A7FB` to `0x00C4A801` only on equality. There is no
intervening call or local write. The second identical comparison must therefore
produce the same flags and cannot take its JNE. A direct jump skips only that
redundant comparison/branch. On this admitted edge, CF=0, PF=1, AF=0, ZF=1,
SF=0 and OF=0 before and after; all other state is untouched. The original
mask load/write and subsequent loop remain in place. The original side call
at `0x00C4A7EF`, its frame and every FP instruction/address remain unchanged,
including when a downstream provider returns the equality result.
No scalar arithmetic admission or side-provider purity claim is needed for
this integer-only reduction: the original call and its returned state remain
in place.

**Compound-program state proof.** At `0x00C49277`, the native block loads
the current index from [EBP-0x1C] and computes its native 32-bit product with
12 into EAX. The first tag check reads the current array pointer at receiver
+0x18 and compares its record tag with two. If it does not exit, the native
block reloads that same private index and recomputes the same product before
reading the current array pointer again and comparing the tag with three.
After another nonterminal result it stores zero to [EBP-0x1D], repeats the
same private-index calculation a third time, rereads the current array pointer
and tag, stores that tag at [EBP-0x60], and dispatches seven/eight/other.

There is no write to [EBP-0x1C], call or EAX modification between the first
product and the point where the third tag read replaces EAX. Both later
MOV/IMUL pairs can therefore be removed. The intervening receiver-local loads,
three live array-pointer reads, three tag reads, and both private stores remain
in their native order. This does not collapse live tags into one cached switch
value: a different tag at the second or third read still follows the original
branch. At either terminal exit, EAX is the original product, ECX is the
receiver, EDX is the most recently read array pointer, and flags are from the
same tag comparison. At seven/eight/other exits, EAX is the third live tag,
ECX/EDX and private stores are identical, and flags come from the same final
comparison. Removed IMUL flags are overwritten by CMP before any exit.
All other registers, ESP/EBP and FP state remain unchanged.

The complete native owner supplies one ordinary entry at `0x00C49277`,
including its backedge from `0x00C4936B`. The replacement's two terminal
branches still reach `0x00C49370`; its remaining exits are `0x00C492C7`,
`0x00C492FF` and `0x00C49335`. No side call is moved: predicate calls at
`0x00C492F5` and `0x00C4932D` retain their addresses, arguments and states.
The arithmetic proof uses native 32-bit multiplication, including overflow,
and does not assume a program size, tag range or immutable engine array.

The other two program dispatchers were independently decoded in full and
qualified against their actual frame/window bytes. Their private index is
[EBP-0x0C], and the live offset is EDX until the third tag read overwrites
it. EAX remains the receiver and ECX the most recently read array pointer.
Each retains both zero/tag stores, all engine reads, all comparison flags,
the loop backedge and every downstream call at its original address. This
conclusion comes from those bodies and payloads, not from substituting one
function's layout for another.

| Dispatcher | Complete window; useful/padded lengths | Receiver local; zero/tag locals | Terminal destination; seven/eight/other destinations | Original backedge; unchanged calls after dispatch |
|---|---|---|---|---|
| Bound `0x00C491A0` | `0x00C49277..0x00C492C7`; 68/12 bytes | -0x54; -0x1D/-0x60 | `0x00C49370`; `0x00C492C7` / `0x00C492FF` / `0x00C49335` | `0x00C4936B`; `0x00C492F5`, `0x00C4932D` |
| Shape `0x00C493A0` | `0x00C4940D..0x00C49460`; 71/12 bytes | -0x28; -0x0D/-0x30 | `0x00C49539`; `0x00C49460` / `0x00C494AB` / `0x00C494FE` | `0x00C49534`; `0x00C494A4`, `0x00C494EF` |
| Portal `0x00C49560` | `0x00C495C0..0x00C49613`; 71/12 bytes | -0x1C; -0x0D/-0x20 | `0x00C496DD`; `0x00C49613` / `0x00C49666` / `0x00C496A2` | `0x00C496D8`; `0x00C4965C`, `0x00C49690` |

All three compiled prospective windows have five verified outgoing branch
destinations: two terminal branches plus seven/eight/other. Their call-free
windows contain no lock, ownership transfer, exception frame change, floating
point instruction or scene mutation. Predicate callbacks remain entirely
outside the changed windows, including the shape's virtual providers.

The actual instructions at `0x00C4A7FF` and `0x00C4A7AE` are unreachable
jumps on the inspected ordinary native routes, not padding. Neither supplies
an additional native entry into the repeated comparison. Complete bounded
owner decoding supplies the branch proof; empty MCP xrefs are only supporting
discovery evidence and do not exclude arbitrary foreign/computed entries.

**Installation contract for later implementation.** Use six exact owned
patch windows and one independent startup transaction in Psycho. Require the
established quiescent pre-CRT activation boundary. The nine-byte entry/frame
signatures below identify `0x00C49050`, `0x00C49100`, `0x00C4A790`,
`0x00C491A0`, `0x00C493A0` and `0x00C49560`; they are not sufficient
admission by themselves:

```text
save:    55 8B EC 83 EC 24 89 4D DC
restore: 55 8B EC 83 EC 1C 89 4D E4
helper:  55 8B EC 83 EC 10 89 4D F0
program: 55 8B EC 83 EC 64 89 4D AC
shape:   55 8B EC 83 EC 3C 89 4D D8
portal:  55 8B EC 83 EC 24 89 4D E4
```

Require the 13-byte predecessor gate at `0x00C4A7F4`:
`89 45 F8 83 7D F8 01 74 04 EB 22 EB 1E`. The third patch depends on that
specific incoming equality proof, so checking its six-byte window alone is
insufficient. Close that admission gap by covering every complete owner body:

| Owner | Complete body, exclusive end | Original body length |
|---|---|---|
| Save | `0x00C49050..0x00C490FD` | 173 bytes |
| Restore | `0x00C49100..0x00C49196` | 150 bytes |
| Sphere/plane | `0x00C4A790..0x00C4A833` | 163 bytes |
| Bound program | `0x00C491A0..0x00C49391` | 497 bytes |
| Shape program | `0x00C493A0..0x00C4955A` | 442 bytes |
| Portal program | `0x00C49560..0x00C496FE` | 414 bytes |

For each owner, preflight its complete entry-to-window prefix and
window-end-to-return suffix using two immutable `CodeSignature` descriptors,
then its window using `OwnedCodePatch::verify()`. The raw evidence retains
every exact prefix/window/suffix byte partition. This covers the frame,
predecessor, native local setup, incoming branches, remaining bounds and calls,
and return without a duplicate full-body array or a new admission framework.
Only the exact native window or the exact researched replacement is admitted;
all other owner bytes must remain native. The helper prefix includes its entire
13-byte predecessor gate. This rejects a changed native owner branch or frame
even when the patch window alone still matches.

Verify all 12 signatures and six windows before any write, then apply the six
patches through one independent transaction. Preflight covers 1839 native
bytes; application retains the existing window revalidation. These fallible
reads and allocations remain cold startup work; there is no per-call
capability scan or scene read. Reject conflicting owner bytes and retain the
existing code. Keep equivalent existing patches unowned and restore only
acquired writes on failure. Do not hook a vtable,
replace an allocator, infer a heap layout, change reference counts or add
per-iteration guards. A provider detouring an entry keeps its own path; foreign
middle-block contracts are not admitted by the intact native-entry proof.

**Qualification boundary.** The supported executable identity, complete
native bodies, frames, incoming native edges, all outgoing registers/flags,
private writes, nonprivate access order, calls and loop bounds are now closed
for all six sites in these four proposals. The actual separately assembled
payloads have been decoded at their native destinations, with verified window
lengths, padding and branch targets. This is prospective binary qualification,
not a production installer test or a behavioral result. Implementing still
requires authorization
for this separate batch and the applicable Psycho acceptance boundary, followed
by actual compiled-descriptor/installer qualification and affected checks.
No production file was changed by this research.

There is no remaining native-data, arithmetic, allocator-order or callback
ownership research prerequisite for this local six-site batch. The complete
owner-byte admission above is part of that conclusion, not an optional future
hardening step. Compiling and qualifying the actual production descriptors,
startup installer and accepted artifact remains implementation work. This
conclusion does not qualify any of the five broader reuse designs below, and
it does not identify the consumer responsible for the owner's FPS drop.

### Broader reuse designs: ownership remains a prerequisite

The continuation also follows the concrete writers behind the five open rows.
It does not establish their mutual exclusion, and it does not treat an
unobserved race as a reported gameplay defect.

- Property membership reaches marker insertion at `0x00B718C8`/`0x00B718D2`,
  ordinary insertion at `0x00B715A8`/`0x00B715D6`, and retirement at
  `0x00B71600`. Complete `0x00B5B260` and `0x00B5B410` brackets call marker
  insertion, traverse current light candidates and call membership retirement;
  their direct roots remain `0x00B5C490`, `0x00B5DAC0` and `0x00B5C5C0`.
  Neither bracket encloses that interval in the node-pool lock. This settles
  their local locking question, not scheduling of every receiver.
- Iterator eligibility has independent writers. `0x00B9E970` publishes the
  WORD at wrapper +0x110 at `0x00B9EF09`, and dirties affected properties at
  `0x00B9EEA9`. Its callers are shadow preparation `0x0087184A` and scene
  traversal `0x00B5E915`. `0x00B9DCB0` publishes the shadow BYTE at +0xEC
  at `0x00B9DD76`; its discovered direct callers are `0x00B5C450`,
  `0x00B5CBD0` and `0x00B5CD00`. Scene visibility also sets/clears native
  APP_CULLED at `0x00B5FAB9`/`0x00B5FCDA`; `0x00B5CBD0` clears it at
  `0x00B5CC57` on its existing-wrapper route. Lock acquisition at
  `0x00B5CC22` belongs to its new-wrapper route and does not enclose that
  existing-wrapper write. The pass iterator takes none of those locks.
- Shared score +0x0C remains written at `0x00B9DCA3`. The sort's copied
  bound is invocation-local, but wrapper/native-light position, radius, primary
  scene offsets and membership are not thereby pinned. Neither a finite-key
  prepass nor a terminal comparator replay excludes a competing writer.
- Transparent sorting's complete comparator still copies the camera vector
  once per pair and separately resolves center/radius bounds in nonzero mode.
  A numeric tuple avoids later use of a stale cached pointer, but reading an
  equal tuple is not a lifetime/coherence guarantee for the current dereferences.
  Any key adapter additionally needs its exact x87 store/pop/control/exception
  and diagnostic-address proof. No such production adapter is represented by
  the prospective integer patches above.
- Compound child dispatch still reaches concrete culler-state mutation:
  `0x00B5F9B0` clears +0xC0 at `0x00B5FB8F`/`0x00B5FC88` and destroys its
  local compound at `0x00B5FCA0`. `0x00C46F60` restores mode +0x90 at
  `0x00C47135`; that is not restoration of +0xC0 or backing arrays.
  These are reachable native behaviors, not proof that they execute inside
  the owner's particular snapshot bracket. Packed rejection must additionally
  handle allocation order: native recovery can call engine owners, while
  Psycho's failed allocation can reclaim owned storage, retry, sleep and finally
  return null. Moving a fallible allocation after mask mutation cannot obtain
  success from a header check. The local loop reductions leave that order intact.

For the five broader rows, the exact missing evidence remains the relevant
receiver's lifetime and scheduler exclusion over its altered read/relink
interval, or a redesigned intervention that preserves those original intervals.
The AABB row also needs its plane-input interval; the numeric/control and
provider/adapter requirements in the earlier table remain explicit. Known
writers plus a caller list do not prove that interval. Arbitrary installed
providers cannot inherit the supported executable's purity by resemblance.
Those designs cannot honestly be marked implementation-ready on this evidence.
The existing
[`NativeRange` admission](../psycho-engine-fixes/src/mods/perf/lighting_contract.rs)
explicitly separates matching code bytes from object lifetime and concurrent
writer exclusion. Adding more byte ranges does not close these data-ownership
gaps. The available xNVSE `NiCullingProcess` declaration supplies layout and
dispatch names, not a scheduler/lifetime contract for the additional compound
state; it cannot supply the missing proof either.

Receiver-specific provenance also remains necessary for plane publishers.
The current direct-call map has 17 calls to `0x00A694A0` and six to
`0x00C47980`; those counts do not identify a common receiver or exclusive
scheduler. The complete `0x00C4F070` entry assigns camera +0x0C, invokes
`0x00A694A0` at `0x00C4F0C1`, and may call the accumulator's virtual +0x8C
with that camera at `0x00C4F168` before root dispatch at `0x00C4F171`.
It has no enclosing ownership lock. That callback prevents treating the whole
entry as pure; its position before the root does not itself prove a mutation
during an AABB predicate. The raw capture preserves both distinctions.

Two publisher receivers now have a more specific contract. In
`0x00B9C020`, the calls at `0x00B9CAF7` and `0x00B9CB26` both target one
invocation-local stack culler, rather than fetching a persistent global culler.
Taking S as ESP after constructor `0x00B9CAD2` returns, the object is S+0x144;
the camera stores at S+0x150 update its +0x0C before each call. Each argument
push precedes `LEA ECX,[ESP+0x148]`, resolving to that same object. The
resulting plane/mask block at S+0x170 is copied as 25 DWORDs into S+0x1D4 and
S+0x23C at `0x00B9CB0F` and `0x00B9CB3E`. This closes the receiver
provenance for those two writer sites and separates their private output
buffers from the unresolved render culler inputs. It does not establish
ownership or scheduler exclusion for the other 15 publisher contexts.

The four local reductions above have closed native intervention contracts
without assuming that the five ownership questions have been answered.

The first batch's completion does not mean the Fairfax bottleneck is identified
or that all five deeper designs are ready. Its concrete deliverable is a
bounded local reduction whose native intervention contract is already proven;
the table defines the next research for further reductions.

## Implementation plan: complete remaining optimization set

This plan covers the four newly closed local reductions across six native
sites and all five broader optimization families. It preserves the existing
score-reuse, sequential-scan, AABB setup and vertex-setup implementations.
The owner subsequently approved implementation of the named six-site local
batch and explicitly requested default-on configuration; its implemented
contract is recorded below. The five broader packages retain their individual
research gates. Explicit user values continue to take precedence. Packaging,
installation and commits are outside this implementation authorization.

The supported executable identity is recorded in
[Executable identity and evidence interpretation](#executable-identity-and-evidence-interpretation).
The [six-site contracts](#loop-reductions-that-preserve-native-read-schedules),
[deferred-contract table](#deferred-optimizations-exact-research-needed) and
[raw continuation evidence](../analysis/radare2/output/fnv_loop_optimization_continuation_20261010.txt)
are the implementation inputs. Matching instruction bytes is code admission,
not proof of object lifetime, exclusion, runtime acceptance or FPS attribution.

### Scope, files and delivery order

Each row is independently owned. A blocked broader design does not block the
closed local batch, and a successful local batch does not qualify the others.
The first batch introduces no retained-input interval. The remaining numbered
packages define independent research and implementation sequences, without
evidence of their relative frame-time impact. Rows 2 through 6 can proceed
only after their individual contracts close.

| Order | Work package | Core production owner | Configuration | Current entry condition |
|---|---|---|---|---|
| 1 | Mask-save/restore forwarding, redundant sphere/plane comparison and three program-index reductions | Implemented `perf/multibound_loop_bookkeeping.rs` | `performance.multibound_loop_bookkeeping`, default true | Native and compiled code contracts qualified; owner log confirms installation and subsequent session activity; native visibility, failure recovery and timing remain unverified |
| 2 | One-walk dirty-pass refresh, then shared enumeration across qualified passes | New `perf/lighting_pass_refresh.rs` | New `performance.lighting_pass_refresh`, default true when implemented | List, eligibility, output ownership and exact adapter still unresolved; sharing also needs a longer interval and stack proof |
| 3 | Full stable lighting-property merge sort | Extend existing `perf/light_property_scores.rs` | Existing `performance.light_property_score_reuse` | Shared score/input/list exclusion and terminal native math state still unresolved |
| 4 | Stronger AABB plane testing using generated extrema and terminal corner replay | New `perf/multibound_plane_tests.rs` | New `performance.multibound_plane_tests`, default true when implemented | Plane lifetime/exclusion, provider capability and original-frame state adapter still unresolved |
| 5 | Transparent merge-head numeric reuse | New `perf/transparent_pass_sort.rs` | New `performance.transparent_pass_sort`, default true when implemented | Current operand lifetime/coherence and exact mixed-path x87 adapter still unresolved |
| 6 | Compound snapshot allocation removal: rejected-object packing and separately qualified accepted-object local storage | New `perf/compound_frustum_culling.rs` | New `performance.compound_frustum_culling`, default true when implemented | Allocation ordering, current restoration target, callback ownership and recursion/storage contracts still unresolved |

These are proposed module and setting names, except the existing score owner
and setting. Add each new field/module only with its implemented operation;
do not publish empty settings for gated designs. No helper, Syringe, OMV,
allocator, third-party mod or shared-library redesign is part of this plan.

### 1. Six-site native loop bookkeeping

**Production changes.** Add one focused module with six immutable
`OwnedCodePatch` descriptors, 12 immutable `CodeSignature` descriptors and one
installation entry point. Use the exact supported prefix/window/suffix
partitions retained in the raw evidence. Do not derive expected bytes from the
running process or substitute nine-byte frame checks for complete ownership.

| Patch owner | Owned window, exclusive end | Replacement layout | Required native continuation |
|---|---|---|---|
| Save `0x00C49050` | `0x00C490CD..0x00C490F6` | 32 useful bytes and nine unreachable NOPs | Backedge `0x00C490A5` |
| Restore `0x00C49100` | `0x00C4914E..0x00C49177` | 32 useful bytes and nine unreachable NOPs | Backedge `0x00C49126` |
| Sphere/plane `0x00C4A790` | `0x00C4A801..0x00C4A807` | Two-byte jump and four unreachable NOPs | `0x00C4A807`; predecessor equality gate remains intact |
| Bound program `0x00C491A0` | `0x00C49277..0x00C492C7` | 68 useful bytes and 12 unreachable NOPs | All five researched exits |
| Shape program `0x00C493A0` | `0x00C4940D..0x00C49460` | 71 useful bytes and 12 unreachable NOPs | All five researched exits |
| Portal program `0x00C49560` | `0x00C495C0..0x00C49613` | 71 useful bytes and 12 unreachable NOPs | All five researched exits |

Preflight every complete native entry-to-window prefix, every
window-end-to-return suffix, and every patch window before the first write.
The 18 checks cover 1839 distinct native bytes. `OwnedCodePatch::verify()`
admits its exact original or exact researched replacement; other owner bytes
must remain native. Application still performs its existing window checks.

Apply all six windows through one independent `ModificationTransaction` at
the established quiescent pre-CRT boundary. Equivalent existing replacements
remain unowned. On failure, restore only writes acquired by this transaction
through the existing best-effort rollback; report any restoration failure
honestly. Never restore another feature's bytes or overwrite foreign code.
Reject a changed owner before installation, leaving its installed path intact.

**Native invariants.** Forward only uninterrupted private-frame values. Keep
every native engine-memory read/write in its original order, all outgoing
registers and flags, private stores, signed loop bounds, calls, arguments,
stack positions and return cleanup. The program patches must still make all
three separate array/tag reads; they do not cache engine tags. The sphere
patch depends on the complete native predecessor gate, including its single
incoming equality branch. Allocator calls, child dispatch, x87 work and engine
data lifetime are unchanged.

**Integration.** Reexport `install_multibound_loop_bookkeeping` from
`perf/mod.rs`. Call it in `startup.rs` after the existing vertex-setup installer,
without moving earlier preparation. Add the boolean at the end of the
existing performance configuration fields and corresponding raw optional
fields; parse absent values through the established default path. Preserve
the inert legacy radio field. Add the shipped TOML entry with this comment:

> Reduces repeated bookkeeping when testing visibility through portals.

No DeferredInit event handler, readiness atomic, new bridge, allocation,
locking, guard scan or logging is needed in the optimized native operation.
Use the established logger for cold installation/configuration status with
the stable tag `[MULTIBOUND_LOOPS]`; a recoverable rejection must say that the
existing code remains active. Document native ABI, admission, ownership and
rollback limitations in the module.

**Qualification.** Decode the actual compiled descriptor payloads at their
native addresses and compare every branch/state/access schedule with the
retained evidence. Check complete signature partitions and transaction
ownership through the actual production mechanisms where executable offline.
These checks qualify code and installation contracts, not gameplay behavior.
No mirrored native loop or config-value assertion is an acceptance test.

The deterministic saving remains three instructions and three private-local
reads per reached save/restore record block; one instruction and one read per
reached repeated-comparison gate; and two instructions/one read for each
reached second or third program tag check. No per-call guard cost is added.
The acceptance authority and supported build checks in the common section
below remain necessary before this separate batch is implemented or accepted.

### 2. Dirty-pass refresh: narrow operation before shared enumeration

**First implementation target.** Own only the no-growth branch
`0x00BB4F7A..0x00BB500A` within `0x00BB4740`. Admit the full DWORD property
count N only when N <= 254 and the byte capacity C >= N+1. Retain native
`0x00B70600`/`0x00B70700` filtering, order and null handling. Preserve
slot zero, current pass mask, output pointers and active count, including count
one for an empty eligible list. The slot-zero and count publications remain
at their qualified native boundaries (`0x00BB4FD8` and `0x00BB5007`).

Replace count-then-fill with one actual eligibility walk writing the already
sufficient output array. Do not retain a scene pointer list across passes in
this stage. Growth, overflow and the separate shadow/pass branches keep their
native operation. Qualification must occur before an output write; a later
failure cannot restart an already-published pass without an exact continuation
contract. The exact detour/adapter is not yet selected by this branch interval.

**Research deliverable before editing.** Prove receiver-specific scheduler
exclusion and lifetime for property nodes, wrappers, native lights and the
output allocation over this one-walk interval. Trace membership roots
`0x00B5B260`/`0x00B5B410`, insertion `0x00B71560`, marker `0x00B718B0`
and unlink `0x00B71600`; close the separate eligibility writers of wrapper
WORD +0x110, wrapper BYTE +0xEC and native APP_CULLED. Their known writer
routes are listed in [Broader reuse designs](#broader-reuse-designs-ownership-remains-a-prerequisite).
Qualify the nonaliasing live pass array through the actual allocation/birth/
retirement routes at `0x00BA8C00`, `0x00BA8EC0` and `0x00BA9520`, including
installed providers. Produce complete incoming-edge, caller-frame, live-state
and fallback contracts for the proposed adapter. Pool locks and header checks
are not substitutes for these results.

**Second implementation target.** After separate longer-interval qualification,
extend this module to the `0x00BB4F40..0x00BB50AD` refresh loop. Its proposed
eight-byte entry window is a research input, not an approved detour. Use one
private 254-pointer/1016-byte array gathered by the native iterators, and reuse
it only across qualified already-sized passes `0x17F..0x1BA`. Preserve every
output copy and count publication. A 255th eligible light selects the native
modulo-count route; there is no truncation. The total property count and
eligible count are distinct.

End the gathered interval before any growth/free/allocation or unqualified
provider call. Keep fresh native enumeration after allocation; gather again
only at a proven resumption point. When earlier passes have already been
published, resume the current and remaining native passes without replaying
completed work. Keep branches `0x1BD..0x1C3` and `0x1C4..0x1C7` native until
their own invalidation contracts close. Prove the complete compiled scratch
frame, recursion bound, output aliasing and pointer lifetime before sharing.

**Qualification target.** Actual arrays, slot zero, count/capacity, filter order,
dirty/key behavior and growth/fallback results must match native output. The
first stage removes one of two eligibility walks for an admitted pass. The
second gathers once per qualified interval while retaining required output
writes. Include admission and gather/copy costs; neither stage is O(1) refresh.

### 3. Full lighting-property sort without a second hook layer

**Production design.** Extend `light_property_scores.rs` using its three
existing caller hooks at `0x00B6823E`, `0x00BB4F0E` and `0x00C06075` and
their captured providers. Retain the current score-reuse/ordered-prefix
operation until the replacement's complete admission closes. No new setting,
engine-wide scorer hook or allocation per property is required.

For the qualified ordinary-key domain, invoke actual scorer `0x00B9DBE0`
once per node in original node order, using wrapper +0x0C as the native scratch
output. Admit the sufficient finite-result domain before the first score write,
not merely finite input bits. Preserve an already ordered list without changing
links. Otherwise use an allocation-free stable bottom-up merge of existing
nodes, with checked run-width arithmetic and constant private working state.
Maintain previous/next links, head/tail/count/fence/dirty state; clear property
+0x38 exactly on the native order-changing condition. Equal keys, including
signed zero, retain original node identities and order.

**Research deliverable before editing.** Close lifetime and writer exclusion
for every participating node, wrapper +0x0C, native-light position/radius and
scene score inputs in all three caller contexts. The concrete marker/insert/
unlink and transform routes already found require scheduler and receiver
provenance, not another list-header prewalk. The node-pool and accumulator
+0x200 locks protect different intervals/objects. Qualify finite-domain
admission, fence semantics, native score stores and the exact terminal native
comparison replay, including x87 control/tag/sticky/condition state and
instruction/data addresses. No separately assembled production terminal
adapter has yet passed this contract.

Fallback to the captured provider must precede score writes and relinking.
Never discover an unsupported computed key after mutation and restart the
native sort. Preserve native exceptional-domain behavior through fallback;
do not impose `total_cmp` ordering or substitute Rust score arithmetic.

**Qualification target.** Actual native node order/identity and every list/cache
field, score side effect and qualified FP environment must agree for ordered,
reverse, equal-key and exceptional-domain cases. The conditional worst-case
comparison/link budget becomes O(n log n), with O(n) ordered-input work and
one score per node plus at most one qualified terminal replay. Count admission
cost. Select no small-list threshold without actual executable operation costs.

### 4. Stronger AABB plane operation with independent ownership

**Production design.** Add `multibound_plane_tests.rs`; keep the two existing
`multibound_frustum.rs` setup patches and their setting independent. The new
target is the native AABB +0x9C operation `0x00C387F0`, after corner generation
at `0x00C38866`. Use the generated buffer at [EBP-0x68], preserving the native
frame and original side-call instruction `0x00C388E8` to `0x0049DA80`.
An admission helper must return before the call with the original argument
locations. Do not regenerate corners on fallback.

Validate the actual Cartesian pattern and the native odd-index-only zero-Z
subset. Apply the recorded sufficient zero/finite-normal coordinate and plane
domain, absolute values [2^-30, 2^30], control word 0x027F, empty valid x87
stack without stack fault, and precision exception already sticky after corner
generation. Select the eligible generated corner maximizing the exact native
rounded expression by integer ordering. Finish each visited plane with the
native corner-7 call whenever it differs from the selected corner. Preserve
plane order, active masks, Boolean result and complete observable FP state.
Unsupported geometry, arithmetic, state or provider uses the original loop
on the already-generated buffer.

**Research deliverable before editing.** Close the actual plane-input interval
for inline culler +0x2C, compound base +0x30 and record/array-backed inputs,
including their publishers and installed providers. The two private stack
cullers in `0x00B9C020` settle only those receiver instances. They do not
settle the other publisher contexts or the render culler. Qualify complete
incoming edges, live registers/locals, admission-state capture/restore and
original-frame bridge, including terminal x87 instruction/data addresses.
Establish actual helper capability and account for per-call admission cost.

The earlier Boolean early-exit proposal remains a separate conditional branch
of this family. It must satisfy the same omitted-FP-effects and terminal
corner contract; Boolean equivalence alone does not qualify it. If admitted,
implement it through this owner rather than adding another layer on the same
loop. It is not an automatic fallback for unqualified arithmetic or ownership.
The +0xA0 companion keeps its existing setup optimization; broader plane-loop
coverage there needs its own complete contract before extension.

**Qualification target.** Actual native visibility and FP results agree for
all admitted masks, boundary/degenerate/cancellation cases and unsupported
fallbacks. The extrema design targets one or two native side calls per active
plane rather than eight, or four in the odd-only branch. Guard cost and domain
coverage remain unmeasured; the work reduction is not an FPS estimate.

### 5. Transparent sorting with current numeric inputs

**Production design.** Add `transparent_pass_sort.rs` and capture the providers
of sorter calls `0x00B99A31` and `0x00B99A41` through the established callsite
abstraction. Preserve the native two-group wrapper, camera/mode publication,
group order and thiscall/RET-4 sorter ABI, including its cdecl comparator
argument. Unknown providers retain their complete operation.

Keep the actual native stable merge schedule, links, head/tail and spare
cleanup `0x00B63E90` before key retention. Hold two numeric key/input tuples
only for the current merge pair. Replace a tuple when its head advances;
discard both at the next pair or return. At every comparison, read mode once
and camera components once for both current operands. Resolve current geometry
and +0x20 bounds with the native null substitute `0x011F4288`. Nonzero mode
must retain separate center and radius bound reads.

Compare current mode/camera/center/radius bits with the retained numeric tuple;
recalculate on any change. Never dereference a previous bound identity to
validate reuse. Implement exact comparator `0x00B98B20` x87 arithmetic,
Y/X/Z order, f32 rounding, radius subtraction and the compare/pop tail at
`0x00B98C3B`. If a pair cannot qualify, discard its reuse state and execute
the exact native comparator for that pair without restarting the sort.

**Research deliverable before editing.** Prove current node/geometry/bound
lifetime and coherent current reads for both modes, following the concrete
transform writer routes. Qualify the actual key adapter and mixed cached/native
comparisons, x87 control/tag/sticky/condition state and diagnostic FP addresses.
Retain native cleanup and comparison decisions for exceptional inputs.
Equal input bits alone do not prove these state or lifetime conditions.
Inspect actual guard-load/branch costs before accepting the adapter design.

**Qualification target.** Actual stable pass identities, node links, cleanup,
two-group results and caller FP state agree in both modes, including changed
inputs and fallback pairs. With unchanged admitted inputs, c comparisons in
one merge pair need at most c+1 key evaluations rather than 2c. A one-comparison
pair saves none; changed inputs can require 2c evaluations plus guards. This
design does not promise one key evaluation per node for the entire sort.

### 6. Compound snapshots: separate rejection from accepted callbacks

**Production design.** Add `compound_frustum_culling.rs` around the native
save/predicate/child/restore bracket in `0x00C4EE90`, preserving its thiscall,
one-object-argument, RET-4 void ABI and ordinary/direct/mode routes. Two storage
designs remain conditional alternatives with separate admission. Neither may
replay the predicate after mask mutation or replace an allocator's recovery
semantics by a guessed capacity check.

For packed rejection, initially admit the recorded stable domain
`1 <= Q <= 4` and `0 <= L <= Q-1`, where Q is signed capacity and L is record
count. Exactly L+1 snapshot words are initialized. The general stable positive
nonoverflowing formula is `1 + min(L, Q-1)`; broader count admission needs its
own qualified bounds. Capacity is not initialized length. Read no unused tail.
Require the upper 26 bits of each saved mask to be zero before mutation. Four
six-bit masks plus a two-bit initialized-count-minus-one fit in one DWORD.
Use the recorded dead native locals [EBP-0x04]/[EBP-0x08]; a temporary helper
must return before the unchanged predicate call `0x00C4F015`.

A qualified rejected object restores its saved masks without heap allocation
or child dispatch. An accepted object reconstructs a real native snapshot
before child +0xD4 dispatch at `0x00C4F021` and retains native restore/free.
Restoration must resolve the actual current culler +0xC0, rather than restore
an entry pointer. The recorded windows `0x00C4EFF7..0x00C4F005` and
`0x00C4F035..0x00C4F047` still need complete incoming-edge and compiled bridge
qualification; their addresses alone are not installation authority.

**Allocation research gate.** Before moving a fallible allocation past mask
mutation, prove pre-mutation admission of an infallible route through the actual
installed getter/allocator for the whole predicate interval, with its cold,
recovery, failure and FP behavior. Native growth can reach engine recovery
`0x00866A90`. Psycho's opaque dummy heap identity does not expose native heap
capacity; reclaim/retry/sleep can still return null. A config enum or non-null
heap identity proves neither layout nor success. If the installed provider
cannot supply the required ordering contract, redesign the intervention or
retain original ordering; do not ship the deferred-allocation path for it.

**Accepted-object local target.** Independently qualify a per-invocation
16-byte/four-DWORD snapshot through the actual child, accumulator and shader
callback chain. Save only native initialized words and restore exactly the
qualified consumed indices of the current culler. Use a separate private
restore that cannot pass a stack pointer to `0x00C49100`, because that native
operation frees its argument. Reentrant children must own distinct frames;
larger or unsupported cases keep complete native snapshots.

This stronger target needs stable capacity/count/backing storage and current
+0xC0 ownership through child callbacks, structural replacement/retirement
coverage, the complete compiled recursive frame budget and native normal/
exceptional exit behavior. Mode +0x90 restoration is not restoration of
+0xC0. Rust RAII does not establish native SEH cleanup. Accepted callbacks
keep original heap snapshots until this separate contract closes.

**Qualification target.** Native child admission and parent/child mask results
agree for rejection, acceptance, recursive callbacks, partial initialized
prefixes and original-provider/larger-capacity paths. Packed rejection removes
one allocation/free pair for admitted rejected objects; accepted reconstruction
still allocates and adds packing cost. Fully qualified local storage removes
the pair on its admitted accepted route as well. Count every metadata/mask
guard and reconstruction operation; neither design is implementation-ready yet.

### Common integration, composition and qualification

**Feature composition.** Use an independent transaction and setting for each
new owner. Extending the score sorter reuses its existing hooks and setting.
Never double-hook a call, change a provider already installed at another
boundary, or rollback a previously installed feature after a new one fails.
No module-name/version detection or wildcard native-byte admission is planned.

The local batch changes the bound-program `0x00C491A0` and sphere helper
`0x00C4A790` bodies used by the later compound predicate proof. That later
admission must explicitly qualify both native bodies and these exact known
state-preserving replacements; rejecting them silently would lose combined
coverage. Prepare immutable expectations for the selected qualified variants,
not a copy of whatever bytes happen to be installed. A later feature that
actually changes a local batch's owner requires a new composed body contract
and defined installation order before both can be enabled.

The planned dirty-refresh interval starts after the score hook. The existing
score caller-1 contract spans `0x00BB4EDA..0x00BB4F13` (57 bytes), ending before
either proposed refresh interval. Their current code admission therefore has
no byte overlap; future wider adapters must recheck this boundary. Dirty refresh
must still preserve the preceding sort and its resulting native order.
The stronger AABB loop is separate from the existing setup windows at
`0x00C387FF` and `0x00C3892F`. Qualify the new operation with the exact
existing setup replacement where its complete-body admission includes it.
Keep native and combined supported variants explicit; do not relax unknown
provider admission to make settings appear active.

**Configuration and lifecycle.** Append implemented boolean/raw optional fields
without reordering established fields or removing compatibility-only storage.
Use existing absent-value parsing and preserve explicit false values. Default
new implemented features on. Keep user comments to their purpose, for example
one eligibility walk, fewer light-order searches, fewer visibility calculations,
reused transparent-depth calculations or fewer temporary visibility snapshots.
No runtime-testing, restart or research-status instructions belong in TOML.
Do not add tests that freeze config values.

`perf/mod.rs` owns module exports and only event forwarding genuinely needed
by an implemented bridge. `startup.rs` prepares new ownership at the existing
pre-CRT barrier; bridge readiness may publish through existing DeferredInit
routing where its proved contract requires it. No executable writes move to
gameplay/DeferredInit and no dynamic unpatching is planned. Retain established
startup order, logger ownership and core/helper boundary. Hot paths add no
routine allocation, blocking lock, file I/O or diagnostics.
Retain each native update/dirty/visibility gate. Do not add periodic scans or
assume every candidate executes on every frame in the reported location.

**Acceptance before production edits.** Define the actual shipped behavioral
boundary for each package and the applicable repository gate. The closed
six-site contract removes its native research prerequisite; it does not create
a blanket static-only exception for Psycho. Earlier approval of named
candidates does not automatically authorize a new batch or waive its behavior
or startup gate. Where behavior can execute offline, test the actual production
operation with evidence-backed inputs. A native code mapping can exercise patch
admission/ownership but is not an engine gameplay or performance oracle.
Do not substitute a reconstructed loop, mirrored sort, guessed engine fixture,
source assertion, logs or successful compilation for native acceptance.

If the owner explicitly authorizes a scoped unreleased static candidate, record
that authority and its scope separately from proof and acceptance. Such an
authorization does not close any ownership, arithmetic, ABI, provider or
failure-order gap. Preserve the exact last startup-accepted baseline and review
only this package's concrete pre-Deferred delta under
[startup safety](nvse_startup_phase_safety.md). Config layout, new static
descriptors and hook preparation are part of that delta even without TLS or
new dependencies. Required Proton startup acceptance remains a separate gate;
this plan requests no profiling or debug build and reports no new runtime result.

**Implementation checks.** For each independently reviewable package, qualify
actual compiled patch/bridge bytes, incoming and outgoing control flow, ABI,
state, fallback and transaction ownership against its closed contracts. Run
applicable production-path checks and the affected core/helper suites using
`--target i686-pc-windows-gnu`, then one affected core/helper release build with
that explicit target. Run formatting and `git diff --check`, and inspect the
final scoped diff. Do not rebuild unrelated OMV or generate source-presence,
symbol, mirrored-formula or config-default tests for this work.

Keep the owning sections and raw evidence current as each material contract
closes. Record deterministic saved work and total added admission/fallback
cost; use executable benchmarks only where the real production operation can
run. Static instruction counts do not establish elapsed time or an FPS gain.
Mark native behavior, startup and performance as unverified until their actual
boundaries have evidence. No commit, deployment, packaging or release follows
automatically from planning, compilation or prospective binary qualification.

## Implemented candidate: six-site native loop bookkeeping

The owner approved proceeding with this named implementation plan in the
static-only research session and explicitly requested enabled-by-default
configuration for Psycho Engine Fixes. This authorizes the local unreleased
candidate; it does not supply the five broader designs' missing contracts or
establish native behavior, startup safety or a performance result.

The core implementation is
[multibound_loop_bookkeeping.rs](../psycho-engine-fixes/src/mods/perf/multibound_loop_bookkeeping.rs).
It installs exactly the six windows recorded in the
[local loop contracts](#loop-reductions-that-preserve-native-read-schedules).
The new `performance.multibound_loop_bookkeeping` switch defaults to true in
the core and shipped configuration. Existing files without the key use the
default; an explicit false is preserved. No config-value test was added.

### Ownership, native behavior and failure containment

Twelve immutable full-owner prefix/suffix signatures plus six exact unmasked
window descriptors cover all 1839 native owner bytes before installation.
Frame setup, predecessor gates, branch sources, local setup, remaining calls
and returns must match the supported executable. Each owned window accepts
only its original bytes or this exact replacement. The sphere prefix includes
the full equality gate on which the redundant-comparison removal depends.
The running process is never used to learn an expected provider body.

All 18 preflights precede application. One independent
`ModificationTransaction` then applies save, restore, sphere, bound, shape and
portal windows in that order. Exact existing replacements are unowned. An
application error drops the uncommitted transaction and attempts restoration
of acquired writes; failed restoration is reported by the shared logger.
Rollback remains best-effort and never overwrites a foreign replacement.
Successful patches have process lifetime and no dynamic unpatching.

Installation requires the existing pre-CRT barrier and unfinished core
initialization. `startup.rs` calls this group after the existing vertex-setup
group, without moving earlier work. No DeferredInit admission/event work,
native data prewalk, reference mutation, TLS owner, new import/API, dependency,
worker or third-party intervention is introduced. The new config boolean,
read-only descriptors, cold verification/transaction work and log messages
are nevertheless a pre-Deferred startup delta. An unaccepted parent artifact
does not become an accepted startup baseline through compilation.

Installed windows retain the native frames, arguments, return cleanup,
outgoing registers/flags, private stores, engine-memory access sequence and
all call sites. Save/restore still reread their signed loop metadata and use
the same allocator/free order. Each program dispatcher still reads its current
array and tag separately at all three stages. No input is retained across a
callback, and no floating point instruction is changed. There is no new
gameplay-time bridge, capability scan, lock, allocation or diagnostic cost.

Cold status uses `[MULTIBOUND_LOOPS]` through the established logger. Success
reports six optimized sites; disabled configuration reports that state;
preflight/application failure reports the stopped installation and its reason.
These messages describe installation, not a measurement of executed savings.

### Static qualification and limits

The [implementation evidence](../analysis/radare2/output/fnv_loop_bookkeeping_implementation_contract_20261010.txt)
retains complete radare2 MCP owner-byte reconfirmation, exact compiled
descriptor slices, native-destination payload decoding and the complete
compiled installer. The supported executable identity was reverified; all
prefix/window/suffix partitions match the retained native bodies.

The actual compiled descriptors contain the qualified original and replacement
bytes, correct native addresses/lengths and no masks. Decoding the compiled
payloads confirms both backedges, the equality-gate continuation and all five
exits of each program block: 18 outgoing branches in total. Every NOP tail is
unreachable. The compiled installer checks all 12 owner signatures and six
windows before its first application, applies all six before committing and
drops the transaction on application failure.

The deterministic instruction/read reductions remain those recorded in the
local contract: three of each per reached save/restore record block, one of
each per reached repeated-comparison gate, and two instructions/one read per
reached second or third program tag check. These counts describe redundant
native work removed, not execution frequency, elapsed time or FPS gain.

The existing supported-target core/helper suites and their 32-bit release build
passed. Formatting of the affected files and scoped diff checks passed. The
workspace-wide formatting check reported an unrelated OMV change; that file
was preserved. No mirrored-loop, synthetic engine, source-presence or
config-default regression was added.

At implementation qualification this was an unreleased static-qualified
candidate. Native startup, installation, visibility/mask behavior, failure
recovery and timing had not been exercised by the agent. Existing
crate tests and compiled-contract checks do not substitute for those boundaries.
The five broader packages remain gated by their specific lifetime, exclusion,
arithmetic, provider, recovery-order and stack contracts. No deployment,
packaging or release is implied by this qualification.

### Owner session evidence after implementation

The owner's later game log confirms the three vertex-setup sites and all six
bookkeeping sites installed at `2026-10-10T20:47:42.698Z`. Both existing lighting
candidates were admitted at DeferredInit at `20:48:07.700Z`. Subsequent engine
activity is logged through `20:52:03.703Z`. Exact bounded log excerpts are
preserved with the
[bookkeeping implementation evidence](../analysis/radare2/output/fnv_loop_bookkeeping_implementation_contract_20261010.txt).

This supplies actual installation and continued-session evidence. No feature
installation failure or rejection was logged. It does not establish execution
frequency, full visibility/mask equivalence, fallback recovery, performance or
the absence of a silent per-operation lighting fallback. No FPS result is
derived from these messages. The separate streetlight report below remains
unresolved. The owner subsequently requested a source commit of these
optimizations and their evidence; that request does not supply missing native
behavior or authorize packaging or release.

## Streetlight on/off regression audit

The owner reports that streetlights appear on across locations, including both
the glowing fixture and the illumination cast on the ground. This observation
does not yet include an affected reference ID, a daytime hour, winning plugin
records, controller state, or a same-scene comparison with the two lighting
optimizations disabled. It establishes a symptom to investigate, not attribution
to Psycho or proof that every observed fixture has a day/night controller.

**Current result:** no regression in the inspected lighting-patch instructions
has been established. The native on/off consumers, light culling gates, dimmer
reads and visibility-transition dirtying remain outside the replaced work.
This is a bounded static finding; it does not establish correct streetlight
behavior in the owner's running game. No production fix or configuration
change is justified by the evidence collected so far.

The executable identity above was rechecked before the address-sensitive audit.
New primary captures and a targeted installed-data extraction are retained in
[streetlight state evidence](../analysis/radare2/output/fnv_streetlight_state_regression_audit_20261010.txt).
Existing complete updater and scan captures remain authoritative for the larger
functions. Tool variable names are not used as stack offsets.

### Actual boundaries inspected

| Boundary | Direct evidence | Result and limit |
|---|---|---|
| Property score reuse | Native sorter `0x00B70390`, scorer `0x00B9DBE0`, and the production private sorter | The scorer writes wrapper score `+0x0C`; sorter mutations are list links/head/tail and conditional property key `+0x38`. The optimization does not write a light dimmer, reference enable state, fixture material emission, or time-of-day value. Shared score/input exclusion remains an existing unresolved condition. |
| Camera sequential scan | Native `0x00B5BE59..0x00B5BE77`, complete camera bytes, four production bridges | Native APP_CULLED testing remains at `0x00B5BE5F`. Native light dimmer `+0xC4` is still read at `0x00B5BEF5`. Neither is replaced with a remembered enabled state. |
| Shadow sequential scan | Native `0x00B9D2CF..0x00B9D2F9` and production getter bridges | Native shadow classification, APP_CULLED and positive-dimmer gates remain after lookup. The patch changes enumeration, not the branch deciding whether the returned light participates. |
| Ordinary property-pass eligibility | Complete native iterator `0x00B70600` | Native wrapper visibility WORD `+0x110`, light APP_CULLED and wrapper shadow BYTE `+0xEC` are still inspected. These iterators are admitted but not replaced by the two candidates. |
| Visibility/fade update | `0x00B5E915` and `0x0087184A` still call `0x00B9E970` | The two lighting candidates do not patch this updater or its callers. Native transition dirtying at `0x00B9EEA9` and publication at `0x00B9EF09..0x00B9EF1C` remain intact. These fields are renderer visibility/fade state, not a universal daytime light switch. |
| Script time and enable/disable commands | Supported command-table entries and native consumers | `GetCurrentTime` executes at `0x005C0DB0` through `0x0059C8E0` and `0x00867DA0`. `Disable` executes at `0x005C45E0` and hands off through `0x005AA500`; `Enable` executes at `0x005C43D0` through `0x005AA5D0`. No reviewed lighting hook owns these boundaries. Complete descendant propagation and the owner's active controller execution were not established by this audit. |

The adjacent AABB and compound/portal setup reductions replace only dead
integer pointer initialization. Their retained plane arithmetic and native
callbacks do not introduce a light-enabled cache. The six-site bookkeeping
candidate likewise preserves engine accesses and callbacks; the current owner
log inspected during this streetlight audit, beginning at `20:18:36Z`, contains
no `[MULTIBOUND_LOOPS]` installation result. Its presence in the worktree was
not proof of activity in that earlier session. The later session above confirms
installation, without resolving the streetlight observation.

### Camera temporary storage recheck

A retained cursor must not overwrite a float that remains live. Exact camera
bytes confirm the existing two-slot design:

- `C+0x64` initially holds an input whose last read precedes the initial bridge.
  Accepted candidates later overwrite it with normalized vector Z, whose last
  read is the direction-dot multiplication at `0x00B5BECC`.
- The first transfer at `0x00B5BE69` saves the cursor into `C+0x30` before
  vector construction. The second at `0x00B5BED2` restores it only after that
  vector-Z read. Brightness first overwrites `C+0x30` at `0x00B5BF4F`.
- APP_CULLED skips both transfers and preserves the cursor in `C+0x64`.
- The candidate output Z load at `0x00B5C013` is exactly
  `MOV EDX,[ESP+0x58]`, not a read of the cursor slot `C+0x64`. The raw
  instruction bytes settle the apparent ambiguity of tool variable labels.
- Native accumulation does not consume the old cursor; the native fallback
  overwrites its vector Z before reading it.

This recheck found no live-float overwrite at these bridges. It does not close
the separately documented scene/node lifetime and concurrent mutation gaps.

### Installed base-data time-of-day policy

The installed physical `Data/FalloutNV.esm` contains the packaged source
`VStreetLightingScript`. Its validated SCTX field is at file offset
`0x0038D41D`; the full source is preserved in the evidence file. It disables
three named Strip starter references when `6 < GetCurrentTime < 20` and
`LightsOn == 1`. At night, outside the Strip, it enables the three groups
and updates its local state; inside the Strip it runs a timed flicker sequence.
The associated trigger starts the quest when it is not already running.

This demonstrates a concrete base-data policy that controls street lighting
through reference groups and script state. It does not prove that all lamps,
including Fallout 3/TTW or mod-added fixtures, use this quest. Nor does packaged
source establish the active compiled script, winning overrides, loaded quest
state or whether this controller ran in the affected save. The source uses
strict hour comparisons, so exactly 06:00 and 20:00 are not suitable points for
an on/off comparison. Its quest delays and flicker sequence also prevent an
instantaneous screenshot from proving persistent failure.

### Evidence needed to distinguish causes

The existing log reports both candidates admitted at
`2026-10-10T20:19:00.880Z`. That timestamp is wall-clock time, not the game
hour. It proves lifecycle admission only: no affected reference, per-invocation
use, dimmer value, controller execution or visual transition is logged.

The narrow causal comparison is the same save, fixture, daytime hour and
rendering settings with only `light_property_score_reuse` and
`scene_light_sequential_scan` changed to `false`. This is an isolation
experiment, not an optimization removal or a proposed fix. If behavior differs,
test the two settings separately to identify the implicated candidate. If it
does not differ, neither candidate is established as the cause; an affected
reference and its active controller/material records become the next required
evidence.

For a controller-backed fixture, the behavioral acceptance boundary is that
its real daytime disable removes both the controlled glow and cast lighting,
and its nighttime enable restores them in the same workload. Distinguish a
reference that remains enabled from one that is disabled while stale rendered
lighting remains visible. The former routes to controller state or reference
propagation; the latter routes to light retirement, dirtying and current-pass
refresh. Neither route may be selected from appearance alone.

The repository's behavioral gate still applies to a Psycho regression fix.
There is no unchanged-game reproduction, controlled candidate comparison or
proven failing native consumer in the current evidence. Production code,
defaults and deployed files remain unchanged by this audit.

## Evidence ledger

| Evidence | Retained content used here | Additional direct binary checks |
|---|---|---|
| [Streetlight state audit](../analysis/radare2/output/fnv_streetlight_state_regression_audit_20261010.txt) | Native score/sort, camera cursor liveness, culling/dimmer gates, visibility publication, command-table consumers and installed base street-light source | Same executable identity rechecked; no patch regression or actual daytime transition established; active records, reference/controller state and controlled comparison remain unknown |
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
| [Fairfax candidate evidence](../analysis/radare2/output/fnv_fairfax_performance_candidates_contract_20261007.txt) | Property-sort prefix, dirty-pass double walks/count width/array allocation, transparent merge-sort comparator and payload/draw lifetime, culler admission, AABB corner loop, compound mask allocation/restore and initial capacity | Same executable identity; radare2 is primary, bounded PE pointer reads establish native vtables, source/provider evidence separates current scrap replacement from native getter cost; actual scene populations and timings remain unknown |
| [Durable optimization design evidence](../analysis/radare2/output/fnv_location_durable_optimization_plan_contract_20261007.txt) | Native corner generation and component-rounding helpers, frustum-array layout, outer culler root dispatch, actual scorer arithmetic and ABI | Same executable identity reverified; corner basis/rounding and callback lifetime prohibit guessed algebraic, arena or full-sort readiness claims |
| [Implementation gap-closure evidence](../analysis/radare2/output/fnv_location_optimization_gap_closure_20261007.txt) | Exact pass frame and continuations, complete iterator/allocator bodies, scorer and CRT finite route, terminal sorter comparisons, transparent cleanup/publication, actual visibility vtables, compound resize/destruction and active-pointer mutation, AABB final comparison and generated buffer | Same executable identity reverified; bounded PE/objdump supplements resolve inferred stack-label ambiguity; incomplete and misaligned captures are explicitly excluded from complete-function proof |
| [Ownership continuation evidence](../analysis/radare2/output/fnv_location_ownership_contract_20261007.txt) | Additional transform routes and recursive writers, property mutation/pool-lock scope, actual accumulator construction and registration slots, complete compound predicate and mask helpers, scene admission flag, native ScrapHeap growth/recovery calls, current comparator input reads and native snapshot frame | Same executable identity reverified; 65 focused MCP captures and bounded PE table reads distinguish complete bodies from prefixes and reject misaligned or adjacent-data discoveries; no worker exclusion or runtime-cost claim is inferred |
| [Remaining-boundary evidence](../analysis/radare2/output/fnv_location_remaining_boundary_contract_20261007.txt) | Complete AABB method/dead-loop and scale-input bodies, original side-call frame, actual RenderPass allocation/retirement, membership caller roots and the diagnostic-function correction; owned allocator source paths are indexed | Same executable identity reverified; 67 native captures plus bounded bytes and separately decoded full-state replacement specify a 64-instruction reduction per admitted AABB call; partial/misaligned discoveries are excluded, and policy qualification remains separate |
| [AABB setup implementation evidence](../analysis/radare2/output/fnv_aabb_setup_implementation_contract_20261007.txt) | Native entry reconfirmation, compiled frame/block descriptors and replacement payloads, native-destination decoding and complete startup installer | Embedded expectations agree with the supported executable and both seven-instruction payloads reach the documented continuations; static qualification does not establish native installation, startup, visibility or timing |
| [Compound/portal setup implementation evidence](../analysis/radare2/output/fnv_compound_vertex_setup_implementation_contract_20261007.txt) | Aligned native reconfirmation, actual compiled frame/block descriptors, three payloads decoded at their native destinations and complete installer | Same supported executable; all six checks precede application and all three continuations agree; actual native startup, visibility, failure recovery and timing remain untested |
| [Deferred ownership follow-up](../analysis/radare2/output/fnv_location_deferred_ownership_followup_20261007.txt) | Actual reassignment roots and scene receiver, distinct synchronized drain and shadow-preparation routes, inline/compound plane publishers, exact snapshot initialized/consumed indices, three redundant four-vertex loops and prospective full-state payloads | Same executable identity reverified after MCP reopening; complete bounded native bodies and corrected terminal extents qualify 32 fewer integer instructions per reached setup block. Misaligned/interior discoveries and clipped output are excluded; proposals have no production installation or runtime attribution |
| [Loop continuation evidence](../analysis/radare2/output/fnv_loop_optimization_continuation_20261010.txt) | Complete mask save/restore, sphere/plane helper and three compound-program bodies; private-local forwarding, repeated-comparison and repeated-index proposals; exact frames/predecessor gate/windows, prospective payload decoding, eligibility writers and callback-state boundaries | Same supported executable; four local reductions across six native sites qualified without moving engine reads/calls or adding retained inputs; five broader reuse ownership designs remain unproved; no production or native behavioral result |
| [Loop-bookkeeping implementation evidence](../analysis/radare2/output/fnv_loop_bookkeeping_implementation_contract_20261010.txt) | Full MCP owner-byte reconfirmation, actual compiled signature/patch slices, six native-destination replacement decodes, shared admission methods and complete production installer | Same supported executable; all 1839 owner bytes covered, six compiled unmasked payloads and 18 outgoing branches agree; all 18 preflights precede application and commit follows the six sites; no native behavioral or performance acceptance |

The original ledger's direct checks are summaries of the initial radare2
session. The native lighting captures preserve the continued audit's raw
tool output. Existing retained text is linked rather than duplicated. The
executable remains the primary source for any address-sensitive follow-up.

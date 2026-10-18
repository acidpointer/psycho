# Runtime visibility injection for unoptimized locations

Research date: 2026-10-17. Status: static feasibility research only. No
production code was changed, no runtime test was run, and no FPS or frame-time
benefit is claimed.

Executable: `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, image base `0x00400000`. Addresses are virtual addresses for this
executable and must be reverified before reuse. The compact address index and
the disassembly excerpts behind this document are in
[the runtime visibility contract](../analysis/radare2/output/fnv_runtime_visibility_injection_contract_20261017.txt).

## Question and short answer

The proposal is to stop chasing draw-call and loop micro-optimizations and
instead give unoptimized locations the visibility data the engine already knows
how to use: room bounds, portals, and occlusion planes.

The engine does have all of those mechanisms, and the installed optimization
mods are built on the premise that adding the missing data to interiors helps;
the AWOP description reports a dramatic impact. That is strong evidence, not a
controlled measurement. The proposal is also not one uniform runtime operation:

- **Occlusion planes are runtime-friendly.** A `BSOcclusionPlane` is a
  standalone native object that is appended to a scene-graph occluder list.
  The list is read every frame by the native visibility pass. Runtime creation
  and insertion are proven feasible; the game even ships a debug console
  command that does exactly that.
- **Room bounds and portals are not runtime-friendly in the same sense.**
  They are content: the engine builds `BSMultiBoundRoom`/`BSPortal` scene
  nodes from cell references and a portal graph at cell load. Runtime
  injection is possible in principle but requires reference/3D lifetime, portal
  graph integration, and a rebuild trigger that this research has not closed.
- **Rooms and portals are interior-oriented.** The installed roombound mods
  cover interiors, and Fairfax Ruins is an exterior. For the exterior the
  relevant native mechanism is the occlusion plane, not the room graph.

So the practical answer is: pursue runtime occlusion-plane injection first,
with offline-generated, conservative per-cell plane data; treat runtime
room/portal injection as a separate, higher-risk project; and verify coverage
before duplicating what installed mods already do. The implementation plan for
that path is in
[runtime occlusion-plane implementation plan](fnv_runtime_occlusion_plane_implementation_plan.md).

## What the engine already provides

### Occlusion planes

`BSOcclusionPlane` is a reference-counted native class of `0xFC` bytes with
vtable `0x101E794`. The constructor at `0x004A5FF0` copies:

| Offset | Meaning |
|---|---|
| `+0x08` | 3-float position |
| `+0x14`, `+0x18` | rectangle half-extent X and Y |
| `+0x1C` | 9-float rotation |
| `+0x40` | admission/active word (constructor writes 0) |
| `+0x44` | cached camera-dependent planes |
| `+0xE4`, `+0xE5` | dirty flags |
| `+0xEA` | constructor sets 1 |

`0x00C35C10` builds the four rectangle corners as `position +/- sizeX *
M*(1,0,0) +/- sizeY * M*(0,0,1)`. The plane is therefore a local **XZ**
rectangle with a local **Y** normal, and the `+0x14`/`+0x18` fields are
half-extents. Generated matrices store columns `(tangent A, normal, tangent B)`;
`0x00C33870` turns the camera and those four corners into the camera-dependent
planes used by the pair predicate.

The engine's authored `XOCP` path uses a different constructor variant:
`0x00AA13E0` allocates `0xFC` bytes, `0x00C335D0` constructs the default plane,
`0x00416A30` sets size, `0x004169F0` sets position, `0x004168A0` builds an
axis-angle rotation matrix and `0x00416A70` stores it. That path also sets the
dirty flags and is the runtime injection path used by this research.

The occluder list lives at `scene_graph + 8`. The scene graph is reached from
the object returned by `0x00450B80(0)` at `+0x1E0`, the same route used by the
main frame and the console command:

- `0x00B5AC90` walks `scene_graph+8` once per frame, tests each plane through
  `0x00C33CF0` and `0x00C358A0`, and writes `+0x40` to 1 (admitted for the
  current camera) or 2 (not admitted).
- `0x00B5BBE0` walks the same list for each camera-admitted bound and calls
  `0x00C47150` only for records whose `+0x40 == 1`, stopping at the first
  rejection.
- `0x00C47150` initializes a 100-byte local frustum through `0x0045C620`,
  obtains camera-dependent planes through `0x00C33870`, and calls the shape's
  virtual slot `+0xA0` for the complete containment predicate. On containment
  it publishes shape result 2 and returns 0 (rejected).
- `0x00C33870` has an existing camera cache: when the plane's dirty byte
  `+0xE5` is clear and the cached camera XYZ at `+0xD8/+0xDC/+0xE0` matches, it
  copies 25 DWORDs from `+0x44` and returns. The expensive reconstruction is
  not repeated per pair.

The list is appended by `0x00C5AE70(scene_graph, plane)`, which obtains a list
node from the native pool (`0x0043A010`), stores the plane at `node+8`, and
inserts through `0x00559A70`. The list does not retain the plane; the node's
free path `0x004A49E0` zeroes `node+8` before freeing. Individual nodes can be
removed by unlinking the tracked node and returning it through the native node
free `0x004A49E0`; the engine's `0x004EDF00` removes only the list tail. A whole
list can be cleared with `0x004ED900`.

The game ships a debug console command that uses this path. The command table
entry at `0x01190340` names `AddOcclusionPlane`, description "Add Occlusion
plane (x size, y size)", function `0x005BB9E0`. It allocates and constructs a
plane from the player/camera transform and appends it to the scene graph. It
has a use-after-free: the plane is wrapped in a stack `NiPointer`, the list does
not retain it, and the smart pointer destroys it at scope exit. Stewie Tweaks
9.95 (`PlaceOcclusionPlaneFix.cpp`) NOPs the release at `0x5BBBA6..0x5BBBAE`,
`0x5BBBB5..0x5BBBBE` and `0x5BBBE4..0x5BBBEC`; the result leaks the plane but
does not crash. That is a useful mechanism test, not a production ownership
pattern.

### Rooms and portals

`BSPortal` is a `BSOcclusionPlane` subclass of `0x108` bytes with vtable
`0x101E82C`; its constructor at `0x004A61F0` calls the plane constructor and
adds room-link fields at `+0xFC`, `+0x100` and the `NiPointer` at `+0x104`.
So portals reuse the same rectangle/frustum primitive and add the two rooms they
connect.

`BSMultiBoundRoom` is a scene node of `0xEC` bytes with vtable `0x10C1064`;
its constructor is `0x00C39640`. The engine builds rooms from references: the
observed build path at `0x00548B10` reads a reference's 3D and bound, allocates
and constructs a room and a portal-graph node, and then calls `0x00439920`,
`0x004ADDC0`, `0x00420F00` and `0x00C5AEF0` (observed registration, bound,
attach and scene-add steps; their exact contracts were not closed). Cell load
resolves the authored reference links in the post-load extra-data fixup around
`0x00417696` (strings "No occlusion plane for occlusion plane ref extra",
"Unable to find portal/room linked reference").

Once built, the room graph feeds the compound-program path already documented
in the location audit: `0x00B5F170` builds room programs, `0x00B5BA80` builds
shared-node programs, and `0x00C4EE90`/`0x00C4EFE0` evaluate them per object
with per-object snapshot/restore.

### Authored spatial data and installed coverage

`XOCP` is a 36-byte payload of nine little-endian floats: `sizeX, sizeY,
posX, posY, posZ, axisX, axisY, angle, axisZ` (axis-angle rotation). `sizeX`
and `sizeY` are native half-extents, as `0x00C35C10` proves. The
reference handler at `0x0041617A` allocates `0xFC` bytes, constructs with
`0x00C335D0`, sets size with `0x00416A30`, position with `0x004169F0`, builds
the rotation matrix with `0x004168A0` and stores it with `0x00416A70`. `XPOD`
is an 8-byte pair of room reference form IDs. `XMBO`/`XPRM` carry the
bound/primitive shapes used by rooms, portals and occluders.

The audit's record inspection found that the seven Fairfax exterior groups
(`0x06001163`..`0x06001175` in `Fallout3.esm`) contain **no** `XMBO`, `XPRM`,
`XMBR`, `XRMR`, `XPOD`, `XPTL` or `XOCP` subrecords. The two Fairfax interiors
(`zFairfaxMaintenance`, `zFairfaxMetro`) have only acoustic/sound/trigger/
collision `XMBO`/`XPRM` references in the base masters, not authored rooms.
`bEnableBoundingVolumeOcclusion=1` is set in the inspected Default profile's
`fallout.ini`, so the native occluder path is enabled there.

The installed content-level fixes are substantial:

| Plugin | Coverage | Observed spatial fields |
|---|---|---|
| `FO3_Optimization.esm` | Many FO3 interiors | `XMBO` 3227, `XPRM` 3270, `XPOD` 1541, `XOCP` 239, `XRMR` 217, `XPTL` 37 |
| `FNV_Optimization.esm` | 238 FNV interiors | `XPRM` 3938, `XMBO` 3805, `XPOD` 2003, `XRMR` 186, `XOCP` 93, `XPTL` 21 |
| `AWOP FO3 Roombound Project.esm` | AWOP FO3 interiors | `XMBO` 686, `XPRM` 688, `XPOD` 379, `XPTL` 20 |

The AWOP mod description states explicitly that its interiors were large and
rendered all objects simultaneously, and that comprehensive roombounding "will
have a dramatic impact on performance". `FO3_Optimization.esm` adds five room
markers plus four `XPOD` portals to `zFairfaxMaintenance`, and three plus three
to `zFairfaxMetro`. This is direct evidence that mod authors treated missing
visibility data as a real cost in interiors; it is not a controlled
measurement of the benefit.

The same inspection found no such additions to the Fairfax exterior groups.
That is the gap this proposal targets.

## Why this direction is credible

The existing draw-submission occlusion attempt (the vendored IntelMOC path
documented in `.reports/2026-09-11-occlusion-*`) operated at or near append
submission, after most native preparation, and had admission/coverage problems.
Native occlusion planes operate earlier: rejection happens in `0x00B5BBE0`
during bound classification, before the rejected subtree's later scene
traversal, property/pass dispatch and draw registration. That is exactly the
"reject earlier" direction the previous work did not reach.

It also fits the reported behavior. The owner reports that turning away restores
FPS and that facing back toward the dense direction costs it. That is a
view-dependent cost, which is what visibility admission controls. It does not,
by itself, prove that geometry admission is the dominant consumer.

The engine already pays for a room/portal/occluder system. Adding data to the
existing system reuses native code, native bounds and native early rejection
instead of maintaining a second software depth pipeline.

## Why it is not a drop-in fix

Three limits must stay explicit.

**The pair loop is multiplicative.** For `B` camera-admitted bounds and `O`
active occluders, `0x00B5BBE0` makes up to `B*O` pair calls per frame, each
creating a 100-byte local frustum and copying 25 DWORDs on the plane-cache hit
path. Early rejection stops a hidden bound at the first containing occluder,
but a visible bound tests every active occluder. `O` must be small
(initially a handful per cell) or the culler can cost more than it saves. The
audit already identifies this multiplication as a scaling risk.

**Placement must be conservative.** The pair predicate only rejects a bound
that is fully contained behind the rectangle. A plane that covers a window,
door or gap still culls objects visible through that gap. Planes must sit on
solid, opaque occluder faces and must not extend past the solid silhouette.
Automatic placement is a visibility-design problem, not a single function
call.

**Occlusion planes do not cover everything.** Lighting maintenance runs
earlier in the main frame (`0x00B60040`), and actor workers overlap rendering.
A visibility rejection cannot retroactively remove that work. Shadow casters
and GPU work are separate paths. A perfect occluder result would still leave
those costs. The audit's "What occlusion can and cannot avoid" section remains
the boundary.

There is also an unresolved engine fact: the research did not prove whether the
runtime-added planes survive cell transitions or how to remove only the added
nodes without disturbing authored planes. That lifecycle must be closed before
shipping.

## Options

| Option | Coverage | Effort | Risk | Evidence | Recommendation |
|---|---|---|---|---|---|
| B. Runtime-collected occlusion planes from live cell geometry | Exteriors and non-room interiors | High | Medium | Live ref list, OBND and world transform verified; placement heuristic needs an in-game visual check | Implemented, default-on |
| A. Offline-generated occlusion planes, runtime-injected as `BSOcclusionPlane` | Exteriors and non-room interiors | Medium | Medium | Native mechanism and console command proven; placement unknown | Deferred; no runtime data path |
| C. Generated override plugin with room markers/portals/`XOCP` | Interiors | High | Medium | Installed mods prove the benefit | Use where B cannot help |
| D. Runtime room/portal graph injection | Interiors | Very high | Very high | Constructors known; build/rebuild contract open | Defer |
| E. Native occluder broad-phase/cache optimization | Enables any large `O` | Medium | Medium | `0xC47150`/`0xC33870` cost documented | Only if measurements demand it |
| F. Existing loop/draw and compound optimizations | All | Done/ongoing | Low | Owner reported no visible benefit so far | Keep; combine |

Option B now runs entirely in gameplay: on each target change the module walks
the loaded cell's reference list, selects large `STAT`/`BGSStaticCollection`
objects, checks their loaded geometry for transparency and skinning, and
derives one conservative oriented box per opaque, unskinned geometry from its
uncompressed vertices and live world transform. Each face is fitted inside the
vertices that support it, horizontal ground/roof faces are skipped, and the
resulting plane is one-sided so the engine's camera-side test rejects it from
behind. A silhouette-accurate `NiTriShapeData` extraction was prototyped but is
parked until that in-memory triangle list is verified in game. Geometry with
compressed vertices is skipped rather than approximated from a sphere bound.
Candidates are filtered by size and observer distance and weighted so nearby,
well-supported occluders win the per-cell cap. Static qualification is
complete; in-game visual and performance qualification is not.

### A. Offline-generated occlusion planes with a runtime injector

Generate a per-cell data set offline from the cell's static references and
their NIF geometry, then create the planes at cell load. This is the
recommended first implementation.

- Data source: the cell reference records and the actual NIF meshes
  (the repository already has a minimal BSA/NIF reader in
  `analysis/radare2/fnv_mesh_array_reader.py`; it needs world-transform and
  solid-face extraction).
- Selection: large, opaque, static occluders (building shells, retaining
  walls, large rock faces). Reject meshes with alpha/transparent materials,
  holes, or thin geometry that does not bound a volume.
- Plane generation: for each selected large face, emit a rectangle on the
  solid face, oriented with its normal toward the visible side, sized no larger
  than the solid face (optionally shrunk by a margin), and offset slightly
  toward the occluder to avoid edge cases.
- Data format: cell key (worldspace + grid or interior cell FormID), plane
  list (position, size, rotation or orientation, priority/score). Ship as data
  files, not code, so placement can be updated without rebuilding the DLL.
- Runtime: on cell load, create planes with the native allocator and
  constructor, retain one reference each, append with `0x00C5AE70`, and remove
  its tracked nodes (unlink in Rust, then the native node free `0x004A49E0`) and
  release on cell unload. Never clear the whole list; authored planes must be
  preserved.
- Configuration: enable per-cell, cap the active plane count, and skip cells
  that already have authored visibility data.

Why this is first: it is deterministic, testable offline, independent of load
order, respects mod overrides by using the loaded references, and does not
require a new runtime placement heuristic.

### B. Runtime auto-generated planes from the loaded scene graph

Instead of shipping data, walk the loaded scene graph at cell load, find large
opaque static meshes by world-space bounds, and create conservative planes from
their OBB faces. This adapts to any load order automatically.

- Strength: no offline asset pipeline and no per-cell data maintenance.
- Weakness: bounds are often spheres or axis-aligned boxes around irregular
  meshes; a conservative rectangle from a loose bound is either too small to
  cull or large enough to false-cull. Clustering and per-mesh local bounds are
  required, and the false-cull risk is higher than the offline path.
- Use as a fallback for cells without generated data, or as an experiment, not
  as the first production mechanism.

### C. Generated override plugin for rooms and portals

This is what the installed mods do. Generate a plugin that adds room markers,
`XMBO`/`XPRM` shapes, `XPOD` portals and `XOCP` occlusion planes to cells that
lack them. The engine's own loader, portal graph, compound builder and
serialization then work unchanged.

- Strength: proven content path; no runtime scene-graph surgery; benefits from
  all existing engine validation.
- Weakness: load-order and override management; needs a record writer and
  conflict handling. It is a content patcher, not a runtime feature.
- Use for interiors that remain slow after the installed roombound mods, or
  for cells the installed mods do not cover.

### D. Runtime room/portal graph injection

Call the native room/portal construction path at cell load, before the compound
programs are built, and integrate the new nodes with the portal graph.

- The constructors (`0x00C39640`, `0x004A61F0`), the room build path
  (`0x00548B10`) and the graph-add call (`0x00439920`) are known.
- What is not closed: what triggers a room-graph rebuild, how to attach a
  synthetic reference or 3D, how the portal graph and scene node are retired on
  cell unload, and how to avoid serializing synthetic content. This is a
  high-risk engine change and should wait for the simpler options to be
  measured.

### E. Native occluder broad-phase and cache work

If the data-driven occluder count must grow, the `0xB5BBE0`/`0xC47150` pair
cost becomes the limiter. Candidate reductions already identified by the audit:

- a conservative broad phase that skips occluders whose rectangle does not
  overlap the bound;
- avoiding the 25-DWORD plane copy on the cache-hit path, or sharing a
  per-frame camera-plane array;
- reducing local 100-byte frustum setup where the shape predicate permits it.

These are engine patches with their own ownership/lifetime contracts and are
only worth doing after measurement shows the pair loop is hot.

### F. Keep the existing optimizations

The current loop, sorting, AABB, compound and root-admission changes remove
proven redundant work. They are complementary to a visibility layer: visibility
reduces how many objects reach those paths, and the loop changes reduce the
cost of the objects that remain. There is no reason to remove them.

## Recommended phased plan

The detailed task list, ABI, data format and gates are in the
[implementation plan](fnv_runtime_occlusion_plane_implementation_plan.md); this
section keeps the phase overview.

**Phase 0 - Measure before building.** Add non-behavioral instrumentation at
`0x00B5BBE0` and `0x00B5AC90` (logged through the established logger, gated by
config) to record per cell/frame: admitted bounds, active occluders, pair
calls, early rejections, and rejected bounds. This quantifies the opportunity
without changing behavior. Also capture the exact problem position: cell
EDID/grid, player coordinates, camera direction, installed plugins and
settings.

**Phase 1 - Mechanism proof.** At the reported Fairfax position, with Stewie
Tweaks installed, use `AddOcclusionPlane` to confirm activation and culling, and
build a small test DLL that creates planes at arbitrary position/size/rotation
using the constructor and `0x00C5AE70`. Verify the front-side convention, the
`+0x40` active result, and list removal. This proves the runtime path.

**Phase 2 - Hand-placed Fairfax planes.** Place a small number (4-8) of
conservative planes on the largest solid building/wall faces in the reported
view. Measure a fixed-camera A/B with planes off/on. This is the first real
signal on whether the location's cost is geometry admission.

**Phase 3 - Runtime collection (implemented).** The module now collects planes
from the loaded cell at every cell change: it walks the reference list, selects
large static bound objects, checks their geometry for transparency and
skinning, and emits conservative face rectangles from the authored `OBND` box
and the live world transform. No offline data is required. In-game visual and
performance qualification remains.

**Phase 4 - Interiors.** Compare against the installed FO3/FNV Optimization and
AWOP roombound coverage. For any cell that lacks authored visibility, evaluate
option C (generated override plugin) before option D (runtime room injection).

**Phase 5 - Scale and enabler.** If more planes are needed, add the option E
broad phase, re-measure the pair cost, and only then raise the plane budget.

## Proposed runtime design (option A)

- Location: a new `psycho-engine-fixes` performance module with the existing
  signature/ownership discipline, plus configuration under
  `performance.occlusion_planes`. The per-cell data path was removed; planes
  are generated at runtime.
- Generation: offline tool, not shipped in the DLL; conservative placement with
  a validation pass that rejects any plane that culls a conservatively visible
  object.
- Lifecycle: install at the documented core startup boundary; create planes on
  cell load on the main thread; retain one reference per plane; append with
  `0x00C5AE70`; on cell unload unlink its tracked nodes and free them through
  `0x004A49E0`, then release; never call the whole-list clear. Do not serialize
  runtime planes.
- Compatibility: capability-check the executable and required code bytes;
  append-only; skip cells with authored visibility; no mod/module detection
  beyond the executable contract; no-op when `bEnableBoundingVolumeOcclusion`
  is disabled.
- Diagnostics: log plane count, active count, pair calls and rejections at a
  low cadence; provide a debug visualization toggle using the existing native
  bound/occluder debug display, not a new overlay.
- Failure: on any signature, allocation or ownership failure, fall back to no
  injection and leave native behavior untouched.

## Acceptance and evidence required

Static qualification:

- executable identity reverified; exact code signatures for `0x004A5FF0`,
  `0x00C5AE70`, `0x004A49E0`, the scene-graph `+0x1E0`/`+0x8` route and the
  `+0x40` values;
- proven allocator/ABI, refcount and list-node ownership, and cell-transition
  removal;
- no authored plane removal or reordering;
- save/load exclusion proven.

Behavioral (game) qualification, which the research does not claim:

- fixed position and camera, identical settings, planes off/on, repeated runs;
- per-cell counters showing rejections actually occur and pass registrations
  decrease;
- visual check that no visible surface is culled (the false-cull risk);
- frame-time measurement with OMV off and on separately, reported as measured
  results, never extrapolated from static counts.

For `psycho-engine-fixes` the repository's real-runtime gate applies to any
production change. This document is research, not an implementation.

## Gaps closed after the plan research

- **XOCP field order is closed.** The reference `XOCP` handler at `0x0041617A`
  and the `0x416A30`/`0x4169F0`/`0x4168A0`/`0x416A70` setters establish
  `sizeX, sizeY, posX, posY, posZ, axisX, axisY, angle, axisZ`. The axis-angle
  representation is the generator contract.
- **The engine's own creation path is closed.** `0x00AA13E0` allocates `0xFC`
  bytes; `0x00C335D0` constructs the default plane; the four setters fill size,
  position and rotation and set the dirty flags. The plane is a `NiRefObject`:
  the runtime increments the count at `+4`, decrements it, and calls the
  object's `DeleteThis` virtual (`vtable+4`) on the zero transition. Append is
  `0x00C5AE70`, node free after a Rust unlink is `0x004A49E0`. The refcount
  entries `0x0040F6E0`/`0x00401970` are not called because performance mods
  commonly replace them in place with equivalent inlined atomics.
- **Orientation is now a per-plane contract.** `0x00C358A0` short-circuits true
  when the constructor's `+0xEA` flag is set. The runtime clears that flag, so
  `0x00C358A0` runs the plane-through-three-corners side test and activates the
  rectangle only when the camera is on its outward (+normal) side. A plane is
  still a window whose occluded volume is the camera-through-rectangle pyramid;
  the normal selects the active side. The owner's visual check remains required.
- **Lifecycle anchors are closed.** The scene graph is `owner + 0x1E0` with
  `owner = *0x011F91C8`; the current cell is `*(player + 0x40)` with
  `player = *0x011DEA3C`; cell/interior/grid/worldspace offsets are known; the
  xNVSE `OnFramePresent` (id 6) and world-lifetime events (7/8/9) are already
  forwarded to the core.
- **The list reset question is designed around.** The module scans the live
  list for its own plane pointers and removes only what it finds; a replaced
  scene graph triggers a forget-and-release path. It does not depend on the
  engine's reset timing.

## Remaining unknowns

- The `B`/`O` populations at the Fairfax exterior and the fraction of bounds
  hidden by buildings; this is a Phase 0 measurement.
- Whether the Fairfax cost is dominated by geometry admission, lighting, actor
  work, shadows or GPU, which determines how much any visibility change can
  help.
- Whether `ON_FRAME_PRESENT` is safely after the native visibility pass; the
  Phase 1 experiment confirms it, with the `0x008774A0`
  CellTransitionOrchestrator as fallback.
- The exact scene-graph list behavior on cell unload; the log records scan
  misses and the design tolerates either behavior.
- The room-build rebuild trigger, synthetic reference/3D ownership and portal
  graph retirement for option D.

## Evidence index

- Compact address index and excerpts:
  [runtime visibility contract](../analysis/radare2/output/fnv_runtime_visibility_injection_contract_20261017.txt)
- Owning location audit:
  [location performance static audit](fnv_location_performance_static_audit.md)
  (see "What occlusion can and cannot avoid", "Multibounds can scan every
  admitted occluder", "Compound programs", "Scaling reassessment").
- Prior draw-submission occlusion attempt:
  `.reports/2026-09-11-occlusion-rejection-root-causes.md`,
  `.reports/2026-09-11-occlusion-coverage-followup.md`.
- Read-only reference for the class vtables and the console-command
  use-after-free fix: `.research/Stewie Tweaks 9.95 Source/code/Internal/class_vtbls.h`,
  `.research/Stewie Tweaks 9.95 Source/code/Fixes/PlaceOcclusionPlaneFix.cpp`.
- Installed content-level visibility mods:
  `Fallout 3 Interior Optimization Project`, `New Vegas Interior Optimization
  Project`, `A World of Pain (AWOP) - FO3 - Roombound Project`.

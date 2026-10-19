# Runtime occlusion-plane injection: implementation plan

Status: runtime mechanism, mod-resilient reference-count path and runtime
occluder collection implemented and enabled by default; in-game qualification
is not done. The collector accepts only uncompressed vertex data, builds each
geometry's box in local space and orients the faces by the live world transform,
fits every rectangle inside the vertices that support that face, and verifies the
rectangle against the mesh's own triangles so a window opening, an empty door
frame or any missing surface is never covered. It skips horizontal ground/roof
faces and keeps the engine's two-sided window only for
faces whose support rectangle nearly fills their vertex hull (an irregular face
stays one-sided). Planes are scored by
supported solid angle and cached per cell. Neighboring loaded cells can be
included from their **complete cache entries only** (`occlusion_planes_grid_radius`,
default `0`): a cell is generated once, when it is the player's own cell, and
reused by key afterwards, so no neighbor mesh walk ever runs on a frame or
cell-crossing path. All covered cells share one injection budget so the native
bounds-times-occluders cost does not grow beyond the previous cap. Installing,
removing, reordering or updating a mod invalidates the cache through the
plugin-list signature. A 2026-10-19 report of a skipped frame while running led
to a resumable, frame-budgeted generator: a cell's mesh walk is sliced across
frames instead of blocking the frame thread for 20-32 ms (see section 4.3.1).
This is a heuristic and needs the owner's in-game visual check. No game run and
no FPS claim.
Companion to
[runtime visibility injection research](fnv_runtime_visibility_injection_research.md).
Address evidence is in
[runtime visibility injection contract](../analysis/radare2/output/fnv_runtime_visibility_injection_contract_20261017.txt)
and
[cross-cell visibility contract](../analysis/radare2/output/fnv_runtime_occlusion_grid_contract_20261019.txt).

Executable: `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, image base `0x00400000`. Reverify every address and byte signature
before implementation.

## 1. Goal and scope

Inject offline-generated `BSOcclusionPlane` objects into the engine's native
occluder list at runtime for cells that lack authored visibility data. Target
the Fairfax exterior groups first; keep the design general enough for other
exterior cells and for uncovered interiors later.

In scope:

- runtime creation, ownership, insertion and removal of `BSOcclusionPlane`;
- a per-frame cell/scene-graph reconciliation on the already-wired xNVSE
  `OnFramePresent` host event;
- an offline generator that emits per-cell plane data for later injection;
- configuration, logging and failure containment.

Out of scope:

- runtime room/portal injection (option D of the research document);
- any modification of authored `XOCP`/`XPOD`/`XMBO` content;
- mod detection or per-mod compatibility paths;
- changing `bEnableBoundingVolumeOcclusion` or any native default.

## 2. Closed knowledge

All addresses below are for the supported executable. The evidence file
contains the excerpts and byte signatures.

### 2.1 The engine's own XOCP creation path

The reference `XOCP` subrecord handler is at `0x0041617A`. It:

1. allocates `0xFC` bytes with the game allocator `0x00AA13E0`;
2. constructs the plane with `0x00C335D0` (a default `BSOcclusionPlane`
   constructor variant: vtable `0x101E794`, six planes at `+0x44`, default
   size from `0x0101B268`, default position from `0x011F426C`, identity
   rotation from `0x011A9448`, `+0x40 = 0`, `+0xEA = 1`, `+0xEC..+0xFB = 0`);
3. calls `0x00416A30` to copy two floats to `+0x14`/`+0x18` (native
   half-extent X/Y; the runtime size is the full extent and is halved at
   this boundary);
4. calls `0x004169F0` to copy three floats to `+0x08` (position);
5. calls `0x004168A0` to build a 3x3 rotation matrix from an axis-angle pair;
6. calls `0x00416A70` to copy the nine matrix floats to `+0x1C`;
7. attaches the plane through `0x00422150` as extra-data type `0x71`.

The three setters set dirty bytes `+0xE4` and `+0xE5`; `0x00C33870` rebuilds the
camera-dependent planes when `+0xE5` is set. No global or static state is
written by these functions except the dirty flags.

### 2.2 XOCP field order (closed)

`XOCP` is 36 bytes, nine little-endian floats:

| Float | Meaning |
|---:|---|
| 0 | size X (native half-extent) |
| 1 | size Y (native half-extent) |
| 2 | position X |
| 3 | position Y |
| 4 | position Z |
| 5 | axis X |
| 6 | axis Y |
| 7 | angle (radians) |
| 8 | axis Z |

`0x004168A0(matrix, angle, axis_x, axis_y, axis_z)` builds the axis-angle
rotation matrix used by authored `XOCP` records. This matches the observed
payloads, e.g. `(0,0,1,1.5708)` is a 90-degree rotation about +Z. The runtime
generator emits ready rotation matrices instead.

### 2.3 Orientation

A `BSOcclusionPlane` is a rectangle in its local **XZ** plane with local **Y**
as the normal. `0x00C35C10` builds the four corners as `position +/- sizeX *
M*(1,0,0) +/- sizeY * M*(0,0,1)`, so the `+0x14`/`+0x18` fields are
half-extents. The generator therefore stores matrix columns `(tangent A,
normal, tangent B)`; the old `(tangent A, tangent B, normal)` order put the
face normal into the rectangle's local Z axis and made the plane edge-on.
`0x00C33870` builds the camera-dependent frustum from the camera and those
corners and has separate code paths for the camera being on either side of the
rectangle. `0x00C358A0` short-circuits to true when the constructor's `+0xEA`
flag is set, which it is for planes created through `0x00C335D0`; the authored
`XOCP` planes therefore behave as two-sided windows. The runtime keeps that flag
for a face whose support rectangle covers at least `TWO_SIDED_COVERAGE` (0.35,
a floor that only rejects a strongly non-rectangular hull) of its vertex hull
**and** whose mesh is at least `MIN_FACE_THICKNESS` (16 units) thick along that
face's normal, and clears it otherwise. The thickness condition excludes thin
panels, decals and one-sided facade quads whose back side may be invisible,
where a two-sided window could false-cull from behind. The scan line reports
`thin` and `low_cov`, the emitted faces each condition kept one-sided, so a
playtest shows which gate limits the two-sided planes. With the flag clear,
`0x00C358A0` then runs the side test:
`0x00C35C10` produces `p0 = +A+B`, `p1 = +A-B`, `p2 = -A-B`, `0x00A699D0`
computes `(p1-p0) x (p2-p1)` (the stored local +Y column), and `0x0049DA80`
activates the plane when the camera is on that plane's negative side. The
builder therefore stores the inverse of the geometric outward normal so the
one-sided path activates only while the camera is outside the solid face. The
occluded volume is the pyramid from the camera through the rectangle; the
stored normal selects the active side when `+0xEA` is clear. The owner's visual
check remains required.

The `+0x40` admission that gates the whole pass is
`+0x40 = ((uVar2 & uVar3) == 0) + 1`, where `uVar2` is `0x00C33CF0` (0 when the
rectangle's four corners are inside one camera-frustum plane, i.e. the rectangle
is on screen) and `uVar3` is `0x00C358A0` (1 when `+0xEA` is set or the camera
is on the stored normal's negative side). A rectangle that is on screen
(`uVar2 == 0`) is therefore admitted regardless of `+0xEA`; the side flag only
changes admission for a rectangle that is off screen. The engine reconstructs
the occlusion pyramid in `0x00C33870` from the camera and the rectangle and has
separate paths for the camera on either side (`0x00C33981` tests the camera side
and branches), so the occluded volume is always the far side and the stored
normal sign does not change a visible plane's cull result. `+0xEA` is kept
authored-faithful for well-shaped, thick solid faces; the one-sided value for
the rest is a conservative no-op for on-screen culling and only affects off-screen
admission. This is why coverage of the rendered scene, not the side flag, is the
main effectiveness lever.

`0x00C33870` builds that pyramid as six planes: the rectangle's own plane plus
four side planes `(edge_i, edge_i+1, camera)`, with the mask at output `+0x60`
set to `0x3f`. There is **no far plane**, so the occluded volume is the infinite
pyramid from the camera through the rectangle. `0x00B5BBE0` walks the occluder
list once per scene-node bound and `0x00C47150` culls the bound when it is fully
inside all six planes. Two consequences drive the tuning: a rectangle's
**angular size from the camera** is what culls (a larger or nearer rectangle
subtends more and rejects more bounds), and the pair predicate is a short
(~50-instruction) test, so the `bounds x planes` cost is small relative to the
draw work it rejects. This is why the plane size, the coplanar merge and the
per-cell cap are the effective levers, and why they are set generously by
default.

### 2.4 Scene graph and the occluder list

- `0x00450B80(0)` returns the scene-graph owner; `owner + 0x1E0` is the world
  scene graph.
- The occluder list is `scene_graph + 8`. List layout: `+0` head, `+4` tail,
  `+8` count; node layout: `+0` next, `+4` prev, `+8` plane pointer.
- `0x00C5AE70(scene_graph, plane)` allocates a node from `0x0043A010` and
  appends it through `0x00559A70`. It does not retain the plane.
- `0x004A49E0(list, node)` is the node free (`ret 4`): it zeroes `node+8` and
  returns the node to the native pool; it does not release the plane. The
  engine's `0x004EDF00` removes and frees the list tail, not a specific node,
  so the runtime unlinks its tracked node in Rust and calls `0x004A49E0`.
  `0x004ED900(list)` frees every node.
- The plane is a `NiRefObject`: its count is the dword at `+4`. The runtime
  increments it with one atomic operation and decrements it with one atomic
  operation. On the decrement-to-zero transition it calls the object's
  `DeleteThis` virtual (`vtable+4`), which runs the scalar deleting destructor.
  This mirrors the engine's `0x0040F6E0`/`0x00401970` exactly but does not call
  those entries.
- This is deliberate: performance mods commonly replace `0x0040F6E0` in place
  with an inlined `lock xadd` form. A 2026-10-17 runtime log from the owner
  showed exactly that patch at `0x0040F6E0`; the old exact-byte gate disabled
  the whole feature. The runtime now owns the documented `NiRefObject`
  semantics and is independent of the patched entry.
- The engine's list clear on scene-graph destruction (`0x00C5AE34`) zeroes
  `node+8` before freeing, so a plane we own stays alive until we decrement it.

### 2.4.1 The native visibility pass covers the whole loaded grid

The occluder list is scene-graph-global, and the exterior visibility pass walks
every loaded grid cell, not only the player's cell:

- `0x0086EBF5` calls `0x00B5AC90(camera)` once per frame to update each plane's
  `+0x40` admission.
- The exterior branch of `0x0045B070` reads the loaded grid and calls
  `0x004BA490(gridCellArray, x, y)` for every slot of the whole grid.
- `0x0084E3A0` returns `*(gridCellArray + 0xC)` (the grid size, `uGridsToLoad`);
  `0x004BA490` bounds both coordinates to `0..gridSize`, indexes
  `gridCells[gridSize * x + y]` at `gridCellArray + 0x10`, and returns the
  `TESObjectCELL*` slot. `TES` is the singleton `*(0x011DEA10)` and its
  `gridCellArray` is at `TES + 0x08`.
- The caller skips a null cell and otherwise tests the cell's render containers
  (`0x00456FC0(cell, 7)` and `0x00456FC0(cell, 2)`) through `0x00B5BBE0`.
- `0x00B5BBE0` reaches the same scene-graph list at `owner + 0x1E0`, `+8`, and
  calls `0x00C47150` for every record whose `+0x40` is 1 until one contains the
  bound.

Consequences for the collector:

- A plane generated from any loaded cell is a valid occluder for the same
  scene graph. Limiting collection to `player->parentCell` left the large
  statics in the adjacent cells uncovered even though the engine was rendering
  and culling them.
- The engine's grid is a square loaded-cell array centered on the player. The
  optional neighborhood is every non-null slot whose cell coordinates are within
  the configured Chebyshev radius of the player's cell; the default radius `0`
  preserves the player-cell-only behavior.
- **Neighbors are cache-only.** Generating a neighbor from its live meshes on a
  frame path caused 1-4.5 ms `frame work` spikes (a 2026-10-18 owner log shows
  `frame work 4487 us`) and a measured FPS regression. A cell is now generated
  only while it is the player's own cell; afterwards its complete cache entry is
  reused by key. The neighborhood rebuild reads the grid array and the cache, not
  a neighbor cell's object list.
- The number of injected planes is not multiplied by the number of cells. The
  per-cell sets are candidates; one shared `occlusion_planes_max_per_cell`
  budget is scored and capped, so the native `bounds x active occluders` cost
  stays at the previous bound.
- Off-thread generation is rejected: the walk reads engine-owned `TESObjectCELL`
  and `Ni*` memory that the engine mutates and frees on the main thread. A worker
  thread would race with cell streaming and 3D attach/detach and could read freed
  memory. The pure-Rust scoring is small and is not the cost.

Evidence: [cross-cell visibility contract](../analysis/radare2/output/fnv_runtime_occlusion_grid_contract_20261019.txt).

### 2.5 Player, cell and worldspace

- Player: `*(0x011DEA3C)` (`TESObjectREFR`/`Actor`).
- Current cell: `*(player + 0x40)` (`TESObjectREFR::parentCell`).
- Cell FormID: `*(cell + 0x0C)` (`TESForm::refID`).
- Interior flag: `*(u8*)(cell + 0x24) & 1`.
- Exterior grid: `*(i32*)(cell + 0x48)`, `*(i32*)(cell + 0x4C)`.
- Worldspace: `*(cell + 0xC0)`; its FormID is at `+0x0C`.
- `0x00702360` / `TES_SINGLETON + 0x77C` expose loading state if a guard is
  needed.

### 2.6 Host events

`psycho-engine-fixes-helper` already forwards xNVSE messages as numeric event
ids (`psycho-engine-fixes/src/events.rs`):

| Event | Id | Use |
|---|---:|---|
| `DEFERRED_INIT` | 1 | mark ready, read data |
| `ON_FRAME_PRESENT` | 6 | per-frame cell/scene-graph check |
| `PRE_LOAD_GAME` | 7 | clear before a save load |
| `EXIT_TO_MAIN_MENU` | 8 | clear |
| `NEW_GAME` | 9 | clear |

`perf::observe_event` already receives these ids; option A adds handling there.
No new host ABI is required.

### 2.7 Function byte signatures

First-byte signatures were captured and are in the evidence file for:
`0x00AA13E0`, `0x00C335D0`, `0x00416A30`, `0x004169F0`, `0x00416A70`,
`0x004168A0`, `0x00C5AE70`, `0x004A49E0`, `0x00450B80`, `0x004A5FF0`.
The runtime uses `0x00C335D0` plus setters and `0x004A49E0`; `0x004A5FF0`
remains a documented alternative constructor. The refcount entries
`0x0040F6E0`/`0x00401970` are deliberately not in the signature gate; the
runtime manages the `NiRefObject` field and `DeleteThis` slot directly.

## 3. Architecture

```
live cell (main thread, on a cell change)
  cell->objectList -> STAT/SCOL/MSTT references
  OBND (base form) + loaded NiNode world transform
  IsNode / IsGeometry virtuals, alpha and skin checks
        |
        v
  conservative face rectangles (position, size, matrix)
        |
        v
psycho-engine-fixes
  performance.occlusion_planes=true
  perf::observe_event -> occlusion_planes::observe_event
        |
        v
  DeferredInit  : ready, load cache
  OnFramePresent: reconcile(player, cell, scene_graph)
  load/new/exit : clear and release
        |
        v
  native BSOcclusionPlane in scene_graph+8
```

No native code is patched. The module only calls verified getters/constructors
and manages its own planes. The runtime collector reads the loaded cell's
reference list and node transforms.

## 4. Runtime module design

### 4.1 Files

- `psycho-engine-fixes/src/mods/perf/occlusion_planes/mod.rs` - install,
  config, event routing, logging.
- `.../occlusion_planes/contract.rs` - addresses, byte signatures, ABI types,
  capability checks and live-scene offsets.
- `.../occlusion_planes/raw.rs` - volatile engine-memory readers.
- `.../occlusion_planes/data.rs` - cell keys and plane records.
- `.../occlusion_planes/runtime_generate.rs` - live cell occluder collection
  and conservative face-rectangle generation.
- `.../occlusion_planes/runtime.rs` - lifecycle state, creation, insertion,
  scanning, removal, release.
- `.../occlusion_planes/tests.rs` - pure-logic tests for cell keys, the
  box-to-face transform, vertex support, the support-coverage gate and the
  one-sided camera contract.

Register in `perf/mod.rs` and `startup.rs` behind the config flag.

### 4.2 ABI types

```rust
type AllocFn      = unsafe extern "cdecl"    fn(usize) -> *mut c_void;          // 0x00AA13E0
type CtorFn       = unsafe extern "thiscall" fn(*mut c_void);                   // 0x00C335D0
type SetSizeFn    = unsafe extern "thiscall" fn(*mut c_void, *const f32);       // 0x00416A30, native half-extents
type SetPosFn     = unsafe extern "thiscall" fn(*mut c_void, *const f32);       // 0x004169F0
type BuildRotFn   = unsafe extern "thiscall" fn(*mut f32, f32, f32, f32, f32);  // 0x004168A0
type SetRotFn     = unsafe extern "thiscall" fn(*mut c_void, *const f32);       // 0x00416A70
type AppendFn     = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);      // 0x00C5AE70
type FreeNodeFn   = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);      // 0x004A49E0
type SingletonFn  = unsafe extern "cdecl"    fn(usize) -> *mut c_void;          // 0x00450B80
type DeleteThisFn = unsafe extern "thiscall" fn(*mut c_void);                   // vtable+4
```

The refcount is not a called engine entry. The runtime uses one atomic add and
one atomic subtract on the object's `+4` field, and calls `vtable+4` when the
subtract returns one (the old value). This is the exact `NiRefObject` contract
implemented by the engine's own retain/release and is immune to mods that
inline or replace those entries.

`+0xEA` is not a called engine entry either. The constructor sets it to 1
(two-sided); `create_plane` keeps that for a face whose support coverage is at
least `TWO_SIDED_COVERAGE`, so a well-shaped solid face behaves exactly like an
authored `XOCP` plane and occludes from both sides. For a lower-coverage face
`create_plane` writes 0, and `0x00C358A0` then builds the plane through
`p0 = +A+B`, `p1 = +A-B`, `p2 = -A-B`, computes `(p1-p0) x (p2-p1)` and
activates the plane while the camera is on that plane's negative side. The face
builder stores the inverse of the geometric outward normal so the one-sided path
activates on the outward side. This is the engine's own per-frame camera-side
rejection.

Node removal is done in Rust using the proven list layout (list `+0` head, `+4`
tail, `+8` count; node `+0` next, `+4` prev, `+8` plane). Unlink the tracked
node, decrement the count, then call `0x004A49E0(list, node)` (`ret 4`, known
callee cleanup) to return the node to the native pool. The engine's
`0x004EDF00` is not used because it removes the tail rather than a specific
node.

`BuildRotFn` is called with `ecx = matrix`, then `angle`, `axis_x`, `axis_y`,
`axis_z`, matching the engine call site at `0x0041627F`.

### 4.3 Lifecycle

State:

```text
Uninitialized -> Ready (DeferredInit)
Ready -> Active (first frame with a player, cell and scene graph)
Active -> Active (same target, no rebuild)
Active -> Reconcile (target changed, or a settle retry is due)
Active -> Ready (load/new/exit: remove + release all)
```

`on_frame` pseudo-flow:

1. read `player = *(0x011DEA3C)`; bail if null.
2. read `cell = *(player + 0x40)`; bail if null.
3. read `owner` with `0x00450B80(0)` (the same call the engine uses) and
   `scene_graph = *(owner + 0x1E0)`; bail if null.
4. compute the cell identity key and its hash; the tracked target is
   `(scene_graph, key_hash)`, so a reused cell pointer still reads as a new
   cell. The interior/exterior decision uses the cell's interior flag, and a
   null worldspace or coords pointer is kept as a stable zero.
5. a different target must persist for `TARGET_STABLE_FRAMES` frames before it
   replaces the current planes. Cell seams can otherwise alternate between two
   cells every few frames; the debounce keeps the previous planes until the new
   target is stable.
6. if the target is unchanged and no settle retry is pending, periodically
   check that the tracked planes are still in `scene_graph + 8` (the engine can
   clear the list on cell unload without changing the cell identity); a missing
   node is released and the diff recreates it. Save the cache on a debounce.
7. a confirmed target change (or load/new/exit reset) forces a rebuild. A
   complete cache hit skips the settle window; a miss generates and restarts the
   settle window, and each settle retry refreshes the cache entry. An entry
   written before the settle window finished is marked incomplete and is
   regenerated on the next visit.
8. the same target also describes a neighborhood: the current cell plus the
   loaded exterior grid slots within `occlusion_planes_grid_radius`. A neighbor
   contributes only its **complete persistent-cache entry**; it is not generated
   from live meshes here. The neighborhood rebuild reads the grid array and the
   cache. A periodic check (60 frames) drops planes for cells that left the grid
   and picks up neighbors whose cache entry became complete.
9. rebuild: if the scene graph is unchanged, drop tracked planes whose node is
   no longer in the list (release the retained object) and diff the generated
   set against the remaining tracked set by quantized plane key. Unchanged
   planes stay linked; unmatched old nodes are unlinked in Rust and returned
   through `0x004A49E0(list, node)`; only new records are created. A changed
   scene graph means the old list is gone, so release every old plane without
   dereferencing retired nodes. The desired set is the union of the center set
   and the cached neighbor sets, deduplicated by plane key, scored by solid
   angle and capped by the shared budget. Cells that remain in the new
   neighborhood keep their in-memory planes, so crossing a cell boundary
   reuses most of the native set instead of rebuilding it.
10. resolve the cell key: the persistent cache wins, then the runtime
    collector. Create, retain and append only the records that were not reused,
    then store the new `(scene_graph, key_hash, signature)`.

The scan is O(list length) and the list holds authored planes plus ours. It
runs on target changes and the bounded settle window, not every frame, and never
on a neighbor cell. A cell change no longer requires the first frame to already
have every reference's 3D attached.

### 4.3.1 Resumable, frame-budgeted generation

Walking a dense cell's meshes and proving every face hole-free is larger than a
frame. A 2026-10-19 release playtest measured `gen_ms=20-32` for the Fairfax
exterior cells, and the settle window repeated the walk, so entering a cell
dropped one or more frames — the tester reported a skipped frame while running
through the exterior. The triangle coverage test added in the previous commit
was the dominant cost (a release benchmark measures 0.06-0.25 ms for a
512-2048-triangle solid face and up to 1.2-1.9 ms for an 8192-triangle face, so
a cell with dozens of large meshes reaches 20-30 ms).

The generator is therefore resumable (`runtime_generate::Generation`):

- `Generation::advance` examines at most `GENERATION_REFS_PER_FRAME` (96)
  references, `GENERATION_TRIANGLES_PER_FRAME` (8000) triangles and
  `GENERATION_SLICE_BUDGET_MS` (2 ms) per call, then returns `false`; the frame
  path advances it every frame while `GENERATION_ACTIVE` is set and only
  installs the set when the whole reference list has been walked.
- References are located by re-walking the cell list from its head to a saved
  index each frame, so no engine list node is held across frames (the engine can
  re-link the list while geometry streams in). A re-link can skip or repeat a
  reference, which only wastes a duplicate the shared dedup already removes.
- On a target change the previous cell's tracked planes are removed once, before
  the walk starts, so a stale rectangle cannot cull the new cell's geometry
  during the assembly window.
- The settle window still runs a bounded number of verification passes; each
  pass is now sliced the same way, so no pass stalls a frame.

The coverage test itself reuses caller-owned scratch buffers
(`CoverageScratch`), sorts packed edge keys instead of hashing every edge per
face, and keeps only the opening edges whose bounding box overlaps the candidate
rectangle, so a solid face skips the boundary analysis. All buffers are reused
across every face of every mesh in a generation.

### 4.3.2 Completion-frame bounds

`Generation::finish` still runs when the walk completes, and two of its steps
were unbounded on that one frame:

- `merge_coplanar` is quadratic within each coplanar group. A release benchmark
  of a non-merging coplanar row measured 67 µs at 64 candidates, 265 µs at 128,
  1.06 ms at 256 and 4.22 ms at 512 (about 38 ns per pair); the documented cells
  can emit up to 892 raw candidates, which would be roughly 15 ms. The pairwise
  work is now bounded by `MERGE_PAIR_BUDGET` (30 000 comparisons, about 1.2 ms
  in the same benchmark); once it is spent the remaining candidates stay
  unmerged and the score-and-cap step still selects the largest. The budget is
  part of the generation signature, so cached sets from a different budget are
  discarded.
- The rebuild diff looked a tracked plane's node up by walking the occluder list
  once per tracked plane and again per removed plane. `inject` now builds one
  `plane -> node` map from a single list walk (`linked_nodes`) and reuses it for
  both the keep test and the unlink, so a cell change is linear in the injected
  count instead of quadratic.

The completion frame also allocates the injected planes and writes the cache
entry; those are bounded by the plane cap.

### 4.4 Data lookup

- Interior: `CellKey::Interior { form_id: u32 }`.
- Exterior: `CellKey::Exterior { worldspace: u32, x: i32, y: i32 }`.
- "Behave like exterior" interiors use the interior key.
- The generator returns a per-cell list of plane records. The per-cell list is a
  candidate set; the union of the whole neighborhood is scored and capped by one
  shared `occlusion_planes_max_per_cell` budget, so the injected plane count and
  the native `B*O` pair cost do not grow with the grid radius.

### 4.5 Configuration

Add to `PerformanceConfig`:

- `occlusion_planes: bool` (default `true`, owner-requested);
- `occlusion_planes_max_per_cell: u16` (default 128, clamped `1..=256`). It is
  both the per-cell generation cap and the shared injected budget;
- `occlusion_planes_grid_radius: u8` (default `0`, clamped `0..=2`). `0` is the
  player-cell-only behavior and the measured-safe default. `1` reuses the
  complete cache entries of the loaded 3x3 neighborhood and `2` the 5x5
  neighborhood. Enabling it adds no frame-path generation: a neighbor is
  generated only while it is the player's own cell.
- `occlusion_planes_cache_path: String` (default
  `syringe/psycho_occlusion_planes.cache`);
- `occlusion_planes_debug_log: bool` (default `false`). Gates the verbose
  per-cell `scan`, `cell` and `presence` diagnostics; warnings and errors always
  log. Turn it on with `debug_log = true` only while investigating the feature.

Frame-path budget: the common frame does no hashing. The scene/cell pointers
are compared directly, and the cell identity hash (`FxHasher`) is only computed
when a pointer changes. The presence check runs every 30 frames and walks the
occluder list once (a single walk maps every linked plane to its admission
state), not once per tracked plane. While a generation is in flight the frame
path pays only one fixed slice (`GENERATION_REFS_PER_FRAME` references,
`GENERATION_TRIANGLES_PER_FRAME` triangles and `GENERATION_SLICE_BUDGET_MS`);
otherwise the generator and file writes only run on a target change or its
bounded settle window, and they never run for a neighbor cell. A grid
refresh check runs every 60 frames and is a few array reads plus cache lookups
when the grid changed, nothing otherwise. The per-frame neighbor path is one
atomic countdown decrement.

Config parsing happens at startup and changes the DLL's static/config layout,
so the startup gate in section 7 applies.

### 4.6 Logging and diagnostics

The verbose `scan`, `cell` and `presence` lines are gated by
`occlusion_planes_debug_log` (default off) and require `debug_log = true` as
well, so a default install stays quiet; warnings and errors always log. The
helper's **Runtime dashboard** shows the live state instead: the covered cell,
placed and camera-admitted rectangle counts, whether a cell is being measured,
the last rebuild summary, the cached-cell count, session
rebuild/cache-hit/created/removed totals and the per-cell budget. The core
publishes those as lock-free scalars in the dashboard snapshot (ABI version 6),
updated on the event thread only, so the sampling worker never walks the engine
list or touches engine memory. This replaced the removed debug overlay.

Stable tag `[OCCLUSION_PLANES]`. Log at `info` on install and cache load; log
at `debug` the scan counters and per-cell summaries. The `scan` line reports
`refs`, `not_stat`, `render_null`, `node_null`, `radius`, `no_vertices`,
`no_triangles`, `horizontal`, `support`, `small`, `size`, `opening`, `distance`,
`faces`, plus
`mesh_area`, `rect_area`, `cap_drop`, `thin`, `low_cov` and `merge_ms`: the
admitted surface area, the merged rectangle area before the cap, the merged area
the cap dropped, the faces rejected because the rectangle covered a window,
doorway or other missing surface, the emitted faces each two-sided gate kept
one-sided, and the time spent in the quadratic coplanar merge. So the log shows
how much solid surface became occluders, whether the cap is the coverage limiter,
how many faces an opening rejected, which two-sided gate is limiting, and whether
the merge is the generation cost. The per-cell `cell`
line reports `key`, `cells`, `neighbors=K/N` (cached neighbor cells and their
candidate plane count), `candidates`, `selected`, `center`, `raw`, `injected`,
`reused`, `removed`, `cap`, `two_sided`, `cached`, `complete`, `gen_ms` and the
observer position.
The `scan` line includes `dist_max`, so a playtest can show which cell is being rebuilt, how
many planes kept the two-sided window, how long generation took, and why the
distance filter rejected candidates. A `presence` line is emitted only when the
engine-admitted plane count changes or a missing plane is repaired; it reports
`tracked`, `present` and `active`. The presence path is skipped entirely while
no planes are tracked, so an empty cell costs nothing per frame. Route through
`libpsycho::logger::Logger` / `log`, never `println!`.

### 4.7 Failure containment

- If any signature or executable check fails, disable the module and keep the
  native list untouched.
- If the cache is missing/corrupt, log and regenerate.
- If allocation fails, skip that plane and continue.
- If the scene graph, cell or player is null, do nothing.
- Never clear the whole list; only remove nodes whose `+8` matches a tracked
  plane.
- All engine calls run on the xNVSE event thread (main).

## 5. Runtime occluder collection

### 5.1 Inputs

- The loaded cell's reference list (`TESObjectCELL::objectList` at `+0xAC`).
- Each reference's base form (`+0x20`) and its `typeID` (`+0x04`).
- The reference's loaded node (`RenderState::niNode` at `+0x14`) and its world
  transform (`NiAVObject::m_kWorld` at `+0x68`).
- The `IsNode` (`vtable+0x0C`) and `IsGeometry` (`vtable+0x18`) virtuals.
- `NiGeometry` alpha (`+0x9C`), model data (`+0xB8`) and skin (`+0xBC`)
  pointers.
- `NiGeometryData` vertex count (`+0x08`), vertex pointer (`+0x20`) and
  compression flags (`+0x39`). The local/world sphere bound is no longer a
  plane source.
- `NiAVObject` world bound (`+0x20`, radius at `+0x0C`) for the cheap radius
  pre-filter only.

### 5.2 Pipeline

1. Resolve the candidate cell set. An interior contributes its own cell only.
   An exterior contributes the current cell plus every non-null loaded grid slot
   within the configured radius. The current cell is generated on the target
   change; a neighbor contributes only its complete cache entry and is never
   generated on this path.
2. On a generation pass, walk that cell's `objectList`; stop after a fixed
   reference or vertex budget.
3. Accept a reference whose base form is `TESObjectSTAT` or
   `BGSStaticCollection` and whose `parentCell` is null or the current cell.
   The collector reads the loaded 3D geometry, so the base-type gate only
   chooses what is worth walking. `BGSMovableStatic` is excluded because its 3D
   can move after the planes are created.
4. Resolve the loaded node. Reject it cheaply when the engine's world-bound
   radius is below the minimum.
5. Walk the node tree through the `IsNode`/`IsGeometry` virtuals. A transparent
   or skinned geometry is skipped individually. The `+0x9C` alpha pointer is
   trusted only when its vtable is `NiAlphaProperty`, so a shifted offset cannot
   reject the whole cell.
6. For each admitted geometry, read the uncompressed CPU vertices through a
   borrowed slice and reduce them to a **local** AABB. The slice read lets the
   compiler vectorize the copy; the reduction is a four-wide SIMD min/max
   (`wide`, portable SSE/AVX/NEON with a scalar fallback). Geometry whose
   vertices are compressed, unavailable or over budget is skipped; a sphere
   bound is never turned into a rectangle. Each geometry is treated on its own
   (never merged across an object), so a multi-part object contributes tighter
   boxes.
7. Reject a geometry whose world-space largest extent is outside
   `256..=8192` units.
8. For each local face, collect the vertices within 5% of that face and build
   their 2D convex hull. Fit the largest axis-aligned rectangle supported by
   the hull: a centered binary search plus a bounded 16x16 occupancy grid when
   the centered rectangle is missing or clearly smaller. Reject the face when
   the rectangle cannot cover at least 5% of the face. Skip faces whose world
   normal is nearly vertical (`|normal.z| >= 0.8`), which removes ground and
   roofs.
9. Verify the rectangle against the mesh's triangles. The support hull is
   convex, so it spans any hole; a rectangle that covers a window opening, an
   empty door frame or any missing surface would cull what is visible through
   it. The near-face triangles are projected to the face plane and the
   rectangle is reduced to the largest solid part: cells crossed by an opening
   boundary (an edge used by one near-face triangle) or not inside a triangle
   are excluded. A face with no solid part emits nothing. A geometry whose
   triangles cannot be read or cross-checked emits nothing.
10. Emit the surviving face rectangle:
    - position: the supported rectangle center on the local face plane,
      transformed to world and offset outward by two units along the geometric
      outward normal;
    - size: supported in-plane extents scaled by the node's world scale,
      multiplied by a final `PLANE_SHRINK` (0.9); `create_plane` halves them for
      the native half-extent fields;
    - rotation: row-major matrix whose columns are the world tangent, the
      **inverse** of the geometric outward normal, and `tangent x normal` as the
      bitangent. `0x00C358A0` activates the plane on the stored normal's negative
      side, so the inverse normal selects the outward side. The engine spans
      local X/Z and takes local Y as the rectangle normal.
11. Merge coplanar rectangles within the cell whose in-plane union is exactly a
    rectangle: same stored normal, same plane offset within 1 unit, aligned
    in-plane axes, and either one contains the other or they share a full
    in-plane interval and touch/overlap in the other within 4 units. The merged
    rectangle is the union of two support-validated rectangles, so it cannot
    cover empty space; the 4-unit gap only bridges a tile seam, far below a
    doorway. This raises culling per plane (a wider camera-through-rectangle
    pyramid) and lowers the `B*O` pair cost.
12. Apply the observer distance filter and score each rectangle by supported
    solid angle (`area / (1 + (distance/2048)^2)`), then keep the per-cell
    candidate set. The `scan` line reports `cap_drop` for that set.
13. For the whole neighborhood, deduplicate by quantized plane key, score the
    per-cell candidates again against the same observer, sort, and cap at the
    shared `occlusion_planes_max_per_cell` budget. This is the injected set;
    the native pair cost stays bounded even though the collector now covers
    several cells.
14. Set `+0xEA` on the created object from the face's side confidence: keep the
    constructor's two-sided window for a face at or above
    `TWO_SIDED_COVERAGE` (0.35) whose mesh is also at least `MIN_FACE_THICKNESS`
    (16 units) thick along the face normal, and clear it otherwise. The coverage
    floor only rejects a strongly non-rectangular hull; the thickness condition
    is the one that excludes thin one-sided panels. With `+0xEA` clear,
    `0x00C358A0` activates the plane only while the camera is on the rectangle's
    outward side; both paths need no per-frame Rust work and reverse
    automatically when the camera moves around the object.

### 5.2.1 Limits and risks

The collector uses the vertex support hull to place the rectangle and the mesh's
own triangles to prove it is solid. The support fit is computed in the mesh's
local axes. The mitigations are the per-geometry oriented box (never merged), the
vertex support fit, the triangle coverage test, the horizontal-face rejection,
the size threshold, the final `PLANE_SHRINK`, the support-coverage gate, the
thin-panel thickness guard, the per-cell cap and the kill switch. Geometry whose
triangles cannot be read or cross-checked emits nothing. Geometry with compressed
vertices is currently skipped, which may reduce coverage in cells that rely on
compressed meshes. The owner's in-game visual check remains required.

The earlier prototype that read `NiTriShapeData`'s triangle list produced zero
candidates because the Fairfax population is `NiTriStrips`, whose data class
stores strips (`m_usStrips` +0x44, `m_pusStripLengths` +0x48,
`m_pusStripLists` +0x4C) rather than a flat triangle list. Both classes and
their dynamic variants are now decoded and the declared `m_usTriangles` count is
cross-checked before use. Evidence:
[triangle/alpha layout](../analysis/radare2/output/fnv_occlusion_triangle_and_alpha_layout_20261019.txt).

One residual false-cull class remains documented:

- **One-sided meshes.** A mesh rendered with backface culling can be invisible
  from its back, where a two-sided window would false-cull. The thickness guard
  excludes the common thin panel/facade case, but a thick one-sided mesh is not
  distinguished without the mesh's stencil/backface flag. Research so far: the
  `NiStencilProperty` vtable is `0x0101e07c`, its flags word is at `+0x18`
  (constructor default `0x4180`), but the bit that means two-sided and the path
  from a live `NiGeometry` to its stencil property are not yet closed, so the
  guard stays a thickness heuristic. A window opening is now handled by the
  triangle coverage test, not by this flag.

### 5.3 Persistent plane cache

Generating planes is the expensive part, so a revisited cell re-appends its
planes instead of re-walking the meshes. The cache is a compact binary file
(`syringe/psycho_occlusion_planes.cache`, `PSOC` magic) keyed by cell; each
entry stores the ready rectangle (position, size, rotation, priority) and the
`TESForm::refID` of the base form it came from, binding it to its source
plugin.

The header carries a schema/generator version (bumped whenever the extracted
set would change for the same meshes) and a hash of the active plugin list read
from
`DataHandler::modList` (`*(DataHandler**)0x011C3F2C`, `modList` at `+0x210`,
`tList<ModInfo>` with `ModInfo::name` at `+0x20` and the `WIN32_FIND_DATA` file
size at `+0x2B8`/`+0x2BC`). The hash covers load order, names and sizes, so
installing, uninstalling, reordering or updating a mod changes it and the whole
cache is discarded. A cache entry is only consulted on a target change; a
complete entry skips the settle window, and an incomplete entry (written before
the window finished) is regenerated instead of trusted. Every generated set is
written to the cache immediately as incomplete, so the cache always holds the
latest set and a revisit repairs a set that was interrupted by a cell change.
The settle comparison uses a coarse, quantized,
**order-independent** plane signature (`FxHasher`, positions rounded to quarter
units, per-plane keys sorted before hashing) so neither sub-unit engine jitter
nor a re-link of the cell's reference list defeats stability; the window stops
after two identical passes (`SETTLE_STABLE_PASSES`), or after one when every
reference already has an attached render node (`render_null == 0`), instead of
always running all five retries. This was the headline fix after a 2026-10-18 log showed
`cached=false` and six full regenerations per cell change, which cost frame time
and churned the occluder list. A later 2026-10-18 log proved the window still ran
to its full six scans while every scan statistic
(`refs/nodes/geoms/faces/mesh_area/rect_area`) was byte-identical, so the same
set was being emitted in a different order and the order-sensitive hash reported
a change every pass; sorting the per-plane keys fixed that. The file is
snapshotted on the main thread and written on the debounce, so the final state
is durable; a later offload experiment was reverted to this synchronous write
after it changed the measured baseline. A periodic presence check re-appends the
cached planes if the
engine cleared the occluder list without changing the cell identity, which is
what fixes the "leave and come back" loss of planes. Changing the per-cell cap
changes the config part of the signature, so cached sets from a different cap
are discarded.

The cache is per cell, so the same entry serves as the player's cell and as a
neighbor. A cell is generated (and its entry completed by the settle window)
only while it is the player's own cell. As a neighbor it is then reused by key,
with no mesh walk. This is what makes the optional 3x3 coverage free on the
frame and cell-crossing paths; a neighbor with no complete entry is simply
absent until the player visits it. The injected set is the shared-budget union
of the center set and the cached neighbor sets; the cache never stores that
union, so changing the grid radius does not invalidate cached cells.

The runtime now diffs the generated set against the tracked set using the same
quantized per-plane key. Unchanged native planes stay in the list, only changed
planes are removed, and only new planes are created. A missing node found by
the presence check is released and recreated by the same diff. This avoids the
one-frame cull flip caused by removing and re-adding the whole list on every
settle pass. The cache schema version is 9 and each entry carries a completion
flag and the face's side confidence; older caches are discarded because the
extraction semantics changed. The
header signature also mixes a fingerprint of the generation constants
(`PLANE_SHRINK`, size thresholds, support tolerances, merge tolerances, grid
resolution), so changing extraction or merge semantics invalidates the cache
even when the manual format version is not bumped. This was added after a
2026-10-18 cache generated under larger planes was reused across a constant
change and contributed to a measured FPS regression.

## 6. Phased delivery

**Phase 0 - Measure and capture.**
Add the optional diagnostic counters and a scene/cell dump for the reported
Fairfax position. Capture cell, grid, player coordinates, camera direction,
installed settings and a frame-time baseline with planes absent.

**Phase 1 - Mechanism proof.**
A small config-gated module creates 4-8 hand-authored planes at the largest
solid faces in the reported view. Confirm: creation, `+0x40` activation,
rejection counts, removal, cell transition, save load and no visual false
culling. Confirm that `ON_FRAME_PRESENT` insertion is safe; if not, move the
reconcile to a hook on `0x008774A0` (CellTransitionOrchestrator), which is a
known quiescent point.

**Phase 2 - Runtime module.**
Implement the module and lifecycle. Unit-test the pure logic; run the
real-runtime gate for the engine calls.

**Phase 3 - Offline generation.**
Deferred. If runtime extraction proves insufficient for some cells, extend the
NIF/record tooling, generate conservative data for the seven Fairfax exterior
groups, validate offline, then run the A/B in game.

**Phase 4 - Scale.**
Extend to other exterior cells. Measure the `B*O` pair cost; only if it is hot,
add the option E broad phase before raising the per-cell cap.

**Phase 5 - Interiors.**
Only for cells that the installed FO3/FNV Optimization and AWOP roombound mods
do not cover. Prefer generated override content before runtime room injection.

## 7. Qualification gates

Startup compatibility (`docs/nvse_startup_phase_safety.md` is mandatory): this
change adds code, statics and configuration to the core DLL. Keep all file I/O,
allocation and data parsing after `DeferredInit`; add no new pre-Deferred
imports or TLS. The owner must run the representative Proton
load-to-gameplay playtest before release, because the pre-Deferred footprint
changes. This is not the OMV no-game-runtime exception.

Static:

- executable identity and all byte signatures reverified;
- ABI and calling conventions checked against the captured signatures;
- corner-builder orientation and half-extent semantics proven against
  `0x00C35C10` (`0x4B4500` is row-major `M*v`; corners are `position +/- sizeX
  * localX +/- sizeY * localZ`); box-face and negative-scale transform tests
  pass;
- atomic `NiRefObject` increment/decrement and `DeleteThis` dispatch exercised
  by a focused test; node ownership remains as above;
- alpha-admission, base-type admission and plane-set-signature helpers covered
  by focused tests; the `+0x9C` alpha pointer is vtable-gated so a shifted
  offset fails open;
- oriented face construction covered by focused tests: a rotated box's faces
  stay on the rotated box, a negative scale mirrors the face and its outward
  normal, a face without vertex support emits nothing, horizontal ground faces
  are rejected, the one-sided `+0xEA = 0` corner/cross-product contract is
  checked against the engine's outward side, and the side-confidence gate keeps
  a full rectangular solid face two-sided while a thin panel face stays
  one-sided and an ordinary triangle still passes the coverage floor;
- cache round-trip and corrupt/signature-mismatch rejection covered by focused
  tests; the four-wide SIMD AABB reducer is checked against a scalar reference
  for every tail length;
- the loaded-grid neighborhood is covered by focused tests: the union selection
  keeps a near plane over an equally sized far plane, drops planes past the
  distance bound, and respects the shared budget; the grid/cell coordinate
  helpers are unit-covered;
- no authored plane removal; only tracked nodes removed;
- save/load exclusion: planes live only in the scene-graph list, never in
  reference extra data;
- `git diff --check`, formatting, and the supported 32-bit release build.

Behavioral (real runtime, owner-run):

- fixed position and camera, planes off/on, repeated runs;
- no visible false culling at the target view and while rotating;
- interior to exterior, exterior grid transitions, fast travel, save and load,
  new game and exit to main menu without crash or duplicate planes;
- logs show the expected add/remove/scan counts;
- frame-time comparison with OMV off and on separately, reported as measured
  results.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| False culling through windows/open doors | Triangle coverage test: the rectangle is reduced to the largest area with no opening boundary crossing it and no uncovered sample. A geometry without readable triangles emits nothing |
| A transparent surface admitted as an occluder | `NiAlphaProperty` vtable corrected to `0x0101_62DC`; blend/test geometries are skipped |
| False culling through windows/gaps | Vertex support fit, oriented faces, horizontal-face rejection, size limits, support-coverage gate that keeps an irregular face one-sided, shrink margin, owner visual check |
| Camera-side sign is wrong | The contract test proves the current corner order; a wrong sign deactivates the one-sided plane from the intended side and must be caught by the owner's visual check |
| `B*O` pair cost outweighs savings | One shared budget across all covered cells; per-cell candidate cap of 128 by default; support-coverage gate; lower the cap if a dense cell regresses |
| Neighbor generation costs frame time | Neighbors are cache-only; a cell is generated only while it is the player's own cell. The per-frame neighbor path is one atomic countdown decrement |
| A loaded grid slot changes under the collector | The neighborhood rebuild re-reads the grid array and matches cells by key, and a 60-frame validation drops planes for cells that left the grid |
| Shared budget starves the player's own cell | The union is scored by solid angle, so the near player-cell planes normally win; the default radius `0` keeps the original player-cell-only set |
| Native pair cost from neighbor planes | Neighbor planes are always scored against the player-cell planes under the same `occlusion_planes_max_per_cell` cap; set `occlusion_planes_grid_radius = 0` to restore the measured baseline |
| List reset/duplicate planes | Diff tracked planes by quantized key; only remove changed planes; never clear the whole list |
| Refcount/list ownership error | Increment the `NiRefObject` count once per plane; decrement only after node removal or scene-graph replacement |
| Startup compatibility regression | Defer all work to DeferredInit; owner Proton playtest |
| Data staleness after load-order changes | Cache header hashes the active plugin list (order, names, sizes) and discards the cache on any change; each plane records its source FormID |
| Engine clears the occluder list without a cell change | Periodic presence check releases missing nodes and the diff recreates them |
| Regenerating on every visit wastes work | Persistent per-cell cache; a complete cache hit skips the mesh walk and the settle window |
| Cell-seam target flapping swaps the plane set every few frames | `TARGET_STABLE_FRAMES` confirmation before a new target replaces the current set |
| A settle window aborted by a cell change caches an empty/partial set | Per-entry completion flag; incomplete entries are regenerated on the next visit |
| Stable cell identity flips while an exterior cell streams in | Interior flag decides interior/exterior; null worldspace or coords is kept as a stable zero; the cell key is logged |
| Settle pass flips the whole plane set | Quantized per-plane keys and a diff that keeps unchanged native planes |
| Compressed meshes lose coverage | Skip them for safety; verify the compressed vertex layout before recovering them |
| Event timing during visibility pass | Phase 1 verifies `ON_FRAME_PRESENT`; fallback to CellTransitionOrchestrator |
| Config/data path errors | Path next to the DLL or explicit config; missing file disables cleanly |

## 9. Open items

- Confirm `ON_FRAME_PRESENT` occurs at a quiescent point relative to
  `0x00B5AC90`/`0x00B5BBE0`; otherwise use the CellTransitionOrchestrator hook.
- Confirm the engine's list behavior on cell unload; the design is independent
  but the log should record scan misses.
- The mesh triangle data is now read (`NiTriShapeData` `+0x44`/`+0x48`,
  `NiTriStripsData` `+0x44`/`+0x48`/`+0x4C`, and their dynamic variants) and used
  for the coverage test. The declared `m_usTriangles` count is cross-checked; a
  geometry whose triangles cannot be read or validated emits nothing. A
  compressed-vertex mesh is still skipped before the triangle read.
- Geometry with compressed vertices is skipped. Verify the compressed vertex
  layout before reading it or before adding an offline data path for those
  meshes.
- A face whose candidate rectangle covers an opening is reduced to the largest
  covered sub-rectangle (16x16 coverage grid), so the solid band around a
  window or door is still an occluder. The `scan` line's `opening` counter
  shows how often a face had to be reduced or dropped.
- A cell-change pass now retries a bounded settle window, but a reference whose
  3D never attaches before the window closes is still missed. An entry that did
  not settle is marked incomplete and regenerated on the next visit. The window
  and interval are `SETTLE_RETRIES`/`SETTLE_INTERVAL_FRAMES` in `runtime.rs`.
- Confirm in the next playtest that the `key` and `complete` fields stop the
  same-second `cell` alternation, and use `gen_ms` to measure per-cell
  generation cost. `TARGET_STABLE_FRAMES` can be tuned if a genuine fast cell
  change is delayed too long.
- The resumable generator (`GENERATION_TRIANGLES_PER_FRAME`,
  `GENERATION_REFS_PER_FRAME`, `GENERATION_SLICE_BUDGET_MS`) bounds one frame's
  generation work but has no in-game behavioral test: the walk reads engine
  memory that cannot be fabricated offline. Confirm in the next playtest that
  planes appear within a fraction of a second of a cell change (the frame-cost
  warning should stay below 2 ms), that crossing a seam does not leave a gap or
  a stale rectangle, and that a save/load mid-generation recovers.
- If a cell still yields too few candidates, the `scan` debug counters
  distinguish an empty `objectList` (`refs=0`) from a rejected population
  (`parent_mismatch`, `not_stat`, `render_null`, `node_null`, `radius`,
  `no_vertices`, `no_triangles`, `size`, `horizontal`, `support`, `small`,
  `opening`, `distance`). Use that line before changing any offset.
- The `+0x40` derivation above shows the one-sided `+0xEA` value only changes
  admission for off-screen rectangles; it does not stop an on-screen rectangle
  from culling. The current thin/low-coverage gate is therefore conservative and
  cheap but not a false-cull protection for a visible face. If a playtest ever
  shows off-screen pair cost, setting `+0xEA` for every generated plane would
  match authored `XOCP` exactly and let `0x00C358A0` reject two-sided off-screen
  planes; that is a runtime-tuned change, not a coverage fix.
- The cross-cell option is grounded in the engine's own whole-grid visibility
  loop, but a 2026-10-18 owner log showed the original live-neighbor generation
  ran 31 neighbor scans in ~90 s (26 not-ready, ten retried twice), totalled
  28.4 ms of generation and produced a 4487 us `frame work` spike, alongside a
  10-20% FPS loss. The runtime now reuses complete cache entries only, and the
  option defaults to `0`. A local run is still required to confirm the
  neighborhood appears in the `cell` line (`neighbors=K/N`), that the native
  `active` count does not fall, and that no visible surface is culled before
  raising `occlusion_planes_grid_radius` again. If the pair cost turns out hot,
  lower `occlusion_planes_max_per_cell` before changing the collector.
- Remaining native per-frame cost: the engine walks the occluder list once per
  frame (`0x00B5AC90`) and once per camera-admitted bound (`0x00B5BBE0` ->
  `0x00C47150`), so its cost is `bounds x admitted planes`. Rust cannot remove
  it without patching `0x00B5BBE0` (option E broad phase), and the feature does
  not. The only in-scope lever is the injected count, and no full playtest log
  has been captured to correlate `active` with frame time. Before lowering
  `occlusion_planes_max_per_cell`, capture a fixed-camera A/B with planes on and
  off and the `frame work` warning; do not lower it on inference.
- Remaining Rust frame cost: the cache is serialized and written synchronously
  on the debounce (`CACHE_SAVE_INTERVAL_FRAMES`, about 30 s) and on
  load/new/exit. A long playthrough grows the cache to hundreds of cells; the
  write is bounded by the cache size but not measured. An offload experiment was
  reverted once, so only revisit it with a measured baseline.
- Off-thread generation of neighbor cells is not viable: the walk reads
  engine-owned `TESObjectCELL`/`Ni*` memory that the engine mutates and frees on
  the main thread, so a worker thread could read freed memory during cell
  streaming. The cache-only design removes the work from the frame path instead.
- The feature ships enabled by the owner's request; the in-game A/B, false
  culling check and startup playtest remain the release gates.

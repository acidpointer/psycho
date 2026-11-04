# Runtime occlusion-plane injection: implementation plan

Status: enabled by default; explicit false disables it. The ownership repair
was committed as `129fc60` after the owner reported no crashes. The authorized
[post-review work](#12-post-review-correctness-and-performance-plan) is implemented
under the same explicit no-runtime-test authorization.
It preserves graph ownership, publisher synchronization, native side policy,
shared plane cap and default neighbor radius zero.

The collector fits rectangles to live opaque static geometry and checks triangle
coverage before native creation. Local mesh analysis is content-validated and
reusable; disk data never authorizes world placement. Optional neighbors require
settled records and freshly matching source inputs. Collection, coverage and
completion yield across frames under a soft 1 ms target. Native acquisition,
one mesh, one face, publication and destruction are not hard latency bounded.
See sections 4.3, 5.3 and 12 for ownership, budgets and qualification limits.
No game run, image-correctness acceptance or FPS claim accompanies this work.
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

The native admission byte sequence computes
`+0x40 = ((frustum_test & side_test) == 0) + 1`. The bound consumer accepts
state 1 only, so both tests must succeed. `0x00B5AD91` ANDs their results,
`0x00B5AD98`/`0x00B5AD9B` compute the state, and `0x00B5BC60` rejects state 2.
The previous assertion that the side policy cannot affect visible rectangles
inverted this condition. It is not authority for changing the side policy or
normal convention. The frustum producer still handles both camera sides;
that does not bypass the earlier admission gate. See
[verified admission instructions](../analysis/radare2/output/occlusion_admission_review_20261104.txt).

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
- `0x00702360` is a menu-mode predicate, not a loading-only predicate. The
  injector uses xNVSE's explicit presentation-phase payload, not this menu
  predicate or an inferred cell-state value, for loading admission.

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
  load/new/exit : invalidate; next normal present unlinks and releases
        |
        v
  native BSOcclusionPlane in scene_graph+8
```

Two native append caller bridges serialize publication with injector list
maintenance. The module calls verified getters/constructors and manages its
own planes and graph reference. The runtime collector reads the current cell's
reference list under its native lock and reads admitted static node transforms.

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
- `.../occlusion_planes/runtime_generate_work.rs` - resumable merge and top-K selection.
- `.../occlusion_planes/runtime_generate_cache.rs` - bounded owned local analysis,
  validated persistence and real-asset/file-path regressions.
- `.../occlusion_planes/cache.rs` - ephemeral loaded-neighborhood world records
  and weak source provenance.
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
Active -> Reset pending (loading/unknown/load/new/exit: invalidate epoch only)
Reset pending -> Ready (normal main presentation: unlink + release owned state)
```

Normal presentation admits native work only on the DeferredInit thread after
pre-publication native publishers drain. Pending world invalidation retires the
owned graph before player/cell lookup. A target contains the world epoch, full
`CellKey`, current cell address and current graph address. Stored addresses are
comparison tokens, never resumable borrowed engine pointers. Target confirmation
still suppresses cell-seam flapping. A changed cell address requires fresh input,
even when its logical key matches.

A confirmed target always captures live sources. Completed generation and
pending slices have distinct outcomes: only completion spends a settle attempt.
Equality compares sorted full plane descriptors, including actual native side
policy; 32-bit hashes and rounded confidence cannot establish semantic equality.
A repeatable set with no observed unavailable input or truncation ends settling.
Empty, unavailable or budget-limited scans keep five fast retries followed by a
cold retry at the existing 1,800-frame cadence. Completeness records observations
of that pass; it does not prove arbitrary future script-driven 3D immutability.

Desired records survive native allocation failure separately from tracked native
objects. Periodic presence repair can recreate a missing subset, including zero
successful allocations, without mesh regeneration. The diff scans the native
list once and reuses Rust scratch. Borrowed node addresses are cleared before
publication unlock. Native object identity and authored list entries are kept.
Graph release stays outside tracking/publication locks.

A neighborhood description reads loaded identities only. Optional neighbor reuse
requires complete ephemeral records plus fresh matching reference membership,
geometry input, instance transform and source eligibility. Validation copies
admitted native input in bounded slices but runs no coverage or merging. Default
radius zero bypasses it. A new target discards previous neighbor admission;
world invalidation clears every world placement. No neighbor is generated merely
to fill the optional union.

### 4.3.1 Resumable, frame-budgeted generation

Each capture resolves current reference membership under CellRefLock. Relinking
without membership change cannot skip work; membership change restarts owned
results. A partial reference rewalks its hierarchy and checks the saved address
prefix against freshly encountered objects. Only comparison tokens survive a
slice. Native geometry arrays are copied into bounded Rust-owned surfaces before
releasing the lock; CPU analysis never borrows an engine mesh across frames.

Capture targets 96 references, 8,000 vertices/triangles of work and 1 ms per
advance. It checks inside a large reference between meshes; the final atomic
mesh can overshoot the count target. Coverage yields between faces. Grouping,
merge comparison/emission and top-K selection advance in batches of 96 operations.
An individual face, mesh, lock wait or native call can exceed the soft target.
There is no hard frame-latency guarantee and no reduction of admitted coverage
to meet a timer.

Opening recovery uses a fixed-stack histogram: 16 row passes replace 136 suffix
row passes and their allocations. The first complete histogram sweep already
finds the maximum; preserving its stack order and strict improvement rule keeps
the original bottom/right/pop-order tie. Already-covered mask cells skip repeat
containment queries. Scratch is reused; projected-triangle materialization is not
retained without a repeatable cold-path improvement.

### 4.3.2 Completion and timing boundaries

Merging retains its three passes and total 30,000-pair budget, but grouping and
comparison now yield instead of landing on one completion frame. Exhaustion
keeps remaining rectangles unmerged. Selection retains stable score ties and
uses streaming top-K; only the configured cap (at most 256) is sorted finally.
The existing offset/gap/angle merge tolerances do not prove an exact geometric
union; their conservativeness remains a research gate before expanding coverage.

Generation timing includes lock acquisition, capture, owned analysis, merge,
selection and source-certificate preparation. The outer frame warning also
includes neighborhood work, native publication and checkpoint work. Its cooldown
advances on normal admitted frames. Native publication remains atomic; its
creation/destruction cost and filesystem sync/rename latency are unmeasured in
the game and are not claimed bounded by 1 ms. Persistent work advances in idle
frames, separately from generation completion.

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
  neighborhood. Neighbors are generated only while they are the player's cell;
  reuse performs bounded live source validation, without rectangle generation.
- `occlusion_planes_cache_path: String` (default
  `syringe/psycho_occlusion_planes.cache`);
- `occlusion_planes_debug_log: bool` (default `false`). Gates the verbose
  per-cell `scan`, `cell` and `presence` diagnostics; warnings and errors always
  log. Turn it on with `debug_log = true` only while investigating the feature.

Frame-path budget: every admitted frame checks the current cell identity and
its fixed-size hash, including when its address is unchanged. The presence
check runs every 30 frames and walks the
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
`unavailable`, `no_triangles`, `horizontal`, `support`, `small`, `size`, `opening`, `distance`,
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
`tracked`, `present` and `active`. An empty tracked set skips native presence traversal; a missing desired subset
still receives periodic repair. Route through
`libpsycho::logger::Logger` / `log`, never `println!`.

### 4.7 Failure containment

- If any signature or executable check fails, disable the module and keep the
  native list untouched.
- If the cache is missing/corrupt, log and regenerate.
- If allocation fails, skip that plane and continue.
- If the scene graph, cell or player is null, skip collection/injection.
  Pending cleanup of a strongly owned graph still finishes before those lookups.
- Never clear the whole list; only remove nodes whose `+8` matches a tracked
  plane.
- Injector engine calls run only in normal presentation on the DeferredInit
  main thread. The two native publication bridges run on their callers' threads
  and preserve the original provider, arguments and last-error behavior.

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
13. For the whole neighborhood, deduplicate by full native descriptor, score the
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

### 5.3 Content-validated local cache and ephemeral placements

`runtime_generate_cache.rs` owns PSOC revision 11 at the existing configured
path. The file stores finite local vertices, valid triangle indices and computed
local support/coverage footprints, plus extraction signature and per-record
integrity checks. Older world-placement formats are rejected. Decoder bounds
apply to the whole file and aggregate data, not only individual records. Code
or format changes require a revision; the signature includes both coverage-grid
resolutions and listed extraction constants. Plugin names, file sizes, raw engine
addresses and a merged plane's first FormID are not cache authority.

Every local hit hashes then compares complete input bytes/indices. Hash equality
alone never establishes identity. World transform, signed scale, material/skin
admission, horizontal rejection, shrink and native side policy stay at the live
instance boundary. Changed input recomputes analysis; changed placement uses the
same local analysis with its fresh transform. New world planes are always derived
from live inputs, including on cell revisits.

The owner selected the existing input budget: active snapshots and reusable local
surfaces share 200,000 vertices and 400,000 triangles (4.58 MiB of retained array
payload). LRU residency is also bounded to 2,000 entries. Evicted surfaces still
held by snapshots remain charged until dropped. Scratch, bounded metadata and
encoded checkpoint bytes are additional memory; 4.58 MiB is not a total cache
VAS claim. Decoder and writer derive their encoded cap from those same limits;
the writer never retains a second decoded mesh pool.

`cache.rs` retains at most the 25 loaded neighborhood cells. Each certificate
bounds reference and mesh metadata to 2,000 items per cell; oversized certificates
make that world result uncacheable without changing center output. Certificates
hold only weak, separately allocated content identity tokens. They neither own
engine objects nor keep decoded surface allocations alive after eviction.
A neighbor placement is admitted only after fresh matching sources; expired
identity is a cache miss. Incomplete results cannot be promoted via an old
neighborhood map. World events clear placements but retain reusable local data.
This validates reuse; it is not a new continuous tracker for arbitrary scripted
geometry mutation while the player stays in one cell.

One sequenced checkpoint encodes at most one admitted mesh record or writes one
bounded chunk per idle advance. It uses weak inputs, an encoded-size cap and a
temporary file followed by sync and atomic replacement. Failure leaves the old
file and dirty state for a later checkpoint. Changes during a checkpoint keep
newer work dirty; older snapshots cannot finish after newer writers. No worker,
new startup initializer, config field or host ABI is added. Loading callbacks only
request a checkpoint. Menu presentation can progress it; process termination
before completion can lose recent reusable analysis, which is regenerated safely.
Filesystem latency, final sync/rename and crash durability are not hard bounded.

Presence repair uses the independent desired set, not a stale disk world cache.
Exact native descriptors keep unchanged objects linked across settle passes.
Dashboard cache counters now describe loaded world records and passes that
reused local analysis, preserving the existing host layout.

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
| Neighbor generation costs frame time | Default radius zero bypasses neighbors. Other radii validate cached sources in bounded slices without rectangle generation |
| A loaded grid slot changes under the collector | The neighborhood rebuild re-reads the grid array and matches cells by key, and a 60-frame validation drops planes for cells that left the grid |
| Shared budget starves the player's own cell | The union is scored by solid angle, so the near player-cell planes normally win; the default radius `0` keeps the original player-cell-only set |
| Native pair cost from neighbor planes | Neighbor planes are always scored against the player-cell planes under the same `occlusion_planes_max_per_cell` cap; set `occlusion_planes_grid_radius = 0` to restore the measured baseline |
| List reset/duplicate planes | Diff tracked planes by full descriptor; only remove changed planes; never clear the whole list |
| Refcount/list ownership error | Increment the `NiRefObject` count once per plane; unlink own nodes before plane release; retain the graph through retirement and release it outside publication locks |
| Startup compatibility regression | Defer all work to DeferredInit; owner Proton playtest |
| Stale world placement after source changes | Disk stores local content only; live input equality controls analysis reuse and fresh certificates control neighbor placement |
| Engine clears the occluder list without a cell change | Periodic presence check releases missing nodes and the diff recreates them |
| Repeating local analysis wastes work | Bounded content-matched mesh footprints; source capture and instance validation still run |
| Cell-seam target flapping swaps the plane set every few frames | `TARGET_STABLE_FRAMES` confirmation before a new target replaces the current set |
| A settle window aborted by a cell change caches an empty/partial set | Per-entry completion flag; incomplete entries are regenerated on the next visit |
| Stable cell identity flips while an exterior cell streams in | Interior flag decides interior/exterior; null worldspace or coords is kept as a stable zero; the cell key is logged |
| Settle pass flips the whole plane set | Exact per-plane descriptors and a diff that keeps unchanged native planes |
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
- Both frustum and side predicates must succeed for native admission. Preserve
  the current side policy; the previous off-screen-only interpretation was
  incorrect, as the reverified instructions in section 2.3 establish.
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
  not. Selection and ordering can affect early exits, but no full playtest log
  has been captured to correlate `active` with frame time. Before lowering
  `occlusion_planes_max_per_cell`, capture a fixed-camera A/B with planes on and
  off and the `frame work` warning; do not lower it on inference.
- Checkpoint encoding and writes are now incremental and bounded in size, on
  idle frames. Sync/rename and native publication/destruction latency remain
  game-only measurements; no worker or off-thread engine traversal is added.
- The shipped TOML, Rust fallback and dashboard fallback enable the feature
  by default at the owner's request. This implementation's runtime-test waiver
  and unverified gameplay/image/performance scope are recorded in section 11.

## 10. Stability investigation and repair plan, 2026-11-04

### 10.1 Scope, conclusion and evidence limits

Research baseline: `cec29ce`, before the separately authorized implementation
in section 11. Descriptions of current code in this section refer to that
baseline; the failure evidence is retained rather than rewritten as a passing
game test.

The owner reports a substantial FPS benefit followed by rapid crashes and
explicitly selected the October 18-22 archives for this investigation. Preserve
the native early-culling feature and its coverage while repairing stability.
This is research and a repair plan, not an implemented crash fix.

There is a concrete unsafe ownership assumption in the injector: **changing the
active graph pointer is treated as destruction of the previous graph's list**.
Native graph switching does not establish that destruction. If the old graph
survives, the injector releases planes without removing its old list entries.
That supplies a specific dangling-pointer mechanism to investigate first.
Loading-frame admission is also missing, and the production geometry coverage
predicate has an independently reproduced defect. These findings do not prove
which writer produced the archived invalid linked-plane pointer, or that all
the archived crashes share one cause. A complete incident root cause remains
open.

The supported executable identity above was reverified. New native evidence:

- [Constructor, consumers, dynamic storage and node-pool ownership](../analysis/radare2/output/occlusion_stability_native_ownership_20261104.txt).
- [Complete active-graph switch](../analysis/radare2/output/occlusion_stability_graph_retirement_20261104.txt).
- [Its owner-state drain](../analysis/radare2/output/occlusion_stability_switch_drain_20261104.txt).
- [Entry-aligned switch callers and owning-pointer helpers](../analysis/radare2/output/occlusion_stability_switch_ownership_verified_20261104.txt).
- [Graph-destructor list clear](../analysis/radare2/output/occlusion_stability_graph_destructor_20261104.txt).
- [Compound builder](../analysis/radare2/output/occlusion_stability_0x00C47D20_20261104.txt),
  [append](../analysis/radare2/output/occlusion_stability_0x00C5AE70_20261104.txt),
  [list insertion](../analysis/radare2/output/occlusion_stability_0x00559A70_20261104.txt)
  and [node free](../analysis/radare2/output/occlusion_stability_0x004A49E0_20261104.txt).

The verified caller capture supersedes the explicitly misaligned preliminary
probes in `occlusion_stability_switch_ownership_20261104.txt`. Decompiler types
and calling-convention labels are not authority; use the exact instructions.
The captured native caller references cover five direct graph-switch calls,
not indirect or plugin writes.

The [incident matrix](../.reports/20261104-occlusion-stability/incident-matrix.json)
records the selected reports, complete reported calltraces, registers, matching
feature log markers and available configuration. It does not reconstruct
allocation or writer history. No game directory, reproducible save/route,
minidump or live process is available. The newly discovered November 4 log has
the feature disabled and an empty crash report; it is not incident evidence.
Archived candidate binaries, old source snapshots and the current source must
be kept distinct.

### 10.2 What the crashes actually establish

| Incident family | Reliable failure | What remains unknown |
| --- | --- | --- |
| [October 18 linked plane](crash_20261018_occlusion_link_plan.md#established-fault) | `0x00C33887` reads the dirty byte through invalid `this = 0xA5000000`; caller `0x00C47EB3` is the selected-link cache path. | Source allocation identity, selected slot, publication/retirement history and corrupting writer. |
| [October 21 cache write](crash_20261018_occlusion_link_plan.md#october-21-follow-up-readable-linked-pointer-forbidden-cache-write) | Native corner-cache publication writes through linked `this = 0x004F004D`, an executable code address, while the older readable-memory guard is active. | How that value reached the source link or caller local. Writability containment repairs admission, not ownership. |
| [October 21 scene destruction](../.reports/20261021-invisible-terrain-crash/CrashLogger.log), recurring in the [13:03 archive](../.reports/20261021-1303-recurrent-scene-crash/CrashLogger.log) | `0x00667137` reads an array cookie through invalid array storage during scene-object destruction. | The writer of the child-array pointer; the destroyed scene node is not identified as an injected plane. |
| [October 21 transition](../.reports/20261021-1911-transition-crash/CrashLogger.log), [second transition](../.reports/20261021-second-transition-crash/CrashLogger.log), [October 22 water recurrence](../.reports/20261022-0035-water-recurrence/CrashLogger.log) | `0x0043B4AD` indexes child storage with ECX zero and EAX zero. The archived provider installs a different instruction sequence at this native address. | Why the caller reaches empty storage and whether injection caused it. The last two reports share a water-visibility caller chain; the first has a different caller context. |
| [October 19 fade owner](crash_20261019_vault108_fade_owner_plan.md), [October 20 Corvega](crash_20261020_corvega_exit_scene_owner_plan.md), [fast-travel fade list](crash_20261020_fast_travel_fade_list_plan.md) | Separate scene-owner, lookup and fade-list failure boundaries, covered by their owning investigations. | A common originating writer is not supplied by the fact that planes were enabled. |
| [Teleport doors](crash_20261019_teleport_door_null_base_plan.md) and [October 20 level-up inventory](crash_20261020_levelup_inventory_plan.md) | Different reference/base-form and inventory mutation paths. | A connection to plane generation or plane-list retirement is not established. |

The archive playtimes vary from roughly one minute to nearly 24 minutes. They
do not establish a ten-minute timer, monotonic plane accumulation or one common
crash signature. Unwind warnings and recognizable objects elsewhere on the
stack are not writer identification. The existing linked-plane investigation
explains why its unwind warning is not independent heap-corruption proof.

For the child-storage family, retain the
[provider installer and literal bytes](../.reports/20261021-1911-transition-crash/provider-installer.txt)
and [disassembly at the installed address](../.reports/20261021-1911-transition-crash/replacement-at-native-address.txt).
The installed instruction is `mov eax, [ecx+eax*4]`, whereas the supported
unmodified executable has a different instruction boundary there. Diagnosing
only the unmodified executable would misidentify this fault. This establishes
the immediate null-storage access, not a defect attribution to that provider.
No modification or compatibility patch to another mod is proposed.

### 10.3 Ownership defect: active selection is not retirement

The current `runtime.rs::inject` computes `same_scene` from pointer equality.
When it is false, it creates an empty `linked` map, drains the tracked planes,
and releases every retained plane. It does not unlink anything from the former
graph. The comment asserts that the old list is gone. The native evidence does
not support this assertion:

1. Getter `0x00454B30` returns `owner+0x1E0` without retaining it. This is an
   active visibility-graph selection, not evidence of ownership transfer.
2. Switch `0x00B5DDF0` clears owner-side work lists, updates room/object
   associations, and stores the new graph at `0x00B5E06E`. It performs no
   direct clear of the former graph's occluder list at `graph+8` or release
   of the graph as an owning pointer. Its `0x00B5D180`/`0x00B5C3C0` drain
   operates on other owner lists and releases scene-object state. These
   operations do not establish that the old graph and its occluder nodes have
   been destroyed before the injector's next callback.
3. The graph has a separate owning pointer in `TESObjectCELL+0xD4`, read by
   `0x009D9F20`. The activation caller at `0x00552AAC` publishes that graph.
   Cell cleanup `0x00545C10` clears active selection at `0x00545C6C` and only
   subsequently releases the cell's owning pointer at `0x00545C7C` through
   `0x0066B0D0`. Reference cleanup `0x00583270` similarly separates selection
   removal from its owning-pointer release. Selection and lifetime are distinct.
4. Actual graph destruction clears `graph+8` through `0x004ED900`, called at
   `0x00C5AE34`. This is the retirement operation the injector currently
   assumes has already occurred merely because selection changed.
5. Append stores a borrowed plane pointer in a list node. It takes no strong
   plane reference. The injector's own decrement can therefore destroy a plane
   while a surviving old graph still contains its pointer.

The conditional failure sequence is precise:

```text
graph A owns list node -> injected plane P; injector owns P's strong reference
engine selects graph B while graph A survives
injector sees a different pointer and releases P without unlinking A's node
graph A still contains P's address after P's destruction
later use of A can dereference freed or reused storage
```

The native switch does not itself prove the survival interval through the
injector callback in any supplied incident. No captured plane address is tied
to this sequence. Thus this is an unsupported ownership invariant and a
specific candidate use-after-free mechanism, not a reproduced incident root
cause. The old graph must not simply be dereferenced after a pointer change:
it may instead already have been destroyed. Both cases require an ownership
protocol.

The ordinary same-graph removal is materially different: it discovers current
nodes by plane pointer, unlinks them, returns nodes through the native pool,
then releases planes. The audited node offsets, `RET 4` ABI and refcount
decrement-to-`DeleteThis` shape agree with the native implementation. This does
not establish exclusion from simultaneous native readers.

### 10.4 Frame phase, collection and synchronization

Local xNVSE source and the
[upstream implementation](https://github.com/xNVSE/NVSE/blob/master/nvse/nvse/Hooks_Gameplay.cpp)
define `DisplayFrameHook<false>` for the main loop and
`DisplayFrameHook<true>` for loading screens, at `0x0087055E` and
`0x007147C4`. Both dispatch `OnFramePresent` with a four-byte integer flag.
The [archived xNVSE callback disassembly](../.reports/20261021-corruption-causality-followup/nvse-present-callbacks.txt)
independently shows payload values zero and one. This is not an assumption
that every presentation is a gameplay boundary.

Current helper `events.rs` forwards null data, length zero and boolean `-1`.
Core `host_events.rs` ignores those arguments. The injector routes every
presentation to `frame_tick`, with no loading admission. Pre-load/new-game/menu
events only set `RESET_PENDING`; on the next successful scene lookup the
injector can cancel generation and reconcile again, including during a loading
presentation. Null checks establish neither scene lifetime nor cell attachment.

The resumable collector does not keep list nodes or geometry pointers across
frames: it restarts the list walk at its cursor, and clears the node stack per
reference. It does keep an unretained cell address, and continuation admission
checks that address alone. A loading interruption, graph switch or address
reuse is not represented by a generation epoch. Reading volatile memory does
not pin an object or synchronize with attach/detach writers.

The injector's Rust mutex protects its own tracking data. Native readers do
not acquire it. Native list-node allocation/free use a shared pool lock, but
the neighbor/head/tail edits occur outside that pool operation. That lock is
not a visibility-reader fence. The two owner locks in `0x00B5DDF0`, or the
critical section in `0x00C5B8D0` covering other lists, must not be borrowed as
an assumed lock for `graph+8`. Complete reader/writer and task-completion
coverage remains an implementation gate.

Archived [loading-admission work](../.reports/20261021-loading-phase-implementation/core-occlusion.asm)
and a [later source snapshot](../.reports/20261022-single-diagnostic-build/before/psycho-engine-fixes/src/mods/perf/occlusion_planes/runtime.rs)
already contain a loading/unknown-phase guard. They are not the current source,
and are not proof of crash recovery. Restoring admission alone must not be
presented as a complete stability fix.

### 10.5 Geometry and cache defect reproduced offline

The archived fixture is the complete `BlackVoid` mesh from `WoodShack01`:
[asset provenance](../.reports/20261021-generator-surface-audit/asset-input.json),
[vertices and strip triangles](../.reports/20261021-generator-surface-audit/blackvoid-actual-surface.bin)
and [actual-production harness](../.reports/20261021-generator-surface-audit/production_math_research.rs).
Its triangle `[23,23,23]` has no surface. The current
`point_in_triangle_2d` nevertheless accepts a displaced point because all three
cross products are zero. `near_face_triangles_into` also retains such triangles
when their vertices satisfy the face-distance test. Zero projected area must
not constitute evidence of a solid face.

The archived harness was attached under `cfg(test)` to the unchanged production
module and executed through Wine with the supported 32-bit release-profile
test command. The no-surface assertion failed again. The companion test that
extracts the complete mesh with and without strip connectors passed and emitted
the same rectangles. This proves the predicate defect but does not prove a
false rectangle for this complete asset, invisible terrain, pointer corruption
or a game crash. The fixture provenance explicitly does not establish the
crash-time VFS asset.

The [new regression result](../.reports/20261104-occlusion-stability/unchanged-geometry-unsandboxed.log)
and [input/source record](../.reports/20261104-occlusion-stability/regression-inputs.json)
are preserved. The temporary test attachment was removed and the source
restored byte-for-byte. Earlier
[correction evidence](../.reports/20261022-occlusion-correction/qualification.json)
includes a geometry fix and cache invalidation, but those changes are absent
from the current predicate and its version-9 cache reader. Reusing an old cache
after correcting generation would bypass regeneration; any extraction repair
must advance the cache/generation revision and reject the actual old cache.

### 10.6 Plane count and rendering-pipeline hypotheses

No fixed small plane-count limit was found in the audited paths. The native
list allocates one node per plane. The compound builder checks capacity before
appending frusta/instructions, growing storage through `0x00C4A070` and
`0x00C4A1E0`; it does not index a discovered fixed array by total plane count.
This is bounded static evidence, not proof of support for arbitrary counts or
allocation failure.

The archived configurations examined use a shared cap of 128 and grid radius
zero. The current configuration clamps generated planes to 1-256 and union
selection applies one shared cap. Authored planes are additional native input;
the cap is not a limit on total engine planes. Native cost still grows with
tested bounds times admitted planes, and compound storage can grow. No archived
workload establishes a count threshold, monotonic leak, allocation failure or
plane-count-induced overwrite. Reducing the cap is not an established crash
repair.

Injection does not replace D3D render hooks or install a new shader/pass. It
does modify native scene visibility before draw submission, including compound
visibility consumers. Therefore the absence of render-hook changes does not
establish integration safety. Conversely, a rendering crash does not identify
an OMV pass or GPU resource as its cause. The reported FPS benefit is the
owner's runtime observation; this investigation makes no new FPS measurement.

### 10.7 Ordered repair plan and proof gates

1. **Establish incident ownership at the real boundary.** Reproduce an archived
   failure with its actual save/route, configuration and enabled feature before
   a crash repair. Compare the same workload with only plane injection changed;
   preserve rendering settings, other fixes and allocator selection. Record
   whether the bad source plane is authored or injected, its graph, all four
   link slots, and allocation/publication/unlink/destruction history. Existing
   archives lack these records. If observation is needed, use bounded,
   test-only instrumentation at the actual native boundaries, with no changed
   ownership or exception suppression. A debug-only build is not required.
   No game execution or new instrumentation was performed by this research.

2. **Close native lifetime and reader exclusion before editing ownership.**
   Trace graph-owner publication/release and all discovered list consumers,
   including worker/task entry and completion. Prove a mutation point at which
   old nodes cannot still be in use. The intended invariant is: an injected
   plane is released only after every list that exposes it has unlinked it and
   every admitted reader has finished. An active-pointer comparison, a mapped
   address, a fixed frame delay or a private mutex cannot supply that proof.
   The current evidence is insufficient to choose a safe native hook.

3. **Implement an explicit injection owner at the proven boundary.**
   Replace the changed-graph release assumption in `runtime.rs` with ownership
   of the graph/list and its plane references. A supported design can retain
   the graph while its injected nodes exist, then unlink its own nodes before
   releasing planes and finally the graph; an engine retirement callback is
   another option if its complete lifetime/ABI contract is proven. Choose only
   after step 2. Handle both surviving and destroyed old graphs and native
   list clears. Avoid leaking planes until process exit or blindly touching
   an old graph. Preserve authored nodes and exactly one injector-owned strong
   plane reference. Keep allocation and rollback explicit.

4. **Carry presentation phase and a world generation identity.**
   Update helper `events.rs`, core `host_events.rs`, `perf` routing and
   occlusion event admission to preserve the existing phase payload/ABI.
   Loading or unknown phase must not walk live cell/mesh memory, mutate lists,
   create planes or run deferred cleanup against a retiring owner. Invalidate
   an interrupted generator using a world epoch plus cell identity and graph
   association. Resume only at the boundary established in step 2; a normal
   presentation alone is not evidence that background streaming has finished.
   Keep transitions allocation-free where possible and avoid added per-bound
   permission queries, polling or logs. Read the complete startup contract
   before changing these shared paths and preserve pre-DeferredInit behavior.

5. **Correct coverage independently and invalidate affected caches.**
   Reject repeated-index and zero-projected-area triangles consistently in
   face selection and point containment, using the actual asset regression.
   Preserve genuine triangle edges and valid thin geometry; do not introduce
   an arbitrary tolerance that silently removes coverage. Retain the complete
   asset/control test and opening tests. Advance cache/generation revision and
   exercise the production decoder with the archived pre-correction cache.
   Keep this separate from the native ownership fix and do not label it a
   repaired crash without native evidence.

6. **Qualify stability, correctness and cost separately.**
   The behavioral gate must exercise actual native creation, insertion,
   consumption, graph switching and retirement. Include buffered surviving
   graphs, destroyed graphs, A-to-B-to-A transitions, same-address reuse,
   save load/reload, new game, main menu, loading presentations and interrupted
   generation. Confirm no dangling injected list entry, duplicate unlink,
   double release or authored-node mutation. Execute native linked-plane
   clipping for valid authored/generated input, not just permission rejection.
   Cover the water/child-array recurrence separately if it remains after the
   ownership repair. Preserve the affected scene's visibility and compare
   frame-time distributions on the same workload/settings through repeated
   transitions and beyond the reported failure interval. A ten-minute clean
   run alone does not prove resolution. Run focused regressions, affected
   core/helper suites, the supported complete 32-bit release build, formatting,
   startup acceptance and diff review before calling the fix ready.

More pointer guards can contain a bad input but cannot identify a writable
reused object or repair a dangling owner. Do not clear authored links, alter
the allocator, disable the feature, reduce its coverage or replace it with a
different occlusion system as a substitute for these gates. The shipped-TOML
versus-Rust-default mismatch is a separate configuration inconsistency to
resolve with the experimental rollout policy; it is not the crash mechanism.

### 10.8 Research handoff state before implementation authorization

Production code is unchanged. The current geometry defect has fresh offline
failure evidence; the graph-lifetime and phase findings have source/binary
evidence. Native incident reproduction, invalidating writer identity, reader
exclusion, startup, rendered correctness and performance acceptance remain
unverified. Research used the existing reporter archives without assuming a
reporter-only implementation exception. No deployment, packaging or commit
was performed. The next ownership implementation is blocked on the real
behavioral reproduction and the reader/lifetime contract, rather than on a
speculative plane-count adjustment. The subsequent explicit owner instruction
waived runtime testing and authorized the implementation in section 11.

## 11. Ownership and phase correction implementation

The owner explicitly authorized implementing all identified occlusion issues
without runtime testing. This task-specific authorization includes repairing
the injector's own ownership, beyond the guard-only scope of
`psycho_engine_fix_exception.md`. Native ABI, source/binary evidence, scope,
offline tests and honest reporting remain required. No game execution is an
implementation gate for this authorized candidate, and none is requested or
claimed. This does not establish the original corrupting writer or repair the
separately investigated unrelated crash families in section 10.2.

### Graph ownership and mutation boundary

`runtime::Injection` owns its graph and every injected plane. Incoming graph
ownership is acquired before outgoing ownership is released. A graph switch
unlinks all tracked old nodes while the old graph is still strongly owned,
then releases the planes. `RetiredGraph` releases the graph only after the
publication guard and tracking mutex have dropped. This prevents both a
dangling old list and graph destruction under a lock that a native publisher
could be waiting for while holding another engine lock. Empty sets and failed
allocations also release an unused graph outside the publication lock.

Native reader coverage was extended against the same verified executable:

| Reader | Native caller coverage found |
| --- | --- |
| `0x00B5AC90`, plane activation | One direct call at `0x0086EBF5` in main frame `0x0086E650`. |
| `0x00B5BBE0`, bound/list traversal | Six direct calls in `0x0045B070`, and three in `0x006FA6D0`. The latter is called by `0x006FD080`, whose found caller is `0x0045B235` in that same `0x0045B070` pass. |
| `0x00B5F170`, compound construction | Three direct calls in `0x0045B070`. Its builder copies frusta into owned compound storage; it does not publish our plane pointers to later culling work. |
| `0x0045B070`, outer visibility pass | Found caller `0x0086EC18` in main frame `0x0086E650`. |

The main frame calls render owner `0x0086FF70` at `0x0086EDE8`, after the
synchronous visibility pass. Its normal present call is `0x0087055E`, where
xNVSE dispatches the normal presentation message. Injector list changes are
confined to that main-thread callback, after these readers have returned.
The thread ID is captured at DeferredInit; a foreign-thread invocation cancels
work without entering the engine. This contract covers the verified native
references and normal chained providers, not arbitrary external code that
introduces an asynchronous engine-list reader outside the native contract.

Evidence: [reader/publisher references](../analysis/radare2/output/occlusion_stability_reader_callers_20261104.txt),
[list methods and reader bodies](../analysis/radare2/output/occlusion_stability_list_threads_20261104.txt),
[secondary reader owner](../analysis/radare2/output/occlusion_stability_world_thread_owners_20261104.txt)
and [complete render/present owner](../analysis/radare2/output/occlusion_normal_present_owner_20261104.txt).
The last source-owner capture's `0x0093E840` probes do not cover the separate
`0x00940161`/`0x0094383C` attachment callers and are not used as thread proof.
Publisher serialization avoids depending on those callers' thread ownership.

`native_list` chains both native append callers (`0x0054AA11` reference
attachment and `0x005BBBD1` console creation), using exact caller context and
the provider captured at each call. A recursive mutex serializes those whole
calls with injector list scans/unlinks. It is never taken by a per-bound or
per-draw consumer, or held over mesh collection or cache I/O. Graph destruction
cannot clear the list while injected nodes exist because the injector holds
a strong graph reference. The native pool lock remains owned by the engine.

Both bridges are prepared transactionally at the existing pre-CRT barrier.
Before DeferredInit they forward without first-touching the recursive mutex or
its thread-local state. An atomic enroll-before-check counter tracks those
unguarded calls. DeferredInit verifies that both prepared callers still target
our bridges and publishes synchronization without code writes. The first
normal callback waits by returning and retrying until pre-publication calls
have completed; it holds no engine lock while doing so. There is no guessed
frame delay. A rollback survivor always retains its original provider.

### World identity and collection lifetime

The helper decodes xNVSE's four-byte integer presentation payload into the
existing host ABI scalar: zero normal, one loading, minus one unknown. It does
not treat that integer pointer as PostLoadGame's pointer-valued boolean. No
host export, configuration layout, event number or dashboard structure changed.
Other subsystems retain their existing event routing.

Loading/unknown presentations and pre-load/new-game/menu events only advance
the world epoch and mark reset pending. The next normal main-thread callback
retires the retained injection and cancels Rust generation/neighborhood state
before player/cell lookup, so menu cleanup does not require a live player.
An interrupted generation must match epoch, full cell key, cell address and
graph. The generator no longer stores a dereferenceable cell pointer: every
slice receives the current cell anew. Each slice holds one verified native
CellRefLock recursion level, released by RAII before selection/injection.
Identity is checked even when the cell address has not changed.

The lock protects reference-list membership, not arbitrary geometry writes.
Static mesh reads remain confined to the native main-frame boundary and the
existing admitted static/unskinned geometry contract. No worker walks a scene
graph. [Native lock entry](../analysis/radare2/output/occlusion_cell_lock_enter_20261104.txt)
and [leave](../analysis/radare2/output/occlusion_cell_lock_leave_20261104.txt)
have exact activation signatures.

### Surface coverage, caches and configuration

Zero projected area and nonfinite projected area are rejected both when
choosing near-face triangles and in point containment. Exact zero is used;
no arbitrary minimum area removes valid thin triangles or genuine shared
edges. The actual BlackVoid strip connector no longer supplies surface or
boundary-edge evidence. The complete asset still emits its four rectangles
and is unchanged by removing its zero-area connectors.

Cache revision 10 rejects the actual archived revision-9 cache even when its
plugin/configuration signature matches. This forces regeneration instead of
reusing pre-correction planes. The compact actual mesh and cache are preserved
with provenance in the module's `fixtures/` directory, so regressions no longer
depend on optional developer report paths. The owner subsequently requested
default-on behavior: shipped TOML, core and dashboard now agree, and explicit
false remains false. This default policy is separate from the ownership repair.

### Qualification and remaining uncertainty

The real archived-input baseline reproduced the connector containment,
near-face selection and cache-admission failures before production corrections.
Their production regressions now pass, including complete-surface preservation
and existing opening/coverage tests. The production phase decoder exercises
normal, loading, unknown, malformed-length and null payloads. Actual core and
dashboard parsers default on while preserving explicit disable.

Results and pre-edit artifacts are retained under
[offline qualification](../.reports/20261104-occlusion-stability/implementation/qualification.json).
The affected core/helper suites, supported 32-bit release build, formatting,
document checks and diff review passed. The
[compiled ABI capture](../analysis/radare2/output/occlusion_stability_candidate_abi_20261104.txt)
confirms both bridges preserve thiscall argument/stack cleanup, retain the
pre-DeferredInit direct-provider path, and release retired graphs after both
list guards. The existing host export retains its four-argument stdcall ABI
and forwards the phase scalar. The
[startup comparison](../.reports/20261104-occlusion-stability/implementation/startup-comparison.json)
against the pre-edit local artifacts found unchanged import sequences, TLS
layout and CRT initializers. That comparison is not a deployed-artifact match
or runtime startup acceptance.
Native graph switching, linked-plane clipping, continued gameplay, startup,
image correctness and frame-time/FPS behavior were not executed locally. The graph and
publisher changes are qualified by native contracts and compiled ABI review,
not mocks or reconstructed engine objects. The owner runtime-test waiver does
not convert those static results into gameplay observations. Agents have not
deployed or packaged artifacts, and the original incident writer remains unknown.

After the default-on change, the owner reported "no crashes" and requested
committing the fix. This is positive owner-reported runtime evidence. Session
duration, route, deployed artifact identity, transition coverage and performance
measurements were not supplied, so those details remain unverified.

## 12. Post-review correctness and performance plan

Status: implementation authorized after the review and plan, against baseline
`129fc60`. The earlier planning-only restriction is superseded by the owner's
instruction to proceed. Preserve the graph ownership and publisher synchronization
repair, normal main-thread admission, default-on setting, explicit disable,
shared plane cap and default neighbor radius. Improve work scheduling and
selection without reducing validated surface coverage to meet a timing target.
The existing task-specific runtime-test waiver remains recorded in section 11;
gameplay, image and FPS conclusions require observations, not offline timing.

### Baseline and evidence

Review established source-level errors in settle completion handling, semantic
identity, side-flag reuse, readiness/completeness, neighbor admission and repair
after injection failure. It also identified insufficient cache provenance and
numeric validation. Merge over-coverage remains a proof gap, not a reproduced
false cull. No additional release-before-unlink defect was established in the
new ownership code. Most generator/cache findings predate the ownership repair.

Correct the contradictory admission explanation in section 2.3 before changing
side policy. Verified `0x00B5AD91` ANDs the two predicate results;
`0x00B5AD98`/`0x00B5AD9B` turn false into state 2 and true into state 1.
The consumer at `0x00B5BC60` accepts state 1 only. The assertion that a visible
plane is admitted regardless of its side flag is not supported by this chain.
Preserve the review's native capture under `analysis/radare2/output/` before
implementing a policy change; do not infer another normal convention from the
erroneous paragraph. Correct affected module comments at the same time.

Use the existing production coverage and merge benchmarks to compare CPU work.
Run serial repetitions with identical inputs/settings; report mean ranges and
completion-frame costs separately. The 64x64 coverage workload has 4,225
vertices, exceeding production's 4,096-vertex admission limit: it is a component
stress probe, not an admitted complete mesh or a gameplay workload. Include the
actual archived mesh/cache fixtures, and obtain additional real affected assets
before qualifying new geometry cases. No FPS conversion or guessed time saving.

### Delivery order and owning files

| Phase | Outcome | Main ownership | Dependencies |
| --- | --- | --- | --- |
| 1 | Correct identities, completion, readiness and repair | `runtime.rs`, `data.rs`, `runtime_generate.rs`, `cache.rs` | Verified existing contracts |
| 2 | Less CPU/allocation for identical geometry results | `runtime_generate.rs`, existing geometry tests | Baseline outputs and tie rules |
| 3 | Resumable expensive stages and truthful timing | `runtime.rs`, `runtime_generate.rs` | Phases 1 and 2; collection lifetime proof |
| 4 | Validated persistent data with bounded persistence work | `cache.rs`, `runtime.rs`, source-validation boundary | Phase 1; verified source revalidation contract |
| 5 | Reuse immutable local mesh analysis | Generator/cache ownership | Phases 3 and 4 |
| 6 | More useful planes within the existing native budget | Selection, merge and injection ordering | Earlier phases; coverage and native consumer proof |

Each phase is independently reviewable. Qualify it before combining it with
the next behavioral change. Do not introduce new config fields, startup owners,
workers, per-bound hooks or ABI changes as incidental cleanup.

### Phase 1: correctness and recovery

- Compare full `CellKey` values for current and pending targets. Keep epoch,
  cell address and graph checks for in-flight work. A hash indexes candidates;
  it never establishes semantic identity. On the supported target, FxHasher's
  `usize` state is 32 bits even when `finish()` returns `u64`.
- Define a canonical plane descriptor for reuse/deduplication and verify its
  fields after hash lookup. Include the actual native side-policy boolean.
  Coverage 0.349 and 0.351 currently share a rounded key but select different
  flags. Separate native reuse equality from stability tolerances; retain a
  geometric tolerance only after its conservativeness is established.
- Replace the ambiguous generation/settle boolean with explicit outcomes for
  pending work, completed work and retryable failure. Consume completion on
  both immediate and multi-frame paths. Charge a settle attempt when its pass
  finishes, and stop future passes when the completed result is stable.
- Track scan termination, unavailable eligible 3D and budget truncation
  separately. Repeated empty/partial output does not prove source readiness.
  Budget-limited output must retain its provenance rather than claim a full
  scan. Preserve already validated coverage while incomplete work waits.
- Prove a stable enumeration/readiness contract for streaming references.
  Re-walking by ordinal cursor can skip references after relinking; holding
  CellRefLock during one slice does not stabilize the next slice. Select a
  verified membership/change signal or re-resolution scheme before replacing
  this traversal. Never retain borrowed list nodes across frames.
- Make neighbor records carry settled/validated status. Apply that status to
  both persistent-cache and previous-neighborhood reuse paths.
- Keep the desired plane set independently of successful native allocations.
  Retry a missing subset with bounded work and backoff, including when zero
  planes were injected. Do not regenerate meshes merely to repair injection.

Acceptance: execute the actual production Rust decisions offline wherever
possible. Confirm equivalent final behavior for immediate and sliced completion,
no lost completion result, side-policy changes never reusing the old flag,
distinct descriptors surviving hash collisions, no unsettled neighbor admission,
and desired-set recovery after failed allocation admission. Native allocation,
list mutation and streaming integration require verified contracts under the
owner waiver; fabricated engine objects/providers are not acceptance evidence.

### Phase 2: preserve output while reducing pure CPU work

- Replace the opening-recovery rectangle search's repeated top-row histogram
  sweeps with a single sweep and fixed stack storage. A 16x16 search currently
  executes 136 histogram-row passes and allocates a vector in each pass; one
  sweep needs 16 row passes. Preserve the selected rectangle's tie behavior
  explicitly, not just its maximum area.
- Reuse scratch storage in presence checking, injection diffing and generator
  restarts. Avoid rebuilding the unchanged neighborhood on every generation
  slice, particularly with radius zero. Scratch contains Rust-owned values,
  not cached native nodes or unretained geometry pointers.
- Prepare projected triangle data once per face instead of recomputing area
  and edge arithmetic for every containment query. Skip already-covered mask
  cells where the existing OR accumulation proves that equivalent.
- Reuse the scoring vector and squared distance where possible. Keep stable,
  explicit tie ordering; only use partial top-K selection if it preserves the
  chosen set and final order. Benchmark this separately from coverage work.
- Bound orientation-group construction as well as merge comparisons. Evaluate
  conservative orientation/plane-position candidate bucketing, with exact
  existing checks after lookup and proof that bucket boundaries omit no pair.

Acceptance: actual production extraction and opening tests preserve rectangles,
native side policy, holes and complete-asset coverage. Compare serial executable
benchmarks and deterministic operation/allocation budgets. A changed output or
tie rule is a semantic change requiring separate coverage qualification and
cache invalidation; it cannot be hidden in a performance-only patch.

### Phase 3: bound scheduling and account for complete frame work

Make collection, coverage, merging, selection and publication preparation
explicit resumable stages. Budget checks must occur inside expensive work,
not only after a complete reference. Include completion work in the same
scheduler; a completed collection must not trigger an unbudgeted merge/cache/
injection burst in that frame. Retain the current 1 ms setting as a soft target,
not a guarantee about operating-system scheduling or native destructor time.

Before changing collection lifetime, prove which current-cell operations keep
each geometry's data live and immutable. Copy bounded admitted mesh data into
Rust-owned snapshots at that boundary, then perform resumable CPU math after
releasing CellRefLock. Do not merely shorten the lock around unowned pointers.
Capture and memory budgets are part of this design, not an unbounded queue.
Discard stale snapshots/results using the existing world/cell/graph identity.

Keep native publication atomic with respect to its verified readers/publishers.
If native creation work needs staging, retain unpublished objects explicitly,
roll back partial construction and publish only the validated target set at the
safe boundary. Preserve graph release outside the publication/tracking locks.
Do not claim that graph destruction or a contended engine call is time-bounded.

Account separately for collection/lock wait, pure geometry, completion,
publication and persistence. Report actual-frame warnings using a cooldown
that advances on frames, and include completion in generation cost. Avoid
routine diagnostic allocation, logging or file writes on the frame path.

Acceptance: deterministic per-advance work limits, interruption at each pure
CPU stage, stale-result rejection and output equivalence on actual fixtures.
Compare total CPU and worst-slice timing; improving the maximum slice must not
silently multiply total work. Game-only lock wait, native integration and frame
timings remain unmeasured until separately observed.

### Phase 4: cache provenance, validation and persistence

- Validate finite positions, positive supported sizes, the native rotation
  contract and valid policy/confidence fields before native use. Establish
  numeric tolerances from generator/native evidence. Check aggregate encoded
  and decoded size/count budgets, not only per-cell counts.
- Separate immutable local geometry results from cached world placements.
  Prove source reference re-resolution and transform/material/geometry
  validation before reusing a world-space rectangle. Plugin names and sizes
  alone are insufficient for asset overrides or save-dependent changes.
  Define invalidation for changed or unavailable sources and merged provenance;
  a merged plane's first base-form ID cannot validate all its sources.
- Keep settled, pending and budget-limited provenance explicit. Revalidate
  source changes through a verified lifecycle/membership contract; do not
  invent a cell-ready flag, assume callbacks exist, or poll config per frame.
- Advance the cache revision when descriptors, readiness, provenance or
  extraction semantics change. Include all output-affecting choices in the
  signature. Reject actual older caches and regenerate validated coverage.
- Compute serialization capacity from actual entries and bound snapshot work.
  Evaluate incremental serialization before adding concurrency. Any offload
  uses a bounded immutable snapshot and one sequenced writer, activated only
  at the established post-DeferredInit boundary. Preserve atomic replacement,
  failure retry and newest-snapshot ordering. Revisit the previous reverted
  offload only after its retained failure evidence has been understood.

Acceptance: production decoder and file path tests with actual archived cache
inputs, invalid numeric records, truncation, failed replacement and schema
changes; source changes must invalidate affected world placements. Derive the
memory/file budget from repository VAS constraints and actual cache workloads
before implementation. Source lifetime, change notification and rotation
tolerances remain research gates, not assumed implementation details.

### Phase 5: reuse immutable mesh analysis

Reuse local bounds, support hulls and triangle-coverage results for repeated
geometry and settle passes. Key by validated geometry/content and extraction
semantics, not a raw engine address or base FormID alone. Keep world transform,
scale, material admission, horizontal rejection and native side policy at the
instance boundary. Own cached data in Rust, bound its memory, and invalidate
it when the verified source changes. No new worker is needed for this phase.

Acceptance: repeated real assets and different verified instance transforms
produce the same rectangles as direct production extraction. Measure cache
lookup/capture cost, CPU saved and memory retained; an optimization that only
moves an equivalent cost into content hashing is not qualified as a win.

### Phase 6: improve usefulness within the same native plane budget

After correctness and scheduling are qualified, evaluate these independently:

1. Retain a bounded, spatially diverse candidate reservoir, then reselect after
   meaningful observer movement with hysteresis. The current cache permanently
   loses candidates outside the initial observer's top set. Choose reservoir
   and refresh thresholds from actual workloads, not guessed constants.
2. Compare distance/area scoring with projected angular usefulness. The native
   bound consumer exits after a successful occlusion rejection, so useful
   ordering can reduce tested pairs. Prove any own-node reordering boundary;
   do not reorder authored nodes or churn native objects on every frame.
3. Recover additional solid rectangles around openings only when their marginal
   usefulness justifies their share of the existing cap. Every rectangle must
   retain the same surface-coverage proof as the current single result.
4. Qualify merge conservativeness before expanding merge coverage. The current
   gap, offset and angular tolerances need proof across repeated merges. Carry
   coverage provenance or establish a conservative geometric bound. Evaluate
   merging before final shrink only after that proof; do not fill an unproven
   gap to make a larger occluder.

Acceptance: real-asset opening, thin-surface, negative-scale and transformed-face
regressions; deterministic selection; stable native object reuse; unchanged
shared count budget. Native side policy stays as implemented until its complete
consumer contract is reverified. Broad-phase engine hooks, compressed formats,
larger caps/radii and off-thread engine traversal are outside this plan.

### Qualification and stop conditions

For each implementation phase, define the observable first and preserve an
unchanged failing result for confirmed behavior that can execute offline.
Exercise shipped Rust/native boundaries where available; do not replace native
integration with mocks, mirrored algorithms or source-order assertions. Use the
owner waiver and direct engine evidence for game-only boundaries, with those
limits stated explicitly. No game execution is requested as part of this plan.

Run focused regressions, affected core/helper suites, formatting, document/link
checks, `git diff --check` and the complete supported
`i686-pc-windows-gnu` release build after code changes. Recheck startup footprint
when a phase actually changes startup-visible state, imports, TLS, config or
workers. Pure Rust output-preserving changes do not require speculative new
engine research. Stop a phase when its acceptance evidence is sufficient.
Deployment and packaging remain user-only. Implementation results are recorded below.

### Implemented outcomes and remaining research gates

The current changes implement the correctness, owned scheduling and local-cache
work above. The native admission correction is supported by the preserved
[admission review](../analysis/radare2/output/occlusion_admission_review_20261104.txt).
The real archived WoodShack surface runs through the production owned pipeline,
cache codec and transformed-instance extraction. Decoder cases include actual
legacy cache input, nonfinite data, invalid indices, truncation and signature
changes. The real file path exercises replacement and failure cleanup. Evidence
and serial CPU probes are retained under
`.reports/20261104-occlusion-stability/post-review/`. Component stress inputs are
not gameplay or FPS acceptance.

Phase 6 was evaluated without changing geometric coverage or native ordering.
The reverified [native consumer](../analysis/radare2/output/occlusion_selection_review_20261104.txt)
walks forward and exits after a successful bound rejection. That establishes an
ordering opportunity, not a useful-order oracle for the supplied workload.
Reservoir/movement thresholds, projected scoring and additional opening rectangles
lack qualified real-workload evidence; no thresholds or coverage proof are
invented. Expanding merging remains blocked by its tolerance proof gap. These
proposals stay separate research work, with default cap/radius/side policy intact.
No guessed FPS gain, authored-node reordering or per-bound hook is introduced.

The earlier owner report of no crashes applies to the committed ownership repair.
New game-only image, streaming, native allocation repair, locking and frame/FPS
behavior is not run under the owner's standing waiver. Offline qualification does
not convert those unknowns into runtime acceptance. Arbitrary scripted live
geometry changes outside cell transition/revalidation remain an integration limit.

Offline qualification passed for the production regressions and file path,
affected core/helper suites, supported 32-bit release build, formatting, document
checks and final diff review. Startup imports, CRT initializers and normalized
TLS inputs match the retained baseline. Static/offline agreement does not prove
game startup, native integration, images or FPS. Deployment remains user-only.

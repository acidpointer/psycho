# Runtime occlusion-plane injection: implementation plan

Status: runtime mechanism, mod-resilient reference-count path and runtime
occluder collection implemented and enabled by default; in-game qualification
is not done. The collector accepts only uncompressed vertex data, builds each
geometry's box in local space and orients the faces by the live world transform,
fits every rectangle inside the vertices that support that face, skips
horizontal ground/roof faces, and keeps the engine's two-sided window only for
faces whose support rectangle nearly fills their vertex hull (an irregular face
stays one-sided). Planes are scored by
supported solid angle and cached per cell. Installing, removing, reordering or
updating a mod invalidates the cache through the plugin-list signature. This is
a heuristic and needs the owner's in-game visual check. No game run and no FPS
claim.
Companion to
[runtime visibility injection research](fnv_runtime_visibility_injection_research.md).
Address evidence is in
[runtime visibility injection contract](../analysis/radare2/output/fnv_runtime_visibility_injection_contract_20261017.txt).

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
8. rebuild: if the scene graph is unchanged, drop tracked planes whose node is
   no longer in the list (release the retained object) and diff the generated
   set against the remaining tracked set by quantized plane key. Unchanged
   planes stay linked; unmatched old nodes are unlinked in Rust and returned
   through `0x004A49E0(list, node)`; only new records are created. A changed
   scene graph means the old list is gone, so release every old plane without
   dereferencing retired nodes.
9. resolve the cell key: the persistent cache wins, then the runtime
   collector. Create, retain and append only the records that were not reused,
   then store the new `(scene_graph, key_hash, signature)`.

The scan is O(list length) and the list holds authored planes plus ours. It
runs on target changes and the bounded settle window, not every frame. A cell
change no longer requires the first frame to already have every reference's 3D
attached.

### 4.4 Data lookup

- Interior: `CellKey::Interior { form_id: u32 }`.
- Exterior: `CellKey::Exterior { worldspace: u32, x: i32, y: i32 }`.
- "Behave like exterior" interiors use the interior key.
- The generator returns a per-cell list of plane records. A per-cell cap
  (default 64) bounds the `B*O` pair cost.

### 4.5 Configuration

Add to `PerformanceConfig`:

- `occlusion_planes: bool` (default `true`, owner-requested);
- `occlusion_planes_max_per_cell: u16` (default 64, clamped `1..=256`);
- `occlusion_planes_cache_path: String` (default
  `syringe/psycho_occlusion_planes.cache`);
- `occlusion_planes_debug: bool` (default `false`). Also toggled in game with
  the `PsychoOcclusionDebug` console command.

Frame-path budget: the common frame does no hashing. The scene/cell pointers
are compared directly, and the cell identity hash (`FxHasher`) is only computed
when a pointer changes. The presence check runs every 30 frames and scans the
list once per tracked plane. The generator, cache lookups and file writes only
run on a target change or its bounded settle window.

Debug overlay: while `occlusion_planes_debug` is on, the core keeps the last
injected set and exposes it through `PsychoEngineFixes_QueryOcclusionDebug` as a
flat float frame (observer plus one rectangle per plane). The helper's
`PsychoOcclusionDebug` command toggles it and opens the dashboard, which draws a
top-down wireframe of each rectangle's world XY footprint using a new
`psycho-imgui` foreground-line primitive; the dashboard's navigation menu also
exposes an "Occlusion debug" checkbox for the same toggle. Once enabled the
overlay is drawn on every present, even after the dashboard window is closed,
until the checkbox or command turns it off. The query is pure (no engine calls
from the render thread) and reuses a thread-local buffer. The command never
prints through the console helper: `CommandContext::print` runs `print "..."`
via `RunScriptLine`, which re-enters xNVSE's non-re-entrant script parser from
inside the handler and reports a bogus "Mismatched quotes" error. The state is
logged and shown in the overlay instead.

Config parsing happens at startup and changes the DLL's static/config layout,
so the startup gate in section 7 applies.

### 4.6 Logging and diagnostics

Stable tag `[OCCLUSION_PLANES]`. Log at `info` on install and cache load; log
at `debug` the scan counters and per-cell summaries. The `scan` line reports
`refs`, `not_stat`, `render_null`, `node_null`, `radius`, `no_vertices`,
`horizontal`, `support`, `small`, `size`, `distance`, `faces`, plus `mesh_area`,
`rect_area`, `cap_drop`, `thin`, `low_cov` and `merge_ms`: the admitted surface
area, the merged rectangle area before the cap, the merged area the cap
dropped, the emitted faces each two-sided gate kept one-sided, and the time
spent in the quadratic coplanar merge. So the log shows how much solid surface
became occluders, whether the cap is the coverage limiter, which two-sided gate
is limiting, and whether the merge is the generation cost. The per-cell `cell`
line reports `key`,
`candidates`, `raw`, `injected`, `reused`, `removed`, `cap`, `two_sided`,
`cached`, `complete`, `gen_ms` and the observer position, and the `scan` line
includes `dist_max`, so a playtest can show which cell is being rebuilt, how
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

1. On a target change, walk `cell->objectList`; stop after a fixed reference or
   vertex budget.
2. Accept a reference whose base form is `TESObjectSTAT` or
   `BGSStaticCollection` and whose `parentCell` is null or the current cell.
   The collector reads the loaded 3D geometry, so the base-type gate only
   chooses what is worth walking. `BGSMovableStatic` is excluded because its 3D
   can move after the planes are created.
3. Resolve the loaded node. Reject it cheaply when the engine's world-bound
   radius is below the minimum.
4. Walk the node tree through the `IsNode`/`IsGeometry` virtuals. A transparent
   or skinned geometry is skipped individually. The `+0x9C` alpha pointer is
   trusted only when its vtable is `NiAlphaProperty`, so a shifted offset cannot
   reject the whole cell.
5. For each admitted geometry, read the uncompressed CPU vertices through a
   borrowed slice and reduce them to a **local** AABB. The slice read lets the
   compiler vectorize the copy; the reduction is a four-wide SIMD min/max
   (`wide`, portable SSE/AVX/NEON with a scalar fallback). Geometry whose
   vertices are compressed, unavailable or over budget is skipped; a sphere
   bound is never turned into a rectangle. Each geometry is treated on its own
   (never merged across an object), so a multi-part object contributes tighter
   boxes.
6. Reject a geometry whose world-space largest extent is outside
   `256..=8192` units.
7. For each local face, collect the vertices within 5% of that face and build
   their 2D convex hull. Fit the largest axis-aligned rectangle supported by
   the hull: a centered binary search plus a bounded 16x16 occupancy grid when
   the centered rectangle is missing or clearly smaller. Reject the face when
   the rectangle cannot cover at least 5% of the face. Skip faces whose world
   normal is nearly vertical (`|normal.z| >= 0.8`), which removes ground and
   roofs.
8. Emit the surviving face rectangle:
   - position: the supported rectangle center on the local face plane,
     transformed to world and offset outward by two units along the geometric
     outward normal;
   - size: supported in-plane extents scaled by the node's world scale,
     multiplied by a final `PLANE_SHRINK` (0.8); `create_plane` halves them for
     the native half-extent fields;
   - rotation: row-major matrix whose columns are the world tangent, the
     **inverse** of the geometric outward normal, and `tangent x normal` as the
     bitangent. `0x00C358A0` activates the plane on the stored normal's negative
     side, so the inverse normal selects the outward side. The engine spans
     local X/Z and takes local Y as the rectangle normal.
9. Merge coplanar rectangles whose in-plane union is exactly a rectangle: same
   stored normal, same plane offset within 1 unit, aligned in-plane axes, and
   either one contains the other or they share a full in-plane interval and
   touch/overlap in the other. The merged rectangle is the union of two
   support-validated rectangles, so it cannot cover empty space. This raises
   culling per plane and lowers the `B*O` pair cost.
10. Apply the observer distance filter, score each rectangle by supported solid
    angle (`area / (1 + (distance/2048)^2)`), sort, and cap at
    `occlusion_planes_max_per_cell` (default 64). The `scan` line reports
    `cap_drop` (merged area dropped by the cap).
11. Set `+0xEA` on the created object from the face's side confidence: keep the
    constructor's two-sided window for a face at or above
    `TWO_SIDED_COVERAGE` (0.35) whose mesh is also at least `MIN_FACE_THICKNESS`
    (16 units) thick along the face normal, and clear it otherwise. The coverage
    floor only rejects a strongly non-rectangular hull; the thickness condition
    is the one that excludes thin one-sided panels. With `+0xEA` clear,
    `0x00C358A0` activates the plane only while the camera is on the rectangle's
    outward side; both paths need no per-frame Rust work and reverse
    automatically when the camera moves around the object.

### 5.2.1 Limits and risks

The collector uses the vertex support hull, not a collision or silhouette
proof. A convex hull around a concave mesh can still over-cover empty space,
and the support fit is computed in the mesh's local axes. The mitigations are
the per-geometry oriented box (never merged), the vertex support fit, the
horizontal-face rejection, the size threshold, the final
`PLANE_SHRINK`, the support-coverage gate, the thin-panel thickness guard, the
per-cell cap and the kill switch. A silhouette-accurate extraction from
`NiTriShapeData` was prototyped but its in-memory triangle list is not yet
verified against the running game, so it is not enabled. Geometry with
compressed vertices is currently skipped, which may reduce coverage in cells
that rely on compressed meshes. The owner's in-game visual check remains
required.

Two residual false-cull classes are documented and not closed:

- **Concave faces.** The support hull is convex, so a window or a notch inside
  the face is still covered by the emitted rectangle. Both the one-sided and
  two-sided paths cull through it. Closing this needs triangle coverage, which
  is blocked on the `NiTriStripsData` layout (the Fairfax population is
  `NiTriStrips`, not `NiTriShape`, which is why the earlier triangle prototype
  produced zero candidates).
- **One-sided meshes.** A mesh rendered with backface culling can be invisible
  from its back, where a two-sided window would false-cull. The thickness guard
  excludes the common thin panel/facade case, but a thick one-sided mesh is not
  distinguished without the mesh's stencil/backface flag. Research so far: the
  `NiStencilProperty` vtable is `0x0101e07c`, its flags word is at `+0x18`
  (constructor default `0x4180`), but the bit that means two-sided and the path
  from a live `NiGeometry` to its stencil property are not yet closed, so the
  guard stays a thickness heuristic.

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

The runtime now diffs the generated set against the tracked set using the same
quantized per-plane key. Unchanged native planes stay in the list, only changed
planes are removed, and only new planes are created. A missing node found by
the presence check is released and recreated by the same diff. This avoids the
one-frame cull flip caused by removing and re-adding the whole list on every
settle pass. The cache schema version is 8 and each entry carries a completion
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
| False culling through windows/gaps | Vertex support fit, oriented faces, horizontal-face rejection, size limits, support-coverage gate that keeps an irregular face one-sided, shrink margin, owner visual check |
| Camera-side sign is wrong | The contract test proves the current corner order; a wrong sign deactivates the one-sided plane from the intended side and must be caught by the owner's visual check |
| `B*O` pair cost outweighs savings | Per-cell cap of 64 by default, support-coverage gate, measure, add broad phase if needed |
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
- The triangle list offsets (`+0x44`/`+0x48`) are proven by the engine's field
  writer, but the runtime does not read the triangle list (a prototype produced
  zero candidates and a frame-time regression in the owner's 2026-10-18 run),
  so the current collector uses the vertex support hull.
- Geometry with compressed vertices is skipped. Verify the compressed vertex
  layout before reading it or before adding an offline data path for those
  meshes.
- A cell-change pass now retries a bounded settle window, but a reference whose
  3D never attaches before the window closes is still missed. An entry that did
  not settle is marked incomplete and regenerated on the next visit. The window
  and interval are `SETTLE_RETRIES`/`SETTLE_INTERVAL_FRAMES` in `runtime.rs`.
- Confirm in the next playtest that the `key` and `complete` fields stop the
  same-second `cell` alternation, and use `gen_ms` to measure per-cell
  generation cost. `TARGET_STABLE_FRAMES` can be tuned if a genuine fast cell
  change is delayed too long.
- If a cell still yields too few candidates, the `scan` debug counters
  distinguish an empty `objectList` (`refs=0`) from a rejected population
  (`parent_mismatch`, `not_stat`, `render_null`, `node_null`, `radius`,
  `no_vertices`, `size`, `horizontal`, `support`, `small`, `distance`). Use
  that line before changing any offset.
- The feature ships enabled by the owner's request; the in-game A/B, false
  culling check and startup playtest remain the release gates.

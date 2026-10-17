# Runtime occlusion-plane injection: implementation plan

Status: runtime mechanism, mod-resilient reference-count path and runtime
occluder collection implemented and enabled by default; in-game qualification
is not done. The collector extracts large, fully covered coplanar surface
patches from live `NiTriShape` meshes, so planes sit on real solid geometry and
do not false-cull visible objects. No data file is required; the TOML file
remains an optional per-cell override. This is a heuristic and needs the owner's
in-game visual check. No game run and no FPS claim.
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
- an offline generator that emits per-cell plane data in the same axis-angle
  representation the engine uses for authored `XOCP`;
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
   half-extent X/Y; the TOML/runtime size is the full extent and is halved at
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
rotation matrix. This matches the observed payloads, e.g. `(0,0,1,1.5708)` is
a 90-degree rotation about +Z. The axis-angle representation is the generator
contract.

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
flag is set, which it is for planes created through `0x00C335D0`. The rectangle
therefore behaves as a window: the occluded volume is the pyramid from the
camera through the rectangle, and the stored normal sign does not select the
side. The owner's visual check remains required.

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
        |                    optional per-cell TOML override
        v                    /
psycho-engine-fixes  <------/
  performance.occlusion_planes=true
  performance.occlusion_planes_runtime=true
  perf::observe_event -> occlusion_planes::observe_event
        |
        v
  DeferredInit  : ready, lazy override read
  OnFramePresent: reconcile(player, cell, scene_graph)
  load/new/exit : clear and release
        |
        v
  native BSOcclusionPlane in scene_graph+8
```

No native code is patched. The module only calls verified getters/constructors
and manages its own planes. The runtime collector reads the loaded cell's
reference list and node transforms; the TOML file is only an optional
per-cell override.

## 4. Runtime module design

### 4.1 Files

- `psycho-engine-fixes/src/mods/perf/occlusion_planes/mod.rs` - install,
  config, event routing, logging.
- `.../occlusion_planes/contract.rs` - addresses, byte signatures, ABI types,
  capability checks and live-scene offsets.
- `.../occlusion_planes/raw.rs` - volatile engine-memory readers.
- `.../occlusion_planes/data.rs` - optional override parser, cell keys and
  plane records.
- `.../occlusion_planes/runtime_generate.rs` - live cell occluder collection
  and conservative face-rectangle generation.
- `.../occlusion_planes/runtime.rs` - lifecycle state, creation, insertion,
  scanning, removal, release.
- `.../occlusion_planes/tests.rs` - pure-logic tests for the override parser,
  cell keys, capping and the box-to-face transform.

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
   cell.
5. if the target is unchanged and no settle retry is pending, return.
6. a target change (or load/new/exit reset) forces a rebuild and restarts the
   settle window; a settle retry regenerates only every few frames and rebuilds
   only when the generated set changed.
7. rebuild: if the scene graph is unchanged, scan `scene_graph + 8` for nodes
   whose `+8` equals a tracked plane; unlink each node in Rust and call
   `0x004A49E0(list, node)` to return it to the native pool. A changed scene
   graph means the old list is gone, so skip the unlink. Release all tracked
   planes.
8. resolve the cell key: a per-cell override wins; otherwise the runtime
   collector supplies planes. Create, retain and append each plane, then store
   the new `(scene_graph, key_hash, signature)`.

The scan is O(list length) and the list holds authored planes plus ours. It
runs on target changes and the bounded settle window, not every frame. A cell
change no longer requires the first frame to already have every reference's 3D
attached.

### 4.4 Data lookup

- Interior: `CellKey::Interior { form_id: u32 }`.
- Exterior: `CellKey::Exterior { worldspace: u32, x: i32, y: i32 }`.
- "Behave like exterior" interiors use the interior key.
- The lookup returns a slice of plane records. A per-cell cap (default 16)
  bounds the `B*O` pair cost.

### 4.5 Configuration

Add to `PerformanceConfig`:

- `occlusion_planes: bool` (default `true`, owner-requested);
- `occlusion_planes_runtime: bool` (default `true`);
- `occlusion_planes_max_per_cell: u16` (default 32, clamped `1..=256`);
- `occlusion_planes_path: String` (default
  `syringe/psycho_occlusion_planes.toml`).

Config parsing happens at startup and changes the DLL's static/config layout,
so the startup gate in section 7 applies.

### 4.6 Logging and diagnostics

Stable tag `[OCCLUSION_PLANES]`. Log at `info` on install, data load success
and per-cell add/remove summaries; log at `debug` per-plane details. Counters:
cells seen, planes created, planes active (`+0x40 == 1`), removals, scan hits,
allocation failures. Route through `libpsycho::logger::Logger` / `log`, never
`println!`. Optional diagnostic mode may hook `0x00B5BBE0`/`0x00B5AC90` to
count native pairs and rejections; it is a separate, config-gated build aid and
must not alter behavior.

### 4.7 Failure containment

- If any signature or executable check fails, disable the module and keep the
  native list untouched.
- If the data file is missing/corrupt, log and run with no planes.
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
- The `IsNode` (`vtable+0x0C`), `IsGeometry` (`vtable+0x18`) and `IsTriShape`
  (`vtable+0x24`) virtuals.
- `NiGeometry` alpha (`+0x9C`), model data (`+0xB8`) and skin (`+0xBC`)
  pointers.
- `NiGeometryData` vertex count (`+0x08`), vertex pointer (`+0x20`) and
  compression flags (`+0x39`).
- `NiTriShapeData` triangle index count (`m_uiTriListLength`, `+0x44`) and
  index pointer (`m_pusTriList`, `+0x48`).

### 5.2 Pipeline

1. On a target change, walk `cell->objectList`; stop after a fixed reference,
   vertex and triangle budget.
2. Accept a reference whose base form is `TESObjectSTAT` or
   `BGSStaticCollection` and whose `parentCell` is null or the current cell.
   The collector reads the loaded 3D geometry, so the base-type gate only
   chooses what is worth walking. `BGSMovableStatic` is excluded because its 3D
   can move after the planes are created; the override file can still target
   its cells.
3. Resolve the loaded node. Reject it cheaply when the engine's world-bound
   radius is below the minimum.
4. Walk the node tree through the `IsNode`/`IsGeometry` virtuals. A transparent
   or skinned geometry is skipped individually. The `+0x9C` alpha pointer is
   trusted only when its vtable is `NiAlphaProperty`, so a shifted offset cannot
   reject the whole cell. Only `NiTriShape` meshes with readable, uncompressed
   vertices and a triangle list are used (`NiTriStrips` has no verifiable
   silhouette and is skipped).
5. Transform the mesh vertices to world space and cluster the triangles into
   coplanar patches (normal within `CLUSTER_NORMAL_DOT`, plane distance within
   `CLUSTER_DISTANCE_TOLERANCE`).
6. For each patch, project it into its plane and take the **largest
   all-covered sub-rectangle** of a `COVERAGE_GRID x COVERAGE_GRID` grid. This
   is what keeps the plane on real surface: an axis-aligned AABB or a concave
   facade no longer becomes a plane over empty space, a rotated wall is
   represented by its own plane, and a window or courtyard yields a smaller
   solid rectangle.
7. Reject a patch whose solid rectangle has an extent below `MIN_FACE_EXTENT`.
8. Emit one rectangle per patch:
   - position: rectangle center, then offset outward by a small epsilon along
     the patch normal;
   - size: full rectangle extents shrunk by `PLANE_SHRINK`; `create_plane`
     halves them for the native half-extent fields;
   - rotation: row-major matrix whose columns are the in-plane tangent, the
     patch **normal**, and the bitangent (the engine spans local X/Z and takes
     local Y as the rectangle normal).
9. Apply the observer distance filter/weight, score by patch area, sort, and
   cap at `occlusion_planes_max_per_cell`. A cell listed in the TOML override
   uses those records instead of the runtime set.

### 5.2.1 Limits and risks

The collector emits planes only on surface patches that are fully covered by
their own triangles, so an axis-aligned box or a concave facade no longer
becomes a plane over empty space and the false culling that caused object
popping is removed. Remaining risks: the coverage grid is coarse, so a patch
with a small hole can still pass; a patch can be a thin solid strip; and a mesh
that moves after generation would leave a stale plane (the base-type filter
excludes movable statics). The mitigations are the per-patch solidity test, the
size threshold, the plane shrink, the distance range, the per-cell cap and the
kill switch. The owner's in-game visual check remains required.

### 5.3 Data file

Implemented format: TOML, parsed with `serde` and `toml`, default path
`syringe/psycho_occlusion_planes.toml` relative to the game directory. TOML is
used for the early hand-authored phase because it is reviewable and matches the
repository's config tooling. A binary form is a later optimization only if
file size or parse time becomes material.

```toml
[[cells]]
kind = "exterior"
worldspace = 0x0000003C
grid = [-3, -12]

[[cells.planes]]
position = [x, y, z]      # world-space rectangle center
size = [width, height]    # full rectangle width/height (native fields are half)
axis = [ax, ay, az]       # unit axis, or all zero for identity
angle = radians           # rotation about `axis`
priority = 255            # higher survives the per-cell cap

[[cells]]
kind = "interior"
cell = 0x0003C944
```

Validation rejects unknown kinds, missing identity, duplicate keys,
non-finite values, non-positive sizes, a non-unit axis when the angle is
nonzero, and a zero axis with a nonzero angle. Records are sorted by descending
priority and capped at `occlusion_planes_max_per_cell`. The runtime records a
generator version and a target-cell list in the file header, not a game DLL
hash. The shipped file has an empty `cells` array until data is generated.

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

**Phase 2 - Runtime module with hand data.**
Implement the module, parser and lifecycle against a small hand-authored
dataset. Unit-test the pure logic; run the real-runtime gate for the engine
calls.

**Phase 3 - Offline generation.**
Extend the NIF/record tooling, generate conservative data for the seven Fairfax
exterior groups, validate offline, then run the A/B in game.

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
  * localX +/- sizeY * localZ`); solid-patch extraction and negative-scale
  transform tests pass;
- atomic `NiRefObject` increment/decrement and `DeleteThis` dispatch exercised
  by a focused test; node ownership remains as above;
- alpha-admission, base-type admission and plane-set-signature helpers covered
  by focused tests; the `+0x9C` alpha pointer is vtable-gated so a shifted
  offset fails open;
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
| False culling through windows/gaps | Conservative placement, shrink margins, offline oracle, Phase 1 visual check |
| `B*O` pair cost outweighs savings | Per-cell cap, start with few planes, measure, add broad phase |
| List reset/duplicate planes | Scan-and-reconcile by plane pointer; never clear the whole list |
| Refcount/list ownership error | Increment the `NiRefObject` count once per plane; decrement only after node removal or scene-graph replacement |
| Startup compatibility regression | Defer all work to DeferredInit; owner Proton playtest |
| Data staleness after load-order changes | Generator version and regeneration step; runtime does not inspect mods |
| Event timing during visibility pass | Phase 1 verifies `ON_FRAME_PRESENT`; fallback to CellTransitionOrchestrator |
| Config/data path errors | Path next to the DLL or explicit config; missing file disables cleanly |

## 9. Open items

- Confirm `ON_FRAME_PRESENT` occurs at a quiescent point relative to
  `0x00B5AC90`/`0x00B5BBE0`; otherwise use the CellTransitionOrchestrator hook.
- Confirm the engine's list behavior on cell unload; the design is independent
  but the log should record scan misses.
- The triangle list offsets (`+0x44`/`+0x48`) are proven by the engine's field
  writer, but the in-game silhouette quality of the solid-patch extraction still
  needs the owner's visual check, and a mesh type not covered by `IsTriShape`
  contributes no planes by design.
- A cell-change pass now retries a bounded settle window, but a reference whose
  3D never attaches before the window closes is still missed. The window and
  interval are `SETTLE_RETRIES`/`SETTLE_INTERVAL_FRAMES` in `runtime.rs`.
- If a cell still yields too few candidates, the `scan` debug counters
  distinguish an empty `objectList` (`refs=0`) from a rejected population
  (`parent_mismatch`, `not_stat`, `render_null`, `node_null`, `radius`,
  `no_mesh`, `triangles`, `clusters`, `cluster_area`, `coverage`, `size`,
  `distance`). Use that line before changing any offset.
- The feature ships enabled by the owner's request; the in-game A/B, false
  culling check and startup playtest remain the release gates.

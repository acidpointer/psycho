# FNV/OMV shadow diagnostics and playtest evidence

This document owns the lightweight, opt-in dynamic-shadow diagnostics and the
evidence gathered from gameplay sessions. It is the entry point for keeping
future performance work evidence-driven without a dedicated instrumentation
build. The engine mechanics and invariants live in
`docs/graphics_fnv_nvr_shadows_engine_contract.md`; this file does not repeat
them.

## Enabling the lightweight log

Enable it in game: `Shadows` panel -> `DIAGNOSTICS` -> `Lightweight shadow log`.
It persists as `graphics.native_shadows.debug_logging` in
`Data/NVSE/plugins/omv/omv.toml`.

The toggle is self-contained. It emits one `INFO` summary per second while the
dynamic-shadow producer runs and never changes rendering. It does not require
`[diagnostics].debug_log` (that unrelated master flag raises the whole logger to
`Debug`).

## Summary field reference

`[SHADOWS] Producer summary per <ms>ms: ...`

| Field | Meaning |
|---|---|
| `transactions` | Producer transactions in the interval (one per rendered frame that reached map production). |
| `dirty_lights` | Selected lights with at least one face scheduled this interval. |
| `moving_lights` | Subset whose point source moved (exact-coherence full rebuild). |
| `rebuilt_faces` | `RebuildPublished` faces: clear + current static roots + current actors in one pass. |
| `refresh_faces` | `RefreshStatic` faces: the retained static backing changed. |
| `publish_faces` | `PublishStatic` face copies from the retained static backing. |
| `merge_faces` | `MergeAnimated` actor merges over retained static depth. |
| `root_all_changed` | Transactions whose all-roots static root-set signature changed. |
| `root_nolod_changed` | Transactions whose non-object-LOD static root-set signature changed. |
| `moving_position` | Moving lights whose change was position-only. |
| `moving_radius` | Moving lights whose change was radius-only (for example an animated/flickering source). |
| `moving_both` | Moving lights whose position and radius both changed. |

Interpretation:

- `moving_lights ~ dirty_lights` with high `rebuilt_faces` means point sources
  move every frame; this is the exact-coherence cost, not caster churn.
- `refresh_faces` scaled by caster count means a movable static object
  invalidates a cached face and forces a whole-face static rebuild.
- `merge_faces` with no `rebuilt_faces`/`refresh_faces` is pure actor churn and
  is what the actor pose delta should suppress for stationary, unanimated
  actors.
- `transactions > 0` with all face counts `0` means the producer ran without
  drawing (should be near zero once the pose delta lets idle scenes take the
  zero-D3D republish route).

## Session record: 2026-10-16

Environment: FNV through Proton, gameplay 16:09:27-16:17:40 UTC, main target
3440x1440. Raw log preserved at
`.reports/2026-10-16-shadow-diagnostics-playtest.log`.

Deployed configuration (from the live `omv.toml`):

- dynamic shadows High (512-square cube faces), `interior_shadowed_lights = 16`
  (raised from the shipped 12).
- `sun_shadows = false`; `directional_occlusion = "screen_space"` (shipped
  default).
- volumetric lighting High, local lights High.
- `debug_logging = true` (enabled by the tester for this session).

Shadow lifecycle events:

- `Deferred route installed` with the values above; complete shader family
  prepared in 4561 ms.
- Point-light resource family grew with nearby-light demand:
  `1 -> 7 -> 8 -> 9 -> 16` lights, retained bytes `13.0 -> 85 -> 97 -> 109 ->
  193 MiB` at High/512. This confirms capacity tracks selected demand and that
  a dense scene reached the full 16-light budget.
- `exterior maps produced ... (1 shadowed point lights)` and, later, the same
  interior event reported only one selected light, while a later frame reached
  16. Light selection count varies strongly within one session.
- One `Experimental sun resources ready (4 x 2048 EVSM4 cascades, 4x sampling)`
  event occurred near the start. The final persisted configuration keeps
  `sun_shadows = false` and `directional_occlusion = "screen_space"`, so this
  corresponds to a temporary World-cascades selection during the session. This
  is an inference: the log did not yet carry the requirement flags, which were
  added afterward (see below) to remove the ambiguity.

Atmosphere configuration observed:

- full 3440x1440, reduced target half-resolution 1720x720, shaft field 860x360.
- fog and directional lighting both active, fog `samples = 12`, shaft
  `samples = 40`, TAA active.
- directional sun present (`sun=true`); fog/dispersion otherwise steady across
  the session.

World-pipeline health (unrelated effects included for context):

- `presents` advanced from 4800 (16:10:48.878) to 38400 (16:17:40.655): 33600
  presents over 411.8 s, i.e. about 82 presents/s on average. This is a present
  rate, not an isolated FPS measurement, and no shadow on/off comparison was
  captured.
- depth-resolve cache hits 24152 of 32246 coherent resolves (about 75%);
  zero counted failures across the session.

## What this session established

- The decoupling controls ship and persist: the live config carries
  `directional_occlusion = "screen_space"` and `debug_logging`, so the
  Workstream A default and the diagnostics toggle are deployed.
- The point-resource family correctly tracks selected-light demand and reached
  the 16-light budget in a dense scene at High/512.
- No producer face-count summary appeared. The cause was diagnostic, not
  behavioral: the summary was emitted with `log::debug!`, and the logger runs at
  `Info` by default, so it was filtered. The emission was corrected to `info`
  and the shadow menu-settings line now records `debug_log`.

## Session record: 2026-10-16b (producer summary live)

Environment: same installation, gameplay around 16:46-16:58 UTC, 3440x1440,
main target. Raw log preserved at
`.reports/2026-10-16b-shadow-producer-summary-playtest.log`.

`[FNV WORLD] Requirements updated: world_depth=true, world_color=true,
temporal_aa=true, directional_shadows=false` — the screen-space volumetric
default does **not** request the cascade producer. This directly confirms the
Workstream A decoupling.

The producer summary produced 138 one-second intervals in this snapshot
(`transactions ~95/s`). Aggregate: `dirty_lights` about 8.6 per transaction,
`moving_lights` about 35% of dirty lights, `rebuilt_faces ~21/txn`,
`refresh_faces ~23/txn`, `publish_faces ~24/txn`, `merge_faces ~4.9/txn`.

Three regimes are clearly visible:

1. **Idle (9 intervals):** `dirty_lights=0` and every face count `0`. The
   producer still ran (~120 transactions/s) but drew nothing. This validates the
   PC1 actor pose delta: a stationary, unanimated actor scene takes the
   zero-D3D republish path instead of remaking actor faces.
2. **Moving point lights (113 intervals):** `moving_lights` up to hundreds per
   second with `rebuilt_faces` in the thousands, while `refresh_faces` is low.
   Each moving selected light forces a complete six-face rebuild including every
   intersecting static caster.
3. **Static churn (16 intervals):** `moving_lights=0` yet `refresh_faces` and
   `publish_faces` reach about `96 x transactions` — that is all 16 selected
   lights times all six faces rebuilding **every frame**. Here the retained
   static face cache is fully defeated: the whole static caster set is re-drawn
   for every light every frame. This is the direct "many casters are expensive"
   cost.

The `moving_lights` share (~35% of dirty lights per transaction) is far higher
than world lamps should produce and is the surprising result of this session.
The summary now classifies each rejection as `moving_position`, `moving_radius`,
or `moving_both` so the next capture can separate real motion from a radius-only
change (for example a flickering torch, or a light position that is re-derived
with floating-point noise every frame). The static-churn regime is likewise
now attributed through `root_all_changed` versus `root_nolod_changed` to tell a
churning object-LOD root (one huge-bound root that can follow the camera) apart
from generic movable statics.

## Session record: 2026-10-16c (after object-LOD exclusion)

Environment: same installation, gameplay around 18:11-18:18 UTC, 3440x1440. Raw
log preserved at `.reports/2026-10-16c-shadow-lod-exclusion-playtest.log`. 245
intervals, 22330 transactions.

- `directional_shadows=false` again. The screen-space volumetric default still
  never requests the cascade producer.
- **All moving-light rejections are position changes.** Totals:
  `moving_position=48743`, `moving_radius=0`, `moving_both=0`; `moving_position`
  equals `moving_lights` in 244 of 245 intervals. Radius is perfectly stable
  across the session, so radius-only reuse (an earlier candidate) would do
  nothing and is dropped.
- **The pathological all-face static churn is gone.** `refresh_faces` per
  transaction: median 4.26, p90 9.31, max 28.5, and only 3 intervals above 20.
  The previous session's regime of `96 x transactions` (all 16 lights x 6 faces
  every frame) did not recur. Object-LOD exclusion is the plausible cause; the
  scene also differed, so this is reported as a strong result rather than a
  controlled before/after.
- **Moving lights are now the dominant remaining cost.** `rebuilt_faces` per
  transaction: median 6.15, p90 30, max 36; 84 intervals above 20. `rebuilt` is
  the exact-coherence six-face rebuild for a point source that translated this
  frame.
- A non-LOD static root still changes every transaction
  (`root_all_changed == root_nolod_changed == transactions` in 231 of 245
  intervals) but now affects only a few faces per transaction, so it is a small
  local movable rather than a global invalidator.

## Resolution status

- **Shipped and effective:** object-LOD roots are excluded from point cube
  casters, in the same way landscape already is. The 2026-10-16c session shows
  the all-16-lights static churn did not recur (refresh median 4.3 vs the prior
  `96 x transactions`), at the cost of nothing observable. Offline-qualified by
  the planner contract tests.
- **Dropped — radius-only cube reuse:** radius never changed across 22330
  transactions, so this optimization has no target.
- **Shipped — region-scoped static refresh (PC4):** the producer retains each
  static caster root's world state and scopes a face's static clear, re-render,
  and publish copy to the union of the changed roots' old and new projected
  regions when the face's static mask is partial (proving the backing was
  complete). Any add/remove, missing bound, overflow, full mask, or empty region
  falls back to a full-face rebuild. This removes the casters-per-face
  multiplier for localized movable statics without changing any pixel the full
  render would have produced.
- **Shipped — cross-face caster amortization (C1):** the producer now walks
  each light's hierarchy once, records every admitted caster with its touched-
  face mask, and submits the records per dirty face instead of re-traversing the
  same subtrees six times. No pixel change; the mask is the exact disjunction of
  the six per-face predicates with preserved ancestor pruning. Offline-
  qualified; see `docs/graphics_fnv_shadows_performance_plan.md`.
- **Shipped — per-face projected-size caster minimum (C2):** the fixed 0.5
  world minimum is raised to `0.5 * cube_radius / resolution` when larger, so a
  large-radius light drops sub-texel casters from both the retained signature and
  the render. Quality-neutral by construction; offline-qualified.
- **Fixed — multibound ownership on the cross-face path:** C1's node admission
  read the `BS_MULTIBOUND` field (`+0xAC`) without first confirming ownership
  through the engine's multibound-node virtual, so an ordinary `BSFadeNode` on
  save load had its unrelated non-null field dereferenced as a shape pointer and
  faulted. The read is now gated exactly as the retained directional traversal
  does, and the offline regression reproduces the original fault when that gate
  is removed. See `docs/graphics_fnv_nvr_shadows_engine_contract.md`.
- **Next target — moving point lights (PC5):** `rebuilt_faces` from point
  sources that translated this frame is the dominant local-shadow cost
  (p90 30/txn, up to six moving lights). Each rebuild re-renders every caster
  into all six faces. Because the cube is sampled only at directions of visible
  lit receivers, the quality-preserving lever is to avoid rendering cube
  coverage no visible receiver samples, not to drop lights. See the moving-light
  optimization proposals below.

## Moving point-light cost: optimization research

Direct-source facts (no guessing):

- `shadow_cube.hlsl` stores `depth = saturate(length(LightPositionRadius.xyz -
  world.xyz) / radius)`; a moved light changes that value in every texel.
- `shadow_point_accumulate.hlsl` samples the cube only in the direction
  `toLight = lightPos - world` of each **visible**, in-radius, front-facing
  surface. The cube is never read at a direction no visible lit receiver
  points at.
- A moved selected light runs `RebuildPublished`: all six faces cleared, every
  intersecting static root and actor re-submitted.

### Frame-ordering constraint (decisive)

The producer runs at the common shadow hook, inside the world render, before
the pre-alpha depth resolve and before the world geometry samples the cube
(`fnv_render.rs:621,718`; `fnv_world_pipeline.rs:281`). The depth provider is
acquired only in the consumer (`pipeline.rs:4387,4411`). The receiver positions
are the world geometry itself, which cannot be drawn until the cube exists.
Therefore the producer cannot know the current frame's visible receivers:
receiver-driven face/tile culling and fully-occluded-light culling would need
either an engine depth prepass or a one-frame-lag mask, and a stale mask can
omit a newly sampled face, which would show a stale shadow. Those options are
recorded as researched-and-blocked, not implemented, because they cannot be
done without a quality regression or an engine change.

### Plan (quality-preserving, same-frame)

1. **Cross-face caster traversal amortization (CPU).** For one light, walk the
   hierarchy and build the touched-face set once, then render each face from
   that set, instead of six independent `traverse_root` passes. The cube culling
   predicate is already per-bound: `object_bound_within` tests
   `sphere_intersects_point_light` and then `sphere_intersects_cube_face(face)`,
   so a per-object face mask is `sphere_intersects_point_light(bound) ?
   fold(face -> sphere_intersects_cube_face(...)) : 0`, identical to the six
   per-face tests. Classification is already memoized per transaction; the
   repeated cost is the hierarchy walk and per-face bound tests, which this
   removes. No GPU or pixel change.
2. **Per-face projected-size caster minimum.** Extend the existing
   `minimum_radius` admission to a projected pixel threshold at the cube face
   (`pixels * cube_radius / resolution`), applied identically to the static
   signature, masks, and render, so sub-pixel casters of a moved light are
   neither drawn nor able to invalidate a cached face. Quality-neutral by
   construction (sub-pixel geometry is not resolvable in the map), and it
   reduces both CPU and GPU for dense scenes.
3. **Fixed per-face cost trim.** `configure_generation_state` and the face
   baseline are re-set per face; hoist what is provably invariant across the
   faces of one light and cache the face surfaces (already done). Minor.

Ordering: (1) first (safe CPU, no pixel change), then (2).

### Proposal 1 implementation sketch

- `render.rs`: split traversal from submission. A new
  `collect_point_faces(context, root, scratch, out: &mut [CasterList; 6])` walks
  the hierarchy once, computes each node/geometry touched-face mask from the
  existing `sphere_intersects_point_light` + `sphere_intersects_cube_face`
  predicate, prunes subtrees whose mask is zero, and appends a compact record
  (geometry pointer, classification bits, camera-relative world matrix) to each
  touched face's list. The existing `draw_geometry` submission body becomes
  `submit_caster(context, record, face)`, called once per list entry.
- `pipeline.rs`: `ShadowResources` owns six fixed-capacity caster lists reused
  across transactions (no per-frame allocation, capacity bounded like
  `MAX_NODE_VISITS`). `draw_point_static_roots`/`draw_point_dynamic_roots`
  become: collect once, then for each dirty face bind its target, clear (PC4
  scissor where applicable), `begin_point_face`, and submit that face's list.
- Skinned casters keep the existing per-transaction skin journal; each record
  carries its journal key so bone rows are computed once and reused across the
  face submissions.
- Tests: a synthetic D3D test asserts the per-face submitted set and the final
  pixels equal the current six-pass path; a work-budget test asserts the
  hierarchy is walked once per light, not once per face.

### Proposal 2 implementation sketch

- Replace the fixed `CasterPolicy::quality_default().minimum_radius` admission
  at cube generation with `max(world_minimum, projected_pixels * cube_radius /
  resolution)`, computed per selected light from its `cube_radius` and the active
  cube resolution.
- Apply it identically to `DirectionalRoot::admits_point_static_size`
  (signature) and the render bound test so the retained signature and the draw
  agree; a sub-pixel caster then neither draws nor invalidates a face.
- Tests: a signature/render agreement test at the boundary and a pixel test
  proving the removed casters were sub-texel.

### What is deliberately not planned

- Dropping or de-prioritizing moving lights, or honoring vanilla `CastShadows`
  to thin the set: rejected for immersion/quality per owner direction.
- Any position or radius reuse tolerance: a moved light publishes a displaced
  or mis-scaled shadow, which the owner rejected.
- Receiver-driven face/tile culling and occluded-light culling: blocked by the
  frame-ordering constraint above.
- Lowering cube resolution for moving lights: visible quality loss.

## Open gaps for the next capture

Record one `Lightweight shadow log`-enabled session in a scene with several
casters, a known moving light, and a walk from a dense area to open ground, and
capture:

1. `moving_position` / `moving_radius` / `moving_both` totals. If
   `moving_radius` (or `moving_both` with radius) dominates, the exact-projection
   rebuild cost is driven by animated radius rather than real motion and should
   be addressed on the radius field only. If `moving_position` dominates, the
   position values are changing every frame and the reading path must be checked
   for floating-point instability.
2. `root_all_changed` versus `root_nolod_changed`. If `root_all_changed` tracks
   transactions while `root_nolod_changed` stays low, the object-LOD root owns
   the static churn. If both track, generic movable statics own it and the
   region-scoped static update (PC4) is the fix.
3. Whether `merge_faces` fully collapses to zero after actors settle (PC1
   validation) and how often `dirty_lights=0` (zero-D3D republish) occurs.
4. A shadow-on vs shadow-off present-rate comparison, and a
   `directional_occlusion` screen-space vs world-cascades comparison in the same
   exterior view, to attribute the volumetric directional cost.

## Related documents

- `docs/graphics_fnv_shadows_performance_plan.md`: the ordered change set,
  file-level design, tests, and acceptance gates for the moving-light and
  caster-set optimizations.
- `docs/graphics_fnv_nvr_shadows_engine_contract.md`: engine layout, phase
  ordering, ownership, and the producer/consumer invariants.
- `docs/graphics_fnv_omv_runtime_performance.md`: broader OMV runtime
  performance evidence.
- `docs/graphics_fnv_atmosphere_phase3_directional_lighting_plan.md`:
  directional volumetric lighting and the world-occlusion source contract.

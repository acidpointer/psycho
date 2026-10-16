# OMV dynamic-shadow performance change plan

Status: C1 shipped and offline-qualified; C2/C3 planned. Date: 2026-10-16.
Owner: repository owner.

Evidence and measurements live in `docs/graphics_fnv_shadows_diagnostics.md`;
engine invariants live in `docs/graphics_fnv_nvr_shadows_engine_contract.md`.
This file owns the ordered change set and its acceptance gates.

## Objective and constraints

Reduce the per-frame cost of dynamic point-light shadow production without any
visual-quality regression, and **keep every moving light**. Constraints:

- Preserve or improve visual quality; never worsen it.
- Do not drop casters, thin the selected light set, or honor vanilla
  `CastShadows` merely to save work.
- No position or radius reuse tolerance (a moved light must not publish a
  displaced or mis-scaled shadow).
- No debug-only build; every change is a production change validated offline.

## Measured baseline (2026-10-16 sessions)

- Moving selected lights: `rebuilt_faces` p90 ~30/transaction (up to six moving
  lights x six faces); 100% position changes, radius never changes.
- Stationary movable statics: `refresh_faces` median ~4.3/transaction after the
  object-LOD exclusion.
- `shadow_pre` producer CPU span ~0.9-1.6 ms.
- Shipped: Workstream A directional decoupling; the actor pose delta (PC1); the
  admission-consistent point signature (PC3); object-LOD exclusion; the
  region-scoped static refresh (PC4).

## Decisive frame-ordering constraint

The producer runs inside the world render, before the pre-alpha depth resolve
and before the world geometry samples the cube (`fnv_render.rs:621,718`;
`fnv_world_pipeline.rs:281`). The depth provider is acquired only in the consumer
(`pipeline.rs:4387,4411`). The producer therefore cannot know the current
frame's visible receivers, so receiver-driven face/tile culling and
fully-occluded-light culling cannot be done same-frame without an engine depth
prepass or a one-frame-lag mask. Both are out of scope here.

## Change C1 - cross-face caster traversal amortization (CPU)

Status: **shipped**. `render::collect_point_casters` walks each root once and
records every admitted caster with its touched-face mask (the disjunction of the
six `sphere_intersects_point_face` tests, intersected with the inherited
ancestor mask so per-face subtree pruning is preserved); `render::submit_point_casters`
submits the records whose mask covers the bound face. `ShadowResources` owns the
static and dynamic record vectors and reuses them. `draw_point_static_roots`,
`draw_point_draw_roots`, and `draw_point_root` were removed. Offline tests: a
`cube_face_mask` disjunction test; the full OMV suite; 32-bit release build.

### Problem

A moved light runs `RebuildPublished` per face. For each of up to six faces,
`draw_point_static_roots` / `draw_point_dynamic_roots` re-walk the same
hierarchy and re-test every object's bound against that one face. The walk,
virtual casts, bound tests, fade/multibound checks, and child pushes repeat six
times per light.

### Design

Separate traversal from submission and build the touched-face set once.

- New `render::collect_point_faces(context, root, scratch, out)`:
  - one DFS over the root, reusing the existing `scratch.nodes` stack, budget,
    switch-node handling, visibility, fade, and multibound logic;
  - computes a per-object face mask instead of a single-face boolean:
    `mask = sphere_intersects_point_light(bound) ? fold(face -> sphere_intersects_cube_face(center_from_light, radius, face)) : 0`.
    This is exactly the disjunction of the six current
    `object_bound_within` face results, so the submitted set is identical;
  - prunes a subtree whose node mask is zero; appends each admitted geometry to
    every face list in its mask as
    `CasterRecord { geometry, classification, world_matrix, skin_key }`.
- New `render::submit_caster(context, record, face)` is the current
  `draw_geometry` submission body, parameterized by the already-computed
  classification and world matrix; the skinned path reuses the per-transaction
  skin journal key in `record.skin_key` so bone rows are computed once and only
  re-uploaded/drawn per face.
- `pipeline.rs`:
  - `ShadowResources` owns six fixed-capacity `Vec<CasterRecord>` lists (one per
    cube face), reused across transactions; capacity bounded like
    `MAX_NODE_VISITS`; overflow of a face list falls back to that face's current
    per-face traversal (correct, just not amortized);
  - `draw_point_static_roots` / `draw_point_dynamic_roots` become
    "collect once, then for each dirty face: bind target, clear (PC4 scissor
    where applicable), `begin_point_face`, iterate that face's list, submit";
  - `RebuildPublished`, `RefreshStatic`, and `MergeAnimated` all use the shared
    collection so a moved light, a scoped static refresh, and an actor merge
    each walk once.

### Quality and risk

- No pixel change: the per-face fragment stream and state writes are identical;
  only the ordering of the hierarchy walk changes, and each record carries the
  same classification/world matrix the current code computes.
- Risk: correctness of the face-mask generalization (must equal the six
  per-face tests), and the RT/state ordering per face. Mitigated by an
  equality test against the current path.
- Memory: six lists bounded by the node/child caps; no per-frame allocation
  after first growth.

### Tests

- Synthesized D3D test: a caster touching several faces is submitted to exactly
  the faces the current six-pass code selects, and the final cube pixels equal
  the current path (byte-equal on a fixed fixture).
- Work-budget test: the hierarchy is walked once per light, not once per dirty
  face, with a multi-face dirty light.

## Change C2 - per-face projected-size caster minimum (CPU + GPU)

Status: **shipped**. `contract::point_caster_minimum_radius(cube_radius,
resolution)` raises the fixed world minimum (0.5) to `0.5 * cube_radius /
resolution` when that is larger, mirroring the directional
`cascade_minimum_caster_radius` scale. It is applied identically to
`DirectionalRoot::is_point_static_caster` (signature and masks, threaded through
`point_scene_static_signatures`, `collect_point_static_face_masks_for_light`, the
spatial index, and `include_point_static_root`) and to the render via the new
`minimum_radius` argument of `render::collect_point_casters`. Sub-texel casters
of a large-radius light therefore neither draw nor invalidate a retained face,
and the signature and render set stay identical. Offline test:
`point_caster_minimum_radius_scales_with_light_radius_and_keeps_the_floor`.

### Problem

Cube generation admits casters at a fixed `minimum_radius` (0.5 world,
`CasterPolicy::quality_default`). Casters far below one cube texel are still
walked, classified, submitted, and can invalidate a retained face.

### Design

- Derive a per-light projected minimum at the cube face:
  `max(world_minimum, projected_pixels * cube_radius / resolution)`, with
  `projected_pixels` at or below one texel (mirroring the directional
  `NVR_CASCADE_MIN_RADIUS_PIXELS` rule and its `cube_radius / resolution` scale).
- Apply it identically to `DirectionalRoot::admits_point_static_size` (signature
  and masks) and the render bound test, so the retained signature and the draw
  agree: a sub-texel caster neither draws nor invalidates a face.

### Quality and risk

- Quality-neutral: geometry below one cube texel cannot change the sampled
  point-filtered depth by more than the bias margin; the directional path
  already removes one-pixel casters.
- Risk: the boundary must be consistent between signature and render, or a
  threshold-crossing caster would flicker. Mitigated by an agreement test.

### Tests

- Signature/render agreement at the threshold (a caster exactly at the
  projected minimum is either admitted by both or removed by both).
- Pixel test proving a removed caster projected to less than one texel.

## Change C3 - fixed per-face cost trim (minor, opportunistic)

Hoist state that is provably invariant across one light's faces
(`configure_generation_state` baseline; the `D3DCULL_NONE` cube baseline is
already de-duplicated). Only if C1/C2 leave it visible in the counters. No new
behavior.

## Non-goals

- Receiver-driven face/tile culling, occluded-light culling (frame-ordering
  blocked).
- Dropping moving lights, `CastShadows` thinning, position/radius tolerance,
  reduced cube resolution (owner rejected / quality loss).

## Order and acceptance gates

1. C1, then C2, then C3 only if needed.
2. Each change: fail-first offline behavioral test on the unchanged path; the
   matching equality/agreement/pixel tests above; `cargo test --target
   i686-pc-windows-gnu -p omv`; one 32-bit release build; `cargo fmt --check`;
   `git diff --check`; final diff review.
3. Report the measured offline work reduction (walks per light, admitted
   caster count) and state that game FPS and image continuity were not run.

## Open decisions

- C2 threshold: one texel, or a stricter sub-texel fraction (for example 0.5
  texel) to be conservative at first.
- Whether C1's per-face lists should also serve the directional cascade path
  (same amortization) in a later change.

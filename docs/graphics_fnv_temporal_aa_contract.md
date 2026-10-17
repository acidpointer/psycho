# FNV Temporal AA Contract

Owner: `omv/src/effects/temporal_aa.rs`, `omv/shaders/embedded/aa_temporal.hlsl`,
`omv/shaders/embedded/aa_temporal_depth_key.hlsl`. Integration:
`omv/src/fnv_world_pipeline.rs`.

## Phase and ownership

Temporal AA is a **world-only** resolve in `ShaderPhase::ScenePostImageSpace`.
It runs after the engine world pass and before first-person and UI rendering, so
those layers stay unjittered. It owns the world boundary together with the
atmosphere:

1. OMV applies subpixel projection jitter to the engine world camera for the
   frame (`temporal_aa_jitter`), then the engine renders the world.
2. The resolve reads the world target, the raw depth, and the ping-pong
   history, resolves color onto the fixed output grid, and copies the result
   back to the world target.
3. The atmosphere composites volumetric lighting on top of the resolved color.
4. The final-color owner may run a spatial anti-alias companion over the
   composed image when temporal AA is active and no explicit spatial effect
   (Fast FXAA, NFAA, AXAA, DLAA, SMAA) is selected.

The engine world target is `D3DFMT_A16B16G16R16F` at full resolution with no
MSAA. MSAA is intentionally absent, so temporal AA carries the world's
anti-aliasing.

## Resources

Per target description (width, height, format):

- `current`: one full-resolution render-target texture in the engine target's
  format, a snapshot of the world target.
- `color_history[2]`: ping-pong `D3DFMT_A16B16G16R16F`.
- `depth_key_history[2]`: ping-pong `D3DFMT_R16F` logarithmic depth keys.

The resolve emits color and depth key in one pass when the device exposes two
render targets with independent bit depths (`MRTINDEPENDENTBITDEPTHS`);
otherwise a second depth-key pass runs. Both paths produce identical images.
Copy-back is `StretchRect`, so it also serves as the MSAA resolve were MSAA
re-enabled.

## Projection jitter

`fnv_world_pipeline::temporal_jitter_pixels(frame_index + 1, jitter_scale)`
returns the subpixel offset in pixel units from the `R2` low-discrepancy
sequence (the two-dimensional generalized golden ratio). The index is a `u64`
frame counter evaluated in `f64`, so the fractional part stays exact. `R2`
covers every prefix length uniformly, unlike the early clumping of an
unscrambled `Halton(2,3)`, so a short retained history still decorrelates
far-field aliasing. A zero or non-finite scale degrades to a centered no-op.

Reprojection is computed with jitter cancelled at both endpoints, so a still
camera always yields a null motion vector.

## Resolve contract (`aa_temporal.hlsl`)

- **Fixed output grid:** the new color is the bilinear read of the jittered
  raster at `uv - jitter`. Alpha is the exact engine-owned raster pixel.
- **Depth:** the raw depth is point-sampled at the snapped raster texel of the
  jittered position; the single contributing point, not the filtered blend,
  drives reprojection and the depth key.
- **Reprojection:** camera-only. A 3x4 matrix maps the current view-space point
  to the previous view space; motion is the previous minus current projected
  UV, on the fixed grid.
- **Variance clipping:** the 5-tap neighborhood is gathered on the **fixed
  output grid** (`uv`), so the history clamp does not move with the subpixel
  jitter. The history is clamped to `mean +/- clamp_strength * sigma`,
  intersected with the neighborhood min/max and expanded to include the
  current sample. Variance clipping is the rejection mechanism; the previous
  relative-RGB agreement test was removed because it over-rejected
  high-frequency far detail and caused the far-field crawl.
- **Motion-adaptive history:** a nearly static pixel pushes the history weight
  toward `min(0.99, configured_weight + 0.09)`, a moving pixel returns to the
  configured weight. The reprojection is camera-only, so a long static history
  is safe; the clamp and depth key still bound disocclusions.
- **Depth-key agreement:** the expected logarithmic key is compared against the
  footprint's **nearest** history-key texel, the point sample the bilinear
  color read is registered to (`PreviousDepth.z` scales the tolerance). Every
  contributing history-key corner must additionally belong to the same layer
  (geometry, sky, or invalid), so a bilinear read still cannot mix those
  layers. A different *geometry* depth inside the footprint is accepted as
  legitimate local slope: a sloped surface spans several valid keys within one
  pixel, and rejecting them stalls accumulation and shows per-frame jitter.
- **Sharpening:** an unsharp residual against the neighborhood mean, clamped to
  the neighborhood min/max, so it can never create a new radiance peak.

Sky, invalid depth, unavailable projections, and out-of-range history UVs exit
before the resolve and preserve the current sample. Any failed GPU step
invalidates the recursive history.

## Budgets

`temporal_aa_shader_keeps_bounded_ps_3_0_work` enforces, per variant, compiled
instruction counts, texture-operation counts, sampler/temporary/constant
bounds, and the absence of derivatives, `discard`, and dynamic loops. The
resolve uses 12 texture operations; the two-pass fallback adds the depth key.

## Offline validation

`omv/src/effects/temporal_aa/behavior_tests.rs` runs the shipped shaders on a
real D3D9 device with upload/readback oracles:

- `fixed_grid_affine_radiance_is_invariant_over_jitter_and_history_weights`
- `shipped_world_settings_reduce_thin_geometry_sampling_error`
- `far_field_detail_stays_temporally_stable_under_the_shipped_jitter`: a still
  camera on a constant-depth far plane carrying a half-pixel-phase checker
  (above-Nyquist) must converge to the box-filtered image. The oracle is a
  ratio gate (`resolved instability < raw instability * 0.05`) and is
  fail-first: the pre-variance-clip resolve measured `0.0405` against a raw
  `0.45` and failed; the shipped resolve measures `0.0029`.
- sky-border, disocclusion, invalid-settings, and MRT-vs-two-pass equivalence
  oracles.
- `sloped_surface_history_survives_camera_motion`: a slowly rotating camera
  over a high-frequency scene on a depth gradient must keep accumulating
  history. The oracle is the frame-to-frame resolved instability (the jitter
  signal) with the flat surface as an in-run control, and it is fail-first:
  the pre-change resolver rejected history on any slope steeper than the flat
  tolerance and measured `0.029`-`0.033` against a flat control of `0.0044`;
  the shipped resolve measures `0.005`.

## Deliberately not implemented

- **Per-object motion vectors:** Gamebryo/FNV stores no previous-frame object
  transform and exposes no velocity buffer. Camera+depth reprojection already
  handles static geometry exactly; the reported far-field crawl is a
  reconstruction/rejection problem, not a velocity problem.
- **Copy elimination:** sampling the engine world target directly instead of
  the `current` snapshot needs entity-container plumbing and a proven
  non-MSAA sampleability contract.
- **Catmull-Rom history:** would exceed the current texture-operation budget.
- **MSAA restoration and an always-on spatial companion:** owner-level
  quality/performance trades.

## Unresolved

Game-only far-field appearance after this change is not run by an agent; only
the offline oracles above are qualified.

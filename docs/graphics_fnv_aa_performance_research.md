# FNV AA performance research

Date: 2026-07-17

Scope: OMV temporal AA, Fast FXAA, NFAA, AXAA, DLAA, and LUT-free SMAA.

The optimization requirement is strict: preserve the current image quality or
improve it. Reducing resolution, reducing the intended filter footprint,
lowering history precision, weakening rejection, or moving TAA across the
world/first-person/UI boundary is not an acceptable performance fix.

This is a static code, bytecode, and engine-contract audit. It does not contain
in-game GPU timings yet. Shader bytecode was compiled through OMV's actual
`D3DCompile` path with backwards compatibility and optimization level 3, using
the `ps_3_0` target under Wine. All 35 OMV tests passed under the same Wine
environment.

## Executive result

The first optimization should not alter an AA shader. OMV currently treats all
enabled effects as consumers of every FNV scene input. This causes spatial-AA-
only configurations to capture world depth, first-person depth, and world color
that those effects never sample. TAA needs world depth, but it does not consume
the separate world-color copy or first-person depth. A capability-based input
contract removes this work without changing one output pixel.

After that, the strongest quality-neutral changes are:

1. Validate each camera snapshot as one contiguous range instead of issuing a
   `VirtualQuery` for each scalar field.
2. Remove TAA's duplicate center-color sample. Compiled evidence shows a real
   reduction from 8 to 7 texture instructions and from 236 to 233 instruction
   tokens.
3. Bind common D3D state once, apply only effect-specific deltas, and avoid a
   second common-state bind when no later pass needs it.
4. Stop cloning complete shader-source objects in the render hook and stop
   copying the backbuffer after permanent shader compilation failure.
5. Pool DLAA/SMAA scratch targets and skip SMAA's weight pass in edge-debug
   mode.

There are also quality defects that should be corrected before calling the port
finished. DLAA computes "luma" from green only, TAA overwrites world-target
alpha with private depth metadata, and SMAA's `corner_rounding` option globally
attenuates all weights rather than detecting corners.

## Compiled shader cost

The table counts legacy D3D9 bytecode instruction tokens and texture-instruction
sites. Dynamic flow means the number executed by one pixel can be lower, or in
AXAA's loop higher, than the static texture-site count.

| Shader | Instruction tokens | Texture sites | Dynamic texture behavior |
|---|---:|---:|---|
| Fast FXAA | 111 | 9 | 5 on early exit, 9 on an edge |
| NFAA | 138 | 9 | 4 in normal debug, 5 below threshold, 9 filtered |
| AXAA | 372 | 12 | 5 early; up to 16 with three search iterations |
| DLAA prefilter | 31 | 5 | 5 unconditional |
| DLAA resolve | 265 | 17 | 17 unconditional |
| SMAA edges | 113 | 5 | 3 without an edge, 5 with local contrast |
| SMAA weights | 210 | 17 | 1 to 17 depending on edge orientation |
| SMAA blend | 142 | 9 | debug/empty paths are cheaper |
| Temporal AA | 236 | 8 | 2 on rejected history, 8 on valid history |
| Temporal AA without duplicate center sample | 233 | 7 | 2 rejected, 7 valid |

The compiled measurements establish several useful facts:

- TAA's duplicate center fetch is not removed by compiler common-subexpression
  elimination. Removing it is a proven one-fetch saving.
- DLAA is bandwidth and texture-fetch heavy: its two passes execute 22 texture
  instructions per pixel before accounting for the initial scene-color copy.
- SMAA has 465 instruction tokens and 31 texture sites across three passes.
- AXAA has the largest single-shader instruction body. Its two search texture
  instructions can execute up to three times each.

Source references:

- `omv/shaders/embedded/aa_fast_fxaa.hlsl:11-40`
- `omv/shaders/embedded/aa_nfaa.hlsl:12-44`
- `omv/shaders/embedded/aa_axaa.hlsl:15-123`
- `omv/shaders/embedded/aa_dlaa_resolve.hlsl:20-76`
- `omv/shaders/embedded/aa_smaa_weights.hlsl:12-60`
- `omv/shaders/embedded/aa_temporal.hlsl:56-110`

## Full-resolution traffic

At 1920x1080, one A8R8G8B8 surface is 7.9 MiB. A full-surface copy reads and
writes about 15.8 MiB. At 60 FPS that one copy represents about 0.93 GiB/s of
logical payload. At 3840x2160 it represents 63.3 MiB per frame or 3.71 GiB/s.
Physical VRAM traffic depends on DXVK, caching, and the source format, but dead
copies remain dead work regardless of the exact hardware path.

Every spatial AA invocation currently performs a scene-color `StretchRect`
before its shader pipeline (`omv/src/runtime.rs:1247-1269`). DLAA then writes
one private full-resolution target. SMAA writes two private full-resolution
targets. These writes are intrinsic to the current algorithms; the unrelated
pre-first-person world-color capture is not.

TAA owns one current-color target and two FP16 history targets
(`omv/src/effects/temporal_aa.rs:468-500`). If the world target is also FP16,
steady-state fixed copy/write traffic, before shader texture reads, is about 40
bytes per pixel:

- current world to current-color target: 16 bytes per pixel read plus write;
- FP16 history render write: 8 bytes per pixel;
- FP16 history copied back to world: 16 bytes per pixel read plus write.

That is about 79.1 MiB/frame at 1080p and 316.4 MiB/frame at 4K. The current
generic world-color capture adds another full copy after TAA even when no later
effect consumes it.

## CPU and driver command pressure

The steady-state TAA resolve issues approximately 51 D3D9 method calls. Each
RESZ depth resolve adds roughly 31. With the currently unnecessary first-person
resolve and world-color capture, a TAA-only frame reaches roughly 115-120 D3D
calls before COM reference operations. Exact driver cost must be measured under
the deployed DXVK version, but eliminating calls for unused inputs is strictly
better than micro-optimizing an individual setter.

Spatial AA also duplicates state setup. Its local binder issues about 27 D3D
calls after runtime has already established common state, and runtime can then
issue roughly another common-state bind before the outer state block restores
the engine state.

Camera validation is another likely Wine/Proton CPU cost. The TAA path can
approach 90 `VirtualQuery` calls in a frame with world and first-person capture.
This estimate comes from scalar-by-scalar validation, not measured timing; the
contiguous snapshot change below retains validation while collapsing the query
count.

## Priority 0: output-equivalent work

### Use per-effect scene-input requirements

`ScreenShaderRuntime::needs_fnv_scene_inputs` currently delegates to the broad
`has_enabled_shader` result (`omv/src/runtime.rs:1634-1661`). Consequently every
enabled AA effect activates both depth hooks and world-color capture.

Replace the broad boolean with explicit requirements:

| Consumer | World depth | First-person depth | World color copy |
|---|---:|---:|---:|
| TAA | yes | no | no |
| Fast FXAA/NFAA/AXAA/DLAA/SMAA | no | no | no |
| Embedded AO/DOF/sunshafts | yes | yes | verify per effect |
| Bloom | no world reconstruction | yes for its mask | no |
| External shader | conservatively yes | conservatively yes | yes |

The external-shader row deliberately preserves the advertised generic input
contract. This optimization must specialize known embedded effects, not remove
inputs globally.

Expected TAA-only saving:

- one world-color `StretchRect`;
- one first-person RESZ resolve and its D3D state traffic;
- the persistent world-color target when no other consumer requires it.

Expected spatial-AA-only saving:

- world and first-person RESZ resolves;
- the world-color `StretchRect` and target;
- camera/environment input assembly unrelated to the final AA pass.

### Consolidate validated camera reads

`validate_memory_range` calls `VirtualQuery`
(`libpsycho/src/os/windows/memory.rs:48-95`). Camera reads currently validate
near/far, four frustum values, rotation, translation, and scale independently
(`omv/src/backend/fnv.rs:332-413`). A complete camera read is approximately 21
queries, and the TAA path reads the world camera before jitter and again during
depth publication.

The relevant camera fields are contiguous. Validate the complete required
range once, copy a local snapshot, and validate the pointer slots separately.
This preserves memory safety while removing roughly 18 queries per snapshot.
Do not cache a raw camera pointer across frames or transitions.

### Remove the duplicate TAA center fetch

`Main` samples current color at `aa_temporal.hlsl:78`. `Neighborhood` samples
the same sampler and UV again at line 58. Pass the existing `current` value into
`Neighborhood`.

The compiled result is confirmed:

- bytecode words: 1018 to 1008;
- instruction tokens: 236 to 233;
- texture instructions: 8 to 7.

The current color, neighborhood bounds, average, sharpen, clamp, and temporal
blend equations remain unchanged.

### Reduce redundant D3D state calls

`draw_passes` binds generic common state before dispatch
(`omv/src/runtime.rs:984`). Spatial AA immediately repeats most of it in
`bind_pipeline_state` (`omv/src/effects/anti_aliasing.rs:292-311`), then runtime
binds common state again after the AA pipeline (`omv/src/runtime.rs:1100-1102`).

Use this contract:

1. Bind common phase state once.
2. Apply only the sampler/target deltas required by the selected AA pipeline.
3. Rebind common state only when a later enabled pass exists.
4. Keep the outer D3D state block as the engine-state restoration owner.

TAA has the same smaller issue: sampler 1 is set to linear in the generic loop
and immediately overwritten to point before any draw
(`omv/src/effects/temporal_aa.rs:424-432`).

Do not remove state blocks until scissor, stencil, sRGB, render-target, and
error-path ownership are explicit.

### Remove render-hook allocation work

TAA clones a complete `ScreenShaderSource` before jitter and again before
resolve (`omv/src/runtime.rs:663-668`, `717-722`). It needs only four option
constants and enabled/availability state. Publish a compact copyable TAA frame
configuration instead of cloning names, paths, option strings, and vectors.

### Schedule only available shaders

A `ShaderSlot` permanently records failure (`anti_aliasing.rs:225-238`), but the
runtime has already copied the full backbuffer before it asks the slot to draw.
Propagate availability to scheduling so a failed shader does not retain a
full-resolution copy cost every frame. Preserve a visible error in the menu.

### Pool spatial-AA scratch targets

DLAA owns one A8 target and SMAA owns two (`anti_aliasing.rs:66-67`, `368-383`).
They execute serially, including when deliberately stacked. A two-target pool
can serve both pipelines:

- DLAA uses target 0;
- SMAA uses targets 0 and 1 after DLAA has completed.

This saves one retained full-resolution target after both effects have been
used: 7.9 MiB at 1080p or 31.6 MiB at 4K.

### Remove pass-invariant uploads and debug-only work

DLAA and SMAA upload the same screen/options constants for every internal pass
(`anti_aliasing.rs:143-153`, `184-202`). Upload once per pipeline. Their target
sizes are identical, so repeated identical viewport setup can also be removed
after target ownership is explicit.

SMAA edge-debug output reads the edges target, but the pipeline still executes
the complete weights pass. In edge-debug mode, skip that pass. This is exactly
output-equivalent for that debug view.

## Priority 0: quality fixes with no intended performance loss

### Correct DLAA luma

Both DLAA shaders use:

```hlsl
dot(color.ggg, float3(0.333333, 0.333333, 0.333333))
```

This is just `color.g`. Red/blue chromatic edges with constant green can be
missed. Replace it with the source algorithm's intended intensity metric or a
documented RGB luma calculation. Texture count and render-target traffic are
unchanged. This is a quality correction, not a speed tradeoff.

References: `aa_dlaa_prefilter.hlsl:7-9` and
`aa_dlaa_resolve.hlsl:8-10`.

### Make jitter/resolve success transactional

Jitter, depth capture, resolve, world-color capture, and Present completion use
separate `try_lock` acquisitions. If jitter succeeds and a later acquisition or
D3D operation fails, the frame can remain jittered without temporal resolve.
That is a quality failure.

Use render-thread-owned compact state or a configuration mailbox so jitter is
only armed when the full resolve path is ready. Do not hold the current runtime
mutex across the original world render; that would create an unbounded engine
lock scope.

### Preserve FP16 history quality

TAA falls back from A16B16G16R16F to A8R8G8B8 history
(`temporal_aa.rs:475-488`). A8 history can quantize HDR color and depth keys.
Under the strict quality requirement, an FP16 source should bypass TAA if FP16
history is unavailable rather than silently reducing history precision. An A8
fallback can remain valid for a proven LDR A8 source.

### Establish scissor and sRGB state explicitly

Neither common nor AA-local state establishes scissor and sRGB decode/write
behavior. Inherited scissor can process only part of the frame. Inherited sRGB
state can alter edge thresholds and intermediate values. Capture runtime state
first, then explicitly set the contract chosen for each pipeline. Do not assume
the inherited engine state is stable.

## Priority 1: output-equivalent after validation

### Short-circuit closed SMAA searches

Each orientation in `aa_smaa_weights.hlsl` issues all eight directional samples
once entered. `open` is multiplied by binary step results and can never become
nonzero again. Explicit bounded branches can skip later pairs once both sides
are closed without changing the resulting span or weights.

Keep the search statically bounded. Do not replace it blindly with a generic
dynamic loop on ps_3_0; compare compiled bytecode and DXVK GPU timings.

### Precompute uniform TAA projection terms

The CPU already owns validated current/previous camera data. It can precompute:

- inverse previous frustum width and height;
- previous frustum projection offsets;
- reciprocal `log2(far + 1)` depth-key scales;
- normal/reversed depth linearization coefficients.

This removes uniform divisions/logarithms from per-pixel code. It should be
visually equivalent but may not be bit-identical due to operation order, so it
requires image-difference and motion testing.

### Reuse a fullscreen triangle/static vertex buffer

Every pass rebuilds four vertices and uses `DrawPrimitiveUP`
(`anti_aliasing.rs:331-340`; TAA has an equivalent helper). A reusable D3D9
fullscreen triangle removes one vertex, the internal diagonal, and repeated
user-memory vertex upload. Its half-pixel coordinates must be derived and
validated against the current quad before adoption.

## Research-gated architecture changes

### MRT TAA output

TAA stores a logarithmic depth key in history alpha, then copies that FP16
history surface wholesale back to the world target (`aa_temporal.hlsl:77-110`,
`temporal_aa.rs:191-197`). Therefore current TAA replaces world-target alpha
with private temporal metadata. The engine impact is not proven.

An MRT resolve could write:

- RT0: resolved RGB plus original world alpha;
- RT1: resolved RGB plus temporal depth key.

It would preserve alpha and eliminate the final FP16-history-to-world copy,
saving 8 bytes per pixel of fixed traffic: 15.8 MiB/frame at 1080p and 63.3
MiB/frame at 4K. It may also avoid FP16 round-trip quantization of final color.

Do not implement this until all of these are proven:

- two simultaneous render targets are supported;
- source and history formats satisfy D3D9 mixed-format MRT constraints;
- multisample type and quality match;
- RT1 and color-write state are fully restored;
- vanilla/other plugins' world alpha contract is known;
- DXVK/Wine behavior is verified.

### Merge depth-resolve and TAA state ownership

World RESZ and TAA each capture/apply an all-state block. One post-world owner
could reduce state-block traffic, but the RESZ point-size trigger, original
depth surface restoration, TAA targets, and all errors would need one proven
restoration path. This is not a safe first optimization.

## Contract gaps

The 2026-07-17 projection/alpha follow-up proves more of the boundary but does
not close every current TAA assumption:

- `NiRenderer::SetCameraData @ 0x004E9BB0` passes camera `+0xDC` directly as its
  frustum input. This is exactly the block OMV jitters.
- The raw body at `0x006629F0` adds `0xAC` to a `SceneGraph` and dereferences
  that camera slot. `RenderWorldSceneGraph` calls it at `0x0087417A`, passes the
  result unchanged to rendered-texture camera setup at `0x00874180`, and that
  setup calls `SetCameraData` before later world operations.
- Both main paths call `RenderFirstPerson` only after `RenderWorldSceneGraph`
  returns (`0x00870B21` and `0x00870F74`). OMV restoring the frustum before the
  world hook returns therefore excludes first-person rendering.
- The image-space owner replaces `pCurrentCamera` at `0x00876125` before
  `ProcessImageSpaceShaders`, independently excluding the later image-space/UI
  camera.

This closes the frustum-to-world-upload contract for the `SceneGraph` being
rendered. The raw global getter at `0x0045C670` also proves that the persistent
World scene graph is `*(SceneGraph**)0x011DEB7C`, and later world paths obtain
its camera through the same `+0xAC` getter.

Runtime validation disproved an earlier ABI assumption: the first stack argument
to the `0x00873200` hook is not the `SceneGraph` later held in internal local
`[EBP-0x24]`. Treating that argument as a `SceneGraph` makes `+0xAC` unreadable
and disables world depth. The proven usable camera source at the entry hook is
the main World scene graph global `*(SceneGraph**)0x011DEB7C`; keep using it for
jitter and world-depth projection publication.

The alpha audit found only five direct references to the current-render-target
global: its writer, one first-person reader, and three depth-resolve readers.
That is useful negative evidence, but it does not prove pixel-shader alpha
semantics or indirect texture consumers. MRT remains blocked on shader-package
inspection and runtime alpha telemetry.

Other open contracts:

- meaning and downstream use of world-target alpha;
- projection type at camera `+0xF4` and special/orthographic paths;
- exact reversed-depth mapping, not only the active Z comparison function;
- whether phase-zero world rendering can occur more than once per Present;
- sky depth behavior under projection jitter;
- D3D9 MRT format/multisample support on the actual DXVK path.

Evidence is in
`analysis/ghidra/output/perf/graphics_fnv_taa_projection_alpha_perf_contract_audit.txt`.
The completed raw pointer-identity evidence is in
`analysis/ghidra/output/perf/graphics_fnv_taa_world_camera_upload_identity_followup.txt`.
Runtime D3D capability and alpha telemetry are still required for MRT.

## Rejected performance shortcuts

Do not use these as optimizations:

- A8 history for an FP16/HDR source;
- half-resolution TAA history/current color;
- point-filtered temporal history;
- fewer neighborhood-clamp samples without a stronger replacement;
- lower-resolution spatial-AA intermediates;
- shorter DLAA kernels or SMAA search distance without quality proof;
- removing world depth from TAA;
- resolving TAA after first-person or UI;
- globally disabling effects/captures rather than specializing consumers;
- removing state restoration or camera validation;
- caching raw engine camera pointers across frames;
- increasing history weight to hide instability.

## Benchmark and quality gate

Implementation work should report both performance and image quality:

1. Add CPU timings around jitter preparation, world RESZ, first-person RESZ,
   TAA resolve, world-color capture, and each spatial-AA pipeline.
2. Add D3D9 timestamp/event-query wrappers where supported; otherwise use
   carefully isolated frame-time A/B runs under the same DXVK configuration.
3. Log actual source/target formats, dimensions, resource recreation, world-call
   count per Present, and input-requirement decisions.
4. Capture stationary subpixel edges, slow pan, fast rotation, translation,
   foliage, alpha-tested geometry, sky, weapon silhouettes, interiors, loading
   transitions, camera/FOV changes, and HUD/menu overlays.
5. Compare identical frames or controlled camera paths. No optimization ships
   if it adds shimmer, missed chromatic edges, blur, ringing, ghosting, UI
   contamination, or temporal instability.

Recommended implementation order:

1. Per-effect input requirements.
2. Read the persistent World `SceneGraph` global and its camera through the
   proven `+0xAC` contract; do not reinterpret the hook's first stack argument.
3. Contiguous validated camera snapshots.
4. TAA duplicate-sample removal.
5. State-call reduction and compact TAA configuration.
6. Failed-shader scheduling and scratch-target pooling.
7. DLAA luma correction and TAA precision/error-path hardening.
8. SMAA closed-search optimization with bytecode and runtime comparison.
9. Runtime telemetry for alpha, formats, timing, and call multiplicity.
10. MRT only if all engine and D3D contracts are proven.

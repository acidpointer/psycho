# OMV NVIDIA Close-Terrain Shader-Lowering Fix Plan (Superseded Design)

Date: 2026-08-10

Status: the split-constant-array design in this document was rejected by its
own Phase 0 compiler gate. It is preserved as the pre-implementation decision
record and must not be implemented. The replacement design, source changes,
static evidence, and remaining runtime gates are authoritative in
`graphics_fnv_omv_nvidia_close_terrain_shader_fix_implementation.md`.

Both supported compiler routes lowered separate dynamically indexed constant
arrays to compare/select cascades rather than relative constant reads. OMV
therefore moved only its supplemental light records to a 32x2 dynamic RGBA32F
shader-data texture. Native `c39..c88`, supplemental count `c91`, one shader
per row, one draw, full light coverage, and all material equations remain
unchanged. No NVIDIA performance claim is closed until the controlled runtime
matrix passes.

## Purpose

This plan defines the smallest durable change that can test and remove the
remaining NVIDIA-specific native-PBR performance cliff without changing PBR
appearance, terrain coverage, portable-light coverage, or the engine-facing
draw contract.

The earlier NVIDIA remediation corrected real hook, lifecycle, sampler,
light-capture, resource, and copy-graph defects. An affected NVIDIA playtest
reported no meaningful performance recovery. The remaining evidence now points
to the close-terrain pixel program produced from
`omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl`.

This document supplements
`docs/graphics_fnv_omv_nvidia_1fps_remediation_plan.md`. It supersedes that
plan's prohibition on changing shader bytecode only for the output-equivalent
constant-layout and control-flow rewrite specified here. It does not authorize
different material equations, fewer lights, fewer terrain layers, a vendor
fallback, or a different render path.

Repository commit creation still requires a separate explicit user request.

## Required outcome

The completed change must satisfy all of these conditions:

1. NVIDIA no longer exhibits the multi-fold exterior slowdown associated with
   enabling OMV native PBR.
2. The RX 6800 XT control retains its current performance and output.
3. Close terrain keeps all one-through-seven-layer, base/canopy, and
   `0/6/12/24` native-point-light rows.
4. The OMV portable/Pip-Boy light supplement remains available on every row,
   including native zero-point-light rows.
5. The combined native plus supplemental point-light cap remains 24, with the
   same order, positions, radii, RGB values, attenuation, and BRDF equations.
6. OMV keeps one engine-cache-owned shader pair per selected row. The fix adds
   no raw per-draw shader switch and no extra D3D draw or pass.
7. Normal render callbacks add no allocation, blocking lock, file I/O, shader
   compilation, state query, or repeated logging.
8. The released config schema, preset payload, startup publication order, hook
   set, and engine ABI remain unchanged.
9. The exact supported i686 tests and release build pass, and the affected
   NVIDIA runtime matrix closes the performance claim.

## Evidence and causal position

### Proven source and runtime facts

- OMV's PBR selection and close-terrain HLSL do not branch on PCI vendor.
  Native alpha-coverage modes and NvAPI/RESZ depth routes belong to other
  effects and do not select a PBR terrain program.
- The issue persists with and without DXVK. The physical NVIDIA GPU and its
  backend/compiler execution remain common, while the D3D translation route
  changes.
- The affected logs selected zero-native-point-light close-terrain rows:
  `B[116]` with four layers and `B[124]` with five layers.
- Modern NVR declares native point positions and colors as two contiguous
  arrays and indexes them directly. Its zero-point-light variants preprocess
  the entire point-light loop out.
- OMV declares one interleaved 48-register supplemental array and cannot use a
  shader-model-3 relative address for `index * 2` and `index * 2 + 1`.
- OMV's first correction removed the compiler's linear selection cascade but
  retained explicit native and supplemental binary selector trees. The
  affected NVIDIA playtest reported no performance improvement.
- The current one-layer zero-native row still compiles to 538 Wine instruction
  tokens and contains the complete 24-entry supplemental selector. NVR's
  equivalent zero-native row has no native point-light loop or selector.
- OMV needs the supplemental path because the native terrain pass can omit an
  otherwise eligible portable light. Removing that path would regress the
  already accepted Pip-Boy lighting behavior.

### Best current causal model

The strongest current explanation is NVIDIA-specific lowering or execution of
OMV's shader-model-3 constant-selection/control-flow shape. This is more
specific than a generic claim that PBR is expensive:

```text
admitted close-terrain row
  -> dynamic native/supplemental combined loop
  -> explicit 24-way constant selector trees
  -> NVIDIA-specific compiler/backend execution cliff
  -> exterior terrain multiplies the per-pixel cost
```

The RX 6800 XT result supports the vendor multiplier but does not prove the
driver-internal mechanism. Only an output-equivalent bytecode rewrite followed
by the affected-machine A/B can establish attribution.

### Explicit uncertainty

Static shader bytecode cannot prove final NVIDIA machine code or GPU time. The
split-array design below is therefore gated first by exact compiler output and
then by ordinary gameplay acceptance. If either compiler still lowers the new
access into a comparison cascade, implementation stops before deployment.

## Immutable boundaries

The fix must not:

- detect NVIDIA, AMD, DXVK, WineD3D, a driver version, or another mod at
  runtime;
- disable close terrain, supplemental lights, canopy companions, PBR, depth,
  shadows, or another graphics feature on NVIDIA;
- reduce the 24-light cap, terrain layer count, texture samples, resolution,
  or BRDF quality;
- alter native `c39..c88`, OMV terrain controls `c89/c90`, the combined light
  order, RGB-only visibility, attenuation, fog, normal blending, or material
  equations;
- add another close-terrain shader per row or select a shader from the
  per-geometry supplemental count;
- issue a raw `SetPixelShader` or `SetVertexShader` for an admitted draw;
- change the global HLSL compiler flags merely to influence this family;
- add a config field, preset migration, runtime tuning switch, TLS owner,
  `LazyLock`, mutex, worker, hook, or engine-facing publication;
- change another mod or build anything under `.research`.

Two shader programs per row are specifically rejected. Supplemental-light
membership becomes final only at the geometry draw boundary. Choosing a second
program there would reintroduce a raw per-draw shader transition while the
engine cache owns the original replacement. It would also double close-terrain
prewarm inputs and D3D resources. The selected design keeps one shader handle
and makes the supplemental loop execute zero iterations when its count is
zero.

## Target shader and constant ABI

### Register layout

Keep all native and material registers unchanged. Replace only the internal
layout of `c92..c139`:

| Registers | Current meaning | Target meaning |
|---|---|---|
| `c39..c62` | native point colors | unchanged |
| `c63..c86` | native point positions/radii | unchanged |
| `c88.x` | native point count | unchanged |
| `c89/c90` | OMV terrain controls | unchanged |
| `c91.x` | supplemental point count | unchanged |
| `c92..c115` | first half of interleaved data | supplemental positions/radii `[24]` |
| `c116..c139` | second half of interleaved data | supplemental colors `[24]` |

The register range and total maximum upload size remain unchanged. No consumer
outside OMV's replacement shader owns `c91..c139`.

### HLSL structure

In `native_pbr_pplighting_close_terrain.hlsl`:

1. Replace `OMV_SupplementalPointLightData[48]` with separate fixed arrays for
   positions and colors at the registers above.
2. Delete `LoadNativePointLight`, `LoadSupplementalPointLight`, all terminal
   selector macros, and every selector-tree branch.
3. Preserve the native compile-time `PBR_TERRAIN_POINT_LIGHTS` guard.
4. Evaluate native lights in their own bounded dynamic loop using direct
   `PointLightPosition[i]` and `PointLightColor[i]` reads.
5. Evaluate supplemental lights in a second bounded dynamic loop using direct
   `OMV_SupplementalPointLightPosition[i]` and
   `OMV_SupplementalPointLightColor[i]` reads.
6. Clamp the supplemental loop count to `24 - native_point_count`, exactly as
   today. Preserve native-first ordering.
7. Call one shared point-light accumulation helper from both loops so
   attenuation, tangent-space transformation, the `0.001` gate, RGB use, and
   prepared PBR evaluation cannot drift.

For a native zero-point-light row, preprocessing must remove the native array
declarations and native loop. The supplemental loop remains because a portable
light may legitimately be present, but a zero supplemental count executes no
iterations. There must be no native-versus-supplemental branch inside either
loop.

### CPU serialization

In `terrain_lights.rs`, retain the existing scalar light representation,
selection, identity deduplication, order, cache key, and fixed atomic cache.
Change only `write_shader_constants`:

- row 0 is the count for `c91`;
- rows 1 through 24 are positions/radii for `c92..c115`;
- rows 25 through 48 are colors for `c116..c139`;
- inactive rows are zero;
- an empty payload initializes and uploads only the count row;
- a nonempty payload reports the full 49-row ABI block as initialized.

In `constants.rs`, retain one `SetPixelShaderConstantF` call per admitted close
terrain draw:

- empty supplement: upload `c89..c91`, explicitly resetting stale count to
  zero;
- nonempty supplement: upload the complete `c89..c139` block in one call.

Uploading the complete split block avoids adding two more driver calls for
separate position and color ranges. The maximum transfer remains 51 float4
rows including `c89/c90`, which the existing ABI already reserves and can
upload at its 24-light maximum. The byte increase for a small nonempty set must
be recorded in the static performance table and accepted only if the NVIDIA
runtime gate passes.

## Source-change inventory

### Required production changes

| File | Planned change |
|---|---|
| `omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl` | split constant arrays, remove selectors, separate native/supplemental loops, share light evaluation |
| `omv/src/effects/pbr/terrain_lights.rs` | serialize the split fixed ABI without changing light selection or cache ownership |
| `omv/src/effects/pbr/constants.rs` | preserve one constant setter and choose empty versus full split-block upload length |
| `omv/src/effects/pbr/shader_registry.rs` | replace obsolete source/selector regressions with exact split-ABI and bytecode-lowering gates; retighten measured budgets |
| `omv/src/effects/pbr/compiler.rs` | tests only if needed to prove unchanged template grouping/cache scope; no production topology change |
| `omv/src/effects/pbr/hooks.rs` | source-architecture tests only; admitted draw selection and shader ownership must remain unchanged |

No production change is expected in `device_resources.rs`, `startup.rs`,
`runtime.rs`, `backend/fnv.rs`, `libpsycho`, config, presets, hook installation,
or draw-boundary code. If implementation unexpectedly requires one of those
areas, stop and update this plan before expanding scope.

### Shader registry and cache invariants

- Keep exactly one close-terrain vertex entry and the existing 56 pixel
  entries.
- Preserve every SLS number, base/canopy alias, texture-count define, native
  point-capacity define, stage, profile, and cache family.
- Keep base and canopy companion bytecode identical for the same layer/light
  row.
- Keep `HLSL_COMPILER_FLAGS` unchanged.
- Do not bump the global `SHADER_CONTRACT_REVISION` solely for this source
  edit. The complete source is already part of the cache key and validation;
  tests must prove that only changed close-terrain compile groups miss.
- Preserve asynchronous CPU preparation and Present-owned D3D resource
  creation. No compilation or creation may move into a render callback.
- Preserve existing family failure behavior: incomplete or failed
  close-terrain resources keep the family native rather than using partial
  replacement.

## Implementation and proof sequence

### Phase 0: freeze the comparison and prove compiler feasibility

Before editing production source:

1. Record the accepted OMV startup baseline. The current documented baseline
   is commit `9975b2e`; current OMV production code is unchanged from it.
   Record the exact reviewed and deployed DLL hashes and successful startup
   markers.
2. Preserve a current pre-fix close-terrain bytecode/metric table for
   representative rows `SLS2092`, `SLS2116`, `SLS2124`, `SLS2140`, and their
   `6/12/24`-light counterparts.
3. Compile a minimal split-array prototype with the production entry point,
   `ps_3_0`, and unchanged flags through:
   - the normal repository Wine compiler route; and
   - the exact native `d3dcompiler_47.dll` used by the game prefix.
4. Inspect normalized shader-model-3 bytecode, not only HLSL or total static
   slot count.

The prototype may proceed only if both compilers show:

- direct relative constant addressing for the two separate arrays;
- no linear `cmp` selection cascade;
- no 24-way `if`/`ifc` selector tree;
- one bounded supplemental loop;
- no native loop in a zero-native-light row;
- unchanged texture sample count and shader-model version.

If either compiler fails these conditions, do not land a compiler-flag change
or fallback selector. Stop and design a separately reviewed shader-model-3
specialization strategy using the captured bytecode evidence.

### Phase 1: add failing regressions

Add the tests before the production rewrite so they reject the current source:

1. Exact source ABI test for split register declarations and direct indexing.
2. Negative source test rejecting the interleaved array, selector loader
   functions, terminal selector macros, and index-comparison tree.
3. Pure serializer test across every supplemental count `0..=24`.
4. Semantic light-input equivalence test across native capacities
   `0/6/12/24`, including cap truncation and native-first order.
5. Zero-to-nonzero-to-zero test proving `c91` prevents stale light reuse.
6. Compiler micro-test retaining the interleaved dynamic access as a negative
   control and proving the split access uses bounded relative addressing.
7. Production bytecode tests for zero/native-lit representative rows.
8. Source-architecture tests rejecting new raw shader setters, extra shader
   variants, changed compiler flags, or another per-draw D3D call.

### Phase 2: implement the single coherent ABI rewrite

Land the HLSL declaration/control-flow change and CPU serializer/upload change
together. Do not temporarily deploy mismatched CPU and shader layouts. Keep the
patch limited to the files in the required source inventory.

After the rewrite, update bytecode ceilings from measured results. Use tight
per-family ceilings with small explicit slack; do not retain the old broad
limits merely to make the test pass. Record for each representative:

- byte size;
- instruction tokens;
- `loop`, `mova`, `if`, `ifc`, and `cmp` counts;
- relative constant reads;
- texture samples;
- maximum constant register.

### Phase 3: static integration and startup-footprint audit

Run focused tests first, then the complete supported gates once:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
cargo fmt --all -- --check
git diff --check
```

Also compile every registered PBR variant through the exact native compiler in
the game prefix. A Wine-only success is insufficient because a prior selector
fix passed Wine and failed the native compiler.

Compare the release DLL with the accepted startup baseline for:

- imports and delay imports;
- TLS directory, callbacks, and symbols;
- `.text`, `.rdata`, `.data`, and `.bss` sizes;
- exported ABI;
- template and unique compile-group counts;
- static/lazy owner inventory;
- plugin-load call order;
- config schema, preset manifests, and shipped payload;
- cold-cache worker count and preparation phase ordering.

Expected pre-Deferred delta: changed embedded HLSL bytes and cache misses for
the existing close-terrain groups only. There must be no new import, TLS,
owner, worker, template, hook, config, or publication delta.

### Phase 4: ordinary runtime acceptance

Deploy the exact reviewed release artifact and record its hash. Use the same
save, camera, weather, time, resolution, AA, mod list, configuration, and
warm-up for each comparison. Shader preparation must be complete before frame
sampling.

Required systems:

- the affected physical NVIDIA GPU on the normal Proton/DXVK route;
- the same NVIDIA system without DXVK when that route remains reproducible;
- the RX 6800 XT control on its normal route.

Required scenes:

- the original exterior/camera path that produced the catastrophic result;
- a daylight exterior with no visible portable-light contribution;
- a night exterior with Pip-Boy off and on, including a native zero-light row;
- a scene selecting native point-light terrain rows when practical;
- canopy companion geometry while rotating and approaching it;
- an interior/object-PBR control;
- alt-tab or device reset followed by the same exterior.

Capture at least 300 warm gameplay frames per sample and report median, p95,
p99, worst non-transition frame, and consecutive frames over 100 ms. Average
FPS alone is not acceptance.

Performance gates inherited from the NVIDIA remediation contract:

1. No ten consecutive gameplay frames exceed 100 ms outside loading,
   compilation, menu transition, or reset.
2. NVIDIA PBR-enabled median frame time is no more than 1.5 times the exact
   same-scene PBR-disabled median.
3. NVIDIA no longer retains a multi-fold normalized PBR on/off slowdown absent
   from the AMD control.
4. The RX 6800 XT shows no statistically meaningful regression; investigate
   any median or p95 loss above five percent before acceptance.
5. Interiors and master-disabled behavior do not regress.

Visual gates:

- stable terrain material, normal, sun, fog, and layer blending;
- identical native/supplemental light order and total contribution;
- Pip-Boy illumination remains present on the previously accepted zero-native
  terrain case;
- no return of dark/blinking terrain rectangles;
- base and canopy companions remain visually coherent;
- missing-resource fallback remains native and safe.

Startup gates:

- at least three cold starts with the representative modlist and
  BaseObjectSwapper installed;
- xNVSE completes plugin initialization;
- OMV reaches DeferredInit world publication, deferred hook initialization,
  completed PBR preparation, and live Present telemetry;
- no BaseObjectSwapper `+0x4990` crash;
- no per-start rebuilding after the changed close-terrain cache has been
  populated.

## Failure behavior and stop conditions

- Compiler incompatibility: keep the existing shader and stop. Do not weaken
  the bytecode gate.
- Shader creation failure: preserve current family-atomic native fallback and
  report the existing one-time failure status.
- Constant upload failure: keep that geometry native through the existing
  fallback path.
- Missing sampler or stale device/resource generation: keep the existing exact
  native fallback.
- Pre-Deferred crash: investigate only the changed embedded-source/cache
  preparation footprint until DeferredInit is restored. Do not tune render
  code or intervene in another mod.
- Visual mismatch: reject the build even if performance improves.
- NVIDIA performance gate still fails: do not call this a fix and do not add a
  vendor downgrade. Preserve the measurements, identify the next longest
  driver-facing interval, and revise the causal plan before another source
  change.

The shader ABI rewrite is a release fix only after the affected NVIDIA result
passes. Static instruction reduction on AMD or Wine is not sufficient.

## Documentation closure

The implementation change must update:

- `docs/graphics_fnv_pbr_errata.md` with exact old/new source and bytecode
  metrics, compiler identities, runtime result, and the proven/inferred split;
- `docs/graphics_fnv_close_terrain_portable_light_fix_plan.md` with the final
  split `c91..c139` ABI and serializer behavior;
- `docs/graphics_fnv_omv_nvidia_remediation_implementation.md` with the
  affected-machine result and root-cause status;
- `docs/graphics_fnv_omv_nvidia_1fps_remediation_plan.md` with completion or
  remaining-failure status;
- `docs/graphics_fnv_atmosphere_startup_crash_errata.md` and
  `docs/nvse_startup_phase_safety.md` only after the new artifact passes the
  required cold-start acceptance and becomes an accepted baseline.

Record exact commit, DLL hashes, compiler versions/routes, log paths, frame-time
artifacts, GPU/driver/runtime identity, and any remaining playtest limitation.
Keep static proof, inference, and runtime observation explicitly separated.

## Definition of done

This work is complete only when:

- both supported compiler routes produce the required direct relative access;
- the old interleaved access and both selector trees are absent;
- the CPU and HLSL split layouts match for all 24 entries;
- all light/material equations and coverage tests pass;
- no template, resource, hook, draw, config, or startup owner is added;
- the complete i686 OMV suite and release build pass;
- the reviewed artifact passes startup, reset, visual, AMD, and NVIDIA runtime
  gates;
- the catastrophic NVIDIA PBR frame-time cliff is gone in the original scene;
- durable documentation records the exact evidence and accepted artifact.

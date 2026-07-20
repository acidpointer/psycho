# FNV Close-Terrain Portable Point-Light Static Fix Plan

Date: 2026-07-20

Status: OMV-side implementation and static validation.

## Decision

Fix close-terrain PBR lighting entirely in OMV. External terrain-mod source is
read-only evidence and is never patched, built, packaged, or version-gated by
this work.

OMV supplements its own replacement shader from the engine's active light
state. It does not modify the native render pass, replace another mod's pass
builder, overwrite another mod's light constants, or identify a particular DLL
version.

The merge is idempotent by native `NiLight*` identity:

- if the current pass omits an eligible general active point light, OMV adds it
  only to OMV-owned constants;
- if a current or future terrain implementation already includes that light,
  OMV adds nothing;
- if the OMV close-terrain draw contract is not admitted, native rendering is
  unchanged.

## Proven Defect and Engine Contract

Authoritative inputs:

- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_portable_light_classification_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_pipboy_light_0147_shadow_path_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_light_value_copy_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_shader_virtual_interface_followup_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_ao_temporal_basis_handedness_followup.txt`
- `analysis/shaders_disasm/shaderpackage019/SLS2092.pso.dis`
- `analysis/shaders_disasm/shaderpackage019/SLS2100.pso.dis`
- `analysis/shaders_disasm/shaderpackage019/SLS2140.pso.dis`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`

The static evidence proves:

- `0x00B70590` / `0x00B70680` enumerate the general active light list;
- `0x00B70600` / `0x00B70700` additionally reject
  `ShadowSceneLight+0xEC == 1`, the shadow-classified subset;
- the expanded landscape pass builder in the researched terrain source uses
  the non-shadow iterator, so a shadow-classified portable point light can be
  absent from the pass while remaining valid for general object lighting;
- the current `RenderPass` at `0x0126F74C` owns its light array at `+0x0C` and
  count at `+0x09`;
- `ShadowSceneLight+0xF4/+0xF5/+0xF8` are point, ambient, and native-light
  fields; `+0xD0/+0xD4` are LOD dimmer and fade;
- native light translation, dimmer, diffuse color, and radius are at
  `+0x8C/+0xC4/+0xD4/+0xE0`;
- the renderer adds `ShadowSceneNode[0]+0x1E4` to the camera-relative light
  position before applying the geometry matrix;
- `0x00C4C2D0` builds the exact geometry matrix passed to native light staging;
- terrain multibound eligibility uses parent `IsMultiBoundNode`, node `+0xAC`,
  shape `+0x0C`, and AABB `CheckBound @ 0x00C382B0`;
- native terrain lighting caps point lights at 24 and stages light fade in color
  alpha.
- `ShadowSceneNode+0xB4` is a manager-wide linked list with next at node `+0x00`
  and `ShadowSceneLight*` at node `+0x08`;
- active state `+0x110 == 0x00FF` rejects a light, while shadow class `+0xEC == 1`
  is exactly the class excluded by the non-shadow iterator;
- vanilla terrain pixel shaders center every encoded normal sample by `-0.5`
  before applying its blend weight and normalizing the combined result.

This evidence identifies a safe downstream intervention: the OMV replacement
draw after native state is staged and before OMV uploads its own constants.

## OMV Production Design

### 1. Exact draw boundary

Run supplementation only inside the already-admitted close-terrain replacement
path. Keep all existing pass/pixel-row, shader-pair, sampler, exterior, and
resource gates. Canopy rows and foreign/mismatched rows remain native.

### 2. Read current native membership

Read the current pass light array once. Record native `NiLight*` identities and
count native point lights. The directional light may be present in the same
array but does not consume point-light capacity.

### 3. Enumerate general active candidates

Walk `0x00B70590` then `0x00B70680` in engine order. Do not resort or mutate the
property list. Stop when OMV fills the remaining 24-light capacity or after a
fixed corruption guard of 64 iterator results.

Each candidate must satisfy the source-equivalent contract:

- non-null native identity;
- point light and not ambient;
- enabled native light;
- at least one `diffuse * dimmer` component greater than `1/255`;
- positive finite radius and finite color/dimmer/fade data;
- valid current forced-darkness behavior;
- intersection with the geometry multibound when one exists;
- identity absent from both the native pass and prior supplemental output.

Preserve iterator order. Do not search for Pip-Boy, torch, flashlight, editor
ID, form ID, owner name, or module origin.

### 4. Match native value staging

For each selected supplemental light:

- add the active shadow-scene lighting offset to its camera-relative position;
- apply the exact matrix produced by `0x00C4C2D0`;
- divide radius by geometry world scale;
- clamp dimmer to 1 only in non-HDR mode;
- multiply diffuse RGB by dimmer, property forced darkness, and scene-light LOD
  dimmer;
- keep scene-light fade in alpha for saturated shader consumption;
- suppress the point light when forced darkness is below 1, matching the
  terrain staging contract.

Invalid inputs reject only that supplemental candidate. Failure to capture the
engine context produces an empty supplemental set and leaves native OMV terrain
lighting intact.

If a zero-native-point row's property-local iterator yields no missing light,
walk at most 64 entries from the proven manager-wide
`ShadowSceneNode+0xB4` list. Accept only active shadow-classified entries and
feed them through the exact same candidate filters and identity merge. Do not
run this second scan when the native pass or normal supplement path already
owns a point light.

### 5. OMV-only shader ABI

Keep upstream terrain constants unchanged:

- native point colors: `c39...`;
- native point positions: `c63...`;
- native point count: `c88`;
- OMV terrain settings: `c89/c90`.

Add a disjoint OMV ABI:

- `c91.x`: supplemental point-light count;
- `c92..c139`: up to 24 interleaved position/radius and color/fade pairs.

Upload `c89` through the last active supplemental pair in one OMV setter call.
An empty set still uploads `c91 = 0`, preventing stale supplemental lights from
leaking into a later draw.

The replacement pixel shader evaluates native and supplemental loops
separately with the same attenuation and PBR point-light function. Supplemental
evaluation is unconditional across the `0/6/12/24` native row families, so an
old pass that selected its zero-point-light row can still receive a genuinely
missing portable light.

Blend terrain normals with the vanilla center-before-weight equation. Decoding
one final encoded sum is forbidden because it is equivalent only when active
blend weights total exactly one; partial weights can invert an upward normal
and erase overhead point-light response.

## Mod-Agnostic Compatibility Rule

No compatibility export, private RVA, DLL version, source hash, plugin version,
or filename decides whether the correction runs.

The engine pass itself is the capability signal:

| Current engine state | OMV result |
|---|---|
| Eligible general light missing from pass | Add one OMV supplemental light |
| Same `NiLight*` already in pass | Add zero |
| Duplicate general-list entry | Add once |
| Native point count already 24 | Add zero |
| Close-terrain draw contract not admitted | Do not inspect or change lights |
| Required engine context invalid | Upload supplemental count zero |

This automatically accommodates an upstream fix, reorder, or changed selection
policy as long as the current draw still satisfies OMV's independently proven
close-terrain shader ABI. An incompatible future shader/pass ABI must fail the
existing OMV draw gate and remain native; it must not be guessed from a version
number.

## Static Validation

Static tests call the production merge and transform helpers directly.

Required pure tests:

1. An old-style pass omits a valid general candidate: exactly one supplement.
2. A future fixed pass already includes the same `NiLight*`: zero supplements.
3. Native and supplemental duplicates are removed by identity.
4. General iterator order is preserved.
5. Native plus supplemental point lights never exceed 24.
6. Directional, ambient, disabled, black, out-of-bound, invalid, and non-finite
   candidates are rejected.
7. Forced-darkness and HDR/non-HDR dimmer behavior match native terrain staging.
8. Camera-relative offset, engine D3D matrix convention, and scale-adjusted
   radius produce exact expected constants.
9. Constant payload is `count + interleaved pairs`, and an empty payload resets
   count to zero.
10. A zero-native-light row accepts an active manager shadow light, while
    non-shadow and inactive manager entries are rejected.
11. Production offsets and list-node layout remain linked to their Ghidra
    source contract.

Required row and shader tests:

1. All 28 non-canopy close-terrain variants map exactly across 1..7 textures
   and native capacities 0/6/12/24.
2. All 28 canopy companions remain classified but native.
3. Mismatched and foreign pass/pixel pairs are rejected.
4. HLSL source asserts native `c39/c63/c88`, OMV `c91/c92..c139`, and saturated
   alpha use.
5. Every registered PBR shader permutation compiles with the real D3D compiler.
6. Representative 1-layer and 7-layer, zero-light and 24-light bytecode remains
   under per-variant bytecode and instruction budgets with exact texture-sample
   counts.
7. A source-linked normal test proves the shader matches the vanilla
   center-before-weight equation and includes the old equation as a negative
   control.
8. A zero-native-light night test proves partial flat-normal weights retain
   positive overhead PBR diffuse response for both ordinary and configured
   metallic terrain, while the old equation produces zero.

Build and test only the supported target:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

The workspace release build remains a separate regression gate for the shipped
FNV components. No external terrain project is built.

## Performance Contract

This correction adds no logs, counters, status UI, D3D getters, per-frame
history, allocations, locks, material scans, or texture work.

Per admitted close-terrain draw it performs:

- one bounded current-pass identity scan;
- one bounded engine iterator walk that stops at remaining capacity;
- only for a zero-native-point row when that walk finds no missing light, one
  bounded 64-entry manager shadow-light scan;
- one multibound lookup and candidate bound checks;
- one engine matrix build;
- one fixed-size stack merge;
- the existing OMV constant upload extended only through active pairs.

The corrected normal blend changes no texture count or dynamic light-loop
bound. The representative compiler gates cap both bytecode and instruction
count, and require exactly 2 samples for one-layer rows and 14 for seven-layer
rows.

The implementation must not reintroduce the previous broad terrain diagnostic
or 14-texture hot-path work that caused the recorded large FPS loss.

## Files in Scope

- `omv/src/effects/pbr/terrain_lights.rs`
- `omv/src/effects/pbr/engine_contracts.rs`
- `omv/src/effects/pbr/constants.rs`
- `omv/src/effects/pbr/hooks.rs`
- `omv/src/effects/pbr/shader_registry.rs`
- `omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl`
- `docs/graphics_fnv_pbr_errata.md`
- `docs/graphics_fnv_pbr_light_shadow_continuity_fix_plan.md`
- `docs/graphics_fnv_omv_dependency_compatibility_plan.md`
- this plan

`.research/fnv-vanilla-plus-terrain-main/` is explicitly out of scope for
changes and builds.

## One Ordinary Playtest

Static validation is the deployment gate. The only requested runtime check is
an ordinary feature-first playtest:

1. Use the exterior location where the player/portable light illuminates
   objects but previously not close terrain.
2. Enable OMV terrain PBR and toggle the portable light while stationary.
3. Walk across the original transition and multibound boundary.
4. Confirm terrain illumination follows the light without duplicate brightness,
   chunk blinking, color corruption, interior leakage, or a material FPS loss.

No diagnostic build or telemetry session precedes this playtest. Static tests
cannot prove final pixels, driver behavior, or the live multibound result; the
playtest checks only those remaining runtime facts.

## Acceptance Criteria

- External mod source is unchanged.
- OMV repairs missing close-terrain portable illumination using engine state.
- A pass that already owns the light receives no duplicate contribution.
- Native pass membership and native constants remain untouched.
- Supplemental constants are OMV-owned, bounded, reset every close-terrain
  draw, and alpha-aware.
- Static merge, transform, mapping, ABI, compiler, bytecode, and i686 build
  gates pass.
- The ordinary playtest shows correct illumination without the known terrain
  regressions.

## Explicit Non-Fixes

- patching, forking, compiling, or redistributing VPT;
- version/export capability handshakes;
- changing the native light sorter or shadow classifier;
- adding comparator hysteresis or a second shadow fade;
- identifying the portable light by name or form;
- mutating another owner's render pass or `c39/c63/c88` data;
- broadening close-terrain draw admission;
- enabling canopy replacement;
- claiming that static tests prove runtime pixels.

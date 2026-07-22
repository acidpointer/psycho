# FNV Close-Terrain Portable Point-Light Static Fix Plan

Date: 2026-07-20

Status: closed. The corrected implementation, production-path regression, and
runtime pixel acceptance all passed.

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

Executable researched: `FalloutNV.exe`, PE32 x86, image base `0x00400000`,
SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Address-sensitive conclusions below apply to this executable identity. Direct
radare2 inspection was cross-checked against the existing authoritative static
outputs listed here.

Authoritative inputs:

- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_portable_light_classification_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_pipboy_light_0147_shadow_path_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_light_value_copy_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_manager_epoch_contract_followup.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_light_selection_continuity_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_shader_virtual_interface_followup_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_ao_temporal_basis_handedness_followup.txt`
- `analysis/shaders_disasm/shaderpackage019/SLS2092.pso.dis`
- `analysis/shaders_disasm/shaderpackage019/SLS2100.pso.dis`
- `analysis/shaders_disasm/shaderpackage019/SLS2140.pso.dis`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl`

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
- native staging calls
  `0x00C4C2D0(geometry+0x68, *(geometry+0xBC), output)`; its non-null context
  branch is not equivalent to passing null;
- terrain multibound eligibility uses parent `IsMultiBoundNode`, node `+0xAC`,
  shape `+0x0C`, and AABB `CheckBound @ 0x00C382B0`;
- native terrain lighting caps point lights at 24 and stages light fade in color
  alpha.
- `FUN_00B9E970` can drive `ShadowSceneLight+0xD4` to zero as part of native
  light/shadow transition state;
- the VPT close-terrain pixel source consumes `PointLightColor[i].rgb` and not
  `.a`, so native fade alpha is not proof that an omitted light is physically
  invisible;
- `ShadowSceneNode+0xB4` is a manager-wide linked list with next at node `+0x00`
  and `ShadowSceneLight*` at node `+0x08`;
- active state `+0x110 == 0x00FF` rejects a light, while shadow class `+0xEC == 1`
  is exactly the class excluded by the non-shadow iterator;
- `BSLightingShaderProperty+0x6C` is the scalar passed to native light staging,
  not a darkness Boolean. For point lights and values below one,
  `0x00B70820` substitutes RGB at
  `0x011F4998/0x011F499C/0x011F49A0` and still stages fade from
  `ShadowSceneLight+0xD4`;
- the manager `+0xB4` chain is stable during the synchronous world-light
  transaction at `0x00871290`; its pointers are not proven safe at an
  arbitrary later terrain draw;
- vanilla terrain pixel shaders center every encoded normal sample by `-0.5`
  before applying its blend weight and normalizing the combined result.

This evidence identifies a safe downstream intervention: the OMV replacement
draw after native state is staged and before OMV uploads its own constants.

## OMV Production Design

### 1. Exact draw boundary

Run supplementation only inside the already-admitted close-terrain replacement
path. Keep all existing pass/pixel-row, shader-pair, sampler, exterior, and
resource gates. Foreign and mismatched rows remain native. The original
portable-light deployment kept canopy companions native; the later dark-square
regression proved that policy incomplete. All 28 canopy companions now use
their own PBR identities but compile to the same material/light bytecode as
their paired base rows. They do not consume native `s14/s15`, as documented in
`graphics_fnv_pbr_errata.md`.

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
- positive finite radius and finite color/dimmer data; native fade is not a
  supplemental admission input;
- valid current property-light scalar behavior;
- intersection with the geometry multibound when one exists;
- identity absent from both the native pass and prior supplemental output.

Preserve iterator order. Do not search for Pip-Boy, torch, flashlight, editor
ID, form ID, owner name, or module origin.

### 4. Match native value staging

For each selected supplemental light:

- add the active shadow-scene lighting offset to its camera-relative position;
- call `0x00C4C2D0` with `geometry+0x68` and the context stored at
  `geometry+0xBC`, then apply the resulting matrix;
- divide radius by geometry world scale;
- clamp dimmer to 1 only in non-HDR mode;
- for property scalar values at least one, multiply diffuse RGB by dimmer, the
  property scalar, and scene-light LOD dimmer;
- for property scalar values below one, use the native point-light override RGB
  at `0x011F4998/0x011F499C/0x011F49A0` instead of suppressing the light;
- keep native-row scene-light fade in its native alpha path;
- write explicit visibility `1.0` for an OMV supplemental light, because
  reusing the fade from the native path that omitted it can erase valid
  illumination;

Invalid inputs reject only that supplemental candidate. Failure to capture the
engine context produces an empty supplemental set and leaves native OMV terrain
lighting intact.

If a zero-native-point row's property-local iterator yields no missing light,
consume at most 64 copied entries from the manager-wide scalar epoch. The
epoch is produced after the proven `0x00871290` world transaction and tagged
with render epoch and D3D device identity. A terrain draw uses `try_lock` and
requires both tags to match. Accept active copied entries regardless of mutable
shadow-casting state at `ShadowSceneLight+0xEC`, then feed them through the
same candidate filters and identity merge. Active state at `+0x110`, not
shadow ownership, controls capture eligibility. No manager node or engine
object pointer survives publication.

### 5. OMV-only shader ABI

Keep upstream terrain constants unchanged:

- native point colors: `c39...`;
- native point positions: `c63...`;
- native point count: `c88`;
- OMV terrain settings: `c89/c90`.

Add a disjoint OMV ABI:

- `c91.x`: supplemental point-light count;
- `c92..c139`: up to 24 interleaved position/radius and color/visibility pairs.

Upload `c89` through the last active supplemental pair in one OMV setter call.
An empty set still uploads `c91 = 0`, preventing stale supplemental lights from
leaking into a later draw.

The replacement pixel shader evaluates native and supplemental entries through
the same bounded loop, attenuation, and PBR point-light function. Supplemental
evaluation is unconditional across the `0/6/12/24` native row families, so an
old pass that selected its zero-point-light row can still receive a genuinely
missing portable light. Native entries retain saturated native alpha;
supplemental entries arrive with explicit visibility one.

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
7. Property scalar values below one use the source-proven native point-light
   override RGB instead of suppressing the candidate; ordinary scalar and
   HDR/non-HDR dimmer behavior still match native staging.
8. Camera-relative offset, engine D3D matrix convention, exact
   `geometry+0x68`/`geometry+0xBC` arguments, and scale-adjusted radius produce
   the expected constants.
9. Constant payload is `count + interleaved pairs`, and an empty payload resets
   count to zero.
10. A zero-native-light row accepts active point lights from a current copied
    manager epoch, while inactive or disabled entries are rejected at capture.
11. Stale-frame and foreign-device epochs are rejected, and production terrain
    code contains no raw manager-list walk.
12. Production offsets, native override behavior, matrix-call provenance, and
    manager snapshot ownership remain linked to their static source contracts.
13. A zero-native row plus a copied manager Pip-Boy-like light with zero native
    shadow/pass fade reaches the production merge, serializes through
    `c91..c93` with visibility one, and produces positive attenuated overhead
    light input. The pre-fix alpha-zero behavior is the negative control.

Required row and shader tests:

1. All 56 close-terrain variants map exactly across 1..7 textures, native
   capacities 0/6/12/24, and base/canopy companions.
2. All 28 canopy companions exclude `s14/s15`; each production-compiled shader
   is byte-identical to its paired base row so projected object-shadow data
   cannot make local-light response camera-dependent.
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
8. A partial-weight night test proves flat terrain normals retain positive
   overhead PBR diffuse response for both ordinary and configured metallic
   terrain, while the old normal equation produces zero. It intentionally does
   not claim to cover light capture or payload delivery.

Build and test only the supported target:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

The workspace release build remains a separate regression gate for the shipped
FNV components. No external terrain project is built.

Validation evidence on 2026-07-21:

- the new zero-native/zero-fade production-path regression failed before the
  correction (`c93.w == 0`) and passed after it (`c93.w == 1` with positive
  attenuated overhead light input);
- focused terrain staging: 18 passed, 0 failed;
- focused shared light-epoch ownership: 11 passed, 0 failed;
- complete OMV suite: 234 passed, 0 failed, including registered PBR shader
  compilation and representative close-terrain bytecode budgets;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed;
- runtime acceptance: the user confirmed that the previously unaffected dark
  terrain now responds to the Pip-Boy light with the corrected release DLL,
  SHA-256
  `fccfa48f6f1b67726dc0c24b0fb915bc3ebd112e6bf2724baa59e76439d15840`.

## Performance Contract

This correction adds no per-draw logs, counters, status UI, D3D getters,
allocations, blocking locks, material scans, or texture work.

Once per world-light epoch, the shared `0x00871290` hook performs one existing
bounded manager traversal. When terrain PBR is enabled it copies at most the
first 64 active/enabled scalar records into a fixed mailbox. Terrain-only use
does not start or retain the atmosphere shadow-texture capture path.

Per admitted close-terrain draw it performs:

- one bounded current-pass identity scan;
- one bounded engine iterator walk that stops at remaining capacity;
- only for a zero-native-point row when that walk finds no missing light, one
  `try_lock` and a bounded scan of copied scalar records;
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
- `omv/src/fnv_local_lights.rs`
- `omv/src/startup.rs`
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

## Runtime Acceptance and Regression Checklist

The user completed the feature-first runtime acceptance on 2026-07-21 and
confirmed the issue fixed: close terrain that remained dark while objects were
lit now responds to the Pip-Boy light. Preserve the following as the regression
checklist for any future change to terrain light selection or constants:

1. Use the exterior location where the player/portable light illuminates
   objects but previously not close terrain.
2. Enable OMV terrain PBR and toggle the portable light while stationary.
3. Walk across the original transition and multibound boundary.
4. Confirm terrain illumination follows the light without duplicate brightness,
   chunk blinking, color corruption, interior leakage, or a material FPS loss.

Static tests do not replace this recorded pixel result. A future change that
makes supplemental visibility inherit `ShadowSceneLight+0xD4`, removes the
zero-native-row regression, or again leaves terrain dark is a regression of
this closed contract, not a new design question.

## Acceptance Criteria

- External mod source is unchanged.
- OMV repairs missing close-terrain portable illumination using engine state.
- A pass that already owns the light receives no duplicate contribution.
- Native pass membership and native constants remain untouched.
- Supplemental constants are OMV-owned, bounded, reset every close-terrain
  draw, and use explicit visibility independent of native shadow/pass fade.
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
- changing the user's global canopy-shadow setting or sampling projected
  canopy resources without a proven VPT-compatible vertex/pixel ABI;
- claiming that static tests prove runtime pixels.

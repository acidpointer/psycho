# FNV Close-Terrain Portable Point-Light Static Fix Plan

Date: 2026-07-20

Status: implemented and statically validated; runtime acceptance for the
native/supplemental membership-equivalence correction is pending. The earlier
Pip-Boy zero-native-row subcase passed runtime acceptance. Manager recovery,
native color rewriting, the half-vector correction, and family-atomic
activation were each rejected as the owner of the residual random squares.

## Decision

Fix close-terrain PBR lighting entirely in OMV. External terrain-mod source is
read-only evidence and is never patched, built, packaged, or version-gated by
this work.

OMV supplements its own replacement shader from the engine's active light
state. It does not modify the native render pass, replace another mod's pass
builder, overwrite native `c39/c63/c88`, or identify a particular DLL version.

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
- VPT terrain multibound eligibility uses parent `IsMultiBoundNode`, node
  `+0xAC`, shape `+0x0C`, and AABB `CheckBound @ 0x00C382B0`; its tested
  `NiBound` uses the raw `NiLight::m_kWorld.m_Translate` and radius, matching
  OMV's `NiLight+0x8C/+0xE0` values;
- native terrain lighting caps point lights at 24 and stages light fade in color
  alpha, but VPT and NVR terrain pixel sources consume only RGB;
- `FUN_00B9E970` can drive `ShadowSceneLight+0xD4` to zero as part of native
  light/shadow transition state;
- the VPT close-terrain pixel source consumes `PointLightColor[i].rgb` and not
  `.a`, so native fade alpha is not proof that an omitted light is physically
  invisible;
- `ShadowSceneNode+0xB4` is a manager-wide linked list with next at node `+0x00`
  and `ShadowSceneLight*` at node `+0x08`;
- active state `+0x110 == 0x00FF` rejects a light, while shadow class `+0xEC == 1`
  is exactly the class excluded by the non-shadow iterator;
- `BSLightingShaderProperty+0x6C` is the forced-darkness scalar passed to native
  light staging. For point lights and values below one, `0x00B70820`
  substitutes the immutable black RGB at
  `0x011F4998/0x011F499C/0x011F49A0` while still staging fade from
  `ShadowSceneLight+0xD4`;
- the manager `+0xB4` chain is stable during the synchronous world-light
  transaction at `0x00871290`; its pointers are not proven safe at an
  arbitrary later terrain draw;
- vanilla terrain pixel shaders center every encoded normal sample by `-0.5`
  before applying its blend weight and normalizing the combined result.

The camera-dependent recurrence required inspection of the installed terrain
owner, not only its source. The installed `VanillaPlusTerrain.dll` is PE32 x86,
image base `0x10000000`, NVSE plugin version `101`, SHA-256
`a241bf8e0bdde3ad5cd4d3926b83cbee2fae8d3900e8c7822ab05957fa71247d`.
Radare2 proves:

- `NVSEPlugin_Load` calls initialization at DLL `+0x21B0`; DLL `+0x245D`
  replaces the game call at `0x00B7DBAC` with the wrapper at DLL `+0x1EE0`;
- the wrapper routes landscape rows `503..558` to the alternate light updater
  at DLL `+0x19F0`;
- DLL `+0x1C78` reads property `+0x6C`, and
  `+0x1C90..+0x1C98` zeros the point-light dimmer when that value is below one;
- DLL `+0x1CB6..+0x1CED` nevertheless preserves scene-light `+0xD4` as alpha,
  stores the point color, and increments the point-light index;
- DLL `+0x1E45..+0x1E57` publishes that index as the native point-light count.

This does not differ from Fallout. Radare2 reads twelve zero bytes at
`0x011F4998` and finds only read cross references, so the three substituted
floats are the engine's constant black color. The attempted `c39` rewrite was a
no-op and did not execute in the deployed session that reproduced the
artifact. It was removed.

The camera-dependent recurrence instead identifies a shader-local defect shared
by every close-terrain variant. The sun and point BRDFs used a surface-normal
fallback for a nearly zero `view + light` half-vector. Crossing that cutoff by a
small camera motion changes Fresnel and direct diffuse discontinuously. The
safe intervention is OMV's own replacement source; native light and pass state
remain untouched.

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
- for property scalar values below one, reproduce the native black result at
  `0x011F4998/0x011F499C/0x011F49A0`, which rejects the ineffective
  supplemental candidate;
- keep the supplemental fourth component neutral at `1.0`;
- consume only point-light RGB in the terrain shader for both native and
  supplemental entries, matching VPT and preventing pass membership from
  changing visibility;

Invalid inputs reject only that supplemental candidate. Failure to capture the
engine context produces an empty supplemental set and leaves native OMV terrain
lighting intact.

When native plus property-local point lights leave capacity, consume the
manager-wide scalar epoch. The epoch is produced after the proven `0x00871290`
world transaction and tagged with render epoch and D3D device identity. A
terrain draw uses `try_lock` and requires both tags to match. Accept active
copied entries regardless of mutable shadow-casting state at
`ShadowSceneLight+0xEC`, then feed them through the same candidate filters,
multibound test, and identity merge. Active state at `+0x110`, not shadow
ownership, controls capture eligibility. No manager node or engine object
pointer survives publication.

Terrain capture examines at most 512 manager nodes. It rejects inactive,
disabled, directional, ambient, invalid, and ineffectively dark entries before
they consume mailbox capacity, then retains the 64 candidates with the smallest
camera-normalized squared distance (`distance^2 / radius^2`). Native identity
breaks equal-score ties. If a valid world camera is temporarily unavailable,
the bounded fallback preserves the first 64 eligible manager entries. This
selection is fixed-size, allocation-free, and deterministic for a given world
epoch.

### 5. OMV-only shader ABI

Keep native light ownership and layout unchanged:

- native point colors remain at `c39...`;
- native point positions remain untouched at `c63...`;
- native point count remains untouched at `c88`;
- OMV terrain settings: `c89/c90`.

Add a disjoint OMV ABI:

- `c91.x`: supplemental point-light count;
- `c92..c139`: up to 24 interleaved position/radius and color/reserved-alpha
  pairs.

Upload `c89` through the last active supplemental pair in one OMV setter call.
An empty set still uploads `c91 = 0`, preventing stale supplemental lights from
leaking into a later draw.

The replacement pixel shader evaluates native and supplemental entries through
the same bounded loop, attenuation, and PBR point-light function. Supplemental
evaluation is unconditional across the `0/6/12/24` native row families, so an
old pass that selected its zero-point-light row can still receive a genuinely
missing portable light. Both native and supplemental entries contribute their
RGB without an alpha visibility gate.

Blend terrain normals with the vanilla center-before-weight equation. Decoding
one final encoded sum is forbidden because it is equivalent only when active
blend weights total exactly one; partial weights can invert an upward normal
and erase overhead point-light response.

Calculate sun and point BRDF half-vectors with branchless zero-safe
normalization. A surface-normal fallback is forbidden: it changes dielectric
Fresnel from about `0.04` to about `1.0` at a camera-dependent cutoff and can
erase direct diffuse response across a nearly flat terrain draw.

## Mod-Agnostic Compatibility Rule

No compatibility export, private RVA, DLL version, source hash, plugin version,
or filename decides whether the correction runs.

The engine pass itself is the capability signal:

| Current engine state | OMV result |
|---|---|
| Eligible general light missing from pass | Add one OMV supplemental light |
| Same `NiLight*` already in pass | Add zero |
| Duplicate general-list entry | Add once |
| Native point count already 24 | Add no supplement |
| Close-terrain draw contract not admitted | Do not inspect or change lights |
| Supplemental engine context invalid | Upload supplemental count zero |

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
7. Property scalar values below one reproduce the source-proven native black
   point-light result; ordinary scalar and HDR/non-HDR dimmer behavior still
   match native staging.
8. Camera-relative offset, engine D3D matrix convention, exact
   `geometry+0x68`/`geometry+0xBC` arguments, and scale-adjusted radius produce
   the expected constants.
9. Constant payload is `count + interleaved pairs`, and an empty payload resets
   count to zero.
10. A row with zero or unrelated native lights accepts missing active point
    lights from a current copied manager epoch, while inactive or disabled
    entries are rejected at capture.
11. Stale-frame and foreign-device epochs are rejected, and production terrain
    code contains no raw manager-list walk.
12. Production offsets, native override behavior, matrix-call provenance, and
    manager snapshot ownership remain linked to their static source contracts.
13. A zero-native row plus a copied manager Pip-Boy-like light with zero native
    shadow/pass fade reaches the production merge, serializes through
    `c91..c93` with visibility one, and produces positive attenuated overhead
    light input. The pre-fix alpha-zero behavior is the negative control.
14. Terrain-only capture examines the bounded 512-node manager epoch, filters
    before the 64-entry mailbox limit, and retains a camera-relevant candidate
    that arrives after raw node 64.
15. One unrelated native point light does not prevent a missing manager light
    from reaching the supplemental merge.
16. Moving the same light between native and supplemental membership cannot
    change its visibility: VPT contains no `PointLightColor.a` consumer and
    OMV's combined terrain loop likewise consumes RGB only. The previous
    zero-alpha native versus one-alpha supplemental result is the negative
    control.

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
9. A camera sweep across view/light opposition includes the old
   surface-normal fallback as a negative control. The old shader changes
   diffuse response by more than `0.9`; the production half-vector changes it
   by less than `0.001` for the same motion.

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

Validation evidence for the manager-recovery hypothesis on 2026-07-23:

- the all-row manager regression failed before the correction because
  `manager_fallback_needed(1, 0)` was false;
- the terrain-only epoch regression failed before the correction because its
  manager traversal stopped at raw node 64 instead of the bounded 512-node
  epoch;
- focused terrain validation: 38 passed, 0 failed;
- complete OMV suite: 261 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed; the
  resulting `omv.dll` SHA-256 is
  `fcfebf91fe18e9fe692a76470d1e05c1945c4106dca0059bf118200630e4b8e1`;
- runtime rejection: the user deployed this build and reported that the
  camera-dependent random rectangles were unchanged. These results validate
  manager completeness, not the moving-square root cause.

Rejected native-color hypothesis on 2026-07-23:

- Fallout's three supposed override floats are all zero and have only read
  cross references;
- the deployed reproduction log contains no native-color-repair activation,
  while close-terrain PBR is active and the artifact remains;
- the `c39` rewrite and its tests were removed rather than retained as an
  unproven compatibility patch.

Camera-discontinuity validation on 2026-07-23:

- the new production-source regression failed before the shader change because
  close terrain had no branchless `StableHalfway`;
- its old-equation negative control reproduces a greater-than-`0.9` direct
  diffuse response step across the former camera cutoff;
- after the shader change, the same motion changes response by less than
  `0.001`;
- complete OMV suite: 262 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed; the
  resulting `omv.dll` SHA-256 is
  `4e9c6a5c5bcd127ac391fdf38c411d113c057cf1892db924b8b18fc1926b5c43`;
- runtime pixels remain an ordinary playtest requirement. The shader
  discontinuity is proven; its identification with the reported rectangles
  remains reasoned inference until that acceptance passes.

Runtime rejected that identification later on 2026-07-23: the corrected
half-vector build reproduced the same squares. The user established a more
specific lifecycle discriminator: a new session initially looked correct, the
cell-aligned squares appeared only after travel, and disabling PBR removed
them.

Shader-family activation evidence and correction:

- the reproduced session queued all 162 PBR shaders at `11:47:06`;
- close terrain logged a warming `SLS2116` row at `11:47:59.793`, then activated
  the independently ready `SLS2100` row at `11:48:00.381`;
- at that activation only 4 of 57 close-terrain resources were ready;
- the session ended more than seven minutes later with 42 of 57 resources
  ready, without compiling the final 12-light companion or any 24-light row;
- the old policy therefore mixed native VPT and OMV PBR per terrain
  texture/light row. A camera-dependent point-light bucket change could switch
  the same terrain tile between those pipelines;
- the regression's legacy negative control proves that one selected ready row
  activated under the old policy, while the production gate rejects all
  partial-family combinations and every failure state;
- compiler readiness and current-device resource readiness are now published
  independently and required together for all 57 resources. Reset/device
  change clears the resource-ready publication;
- focused PBR suite: 70 passed, 0 failed;
- complete OMV suite: 263 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed; the
  resulting `omv.dll` SHA-256 is
  `ab77c17f8e95c3ef0b35b18ada0734cd22d8ae5f7a742256cd250540416cc898`;
- the prevention of mixed-family draws is statically proven. Visual closure of
  the reported squares still requires ordinary travel acceptance.

Runtime rejected the family-activation identification later on 2026-07-23.
The new session reached full `57/57` close-terrain compilation and resource
readiness before PBR activation, yet the random camera-dependent squares
returned unchanged.

Native/supplemental membership-equivalence evidence:

- VPT and NVR `TerrainTemplate.hlsl` pass `PointLightColor[i].rgb` to point
  lighting and never consume `.a`;
- VPT's multibound source uses the same raw light translation/radius sphere as
  OMV, rejecting the proposed collision-coordinate mismatch;
- OMV alone multiplied the combined terrain light RGB by
  `saturate(light_color.a)`;
- recovered lights used neutral alpha one, while the same light admitted by a
  native terrain pass could carry `ShadowSceneLight+0xD4 == 0`;
- the regression failed before the shader correction and passes only when the
  native and supplemental paths both consume RGB without alpha;
- focused PBR suite: 71 passed, 0 failed;
- complete OMV suite: 264 passed, 0 failed;
- every registered PBR shader permutation compiled and the representative
  close-terrain bytecode budgets passed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed; the
  resulting `omv.dll` SHA-256 is
  `7aa97812e5b802dc35c9c2b1f2d8636f9a9b3576cb2f4aff225cf5d8b2751df8`;
- `cargo fmt -p omv --all -- --check` and `git diff --check`: passed;
- runtime travel acceptance remains pending.

## Performance Contract

This correction adds no per-draw logs, counters, status UI, allocations,
blocking locks, material scans, constant uploads, or texture work.

The close-terrain `SetShaders` gate adds only fixed atomic readiness reads. The
compiler scans its 57 states only after a close-terrain compilation completes
and publishes one atomic family result; render callbacks never scan the family.
The current-device resource owner likewise publishes one atomic result after
its existing bounded creation service. Cold-cache compilation cost is
unchanged and remains off the render thread.

Once per world-light epoch, the shared `0x00871290` hook performs one existing
bounded traversal of at most 512 manager nodes. When terrain PBR is enabled it
filters scalar records before retaining at most 64 camera-relevant candidates
in a fixed mailbox. Ranking uses fixed arrays and no allocation. Terrain-only
use reads the existing world camera transform for relevance but does not start
or retain the atmosphere shadow-texture capture path.

Per admitted close-terrain draw it performs:

- one bounded current-pass identity scan;
- one bounded engine iterator walk that stops at remaining capacity;
- whenever native plus property-local lights leave capacity, one `try_lock`
  with the existing current-device identity check and a bounded scan of at
  most 64 copied scalar records;
- one multibound lookup and candidate bound checks;
- one engine matrix build;
- one fixed-size stack merge;
- the existing OMV constant upload extended only through active pairs.

The corrected normal blend, half-vector, and RGB-only light input change no
texture count or dynamic light-loop bound. Branchless half-vector normalization
removes a conditional selection; the membership fix removes one saturate and
multiply per evaluated point light. Neither adds a pass or sample. The
representative compiler gates cap both bytecode and instruction count, and
require exactly 2 samples for one-layer rows and 14 for seven-layer rows.

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

The user completed the feature-first Pip-Boy runtime acceptance on 2026-07-21:
close terrain that remained dark while objects were lit responded to the
portable light. The user then rejected the manager, native-color, and
half-vector explanations for the separate random-square symptom, and a later
fully ready session rejected family activation as its owner. The
membership-equivalence correction requires fresh runtime acceptance:

1. Use the exterior location where the player/portable light illuminates
   objects but previously not close terrain.
2. Enable OMV terrain PBR and toggle the portable light while stationary.
3. Walk across the original transition and multibound boundary.
4. Confirm terrain illumination follows the light without duplicate brightness,
   chunk blinking, color corruption, interior leakage, or a material FPS loss.
5. On a cold shader cache, confirm close terrain remains entirely VPT while
   status is below bytecode/resources `57/57`; no close-terrain PBR active log
   may appear during partial readiness.
6. After status reaches `57/57`, confirm close-terrain PBR activates and no
   native/PBR tile patchwork appears during camera movement.
7. Travel through several exteriors at night, revisit at least one route, and
   confirm no dark square migrates between terrain chunks as scene lights
   stream or reorder.
8. Rotate the camera slowly through the angles that previously toggled a dark
   rectangle and confirm direct terrain lighting remains continuous.

Static tests do not replace the pending pixel result. A future change that
makes terrain RGB depend on native or supplemental alpha, restricts manager
recovery to zero-native rows, truncates the manager before candidate
filtering/ranking, or restores a surface-normal half-vector fallback is a
regression of this contract.

## Acceptance Criteria

- External mod source is unchanged.
- OMV repairs missing close-terrain portable illumination using engine state.
- A pass that already owns a light receives no duplicate contribution.
- Native pass membership, constants, positions, counts, ordering, and staged
  fades remain untouched; OMV consumes terrain point-light RGB as VPT does.
- Supplemental constants are OMV-owned, bounded, reset every close-terrain
  draw, and use a neutral reserved alpha.
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
- mutating another owner's render pass or `c39/c63/c88` constants;
- broadening close-terrain draw admission;
- changing the user's global canopy-shadow setting or sampling projected
  canopy resources without a proven VPT-compatible vertex/pixel ABI;
- claiming that static tests prove runtime pixels.

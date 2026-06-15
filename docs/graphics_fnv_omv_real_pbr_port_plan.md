# OMV Real PBR Port Plan

This is the implementation plan for porting the useful New Vegas Reloaded PBR contracts into Oh My Vegas / OMV.

NVR is reference material only. OMV will not patch NVR, depend on NVR, or spend implementation budget on NVR coexistence. Terrain PBR is allowed to require Vanilla Plus Terrain, Fallout Shader Loader, and LOD Flicker Fix because those mods own the correct terrain substrate.

## Decision

The port is viable as a delivery-first contract port:

1. Ship ordinary object PBR against the NVR object shader contract.
2. Ship base LandLOD PBR against the NVR/VPT terrain register contract.
3. Add VPT-backed close terrain PBR as a narrow exterior sun-only slice using VPT pass rows and constant maps.
4. Leave terrain parallax, skin, only-light/specular-only rows, water, sky, and NVR shadows out of the first shippable PBR target.

Do not try another broad close-terrain shader swap. That already failed, cost about `-40 FPS`, and caused terrain/interior/light corruption because the engine-side contract was incomplete.

## 2026-06-15 Delivery Plan Change

Telemetry is not the product. It stays as bounded diagnostics that make each
feature slice debuggable without turning terrain into a logging benchmark.

The current delivery target is:

1. Ship ordinary object PBR as the first visible feature.
2. Ship base LandLOD PBR as the first terrain/LOD feature.
3. Deliver close terrain only as a VPT-backed exterior sun-only slice behind an
   experimental flag.
4. Expand to terrain fade and terrain point lights after base terrain is
   visually correct and performance-stable.
5. Keep parallax, skin, water, sky, NVR shadows, and broad shader-family
   replacement out of this delivery cycle.

Quality and performance rules:

- Unsupported variants must stay vanilla; do not block the whole feature on
  skin, PAR/POM, point-light terrain, or projected-shadow terrain.
- A feature cannot ship if it corrupts interiors, uses wrong row identity,
  aliases object and terrain registers, or causes a broad FPS regression.
- Do not add unbounded terrain logs, per-draw broad selector scans,
  active-layer fallback to layer 0, or seven-layer sampling when `TEX_COUNT` is
  smaller.

## Sources Used

- `docs/graphics_fnv_pbr_errata.md`
- `docs/graphics_fnv_pbr_contract_map.md`
- `docs/graphics_fnv_nvr_shader_contract_research.md`
- `docs/graphics_fnv_nvr_shader_portability_matrix.md`
- `omv/src/effects/pbr.rs`
- `omv/shaders/embedded/native_pbr_pplighting_object.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_landlod.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_landlod.vs.hlsl`
- `.research/TESReloaded10-master/src/effects/PBR.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.h`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Object.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/PBR.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainLODTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainFadeTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Terrain.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Parallax.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainLODTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainFadeTemplate.hlsl`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_vpt_nvr_contract_gap_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_landlod_abi_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_shader_abi_closure_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_true_land_discriminator_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_abi_contract.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_declaration_contract.txt`

## Current Problems Mapped To Contracts

### 1. Close Terrain PBR Is Not Implemented

Current OMV has no VPT row-aware close terrain replacement. It only replaces selected PPLighting object/LandLOD shader pairs through `BSShader::SetShaders`.

NVR close terrain requires:

- VPT terrain pass rows `503..558`.
- VPT fade row `560`.
- Active `TEX_COUNT` specialization.
- `BaseMap[7]` at `s0..s6`.
- `NormalMap[7]` at `s7..s13`.
- `LandSpec` at `c32/c33`.
- `LandHeight` at `c34/c35`.
- Fog at `c36/c37`.
- Point lights at `c39`, `c63`, and `c88`.
- OMV/NVR terrain controls at `c89/c90`.
- Parallax controls at `c91/c92` only after base terrain works.

The old close-terrain attempts failed because they treated land-looking shader pairs as terrain identity. That is not enough. Ghidra proves land-like slots can belong to helper rows, projected-shadow rows, point-light rows, SI, LandO, landlo-fog, fade, and interior/static paths.

### 2. LandLOD Register Ownership Is Corrected, But Not Finished

Previous OMV LandLOD used object-style `c32/c33`, which conflicted with terrain
`LandSpec`. Current OMV base LandLOD has been moved to the NVR/VPT terrain-style
contract:

- `LODTexParams c31`
- `LandLODSpec c38`
- `TESR_TerrainData c89`
- `TESR_TerrainExtraData c90`
- samplers `s0`, `s1`, `s4`, `s6`, `s7`

Remaining LandLOD work:

- validate base LandLOD quality/performance in exterior playtests;
- keep projected-shadow LandLOD disabled until its ABI is proven;
- keep terrain fade row `560` as a separate feature, not as base LandLOD.

### 3. Object PBR Is Close But Still Needs Variant Accounting

Current OMV object replacement already targets PPLighting family C/B variants and uploads object PBR registers:

- `TESR_PBRData c32`
- `TESR_PBRExtraData c33`

This matches NVR object PBR. Current OMV rejects skin vertex indices before
ordinary object matching; keep that invariant. TESReloaded10 leaves the skin
collection route disabled because those shaders are half broken, so skin remains
out of the first shippable target.

Object projected-shadow and high-light variants also need a stricter survival gate. They can remain candidates, but the logs must prove which variant is active before blaming broader shadow bugs on terrain or lighting.

### 4. Interior PBR Bugs Are Contract Bugs

NVR terrain updates return early outside exteriors. Close terrain PBR is not an interior wall/floor path.

Interior corruption from prior attempts means OMV replaced a draw that did not own the terrain material ABI. Interior support belongs to ordinary object PBR first. Interior terrain-like rows must remain vanilla unless a separate interior-land contract is proven.

### 5. Light And Shadow Blinking Is Most Likely Wrong Row Coverage

The previous symptoms match replacing projected-shadow, point-light, SI, LandO, landlo-fog, or helper rows with shaders that assume base terrain texture arrays.

Do not fix this by changing BRDF math. The first fix is row identity and variant exclusion.

## Contract To Port

### Object Constants

Port directly:

```text
c32 TESR_PBRData
  x metallicness
  y roughness scale
  z light scale
  w ambient scale

c33 TESR_PBRExtraData
  x albedo saturation
```

NVR blends those settings across default, rain, night, night-rain, and interiors. OMV can start with the current static config values, then add state blending after the shader ABI is stable.

### Terrain Constants

Add as a separate terrain register block:

```text
c89 TESR_TerrainData
  x metallicness
  y roughness scale
  z light scale
  w ambient scale

c90 TESR_TerrainExtraData
  x use PBR
  y saturation
  z LOD noise scale
  w LOD noise tile

c91 TESR_TerrainParallaxData
  x enabled
  y shadows
  z height blend
  w high quality

c92 TESR_TerrainParallaxExtraData
  x max distance
  y height
  z shadow intensity
```

`c91/c92` stay uploaded but disabled until base terrain PBR is stable.

### VPT Constants

Rely on VPT for:

```text
c32/c33 LandSpec
c34/c35 LandHeight
c36     StandardFogParams
c37     StandardFogColor
c38     LandLODSpec
c39     PointlightColors[24]
c63     PointlightPositions[24]
c88     PointlightCount
```

OMV should not duplicate VPT terrain hooks. If VPT is missing, close terrain/fade/terrain point-light PBR must fail closed.

## Shader Families To Implement

### Phase 1: Object PBR Delivery

Port NVR `ObjectTemplate.hlsl` and `Includes/PBR.hlsl` into OMV's embedded shader layout.

Keep:

- ADTS base.
- ADTS OPT.
- ADTS LOD.
- ADTS projected shadow.
- ADTS `LIGHTS=2`.
- ADTS `LIGHTS=2 + projected shadow`.
- ADTS specular.
- ADTS specular projected shadow.
- ADTS specular `LIGHTS=2`.
- ADTS specular `LIGHTS=2 + projected shadow`.
- ADTS10 `LIGHTS=9`.
- ADTS10 `LIGHTS=4`.
- ADTS10 `LIGHTS=4 + OPT`.
- ADTS10 specular `LIGHTS=4`.
- ADTS10 specular `LIGHTS=4 + OPT`.

Exclude for now:

- Skin.
- SI.
- Hair.
- Only-light.
- Only-specular.
- Diffuse-point special rows.
- PAR/POM.

Required code changes:

- Keep all `*_SKIN_INDEX` routes rejected from ordinary object matcher helpers.
- Split object variant metadata from the current single `ReplacementShaderKind`
  table into a table that records shader family, vertex group/index, pixel
  group/index, defines, and risk tier.
- Keep object PBR constants at `c32/c33`.
- Add NVR-style state-blended PBR settings for default, rain, night,
  night-rain, and interior states. Static config values can remain the first
  implementation, but the config layout should not block the NVR blend.
- Add cheap replacement counters per object variant.
- Add skip counters for skin, SI/hair, light-only/specular-only, unknown object, and unsupported family.

Acceptance:

- Object PBR applies in exterior and interior ordinary material draws.
- No skin faces/body meshes are routed through ordinary object PBR.
- Projected-shadow object variants either work with bounded counters/logs or are
  excluded explicitly.
- No close terrain or LandLOD path consumes object `c32/c33`.
- No broad performance regression in ordinary object-heavy exterior or interior
  views.

### Phase 2: Base LandLOD PBR Delivery

Current OMV base LandLOD already uses the corrected terrain register contract.
This phase delivers that path as a tuned feature instead of rewriting it again.

Implement:

- Pixel shader reads `LandLODSpec c38`.
- Pixel shader reads `TESR_TerrainData c89`.
- Pixel shader reads `TESR_TerrainExtraData c90`.
- Noise tile uses `c90.w`.
- Noise strength uses `c90.z`.
- Roughness derives from normal alpha only when `LandLODSpec.x > 0`.
- Base LandLOD and projected-shadow LandLOD are separate replacement kinds unless runtime evidence proves they share ABI.

Required code changes:

- Keep terrain constant upload separate from object constant upload.
- Keep `native_pbr_pplighting_landlod.hlsl` on `c38/c89/c90`.
- Rename or document LandLOD replacement kind as a terrain kind, not object
  material PBR.
- Stop mapping projected-shadow LandLOD to base LandLOD without proof.
- Use VPT dependency report to mark LandLOD terrain-contract confidence. If VPT
  is missing, either disable LandLOD PBR or run a clearly named OMV-specific
  fallback that does not claim NVR parity.
- Tune exposed terrain controls for far terrain lighting response without
  changing close terrain behavior.

Acceptance:

- No LandLOD shader reads object `c32/c33`.
- LandLOD uses `c38/c89/c90`.
- Far terrain does not blink between object-style and terrain-style lighting.
- Projected-shadow LandLOD and fade remain separate vanilla paths until proven.
- Missing VPT/FSL/LODFF is logged with the exact disabled feature.

### Phase 3: VPT-Backed Close Terrain Base PBR

Start after object PBR and base LandLOD are build-clean and playtest-ok. Do not
wait on broad telemetry work, but keep the first close-terrain slice narrow and
experimental.

Use VPT pass formula:

```text
land_pass_count = min(usLandPassCount, 7)

sun-only row:
  pass = 8 * land_pass_count + 503
  + 1 if canopy shadows

point-light row:
  pass = 8 * land_pass_count + 505
  + 1 if canopy shadows
  + 2 if point lights > 6
  + 2 if point lights > 12

fade row:
  pass = 560
  cCurrLandTexture = 9
```

Shader variants:

- `TEX_COUNT=1..7`
- no point lights in the first slice
- point-light buckets `6`, `12`, `24` only in the point-light phase
- canopy/projected-shadow rows only after base rows are proven

Initial close terrain target:

- exterior only
- sun-only base rows first
- VPT/FSL/LODFF present
- `TEX_COUNT=1..7` specialization
- no parallax
- no fade
- no point lights
- no projected-shadow rows
- hard experimental config flag until playtest passes

Required code changes:

- Add a terrain replacement classifier that uses VPT pass row identity, not just shader pair identity.
- Keep bounded pass-entry diagnostics for selector `+0x3C` as guard rails, not
  as a separate pre-feature milestone.
- Derive active layer count from the VPT row formula or proven selector state.
- Bind only active diffuse/normal layers, or leave dependency-owned stages
  untouched if runtime evidence proves they are already correct at the OMV hook.
- Do not fallback active missing layers to layer 0.
- Cache resolved terrain resources by a proven selector/material/pass key.
- Compile terrain shaders per `TEX_COUNT`; do not sample all seven layers for every draw.
- Upload terrain `c89/c90` before draw.

Acceptance:

- Close terrain replacement is off when VPT/FSL/LODFF are missing.
- Close terrain replacement is off inside interiors.
- Base exterior terrain color matches vanilla material identity and only changes lighting response.
- No `-40 FPS` class regression in the known exterior repro.
- No active-layer fallback to wrong textures.
- If this phase fails, object PBR and base LandLOD remain shippable.

### Phase 4: Terrain Fade

Implement VPT row `560` separately with `TerrainFadeTemplate.hlsl`.

Requirements:

- `LandLODSpec c38`.
- `TESR_TerrainData c89`.
- `TESR_TerrainExtraData c90`.
- `LODLandNoise` sampler.
- `cCurrLandTexture = 9` evidence.

Acceptance:

- Close-to-LOD blend remains stable while moving.
- No fade-row replacement occurs on ordinary LandLOD or close terrain base rows.

### Phase 5: Terrain Point Lights

Implement only after sun-only terrain is stable.

Requirements:

- VPT `UpdateLightsAlt` must be present.
- Use `PointlightColors c39`, `PointlightPositions c63`, `PointlightCount c88`.
- Compile bucketed variants for `NUM_PT_LIGHTS=6`, `12`, and `24`.
- Keep row discrimination strict.

Acceptance:

- Street lights and player light do not blink as rectangular patches.
- Point-light rows do not corrupt sun-only terrain rows.
- Missing point-light constants disable only point-light terrain PBR, not object PBR.

### Phase 6: Terrain Parallax

Implement last.

Requirements:

- Base close terrain stable.
- `LandHeight c34/c35` proven per active layer.
- `TESR_TerrainParallaxData c91`.
- `TESR_TerrainParallaxExtraData c92`.
- Reflection-stage behavior decided. NVR disables terrain parallax during water reflections.

Acceptance:

- Disabled by default until performance and reflection behavior are proven.
- No parallax code runs on LandLOD, fade, interiors, or helper rows.

## Runtime Architecture

Refactor `omv/src/effects/pbr.rs` before adding terrain breadth:

```text
effects::pbr
  object
    constants c32/c33
    object variant table
    object shader compile/cache
    object replacement classifier

  terrain
    constants c89/c90/c91/c92
    dependency gate
    landlod classifier
    close terrain row classifier
    terrain shader compile/cache

  native
    common draw context
    shader membership cache
    pass-entry capture
    D3D constant upload helpers
```

This split is needed because object and terrain both use PPLighting infrastructure, but their register meanings conflict.

## Dependency Gates

OMV should detect and log:

- `Fallout Shader Loader.dll`
- `VanillaPlusTerrain.dll`
- `LODFlickerFix.dll`

Feature decisions:

- Object PBR: can run without VPT if hooks are available.
- LandLOD NVR parity: requires VPT for `LandLODSpec c38`; otherwise disable or mark as OMV-specific fallback.
- Close terrain: requires all three dependencies.
- Terrain fade: requires all three dependencies.
- Terrain point lights: requires all three dependencies.
- Terrain parallax: requires all three dependencies and stable base terrain.

Fallout Shader Loader version `>= 131` is required by VPT source. If OMV can query FSL version safely, log it. If not, document that OMV relies on VPT's own version check.

## Bounded Diagnostics Required During Delivery

Diagnostics are guard rails, not a blocking milestone. Add bounded logs with
stable counters:

- object variant apply counts;
- terrain dependency status;
- LandLOD base/projected-shadow apply counts;
- close terrain candidate rows by pass id;
- close terrain skipped reason:
  - missing dependency;
  - interior;
  - unsupported row;
  - helper row;
  - projected-shadow row;
  - point-light row before point-light phase;
  - missing active diffuse;
  - missing active normal;
  - unproven vertex ABI;
  - constant upload unavailable;
- terrain shader compile errors by `TEX_COUNT` and light bucket;
- one-time debug dump of pass-entry fields for terrain candidates when an
  explicit debug config is enabled.

Do not log every terrain draw unbounded. Terrain is too hot.

## Ghidra And Runtime Research Still Needed

No new Ghidra script is needed before the delivery slices above. TESReloaded10,
VPT, and existing Ghidra output are enough to start object PBR, base LandLOD,
and the narrow VPT-backed sun-only close-terrain slice.

Use runtime logs during phase 3 to validate what static Ghidra did not:

- exact current pass-entry row for VPT close terrain draws;
- exact active-layer count at draw time;
- exact terrain vertex declaration or FVF for the selected rows;
- whether projected-shadow LandLOD has a different ABI from base LandLOD.

If runtime logs contradict VPT source, prepare a focused Ghidra script for that one gap. Do not guess.

## Delivery Order

1. Object PBR delivery:
   - keep skin rejected from ordinary object matcher;
   - keep supported ADTS/ADTS10 material variants only;
   - port the useful NVR object BRDF/template subset;
   - add NVR-style state-blended settings/config;
   - add cheap variant counters and skip counters;
   - playtest exterior and interior ordinary materials.
2. Base LandLOD delivery:
   - keep base LandLOD on `c38/c89/c90`;
   - keep projected-shadow LandLOD and fade vanilla;
   - tune/validate far terrain quality and performance;
   - log dependency gates clearly.
3. Close terrain first slice:
   - require VPT/FSL/LODFF;
   - support exterior sun-only rows;
   - compile active `TEX_COUNT=1..7` variants;
   - exclude point lights, fade, parallax, canopy, and projected-shadow rows;
   - keep an experimental flag until visuals and FPS pass.
4. Terrain fade row `560`.
5. Terrain point-light buckets.
6. Terrain parallax only after stable base/fade/light terrain.
7. Separate later projects: PAR2, skin, water, sky, and shadows.

## Release Gate

Native PBR can ship as object PBR plus base LandLOD while close terrain remains
experimental or disabled. The release gate is:

- object PBR keeps rejecting skin;
- LandLOD keeps using terrain registers, not object PBR registers;
- close terrain is disabled unless VPT/FSL/LODFF are present;
- interior draws do not receive close terrain PBR;
- any enabled close-terrain replacement uses row identity and active-layer specialization;
- known shadow/light blinking is attributed to an enabled variant and either fixed or excluded;
- logs explain every disabled or skipped PBR feature.

If phases 1 and 2 cannot be stabilized, drop native PBR as a user-facing feature and keep only the diagnostics/research path. If phases 1 and 2 stabilize but phase 3 does not, ship object PBR plus corrected LandLOD and keep close terrain off.

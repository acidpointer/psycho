# OMV Real PBR Port Plan

This is the implementation plan for porting the useful New Vegas Reloaded PBR contracts into Oh My Vegas / OMV.

NVR is reference material only. OMV will not patch NVR, depend on NVR, or spend implementation budget on NVR coexistence. Terrain PBR is allowed to require Vanilla Plus Terrain, Fallout Shader Loader, and LOD Flicker Fix because those mods own the correct terrain substrate.

## Decision

The port is viable, but only as a staged contract port:

1. Make ordinary object PBR match the NVR object shader contract.
2. Fix LandLOD so it uses the NVR/VPT terrain register contract, not object PBR registers.
3. Add VPT-backed close terrain PBR using VPT pass rows and constant maps.
4. Leave terrain parallax, skin, only-light/specular-only rows, water, sky, and NVR shadows out of the first shippable PBR target.

Do not try another broad close-terrain shader swap. That already failed, cost about `-40 FPS`, and caused terrain/interior/light corruption because the engine-side contract was incomplete.

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

### 2. LandLOD Uses The Wrong Registers

Current OMV LandLOD shader uses object-style:

- `TESR_PBRData c32`
- `TESR_PBRExtraData c33`

NVR/VPT LandLOD expects:

- `LODTexParams c31`
- `LandLODSpec c38`
- `TESR_TerrainData c89`
- `TESR_TerrainExtraData c90`
- samplers `s0`, `s1`, `s4`, `s6`, `s7`

This is a real ABI conflict. `c32/c33` are object PBR registers for object shaders, but terrain uses `c32/c33` for `LandSpec`. LandLOD must be moved to terrain-style constants before it can be called a real NVR-derived PBR port.

### 3. Object PBR Is Close But Too Broad

Current OMV object replacement already targets PPLighting family C/B variants and uploads object PBR registers:

- `TESR_PBRData c32`
- `TESR_PBRExtraData c33`

This matches NVR object PBR, but the matcher currently accepts several skin vertex indices as ordinary object variants. TESReloaded10 leaves the skin collection route disabled because those shaders are half broken. OMV must exclude skin from ordinary object PBR until a true skin shader contract exists.

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

### Phase 1: Object PBR

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

- Remove all `*_SKIN_INDEX` acceptance from ordinary object matcher helpers.
- Split object variant metadata from the current single `ReplacementShaderKind` table into a table that records shader family, vertex group/index, pixel group/index, defines, and risk tier.
- Keep object PBR constants at `c32/c33`.
- Add replacement counters per object variant.
- Add skip counters for skin, SI/hair, light-only/specular-only, unknown object, and unsupported family.

Acceptance:

- Object PBR applies in exterior and interior ordinary material draws.
- No skin faces/body meshes are routed through ordinary object PBR.
- Projected-shadow object variants either work with logs or are excluded explicitly.
- No close terrain or LandLOD path consumes object `c32/c33`.

### Phase 2: LandLOD PBR Cleanup

Replace the current OMV LandLOD shader with an NVR/VPT-derived LandLOD shader.

Implement:

- Pixel shader reads `LandLODSpec c38`.
- Pixel shader reads `TESR_TerrainData c89`.
- Pixel shader reads `TESR_TerrainExtraData c90`.
- Noise tile uses `c90.w`.
- Noise strength uses `c90.z`.
- Roughness derives from normal alpha only when `LandLODSpec.x > 0`.
- Base LandLOD and projected-shadow LandLOD are separate replacement kinds unless runtime evidence proves they share ABI.

Required code changes:

- Add terrain constant upload path alongside object constant upload.
- Replace `native_pbr_pplighting_landlod.hlsl` register usage.
- Rename LandLOD replacement kind to a terrain kind, not object material PBR.
- Stop mapping projected-shadow LandLOD to base LandLOD without proof.
- Use VPT dependency report to mark LandLOD terrain-contract confidence. If VPT is missing, either disable LandLOD PBR or run a clearly named OMV-specific fallback that does not claim NVR parity.

Acceptance:

- No LandLOD shader reads object `c32/c33`.
- LandLOD uses `c38/c89/c90`.
- Far terrain does not blink between object-style and terrain-style lighting.
- Missing VPT/FSL/LODFF is logged with the exact disabled feature.

### Phase 3: VPT-Backed Close Terrain Base PBR

Implement only after phases 1 and 2 are stable.

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
- no point lights
- point-light buckets `6`, `12`, `24`
- canopy/projected-shadow rows only after base rows are proven

Initial close terrain target:

- exterior only
- sun-only base rows first
- no parallax
- no fade
- no point lights
- no projected-shadow rows

Required code changes:

- Add a terrain replacement classifier that uses VPT pass row identity, not just shader pair identity.
- Capture pass-entry fields from selector `+0x3C`:
  - row at entry `+0x04`
  - selector flag at `+0x07`
  - runtime mutation flag at `+0x08`
  - arg count at `+0x09`
  - layer byte at `+0x0B`
  - arg table at `+0x0C`
- Capture active layer count from the row formula or proven selector state.
- Bind only active diffuse/normal layers.
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

## Instrumentation Required Before Enabling Terrain

Add bounded logs with stable counters:

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
- one-time debug dump of pass-entry fields for terrain candidates.

Do not log every terrain draw unbounded. Terrain is too hot.

## Ghidra And Runtime Research Still Needed

No new Ghidra script is needed before starting phases 1 and 2.

Before phase 3, use runtime logs to close what static Ghidra did not:

- exact current pass-entry row for VPT close terrain draws;
- exact active-layer count at draw time;
- exact terrain vertex declaration or FVF for the selected rows;
- whether projected-shadow LandLOD has a different ABI from base LandLOD.

If runtime logs contradict VPT source, prepare a focused Ghidra script for that one gap. Do not guess.

## Implementation Order

1. Refactor PBR variant metadata into object and terrain tables.
2. Remove skin from ordinary object matcher.
3. Port NVR object BRDF/ObjectTemplate subset into OMV object shader.
4. Add object variant counters and skip counters.
5. Add terrain constant upload for `c89/c90`, with `c91/c92` disabled.
6. Rewrite LandLOD shader to use `c38/c89/c90`.
7. Split or disable projected-shadow LandLOD until proven.
8. Add VPT/FSL/LODFF feature gate messages to runtime status/UI/logs.
9. Add close terrain row/pass-entry capture without replacement.
10. Enable sun-only close terrain `TEX_COUNT=1..7` replacement behind an experimental flag.
11. Add terrain fade row `560`.
12. Add point-light terrain buckets.
13. Add terrain parallax as a separate disabled-by-default feature.

## Release Gate

Native PBR is not shippable until:

- object PBR no longer accepts skin;
- LandLOD no longer uses object PBR registers;
- close terrain is disabled unless VPT/FSL/LODFF are present;
- interior draws do not receive close terrain PBR;
- terrain replacement uses row identity and active-layer specialization;
- known shadow/light blinking is attributed to a variant and either fixed or excluded;
- logs explain every disabled or skipped PBR feature.

If phases 1 and 2 cannot be stabilized, drop native PBR as a user-facing feature and keep only the diagnostics/research path. If phases 1 and 2 stabilize but phase 3 does not, ship object PBR plus corrected LandLOD and keep close terrain off.

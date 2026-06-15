# FNV OMV Native PBR Contract Map

This is the current baseline for Oh My Vegas / OMV native PBR after the close-terrain revert. It maps the unresolved visual problems to the contracts proven by TESReloaded10/New Vegas Reloaded 441 sources, VanillaPlusTerrain, current code under `omv/`, and the Ghidra outputs under `analysis/ghidra/output/perf/`.

This document is intentionally conservative. If a draw contract is not proven, the correct state is "unknown", not "probably terrain".

Updated project rule: OMV is allowed to depend on Shader Loader, Vanilla Plus Terrain, and LOD Flicker Fix when those dependencies own the correct engine contract. Avoiding dependencies is not a goal for close terrain. NVR compatibility is no longer a requirement; TESReloaded10 remains reference material only.

## Sources

- `docs/graphics_fnv_pbr_errata.md`
- `docs/graphics_fnv_omv_dependency_compatibility_plan.md`
- `omv/src/effects/pbr.rs`
- `omv/shaders/embedded/native_pbr_pplighting_object.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_landlod.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_landlod.vs.hlsl`
- `.research/TESReloaded10-master/NewVegasReloaded/Main.cpp`
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp`
- `.research/TESReloaded10-master/src/core/ShaderRecord.cpp`
- `.research/TESReloaded10-master/src/effects/PBR.cpp`
- `.research/TESReloaded10-master/src/effects/PBR.h`
- `.research/TESReloaded10-master/src/effects/POM.cpp`
- `.research/TESReloaded10-master/src/effects/POM.h`
- `.research/TESReloaded10-master/src/effects/Terrain.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.h`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/ShaderIO.cpp`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Render.cpp`
- `.research/TESReloaded10-master/src/NewVegas/nvse/GameNi.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Object.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainLODTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainFadeTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Terrain.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ParallaxTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Parallax.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainLODTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainFadeTemplate.hlsl`
- Ghidra outputs:
  - `graphics_fnv_nvr_shader_replacement_contract_audit.txt`
  - `graphics_fnv_native_material_draw_contract_followup_audit.txt`
  - `graphics_fnv_pbr_close_terrain_pass_identity_followup.txt`
  - `graphics_fnv_pbr_close_terrain_runtime_layer_constant_audit.txt`
  - `graphics_fnv_pbr_close_terrain_selector_material_lifetime_audit.txt`
  - `graphics_fnv_pbr_close_terrain_selector_family_classification_audit.txt`
  - `graphics_fnv_pbr_landlod_abi_audit.txt`
  - `graphics_fnv_pbr_land_par2_array_contract_followup.txt`
  - `graphics_fnv_pbr_vpt_nvr_contract_gap_audit.txt`

## Top-Level Findings

1. Object PBR, object parallax/PAR2, LandLOD PBR, and close-terrain PBR are different contracts. Merging them is the main source of bad fixes.
2. Current OMV code has object and LandLOD shader substitution only. It has no close-terrain replacement kind, no VPT terrain constant bridge, and no terrain texture-array binding.
3. TESReloaded10 NVR requires `LODFlickerFix.dll` and `VanillaPlusTerrain.dll` at post-load. For OMV, this is reference evidence that terrain PBR should use the VPT contract, not that OMV should depend on or modify NVR.
4. NVR coexistence is not a requirement. Do not spend implementation budget on NVR hook chaining unless that goal is explicitly reopened.
5. The existing Ghidra research proves close-land shader table slots and material-array layout, but TESReloaded10/VPT source now answers the pass formula and constant ABI more directly.
6. The biggest register mismatch is `c32/c33`: the current `omv` implementation uses these as generic PBR controls for object and current LandLOD replacements, while NVR/VPT terrain uses them as `LandSpec`. NVR terrain PBR controls are `c89/c90`.

## TESReloaded10 Source Contract Update

TESReloaded10 is the strongest current NVR reference. The source shows these contracts directly:

- `NewVegasReloaded/Main.cpp` aborts loading if `VanillaPlusTerrain.dll` is not already loaded. Close terrain must therefore be treated as a VPT-backed terrain contract when matching NVR behavior. OMV must not patch or depend on NVR internals.
- `PBRShaders::RegisterConstants` registers object `TESR_PBRData` and `TESR_PBRExtraData`. In `Object.hlsl` they are `c32` and `c33`.
- `TerrainShaders::RegisterConstants` registers `TESR_TerrainData`, `TESR_TerrainExtraData`, `TESR_TerrainParallaxData`, and `TESR_TerrainParallaxExtraData`. In `Terrain.hlsl` / `Parallax.hlsl` they are `c89`, `c90`, `c91`, and `c92`.
- `TerrainShaders::UpdateConstants` returns early outside exteriors. Terrain PBR is not an interior wall/floor path.
- `POMShaders` owns object parallax separately under `PAR*` shaders and `TESR_ParallaxData c35`. It is not an object PBR variant.
- `ShaderManager::GetShaderCollection` maps `PAR` to POM, template-mapped `SLS20xx` object shaders to PBR, and template-mapped terrain shaders to Terrain. The `SKIN` collection branch is commented out as disabled because the shaders are half broken.
- `ShaderRecord::CreateCT` captures only shader constants/samplers whose names start with `TESR_`. Vanilla and VPT constants such as `LandSpec`, `LandHeight`, `LandLODSpec`, and point-light arrays are still supplied by the game/VPT constant maps, not by NVR's generic `TESR_*` table.
- `ShadowLightShader::EnableEyePositionForAllPasses` sets the EyePosition vertex constant flag for SLS rows `88..560`. The current implementation has no equivalent patch; only its LandLOD replacement vertex shader explicitly reads `EyePosition c16`.
- `RenderReflectionsHook` temporarily disables terrain parallax during water reflections. Terrain parallax therefore has reflection-stage behavior, not just shader math.

Current OMV-specific correction:

- `pbr.rs` accepts several `*_SKIN_INDEX` vertex variants and maps them into ordinary object replacement kinds. TESReloaded10 explicitly does not route `SKIN` through its skin collection. Skin should be excluded from the object PBR survival gate until separately proven.

## Current Implementation State

`omv/src/effects/pbr.rs` currently gates replacement to PPLighting family vertex group C / pixel group B. The accepted replacements are:

- Object ADTS and ADTS10 variants from the NVR object-style ABI.
- LandLOD base pair `VS[2] / PS[3]`.
- LandLOD projected-shadow pair `VS[5] / PS[6]`, currently mapped to the same LandLOD replacement kind.

The current replacement kind explicitly reports:

- `uses_selector_material_resources() -> false`
- `uses_extra_material_stages() -> false`
- `writes_material_flags() -> false`
- `requires_normal_stage() -> true`

That means the current implementation relies on the vanilla final texture-stage cache, especially `s0/s1`, and does not implement the close-terrain `BaseMap[7]` / `NormalMap[7]` material array.

The shipped config enables `graphics.native_pbr.enabled = true`, but the Rust default remains `false`. With the shipped config, the object/LandLOD replacement path is active unless a hook collision or prologue mismatch disables it.

## NVR and VPT Shader Contracts

### Object PBR

NVR object PBR is the safest current match for OMV's implementation.

Relevant NVR contract:

- Object templates use ordinary material textures, not terrain texture arrays.
- PBR controls can use the object-style register pair currently modeled by OMV as `TESR_PBRData c32` and `TESR_PBRExtraData c33`.
- Variants are separate for base, OPT, LOD, projected shadow, light-count variants, specular variants, and ADTS10 high-light variants.

Current OMV status:

- Implemented for the proven ADTS/ADTS10 PPLighting C/B variants in `pbr.rs`.
- SI, HAIR, parallax, and pure helper/light-only passes remain vanilla.
- Several `*_SKIN_INDEX` vertex variants currently flow into the ordinary object replacement helpers. This is not NVR10-safe and should be treated as a bug/risk, not object PBR coverage.
- Shadowed object variants are attempted as separate object variants, but any remaining lighting bug must still be audited against the exact object variant and sampler/constant contract.

### Object Parallax / PAR2

NVR object parallax is not an extension of the current PPLighting C/B replacement.

Static Ghidra contract:

- `graphics_fnv_pbr_land_par2_array_contract_followup.txt` proves a separate `ParallaxShader` object.
- PAR2 vertex shader creation uses the `PAR2%03i.vso` format and writes the VS array at `this+0x8C`.
- PAR2 pixel shader creation uses the `PAR2%03i.pso` format and writes the primary PS array at `this+0xDC`, usually indices `0..0x1C`.
- PAR2 pixel shader creation writes the extended PS array at `this+0x150`, starting at index `0x1D` when the shader-model gate allows it.

NVR shader ABI:

- `ParallaxTemplate.hlsl` uses tangent/binormal/normal vertex input and tangent-space view/light directions.
- Object parallax reads `TESR_ParallaxData c35`.
- `HeightMap` is variant-dependent: ordinary material variants use `s3`, while light-only/specular/no-light layouts can shift it to `s2`.
- Projected-shadow variants also add shadow samplers and shadow projection interpolants.

Current OMV mismatch:

- `pbr.rs` classifies only PPLighting vertex group C / pixel group B pairs.
- No PAR2 array membership, pass-pair census, height-map provenance, or `c35` upload path exists.
- Treating PAR2 as object PBR would miss the height source and bind the wrong constants.

Conclusion:

Object parallax should stay out of the near-term PBR survival decision. It is a separate shader-family project after ordinary object PBR is stable.

### LandLOD PBR

NVR/VPT LandLOD is separate from close terrain.

NVR/VPT shader ABI:

- Vertex input: `POSITION`, `TEXCOORD0`, `TEXCOORD1` geomorph height.
- Vertex constants:
  - `c0` `ModelViewProj`
  - `c8` `ObjToCubeSpace`
  - `c12` `HighDetailRange`
  - `c14` fog params
  - `c15` fog color
  - `c16` eye position
  - `c19` geomorph/LODLand params
  - `c25` light data
- Pixel samplers:
  - `s0` base map
  - `s1` normal map
  - `s4` LOD parent texture
  - `s6` LOD parent normals
  - `s7` LOD land noise
- Pixel constants:
  - `c1` ambient
  - `c3` sun/light color
  - `c31` LOD texture params
  - `c38` `LandLODSpec`
  - NVR terrain include also reads `c89/c90` for terrain tuning/noise controls.

Current OMV mismatch:

- `native_pbr_pplighting_landlod.hlsl` uses `c32/c33` for PBR tuning, not NVR terrain `c89/c90`.
- It does not consume `LandLODSpec c38`; roughness is derived directly from normal alpha.
- `pbr.rs` maps both LandLOD base and LandLOD projected-shadow shader pairs to the same `LandLod` replacement kind. The projected-shadow pair needs its own proof before it should share the base LandLOD shader.

### Close Terrain PBR

NVR close terrain is not implemented by current OMV code.

NVR shader ABI:

- Vertex input:
  - `POSITION`
  - `TANGENT`
  - `BINORMAL`
  - `NORMAL`
  - `TEXCOORD0` UV
  - `COLOR0` vertex color
  - `TEXCOORD1` blend weights 0-3
  - `TEXCOORD2` blend weights 4-6
- Pixel samplers:
  - `BaseMap[7]` at `s0..s6`
  - `NormalMap[7]` at `s7..s13`
- Pixel constants:
  - `c1` ambient color
  - `c3` sun color
  - `c18` sun direction
  - `c32/c33` `LandSpec`
  - `c34/c35` `LandHeight`
  - `c36` fog params
  - `c37` fog color
  - point-light variants also need `c39` point light colors, `c63` point light positions, and `c88` point light count
  - NVR PBR controls are `c89` `TESR_TerrainData` and `c90` `TESR_TerrainExtraData`
- Shader specialization:
  - `TEX_COUNT` must match the active terrain layer count.
  - Point-light variants are separate and compile with different `NUM_PT_LIGHTS` limits.

VanillaPlusTerrain engine-side additions:

- Replaces `BSShaderPPLightingProperty::SetLandscapeSpecularExponents` at `0x00B66640`.
- Replaces landscape pass creation at `0x00BDF3E0`.
- Extends the pixel constant map in `ShadowLightShader::InitShaderConstants`:
  - `LandSpec` at `c32`, count 2
  - `LandHeight` at `c34`, count 2
  - `StandardFogParams` at `c36`
  - `StandardFogColor` at `c37`
  - `LandLODSpec` at `c38`
  - `PointlightColors` at `c39`, up to 24
  - `PointlightPositions` at `c63`, up to 24
  - `PointlightCount` at `c88`
- Enables eye position vertex constants for render pass type `254` and for pass types `503..560`.
- Replaces the existing vanilla landscape pass family around rows/pass types `503..558`, plus `560` for LANDLO close-to-LOD fade.
- Replaces the landscape light update path for those passes so terrain can receive more point lights than vanilla.

VPT source-level pass contract:

- `BSShaderPPLightingProperty` has terrain-specific state after the ordinary texture arrays:
  - `usTextureCount`
  - `ppTextures[6]`
  - `pLandSpecularExponents`
  - `usLandPassCount`
  - `pLandSpecularStatus`
- `AddPass_Landscape` clamps `usLandPassCount` to `7`.
- If no point lights are selected, VPT uses `pass = land_pass_count * 8 + 503`, plus `+1` for canopy shadows.
- If point lights are selected, VPT uses `pass = land_pass_count * 8 + 505`, plus `+1` for canopy shadows, `+2` when point lights exceed `6`, and another `+2` when point lights exceed `12`.
- VPT attaches `1 + point_light_count` lights to the render pass through `RenderPassSetLights`.
- VPT adds the close-to-LOD fade pass as `560` and writes `cCurrLandTexture = 9`.
- `UpdateToggles` disables VPT terrain entries first, then re-enables:
  - `LandLODSpec` for pass `254`
  - `LandSpec`, `LandHeight`, and standard fog entries for passes `503..558`
  - `LandLODSpec` for pass `560`
- `UpdateLightsAlt` fills `PointlightColors`, `PointlightPositions`, and `PointlightCount`, then enables their constant-map entries for landscape passes.

NVR terrain PBR controls:

- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Terrain.hlsl` requires `TESR_TerrainData` at `c89` and `TESR_TerrainExtraData` at `c90`.
- `.research/TESReloaded10-master/src/effects/Terrain.cpp` registers both constants and fills them from `Shaders.Terrain.*` settings.
- `TESR_TerrainExtraData.x` is the terrain PBR enable flag.
- `TESR_TerrainExtraData.y` is terrain saturation.
- `TESR_TerrainExtraData.z` is LOD noise scale.
- `TESR_TerrainExtraData.w` is LOD noise tile.
- When terrain PBR is enabled, `TESR_TerrainData.x` is metallicness and `.y` is roughness.
- `TESR_TerrainData.z` is light scale and `.w` is ambient scale.
- Terrain parallax adds `TESR_TerrainParallaxData c91` and `TESR_TerrainParallaxExtraData c92`.

Important uncertainty:

- TESReloaded10 template filenames map close terrain to `SLS2092..SLS2146`, LandLOD to `SLS2002/SLS2003`, and terrain fade to `SLS2080/SLS2082`.
- VPT source maps the active layer count and point-light bucket to the pass number. Runtime instrumentation is still needed in OMV only to prove our hook-time discriminator and fallback behavior, not to rediscover the NVR/VPT formula.

## Ghidra-Proven Engine Contract

### VPT/NVR Gap Audit Follow-Up

`graphics_fnv_pbr_vpt_nvr_contract_gap_audit.txt` adds these facts:

- `FUN_00BFC860` decompiled fully and is the close-land shader table dispatcher for the vanilla close-land family.
  It selects separate vertex/pixel shader globals for each close-land variant:
  - base: VS `DAT_011FDF94`, PS `DAT_011FDC48`
  - alpha: VS `DAT_011FDF98`, PS `DAT_011FDC4C`
  - landlo-fog: VS `DAT_011FDF9C`, PS `DAT_011FDC50`
  - SI pixel branch in the dispatcher: VS `DAT_011FDFA0`, PS `DAT_011FDC54`
  - alpha SI: VS `DAT_011FDFA0`, PS `DAT_011FDC58`
  - point: VS `DAT_011FDFA4`, PS `DAT_011FDC5C`
  - alpha point: VS `DAT_011FDFA8`, PS `DAT_011FDC60`
  - projected shadow: VS `DAT_011FDF30`, PS `DAT_011FDBF8`
  - alpha projected shadow: direct `FUN_00B79950(DAT_011FDF34)` / `FUN_00B80600(DAT_011FDBFC)` calls
  Landlo-fog also sets a third resource record and calls `FUN_00E7DE90(3)` before installing its shader pair.
  The old target label that paired `close_land_si` with base VS `DAT_011FDF94` was not proven by the dispatcher; runtime pass identity still has to bind the semantic variant names to these branch-local shader pairs.
- Vanilla already uses the landscape row/pass family `0x1F7..0x230`:
  - `0x1F7` is decimal `503`.
  - `0x230` is decimal `560`.
  - VPT replaces and extends this vanilla family; it does not create the numeric range from nothing.
- `FUN_00BDF3E0` computes vanilla landscape rows from the active land pass/layer count:
  - no extra light path: `row = count * 8 + 0x1F7`, plus canopy and skip-normal-map adjustments
  - light path: `row = count * 8 + 0x1FB`, plus canopy and skip-normal-map adjustments
  - close-to-LOD fade: row `0x230`, with pass-entry layer byte `9`
- VPT replaces the same function at `0x00BDF3E0` and changes the point-light formula to `row = count * 8 + 505`, then `+2` for `>6` point lights and another `+2` for `>12` point lights. When VPT is present, the VPT source contract wins for NVR-compatible terrain.
- `FUN_00B795B0` treats rows `0x1F7..0x22E` as landscape by testing `param_2 - 0x1F7 < 0x38`.
- Vanilla `ShadowLightShader::InitShaderConstants @ 0x00B7E430` does not add the VPT/NVR terrain constants. The audit's `0x27`/`39` immediate hit is `PrevWorldViewT`, not `PointlightColors`.
- The audit found no vanilla `c89/c90` terrain control path in the focused functions.
- The `0x200` hits in `FUN_00BDB4A0` and `FUN_00BDF790` are flag tests, not proof that pass `512` is handled specially there.

### Shader Replacement Architecture

`graphics_fnv_nvr_shader_replacement_contract_audit.txt` proves NVR patched native shader object allocation sizes:

- vertex shader object size patch at `0x00BE1690`
- pixel shader object size patch at `0x00BE1DFB`

OMV must not copy that layout-extension strategy. The current implementation correctly uses side tables keyed by native shader object pointers and swaps shader handles during `BSShader::SetShaders`.

`BSShader::SetShaders @ 0x00BE1F90` reads the current pass global `0x0126F74C`.

Pass offsets:

- pass `+0x44`: pixel shader object
- pass `+0x5C`: vertex shader object

Native shader handle offsets:

- pixel shader handle at shader object `+0x2C`
- vertex shader handle at shader object `+0x34`

### Draw Context

`graphics_fnv_native_material_draw_contract_followup_audit.txt` proves:

- `0x0126F74C` is only authoritative inside `BSShader::SetShaders` and closely related apply contexts.
- `0x011F91E0` is contextual. Some paths write stack/proxy objects into it, so it must not be treated as unconditional `NiGeometry`.
- The selector can be recovered from `*(*current_draw + 0xC0)` only in the proven PPLighting draw path.

### Selector and Pass Entries

Ghidra proves the selector material-array fields:

- selector `+0xAC..+0xC0`: six material arrays
- selector `+0xC4/+0xCC`: layer/flag byte arrays
- selector `+0xC8`: contiguous base-layer count
- selector `+0xA8`: mutable descriptor state; `+0xA8 == 9` is not enough for draw identity
- selector `+0x3C`: pass-entry list

Pass-entry ABI from `FUN_00BA8EC0` / `FUN_00BA9EE0`:

- entry `+0x00`: resource/owner
- entry `+0x04`: row low word
- entry `+0x07`: selector flag
- entry `+0x08`: runtime mutation flag
- entry `+0x09`: arg count
- entry `+0x0A`: arg capacity
- entry `+0x0B`: layer byte
- entry `+0x0C`: arg table

Rows that must not be treated as close-terrain material-array rows:

- `FUN_00BDAC00` zero-resource land/spec rows `0x14A..0x152`
- `FUN_00BDF3E0` LandO/light-resource rows `0x1F7..0x230`
- `FUN_00BDF650` helper rows `0x10..0x13`
- `FUN_00BDF6C0` helper rows including `0x62/0x63`

Rows that look like material layer rows:

- `FUN_00BDAF10` diffuse/glow rows `0x93`, `0x94`
- per-layer rows `0x1F2`, `0x1F3`, `0x1F4`, `0x1F5`
- these still require runtime proof against the active selector/pass/material state

### Close-Land Shader Table Slots

`graphics_fnv_pbr_close_terrain_pass_identity_followup.txt` identifies the vanilla PPLighting group slots:

- LandLOD base: `VS[2]`, `PS[3]`
- LandLOD projected shadow: `VS[5]`, `PS[6]`
- close land projected shadow: `VS[53]`, `PS[60]`
- close land alpha projected shadow: `VS[54]`, `PS[61]`
- close land base: `VS[78]`, `PS[80]`
- close land alpha: `VS[79]`, `PS[81]`
- close land landlo-fog: `VS[80]`, `PS[82]`
- close land SI: `VS[78]`, `PS[83]`
- close land alpha SI: `VS[81]`, `PS[84]`
- close land point: `VS[82]`, `PS[85]`
- close land alpha point: `VS[83]`, `PS[86]`

These slots are useful for instrumentation, but they are not a complete replacement key. A shader pair alone cannot separate true terrain from helper, projected-shadow, SI, point-light, LandO, landlo-fog, or interior-looking rows.

## Problem Map

### 1. Close Terrain PBR Fails or Does Nothing

Observed problem:

- Close terrain PBR did not produce stable visual success.
- The previous broad runtime gate caused about `-40 FPS` with no useful visual improvement.
- Broken attempts produced wrong colors, holes, uneven chunks, and unstable coverage.

Missing contract:

- True close landscape draw identity at runtime.
- Vertex declaration matching NVR `TerrainTemplate.hlsl`.
- Active `TEX_COUNT` per pass.
- Correct diffuse/normal texture arrays at `s0..s13`.
- Correct `LandSpec`, `LandHeight`, fog, sun, and point-light constants.
- NVR terrain PBR controls at `c89/c90`.

Current mismatch:

- OMV has no close-terrain shader replacement kind.
- OMV does not bind selector material arrays.
- OMV does not upload `LandHeight c34/c35`, terrain fog constants at `c36/c37`, point light constants at `c39/c63/c88`, or terrain PBR controls at `c89/c90`.
- VPT's replacement semantics for the vanilla `0x1F7..0x230` pass family, light handling, EyePosition flags, and constant-map hooks are not implemented.

Conclusion:

Close terrain remains blocked. The next step is runtime/ghidra contract closure, not shader tuning.

### 2. Interior PBR Is Wrong or Corrupts Walls/Floors

Observed problem:

- Interior walls and floors became overbright, too dark, or shadowed in rectangular blinking regions during previous terrain attempts.

Contract mapping:

- Interior room geometry is not automatically close landscape terrain.
- Some interior-looking draws can share land-ish shader families, but Ghidra already proves that shader family is not enough.
- VPT's landscape contract is keyed around landscape render pass types and terrain property fields. Its `uiInInteriorAddress` use is for light dimming behavior, not a terrain identity proof.

Current mismatch:

- A terrain replacement that triggers from land-ish shader pairs can hit non-landscape interior geometry.
- The object path and terrain path require separate material and light contracts.
- The current matcher includes skin vertex indices in ordinary object replacement helpers. That is also unsafe for interiors because it can route skin-specific draws through a non-skin object shader path.

Conclusion:

Interior surfaces should stay on the object/static material path unless a separate interior landscape discriminator is proven. Do not use close-terrain PBR as an interior fix.

### 3. Shadow and Lighting Bugs

Observed problem:

- Blinking street-light surfaces.
- Rectangular player-light shadows.
- Overbright or underdark light patches.
- Shadow/light behavior changing with player distance.

Contract mapping:

- Close-land base, alpha, projected shadow, SI, point-light, and landlo-fog are distinct slots.
- VPT point-light terrain is a separate pass family with its own pass creation, light sorting, point-light constant uploads, and shader variants.
- Projected-shadow rows must not be treated as base terrain texture-array rows.

Current mismatch:

- Current code maps LandLOD projected-shadow pair to the same LandLOD shader as the base pair.
- Close-land projected-shadow and point-light variants are not implemented.
- Prior terrain attempts likely bound terrain material textures onto rows that did not own the terrain texture-array ABI.
- Vanilla point-light landscape rows do not provide the VPT/NVR point-light constant contract at `c39/c63/c88`.
- OMV does not enable the EyePosition vertex constant flag for the full NVR10 SLS row range `88..560`; NVR10 explicitly patches this for all SLS passes.

Conclusion:

Lighting/shadow bugs are expected if pass variants are collapsed. Each variant needs its own proven resources, constants, samplers, and fallback behavior.

### 4. LandLOD PBR Is Only Partially Matched

Observed problem:

- LandLOD can be replaced, but it is not a complete NVR/VPT terrain contract.

Contract mapping:

- NVR/VPT LandLOD expects `LandLODSpec c38`.
- NVR terrain include reads `TESR_TerrainData c89` and `TESR_TerrainExtraData c90`.
- Terrain fade uses a separate `TerrainFadeTemplate.hlsl` and `LandLODSpec c38`.

Current mismatch:

- Current LandLOD uses `c32/c33` for PBR tuning.
- Current LandLOD ignores `c38`.
- OMV does not implement terrain fade pass `560`.
- LandLOD projected shadow is not proven as safe to share the base LandLOD replacement.

Conclusion:

LandLOD should be treated as implemented-but-incomplete. It is not a valid template for close terrain.

### 5. Object PBR Coverage Is Not Full NVR Coverage

Observed problem:

- Some objects can look correct while other distance, helper, SI, hair, parallax, or unusual lighting variants remain vanilla or inconsistent.

Contract mapping:

- NVR object variants are numerous and separate.
- The current implementation intentionally covers only proven ADTS/ADTS10 variants.

Current mismatch:

- SI/HAIR/parallax/helper/light-only variants are excluded.
- Skin variants are not actually excluded today; the matcher accepts `*_SKIN_INDEX` vertex variants for several object kinds. This should be fixed before calling object PBR stable.
- PAR2/parallax is not a missing PPLighting index; it is a separate `ParallaxShader` array contract.
- If a visible interior or exterior object uses an unsupported variant, it will not receive OMV PBR.

Conclusion:

Object PBR is the most defensible path, but it is not complete NVR parity.

### 6. Register Ownership Conflicts

Observed problem:

- A shader can compile and still be bound to the wrong engine constants.

Contract mapping:

- Object PBR can use object-style `c32/c33` controls.
- NVR close terrain uses `c32/c33` for `LandSpec`, `c34/c35` for `LandHeight`, and `c89/c90` for terrain PBR controls.
- NVR/VPT LandLOD uses `c38` for `LandLODSpec`, with NVR terrain include controls at `c89/c90`.

Current mismatch:

- The current implementation uses `c32/c33` for object and LandLOD PBR controls.
- That register model cannot be copied to close terrain without overwriting `LandSpec`.

Conclusion:

Register ownership must be path-specific. Terrain PBR cannot reuse the object PBR constants.

## Open Contract Gaps

These must be closed before enabling close terrain:

1. Exact vanilla render pass type or pass-entry identity for true close landscape base/alpha/point/shadow/SI/landlo-fog draws.
2. Runtime proof that OMV can observe the VPT row/pass identity safely at replacement time, including active `TEX_COUNT` and point-light bucket.
3. Runtime vertex declaration/FVF/stream source for the selected close terrain rows.
4. Runtime active layer count and its relation to selector `+0xC8`, VPT `usLandPassCount`, and `TEX_COUNT`.
5. Correct upload path in OMV for NVR terrain `c89/c90` and terrain parallax `c91/c92`.
6. Correct source and enable/disable behavior for VPT `LandSpec`, `LandHeight`, fog, `LandLODSpec`, and point-light constant-map entries.
7. Correct fallback when a diffuse or normal layer is missing.
8. Whether LandLOD projected shadow can share base LandLOD replacement, or needs a separate shader.
9. Whether terrain fade pass `560` should be implemented as LandLOD-like, close-terrain-like, or left vanilla.
10. Runtime PAR2 pass-pair census, height-map source, and `TESR_ParallaxData c35` ownership if object parallax is ever considered.
11. Object PBR cleanup: exclude skin variants or implement a true skin contract, and add/prove an EyePosition flag patch if object VS-dependent replacement is ever expanded.

## Required Next Step

Do not re-enable close-terrain replacement yet.

The next engineering step is contract instrumentation/research:

- Add or restore bounded runtime logs for candidate close-land draws:
  - shader group/index pair
  - current pass pointer and pass shader objects
  - selector pointer and selector fields `+0xA8`, `+0xC8`, `+0xC4/+0xCC`, `+0xAC..+0xC0`
  - selector `+0x3C` pass entries with row, layer byte, selector flag, runtime mutation flag, arg count/capacity, and arg table
  - final sampler stages `s0..s13`
  - vertex declaration/FVF/stream source data
- Run the new Ghidra script `analysis/ghidra/scripts/graphics_fnv_pbr_vpt_nvr_contract_gap_audit.py` and inspect its output:
  - `analysis/ghidra/output/perf/graphics_fnv_pbr_vpt_nvr_contract_gap_audit.txt`

That Ghidra output is already useful, but TESReloaded10/VPT source now supersedes it for the NVR-compatible pass formula. The fix is only ready to start after runtime logs prove a positive terrain key inside OMV and the missing constants/resource binding path is implemented.

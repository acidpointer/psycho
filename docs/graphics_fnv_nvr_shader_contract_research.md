# FNV NVR Shader Contract Research

This is the second-pass research note for deciding whether OMV native PBR is worth finalizing and which NVR shader work is useful as reference. It is updated for the fresh TESReloaded10/New Vegas Reloaded 441 source tree in `.research/TESReloaded10-master`.

The key distinction is native shader replacement versus post-effect reuse. NVR supports both through a large engine-side contract. The current `omv` implementation supports only a narrow native PPLighting replacement path and a separate screen-space post runtime.

Current project rule: NVR is reference only. OMV must not modify, depend on, or patch NVR internals. OMV may require Shader Loader, Vanilla Plus Terrain, and LOD Flicker Fix for terrain features when those dependencies are the correct engine contract. NVR coexistence is no longer required.

## Sources

- `.research/TESReloaded10-master/NewVegasReloaded/Main.cpp`
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp`
- `.research/TESReloaded10-master/src/core/ShaderRecord.cpp`
- `.research/TESReloaded10-master/src/effects/PBR.cpp`
- `.research/TESReloaded10-master/src/effects/PBR.h`
- `.research/TESReloaded10-master/src/effects/POM.cpp`
- `.research/TESReloaded10-master/src/effects/POM.h`
- `.research/TESReloaded10-master/src/effects/Terrain.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.h`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Render.cpp`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/ShaderIO.cpp`
- `.research/TESReloaded10-master/src/NewVegas/nvse/GameNi.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `omv/src/effects/pbr.rs`
- `omv/src/runtime.rs`
- `omv/src/shaders.rs`
- `omv/src/backend/fnv.rs`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_land_par2_array_contract_followup.txt`
- `docs/graphics_fnv_omv_dependency_compatibility_plan.md`
- `docs/graphics_fnv_nvr_shader_portability_matrix.md`
- `docs/graphics_fnv_pbr_contract_map.md`

## NVR Manager Contract

NVR does not just replace bytecode. `ShaderManager` adds a shader-record layer:

- `NiD3DVertexShaderEx` / `NiD3DPixelShaderEx` can hold default, exterior, and interior replacement programs.
- `ShaderRecord::CreateCT` reads the D3DX constant table and records every `TESR_*` float/vector/matrix constant and sampler.
- `ShaderRecord::SetCT` uploads those constants before draw and binds `TESR_*` sampler textures through `TextureManager`.
- If a shader has `TESR_RenderedBuffer`, NVR copies the current render target into `RenderedSurface`.
- If a shader has `TESR_DepthBuffer`, NVR resolves depth through `RenderManager::ResolveDepthBuffer`.
- Effects use the same name-based constant/sampler system through `EffectRecord::CreateCT` and `EffectRecord::SetCT`.

TESReloaded10 adds two important reference constraints:

- New Vegas Reloaded aborts if `LODFlickerFix.dll` or `VanillaPlusTerrain.dll` is missing. This proves NVR-compatible terrain is VPT-backed terrain; it does not mean OMV should require or edit NVR.
- `ShaderRecord::CreateCT` only captures shader symbols whose names start with `TESR_`. VPT/game constants such as `LandSpec`, `LandHeight`, `LandLODSpec`, and point-light arrays still depend on the `ShadowLightShader` constant maps.

OMV does not currently have an equivalent generic `TESR_*` constant/sampler table. It has explicit native PBR constants, explicit material texture capture, and a screen-space post runtime.

## OMV Contract Surface

Current native PBR surface:

- PPLighting vertex group C / pixel group B membership.
- `BSShader::SetShaders` hook.
- current pass pointer `0x0126F74C`.
- pass shader object offsets `+0x5C` vertex and `+0x44` pixel.
- final texture stage capture and limited rebinding.
- explicit object-style `TESR_PBRData c32` and `TESR_PBRExtraData c33` uploads.
- LandLOD replacement uses a custom vertex shader and currently reuses object-style `c32/c33`.

Current post-effect surface:

- full-screen pass phases: scene pre-image-space, scene post-image-space, final image-space.
- scene color at `s0`.
- world depth at `s1`.
- first-person depth at `s2`.
- current phase/world color copy at `s3`.
- internal effect intermediates at `s4`.
- screen/frame/camera constants at `c0..c2`.
- user options at `c3..c31`, with `c6` and `c8` reserved for environment/sun data.
- FNV fog/sun/environment reads through `backend/fnv.rs`.

This means selected post-effect math can be reused more easily than native NVR shader families, but only after translating it to OMV's explicit texture/register model.

## Native Shader Family Findings

### Ordinary Object PBR

This remains the only near-term native PBR path.

- Uses PPLighting C/B pairs already captured by `pbr.rs`.
- Uses ordinary object material textures: base `s0`, normal `s1`, optional glow/shadow samplers by variant.
- Uses object PBR controls `TESR_PBRData c32` and `TESR_PBRExtraData c33`.
- Current risk is variant coverage, especially projected shadow, light-count, specular, and interior-visible variants.
- The current implementation also accepts several skin vertex indices into ordinary object replacement helpers. TESReloaded10 leaves the `SKIN` collection disabled in `GetShaderCollection` because the shaders are half broken. Skin must be excluded or separately implemented before object PBR is called stable.

Decision: keep researching/finalizing this before any broader native shader work.

### PAR2 Object Parallax

PAR2 is not ordinary object PBR.

Ghidra already proves:

- separate `ParallaxShader` object;
- PAR2 vertex shader array at `this+0x8C`;
- PAR2 primary pixel array at `this+0xDC`;
- PAR2 extended pixel array at `this+0x150`.

Shader contract:

- `TESR_ParallaxData c35`;
- variant-dependent `HeightMap` at `s2` or `s3`;
- tangent/binormal/normal vertex inputs and tangent-space view/light vectors;
- optional projected-shadow samplers.

Missing:

- runtime PAR2 pass-pair census;
- height-map provenance;
- `c35` upload ownership;
- separate array membership tracking.

Decision: high-pain. Do not include in the PBR survival gate.

### LandLOD

LandLOD is partially reachable but not currently NVR-correct.

- NVR/VPT LandLOD expects `LandLODSpec c38`.
- NVR terrain include also reads `TESR_TerrainData c89` / `TESR_TerrainExtraData c90`.
- Current LandLOD uses object-style `c32/c33`.
- Projected-shadow LandLOD is still not proven safe to share the base replacement.

Decision: medium/high. Either make LandLOD explicitly OMV-specific or implement the missing terrain-style constants; do not present current LandLOD as NVR parity.

### Close Terrain And Terrain POM

Close terrain remains blocked.

- NVR10 close terrain needs VPT pass rows, light bucketing, selector terrain arrays, `TEX_COUNT`, `BaseMap[7] s0..s6`, `NormalMap[7] s7..s13`, `LandSpec c32/c33`, `LandHeight c34/c35`, fog `c36/c37`, point lights `c39/c63/c88`, terrain controls `c89/c90`.
- Terrain POM adds `TESR_TerrainParallaxData c91` and `TESR_TerrainParallaxExtraData c92`.
- VPT source computes close terrain rows as `8 * min(usLandPassCount, 7) + 503` for sun-only and `8 * min(usLandPassCount, 7) + 505` for point-light terrain, with additional point-light bucket offsets. Fade is row `560` with `cCurrLandTexture = 9`.
- NVR10 `TerrainShaders::UpdateConstants` returns early outside exteriors. It is not an interior wall/floor fix path.
- NVR10 terrain replacement is governed by the Terrain shader collection status. Terrain PBR settings exist, but they do not make close terrain safe without the VPT contract and enabled collection.

Decision: no-go as an OMV-only shader swap. Terrain PBR should become a dependency-backed feature that requires VPT/FSL/LODFF and then layers OMV/NVR-style constants only where they do not conflict with NVR.

### Skin

Skin pixel shaders are not obviously impossible, but they are not PBR survival work.

- They use FaceGen maps at `s2/s3`, normal `s1`, optional glow/shadow/attenuation samplers, and skin-specific constants.
- NVR `ShaderConst.Skin` backs `TESR_SkinData` and `TESR_SkinColor`.
- The shader family and vertex ABI are separate from ordinary object PBR.
- TESReloaded10 currently comments out the `SKIN` shader collection route as half broken, so NVR10 source is a warning against treating skin as easy object PBR coverage.

Decision: medium/high. Research after ordinary object PBR is stable.

### Sky

Sky shader files depend on weather/sky constants:

- `TESR_SkyColor`, `TESR_SkyLowColor`, `TESR_HorizonColor`, `TESR_SunColor`, `TESR_SunDirection`, `TESR_SkyData`, `TESR_CloudData`, `TESR_SunAmount`, `TESR_SunPosition`, `TESR_SunsetColor`, `TESR_HDRBloomData`, `TESR_SunDiskColor`.
- `SKYTEX.pso.hlsl` also has an `ObjectID c20` hook for sun/moon/cloud behavior.

Decision: high-pain. Requires weather/sky constant ownership and draw identification.

### Water

Water is a full render-stage project.

- Native water pixel shaders depend on reflection/refraction/noise/displacement/depth maps and `TESR_samplerWater` / ripple samplers.
- They consume many water, weather, sun, wet-world, camera, and shadow constants.
- NVR `ShaderManager::CreateShader("Water")` loads Water, WaterHeightMap, and WaterDisplacement families together.

Decision: high-pain. Not relevant to the PBR finalization decision.

### Shadows

NVR shadows are both native shaders and post effects.

- Native shadow shaders need shadow render targets, shadow view/projection transforms, cube-map light positions, blur/clear passes, and format constants.
- Post shadow effects need normals, point-shadow buffers, shadow atlases/cube maps, and screen-space shadow constants.

Decision: no-go as a port. Current shadow bugs should be diagnosed against current object/terrain replacement decisions, not replaced with NVR's subsystem.

## Post-Effect Findings

Post effects are more portable than native scene shaders only when their buffer and constant needs fit OMV's runtime.

Potentially low/medium value:

- simple color adjustment and sharpening math, rewritten to OMV's `s0` scene color and option constants;
- small bloom or tonemapping ideas, if kept inside OMV's existing bloom/HDR path;
- simple water-lens style distortion only if we provide a local normal/noise texture contract.

Already covered or redundant:

- ambient occlusion;
- sunshafts/godrays;
- bloom.

High-pain post effects:

- WetWorld, Specular, SnowAccumulation, ShadowsExteriors, ShadowsInteriors, PointShadows, Flashlight, VolumetricFog, Underwater.

Reason:

- they depend on normals buffers, shadow buffers, ortho maps, point-light/shadow data, water state, or many NVR weather constants that OMV does not own.

## Practical PBR Decision

PBR should survive only if this bounded target works:

1. Ordinary non-skin object PBR works in exteriors and interiors.
2. Current skin index matches are removed from ordinary object replacement, or a true skin contract is implemented.
3. Projected-shadow/light/specular object variants are either proven and stable or explicitly excluded.
4. LandLOD is corrected or clearly declared OMV-specific.
5. Close terrain is dependency-backed through VPT/FSL/LODFF, not implemented as an OMV-only terrain guess.
6. PAR2, skin, water, sky, shadows, refraction, and terrain POM are excluded from the survival gate.
7. NVR hook-chain compatibility is out of scope unless the project explicitly reopens that goal.

If ordinary object PBR plus corrected LandLOD cannot meet this bar, native PBR should be dropped as user-facing functionality and kept as research/instrumentation only.

## Next Research Probes

Static Ghidra:

- LandLOD projected-shadow ABI proof.
- Only prepare more Ghidra for addresses/prologues or game code that TESReloaded10/VPT source cannot answer. For NVR terrain formulas and constants, source is now the better reference.

Runtime:

- object PPLighting variant census from `BSShader::SetShaders`;
- unsupported pair log aggregation by location/interior/exterior;
- shadow/light blinking attribution to object variant, LandLOD variant, close terrain row, or light-only/specular row;
- check whether EyePosition vertex constant flags are present for rows replaced by OMV, especially before any object vertex shader replacement expansion;
- VPT terrain row/pass capture only if we decide to implement close terrain;
- PAR2 pass-pair and height-map provenance only after ordinary object PBR is stable.

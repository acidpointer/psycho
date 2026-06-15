# FNV NVR Shader Portability Matrix

This is the shader portability map for deciding whether Oh My Vegas / OMV should finalize native PBR or drop it. It is updated for the fresh TESReloaded10/New Vegas Reloaded 441 source tree.

The rule is conservative: a shader family is portable only when its engine contract is known. Shader bytecode/source alone is not enough.

Current project rule: dependencies are allowed when they own real engine contracts. OMV may require Shader Loader, Vanilla Plus Terrain, and LOD Flicker Fix for terrain features. NVR is reference only; co-install compatibility is no longer required.

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
- `docs/graphics_fnv_omv_dependency_compatibility_plan.md`
- `omv/src/effects/pbr.rs`
- `omv/src/runtime.rs`
- `omv/src/backend/fnv.rs`
- `docs/graphics_fnv_pbr_contract_map.md`
- `docs/graphics_fnv_pbr_errata.md`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_land_par2_array_contract_followup.txt`

## Current OMV Capability Baseline

The current `omv` implementation has these useful graphics surfaces:

- Native PPLighting shader handle replacement in `BSShader::SetShaders`.
- Current pass global `0x0126F74C`.
- Pass shader object offsets `+0x5C` vertex and `+0x44` pixel.
- Native texture stage capture and rebinding for ordinary material textures.
- Side-table shader object replacement strategy, not NVR object-layout extension.
- Post-process runtime with scene color and FNV depth resolve.
- FNV world and first-person depth capture.
- Existing OMV bloom, AO, sunshafts, FXAA/CAS, and first-person wall clipping.

OMV does not currently have:

- VPT landscape pass creation/light update hooks.
- VPT terrain pixel constant map entries `c32..c38`, `c39`, `c63`, `c88`.
- NVR terrain controls at `c89/c90`.
- PAR2/ParallaxShader replacement support outside the PPLighting C/B path.
- NVR global shader constant table loader for arbitrary `TESR_*` constants.
- NVR texture manager behavior for shader-declared `TESR_*` samplers.
- NVR shadow map, water, sky, or environment render-stage ownership.

TESReloaded10-specific reference constraints:

- New Vegas Reloaded requires VanillaPlusTerrain and LOD Flicker Fix at post-load.
- NVR's generic constant table handles `TESR_*` names only. VPT terrain constants remain game constant-map work.
- NVR10 enables EyePosition vertex constants for SLS rows `88..560`; OMV has no matching global patch.
- NVR10 comments out the `SKIN` shader collection path as half broken.
- OMV must not patch NVR. NVR hook-chain compatibility is out of scope.

## Portability Tiers

- Low pain: can be ported with current OMV surfaces and small isolated constants.
- Medium pain: needs bounded shader-family expansion or small proven constant/sampler bridge.
- High pain: needs engine-stage ownership, new render targets, new shader tables, or broad draw-contract proof.
- No-go for now: likely to destabilize current bugs unless a larger subsystem is implemented first.

## Matrix

| NVR family | Representative files | ABI surface | Current tier | Reason |
|---|---|---|---|---|
| Object PBR, ADTS/ADTS10 non-skin | `ObjectTemplate.hlsl`, `Includes/Object.hlsl`, `Includes/PBR.hlsl` | PPLighting C/B shader pairs, `BaseMap s0`, `NormalMap s1`, vanilla light/fog constants, NVR `TESR_PBRData c32`, `TESR_PBRExtraData c33` | Medium | OMV already ports a subset. Finalization requires excluding current accidental skin matches, completing visible object variants, and proving projected-shadow/light/specular variants without corrupting interiors. |
| Object projected-shadow variants | `ObjectTemplate.hlsl` | Adds projected shadow interpolants and shadow samplers/constants in selected variants | Medium/high | Current code attempts some shadow variants. Remaining lighting/shadow bugs mean each variant needs proof before enabling broadly. |
| Object skin variants | `ObjectTemplate.hlsl`, `Includes/SkinHelpers.hlsl` | Skin matrices/bones, skin shader variants, face/skin material paths | High | Requires separate skin shader family and skin vertex ABI proof. TESReloaded10 disables the `SKIN` collection as half broken, so current OMV skin-index matching must not be considered coverage. |
| Object only-light / only-specular / diffuse point variants | `ObjectTemplate.hlsl` | Light-only rows, specular-only rows, point-light-specific semantics | High | These are not ordinary material draws. Replacing them risks the current blinking/lighting bugs unless pass identity and light constants are proven. |
| Object POM/parallax | `ParallaxTemplate.hlsl`, `Includes/Parallax.hlsl`, `Includes/Object.hlsl` | Separate `ParallaxShader` object, PAR2 VS array at `this+0x8C`, PAR2 PS arrays at `this+0xDC` and `this+0x150`, height maps, `TESR_ParallaxData c35`, many AD/ADTS/specular/point variants | High | Static Ghidra proves this is not a PPLighting C/B extension. It needs separate array membership, pass pairing, height texture provenance, and c35 upload ownership before replacement. |
| Close terrain | `TerrainTemplate.hlsl`, `Includes/Terrain.hlsl`, VPT `main.cpp` | `BaseMap[7] s0..s6`, `NormalMap[7] s7..s13`, `TEX_COUNT`, VPT rows `503..558`, point-light rows, `LandSpec c32`, `LandHeight c34`, fog `c36/c37`, point lights `c39/c63/c88`, NVR `c89/c90` | Dependency-backed | Require VPT/FSL/LODFF for this feature. Do not attempt OMV-only close terrain shader swaps. |
| Terrain POM | `TerrainTemplate.hlsl`, `Includes/Parallax.hlsl` | Close terrain ABI plus `TESR_TerrainParallaxData c91`, `TESR_TerrainParallaxExtraData c92`, height-in-alpha behavior | No-go for now | Depends on successful close terrain first and adds more constants plus height contract. |
| LandLOD | `TerrainLODTemplate.hlsl` | LandLOD vertex shader, `BaseMap s0`, `NormalMap s1`, parent maps `s4/s6`, noise `s7`, `LODTexParams c31`, `LandLODSpec c38`, NVR terrain include `c89/c90` | Medium/high | OMV already has a LandLOD replacement, but it uses object-style `c32/c33` PBR controls. Correct NVR parity needs `LandLODSpec` and terrain data separation. |
| Terrain fade / LANDLO | `TerrainFadeTemplate.hlsl`, VPT `main.cpp` | Pass `560`, layer byte `9`, `LandLODSpec c38`, `LODLandNoise`, NVR terrain include `c89/c90` | High | Must be tied to VPT fade pass identity. Not the same as ordinary LandLOD base draw. |
| Skin shader pack | `SKIN20xx.pso.hlsl`, `Includes/Skin.hlsl` | `BaseMap s0`, `NormalMap s1`, FaceGen maps `s2/s3`, `TESR_SkinData`, `TESR_SkinColor`, skin debug constants | High | TESReloaded10 has skin shader code but disables the collection route. Treat as a separate high-risk project after object PBR, not as a current PBR target. |
| Sky color | `SKY.pso.hlsl`, `SKYTEX.pso.hlsl`, `Includes/Sky.hlsl` | Many `TESR_Sky*`, `TESR_Sun*`, `TESR_CloudData`, `TESR_HDRBloomData`, object id hook for sun/moon | High | Requires NVR weather/sky constant pipeline and sky draw identification. Not useful for deciding PBR finalization. |
| Sky vertex | `SKY.vso.hlsl`, `SKYT.vso.hlsl`, `SKYMM.vso.hlsl`, `SKYCLOUDS.vso.hlsl`, `SKYSTARS.vso.hlsl` | Sky-specific matrices, blend colors, sky mesh inputs | High | Separate shader table/stage work. No current OMV equivalent contract. |
| Water | `WATER*.pso.hlsl`, `WATER*.vso.hlsl`, `Includes/Water.hlsl` | Vanilla water constants plus NVR water/wetworld constants, reflection/refraction/depth maps, resource-name samplers, ripples | High | Needs water stage ownership, reflection/refraction texture contract, depth semantics, and NVR water constants. |
| Shadow maps | `Shadows/ShadowMap.*`, `Shadows/ShadowCubeMap.*`, `Includes/Shadow.hlsl` | NVR shadow map render targets, EVSM/VSM formats, shadow transforms, shadow buffers, TESR shadow constants | No-go for now | This is a full shadow subsystem. Current shadow bugs should be diagnosed, not replaced with NVR shadow code. |
| Object refraction | `ObjectRefractionTemplate.hlsl` | RenderNormals pass, normal/refraction constants, optional skin/fire/clear variants | High | Requires render-normal/refraction stage ownership and variant mapping. |
| HDR/tonemapping image-space | `ISHDRBLENDINSHADERCIN*.hlsl`, `Includes/Tonemapping.hlsl` | Vanilla HDR blend inputs plus NVR bloom buffer and `TESR_ToneMapping`, `TESR_HDRData`, `TESR_HDRBloomData`, `TESR_BloomExtraData` | Medium/high | OMV has a post runtime and bloom, so selected math can be reused. Direct shader replacement needs NVR image-space constants and buffer binding. |
| Bink | `Bink/Bink.pso.hlsl` | Simple video YCrCb conversion, `consta c0`, samplers `s0..s2` | Low/no value | Portable technically, but unrelated to PBR and not worth schedule unless video output is broken. |
| Occlusion map | `Occlusion/OcclusionMap.*` | Compiled shader blobs, `TESR_OcclusionWorldViewProjTransform` in vso | High | Binary-only in this checkout and tied to NVR occlusion map pass. OMV already has its own AO path. |
| Generic post extras | NVR effect includes and image-space shaders | NVR global shader constant table, rendered buffer/depth buffer loader, many `TESR_*` constants | Medium/high | Some algorithms may be reusable in OMV's post framework, but direct porting requires NVR-style constant and texture binding. |

## Best Candidates to Finish

### 1. Object PBR Subset

This is the only current native PBR area close to shippable. The work is not "add more shaders"; it is close the variant contract:

- Enumerate every currently visible object PPLighting C/B pair at runtime.
- Map each to an NVR `ObjectTemplate.hlsl` variant.
- Exclude skin, only-light, only-specular, diffuse point, and parallax until separately proven.
- Keep `TESR_PBRData c32` and `TESR_PBRExtraData c33` object-only.
- Verify projected-shadow variants independently.
- Patch out current skin-index acceptance from ordinary object replacement unless a real skin path is implemented.

Do not fold PAR2 into this set. `graphics_fnv_pbr_land_par2_array_contract_followup.txt` proves PAR2 is owned by a separate `ParallaxShader` object:

- vertex shader creation writes the PAR2 VS array at `this+0x8C`;
- pixel shader creation writes the primary PS array at `this+0xDC`, usually indices `0..0x1C`;
- pixel shader creation writes the extended PS array at `this+0x150`, starting at index `0x1D` when the shader-model gate allows it;
- `ParallaxTemplate.hlsl` needs `HeightMap` at variant-dependent stages and `TESR_ParallaxData c35`.

That makes object parallax a separate project after ordinary object PBR.

### 2. LandLOD Cleanup

LandLOD can remain if it is made contract-correct:

- Stop treating NVR LandLOD like object PBR.
- Separate `LandLODSpec c38` from object `TESR_PBRData c32/c33`.
- Decide whether to emulate NVR `TESR_TerrainData c89` / `TESR_TerrainExtraData c90`, or keep an OMV-specific LandLOD shader that does not pretend to be NVR.
- Split base LandLOD from projected-shadow LandLOD if runtime proof shows different ABI.
- Decide whether to mirror NVR10's EyePosition flag patch before relying on replacement vertex shaders beyond the current narrow LandLOD path.

### 3. Selected Post Effects

Reusable NVR math may be useful, but not as native shader replacement:

- Port into OMV's post framework only when the needed buffers already exist.
- Do not copy NVR image-space shaders verbatim unless their `TESR_*` constants and textures are mapped.

## Poor Candidates Right Now

These should not be scheduled until object/LandLOD are stable:

- Close terrain without VPT/FSL/LODFF.
- Terrain parallax.
- Water.
- Sky.
- NVR shadows.
- Object refraction.
- Skin PBR/skin lighting.

They are all real engine-contract projects. They may be valuable later, but they cannot be used to rescue the current PBR decision quickly.

## Decision Gate

PBR survives only if the object/LandLOD subset can be made stable and close terrain is treated as a dependency-backed VPT feature:

1. Object PBR works for ordinary non-skin object variants, including interiors.
2. Skin variants are excluded from the ordinary object matcher or implemented with a true skin contract.
3. Object shadow/light variants either work with proof or are explicitly excluded by runtime discriminator.
4. LandLOD uses a path-specific constant contract and does not reuse terrain/object registers incorrectly.
5. Close terrain requires VPT/FSL/LODFF and is disabled with a clear log when dependencies are missing.
6. NVR coexistence is not a success criterion.
7. No new corruption of interiors, shadows, or lighting is introduced.

If those conditions are not achievable, do not ship native PBR as a user-facing feature; keep it as research/instrumentation only.

## Next Research Targets

Immediate:

- Runtime object variant census from `BSShader::SetShaders`: shader group/index, pass pointer, pass row, selector fields, and replacement decision.
- Runtime PAR2 pass-pair census and height-map provenance before considering object parallax.
- Ghidra/runtime proof for LandLOD projected-shadow ABI.
- Runtime confirmation of whether current shadow/light blinking occurs in object variants, terrain variants, or light-only rows.
- Source-backed cleanup task: remove skin indices from current ordinary object replacement or add a real skin gate.
- Runtime or source-backed EyePosition flag task: decide whether to mirror NVR10's SLS `88..560` flag patch.

Deferred:

- Skin shader family contract.
- NVR global `TESR_*` constant table emulation feasibility.
- Water render-stage ownership.
- Sky/weather constant ownership.
- NVR shadow map subsystem.

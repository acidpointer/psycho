# FNV PBR Errata

This document records known Oh My Vegas / OMV PBR failures, their causes, and the rules that prevent repeating them. It is part of the graphics engineering contract for this repo.

Before touching native PBR, read this together with `AGENTS.md` and the relevant Ghidra output in `analysis/ghidra/output/perf/`.

## Current Status

Object PBR and LandLOD PBR are separate paths and should not be blocked solely by close-terrain failures.

Close terrain PBR is still experimental. OMV may replace the VPT close-terrain exterior shader-row family when VPT/FSL/LODFF are available, the material state is known exterior, and all active diffuse/normal samplers are already bound by the engine. Broad vanilla close terrain, interior terrain, and terrain fade remain blocked until their full draw and constant contracts are proven.

The last close-terrain runtime gate attempt was a failed fix: it caused about `-40 FPS` and produced no useful visual improvement.

## Ground Truth

Use these sources before making terrain or lighting changes:

- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_true_land_discriminator_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_descriptor_contract.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_parallax_terrain_shader_family_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_land_par2_array_contract_followup.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_shader_input_signature_followup_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_material_contract_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_material_mutation_contract_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_constant_register_contract_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_entry_runtime_contract.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_abi_contract.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_declaration_contract.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_distance_specular_transition_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_specular_fade_formula_followup.txt`
- `.research/TESReloaded10-master/NewVegasReloaded/Main.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.cpp`
- `.research/TESReloaded10-master/src/effects/PBR.cpp`
- `.research/TESReloaded10-master/src/effects/POM.cpp`
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp`
- `.research/TESReloaded10-master/src/core/ShaderRecord.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Terrain.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainLODTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainLODTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainFadeTemplate.hlsl`
- `.research/Fallout-Shader-Loader-main/ShaderLoader/main.cpp`

Important proven facts:

- `FUN_00b66640` writes terrain layer flags only when selector `+0xA8 == 9`.
- `+0xA8 == 9` is not sufficient proof that the current draw is the correct close landscape PBR pass.
- `FUN_00bdac00` emits zero-resource land/specular rows. These are not terrain material texture-array passes.
- `FUN_00bdf3e0` emits LandO/light-resource rows. These are not the close terrain seven-layer material contract.
- NVR separates terrain, terrain LOD, and object shader contracts. Do not merge those paths because the names look similar.
- PPLighting close-land vertex group C and pixel group B descriptors use vanilla `lighting\2x\v\land.v.hlsl` and `lighting\2x\p\land.p.hlsl`. This proves the shader source family only; it does not prove true close landscape draw identity.
- LandLOD descriptors use separate `landlod` sources and a separate constant contract. Do not reuse close terrain replacement or NVR `TerrainTemplate.hlsl` assumptions for LandLOD.

Latest close-terrain audits add these constraints:

- `FUN_00BDB4A0` / `FUN_00BDF790` are setup slots shared by several selector/vtable families, including particle, SpeedTree leaf/branch, geometry decal, fog, and imagespace-related owners. These functions are not a terrain discriminator by themselves.
- The PPLighting shader selector vtable is a separate object. Its setup slots are `FUN_00B7AF80` / `FUN_00BE1F90`, while its shader descriptor constructors are `FUN_00B71BF0` and `FUN_00B74210`. Do not confuse descriptor construction with runtime material-array ownership.
- `FUN_00B66640` only writes nine terrain layer flag bytes at selector `+0xC4` when selector `+0xA8 == 9`. This proves material-array layout, not current draw identity.
- `FUN_00B68450` initializes/expands the selector material arrays, reallocates `+0xC4/+0xCC`, and can change selector `+0xA8`. Treat `+0xA8` as mutable descriptor state until runtime logs prove the exact draw-time meaning.
- `FUN_00B68660` owns six material arrays at selector `+0xAC..+0xC0`, clears byte flags at `+0xC4/+0xCC`, fills array entries through the resolver vtable, and derives selector `+0xC8` from contiguous base-layer entries. Capture generation must account for these mutations, not only setup-function entry.
- `FUN_00B994F0` writes the current draw global and obtains the selector from `*( *DAT_011F91E0 + 0xC0)`. `DAT_011FFE2C` is a last-selector cache, not the authoritative draw key.
- `FUN_00BA8EC0` / `FUN_00BA9EE0` define the pass-entry ABI: entry `+0x00` resource/owner, `+0x04` row low word, `+0x07` selector flag, `+0x09` arg count, `+0x0A` arg capacity, `+0x0B` layer byte, and `+0x0C` arg table. List `+0x04` is the entry-pointer array and list `+0x10` is the active entry count.
- Runtime close-terrain diagnostics must include selector `+0x3C` pass entries. The row ID at pass-entry `+0x04`, layer byte at `+0x0B`, selector flag at `+0x07`, runtime mutation flag at `+0x08`, and argument table at `+0x0C` are required for separating true close landscape rows from LandO, projected-shadow, SI, point-light, and helper rows.
- `FUN_00B7AF80` routes rows `0x93`, `0x94`, `0x1F1..0x230`, and some zero-resource rows through material resource field `param_1 + 0x78`. That proves resource-family sharing only; it is not a close terrain discriminator.
- `FUN_00BDAF10` is the diffuse/glow material row helper. Rows `0x93` and `0x94` are base material-family rows, while per-layer material rows are `0x1F2`, `0x1F3` (`499`), `0x1F4` (`500`), and `0x1F5`; the helper writes `entry+0x0B = layer_index + 1` for those per-layer rows.
- `FUN_00BDAF10` derives its loop count from selector `+0xC8`, clamped by `DAT_011AD828`. Runtime replacement must compare this against selector material-array state, not assume seven layers are active.
- `FUN_00BDAC00` emits zero-resource land/specular rows `0x14A`, `0x14B`, `0x14C`, `0x14D`, `0x14E`, `0x14F`, `0x150`, `0x151`, and `0x152`. These rows must be excluded from terrain material-array replacement.
- `FUN_00BDF3E0` emits LandO/light-resource rows in the `0x1F7..0x230` range. Row `0x230` explicitly writes layer byte `9`; that is not a terrain material layer.
- `FUN_00BDF650` emits helper rows `0x10..0x13`, and `FUN_00BDF6C0` emits helper rows including `0x62/0x63`. These are not close terrain material rows.
- `FUN_00BDF790` can mutate just-created pass entries, including category-like data at `+0x06` and runtime flag data at `+0x08`. Keep those fields in runtime logs; do not treat constructor defaults as final draw-time state.
- NVR `TerrainTemplate.hlsl` vertex input expects `POSITION`, `TANGENT`, `BINORMAL`, `NORMAL`, `TEXCOORD0` UV, `COLOR0` vertex color, and `TEXCOORD1/TEXCOORD2` blend channels. Runtime replacement must prove this ABI for the selected vanilla row, not only for the source filename.
- `FUN_00B71BF0` proves PPLighting close-land descriptor source families: close terrain uses vanilla `lighting\2x\v\land.v.hlsl` and `lighting\2x\p\land.p.hlsl`, while LandLOD uses separate `landlod` sources. Static shader-group globals are runtime-populated and read as zero in the binary image, so source references and runtime logs are the useful evidence.
- `FUN_00BD4BA0` and `FUN_00B7DAB0` pass the current geometry shader-args block at `geometry+0x68` into shader-interface virtual `+0x78` for both pixel and vertex paths. This closes the runtime apply bridge, but it still does not prove the exact D3D vertex declaration for each selected mesh row.
- `graphics_fnv_pbr_close_terrain_vertex_declaration_contract.txt` did not find a static `D3DVERTEXELEMENT9` declaration candidate matching the NVR terrain ABI. Its D3D9 method-offset scan is broad and noisy; it does not identify the exact close-terrain declaration or FVF path.
- NVR close terrain expects a complete shader ABI: `BaseMap[7]` at `s0..s6`, `NormalMap[7]` at `s7..s13`, `LandSpec` at `c32/c33`, `LandHeight` at `c34/c35`, fog and sun constants, `TEX_COUNT` matching active layers, and NVR-owned terrain controls at `c89/c90`.
- Vanilla PPLighting registers do not prove the NVR close-terrain constant ABI. `c35`/`c39` hits in the closure audit are `PrevWorldViewPT`/`PrevWorldViewT`, and `c32`/`c37` hits inside setup functions are branch/test immediates, not terrain constant bindings. OMV must either upload the NVR terrain constants explicitly or remove those assumptions from the replacement shader.
- The point-light terrain variant additionally needs `PointLightColor`, `PointLightPosition`, and `PointLightCount` constants. VPT provides those constants for landscape rows `503..558`; do not enable point-light terrain without the VPT terrain contract.
- Current OMV terrain replacement shader is not complete against the full NVR contract: it does not implement the proven `LandHeight c34/c35` parallax contract and terrain fade is still separate/unimplemented. Treat broader terrain PBR as blocked until the remaining engine-side constants and pass families are implemented.

Compare these closure outputs with `[PBR_CONTRACT]` runtime logs from `omv/src/effects/pbr.rs` before changing replacement policy.

Remaining vertex declaration gap:

- Static analysis did not close the exact D3D vertex declaration or FVF contract.
- Runtime `[PBR_CONTRACT] Close terrain vertex_input` and `[PBR_CONTRACT] Close terrain vertex_decl` logs now capture the current FVF, declaration handle/elements, and stream sources for candidate close-terrain rows.
- Use those runtime logs as the next source of truth before claiming NVR terrain vertex ABI compatibility.

## Errata

### 1. Shader-Pair Terrain Detection Is Not a Terrain Contract

Symptom:

- Terrain PBR applies to some chunks and not others.
- Roads or nearby patches remain vanilla.
- PBR appears/disappears while walking.
- Interiors get corrupted by terrain PBR.

Cause:

The bad assumption was:

```text
vertex group C land-ish index + pixel group B land-ish index = true close terrain
```

That is false. A LAND shader slot can belong to helper, projected-shadow, point-light, SI, LandO, landlo-fog, or interior-related rows that do not own the close terrain texture-array ABI.

Do not repeat:

- Do not replace close terrain from shader pair alone.
- Do not infer terrain coverage from shader source names.
- Do not treat a selector with terrain-looking fields as proof of current draw ownership.

Correct fix path:

- Prove the exact pass-entry key or owner that means true close landscape draw.
- Prove exclusion of helper, projected-shadow, point-light, SI, LandO, landlo-fog, interior, and non-landscape rows.
- Keep replacement disabled unless this identity is available at draw time.

### 2. Close Terrain PBR Caused a Large Performance Regression

Symptom:

- Around `-40 FPS` average loss on an RX 6800 XT class GPU.
- No meaningful visual change despite the cost.

Cause:

The failed patch left close terrain replacement active in the hottest terrain path and added expensive work before the visual contract was correct:

- selector reads for `+0xA8` and `+0xC4`;
- terrain layer flag reads;
- material array scans;
- diffuse binding to `s0..s6`;
- normal binding to `s7..s13`;
- texture resource resolution before binding;
- heavy terrain shader work on broad terrain draws.

Do not repeat:

- Do not enable broader close terrain PBR by default until the exact contract is proven.
- Do not bind 14 terrain textures per draw as a generic fix.
- Do not repeatedly call the material resolver in terrain hot paths without a proven stable cache key.
- Do not sample/blend all seven layers unconditionally.
- Do not accept a patch that changes FPS but produces no visual improvement.

Correct fix path:

- First prove the draw contract.
- Then build a minimal terrain shader that only samples active layers.
- Cache resolved texture resources by a proven material/pass key.
- Measure before/after FPS in the same exterior and interior views before considering the patch valid.

### 3. Broken Close Terrain Colors

Symptom:

- Purple, rainbow, or wrong-colored terrain patches.
- PBR-looking color appears on a region, then disappears or moves.

Cause:

The close terrain shader did not match the vanilla/NVR terrain ABI. It trusted layer and blend data before proving:

- the current draw is true close landscape terrain;
- the vertex declaration has the expected blend TEXCOORDs;
- the active layer count is valid;
- the pixel shader constants and samplers match NVR/vanilla terrain.

Layer fallback also allowed active layers to sample layer0, which hides missing resources and produces wrong material output.

Do not repeat:

- Do not normalize arbitrary blend channels from unproven draws.
- Do not use layer0 fallback for active layers.
- Do not run PBR when layer, material, vertex, or constant ABI is incomplete.

Correct fix path:

- Match NVR close terrain ABI: blend inputs, `TEX_COUNT`, `LandSpec`, `LandHeight`, terrain data registers, and vanilla fallback behavior.
- Disable replacement for a draw when an active diffuse/normal layer is missing.
- Use fallback only for inactive layers the shader cannot sample.

### 4. Terrain Holes and Chunk-Like Coverage

Symptom:

- Adjacent close terrain surfaces disagree: one patch is PBR, another stays vanilla.
- Holes appear around roads and nearby terrain.
- Entering a bad region can make another region fill or disappear.

Cause:

The engine switches pass variants based on distance, lighting, projected shadows, cell state, and active resources. Partial replacement catches only some of those rows. A stricter but incomplete gate still creates uneven coverage.

Do not repeat:

- Do not treat partial terrain coverage as progress.
- Do not chase the visible chunk with another shader tweak.
- Do not use logs alone to decide the missing surface class.

Correct fix path:

- Trace the full close-terrain pass family from descriptor creation to final apply.
- Prove which variants are base terrain, alpha terrain, light-only, projected-shadow, helper, and fallback.
- Enable only a complete, coherent terrain pass set, or keep terrain PBR off.

### 5. Interior Walls and Floors Were Broken by Terrain Replacement

Symptom:

- Interior walls become too bright.
- Floors become heavily shadowed.
- Player light causes blinking rectangular floor shadows.
- Objects remain mostly correct.

Cause:

Interior room surfaces can flow through land-ish shader/pass families, but they are not close landscape terrain. Replacing those rows with terrain PBR violates both material and lighting contracts.

Do not repeat:

- Do not apply close terrain PBR inside interiors unless a draw is proven to be true landscape terrain.
- Do not assume walls/floors are terrain because the shader family looks land-related.

Correct fix path:

- Default interior close-terrain PBR to off.
- If interior landscape exists, prove it as a separate contract with its own discriminator.
- Keep ordinary interior room geometry on the object/static material path.

### 6. Game Lights and Shadow Rectangles Blinked

Symptom:

- Street-light surfaces blink when player distance changes.
- Lighted areas overbrighten or darken in rectangular patches.
- Player light creates blinking floor rectangles.

Cause:

Projected-shadow, point-light, SI, LandO, and landlo-fog rows were treated as if they owned the same texture-array contract as base landscape. These rows can change with distance and active lights.

For the separately proven VPT point-light landscape rows, `PointLightColor.a` carries the scene light's runtime fade. Using only `.rgb`, as the NVR reference shader does, turns cell/light-list transitions into visible chunk-shaped steps. OMV must multiply each point-light contribution by the saturated alpha fade.

Do not repeat:

- Do not replace projected-shadow, point-light, SI, LandO, or landlo-fog rows until independently proven.
- Do not bind terrain samplers onto light-resource rows.
- Do not discard the proven VPT point-light alpha fade after a point-light row is admitted.

Correct fix path:

- Prove each light/shadow row independently: resources, constants, samplers, fallback, and pass ownership.
- Keep these rows vanilla until proven.
- If PBR needs light integration, derive it from the proven NVR shader contract, not from shader name similarity.
- For proven VPT point-light landscape rows, preserve both the RGB light color and the alpha fade contract.

### 7. Object Distance PBR Blink

Symptom:

- Objects close to the player have PBR.
- The same objects at distance instantly drop to vanilla style.

Cause:

The first object path covered only nearby/runtime-hit object shader variants. Distant object or LOD variants used different shader families and were not replaced. Current OMV contracts now cover the proven base, LOD, ordinary specular, and ADTS10 high-light object pairs, so this is historical context rather than the current widespread failure.

Vanilla object shaders do multiply accumulated specular lighting by the native fade carried by `LightData[0].w`. The complete archive in `analysis/shaders_disasm/` proves this across all 16 installed quality packages for ordinary and ADTS10 combined-specular rows. However, vanilla applies the fade to a bounded gloss lobe: normal-map alpha is amplitude, `glossPower` is lobe width, and the per-light result is saturated before the fade.

Ghidra closes the complete native contract. `BSShaderPPLightingProperty::GetSpecularFade` returns `1` before the configured start distance, `0` at or beyond the end distance, and a linear `1 - (distance - start) / (end - start)` weight between them. `FUN_00B70820` writes that value into staged `LightData[0].w`; `FUN_00B78A90` copies it to renderer vertex constant `c25.w`; the ordinary and ADTS10 object vertex paths pass it to the pixel shader.

NVR deliberately does something different for object PBR. Its object helper calls pass metallicness `0`, its combined BRDF is accumulated as one result, it does not apply the vanilla fade to ordinary PBR specular, and its ADTS10 path leaves the attenuation as a TODO. NVR also leaves its screen-derivative `SpecularAA` call commented out.

OMV mixed these contracts. It enabled the commented-out `SpecularAA`, split the NVR BRDF, and applied the vanilla fade only to the new GGX lobe. The first curve, `smoothstep(0.0, 0.1, nativeTransition)`, made the lobe appear over a very short distance. Replacing that with the full linear fade made more objects unstable because it exposed the screen-space-dependent GGX term across the entire native interval. The installed metallicness is `0.0`, so metallicness switching is not the cause of the captured run.

See `docs/graphics_fnv_pbr_object_temporal_instability_audit.md` for the complete source, bytecode, formula, and fix audit.

Do not repeat:

- Do not call object PBR complete after one visible nearby family works.
- Do not rely on one test distance.
- Do not assume a scalar with proven vanilla meaning can be applied unchanged to a materially different BRDF.
- Do not enable NVR's commented-out derivative roughness experiment as normal behavior.
- Do not use global object metallicness when no per-material metalness mask exists; NVR object calls pass zero.
- Do not tune another transition curve before restoring the source-proven material model.
- Do not reinterpret `c25.w` globally. Alternate PPLighting paths can store point-light radius data there; the specular fade contract applies only to the proven combined-specular object pairs.

Correct fix path:

- Map runtime-visible object shader families across near, mid, far, lit, shadowed, and LOD states.
- Add replacement only for proven object/static ABI-compatible variants.
- Restore source-equivalent NVR object behavior first: dielectric metallicness zero, unified PBR accumulation, no derivative `SpecularAA`, and no added vanilla fade.
- Restore neutral NVR object profile defaults rather than amplifying the lobe with lower roughness and higher light scale.
- If source-equivalent NVR remains too shiny, design a separate material-faithful mode that preserves normal alpha as specular amplitude and maps engine `glossPower` to GGX roughness. Prove its fade contract separately.
- Keep object, terrain, and LandLOD shader contracts separate.

### 8. Vertex Shader Replacement Must Match the Pixel Path

Symptom:

- Pixel PBR appears missing, unstable, or partially wrong even when the pixel shader compiles.
- Distance or pass changes alter PBR unexpectedly.

Cause:

Some families require matching vertex shader replacement because the pixel shader expects NVR-style interpolants. Replacing only the pixel shader can leave missing or incompatible inputs.

Do not repeat:

- Do not add a pixel shader replacement when its interpolants are not proven.
- Do not reuse object vertex output for terrain or LOD.

Correct fix path:

- Prove vertex input and output signatures for each shader family.
- Replace vertex and pixel shaders as a pair when required.
- Keep a vanilla fallback for every unproven vertex ABI.

### 9. Shader Creation Hook Collision Disabled All Native PBR

Symptom:

- PBR does not work at all.
- OMV logs `CreateVertexShader` / `CreatePixelShader` prologue mismatches.
- OMV logs `Native PBR hooks skipped because a target prologue is not vanilla`.
- The runtime menu can still show native PBR settings, but no object, LandLOD, or close-terrain replacement applies.

Cause:

The broken install contract treated `BSShader::CreateVertexShader @ 0x00BE0FE0` and `BSShader::CreatePixelShader @ 0x00BE1750` as mandatory OMV-owned hooks. In a modern graphics stack, VPT, FSL, LODFF, NVR-like components, or another shader plugin may patch those creation functions before OMV deferred init. That does not prove PBR is unsafe. It only means OMV cannot use those hooks for eager shader-wrapper ownership.

The actual mandatory native PBR contract is draw-time ownership:

- selector setup hooks;
- `SetTexture` capture;
- `SetShaders` replacement/restore;
- pass shader-interface apply;
- lazy ownership seeding for active vertex/pixel shader wrappers.

Do not repeat:

- Do not put `CreateVertexShader` or `CreatePixelShader` into the global mandatory prologue verifier.
- Do not disable all native PBR because shader creation prologues are already patched.
- Do not assume shader creation ownership is the only safe way to identify shader wrappers.

Correct fix path:

- Treat shader creation hooks as optional eager ownership probes.
- If creation hooks are unavailable, log the collision and continue with lazy shader ownership from active draw-time shader wrappers.
- Keep `SetShaders`, `SetTexture`, selector setup, and pass shader-interface hooks as the mandatory install contract.
- If the mandatory draw-time hooks collide, block native PBR and report the exact failed hook.

### 10. Runtime Toggle Rewrote Stale Shader Handles

Symptom:

- Object or terrain PBR becomes less stable after the first off/on comparison.
- Coverage changes after toggling even though the camera and scene are unchanged.
- Repeated toggles produce distance-dependent or seemingly random shader selection.

Cause:

The current replacement path binds a replacement D3D shader pair only around the draw and restores the native D3D pair afterward. It does not mutate engine shader wrappers. The old disable path nevertheless wrote side-table snapshot handles back into current wrappers and restored global shader-package, EyePosition, and fog contracts. A snapshot can predate a later FSL, VPT, or engine handle update, so this disable transaction could overwrite valid current ownership with stale state.

The profile loader had a second state bug: the menu edited one global settings block while hidden object, terrain, time-of-day, and interior profiles could override it. Close terrain could therefore receive neutral values while objects received the visible menu values, making a working terrain renderer appear disabled. This also made an off/on comparison misleading because the UI did not represent the constants used by every family.

Do not repeat:

- Do not restore shader wrapper handles unless the same code path actually mutated them and still proves ownership of the current value.
- Do not tear down shared engine contracts for a runtime presentation toggle.
- Do not expose one shared PBR menu while applying hidden per-family overrides.

Correct fix path:

- Make the runtime toggle a passive draw-time bypass. Keep installed hooks and proven engine contracts resident.
- Restore only the temporary D3D shader pair owned by the current draw.
- Use one explicit object settings snapshot and one explicit terrain snapshot shared by close terrain, terrain fade, and LandLOD. Do not let hidden profiles or legacy generic keys override either family; retire legacy keys during config save.

### 11. One Shader Edit Disabled All Close Terrain During Warmup

Symptom:

- Object PBR, LandLOD, and TerrainFade work, but close terrain remains vanilla.
- The log shows close-terrain shaders compiling and being created without ever logging `CloseTerrain PBR active`.
- The failure appears after editing shared close-terrain HLSL even though the draw contract did not change.

Cause:

Close terrain has one vertex shader and 28 pixel variants across texture counts and `0/6/12/24` point-light buckets. A shared HLSL edit invalidates the cache for the whole family. The broken readiness gate required every variant to finish compiling and creating before it admitted any close-terrain draw. On the measured runtime, useful zero-light variants were ready early, while high-light variants were still compiling more than two minutes later. The game exited before the family-wide gate could open. The object path had the same structural mistake across 101 variants: one failed or warming pair could block every otherwise-ready object pair.

Do not repeat:

- Do not gate one proven terrain variant on unrelated texture-count or light-bucket variants.
- Do not gate one proven object pair on unrelated object variants.
- Do not report a proven engine contract as unavailable merely because shader resources are still warming.
- Do not scan the complete close-terrain resource family every frame to decide whether one draw can run.

Correct fix path:

- Keep engine-contract availability separate from shader-resource readiness.
- At each proven close-terrain draw, require only the common vertex shader and the exact selected pixel variant.
- At each proven object draw, require only its exact replacement vertex/pixel pair.
- Leave that one draw vanilla while its variant is unavailable; admit it immediately once both handles exist.

## Required Proof Before Broadening Close Terrain PBR

A future close terrain fix must prove all of this first:

1. Draw identity

- Runtime proof that the selected draw is true close landscape terrain, not only a PPLighting material-resource row.
- Candidate material key: selector `+0xA8 == 9`, valid selector material arrays, row in `0x1F2/0x1F3/0x1F4/0x1F5`, and pass-entry `+0x0B` in `1..selector+0xC8`.
- Exclude known non-material rows: `0x14A..0x152`, `0x1F7..0x230`, `0x10..0x13`, `0x62/0x63`, projected-shadow, point-light, SI, LandO, landlo-fog, interior, and non-landscape rows unless each gets its own proven contract.

2. Vertex ABI

- Exact vertex declaration.
- Blend TEXCOORD channels.
- Active layer count.
- Alpha and non-alpha compatibility.
- Runtime proof that the selected row's mesh declaration matches NVR `TerrainTemplate.hlsl`, not only that the descriptor source is `lighting\2x\v\land.v.hlsl`.
- Runtime `[PBR_CONTRACT] Close terrain vertex_input` / `vertex_decl` proof for the selected pass-entry row. If this log does not match the NVR terrain input contract, keep close terrain replacement disabled.

3. Pixel ABI

- Diffuse and normal layer sampler ownership.
- Shadow, light, and fallback sampler ownership.
- Constants: `AmbientColor`, `SunColor`, `SunDir`, `LandSpec`, `LandHeight`, fog, point lights, and OMV/NVR PBR registers.

4. Fallback behavior

- Vanilla fallback for unproven or incomplete rows.
- Replacement disabled when active material layers are missing.
- Inactive layer fallback only when the shader cannot sample that layer.

5. Performance budget

- No broad per-draw texture rebinding.
- No repeated resolver work for the same resources.
- No unconditional seven-layer shader cost.
- Before/after FPS comparison in the same exterior and interior scenes.

## Operational Rules

- If a graphics effect needs engine data, buffers, masks, or stage ownership, prove the engine contract before shader work.
- If Ghidra output does not explain ownership, lifetime, and the safe intervention point, write more Ghidra scripts instead of patching.
- Do not broaden close terrain PBR beyond the VPT exterior row family until this errata's proof requirements are satisfied.
- A patch that costs FPS and does not visibly improve the target scene is a regression.

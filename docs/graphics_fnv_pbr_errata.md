# FNV PBR Errata

This document records known Oh My Vegas / OMV PBR failures, their causes, and the rules that prevent repeating them. It is part of the graphics engineering contract for this repo.

Before touching native PBR, read this together with `AGENTS.md` and the relevant Ghidra output in `analysis/ghidra/output/perf/`.

## Current Status

Object PBR and LandLOD PBR are separate paths and should not be blocked solely by close-terrain failures.

Close terrain PBR is still experimental. OMV may replace the VPT close-terrain exterior shader-row family when VPT/FSL/LODFF are available, the material state is known exterior, and all active diffuse/normal samplers are already bound by the engine. Broad vanilla close terrain, interior terrain, and terrain fade remain blocked until their full draw and constant contracts are proven.

The last close-terrain runtime gate attempt was a failed fix: it caused about `-40 FPS` and produced no useful visual improvement.

The current portable point-light correction uses an OMV-only implementation.
At an admitted OMV close-terrain draw, it merges eligible general active lights
that are absent from the current pass, deduplicates by native `NiLight*`, and
uploads them through disjoint OMV constants. Whenever the row still has point
light capacity, manager recovery reads only ranked copied scalar values
published from the stable world-light transaction; it never walks or retains
the manager list during a terrain draw.

The replacement now covers all 56 VPT close-terrain pixel rows, including the
28 odd canopy-shadow companions. An odd row uses the same compiled material and
light program as its even companion. OMV does not sample the native `s14/s15`
camera-projected exterior-shadow inputs through VPT's replacement vertex ABI.

The 2026-07-23 deployed manager-recovery build did not change the residual
random-square defect. The user then established the missing discriminator:
the rectangles blink with camera movement. That runtime rejection means the
manager breadth and ranking changes remain defensive completeness work, but
they are not the root-cause closure for this artifact.

The first follow-up diagnosis was also wrong. Fallout's
`0x011F4998/0x011F499C/0x011F49A0` point-light fallback is the immutable black
color, not a usable override. Rewriting VPT's black `c39` values with those
globals was necessarily a no-op, and the artifact recurred without the repair
branch executing. That repair has been removed.

The camera discriminator exposed a real shared close-terrain shader defect:
the BRDF used `SafeNormalize(view + light, surface_normal)` for both sun and
point half-vectors. OMV corrected that discontinuity, but the user's next
runtime test rejected it as the owner of the reported squares.

The reproduced session instead proves partial shader-family activation. A cold
cache compiled the 57 close-terrain resources over several minutes. OMV began
replacing individual texture/light rows as soon as each row became ready, so
one terrain tile could use PBR while another still used VPT. Camera motion can
change a tile's point-light bucket and therefore switch it between ready and
warming rows. Close-terrain activation is now family-atomic: every row remains
native until all bytecode and all current-device resources are ready, and
device reset clears the family-ready publication.

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
- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_portable_light_classification_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_pipboy_light_0147_shadow_path_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_light_value_copy_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_manager_epoch_contract_followup.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_light_selection_continuity_closure.txt`
- `analysis/shaders_disasm/shaderpackage019/SLS2092.pso.dis`
- `analysis/shaders_disasm/shaderpackage019/SLS2100.pso.dis`
- `analysis/shaders_disasm/shaderpackage019/SLS2140.pso.dis`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_distance_specular_transition_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_specular_fade_formula_followup.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_lighting_transition_ownership_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_runtime_contract_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_table_apply_followup.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_owner_runtime_binding_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_pass_248_24b_texture_binding_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_accessors_stage2_owner_closure.txt`
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

For the separately proven VPT point-light landscape rows,
`PointLightColor.a` carries staged scene-light transition state, but both VPT
and NVR `TerrainTemplate.hlsl` consume only `PointLightColor[i].rgb`. Terrain
PBR must therefore ignore alpha for both native and OMV-recovered point
lights. Making alpha affect only the replacement creates a PBR-only visibility
contract that changes whenever terrain-cell light membership changes.

The vanilla package-19 terrain shaders expose a separate normal-blending
contract. `SLS2092`, `SLS2100`, and `SLS2140` subtract `0.5` from every encoded
normal sample before applying that layer's blend weight, then normalize the
sum. OMV previously blended encoded RGB first and decoded the final value once.
Those equations agree only when the active weights sum to exactly one. With a
partial terrain weight, even a flat upward normal can decode as a downward
normal, making an overhead local light contribute zero. This is especially
visible at night as black dirt beside correctly lit asphalt. OMV now implements
the vanilla center-before-weight equation directly.

The property-local general iterator is not sufficient for every admitted
terrain draw. Static analysis proves that `ShadowSceneNode+0xB4` is the
manager-wide `ShadowSceneLight` list, with linked-list next at `+0x00`, value at
`+0x08`, and native `NiLight*` identity at scene-light `+0xF8`. Active state at
`+0x110` rejects `0x00FF`. Scene-light `+0xEC` instead owns mutable
shadow-casting state: the setter at `0x00B9DCB0` accepts both zero and one, and
the non-shadow iterator merely excludes the value one. The first portable-light
correction incorrectly required `+0xEC == 1`; removing that gate was correct,
but runtime observation proved it was not the cause of the zero-response bug.

The list is safe to inspect only while the engine owns the synchronous world
light/shadow transaction at `0x00871290`. OMV examines at most 512 manager nodes
there, rejects unusable records before the mailbox limit, and copies the 64
eligible candidates with the smallest camera-normalized squared distance into
a fixed scalar epoch. It publishes only native identity, class flags, relative
position, radius, diffuse RGB, dimmer, LOD dimmer, and fade, tagged with the
current render epoch and D3D device. The terrain draw consumes the epoch through
`try_lock` only when both tags match; no manager node, `ShadowSceneLight*`, or
`NiLight*` is dereferenced after publication. A busy, stale, reset, or
foreign-device epoch fails closed to no manager supplement.

#### Camera-dependent random dark terrain squares

A 2026-07-23 recurrence established that the residual dark squares were not
owned by fixed terrain data or a particular exterior object: revisiting the
same location could clear it while another terrain chunk became dark. OMV first
corrected two real manager-recovery omissions: recovery had been restricted to
an entirely empty native/property-local result, and terrain capture filtered
only after a raw 64-node truncation. The resulting build consulted a ranked,
bounded manager epoch whenever capacity remained.

Runtime then rejected that explanation. With the corrected build deployed, the
artifact's behavior was unchanged. The user further observed that an affected
rectangle can blink as the camera moves. Preserve the manager corrections, but
do not cite them as the cause or closure of this defect.

The installed binary that owns terrain light staging is:

- `VanillaPlusTerrain.dll`, SHA-256
  `a241bf8e0bdde3ad5cd4d3926b83cbee2fae8d3900e8c7822ab05957fa71247d`;
- PE image base `0x10000000`, NVSE plugin version `101`;
- `NVSEPlugin_Load` calls the initialization routine at DLL `+0x21B0`; that
  routine selects the game call at `0x00B7DBAC` from DLL `+0x245D` and installs
  the wrapper at DLL `+0x1EE0`;
- the wrapper routes landscape rows `503..558` to DLL `+0x19F0`.

Radare2 inspection of that installed DLL proves its point-light branch. DLL
`+0x1C78` reads `BSLightingShaderProperty+0x6C`; after multiplying
the ordinary dimmer and LOD dimmer, `+0x1C90..+0x1C98` replaces the point-light
dimmer with zero when the property value is below one. DLL
`+0x1CB6..+0x1CED` still copies `ShadowSceneLight+0xD4` into color alpha, stores
the resulting black RGB entry, and increments the native point-light index.
DLL `+0x1E45..+0x1E57` publishes that index as `PointlightCount`. The embedded
PDB path and the matching read-only VPT source identify this routine as
`ShadowLightShader::UpdateLightsAlt`.

The researched Fallout executable is the 32-bit PE
`fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Its original point-light staging at `0x00B70C89..0x00B70CAD` substitutes the
engine globals `0x011F4998/0x011F499C/0x011F49A0` for the same property
condition. Radare2 reads twelve zero bytes at that address, and all 46 cross
references are reads. The globals are the engine's constant black color, so
Fallout and VPT agree. The attempted `c39` rewrite copied zero over zero and
could not change a pixel.

The deployed session that reproduced the artifact contains no successful
native-color-repair log. It does contain an admitted zero-native-point
close-terrain row (`vertex=C[100]`, `pixel=B[116]`, four textures), so the
artifact existed while the rejected point-color branch was absent. This is
direct runtime rejection of that diagnosis.

The shared close-terrain pixel source exposes the actual camera transition.
Both `PbrDirect` and `PbrSun` formed their half-vector with
`SafeNormalize(view_dir + light_dir, normal)`. That helper returns the surface
normal at squared length `<= 1e-6`, then an almost tangent unit vector
immediately above the cutoff. For an ordinary dielectric flat surface with the
view nearly opposite the light, the old negative control changes Fresnel from
approximately `0.04` to approximately `1.0` across a camera delta of `0.0002`.
Direct diffuse response therefore changes by more than `0.9`. The source and
math prove this discontinuity. Identifying synchronized crossings on a
distant, nearly flat landscape draw as the reported draw-shaped dark rectangle
was a reasoned inference that runtime subsequently rejected.

The correction is shader-local and shared by every admitted texture/light and
canopy companion. `StableHalfway` multiplies the sum by
`rsqrt(max(length_squared, 1e-8))`; it is zero at exact opposition and
continuous through the former cutoff. It changes no draw identity, constants,
samplers, light membership, texture blending, fog, or pass ownership. The
production regression proves the old branch's greater-than-`0.9` brightness
step and bounds the corrected response change below `0.001` for the same
camera motion.

Runtime rejected that discontinuity as the reported random-square root cause.
The corrected build still reproduced the same artifact. The next observation
was cell-aligned onset only after travel, while disabling PBR removed it.

The same session's shader lifecycle log closes the delayed-state contract:

- at `11:47:06`, OMV queued 162 shaders, including 57 close-terrain resources;
- at `11:47:59.793`, a four-texture row remained native because `SLS2116` was
  warming;
- at `11:48:00.381`, OMV activated the two-texture zero-light `SLS2100` row,
  when only the common vertex shader and three of 56 pixel rows existed;
- compilation continued through `11:55:19`, and the session ended with only 42
  of 57 close-terrain resources created. The remaining 12-light canopy row and
  all 24-light rows were still unavailable.

This is direct proof that the old readiness gate mixed VPT and OMV shading
within the close-terrain family. The VPT row is selected from texture count and
point-light bucket, both of which vary between terrain draws; the light bucket
can change with camera movement. The visible association with cell-sized
squares follows from those per-tile row choices and is the remaining runtime
acceptance point, not an inferred corruption of persistent cell data.

OMV now publishes separate atomic family-ready states from the compiler and
the current D3D resource owner. `close_terrain_contract_available` requires the
engine contract, all 57 bytecode entries, all 57 current-device shader
resources, and no family failure. No selected row can bypass that gate.
Compilation and D3D creation remain asynchronous; a cold-cache session renders
all close terrain through VPT until the family completes, and a warm cache
normally reaches the same gate quickly. Device loss/reset clears readiness and
again fails closed to the complete native family.

A subsequent 2026-07-21 runtime rejection exposed another independent staging
defect. `omv-latest.log` proved that the replacement was active on the exact
two-texture, zero-native-point row (`vertex=C[100]`, `pixel=B[100]`) while the
scene-wide capture later reported one usable local light. The existing test
named `zero_native_light_night_terrain_still_receives_local_pbr_diffuse` did
not exercise that handoff: it tested only the terrain normal equation and
source strings, without producing a manager light, writing `c91..c93`, or
applying color alpha as the shader does.

Static code and executable evidence close that gap. `FUN_00B9E970` can write
zero to `ShadowSceneLight+0xD4`; this value owns native light/shadow transition
state, not whether an omitted manager light physically exists. VPT's
`TerrainTemplate.hlsl` consumes `PointLightColor[i].rgb` and never consumes
`.a`. OMV instead copied `+0xD4` into every supplemental color and its unified
loop multiplied RGB by that alpha. A shadow-classified Pip-Boy light omitted by
the non-shadow landscape builder could therefore be recovered correctly and
then be turned back into black by OMV itself.

Supplemental terrain constants now carry neutral `1.0` in color alpha. The
regression test starts with a zero-native row and a copied manager Pip-Boy-like
point light whose staged fade is zero, runs the production merge and constant
serializer, then evaluates the old alpha gate. It failed before the fix with
alpha and luminance both zero and passes only when the uploaded supplemental
light remains positive.

Runtime acceptance on 2026-07-21 confirmed the closure: after deploying the
corrected release DLL, the user reported that the Pip-Boy light now illuminates
the previously dark close terrain. Treat explicit supplemental visibility as a
locked compatibility invariant. Do not restore `ShadowSceneLight+0xD4` as the
alpha of a light recovered from the native zero-point row.

A later random-square report exposed the other half of the same contract.
OMV's unified loop still multiplied every native `c39` entry by its alpha,
while a recovered entry arrived with alpha one. The same Pip-Boy light could
therefore illuminate a terrain draw when absent from the native pass and
become black when the native pass admitted it. Native property light lists are
sorted and invalidated as the player/camera travels, so the mismatch followed
cell-aligned draw membership and could blink when membership changed.
Disabling PBR returned to VPT, which always used RGB and therefore removed the
mismatch.

The final correction consumes `light_color.rgb` for the combined native and
supplemental terrain loop. The regression uses the VPT source as the reference,
rejects any `PointLightColor.a` use, and proves the old zero-alpha/native versus
one-alpha/supplemental negative control. Native constants remain read-only;
only OMV's interpretation now matches VPT.

Native position staging also calls
`0x00C4C2D0(geometry+0x68, *(geometry+0xBC), output)` at
`0x00B7DB43..0x00B7DB48`. The second argument selects a meaningful non-null
branch beginning at `0x00C4C4A8`; passing null, as the prior OMV code did,
builds a different transform and can move the light out of the terrain's local
space. OMV now passes the exact `geometry+0xBC` context pointer.

#### Exterior canopy companions and dark night squares

A runtime report on 2026-07-22 disproved the first canopy closure. With the
deployed all-row build and the Pip-Boy light on at night, close terrain still
showed dark rectangular regions associated with exterior geometry. The regions
could appear or disappear as the camera rotated or approached them. The
deployed DLL matched the current release artifact, all 57 close-terrain shader
resources were created, and the log contained no close-terrain missing-sampler
or fallback error. The user's profile had `bDoCanopyShadowPass=1`,
`TTW Canopy Shadows Restoration.esm`, and `canopyshadowpatch.esp` enabled.

The camera dependence rejects fixed terrain texture or normal data as the
primary cause. VPT's `NiLight::IsInMultiBound` builds the tested sphere directly
from `m_kWorld.m_Translate` and radius; OMV uses the same raw `NiLight+0x8C`
center and `+0xE0` radius. The geometry AABB test is therefore not an OMV/VPT
divergence, and rotating the camera does not independently change it.
The odd landscape row, however, is selected for exterior canopy/object-shadow
state and consumes camera-relative projected resources. This evidence changes
the closure from "preserve native canopy sampling" to "keep odd-row PBR
coverage but neutralize the unproven projected-shadow inputs."

The executable researched for this closure is the 32-bit PE at
`fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Radare2 analysis of `0x00BDF3E0` confirms that the native landscape builder
adds one to the selected row when its canopy-shadow argument is set. VPT's
source preserves the same `+1` rule in both its zero-point and point-light
branches. Consequently, each texture/light row has an odd canopy companion:
`504/506/.../558` beside the non-canopy `503/505/.../557` row.

OMV previously registered and replaced only the 28 even SLS pixels
`SLS2092/SLS2094/.../SLS2146`. It recognized the 28 odd companions but
deliberately returned no replacement, leaving them on native shaders. That
made neighboring terrain use different material and light paths. In
particular, an odd zero-point row had no access to OMV's recovered Pip-Boy
light at `c91..c139`, so a night scene could alternate between positive PBR
local-light response and zero response at terrain/canopy boundaries.

The installed shader archives prove only the native pixel side. All 448 odd
companion shaders across the 16 archived packages declare `s14` and `s15`.
Package 19 `SLS2093.pso` samples shadow color from `s14` with `TEXCOORD6.xy`
and strength from `s15` with `TEXCOORD6.zw`. VPT's `TerrainTemplate.hlsl`
replacement vertex shader instead writes clip position to `TEXCOORD6` for its
per-pixel fog path and VPT provides no odd companion pixel source. NVR avoids
this unresolved composition entirely by forcing
`bDoCanopyShadowPass:Display` to zero. Therefore native pixel disassembly was
insufficient evidence that OMV could safely compose those resources with the
VPT vertex replacement. Runtime behavior rejected that inference.

OMV now registers the full odd family `SLS2093..SLS2147`, specialized for
one through seven material layers and native point capacities `0/6/12/24`.
The draw classifier preserves the exact pass-to-pixel identity and marks the
odd rows as native canopy companions for diagnostics. Each odd shader is now a
logical alias of its even PBR companion: it uses the same diffuse/normal
samplers, native and supplemental point-light ABI, and compiled bytecode. Its
bind gate does not require `s14/s15`, and the HLSL declares or samples neither.
This leaves the user's global canopy-shadow setting and non-OMV render paths
untouched while preventing camera-projected exterior masks from entering close
terrain PBR.

The production regression has two parts. Native package-19 disassembly is the
negative control and proves that the rejected path reads `s14/s15`. Then all 28
production odd templates are compiled and their bytecode must equal the paired
even template exactly. Separate mapping tests prove all 56 rows and sampler
masks: a one-layer base or companion requires `0x0081`; a seven-layer companion
requires `0x3FFF`, never `0xC000`. Representative bytecode tests require the
same exact texture counts and ceilings for each pair. The 28 companion resource
slots remain cached because the engine uses distinct SLS identities, but they
add no texture fetch or point-loop work over the base family. The draw path adds
one one-time activation log and no per-draw allocation, lock, file I/O, state
readback, or diagnostic work.

Static validation proves row coverage, resource exclusion, production-bytecode
identity, compilation, and bounded work; it does not prove final runtime
pixels. Ordinary acceptance must check the original exterior at night with
Pip-Boy off/on while rotating and approaching the affected geometry, plus a
daylight check. Native canopy appearance under OMV PBR is intentionally not
claimed; restoring it requires a separately proven VPT-compatible projection
contract and a runtime image regression.

Static validation on 2026-07-22:

- the new focused sampler/source tests failed against the first canopy closure
  because it required `s14/s15` and declared both projected resources;
- focused canopy classification, sampler, and production-bytecode tests passed;
- every registered PBR production variant compiled as shader model 3;
- representative base/canopy, one/seven-layer, zero/24-light bytecode budgets
  passed with exact texture counts;
- `cargo test --target i686-pc-windows-gnu -p omv`: 243 passed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed.

The final light/shadow continuity closure separates two native systems that must not be conflated. `FUN_00B70390` stable-sorts each PPLighting property's light list by the normalized camera-relative sphere-separation metric from `FUN_00B9DBE0`; equal metrics keep the existing order, while a real crossing reorders the list and invalidates cached pass state. This general light-list truncation has no outgoing-light cross-fade. In contrast, shadow candidates use target direction `+0xD8` and elapsed transition time `+0xDC`: `FUN_00B9BB10` preserves the current fade when direction reverses, and `FUN_00B9E970` advances and applies that fade before dirtying attached PPLighting properties at membership boundaries. `FUN_00B717A0` removes a rejected candidate from an eligible property's light list and marks that property dirty.

This evidence does not justify adding hysteresis to the native light comparator
or a second shadow fade. Either change would alter vanilla selection. Native
terrain staging may continue carrying its transition alpha, but the
VPT-compatible terrain pixel path must not consume it for either native or
recovered lights.

Do not repeat:

- Do not replace projected-shadow, point-light, SI, LandO, or landlo-fog rows until independently proven.
- Do not bind terrain samplers onto light-resource rows.
- Do not leave an admitted VPT canopy companion on the native material/light
  path. Pair it with the corresponding PBR variant, but do not sample native
  `s14/s15` until both sides of the VPT-compatible projection ABI and runtime
  pixels are proven.
- Do not reinterpret staged point-light alpha as terrain visibility. VPT and
  NVR consume point-light RGB only; native and recovered membership must have
  identical shader semantics.
- Do not decode one final encoded terrain-normal blend unless the engine
  contract proves the layer weights sum to one. Center every sample before its
  weight, as the vanilla bytecode does.
- Do not add comparator hysteresis or an independent shadow fade to hide an unidentified PBR-only transition.
- Do not special-case the Pip-Boy form or a VPT version. Recover missing lights
  through proven engine classification and native identity.
- Do not treat `0x011F4998..0x011F49A0` as a usable point-light override. It is
  the engine's immutable black color; VPT already matches that native branch.
- Do not use a surface-normal fallback for a BRDF half-vector. Camera/light
  opposition must use branchless zero-safe normalization so Fresnel remains
  continuous.
- Do not call `0x00C4C2D0` with a guessed null context. Pass
  `geometry+0x68` and the pointer stored at `geometry+0xBC`.
- Do not walk `ShadowSceneNode+0xB4` from a terrain draw. Copy bounded scalar
  values at the proven `0x00871290` transaction and reject stale epochs.

Correct fix path:

- Prove each light/shadow row independently: resources, constants, samplers, fallback, and pass ownership.
- Keep these rows vanilla until proven.
- If PBR needs light integration, derive it from the proven NVR shader contract, not from shader name similarity.
- For proven VPT point-light landscape rows, consume staged RGB exactly as VPT
  does. Preserve native constants but ignore their alpha in the terrain pixel
  path; keep the supplemental fourth component neutral.
- For missing portable close-terrain illumination in OMV PBR, enumerate the
  proven general active list only at OMV's admitted replacement draw,
  explicitly accept point/non-ambient candidates, preserve `IsLit()` plus
  multibound filters, and deduplicate against the current pass by `NiLight*`.
- Keep the sun separate and preserve native sorted order under a combined
  24-point-light cap. Do not change `+0xEC`, mutate the render pass, or rebuild
  native light positions/count. Stage missing entries in OMV-owned
  `c91..c139`.
- Keep manager recovery allocation-free and bounded. Consult it whenever the
  row remains below the combined 24-point-light cap, accept every eligible
  copied manager entry regardless of mutable shadow-casting state, rank before
  the 64-entry mailbox limit, and reuse every normal candidate filter.
- Preserve the native property-scalar and matrix-call ABI with tests tied to
  the static evidence, not merely self-consistent math fixtures.
- Keep the close-terrain sun and point half-vector calculation branchless and
  sweep the view/light opposition boundary in the CPU reference test.
- Compile every registered close-terrain variant and retain tight bytecode,
  instruction-count, and exact texture-sample budgets for representative
  one-layer/seven-layer, base/canopy, and zero-light/24-light extremes.

### 7. Object Distance PBR Blink

Symptom:

- Objects close to the player have PBR.
- The same objects at distance instantly drop to vanilla style.

Cause:

The first object path covered only nearby/runtime-hit object shader variants. Distant object or LOD variants used different shader families and were not replaced. Current OMV contracts now cover the proven base, LOD, ordinary specular, and ADTS10 high-light object pairs, so this is historical context rather than the current widespread failure.

Vanilla object shaders do multiply accumulated specular lighting by the native fade carried by `LightData[0].w`. The complete archive in `analysis/shaders_disasm/` proves this across all 16 installed quality packages for ordinary and ADTS10 combined-specular rows. However, vanilla applies the fade to a bounded gloss lobe: normal-map alpha is amplitude, `glossPower` is lobe width, and the per-light result is saturated before the fade.

Ghidra closes the complete native contract. `BSShaderPPLightingProperty::GetSpecularFade` returns `1` before the configured start distance, `0` at or beyond the end distance, and a linear `1 - (distance - start) / (end - start)` weight between them. `FUN_00B70820` writes that value into staged `LightData[0].w`; `FUN_00B78A90` copies it to renderer vertex constant `c25.w`; the ordinary and ADTS10 object vertex paths pass it to the pixel shader.

The separate native EnvMap pass is also closed. Rows `0x248..0x24B` select base, skin, window, and eye pairs `VS50/PS57`, `VS51/PS57`, `VS50/PS58`, and `VS52/PS59`. Base, skin, and window bind normal `s0`, cube `s1`, and optional mask `s3`; eye uses the static eye cube at `s1`. Pixel `c1.w` carries `GetEnvMapFade`, while `c27.z` is property EnvMap scale and `c27.w` selects dedicated-mask red instead of normal alpha. The installed shader-package disassemblies prove this is an additive author-authored reflection pass, not an ordinary object-lighting row.

`FUN_00BB4740` invalidates the property pass list when distance crosses an EnvMap fade endpoint. It does not swap EnvMap textures with distance. Native shaders multiply reflection by the continuous `c1.w` fade before the pass disappears at zero, so a visible step is a runtime-state mismatch until live constants and bindings prove otherwise.

NVR deliberately does something different for object PBR. Its object helper calls pass metallicness `0`, its combined BRDF is accumulated as one result, it does not apply the vanilla fade to ordinary PBR specular, and its ADTS10 path leaves the attenuation as a TODO. NVR also leaves its screen-derivative `SpecularAA` call commented out.

OMV mixed these contracts. It enabled the commented-out `SpecularAA`, split the NVR BRDF, and applied the vanilla fade only to the new GGX lobe. The first curve, `smoothstep(0.0, 0.1, nativeTransition)`, made the lobe appear over a very short distance. Replacing that with the full linear fade made more objects unstable because it exposed the screen-space-dependent GGX term across the entire native interval. The installed metallicness is `0.0`, so metallicness switching is not the cause of the captured run.

The lighting-transition ownership audit closes the remaining row-handoff contract. `FUN_00BB4740` invalidates and rebuilds the property pass list when its camera-relative distance reaches the specular-fade end. Source-equivalent NVR leaves its GGX lobe fully active until that row change, so restoring NVR alone removes the experimental instability but does not make the native specular-to-non-specular handoff continuous. `FUN_00B70820` also proves that staged light RGB already contains the engine light dimmer and property scale; object lighting must not reinterpret light alpha as a missing generic RGB fade.

The ADTS10 high-light path had a separate source-level count mismatch inherited from NVR. Native pixel bytecode retains the previous lighting sum when `lightCount <= threshold`; the replacement source used that correct inclusive comparison only for the second light and strict comparisons for lights three through six. At an exact integer count, the pixel shader therefore evaluated one more light than the vertex shader exposed. The unavailable interpolator was zero, and the PBR helper normalized that zero direction before multiplying the contribution by its mask. Camera-driven light-list rebuilds could consequently turn an ordinary count transition into undefined lighting for only the objects using the high-light rows.

The material-faithful follow-up exposed another camera-dependent discontinuity
shared by every object-light family. The zero-length guard for
`eyeDir + lightDir` used the surface normal as its fallback half-vector. When
view and light become opposed, the physical limit is `LdotH -> 0`, but that
fallback changes it to `LdotN` for the exact guarded interval. A light aligned
with the normal therefore changes dielectric Fresnel from approximately `1` to
`0.04` at the boundary, which can restore roughly 96 percent of direct diffuse
lighting in one step and can also create a false specular half-vector. Replacing
the normal with a hard zero removed that exact spike but left a second step at
the epsilon cutoff: the result still jumped from zero to a unit half-vector.
OMV now uses branchless soft normalization. It is zero at exact opposition and
converges continuously to the normalized half-vector, preserving the Fresnel
limit and suppressing the undefined specular lobe across base, specular,
high-light, only-light, diffuse-point, and only-specular object rows.

The vanilla package-19 disassembly exposed a separate ABI omission in the
ported special object rows. `SLS2037..2044` sample the engine attenuation lookup
texture at `s4`, while `SLS2045/2046` sample it at `s3`. Their paired vertex
rows generate two lookup coordinates per point light in `TEXCOORD4..6`. The
NVR-derived replacement omitted those interpolators and samplers and used an
analytic radial approximation instead. OMV now reproduces the native lookup
coordinates and `saturate(1 - sample(xy) - sample(zw))` equation, and rejects a
replacement draw if that native attenuation texture is absent. This preserves
the engine-authored light falloff and remains compatible with future upstream
changes because OMV consumes the current draw's native resource rather than
identifying a dependency version.

The analytic attenuation retained by ordinary and ADTS10 rows also divided the
light vector by radius. An inactive or stale zero-radius slot could therefore
create a NaN before its contribution was masked. OMV uses the equivalent finite
form `1 - dot(L,L) / max(radius^2, epsilon)`. ADTS10 pixel rows now place uniform
branches around inactive light slots, matching the native inclusive light-count
contract and avoiding both undefined arithmetic and unnecessary BRDF work.

See `docs/graphics_fnv_pbr_object_temporal_instability_audit.md` for the complete source, bytecode, formula, and fix audit.

Do not repeat:

- Do not call object PBR complete after one visible nearby family works.
- Do not rely on one test distance.
- Do not assume a scalar with proven vanilla meaning can be applied unchanged to a materially different BRDF.
- Do not enable NVR's commented-out derivative roughness experiment as normal behavior.
- Do not use global object metallicness when no per-material metalness mask exists; NVR object calls pass zero.
- Do not tune another transition curve before restoring the source-proven material model.
- Do not reinterpret `c25.w` globally. Alternate PPLighting paths can store point-light radius data there; the specular fade contract applies only to the proven combined-specular object pairs.
- Do not use strict `N > lightsUsed` exclusion tests in the high-light pixel path. Native excludes the next slot when `lightsUsed <= N`, matching the vertex shader's `N < lightsThreshold` activation rule.
- Do not rely on multiplying an invalid light calculation by zero. Inactive light directions must remain finite before PBR evaluation.
- Do not use the surface normal as the fallback for an undefined BRDF half-vector. It is finite but discontinuous when view and light become opposed.
- Do not replace the normal fallback with a hard epsilon branch. That moves the half-vector step to the cutoff instead of removing it.
- Do not replace the native only-light/diffuse-point attenuation lookup with an analytic radius approximation.
- Do not evaluate inactive ADTS10 light slots and multiply the result by zero afterward.
- Do not feed EnvMap rows through the ordinary object PBR template; their sampler, vertex, constant, and additive-output ABIs are different.
- Do not invent roughness LOD or Fresnel for the native cube. No prefiltered mip-chain, BRDF lookup, or material roughness contract has been proven for this pass.

Correct fix path:

- Map runtime-visible object shader families across near, mid, far, lit, shadowed, and LOD states.
- Add replacement only for proven object/static ABI-compatible variants.
- Restore source-equivalent NVR object behavior first: dielectric metallicness zero, unified PBR accumulation, no derivative `SpecularAA`, and no added vanilla fade.
- Restore neutral NVR object profile defaults rather than amplifying the lobe with lower roughness and higher light scale.
- If source-equivalent NVR remains too shiny, design a separate material-faithful mode that preserves normal alpha as specular amplitude and maps engine `glossPower` to GGX roughness. Prove its fade contract separately.
- Keep object, terrain, and LandLOD shader contracts separate.
- Keep the proven EnvMap rows native while comparing live `c1.w`, `c27`, and `s0/s1/s3` against the static contract at the reported distance transition.

Current material-faithful implementation (2026-07-16):

- Normal-map alpha remains specular amplitude.
- Engine `glossPower` remains lobe width; the object roughness scale adjusts that exponent rather than replacing it with normal alpha.
- Direct object specular uses a normalized, dielectric Blinn distribution with Schlick Fresnel and a bounded per-light result. This preserves the engine material controls without exposing the previous unbounded GGX peak.
- Only combined-specular object rows consume the proven native fade. Diffuse and ambient are not attenuated by it.
- Combined and non-specular rows use the same direct diffuse equation, so the result converges before `FUN_00BB4740` changes rows.
- Normal/view normalization and albedo preparation are performed once per pixel, not once per light.
- Every registered object shader is compiled and guarded by family-specific
  bytecode and instruction-count budgets; pixel rows also have a texture-sample
  ceiling. The current maxima are 520 instructions for the source-equivalent
  skinned high-light vertex row, 328 for the high-light pixel row, and nine
  texture samples for the native three-light SI projected-shadow row.
- Inactive ADTS10 lights are skipped with uniform branches, so their attenuation
  and BRDF are not evaluated.
- Normal runtime mode performs no PBR diagnostic counter updates, draw-trace
  hashing, state readback, or periodic contract logging. Detailed telemetry is
  opt-in. Live draw-boundary shader pointers use the proven fixed layouts
  directly; validated pointer readers remain in capture/adoption/setup paths.
- The opposed view/light boundary is numerically swept by a source-linked
  regression. A full bounded-BRDF sweep covers zero/opposed directions, native
  gloss exponents, attenuation, strength, and fade monotonicity. Registry,
  native attenuation ABI, sampler masks, finite attenuation, light-count gates,
  shader compilation, and GPU budgets are all exhaustive static gates.

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

Close terrain originally had one vertex shader and 28 base pixel variants
across texture counts and `0/6/12/24` point-light buckets; complete canopy
coverage now makes that 56 pixel variants. A shared HLSL edit invalidates the
cache for the whole family. The broken readiness gate required every variant to
finish compiling and creating before it admitted any close-terrain draw. On the
measured runtime, useful zero-light variants were ready early, while high-light
variants were still compiling more than two minutes later. The game exited
before the family-wide gate could open. The object path had the same structural
mistake across 101 variants: one failed or warming pair could block every
otherwise-ready object pair.

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
- When a source-proven defect can be expressed and exhausted through pure
  production helpers, static ABI tests, real shader compilation, and bytecode
  budgets, use that path before deployment. Do not add an in-game diagnostic
  subsystem merely to reconfirm the same source error.
- Static validation is a deployment gate, not proof of final pixels. Finish a
  statically validated graphics change with an ordinary feature-first playtest.

## Performance Contract (2026-07-22)

A runtime report attributed a 7-10 FPS loss, and sometimes more, to native PBR.
That observation establishes the severity and the scenes to retest; it is not a
reproducible benchmark result in the repository. The optimization must retain
the complete material, light, row, and fallback contracts above.

The close-terrain pixel family had three avoidable costs:

- surface normal and view direction were normalized again inside the sun BRDF
  and inside every point-light iteration even though `Main` already produces
  finite normalized values;
- the shader compiled a vanilla BRDF and selected it through
  `TESR_TerrainExtraData.x`, although OMV binds a replacement only while native
  PBR is enabled and always uploads `c90.x = 1`; a disabled, warming, or failed
  replacement draw already remains on the native engine pair;
- metallic reflectance, diffuse color, roughness alpha, `NdotV`, and the
  view-side geometry term were rebuilt for the sun and for every point light.

The active NVR-derived object family also rebuilt invariant material terms for
every admitted sun or point light: diffuse albedo divided by PI, the bounded
specular normalization, and saturated native strength/fade controls.

`native_pbr_pplighting_close_terrain.hlsl` now normalizes surface inputs once,
prepares those loop-invariant BRDF terms once per pixel, and reuses them across
the unchanged sun and combined native/supplemental point-light loop. It also no
longer copies the seven terrain weights or accumulates the vanilla-only weighted
gloss exponent. TerrainFade uses the same replacement-only rule and performs
light/view normalization once in `Main`; LandLOD likewise no longer repeats its
already-completed surface normalization inside `PbrSun`.

Object shaders now prepare those material terms once per pixel and pass the
prepared surface through the unchanged sun/point-light paths. Light direction,
Fresnel, attenuation, radiance, and highlight evaluation remain per light as
required. The three representative object ceilings are now 115 instructions for
the one-light specular row and 235/231 instructions for the four-light normal
and optimized rows, all with their original two texture samples.

This does not change any quality dimension:

- close terrain still samples exactly two textures per active material layer;
- the one-through-seven-layer and `0/6/12/24` native-light variants remain;
- the total native plus supplemental point-light cap remains 24;
- native and supplemental point lights use the same RGB-only VPT contract;
- corrected center-before-weight normal blending remains unchanged;
- canopy companions remain byte-identical to their paired base variants; and
- every object row, native light count, attenuation mode, projected-shadow
  path, specular-strength control, and native specular fade remains enabled; and
- disabling PBR still bypasses the replacement and uses the native shader, not
  an approximation embedded in the replacement.

The tests now sweep the prepared BRDF against the prior equation, prove the
replacement marker, reject repeated surface normalization and unreachable
vanilla work, sweep the prepared object equation against its prior form, compile
every registered PBR shader, and impose tight bytecode, instruction, and
texture-sample ceilings on representative object rows, LandLOD, TerrainFade,
and the close-terrain extremes. Current maximum representative close-terrain
costs are 1,358 compiled instruction tokens and 14 texture samples for the
seven-layer/24-light row. These are static workload gates, not an FPS claim.

Runtime acceptance must compare the same save, camera, resolution, weather, and
scene with PBR off/on. Include daylight and the original night exterior with the
Pip-Boy light while rotating and approaching canopy geometry. Confirm both frame
time and the absence of returning dark/blinking rectangles. A GPU capture or
repeatable frame-time trace is still required before assigning an FPS delta to
this change.

Repository validation on 2026-07-22 passed all 254 OMV tests and the supported
release build for `i686-pc-windows-gnu`. The tests exercise shader compilation
through Wine; the scene-level visual and frame-time acceptance above still
requires the game runtime.

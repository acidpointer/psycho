# OMV PBR vs NVR Contract Gap Report

This report compares the current OMV native PBR implementation against
`docs/nvr_reference_contract.md`, NVR source, VPT source, and the existing FNV
PBR errata. It is a source-level audit, not a playtest verdict.

The short version: OMV now has useful PBR shader work and a much better compile
path, but it is still not a complete NVR PBR port. The biggest remaining
problem is not the BRDF. The biggest problem is that OMV does not yet reproduce
NVR's shader/pass/resource/constant contract. That explains the reported
lighting blink, destroyed point lights, and terrain chunks switching between
states.

## Ground Truth Used

- `docs/nvr_reference_contract.md`
- `docs/graphics_fnv_pbr_errata.md`
- `.research/TESReloaded10-master/src/effects/PBR.h`
- `.research/TESReloaded10-master/src/effects/PBR.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.h`
- `.research/TESReloaded10-master/src/effects/Terrain.cpp`
- `.research/TESReloaded10-master/src/core/ShaderRecord.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl`
- current OMV implementation in `omv/src/effects/pbr.rs`
- current OMV shaders in `omv/shaders/embedded/`

## Highest Severity Gaps

### 1. OMV Does Not Yet Implement NVR's ShaderRecord / SetCT Contract

NVR does not simply force a replacement D3D shader handle and upload two custom
constants. NVR loads replacement `ShaderRecord`s, records constant-table
metadata, clears samplers when required, binds declared textures, applies sampler
states, resolves depth/rendered buffers when a shader declares them, and updates
all `TESR_*` constants through `ShaderRecord::SetCT()`.

Reference:

- NVR parses `TESR_` constants/samplers from the shader constant table in
  `.research/TESReloaded10-master/src/core/ShaderRecord.cpp:265`.
- NVR `SetCT()` clears samplers, binds textures, applies sampler states, and
  uploads all declared constants in
  `.research/TESReloaded10-master/src/core/ShaderRecord.cpp:423`.
- NVR replacement setup calls `SetCT()` when the replacement handle changes in
  `.research/TESReloaded10-master/src/core/ShaderRecord.cpp:480` and
  `.research/TESReloaded10-master/src/core/ShaderRecord.cpp:532`.

Current OMV:

- OMV temporarily writes the replacement pixel handle into the game shader object,
  calls original `SetShaders`, then forces the D3D shader state and uploads only
  OMV material constants in `omv/src/effects/pbr.rs:3057`.
- The key flow is `write_shader_native_handle` at
  `omv/src/effects/pbr.rs:3176`, `original(shader, pass_index)` at
  `omv/src/effects/pbr.rs:3226`, forced D3D shader state at
  `omv/src/effects/pbr.rs:3230`, and custom constant upload at
  `omv/src/effects/pbr.rs:3244`.

Gap:

- There is no NVR-equivalent source-driven constant table.
- There is no per-shader declared sampler binding contract.
- There is no full `TESR_*` upload for every replacement pass.
- There is no generic depth/rendered-buffer resolve contract for shaders that
  need those resources.
- Pixel samplers are not cleared/bound per row the way NVR does.

Impact:

- A replacement shader can run with stale or row-incompatible samplers/constants.
- Projected shadow/helper/point-light variants are especially vulnerable.
- This is a strong match for reported distance/angle lighting blink and lamps
  changing state when PBR is enabled.

Fix direction:

- Build an OMV replacement-record layer modeled after NVR `ShaderRecord`.
- For every replacement row, own the expected constants, samplers, sampler states,
  and fallback behavior.
- Treat handle substitution as an implementation detail only after the contract
  layer exists.

### 2. Material Resource Capture Exists, But Is Disabled For Real Replacement

NVR's contract is resource-driven. A shader row declares what it samples; NVR
binds that exact resource set for that row.

Current OMV has selector/material capture code, but all replacement kinds opt out:

- `uses_extra_material_stages()` returns `false` in `omv/src/effects/pbr.rs:1799`.
- `uses_selector_material_resources()` returns `false` in
  `omv/src/effects/pbr.rs:1803`.
- `writes_material_flags()` returns `false` in `omv/src/effects/pbr.rs:1807`.
- Therefore the real draw path falls back to
  `ReplacementMaterialBindings::vanilla_bound(shader_kind)` in
  `omv/src/effects/pbr.rs:3144`.

Gap:

- The selector material-array path is mostly diagnostic/inactive for replacement.
- OMV relies on whatever vanilla already bound in the D3D texture stages.
- OMV validates only presence of a few current texture stage handles, not the full
  row sampler contract.

Impact:

- Helper rows with different sampler layouts can pass validation while using
  wrong resources.
- Projected shadow rows can sample stale or incompatible shadow samplers.
- Point-light/helper passes can become partially vanilla and partially OMV.

Fix direction:

- Enable row-specific material resource resolution only after a proven stable
  cache key exists.
- Bind only the resources required by the row.
- Clear or explicitly preserve sampler slots according to the row contract.

### 3. Object PBR Row Coverage Is Still Incomplete

NVR object PBR covers a large matrix of vertex and pixel rows. The contract
requires base, optimized, LOD, SI, projected-shadow, STBB, hair, multi-light,
specular, `ONLY_LIGHT`, `DIFFUSE`, `ONLY_SPECULAR`, point-helper, and skinned
variants.

Reference:

- NVR object template table is in
  `.research/TESReloaded10-master/src/effects/PBR.h:8`.
- NVR pixel rows explicitly include STBB/hair and hair helper variants:
  `.research/TESReloaded10-master/src/effects/PBR.h:64`,
  `.research/TESReloaded10-master/src/effects/PBR.h:65`,
  `.research/TESReloaded10-master/src/effects/PBR.h:102`,
  `.research/TESReloaded10-master/src/effects/PBR.h:106`,
  `.research/TESReloaded10-master/src/effects/PBR.h:108`,
  `.research/TESReloaded10-master/src/effects/PBR.h:110`.
- NVR object shader has special hair and STBB logic in
  `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl:541`
  and
  `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl:553`.

Current OMV:

- Object mapping covers many base/SI/projected-shadow/multi-light/helper rows in
  `omv/src/effects/pbr.rs:3426`.
- Skinned vertex rows are explicitly rejected in
  `omv/src/effects/pbr.rs:3382`.
- Hair/STBB rows are not mapped to replacement kinds in
  `pplighting_sls2_object_replacement_kind`.
- Replacement object vertex shaders are not provided. `vertex_source()` returns a
  shader only for `LandLod` in `omv/src/effects/pbr.rs:1593`.

Gap:

- Skinned object PBR is missing.
- Hair object PBR is missing.
- STBB object PBR is missing.
- Hair variants of `ONLY_SPECULAR` helper rows are missing.
- Object vertex replacement is not source-equivalent to NVR; OMV relies on
  vanilla vertex outputs for all object replacement pixels.

Impact:

- Objects can switch between PBR and vanilla based on mesh type, helper pass,
  distance, projected shadow state, or material type.
- That switch can present as blinking lighting or metallicness disappearing on
  some surfaces.

Fix direction:

- Build an explicit row-completion table from NVR `PBR.h`.
- Treat missing hair/STBB/skin/helper variants as blockers for "complete object
  PBR".
- For every object pixel row, either prove the vanilla vertex ABI is compatible
  or add the matching NVR-derived vertex replacement.

### 4. Close Terrain PBR Is Not NVR Terrain PBR

NVR close terrain is built on VPT's contract: close landscape rows, active layer
count, seven diffuse slots, seven normal slots, `LandSpec`, `LandHeight`, fog,
point lights, and NVR terrain/parallax constants.

Reference:

- VPT/NVR terrain constants are documented in
  `docs/nvr_reference_contract.md:868`.
- NVR terrain row coverage is documented in
  `docs/nvr_reference_contract.md:897`.
- NVR terrain source declares `LandHeight[2] : c34` in
  `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl:108`.
- NVR terrain computes parallax-derived `weights` using `getParallaxCoords` in
  `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl:134`.
- NVR terrain uses parallax shadows in
  `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl:146`.

Current OMV:

- OMV close terrain shader declares `LandSpec`, fog, and terrain tuning, but not
  `LandHeight`, `TESR_TerrainParallaxData`, or `TESR_TerrainParallaxExtraData` in
  `omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl:9`.
- OMV blends diffuse/normal maps using original vertex blend channels only in
  `omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl:278`.
- OMV validates only that active diffuse stages and normal stages are non-null in
  `omv/src/effects/pbr.rs:3805`.

Gap:

- `LandHeight c34/c35` is missing.
- Terrain parallax constants `c91/c92` are missing.
- NVR `getParallaxCoords` / height-blend weights are missing.
- NVR parallax shadow multiplier is missing.
- Validation does not prove `LandSpec`, `LandHeight`, active layer count,
  pass-entry identity, point-light constants, or vertex declaration.

Impact:

- Terrain material blending differs from NVR.
- Close terrain can look angle/distance dependent for the wrong reason because
  OMV is not reproducing the height/parallax layer contract.
- It can never be called a complete close terrain PBR port in this state.

Fix direction:

- Port the full NVR terrain shader contract, not only the BRDF part.
- Add terrain parallax settings/state and constants.
- Use VPT `LandHeight` and active layer count.
- Keep replacement disabled for any draw where this contract is not present.

### 5. Close Terrain Runtime Identity Still Uses Shader-Pair Recognition

The errata explicitly says shader-pair recognition is not a terrain contract.

Reference:

- `docs/graphics_fnv_pbr_errata.md:92` states the bad assumption:
  land-ish vertex/pixel shader pair equals true close terrain.
- The correct path requires pass-entry proof and exclusion of helper,
  projected-shadow, point-light, SI, LandO, landlo-fog, interior, and
  non-landscape rows.

Current OMV:

- Close terrain replacement is selected from vertex group/index and pixel
  group/index in `omv/src/effects/pbr.rs:3688`.
- It is gated by module presence and known exterior in
  `omv/src/effects/pbr.rs:3369`.

Gap:

- OMV does not yet require the proven pass-entry key from the Ghidra audits:
  row ID, layer byte, selector flag, mutation flag, argument table, and active
  entry count.
- OMV does not prove exclusion of all non-close-landscape pass families at draw
  time.

Impact:

- Terrain can switch between replaced and vanilla rows as distance, projected
  shadows, point lights, or helper passes change.
- This directly matches "shadowed chunks" and terrain blinking with angle/distance.

Fix direction:

- Promote pass-entry identity from diagnostic logging to the required replacement
  gate.
- Do not use shader pair alone for terrain replacement.

### 6. Terrain Point-Light Variants Are Incorrectly Downshifted

VPT/NVR point-light close terrain rows are separate shader contracts. They have
additional point-light constants at `c39`, `c63`, and `c88`.

Current OMV:

- If a point-light close-terrain tier is not fully created but the zero-light tier
  is available, OMV silently returns the zero-light variant in
  `omv/src/effects/pbr.rs:3407`.

Gap:

- A point-light row must not be rendered with a no-point-light shader.
- This is a deterministic contract violation.

Impact:

- Terrain lighting can disappear or change as the engine switches point-light
  tiers.
- This is one of the most likely contributors to distance-based terrain blink.

Fix direction:

- Remove the point-light-to-zero-light downshift.
- If the exact point-light variant is unavailable, fall back to vanilla for that
  draw.

### 7. Terrain LOD Is Partial And Terrain Fade Is Missing

NVR terrain collection covers three separate contracts:

- close terrain: `SLS2100.vso` and `SLS2092..SLS2146.pso`;
- terrain LOD: `SLS2002.vso` and `SLS2003.pso`;
- terrain fade: `SLS2080.vso` and `SLS2082.pso`.

Reference:

- NVR terrain template table is in
  `.research/TESReloaded10-master/src/effects/Terrain.h:8`.

Current OMV:

- OMV has a LandLOD replacement path and vertex shader.
- LandLOD projected shadow is explicitly skipped in
  `omv/src/effects/pbr.rs:3362`.
- Terrain fade rows are not implemented.

Gap:

- Terrain fade is absent.
- LandLOD projected shadow is absent.
- Distance transitions cannot be coherent with NVR terrain behavior.

Impact:

- PBR can appear/disappear during close-to-LOD transitions.
- Distant/near terrain may disagree in lighting/material response.

Fix direction:

- Implement terrain fade from NVR `TerrainFadeTemplate.hlsl`.
- Decide whether LandLOD projected shadow is required; if the game uses it in
  visible terrain transitions, it is a blocker for coherent terrain PBR.

### 8. PBR Profile Updates Are Missing WetWorld/Rain Contract

NVR PBR constants are not static sliders. They are interpolated from current
game state and WetWorld.

Reference:

- NVR object `rainFactor = max(WetWorld.RainAmount, WetWorld.PuddleAmount)` in
  `.research/TESReloaded10-master/src/effects/PBR.cpp:41`.
- NVR terrain uses the same WetWorld rain factor in
  `.research/TESReloaded10-master/src/effects/Terrain.cpp:50`.

Current OMV:

- Object rain factor is hardcoded to `0.0` in `omv/src/effects/pbr.rs:4497`.
- Terrain rain factor is hardcoded to `0.0` in `omv/src/effects/pbr.rs:4521`.
- Material state is refreshed every `PBR_STATE_REFRESH_INTERVAL` PBR checks, not
  every frame, in `omv/src/effects/pbr.rs:4532`.

Gap:

- Rain and night-rain profiles are parsed but inactive.
- Wet/puddle behavior is not implemented.
- State update timing is not equivalent to NVR's frame/game-state update model.

Impact:

- Outdoor wet terrain/object behavior cannot match NVR.
- Some transitions can lag behind current game state.

Fix direction:

- Port or implement a proven WetWorld-equivalent state source.
- Update PBR constants from a frame-owned state update, not opportunistically
  every N replacement checks.

### 9. Terrain Dependency Detection Is Only Module Presence

Current OMV:

- `GraphicsCompatibility::has_vpt_terrain_contract()` returns true when
  `VanillaPlusTerrain.dll`, `Fallout Shader Loader.dll`, and `LODFlickerFix.dll`
  are loaded in `omv/src/compat.rs:21`.
- `configure_terrain_contract()` stores only a boolean in
  `omv/src/effects/pbr.rs:2618`.

Gap:

- OMV does not verify VPT version, shader row table, constant register map, row
  generation, or FSL replacement state.
- Module presence proves only that the DLLs are loaded.

Impact:

- A mismatched VPT/FSL build can satisfy OMV's gate while not satisfying the real
  terrain contract.

Fix direction:

- Keep module presence as a first gate only.
- Add runtime contract probes for VPT rows/constants and log exact versions or
  row signatures when possible.

### 10. OMV Object Shader Is Intentionally Not Source-Equivalent To NVR

This may be a desired OMV feature, but it is a contract difference.

Reference:

- `docs/nvr_reference_contract.md:729` records the NVR quirk: object PBR constants
  contain metallicness, but current NVR object helper calls pass metallicness `0`
  into the BRDF.

Current OMV:

- `PbrDirectMetallicness()` returns configured metallicness for non-helper object
  rows in
  `omv/shaders/embedded/native_pbr_pplighting_object.hlsl:174`.
- `PbrLightMultiplier()`, `PbrAmbientMultiplier()`, and
  `PbrAlbedoSaturation()` substitute `1.0` when the constant is `<= 0` in
  `omv/shaders/embedded/native_pbr_pplighting_object.hlsl:183`.

Gap:

- OMV object metallicness behavior differs from current NVR.
- OMV cannot represent a deliberate zero light scale, ambient scale, or albedo
  saturation because zero is treated as "use default 1.0".

Impact:

- Metallicness working in OMV does not prove source-equivalent NVR object PBR.
- Some config values cannot be expressed precisely.

Fix direction:

- Decide explicitly whether OMV wants source-equivalent NVR behavior or an
  improved object metallicness model.
- Do not mix the two silently. Document and gate the choice.

### 11. Config Comments Are Stale/Inaccurate

Current OMV config says the proven object contract is "non-SI/non-HAIR" and that
helper passes remain vanilla, but runtime now implements some SI and helper
variants.

References:

- Config comments around `omv/config/omv.toml:149`.
- Runtime SI/helper mappings around `omv/src/effects/pbr.rs:3426` and
  `omv/src/effects/pbr.rs:3571`.

Gap:

- Config documentation no longer accurately describes runtime behavior.
- This makes playtest reports harder to interpret.

Fix direction:

- Update config comments after the row-completion table is formalized.
- Keep comments explicit about incomplete rows: skin, hair, STBB, terrain fade,
  projected LandLOD, WetWorld, terrain parallax.

## Symptom Mapping

### Interior point lights/lamp lighting destroyed

Most likely contract causes:

- helper/point-light row coverage is incomplete;
- row-specific sampler binding is not owned;
- `SetCT` equivalent is incomplete;
- projected shadow/helper sampler slots can be stale;
- skinned/hair/STBB/object special rows can switch to vanilla.

The first suspect should not be the BRDF formula. The NVR contract document says
the first suspect is missing helper/point-light row coverage or stale
constants/samplers.

### Object lighting changes when looking from angle/distance

Most likely contract causes:

- object row switches between replaced and vanilla variants;
- LOD/hair/STBB/skin/special pass rows are incomplete;
- vanilla vertex ABI is assumed rather than proven for every replaced pixel row;
- sampler state from the prior pass leaks into the replacement pass.

### Close terrain PBR appears but blinks/chunks

Most likely contract causes:

- shader-pair terrain detection is still used;
- pass-entry identity is not a required gate;
- point-light terrain rows can be downshifted to no-point-light shaders;
- terrain fade is missing;
- LandLOD projected shadow is missing;
- `LandHeight`/height-blend/parallax contract is absent.

### Performance is better now, but correctness is still broken

The async compile/prewarm work helped the stutter/freeze class of problems. It
does not solve the PBR correctness contract. The next performance risk is not
shader compilation; it is doing material resolution/binding in terrain hot paths
without a stable cache key. The errata already forbids broad hot-path terrain
resource scans.

## Required Fix Order

1. Create a source-derived row table from NVR `PBR.h` and `Terrain.h`.
   It must say, for each row, whether OMV implements it, deliberately falls back,
   or still needs research.

2. Remove incorrect terrain fallback behavior.
   Point-light terrain rows must never downshift to zero-light terrain shaders.

3. Promote terrain pass-entry identity to a hard gate.
   Shader pair alone must not enable close terrain PBR.

4. Implement an OMV replacement-record layer.
   It must own row constants, samplers, sampler states, optional depth/rendered
   buffers, and deterministic fallback.

5. Complete object row coverage.
   Hair, STBB, skin, and helper variants must be handled or explicitly logged as
   vanilla fallback. Complete object PBR cannot be claimed until this table is
   closed.

6. Port full NVR terrain PBR.
   This includes `LandHeight`, terrain parallax constants, height-blend weights,
   parallax shadows, terrain fade, and coherent LOD/fade/close terrain behavior.

7. Add WetWorld-equivalent state.
   Rain/night-rain profiles should stay documented as inactive until this exists.

8. Update config and README documentation after the contract table is true.

## Bottom Line

Current OMV PBR is a partial native shader replacement implementation. It is not
yet an NVR-equivalent PBR port. The biggest wrong implemented parts are terrain
identity, terrain point-light fallback, missing `LandHeight`/parallax terrain
contract, incomplete object row coverage, and lack of NVR's `SetCT`-style
resource/constant binding layer.

Do not continue by tweaking shader math. The next implementation work must close
the row/pass/resource/constant contract.

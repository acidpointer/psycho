# NVR Reference Contract

This document is the working source of truth for porting New Vegas Reloaded
features into OMV. It is based on the local reference source trees:

- `.research/TESReloaded10-master`
- `.research/fnv-vanilla-plus-terrain-main`
- `.research/Fallout-Shader-Loader-main`
- `docs/graphics_fnv_pbr_errata.md`

The goal is not to describe what a shader appears to do in isolation. The goal is
to document the engine-side contract that makes NVR features work: shader object
ownership, replacement timing, render stages, constant registers, sampler
registers, resource lifetime, effect ordering, feature dependencies, and failure
modes. A port that does not reproduce these contracts is not an NVR port; it is a
guess.

## Status And Rules

### Source tiers

Use this priority order when implementing or debugging OMV graphics features:

1. NVR source and VPT source in `.research/`.
2. Current OMV runtime logs and telemetry.
3. Ghidra output in `analysis/ghidra/output/` when the FNV engine contract is not
   exposed by source.
4. New Ghidra scripts when existing output does not prove a required engine fact.

Do not replace missing engine facts with shader tweaks. The PBR errata remains
binding: close terrain, helper rows, projected-shadow rows, LandO, land LOD, and
terrain fade must be proven as separate draw contracts before they are merged or
enabled broadly.

### What is proven by NVR source

NVR proves a complete graphics framework contract:

- It is an NVSE plugin, not a passive shader pack.
- It hooks shader creation and shader pass setup.
- It attaches replacement shader records to the game's own `NiD3DVertexShader`
  and `NiD3DPixelShader` objects.
- It compiles and caches replacement shaders and effects.
- It owns global `TESR_*` constants and texture records.
- It tracks game state every frame and updates constants from camera, weather,
  cell state, water state, lights, and settings.
- It owns pre-tonemap and post-tonemap fullscreen effect stages.
- It resolves depth buffers and copies current render targets on demand when a
  shader declares `TESR_DepthBuffer` or `TESR_RenderedBuffer`.
- It uses VPT and LOD Flicker Fix as hard requirements in the current New Vegas
  build.

### What NVR source does not prove for OMV

NVR source does not prove that OMV's current hooks see the same abstraction
level. In particular, if OMV hooks raw Direct3D `SetPixelShader` or
`SetVertexShader`, that is lower level than NVR's contract. NVR replaces handles
inside the game shader object before the game's pass setup call completes. OMV
must prove that it can identify the same pass and shader object identity before
claiming equivalence.

For close terrain, VPT/NVR prove the intended shader rows and constants. They do
not remove the need to prove, in OMV, that a runtime draw is the true close
landscape pass and not a helper, LandO, projected-shadow, SI, zero-resource,
point-light, land LOD, or terrain fade pass.

## Boot Contract

### Plugin load

Source: `.research/TESReloaded10-master/NewVegasReloaded/Main.cpp`.

NVR loads as an NVSE plugin named `NewVegasReloaded`. During `NVSEPlugin_Load`:

- It initializes logging to `NewVegasReloaded.log`.
- It creates a version string.
- It initializes the command manager.
- In game mode, it registers two message listeners:
  - sender `NVSE` -> `MessageHandler`
  - sender `Shader Loader` -> `ShaderLoaderHandler`
- It initializes the setting manager.
- It loads settings.
- It attaches game and renderer hooks.

The current New Vegas NVR build does not use the optional Direct3D device hook by
default. `HookDevice` is defined as `0`.

### Hard dependencies

On `kMessage_PostLoad`, NVR requires:

- `LODFlickerFix.dll`
- `VanillaPlusTerrain.dll`

If either DLL is missing, NVR shows a message box and calls `ExitProcess(0)`.
This is not a soft integration in the reference build.

### Optional integrations

On `kMessage_DeferredInit`, NVR checks for optional plugins:

- `johnnyguitar.dll`
  - If present, it resolves `JGSetViewmodelClipDistance` and
    `JGGetViewmodelClipDistance`.
  - `CombineDepth` uses the JohnnyGuitar clip distance when available.
- `VanillaPlusAO.dll`
  - If present, NVR marks its own Ambient Occlusion as suppressed.
- `RealTimeMenus.dll`
  - If present, NVR resolves `IsLiveMenu` for menu/render behavior.

NVR also calls `ShadowLightShader::EnableEyePositionForAllPasses()` at deferred
init. VPT uses this to ensure SLS vertex shaders receive `EyePosition`, including
terrain passes that need view direction.

### Shader Loader integration

NVR listens to sender `Shader Loader`. Message type `0` means shader refresh.
When received, NVR:

- calls `ShadowLightShader::EnableEyePositionForAllPasses()`;
- queues effect reload by setting `TheShaderManager->EffectReloadQueued = true`.

The actual reload happens at end frame in
`NiDX9Renderer__Do_EndFrame`, after the vanilla end-frame call.

Shader Loader has a relevant NVR compatibility path: when NVR is present,
Shader Loader-created `NiD3D*Shader` objects set `bEnabled = true` and
`pShaderHandleBackup = pShader`. This is compatible with NVR's replacement model
because NVR expects every wrapped shader object to retain the original handle.

## Hook Contract

Source:

- `.research/TESReloaded10-master/src/NewVegas/Hooks/Hooks.cpp`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Render.cpp`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/ShaderIO.cpp`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Shaders.cpp`

NVR attaches hooks for:

- settings load/write behavior;
- main/game object creation;
- renderer initialization;
- shader creation;
- shader package selection;
- main render;
- image-space processing;
- world scene graph render;
- first-person render;
- shader pass setup;
- sampler state;
- water height and water reflections;
- Pip-Boy state;
- detector window;
- form loading;
- flycam;
- end-frame reload.

The contract is not "set a shader whenever Direct3D sees a shader." The contract
is "modify the game shader object and let the game pass system bind that object."

### Shader creation hook

When the game creates a vertex or pixel shader, NVR:

- stores the vanilla shader handle in `ShaderHandleBackup`;
- records the shader name;
- remaps two water noise shader names:
  - `ISNOISESCROLLANDBLEND.vso` -> `WATERHEIGHTMAP0.vso`
  - `ISNOISENORMALMAP.vso` -> `WATERHEIGHTMAP1.vso`
  - equivalent pixel shader names for water heightmap replacement;
- calls `TheShaderManager->LoadShader(...)` to attach replacement records.

NVR also forces shader package `7` in the shader package hook. This matters
because source shader names and rows depend on the selected package.

### Pass setup hook

In `SetShadersHook`, NVR obtains the current geometry/pass from fixed engine
globals, then calls:

- `VertexShader->SetupShader(currentVS)`
- `PixelShader->SetupShader(currentPS)`

After those calls, it calls the original pass setup.

This timing matters. `SetupShader` changes the shader object's handle before
vanilla setup uses it. Constants are uploaded only if the current Direct3D handle
differs from the replacement handle. Therefore, the replacement record is tied to
the pass identity and to the game shader object, not only to the raw Direct3D
shader pointer.

### Render hook ordering

In the main render hook NVR:

1. Updates frame-rate state.
2. Updates camera scene graph pointers.
3. Updates camera matrices.
4. Updates shader constants.
5. Calls vanilla render.

World and viewmodel depth are captured at scene boundaries:

- After world scene graph render, NVR resolves world depth unless Pip-Boy special
  cases are active.
- Before first-person render, NVR clears the z-buffer.
- After first-person render, NVR resolves viewmodel depth.

Water reflections temporarily disable exterior shadow data and terrain parallax,
then restore them after the reflection render.

Image-space processing wraps the vanilla image-space call:

- Before vanilla image-space, NVR may run the pre-tonemap pipeline.
- After final vanilla output, NVR runs pre-tonemap if it was not already run, then
  runs post-tonemap effects and screenshot handling.

This is why the effect stack cannot be treated as a post-render overlay. It is
interleaved with vanilla image-space.

## Manager Initialization Contract

Source:

- `.research/TESReloaded10-master/src/core/Managers.cpp`
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp`
- `.research/TESReloaded10-master/src/core/TextureManager.cpp`
- `.research/TESReloaded10-master/src/core/RenderManager.cpp`

NVR initializes managers in a fixed order:

1. Texture manager.
2. Shader manager.
3. Frame-rate manager.
4. Game menu manager.
5. Game event manager.
6. Shadow manager.
7. Camera manager.
8. Bink manager.

This order is important:

- Shader manager registers effects and shader collections.
- Effects register textures through the texture manager.
- Shadow manager loads its own shadow-map shaders after shader manager exists.
- Render manager owns camera matrices and depth resolve support used by shader
  constants and effects.

## Settings Contract

Source:

- `.research/TESReloaded10-master/resource/NewVegasReloaded.dll.defaults.toml`
- `.research/TESReloaded10-master/src/core/SettingManager.cpp`
- `.research/TESReloaded10-master/src/core/GameMenuManager.cpp`
- `.research/TESReloaded10-master/src/core/ShaderCollection.cpp`
- `.research/TESReloaded10-master/src/core/EffectRecord.cpp`

NVR settings are schema-driven. The defaults TOML is not just defaults; it is the
schema used to build menu nodes and to infer value types. User config is loaded
as an override. Missing user entries are filled from defaults.

Feature enablement uses:

- `Shaders.<Name>.Status.Enabled`

`SettingManager::GetMenuShaderEnabled(Name)` checks this path. If the section is
absent from both user config and defaults, the feature defaults to enabled.
`ShaderCollection` and `EffectRecord` use this call when determining whether a
shader collection or effect should be active.

Changing `Shaders.<Name>.Status.Enabled` from the menu calls
`TheShaderManager->SwitchShaderStatus(Name)`, unless the feature is forced. This
updates both the stored setting and the enabled flags on existing shader/effect
records.

Important main settings:

- `Main.Main.Misc.RenderEffects`
  - Global gate for replacement shader/effect behavior.
- `Main.Main.Misc.RenderPreTonemapping`
  - Controls whether pre-tonemap effects run before vanilla image-space.
- `Main.Main.Misc.ForceMSAA`, `ForceReflections`, `RemovePrecipitations`, etc.
  - Render-system behavior gates.

NVR uses day/night/interior transition values through
`ShaderManager::GetTransitionValue(Day, Night, Interior)`.

- Exterior: linear interpolation from night to day by the current transition
  curve.
- Interior: returns the interior value.

Rain-dependent effects generally lerp again using rain/puddle animator values.

## Shader Collection Contract

Source:

- `.research/TESReloaded10-master/src/core/ShaderCollection.h`
- `.research/TESReloaded10-master/src/core/ShaderCollection.cpp`
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp`
- `.research/TESReloaded10-master/src/core/ShaderRecord.cpp`
- `.research/TESReloaded10-master/src/core/ShaderTemplate.h`

### Collection selection

NVR maps shader names to collections:

- `WATER*` -> Water
- `GRASS*` -> Grass
- `ISHDR*` or `HDR*` -> Tonemapping
- `PAR*` -> POM
- `SKY*` -> Sky
- blood shader name -> Blood
- object SLS names present in `PBRShaders::Templates()` -> PBR
- terrain SLS names present in `TerrainShaders::Templates()` -> Terrain

Skin exists as a collection but is disabled in `GetShaderCollection` in the
current source path.

### Replacement records

When a game shader object belongs to a collection, NVR tries to load up to three
replacement records:

- default path;
- `Exteriors\` path;
- `Interiors\` path.

Selection at pass setup:

1. If exterior replacement exists and `Player->GetWorldSpace()` is true, use it.
2. Else if interior replacement exists and `Player->GetWorldSpace()` is false,
   use it.
3. Else if default replacement exists, use it.
4. Else use the vanilla backup handle.

The exterior/interior decision uses worldspace, not only `cell->IsInterior()`.
For New Vegas, this matches the NVR source contract. A port may need extra proof
if it uses a different exterior detector.

### Shader template compilation

Templates are named HLSL files with preprocessor defines. For example,
`SLS2146.pso` can compile from `TerrainTemplate.hlsl` with `PS`, `TEX_COUNT=7`,
and `NUM_PT_LIGHTS=24`.

NVR compiles shaders as:

- vertex: `vs_3_0`;
- pixel: `ps_3_0`.

It preprocesses first, compares the preprocessed source against a cached
preprocessed file, and recompiles only when the preprocessed source changed or
compiled output is absent. It passes `REVERSED_DEPTH` as a macro if the render
manager detects reversed depth.

Compiled shader caches live under:

- `data/Shaders/NewVegasReloaded/Shaders/Cache/...`

Effect caches live under:

- `data/Shaders/NewVegasReloaded/Effects/Cache`

### Constant table contract

Only constants with the `TESR_` prefix are handled by NVR's shader/effect
constant table code.

For shader replacements:

- Float/vector/matrix constants store register index and register count.
- If the constant name exists in `ShaderManager::ConstantsTable`, the record
  stores a pointer to that global data.
- Unknown `TESR_*` constants become custom zero-initialized constants and are
  logged.
- Samplers store register index, texture source, and sampler states.

The sampler parser expects shader source declarations with a discoverable
`register ( sX )` pattern and optional `ResourceName`.

Important hidden behavior:

- If a shader declares `TESR_DepthBuffer`, `ShaderRecord::CreateCT` marks
  `HasDepthBuffer`.
- If a shader declares `TESR_RenderedBuffer`, it marks `HasRenderedBuffer`.
- During `SetCT`, `HasRenderedBuffer` copies current render target 0 into
  `TESR_RenderedBuffer`.
- During `SetCT`, `HasDepthBuffer` resolves the depth buffer into
  `TESR_DepthBuffer`.

This is automatic resource ownership. If OMV compiles a shader but does not
reproduce this side effect, the shader ABI is incomplete.

### Sampler clearing

Pixel shader replacement records use `ClearSamplers = true`. Vertex shader
records use `ClearSamplers = false`.

On pixel `SetCT`, NVR clears texture slots `0..15` before binding declared
samplers. This prevents stale samplers from previous pass variants.

Shadow-map generation shaders explicitly override this and set
`ClearSamplers = false` for all shadow generation records because clearing
samplers breaks those passes.

### State upload risk

NVR uploads replacement constants only when the current Direct3D shader handle is
different from the replacement handle. This is efficient, but it means the
replacement model assumes shader handle identity maps cleanly to a pass state.

For OMV, a raw Direct3D hook must be careful: if it binds a replacement shader
without the same object/pass model, constants or samplers can remain stale across
draws. This is one plausible source class for distance/angle lighting blinking.

## Texture And Buffer Contract

Source:

- `.research/TESReloaded10-master/src/core/TextureManager.cpp`
- `.research/TESReloaded10-master/src/core/TextureRecord.cpp`
- `.research/TESReloaded10-master/src/core/RenderManager.cpp`

### Global render buffers

Texture manager creates and registers:

- `TESR_SourceBuffer`
  - HDR render target copy.
- `TESR_RenderedBuffer`
  - HDR render target copy, usually previous stage/current output.
- `TESR_DepthBufferWorld`
  - INTZ depth texture for world render.
- `TESR_DepthBufferViewModel`
  - INTZ depth texture for first-person render.

Effects can also create and register named buffers:

- `TESR_DepthBuffer`
  - Combined depth result from `CombineDepth`.
- `TESR_NormalsBuffer`
  - Normal reconstruction output.
- `TESR_BloomBuffer`, `TESR_BloomBuffer2`, etc.
- `TESR_AvgLumaBuffer`
- `TESR_ShadowAtlas`
- `TESR_PointShadowBuffer`
- `TESR_OrthoMapBuffer`
- point shadow cubemaps and spotlight maps.

### Depth resolve

NVR supports two depth resolve paths:

- RESZ path for AMD/Intel/DXVK.
- NvAPI path for NVIDIA.

The RESZ path backs up FVF, declaration, textures, shaders, stream, and render
states, draws a dummy point with `D3DRS_POINTSIZE = RESZ_CODE`, then restores the
state. This is not a trivial texture copy. It is part of the engine contract for
any effect that reads depth.

### Fullscreen vertex contract

NVR creates a frame quad vertex buffer with:

- `FrameFVF = D3DFVF_XYZ | D3DFVF_TEX1`
- four vertices rendered as `D3DPT_TRIANGLESTRIP`
- UVs include a half-texel offset based on current render target size.

Bloom creates additional frame vertex buffers for each downsampled resolution.

## Global Constant Contract

Source: `.research/TESReloaded10-master/src/core/ShaderManager.cpp`.

NVR registers these common `TESR_*` constants:

- Matrices:
  - `TESR_WorldTransform`
  - `TESR_ViewTransform`
  - `TESR_InvViewTransform`
  - `TESR_ProjectionTransform`
  - `TESR_InvProjectionTransform`
  - `TESR_WorldViewProjectionTransform`
  - `TESR_InvViewProjectionTransform`
  - `TESR_ViewProjectionTransform`
  - `TESR_OcclusionWorldViewProjTransform`
- Dynamic lights:
  - `TESR_LightPosition`
  - `TESR_LightColor`
  - `TESR_SpotLightPosition`
  - `TESR_SpotLightColor`
  - `TESR_SpotLightDirection`
  - `TESR_SpotLightToWorldTransform`
- Sun and camera:
  - `TESR_ViewSpaceLightDir`
  - `TESR_ScreenSpaceLightDir`
  - `TESR_ReciprocalResolution`
  - `TESR_CameraForward`
  - `TESR_DepthConstants`
  - `TESR_CameraData`
  - `TESR_CameraPosition`
  - `TESR_SunDirection`
  - `TESR_SunPosition`
  - `TESR_SunTiming`
  - `TESR_SunAmount`
  - `TESR_GameTime`
- Fog, weather, sky:
  - `TESR_FogData`
  - `TESR_FogDistance`
  - `TESR_FogColor`
  - `TESR_SunColor`
  - `TESR_SunDiskColor`
  - `TESR_SunAmbient`
  - `TESR_SkyColor`
  - `TESR_SkyLowColor`
  - `TESR_HorizonColor`

Each effect and shader collection registers additional constants. The important
point is that HLSL `TESR_*` names are not free variables. They must map to live
native storage, or they silently become zero-initialized custom constants.

## Game State Contract

Source: `.research/TESReloaded10-master/src/core/ShaderManager.cpp`.

`ShaderManager::UpdateConstants` gathers:

- current cell and worldspace;
- whether the player is exterior;
- whether the cell changed;
- underwater state;
- rain/snow state;
- dialogue/VATS/Pip-Boy/overlay state;
- current weather;
- game time and day/night transition;
- sun direction, sun position, sun amount, fog, sky, horizon, ambient colors;
- camera forward and screen/view-space light directions.

Most features do not read game state directly. They read constants that were
derived here. A port should avoid scattering direct game-state reads in shader
specific code unless that is the proven NVR contract.

## Light Tracking Contract

Source: `.research/TESReloaded10-master/src/core/ShaderManager.cpp`.

NVR has two separate light systems:

1. Native object/terrain pass lights supplied by the game's shader pass system.
2. NVR fullscreen light/shadow tracking arrays used by shadows, WetWorld, and
   flashlight-related passes.

`ShaderManager::GetNearbyLights` enumerates `SceneNode->lights`, skips culled or
effectively black lights, rejects distant lights behind the camera unless the
player is within radius, sorts by distance, then fills:

- `ShadowLightsList`
- `LightsList`
- `SpotLightList`
- `TESR_LightPosition`
- `TESR_LightColor`
- `TESR_ShadowLightPosition`
- `TESR_SpotLightPosition`
- `TESR_SpotLightDirection`
- `TESR_SpotLightColor`

`GetNearbyLights` calls the flashlight effect's `UpdateConstants` so the
flashlight can appear as a tracked spotlight.

This light tracking is not the same as the PBR object shader's native pass light
constants. The object shader still depends on vanilla SLS pass registers such as
`LightData`, `PSLightColor`, and `PSLightPosition`.

## Effect Pipeline Contract

Source:

- `.research/TESReloaded10-master/src/core/EffectRecord.cpp`
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp`

### Effect compilation

Effects are `.fx.hlsl` files. NVR preprocesses and compiles them through D3DX
effect compiler APIs, caches preprocessed source and compiled output, then loads
an `ID3DXEffect`.

Effects use the same `TESR_*` constant and sampler parsing rule:

- only `TESR_*` constants are tracked;
- effect constants bind through D3DX handles;
- sampler states are parsed from source;
- file textures with `ResourceName` load from `Data\Textures\...`.

### Effect rendering

`EffectRecord::Render`:

1. Checks `Enabled` and `ShouldRender`.
2. Optionally copies current render target to `SourceBuffer`.
3. Sets the technique.
4. Calls `SetCT`.
5. Begins the effect.
6. For each pass:
   - optionally clears target;
   - begins pass;
   - draws the fullscreen triangle strip;
   - ends pass;
   - copies pass output to `RenderedSurface`.
7. Ends effect.

Effects therefore chain through `SourceBuffer` and `RenderedBuffer`. The contract
is not simply "draw pass N"; each pass may depend on the previous pass having
been copied to `TESR_RenderedBuffer`.

### Pre-tonemap order

`ShaderManager::RenderEffectsPreTonemapping` order:

1. `CombineDepth` -> creates combined `TESR_DepthBuffer`.
2. `Normals` -> creates `TESR_NormalsBuffer`.
3. If shadows are active:
   - `ShadowManager::RenderShadowMaps`
   - `PointShadows`
   - `PointShadows2` if more than six lights
   - `SunShadows` if exterior
4. Copy current render target to `RenderedSurface` and `SourceSurface`.
5. `ShadowsExteriors` or `ShadowsInteriors`.
6. `SnowAccumulation`.
7. `AmbientOcclusion`.
8. `WetWorld`.
9. `Flashlight`.
10. `Specular`.
11. `Underwater`.
12. `VolumetricFog`.
13. `GodRays`.
14. `AvgLuma` if required.
15. `Exposure`.
16. Bloom buffer generation.
17. `Lens`.

### Post-tonemap order

`ShaderManager::RenderEffects` order:

1. `Rain`
2. `Snow`
3. `BloomLegacy`
4. `Coloring`
5. `DepthOfField`
6. `MotionBlur`
7. `BloodLens`
8. `WaterLens`
9. `LowHF`
10. `SMAA`
11. `Sharpening`
12. `Cinema`
13. `ImageAdjust`
14. `Debug`

Any port that changes ordering changes the feature contract.

## Object PBR Contract

Source:

- `.research/TESReloaded10-master/src/effects/PBR.h`
- `.research/TESReloaded10-master/src/effects/PBR.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Object.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/PBR.hlsl`

### Collection coverage

NVR object PBR is a matrix of SLS shader rows. It is not only one base object
shader.

The vertex side covers:

- base SLS rows;
- skinned variants;
- projected-shadow variants;
- two-light variants;
- four-light and nine-light variants;
- optimized variants;
- specular variants;
- `ONLY_LIGHT` helper variants;
- `DIFFUSE` helper variants;
- `ONLY_SPECULAR` helper variants;
- point helper variants.

The pixel side covers:

- base and optimized rows;
- LOD rows;
- SI rows;
- projected-shadow rows;
- STBB and hair rows;
- two/four/nine-light rows;
- specular rows;
- `ONLY_LIGHT` helper rows;
- `DIFFUSE` helper rows;
- `ONLY_SPECULAR` helper rows;
- point helper rows.

If OMV replaces only the base object pixel shader family, it does not implement
NVR object PBR. Missing helper rows are especially dangerous because those rows
carry different alpha, fog, sampler, and light semantics.

### Object PBR constants

NVR registers:

- `TESR_PBRData` -> register `c32` in `Object.hlsl`
- `TESR_PBRExtraData` -> register `c33`

Meaning:

- `TESR_PBRData.x`: global metallicness setting.
- `TESR_PBRData.y`: roughness scale.
- `TESR_PBRData.z`: lighting scale.
- `TESR_PBRData.w`: ambient scale.
- `TESR_PBRExtraData.x`: albedo saturation.

Important source quirk: `Object.hlsl` passes metallicness `0` to the PBR BRDF
helpers. The object metallicness setting exists in constants, but the current
object helper functions do not use it as the BRDF metallic input. Terrain does.

### Object settings interpolation

PBR settings sections:

- `Shaders.PBR.Main`
- `Shaders.PBR.Rain`
- `Shaders.PBR.Night`
- `Shaders.PBR.NightRain`
- `Shaders.PBR.Interiors`

Each section has:

- `Saturation`
- `Metallicness`
- `Roughness`
- `LightingScale`
- `AmbientScale`

Update algorithm:

1. Compute `rainFactor = max(WetWorld.RainAmount, WetWorld.PuddleAmount)`.
2. Compute day/night/interior values through `GetTransitionValue`.
3. Lerp default/night/interior toward rain/night-rain/interior by `rainFactor`.
4. Write `TESR_PBRData` and `TESR_PBRExtraData`.

Known quirk: the final ambient rainy branch uses
`Settings.Default.AmbientScale` as the interior parameter for the rainy branch in
the current source. Preserve or explicitly decide not to preserve this quirk; do
not miss it accidentally.

### Object shader algorithm

The shared BRDF implements:

- Schlick Fresnel.
- Lambertian diffuse.
- GGX normal distribution.
- Schlick-Beckmann single-direction geometry term.
- Smith geometry term.
- `PBRDiffuse`
- `PBRSpecular`
- `PBR`
- `PBRSunSpecular`
- `PBRSun`
- geometric specular AA helper.

Object roughness:

- `getRoughness(gloss) = saturate(max(0.043, 1 - gloss) * TESR_PBRData.y)`

Object albedo:

- desaturates or preserves based on `TESR_PBRExtraData.x`.

Object light scale:

- point/sun light color is multiplied by `TESR_PBRData.z`.

Ambient:

- ambient contribution is multiplied by `TESR_PBRData.w`.

### Object variant semantics

Preprocessor defines change ABI:

- `DIFFUSE` implies `ONLY_LIGHT` and `OPT`.
- `ONLY_SPECULAR` implies `ONLY_LIGHT` and `SPECULAR`.
- `ONLY_LIGHT` implies `NO_FOG` and `NO_VERTEX_COLOR`.

Sampler layouts differ by variant:

- Normal rows use `BaseMap s0`, `NormalMap s1`.
- `DIFFUSE` and `ONLY_SPECULAR` rows use `NormalMap s0` and no base map.
- Glow map slots differ for SI, hair, and only-light variants.
- Projected shadow sampler slots differ:
  - `ONLY_SPECULAR`: `ShadowMap s4`, `ShadowMaskMap s5`
  - `ONLY_LIGHT`: `ShadowMap s5`, `ShadowMaskMap s6`
  - normal rows: `ShadowMap s6`, `ShadowMaskMap s7`

Alpha semantics differ:

- `DIFFUSE`: alpha = 1.
- `ONLY_SPECULAR`: alpha = luminance/weight of final color.
- `ONLY_LIGHT`: alpha = base alpha.
- normal rows: alpha = base alpha * ambient alpha.

Fog is disabled for `ONLY_LIGHT` families. Vertex color is also disabled for
those families.

This is a direct explanation for "some objects are vanilla" and "point lights
are destroyed" symptoms in a partial port. The helper rows are part of the
lighting composition, not optional polish.

## Terrain And VPT Contract

Source:

- `.research/TESReloaded10-master/src/effects/Terrain.h`
- `.research/TESReloaded10-master/src/effects/Terrain.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainLODTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainFadeTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Terrain.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Parallax.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainLODTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainFadeTemplate.hlsl`

### Dependency truth

NVR requires VPT because VPT supplies the terrain pass and constant map contract
that NVR terrain shaders consume.

VPT injects `BSShaderPPLightingProperty::AddPass_Landscape` and creates close
landscape pass numbers:

- no point lights:
  - `pass = 8 * usPassCount + 503`
  - canopy shadows add `+1`
- with point lights:
  - `pass = 8 * usPassCount + 505`
  - canopy shadows add `+1`
  - more than 6 point lights add `+2`
  - more than 12 point lights add another `+2`
- close-to-LOD blend pass:
  - row `560`
  - `cCurrLandTexture = 9`

VPT caps close land pass count to seven.

VPT also sets SLS vertex constant flags so land pass rows receive
`EyePosition`.

### VPT terrain constants

VPT adds pixel constant map entries:

- `LandSpec` -> register `c32`, count 2.
- `LandHeight` -> register `c34`, count 2.
- `StandardFogParams` -> register `c36`, count 1.
- `StandardFogColor` -> register `c37`, count 1.
- `LandLODSpec` -> register `c38`, count 1.
- `PointlightColors` -> register `c39`, up to 24.
- `PointlightPositions` -> register `c63`, up to 24.
- `PointlightCount` -> register `c88`, count 1.

VPT enables/disables those constant entries based on render pass type:

- row `254`: land LOD spec.
- rows `503..558`: close landscape.
- row `560`: land-to-LOD fade.

For close landscape, VPT fills:

- `LandSpec`: per-layer specular availability times exponent.
- `LandHeight`: per-layer diffuse alpha availability.
- `PointlightColors`: per-point-light color and fade.
- `PointlightPositions`: transformed point-light position and radius.
- `PointlightCount`: number of active point lights.

Without this constant map, NVR terrain PBR is not complete.

### NVR terrain collection coverage

NVR terrain shader collection covers three separate contracts:

1. Close terrain:
   - vertex `SLS2100.vso`
   - pixels `SLS2092..SLS2146.pso`
   - `TEX_COUNT = 1..7`
   - optional `NUM_PT_LIGHTS = 6, 12, 24`
2. Terrain LOD:
   - vertex `SLS2002.vso`
   - pixel `SLS2003.pso`
3. Terrain fade:
   - vertex `SLS2080.vso`
   - pixel `SLS2082.pso`

These are not variants of the same ABI. They have different samplers, constants,
vertex inputs, and semantics.

### Close terrain shader ABI

Vertex input:

- `POSITION`
- `TANGENT`
- `BINORMAL`
- `NORMAL`
- `TEXCOORD0` UV
- `COLOR0` vertex color
- `TEXCOORD1` blend channel 0
- `TEXCOORD2` blend channel 1

Pixel samplers:

- `BaseMap[7]` at `s0..s6`
- `NormalMap[7]` at `s7..s13`

Pixel constants:

- `AmbientColor c1`
- `SunColor c3`
- `SunDir c18`
- `LandSpec[2] c32`
- `LandHeight[2] c34`
- `FogParam c36`
- `FogColor c37`
- optional `PointLightColor[NUM_PT_LIGHTS] c39`
- optional `PointLightPosition[NUM_PT_LIGHTS] c63`
- optional `PointLightCount c88`
- NVR terrain controls:
  - `TESR_TerrainData c89`
  - `TESR_TerrainExtraData c90`
  - `TESR_TerrainParallaxData c91`
  - `TESR_TerrainParallaxExtraData c92`

Algorithm:

1. Build TBN from terrain vertex tangent/binormal/normal.
2. Calculate eye direction in tangent space.
3. Read layer blend weights from `blend_0` and `blend_1`.
4. Read per-layer spec exponent/status from `LandSpec`.
5. Read per-layer height availability from `LandHeight`.
6. Optionally compute parallax coordinates and updated blend weights.
7. Blend diffuse maps from active layers.
8. Blend normal maps from active layers.
9. Compute gloss and spec exponent from normal alpha and `LandSpec`.
10. Compute sun lighting with optional parallax self-shadow multiplier.
11. If point-light variant, loop `PointLightCount`.
12. Apply per-pixel fog.

`TEX_COUNT` must match active layers. Sampling all seven layers unconditionally is
both slower and not the proven row contract.

### Terrain PBR constants

NVR registers:

- `TESR_TerrainData`
- `TESR_TerrainExtraData`
- `TESR_TerrainParallaxData`
- `TESR_TerrainParallaxExtraData`

Meanings:

- `TESR_TerrainExtraData.x`: use PBR boolean.
- `TESR_TerrainExtraData.y`: terrain saturation.
- `TESR_TerrainExtraData.z`: LOD noise scale.
- `TESR_TerrainExtraData.w`: LOD noise tile.
- `TESR_TerrainData.x`: terrain metallicness.
- `TESR_TerrainData.y`: terrain roughness scale.
- `TESR_TerrainData.z`: terrain lighting scale.
- `TESR_TerrainData.w`: terrain ambient scale.
- `TESR_TerrainParallaxData.x`: parallax enabled.
- `TESR_TerrainParallaxData.y`: parallax shadows enabled.
- `TESR_TerrainParallaxData.z`: height blend enabled.
- `TESR_TerrainParallaxData.w`: high quality enabled.
- `TESR_TerrainParallaxExtraData.x`: max distance.
- `TESR_TerrainParallaxExtraData.y`: height.
- `TESR_TerrainParallaxExtraData.z`: self-shadow intensity.

Important: `TerrainShaders::UpdateConstants` returns immediately if game state
is not exterior. NVR terrain PBR is exterior-only in the current source. Interior
terrain PBR would be invented behavior unless separately proven.

### Terrain PBR algorithm

The terrain include chooses between vanilla and PBR per pixel:

- If `TESR_TerrainExtraData.x` is true:
  - point lights use `PBR(...)` with metallicness from terrain data;
  - sun uses `PBRSun(...)` with metallicness from terrain data;
  - roughness is `(1 - gloss) * TESR_TerrainData.y`;
  - light color is scaled by `TESR_TerrainData.z`;
  - ambient is scaled by `TESR_TerrainData.w`.
- If false:
  - terrain uses vanilla lighting helpers.

Terrain PBR does use metallicness. This differs from object PBR.

### Terrain parallax contract

Terrain parallax is part of the terrain contract, not a separate optional shader
guess.

The terrain parallax function:

- uses per-layer blend weights;
- uses diffuse alpha availability from `LandHeight`;
- supports height blending;
- uses 8 or 16 steps depending on high-quality setting;
- fades by distance;
- modifies `viewDir.z` to reduce angle artifacts;
- uses `[loop][fastopt]` because compile times are otherwise excessive;
- performs contact refinement;
- returns adjusted UVs and updated blend weights.

Terrain parallax self-shadow:

- samples terrain heights along light direction;
- quality fades with distance;
- multiplies sunlight contribution.

### Terrain LOD contract

Terrain LOD shaders are separate:

- vertex `SLS2002.vso`
- pixel `SLS2003.pso`

Samplers:

- `BaseMap s0`
- `NormalMap s1`
- `LODParentTex s4`
- `LODParentNormals s6`
- `LODLandNoise s7`

Constants:

- `ModelViewProj c0`
- `ObjToCubeSpace c8`
- `HighDetailRange c12`
- `FogParam c14`
- `FogColor c15`
- `EyePosition c16`
- `GeomorphParams c19`
- `LightData c25`
- `AmbientColor c1`
- `PSLightColor c3`
- `LODTexParams c31`
- `LandLODSpec c38`
- NVR terrain LOD noise from `TESR_TerrainExtraData.zw`.

Algorithm:

- morphs/fades terrain LOD;
- blends parent normal/color;
- applies LOD noise;
- uses terrain lighting helper;
- applies fog.

Do not reuse the close terrain shader for this path.

### Terrain fade contract

Terrain fade shaders are separate:

- vertex `SLS2080.vso`
- pixel `SLS2082.pso`

Samplers:

- `BaseMap s0`
- `NormalMap s1`
- `LODLandNoise s2`

Constants:

- `ModelViewProj c0`
- `FogParam c14`
- `FogColor c15`
- `EyePosition c16`
- `LandBlendParams c19`
- `LightData c25`
- `AmbientColor c1`
- `PSLightColor c3`
- `LandLODSpec c38`

Algorithm:

- computes alpha blend from distance to the land blend vector;
- samples base/normal/noise;
- applies directional terrain lighting;
- applies fog;
- outputs alpha as blend.

Do not hide missing terrain fade by replacing close terrain only. That creates
visible chunks and distance-based blinking.

## POM Contract

Source:

- `.research/TESReloaded10-master/src/effects/POM.h`
- `.research/TESReloaded10-master/src/effects/POM.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ParallaxTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Parallax.hlsl`

POM is a shader collection for `PAR*` rows. It covers base, projected shadow,
multi-light, specular, AD, diffuse, no-light, only-specular, and point helper
variants.

POM registers:

- `TESR_ParallaxData` at `c35`

Meanings:

- `.x`: height map scale from `Shaders.POM.Main.HeightMapScale`
- `.y`: `Shaders.PBR.Status.Enabled`

This means POM lighting changes based on the PBR enable state. POM is not
independent from PBR. If PBR is enabled, parallax object shaders use PBR object
lighting helpers; otherwise they use vanilla lighting helpers.

POM sampler layouts vary heavily by variant: base map, normal map, height map,
glow map, attenuation maps, projected shadow maps, and shadow mask maps move
between slots depending on defines. A port must preserve variant-specific ABI.

## Shadow Contract

Source:

- `.research/TESReloaded10-master/src/core/ShadowManager.cpp`
- `.research/TESReloaded10-master/src/core/RenderPass.cpp`
- `.research/TESReloaded10-master/src/effects/ShadowsExterior.*`
- `.research/TESReloaded10-master/src/effects/ShadowsInteriors.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/SunShadows.fx.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/PointShadows.fx.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/ShadowsExteriors.fx.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/ShadowsInteriors.fx.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Includes/Shadows.hlsl`

### Shadow manager ownership

NVR shadows are a native render subsystem:

- It creates shadow render passes for:
  - normal geometry;
  - alpha geometry;
  - skinned geometry;
  - speedtree;
  - terrain LOD.
- It loads shadow-map generation shaders:
  - `ShadowMap.vso`
  - `ShadowMap.pso`
  - `ShadowCubeMap.vso`
  - `ShadowCubeMap.pso`
  - `ShadowMapBlur.vso`
  - `ShadowMapBlur.pso`
  - `ShadowMapClear.pso`
- It accumulates scene geometry into render-pass stacks.
- It renders cascaded sun/moon maps, point-light cubemaps, optional spotlight
  maps, and an ortho height/depth map for wet/snow effects.

This is independent of object PBR. PBR shaders are not expected to generate
shadow maps.

### Shadow geometry filters

NVR skips:

- refs with no node;
- refs flagged `NotCastShadows`;
- land in normal ref path because land is handled separately;
- form types disabled by shadow settings;
- highly refractive refs;
- shader properties with refraction, fire refraction, decal, or dynamic decal
  flags;
- culled nodes;
- too-small nodes based on minimum radius;
- fade nodes below alpha threshold.

Point-light cubemap rendering also skips first-person geometry and uses settings
to decide whether first/third-person player geometry casts shadows.

### Exterior shadow maps

Exterior shadows use a 2x2 atlas:

- near cascade;
- middle cascade;
- far cascade;
- LOD cascade.

NVR computes cascade depths with lambda distribution, builds stable cascade
matrices, quantizes/smooths sun direction to reduce shimmer, snaps to texels, and
limits LOD cascade update frequency with camera-translation compensation.

Supported shadow formats:

- VSM
- EVSM2
- EVSM4

Some modes need custom clear colors. Optional prefilter blur uses two-pass
Gaussian blur over the atlas.

### Ortho map

WetWorld and Snow/SnowAccumulation set `orthoRequired`. When true, NVR renders an
orthographic map even if normal exterior shadow maps are not required.

This map is consumed by WetWorld for puddle placement and by snow-related
effects. If OMV ports WetWorld or snow without this map, it is missing a core
resource.

### Point light shadows

NVR tracks up to configured point lights, renders cubemaps for the selected
shadow-casting point lights, then composites point light contribution in
fullscreen passes.

`PointShadows.fx.hlsl`:

- reads `TESR_DepthBuffer`;
- reads `TESR_NormalsBuffer`;
- reads up to six shadow cubemaps in the first pass;
- uses `TESR_ShadowLightPosition`;
- uses `TESR_LightPosition`;
- uses `TESR_LightColor`;
- includes a flashlight spotlight contribution;
- writes a packed point-shadow/light buffer.

`PointShadows2` exists for more than six lights.

### Sun shadow composite

`SunShadows.fx.hlsl`:

- reads depth, shadow atlas, normals, point shadow buffer, and blue noise;
- reconstructs world position;
- can add screen-space shadows;
- samples cascade shadow maps;
- blends cascades;
- writes final sun shadow into the point-shadow buffer red channel while
  preserving point shadow data.

`SunShadowsEffect::SetCT` modifies sampler state for shadow atlas anisotropy
when configured.

### Exterior and interior shadow effects

`ShadowsExteriors.fx.hlsl`:

- reads `TESR_RenderedBuffer`, `TESR_DepthBuffer`, `TESR_PointShadowBuffer`, and
  `TESR_NormalsBuffer`;
- reconstructs world position and normal;
- skips underwater/special surface cases;
- combines sun and point shadow values;
- tints shadowed areas using sky/fog color logic.

`ShadowsInteriors.fx.hlsl`:

- reads `TESR_RenderedBuffer`, `TESR_SourceBuffer`, `TESR_DepthBuffer`, and
  `TESR_PointShadowBuffer`;
- performs depth-aware blur;
- combines blurred interior point shadowing with source color;
- fades by distance and darkness.

This subsystem directly affects the user's reported "rectangular shadow chunks"
and light blinking. If OMV applies PBR replacements but leaves shadow/resource
state stale or incomplete, the fullscreen shadow composite can change abruptly as
shader rows switch.

## Depth, Normals, AO Contract

### CombineDepth

Source:

- `.research/TESReloaded10-master/src/effects/CombineDepth.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/CombineDepth.fx.hlsl`

CombineDepth creates `TESR_DepthBuffer` as `D3DFMT_G32R32F`.

It combines:

- `TESR_DepthBufferWorld`
- `TESR_DepthBufferViewModel`

It converts projected depth to view-space depth, chooses viewmodel depth when a
viewmodel pixel exists, then outputs:

- channel x: combined view-space depth divided by far plane;
- channel y: projected depth reconstructed for the main camera;
- channels z/w: 1.

JohnnyGuitar can provide a custom viewmodel near clip distance.

### Normals

Source:

- `.research/TESReloaded10-master/src/effects/Normals.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Normals.fx.hlsl`

Normals creates `TESR_NormalsBuffer` as `D3DFMT_A16B16G16R16F`.

The shader reconstructs view-space normals from combined depth using a
depth-gradient method, then performs two depth-aware blur passes. Many later
effects depend on this buffer:

- AO;
- shadows;
- WetWorld;
- flashlight;
- volumetric effects.

### Ambient Occlusion

Source:

- `.research/TESReloaded10-master/src/effects/AmbientOcclusion.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/AmbientOcclusion.fx.hlsl`

AO registers:

- `TESR_AmbientOcclusionAOData`
- `TESR_AmbientOcclusionData`

Settings are split between exterior and interior sections. AO is suppressed if
VanillaPlusAO is loaded.

The shader:

- samples rendered color, depth, source color, blue noise, and normals;
- reconstructs positions;
- generates hemisphere samples around reconstructed normals;
- calculates occlusion;
- applies fog/luminance controls;
- performs depth/normal-aware blur;
- combines AO with the source color in linear space.

## Weather Surface Effects

### WetWorld

Source:

- `.research/TESReloaded10-master/src/effects/WetWorld.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/WetWorld.fx.hlsl`

WetWorld registers:

- `TESR_WetWorldCoeffs`
- `TESR_WetWorldData`

Update behavior:

- tracks rain start/stop with an animator;
- tracks puddle accumulation with a separate animator;
- writes:
  - `.x`: current rain amount;
  - `.y`: rainy boolean;
  - `.z`: puddle amount;
  - `.w`: configured amount/intensity;
- requests ortho map when rain or puddles are active.

Should render only when exterior and not underwater.

The shader:

- builds a puddle mask using the ortho map;
- blurs the puddle mask;
- reconstructs world position and world normals;
- skips water surfaces and viewmodel pixels;
- samples animated ripple texture;
- refracts source color;
- samples point shadow buffer;
- computes sky reflection/fresnel color;
- adds sun and point-light specular.

WetWorld feeds PBR settings because object and terrain PBR use
`max(rainAmount, puddleAmount)` as rain factor.

### Rain and snow

Rain registers:

- `TESR_RainData`
- `TESR_RainAspect`

Rain uses an animator and renders only when exterior, rainy, and not underwater.

Snow registers:

- `TESR_SnowData`

Snow fades in/out with an animator, clears puddles when snow starts, requests
ortho map, and renders only when exterior and not underwater.

SnowAccumulation registers:

- `TESR_SnowAccumulationParams`
- `TESR_SnowAccumulationColor`

It uses a separate accumulation animator, requests ortho map, and renders only
when exterior and not underwater.

## Flashlight Contract

Source:

- `.research/TESReloaded10-master/src/effects/Flashlight.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Flashlight.fx.hlsl`

Flashlight is a fullscreen lighting effect plus optional spotlight shadow map.

Native side:

- creates a `NiSpotLight`;
- detects Pip-Boy light state;
- optionally attaches to weapon or camera/head transform;
- culls the vanilla Pip-Boy light node when active;
- writes spotlight position, direction, color, radius, and view-projection
  matrix;
- can request shadow rendering through the shadow manager.

Shader side:

- can first render spotlight shadow result;
- can depth-blur that shadow result;
- computes spotlight diffuse/specular contribution from depth and normals;
- samples a flashlight texture;
- combines by adding modulated light to source color.

## Water Contract

Source:

- `.research/TESReloaded10-master/src/effects/Water.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/WATER*.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Water.hlsl`

Water is a shader collection, not a fullscreen-only effect. NVR replaces water
shader rows and also registers many water constants:

- `TESR_WaterDeepColor`
- `TESR_WaterShallowColor`
- `TESR_WaterLODColor`
- `TESR_WaterFog`
- `TESR_WaterCoefficients`
- `TESR_WaveParams`
- `TESR_WaterVolume`
- `TESR_WaterSettings`
- `TESR_WaterShorelineParams`
- placed-water equivalents.

NVR also registers texture pointers for water height and reflection maps.

Update behavior:

- reads current water height/form;
- sets underwater flag and water height;
- selects settings for default/interior/blood/lava water;
- scales caustics strength by sun glare.

During reflection rendering, NVR disables exterior shadows and terrain parallax
to avoid reflection artifacts, then restores them.

## Tonemapping, Exposure, Bloom, Lens Contract

### Tonemapping

Source:

- `.research/TESReloaded10-master/src/effects/Tonemapping.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ISHDR*.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Tonemapping.hlsl`

Tonemapping is a shader collection for HDR/ISHDR rows. It registers:

- `TESR_HDRBloomData`
- `TESR_HDRData`
- `TESR_LotteData`
- `TESR_ToneMapping`

Settings are split by main/night/interiors. Update is gated by settings changes
or day-time changes. Lotte tonemapping mode uses scaled constants.

### Exposure

Exposure registers:

- `TESR_ExposureData`

Update behavior:

- marks average-luma calculation as required;
- transitions min/max brightness and adaptation speeds across day/night/interior
  settings.

### AvgLuma

AvgLuma creates:

- `TESR_AvgLumaBuffer`

It is rendered only when another effect, such as Exposure, marks
`avglumaRequired`.

### Bloom

Bloom registers:

- `TESR_BloomData`
- `TESR_BloomExtraData`
- `TESR_BloomResolution`

Bloom creates multiple half-resolution render targets and frame vertex buffers.
It renders by progressive downsample/blur, then upsample/combine. Pass count and
pass blending transition between main/night/interior settings.

`TESR_BloomExtraData.x` is used as a flag for tonemapping and is disabled when
game overlay is on.

### Lens

Lens registers:

- `TESR_LensData`

It transitions strength, bloom exponent, and smudginess by main/night/interior,
and disables itself underwater.

## Feature Catalog Appendix

This catalog is the porting checklist for every visible NVR feature. It is not a
replacement for the HLSL formulas, but it defines the native contract that must
exist before those formulas can work.

Each feature falls into one of two implementation families:

- `ShaderCollection`: replacement shaders for vanilla shader package rows. These
  depend on exact row identity, vertex/pixel ABI, game constants, sampler layout,
  and vanilla fallback.
- `EffectRecord`: fullscreen or offscreen effect passes. These depend on NVR
  buffers, fixed pipeline order, constants, optional private render targets, and
  `ShouldRender` gates.

If a port cannot name the family, rows, constants, buffers, render gate, and
order slot for a feature, the feature is not ready to implement.

### CombineDepth

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/CombineDepth.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/CombineDepth.fx.hlsl`

Contract:

- owns or resolves the public `TESR_DepthBuffer`;
- combines world depth and viewmodel depth into the depth buffer consumed by all
  later depth-aware effects;
- runs first in pre-tonemap order;
- must use the same projection/depth convention as all later depth
  reconstruction helpers.

Port risk:

- if this buffer is stale, not resolved, or in the wrong depth convention, every
  downstream effect can blink in screen-space chunks: normals, AO, shadows,
  specular, underwater, fog, snow accumulation, and PBR helper paths that sample
  depth.

### Normals

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Normals.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Normals.fx.hlsl`

Contract:

- creates `TESR_NormalsBuffer`;
- reconstructs view/world normals from depth;
- runs immediately after `CombineDepth`;
- is required by AO, shadow compositing, wet/specular effects, snow
  accumulation, underwater lighting, and debug views.

Port risk:

- normals must match the same coordinate basis as the shadow and depth helpers;
  a sign or handedness mismatch produces lighting that flips with camera angle.

### AmbientOcclusion

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/AmbientOcclusion.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/AmbientOcclusion.fx.hlsl`

Contract:

- consumes `TESR_RenderedBuffer`, `TESR_DepthBuffer`, and
  `TESR_NormalsBuffer`;
- writes an AO result through the standard effect chain;
- settings are split into exterior and interior profiles;
- registers AO constants for range, strength, angle bias, luma threshold,
  clamp strength, blur threshold, and blur radius multiplier.

Render gate:

- controlled by `_Shaders.AmbientOcclusion.Status.Enabled`;
- profile selection follows `GameState.isExterior`.

Port risk:

- AO must run after normals and before later lighting/compositing passes. If it
  runs after shadows/specular, the final image order differs from NVR.

### ShadowManager, SunShadows, PointShadows, PointShadows2

Family: engine-side shadow subsystem plus `EffectRecord` passes.

Native source:

- `.research/TESReloaded10-master/src/core/ShadowManager.*`
- `.research/TESReloaded10-master/src/effects/SunShadows.*`
- `.research/TESReloaded10-master/src/effects/PointShadows.h`
- `.research/TESReloaded10-master/src/effects/PointShadows2.h`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Shadows/*.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/*Shadows*.fx.hlsl`

Contract:

- renders shadow maps before compositing;
- owns directional/sun shadow atlas resources;
- owns point-light cubemap resources;
- owns optional orthographic top-down map resources used by snow and other
  world-position effects;
- provides shadow textures through registered resource names;
- marks required work through flags such as `shadowMapRender`, `orthoRequired`,
  and point-light shadow requirements.

Feature-specific split:

- `SunShadows` prepares directional shadow data.
- `PointShadows` and `PointShadows2` prepare point-light shadow data.
- `ShadowsExteriors` composites exterior sunlight/shadow contribution.
- `ShadowsInteriors` composites interior point/spot/light contribution.

Port risk:

- the subsystem is stateful and render-stage-sensitive. Updating shadow maps
  from the wrong pass, or sampling a previous frame while constants describe the
  current frame, creates rectangular chunk updates and camera-angle blinking.

### ShadowsExteriors

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/ShadowsExterior.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/ShadowsExteriors.fx.hlsl`

Contract:

- runs in pre-tonemap after shadow map generation and before wet/specular/fog;
- consumes rendered color, depth, normals, sky/weather values, water height, and
  shadow maps;
- uses exterior-only settings for shadow strength, radius, bias, darkness, and
  blend behavior;
- must be disabled or altered during water reflection rendering, then restored.

Port risk:

- this pass must not be confused with object PBR. Object PBR shades direct
  material response in vanilla object rows; `ShadowsExteriors` is fullscreen
  compositing.

### ShadowsInteriors

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/ShadowsInteriors.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/ShadowsInteriors.fx.hlsl`

Contract:

- runs in pre-tonemap for interior light/shadow compositing;
- depends on current point-light data from the game and shadow manager;
- shares depth/normal reconstruction with the rest of the effect chain;
- must preserve vanilla room light contribution unless a matching NVR
  replacement path recomputes it.

Port risk:

- if object/terrain PBR replacement shaders bypass the point-light rows while
  this pass is active, interior lamps disappear or surfaces are lit only by an
  ambient fallback.

### WetWorld

Family: `EffectRecord` plus PBR input source.

Native source:

- `.research/TESReloaded10-master/src/effects/WetWorld.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/WetWorld.fx.hlsl`

Contract:

- animates rain and puddle wetness over time;
- registers `TESR_WetWorldData`;
- samples depth and normals to apply wet surface contribution;
- feeds object and terrain PBR through `max(rainAmount, puddleAmount)`.

Render gate:

- exterior-only and not underwater.

Port risk:

- wetness is not only a post effect. NVR PBR shaders use it as material input,
  so a PBR port needs the same constant even if the fullscreen wet pass is not
  ported yet.

### Flashlight

Family: `EffectRecord` plus optional shadow-render request.

Native source:

- `.research/TESReloaded10-master/src/effects/Flashlight.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Flashlight.fx.hlsl`

Contract:

- creates/manages a `NiSpotLight`;
- detects the Pip-Boy light and optional weapon/camera/head attachment mode;
- culls the vanilla Pip-Boy light node when NVR flashlight is active;
- registers flashlight position, direction, color, and view-projection matrix;
- can request a shadow map and then blur/use it during fullscreen lighting.

Constants:

- `TESR_FlashLightViewProjTransform`
- `TESR_FlashLightPosition`
- `TESR_FlashLightDirection`
- `TESR_FlashLightColor`

Port risk:

- flashlight is not just a color add. It owns scene graph behavior, shadow
  requests, and a native light object.

### Specular

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Specular.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Specular.fx.hlsl`

Contract:

- exterior-only and not underwater;
- registers `TESR_SpecularData` and `TESR_SpecularEffects`;
- interpolates between exterior and rain settings using the rain animator;
- consumes depth/normals/sky/water information to add screen-space specular
  highlights.

Settings:

- exterior and rain profiles contain luma threshold, blur multiplier,
  glossiness, distance fade, specular strength, sky tint strength, Fresnel
  strength, and sky tint saturation.

Port risk:

- because this is post-PBR screen-space specular, it can stack with material PBR.
  A port must decide deliberately whether to keep, disable, or integrate it.

### Underwater

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Underwater.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Underwater.fx.hlsl`

Contract:

- renders when `GameState.isUnderwater` or `Player->inWater`;
- consumes water constants, depth, sky colors, water height, and camera
  position;
- computes underwater extinction, scattering, caustics, fog, and surface
  transition behavior;
- depends on water shader constants even though it is a fullscreen pass.

Render gate:

- `ShouldRender` returns `isUnderwater || Player->inWater`.

Port risk:

- water constants must be updated even when water surface shaders are not being
  actively replaced, because underwater consumes the same data.

### VolumetricFog

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/VolumetricFog.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/VolumetricFog.fx.hlsl`

Contract:

- registers `TESR_VolumetricFogLow`, `TESR_VolumetricFogHigh`,
  `TESR_VolumetricFogSimple`, `TESR_VolumetricFogBlend`,
  `TESR_VolumetricFogHeight`, and `TESR_VolumetricFogData`;
- selects `Shaders.VolumetricFog.Main` for exteriors and
  `Shaders.VolumetricFog.Interiors` for interiors;
- exterior profile enables distant fog, sun power, night fog, and sky-color
  contribution;
- interior profile zeros exterior-only fields.

Render gate:

- renders unless underwater.

Port risk:

- fog is ordered after shadows/specular inputs are available but before
  tonemapping. Moving it after tonemapping changes color response.

### GodRays

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/GodRays.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/GodRays.fx.hlsl`

Contract:

- registers `TESR_GodRaysRay`, `TESR_GodRaysRayColor`, and
  `TESR_GodRaysData`;
- uses day/night transition values for multiplier behavior;
- samples sun glare/visibility state and sun ray color settings;
- renders in the pre-tonemap chain after fog-related preparation.

Render gate:

- exterior-only;
- not underwater;
- requires daylight value above `0.5`.

Port risk:

- source contains precedence-sensitive code for `Ray.w`:
  `rayVisibility * sunGlareEnabled ? sunGlare : 1.0`. A faithful port should
  either preserve this behavior or document a deliberate fix.

### AvgLuma

Family: `EffectRecord` helper buffer.

Native source:

- `.research/TESReloaded10-master/src/effects/AvgLuma.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/AvgLuma.fx.hlsl`

Contract:

- owns `TESR_AvgLumaBuffer`, a 1x1 `A16B16G16R16F` texture;
- renders only when another effect marks `TheShaderManager->avglumaRequired`;
- stores adapted luminance and focus-related data used by exposure and DOF.

Port risk:

- exposure and DOF are temporal effects. Reinitializing this buffer too often
  causes visible pumping/flicker.

### Exposure

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Exposure.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Exposure.fx.hlsl`

Contract:

- registers `TESR_ExposureData`;
- marks average luminance as required every update;
- transitions min brightness, max brightness, dark-adapt speed, and light-adapt
  speed across main/night/interior profiles;
- samples `TESR_AvgLumaBuffer`.

Port risk:

- `AvgLuma` is a hard dependency. Exposure without the temporal luma buffer is
  not equivalent to NVR exposure.

### Bloom

Family: `EffectRecord` plus HDR shader collection integration.

Native source:

- `.research/TESReloaded10-master/src/effects/Bloom.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Bloom.fx.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ISHDR*.hlsl`

Contract:

- registers `TESR_BloomData`, `TESR_BloomExtraData`, and
  `TESR_BloomResolution`;
- creates the `TESR_BloomBuffer` pyramid with up to eight half-resolution
  `A16B16G16R16F` render targets;
- creates matching frame vertex buffers for each bloom level;
- renders progressive downsample/blur, then upsample/combine;
- writes `TESR_BloomExtraData.x` as a flag consumed by tonemapping replacement
  shaders;
- clears bloom buffer when disabled.

Settings:

- main/night/interior profiles control pass count and pass blending;
- bloom strength/blending are read by the tonemapping shader collection.

Port risk:

- the bloom feature crosses the `EffectRecord` and `ShaderCollection` boundary.
  The fullscreen buffer alone is incomplete without the HDR/ISHDR row
  replacements that consume `TESR_BloomBuffer`.

### BloomLegacy

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/BloomLegacy.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/BloomLegacy.fx.hlsl`

Contract:

- registers `TESR_BloomLegacyData` and `TESR_BloomLegacyValues`;
- selects exterior or interior profile;
- applies legacy luminance/middle-gray/white-cutoff bloom composition.

Port risk:

- disabled by default in NVR defaults. Do not treat it as the same feature as
  the newer `Bloom` pipeline.

### Lens

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Lens.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Lens.fx.hlsl`

Contract:

- registers `TESR_LensData`;
- transitions strength, bloom exponent, and smudginess across main/night/interior
  profiles;
- uses lens dirt/smudging resources from the effect shader;
- disables itself underwater.

Render gate:

- not underwater and strength greater than zero.

Port risk:

- depends on the bloom pipeline for visual intensity. Porting lens without bloom
  changes its effective output.

### Rain

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Rain.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Precipitations.fx.hlsl`

Contract:

- registers `TESR_RainData` and `TESR_RainAspect`;
- animates rain intensity in/out when `GameState.isRainy` changes;
- `TESR_RainData.x` is the animated amount;
- vertical scale, speed, opacity, refraction, coloring, and bloom are settings.

Render gate:

- rain amount greater than zero;
- exterior-only;
- not underwater.

Port risk:

- rain amount is also read by WetWorld and Specular. A port must keep the
  animator even if the precipitation overlay is disabled.

### Snow

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Snow.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Snow.fx.hlsl`

Contract:

- registers `TESR_SnowData`;
- animates snowfall when `GameState.isSnow` changes;
- starts fading out WetWorld puddles when snow starts;
- marks `orthoRequired` while snow is visible.

Render gate:

- snow amount greater than zero;
- exterior-only;
- not underwater.

### SnowAccumulation

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/SnowAccumulation.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/SnowAccumulation.fx.hlsl`

Contract:

- registers `TESR_SnowAccumulationParams` and
  `TESR_SnowAccumulationColor`;
- animates accumulated snow in/out with independent increase/decrease rates;
- marks `orthoRequired` while accumulation is nonzero;
- uses orthographic map/depth/normal information to place snow on world
  surfaces;
- uses water height to avoid invalid accumulation around water surfaces.

Render gate:

- accumulation amount greater than zero;
- exterior-only;
- not underwater.

Port risk:

- requires the ortho-map contract. A shader-only copy will not know where world
  surfaces are.

### WaterLens

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/WaterLens.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/WaterLens.fx.hlsl`

Contract:

- registers `TESR_WaterLensData`;
- starts an animator when entering/exiting underwater state;
- settings provide two time multipliers, viscosity, and amount;
- shader uses animated normal/refraction distortion against
  `TESR_RenderedBuffer`.

Render gate:

- water-lens amount greater than zero.

### BloodLens

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/BloodLens.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/BloodLens.fx.hlsl`

Contract:

- registers `TESR_BloodLensParams` and `TESR_BloodLensColor`;
- uses `Effects/bloodlens.dds`;
- randomizes stain offsets/warp when a full-strength blood lens event starts;
- decays `Constants.Percent` over configured time;
- disables itself underwater.

Render gate:

- `Constants.Percent > 0`.

Port risk:

- the source contains event-state behavior beyond the visible shader. A port
  needs to reproduce how damage/events set `Percent` to start the effect.

### LowHF

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/LowHF.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/LowHF.fx.hlsl`

Contract:

- registers `TESR_LowHFData`;
- computes health and fatigue percentages from actor values;
- when health is below the configured limit, writes luma, blur, vignette, and
  darkness terms;
- otherwise fatigue can drive luma only.

Render gate:

- `TESR_LowHFData.x != 0`.

Source quirk:

- `UpdateConstants` reads `HealthLimit` directly from settings while
  `UpdateSettings` also stores `Settings.healthLimit`. A faithful port should
  choose whether to preserve or clean this duplication.

### MotionBlur

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/MotionBlur.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/MotionBlur.fx.hlsl`

Contract:

- registers `TESR_MotionBlurParams` and `TESR_MotionBlurData`;
- tracks player yaw/pitch deltas, handles angle wrapping, applies cutoff, and
  smooths with historical values;
- has first-person and third-person profile settings;
- shader applies directional blur using Gaussian weight, blur scale, and maximum
  offset.

Render gate:

- horizontal or vertical blur amount is nonzero.

Port risk:

- this is temporal/camera-state based. Recomputing only from current matrices is
  not NVR-equivalent.

### DepthOfField

Family: `EffectRecord` plus `AvgLuma` dependency.

Native source:

- `.research/TESReloaded10-master/src/effects/DepthOfField.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/DepthOfField.fx.hlsl`

Contract:

- registers `TESR_DepthOfFieldBlur` and `TESR_DepthOfFieldData`;
- marks average luminance/focus data as required;
- selects profile by camera mode: first person, vanity, and intended
  third-person handling;
- applies context mode gating for dialog/persuasion states;
- writes focus distance, radius, diameter range, near blur cutoff, and distant
  blur range constants.

Render gate:

- enabled/focus data or base blur radius is nonzero.

Source quirk:

- the native source appears to select `FirstPerson` settings in the non-vanity
  third-person branch. A port should either preserve this source behavior or
  document a deliberate correction.

### SMAA

Family: custom `EffectRecord` with private render targets.

Native source:

- `.research/TESReloaded10-master/src/effects/SMAA.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/SMAA.fx.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Includes/SMAA.hlsl`

Contract:

- registers `TESR_SMAAResolution`;
- creates `TESR_SMAA_Edges` and `TESR_SMAA_Blend` full-resolution render
  targets;
- uses external `Effects/SMAA_AreaTex.dds` and
  `Effects/SMAA_SearchTex.dds`;
- clears stencil before rendering;
- renders three passes: edge detection, blend weight calculation, neighborhood
  blending;
- edge detection input is configurable: luma, color, or depth.

Port risk:

- SMAA overrides `EffectRecord::Render`. It is not a one-pass fullscreen effect
  and requires its private surfaces and technique sequence.

### Sharpening

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Sharpening.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Sharpening.fx.hlsl`

Contract:

- registers `TESR_SharpeningData`;
- settings provide strength, clamp, and depth offset/falloff;
- shader uses depth-aware sharpening to avoid uniform full-screen ringing.

### Cinema

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Cinema.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Cinema.fx.hlsl`

Contract:

- registers `TESR_CinemaData` and `TESR_CinemaSettings`;
- controls letterbox aspect ratio, vignette, overlay strength, film grain,
  chromatic aberration, and depth-aware letterbox behavior;
- mode gates the letterbox behavior by dialog/persuasion state.

Port risk:

- `Data.x` is reset to native aspect ratio each frame unless mode/context allows
  the configured aspect. Ports must preserve that gate to avoid permanent bars.

### Coloring

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Coloring.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Coloring.fx.hlsl`

Contract:

- registers `TESR_ColoringColorCurve`, `TESR_ColoringEffectGamma`,
  `TESR_ColoringData`, and `TESR_ColoringValues`;
- selects a color profile by current cell editor name, then exterior worldspace
  editor name, then `Default`;
- applies gamma, contrast, saturation, bleach, fade, color curve, and
  per-channel effect gamma.

Port risk:

- this is not only one global color profile. Cell/worldspace lookup is part of
  the contract.

### ImageAdjust

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/ImageAdjust.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/ImageAdjust.fx.hlsl`

Contract:

- registers `TESR_ImageAdjustData`, `TESR_DarkAdjustColor`, and
  `TESR_LightAdjustColor`;
- transitions brightness, contrast, saturation, strength, and dark/light color
  controls across main/night/interior profiles.

### Debug

Family: `EffectRecord`.

Native source:

- `.research/TESReloaded10-master/src/effects/Debug.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Debug.fx.hlsl`

Contract:

- registers `TESR_DebugVar`;
- reads `_Main.Develop.Main.DebugVar1..4`;
- used by many shaders as a developer control/debug selector, not only by the
  debug fullscreen effect.

Port risk:

- if `TESR_DebugVar` is missing, replacement shaders that reference it must
  still receive a valid zero vector.

### Tonemapping And HDR Rows

Family: `ShaderCollection`.

Native source:

- `.research/TESReloaded10-master/src/effects/Tonemapping.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ISHDR*.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Tonemapping.hlsl`

Contract:

- replaces HDR/ISHDR shader rows;
- registers `TESR_HDRBloomData`, `TESR_HDRData`, `TESR_LotteData`, and
  `TESR_ToneMapping`;
- transitions highlight saturation, weather contrast, tone mapping color,
  linearization, bloom blend, bloom strength, weather modifier, white point,
  exposure, saturation, gamma, and Lotte curve fields;
- reads bloom settings from `_Shaders.Bloom.*`;
- uses `TESR_BloomExtraData.x` and `TESR_BloomBuffer` to integrate NVR bloom;
- updates only when settings or day-time state change.

Port risk:

- tonemapping is not a post effect in NVR; it is a vanilla shader replacement
  family. Porting bloom/exposure without HDR row replacement cannot match NVR.

### Water Shader Collection

Family: `ShaderCollection`.

Native source:

- `.research/TESReloaded10-master/src/effects/Water.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/WATER*.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Water.hlsl`

Contract:

- replaces water shader rows;
- registers default and placed-water constants;
- reads current water height and water form from the game;
- writes shallow/deep/LOD colors, underwater fog range/amount, water
  coefficients, wave parameters, volume parameters, water settings, shoreline
  movement, and refraction power;
- selects settings for default exterior, interiors, blood water, lava, and
  placed water;
- scales caustics by current sun glare;
- provides water constants consumed by water shaders and Underwater.

Port risk:

- water replacement also changes reflection-render behavior. NVR temporarily
  disables exterior shadows and terrain parallax while rendering reflections.

### Sky Shader Collection

Family: `ShaderCollection`.

Native source:

- `.research/TESReloaded10-master/src/effects/Sky.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/SKY*.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Sky.hlsl`

Contract:

- replaces sky, sky texture, clouds, stars, and horizon/fade related rows;
- registers `TESR_SkyData`, `TESR_CloudData`, and `TESR_SunsetColor`;
- settings control atmosphere thickness, sun influence, sun strength, star
  strength, cloud normal use, cloud transparency/brightness, star twinkle, and
  sunset color;
- `TESR_SunsetColor.w` follows tonemapping sky multiplier when tonemapping is
  enabled, otherwise it is `1.0`;
- sunset color RGB is zeroed outside exteriors.

Port risk:

- sky colors feed other passes. Sky replacement is part of the lighting model,
  not only visual sky geometry.

### Grass Shader Collection

Family: `ShaderCollection` plus game setting mutation.

Native source:

- `.research/TESReloaded10-master/src/effects/Grass.*`

Contract:

- registers `TESR_GrassScale`;
- settings control grass scale X/Y/Z;
- `GrassDensity` mutates game settings such as min grass size and texture
  percentage threshold;
- min/max distance settings mutate grass fade/end distance;
- optional wind mutates both game settings and shader parameters from NVR wind
  speed.

Port risk:

- grass is not isolated to shader code. It deliberately writes game setting
  pointers.

### Skin Shader Collection

Family: `ShaderCollection`.

Native source:

- `.research/TESReloaded10-master/src/effects/Skin.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/SKIN*.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Skin.hlsl`

Contract:

- registers `TESR_SkinData` and `TESR_SkinColor`;
- settings control attenuation, specular power, material thickness, rim scalar,
  and color coefficients;
- shader helpers add subsurface/rim/specular skin contribution.

Source status:

- the New Vegas `GetShaderCollection` path currently comments out the `Skin`
  collection return. The source exists, but active collection selection does not
  route skin rows in the same way as water/grass/sky/PBR/terrain.

### Bink Main Menu Renderer

Family: native renderer plus shader replacement.

Native source:

- `.research/TESReloaded10-master/src/core/BinkManager.*`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Bink/Bink.pso.hlsl`

Contract:

- creates a screen-space vertex declaration;
- loads `Bink.pso` from the Bink shader cache path;
- opens Bink movies with `BINKNOFRAMEBUFFERS`;
- creates Y/A/CR/CB D3D textures from Bink frame-buffer metadata;
- locks, copies, unlocks, and draws Bink frame textures;
- advances frames and closes the movie when finished;
- invoked from the New Vegas render hook for main menu intro replacement.

Port risk:

- this is not an effect pass in the post pipeline. It is a separate movie
  renderer using Bink frame buffers and a custom pixel shader.

## Known NVR Source Quirks And Risks

These are source-observed behaviors that a port must handle deliberately:

- Object PBR metallicness setting is not passed into object BRDF helpers; helper
  functions pass metallicness `0`.
- Terrain PBR does use metallicness.
- `TerrainShaders::UpdateConstants` returns early outside exteriors.
- POM reads `Shaders.PBR.Status.Enabled` and changes lighting behavior based on
  PBR status.
- NVR's PBR ambient rainy interpolation has a likely copy/paste quirk using
  default ambient scale in the rainy interior branch.
- Pixel shader replacement records clear sampler slots `0..15`; shadow shaders
  explicitly disable sampler clearing.
- Shader constants upload only when current handle differs from replacement
  handle.
- `TESR_DepthBuffer` and `TESR_RenderedBuffer` declarations cause runtime buffer
  resolve/copy side effects.
- The sampler parser depends on source formatting for register discovery and
  sampler state extraction.
- Effects reload at end frame, not immediately when Shader Loader sends refresh.
- Water reflection rendering disables shadow/parallax constants temporarily.
- VPT adds terrain constants and enables/disables them by render pass type.
- VPT's point-light terrain path is separate from no-point-light terrain rows.
- Terrain LOD and terrain fade are separate contracts and must not be merged with
  close terrain.
- `REVERSED_DEPTH` is both injected by NVR compile macros and hard-defined in
  VPT/NVR terrain templates; do not assume one global policy without checking the
  actual source path being compiled.

## OMV Porting Contract

### Required architecture for a real PBR port

OMV must implement these layers, in this order:

1. Shader identity layer
   - Names and rows must map to the same feature collections as NVR.
   - Replacement must know whether it is object, POM, close terrain, terrain LOD,
     terrain fade, water, HDR, etc.
2. Pass identity layer
   - Runtime draw must be proven to be the expected pass family.
   - Close terrain must use proven pass-entry or shader object identity, not only
     shader pair names.
3. ABI layer
   - Vertex declaration, constants, samplers, and render states must match the
     target row.
4. Resource layer
   - Required buffers, depth resolves, rendered/source copies, textures, and
     sampler states must be bound exactly when the shader expects them.
5. Constant update layer
   - Constants must be updated from current game state at the same stage NVR
     updates them.
6. Fallback layer
   - If any contract component is absent, fall back to vanilla for that draw.
   - Fallback must be deterministic and visible in logs.
7. Performance layer
   - Compile/cache before gameplay-critical draws when possible.
   - Avoid hot-path material scans.
   - Use row-specific shaders that sample only active resources.

### Object PBR completion checklist

To match NVR object PBR, OMV must cover:

- all relevant `SLS2000..SLS2056` pixel rows;
- all relevant `SLS2000..SLS2049` vertex rows;
- helper families:
  - `ONLY_LIGHT`;
  - `DIFFUSE`;
  - `ONLY_SPECULAR`;
  - `POINT`;
- projected shadow variants;
- SI/hair/STBB/LOD variants;
- two/four/nine-light variants;
- sampler layouts per variant;
- alpha/fog semantics per variant;
- PBR constants at `c32/c33` or an equivalent proven binding.

If lamps disappear when PBR is enabled, first suspect missing helper/point-light
row coverage or stale constants/samplers, not the BRDF formula.

### Terrain PBR completion checklist

To match NVR terrain PBR, OMV must cover:

- VPT dependency detection and exact version/contract assumption.
- Close terrain rows `SLS2092..SLS2146` with:
  - `TEX_COUNT 1..7`;
  - `NUM_PT_LIGHTS` variants 6/12/24.
- Vertex row `SLS2100.vso`.
- Samplers:
  - diffuse `s0..s6`;
  - normal `s7..s13`.
- VPT constants:
  - `LandSpec c32/c33`;
  - `LandHeight c34/c35`;
  - fog `c36/c37`;
  - point lights `c39/c63/c88`.
- NVR constants:
  - `c89..c92`.
- Correct active layer count.
- Correct vertex ABI.
- Terrain parallax and height blend if enabled.
- Terrain LOD rows `SLS2002/SLS2003`.
- Terrain fade rows `SLS2080/SLS2082`.
- Exterior-only behavior unless OMV proves another contract.

If terrain PBR appears only at some distances or angles, first suspect incomplete
row coverage between close terrain, point-light variants, LOD, fade, LandO,
projected-shadow, and helper rows.

### Shadow/light blinking checklist

When lighting changes abruptly with camera angle or distance:

- Check if the current draw switches between replaced and vanilla shader rows.
- Check if helper passes are missing.
- Check if `SetCT` equivalent runs for every replacement pass.
- Check if pixel sampler slots are cleared/bound per row.
- Check if point-light constants are present for the row.
- Check if terrain point-light variants are missing.
- Check if fullscreen shadow buffers are stale or partially updated.
- Check if depth/normal buffers correspond to the current world/viewmodel frame.
- Check if replacement uses raw shader handle identity without game pass identity.

### Performance checklist

NVR reduces shader stutter by caching compiled output. It still compiles when a
replacement is first seen or when preprocessed source changes.

For OMV:

- async compile is acceptable;
- synchronous compile during gameplay-critical draw is not acceptable;
- startup/prewarm compile is acceptable if it does not block game load forever;
- compile cache keys must include defines and source content;
- terrain variants must not sample all seven layers unless the row actually uses
  seven active layers;
- material/sampler resolution must use stable cache keys, not repeated hot-path
  scans.

### Current likely OMV violations from playtest symptoms

Based on NVR/VPT contract and reported OMV behavior:

- Close terrain PBR visible only sometimes means row coverage or pass identity is
  incomplete.
- Terrain blinking with distance/angle likely means close terrain, point-light
  variants, LOD, fade, or helper rows are switching between vanilla and OMV.
- Interior lamps disappearing with object PBR likely means object helper rows or
  point-light pass variants are missing or using wrong constants/samplers.
- Rectangular shadow chunks likely mean fullscreen shadow/light buffers or pass
  state are not being updated in the same contract NVR uses.
- If performance is now acceptable after async compile, the next work should not
  be more compile telemetry; it should be completing row/ABI/resource coverage.

These are not final root causes. They are contract-driven hypotheses that should
guide the next instrumentation and implementation.

## Implementation Issue Map

### Complete object PBR port

Required source contracts:

- `PBRShaders::Templates()`
- `ObjectTemplate.hlsl`
- `Object.hlsl`
- `PBR.hlsl`

Implementation risks:

- missing helper rows;
- wrong sampler slots for projected shadow/helper variants;
- wrong alpha output for helper variants;
- stale constants from handle-only updates;
- wrong exterior/interior/default selection.

Planned fix direction:

- build a row table matching NVR templates;
- bind row-specific shader variants;
- log every unmatched SLS object row with pass context;
- treat missing helper rows as blockers for "complete object PBR".

### Complete terrain PBR port

Required source contracts:

- VPT `AddPass_Landscape`
- VPT constant map additions and `UpdateLightsAlt`
- NVR `TerrainShaders::Templates()`
- `TerrainTemplate.hlsl`
- `TerrainLODTemplate.hlsl`
- `TerrainFadeTemplate.hlsl`
- `Terrain.hlsl`
- `Parallax.hlsl`

Implementation risks:

- using shader pair names instead of pass identity;
- replacing row 560 with close terrain shader;
- replacing zero-resource/LandO/helper rows;
- missing VPT constants;
- using layer0 fallback for active missing layers;
- sampling all seven layers on every draw;
- enabling terrain in interiors without proof.

Planned fix direction:

- derive row coverage directly from VPT/NVR tables;
- require VPT contract for terrain PBR;
- implement separate close terrain, terrain LOD, and terrain fade shader families;
- gate close terrain on proven pass-entry identity;
- fail closed to vanilla on incomplete layer/material/constant state.

### Complete shadow/light compatibility

Required source contracts:

- `ShadowManager`
- `RenderPass`
- `SunShadows`
- `PointShadows`
- `ShadowsExteriors`
- `ShadowsInteriors`
- `GetNearbyLights`

Implementation risks:

- PBR replacements interacting with NVR/vanilla shadow fullscreen passes without
  preserving required buffers;
- missing point-light helper shader rows;
- stale depth/normal buffers;
- not clearing/restoring render states around custom passes.

Planned fix direction:

- separate native shader PBR work from fullscreen shadow pass work;
- instrument row switches and constant uploads around light blinking repros;
- verify depth/normal buffer lifetime before debugging BRDF math.

## Required Documentation Before Future Feature Work

Before implementing any NVR feature in OMV, add or update a section in this file
with:

- source files used;
- row/template coverage;
- vertex input ABI;
- pixel sampler ABI;
- constant registers and native storage;
- render stage and ordering;
- resource dependencies;
- exterior/interior behavior;
- fallback behavior;
- known source quirks;
- OMV-specific proof gaps.

If one of those sections is unknown, the next action is source/Ghidra/runtime
research, not a shader tweak.

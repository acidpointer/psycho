# Psycho Graphics Research And Implementation Plan

Date: 2026-06-08

This document records the current research state and implementation plan for
`psycho-graphics`. The target is not another final-frame post-processor. The
target is a graphics layer that can run early enough in the FNV render pipeline
to cooperate with vanilla fog/image-space effects, while remaining compatible
with other graphics mods.

## Primary Goal

`psycho-graphics` must support deeper graphics features than the current
screen-space final pass:

- ambient occlusion that is composed before vanilla fog/image-space effects;
- sunshafts/godrays using real game sun, camera, fog, and weather data;
- future material-level work for PBR-like rendering;
- live shader loading and configuration without breaking other graphics mods.

The hard requirement is compatibility. TESReloaded/NewVegasReloaded is trusted
prior art and is time proven, but Psycho must not blindly copy its invasive
patching model. We should reuse the ideas and avoid the compatibility hazards.

## Current Problem

The current AO path is applied after the game's image-space pipeline. That makes
AO darken already-fogged pixels. In far fog this produces visible dark shadow
lines over a solid fog color, which looks like a ReShade overlay rather than a
real engine effect.

Current hook path:

- `psycho-graphics/src/fnv_render.rs`
  - `ProcessImageSpaceShaders @ 0x00B55AC0`
  - `RenderWorldSceneGraph @ 0x00873200`
  - `RenderFirstPerson @ 0x00875110`

Current final application:

- `hook_process_image_space_shaders` calls the original function first.
- If `rendered_texture_2` is null, it calls `apply_final_image_space`.
- `apply_final_image_space` calls `runtime::apply_fnv_scene_frame`.

That means the current draw happens after vanilla `ProcessImageSpaceShaders`.
This is a valid phase for final AA/CAS/debug overlays. It is the wrong phase for
AO, contact shadows, depth-based lighting, godray occlusion masks, and other
effects that should participate in later vanilla composition.

## Current Psycho Implementation Baseline

### Hooks

`psycho-graphics/src/fnv_render.rs` installs three hooks:

- `0x00B55AC0` - `ImageSpaceManager::ProcessImageSpaceShaders`
- `0x00873200` - `Main::RenderWorldSceneGraph`
- `0x00875110` - `Main::RenderFirstPerson`

Current behavior:

- after `RenderWorldSceneGraph`, Psycho resolves world depth and captures world
  color;
- after `RenderFirstPerson`, Psycho resolves first-person depth;
- at the start of `ProcessImageSpaceShaders`, Psycho draws
  `scene_pre_image_space` passes into the vanilla source `BSRenderedTexture`
  before vanilla image-space effects consume it;
- after `ProcessImageSpaceShaders`, Psycho draws `scene_post_image_space` and
  `final_image_space` passes.

This gives AO/contact-shadow passes a real pre-vanilla-image-space timing while
keeping final AA/CAS/debug passes late.

Important correction from runtime testing:

- drawing scene-pre passes to the current D3D render target is not sufficient.
  Vanilla image-space can immediately overwrite that target from its own source
  rendered texture;
- the default scene-pre path must resolve the second argument to
  `ProcessImageSpaceShaders` as the source `BSRenderedTexture`, validate
  `BSRenderedTexture -> NiRenderTargetGroup -> Ni2DBuffer -> D3D surface`, bind
  that surface temporarily, draw the fullscreen passes, and restore the previous
  render target/state.

### Depth Resolve

`psycho-graphics/src/backend/fnv.rs` currently resolves the active D3D depth
surface using INTZ/RESZ:

- D3D device is read from `NiDX9Renderer::singleton @ 0x011C73B4`.
- Camera pointer is read from `BSShaderManager::pCurrentCamera @ 0x011F917C`.
- Near/far are read from camera offsets `0xEC` and `0xF0`.
- World and first-person depth textures are stored separately.

Important: Psycho's depth chain is independent from DepthResolve. This is good
for compatibility and should remain true.

### Runtime Shader Model

`psycho-graphics/src/runtime.rs` currently treats every shader as the same kind
of fullscreen screen pass:

- source color/current render target copy is bound to `s0`;
- world depth is bound to `s1`;
- first-person depth is bound to `s2`;
- captured world color/current color is bound to `s3`;
- fixed constants are written to `c0`, `c1`, `c2`, and `c6`;
- user options start at `c3`; `c6` is reserved for built-in environment data.

The current fixed constants are:

- `c0`: width, height, texel width, texel height;
- `c1`: frame index, pass index, pass count, depth available;
- `c2`: near, far, aspect ratio, depth provider id;
- `c6`: fog start, fog end, fog power, fog available;
- `c3+`: user option constants from the shader TOML, except reserved `c6`.

This model is enough for simple AO, CAS, FXAA, and debug views. It is not enough
for sunshafts, volumetric fog, PBR/material lighting, shadowing, weather-aware
effects, or proper projection-space reconstruction.

### Shader Configuration

Current shader sidecars only support:

- `enabled`;
- `passes`;
- option sliders/toggles bound to explicit constant registers.

They do not describe:

- render phase;
- required inputs;
- native shader replacement target;
- effect ordering;
- intermediate render targets;
- matrix/environment constants;
- compatibility requirements.

The config format must evolve before complex shader work.

## Current Ghidra Knowledge

Only `.txt` output under `analysis/ghidra/output/` is ground truth for FNV
behavior. Existing prose notes are not authoritative.

### Render Order

Source:

- `analysis/ghidra/output/perf/graphics_fnv_stage_boundary_order_deep_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt`

Relevant known order:

- `Main::RenderWorldSceneGraph @ 0x00873200` is called before first-person
  rendering in the main scene path.
- `Main::RenderFirstPerson @ 0x00875110` happens after world rendering.
- `ImageSpaceManager::ProcessImageSpaceShaders @ 0x00B55AC0` is called later
  from the main render path.
- `ProcessImageSpaceShaders` calls `RenderEndOfFrameEffects @ 0x00B97900`.
- `BSShaderAccumulator::RenderPostDepthGroups @ 0x00B65C60` is an important
  post-depth/alpha/water/refraction-adjacent boundary.
- `ProcessImageSpaceShaders @ 0x00B55AC0` has a single known caller at
  `0x00876136` inside `0x00875FD0`.
- That caller updates `BSShaderManager::pCurrentCamera @ 0x011F917C` at
  `0x00876125` immediately before calling `ProcessImageSpaceShaders`.
- Both main render paths call first-person rendering before the later path that
  reaches `0x00875FD0`.

Conclusion:

- the existing `ProcessImageSpaceShaders` hook can run
  `scene_pre_image_space` before calling the original function;
- this is a better default AO boundary than post-world/pre-first-person;
- no new DepthResolve-owned callsite patch is required.

### Depth Independence

Source:

- `analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`

Known chain:

- `BSShaderManager::pCurrentRenderTarget @ 0x011F9438`
- `BSRenderedTexture.spRenderTargetGroups[0] + 0x08`
- `NiRenderTargetGroup.m_spDepthStencilBuffer + 0x20`
- `NiDepthStencilBuffer.m_spRendererData + 0x10`
- `NiDX92DBufferData.Surface + 0x14`

Important conclusion:

- Psycho should not require DepthResolve's
  `ImageSpaceManager::GetDepthTexture` replacement.

DepthResolve-owned sites that must remain off-limits:

- `ImageSpaceManager::GetDepthTexture @ 0x00B54090`
- replacement calls at `0x00B6657D` and `0x00B665AC`
- associated patch area around `0x00B64057`, `0x00B65C43`, `0x00B65C4C`

### First-Person State

Sources:

- `analysis/ghidra/output/perf/graphics_fnv_first_person_state_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_first_person_depth_composite_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_camera_projection_contract_audit.txt`

Known facts:

- `RenderFirstPerson @ 0x00875110` clears depth around `0x008751C6`.
- It calls `BSShaderAccumulator::RenderFirstPersonAccumulated @ 0x00B64570`.
- First-person setup uses `RenderFirstPerson_Setup @ 0x00874C10`.
- First-person camera/depth values are modified and restored around this path.

TESReloaded patches the first-person depth clear and re-renders first-person.
That may be valid for NVR, but it is not compatibility-first. Psycho should keep
separate first-person depth and use masks before considering this kind of patch.

### Camera And Projection

Source:

- `analysis/ghidra/output/perf/graphics_fnv_camera_projection_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_camera_matrix_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_camera_near_far_frustum_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_scene_fog_property_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_bsfogproperty_layout_audit.txt`

Known facts:

- `BSShaderManager::pCurrentCamera @ 0x011F917C` is written from several paths.
- `RenderImageSpaceCaller @ 0x00875FD0` writes `pCurrentCamera` immediately
  before `ProcessImageSpaceShaders`.
- `CameraVectorGetter_0045BB80` returns `camera + 0x8C`.
- `CameraWriter_00B5E870` copies `camera + 0x8C/+0x90/+0x94` to globals
  `0x011FA2A0/+0xA4/+0xA8`, so the old `WorldToCam + 0x94` candidate is not a
  safe matrix contract. It is part of a position/vector copy.
- The same writer copies camera fields `+0x68/+0x74/+0x80` to
  `0x011FA2B0/+0xB4/+0xB8` and `+0x70/+0x7C/+0x88` to
  `0x011FA2C0/+0xC4/+0xC8`. These are basis/vector candidates, but not yet a
  proven view matrix contract.
- If `param_1 + 0x134` is present, `CameraWriter_00B5E870` copies fields from
  that object into the `0x011FA280` global block:
  `+0x30`, `+0x20/+0x24/+0x28`, `+0x30 - +0x2C`, and `+0x60`.
  This looks frustum/projection related, but ownership and meaning are not yet
  proven.
- `WorldCameraDepthValue_00710AB0` returns `param_1 + 0x670`.
- `FirstPersonCameraDepthValue_00874900` returns `param_1 + 0x674`.
- `SetCameraDepthValues_00C52020` writes `param_4 + 0xFC` from a virtual
  getter at `param_1` vtable `+0x100`, divided by `DAT_01203148`.
- `SetCameraDepthValues_00C52020` writes `param_4 + 0x110` from `param_2`,
  divided by `DAT_01203154`, and caches `param_2` in `param_1[0x2F]`.
- `camera + 0xEC/+0xF0` are now safe to use as projection near/far for depth
  reconstruction. This matches the local `NiCamera` layout (`NiAVObject 0x9C`,
  `worldToCam 0x40`, `NiFrustum.near/far +0x10/+0x14`) and the Ghidra shader
  constant writers `FUN_00B5A220` and `FUN_00BD66C0`, which read
  `BSShaderManager::pCurrentCamera + 0xEC/+0xF0`.
- These fields are not the active scene fog range. Fog distance must be read
  separately from the active `BSFogProperty`.
- First-person camera state is not the same as world camera state during parts
  of first-person rendering.

Needed for future features:

- proven world/view/projection matrices;
- inverse projection;
- camera position and basis vectors;
- correct phase-specific camera selection.

### Sun Projection

Source:

- `analysis/ghidra/output/perf/graphics_fnv_sun_projection_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_sun_weather_layout_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_weather_fog_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_fog_weather_deep_field_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_environment_contract_followup_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_scene_fog_property_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_bsfogproperty_layout_audit.txt`

Known candidate data:

- `Sky singleton: *(Sky**)0x011DEA20`
- `Sky::sun/current object getter @ 0x0045CD60` returns `Sky + 0x28`
- `Sky current climate/weather getter @ 0x004505A0` checks `Sky + 0x28` and then
  calls another function; the current audit does not prove the final weather
  object layout;
- `SkyObject::RootNode candidate: Sun + 0x04`
- candidate local/world position fields on the sun root node;
- camera position/basis fields.

The output explicitly says not to implement sun projection until these offsets
are proven. Since TESReloaded is trusted prior art, we do not need to prove that
the concept works, but we still need a safe Psycho data contract before shipping
code that dereferences game memory and advertises compatibility.

The newer sun/weather layout audit proves `Sky::singleton @ 0x011DEA20` is a
real global used by render code, and it confirms the image-space phase has a
fresh current camera. It does not yet prove the full `TESWeather` fog field
layout or view/projection matrix layout. Godray/PBR environment constants must
therefore stay out of runtime code until follow-up scripts prove those fields.

The weather/fog audit also does not yet prove vanilla fog color or a full
weather/environment block. It proves sky construction/update paths and
sunrise/sunset cached values, while the later `BSFogProperty` audit proves the
active scene fog range/power needed for fog-aware AO.

The deep fog/weather audit adds stronger weather-controller knowledge:

- `FUN_0063B630` computes four day-phase weather weights from
  `param_1 + 0xEC`, sunrise/sunset helpers, and an additional time boundary at
  `param_1 + 0x12C` (shown as decimal `300` in the decompiler).
- `FUN_0063B630` multiplies those weights by `param_1 + 0xF4`, which is a
  weather transition/blend factor.
- `FUN_0063EF20` applies up to four weighted weather slots by calling
  `FUN_0063F790(weight)` and then `FUN_0050F9A0(weather)`.
- `FUN_0063EF20` resolves weather entries through `FUN_005822A0(phase_index)`
  when `param_1 + 0x10` is present, with `FUN_00532FF0()` as a fallback.
- `param_1 + 0x14` gates the alternate/transition weather path, and
  `param_1 + 0xF4` controls whether that path contributes.
- `Sky current climate/weather getter @ 0x004505A0` checks `Sky + 0x28` and
  calls `FUN_006838B0`, but the final returned object layout is still not
  proven.

Conclusion:

- Psycho should not expose raw sky/weather fields directly to shaders.
- The runtime should eventually expose a normalized environment block produced
  by engine-side readers: fog color/range, weather blend, time phase weights,
  sun color/direction, and exterior/interior flags.
- The next proof target is `FUN_0050F9A0`, because it is the likely point where
  a concrete `TESWeather` entry is applied to sky/fog state.

The environment follow-up audit refines that model:

- `Weather command setup/current world candidate @ 0x0046DD00` lazily creates a
  weather controller-sized object (`0x138` bytes through `FUN_00639D40`) and
  stores it in `DAT_011CCB78`.
- `GetCurrentWeather candidate @ 0x0044EDB0` returns
  `weather_controller + 0x10`.
- `Current weather percent getter @ 0x006447D0` returns
  `weather_controller + 0xF4`.
- `Weather weight setter @ 0x0063F790` writes a weather-slot weight to
  `slot + 0x0C`.
- `ApplyWeather candidate @ 0x0050F9A0` is not a full weather application
  function. It is a small setter that writes a weather pointer/value to
  `slot + 0x1C`.
- `FUN_0063EF20` owns four weighted weather slots through fields
  `weather_controller + 0x11C/+0x124/+0x120/+0x128`, using
  `FUN_0063F790(weight)` and `FUN_0050F9A0(weather)`.
- `FUN_00532220` blends two weather records and reads
  `weather + 0xEC/+0xF0` when `weather + 0xE8` is false. This is the strongest
  current evidence for TESWeather fog-distance fields, but the downstream
  setter/global path is still not fully identified.

Important correction:

- `FUN_0050F9A0` must not be treated as the fog/color reader. The real fog
  application path is below `FUN_00532220` and its calls to
  `FUN_00B8B1C0`, `FUN_00B8B000`, `FUN_00B8B0D0`, and related helpers.

Compatibility-first direction for AO fog:

- Prefer reading the active scene fog property over directly walking
  `TESWeather` at runtime.
- The scene fog property contract is now proven enough for a guarded runtime
  reader:
  - `BSShaderManager::ucSceneGraph @ 0x011F91C4` is written by
    `FUN_004E20F0` and by `CameraWriter_00B5E870`.
  - `BSShaderManager::GetShadowSceneNode @ 0x00450B80` returns
    `(&DAT_011F91C8)[index]`.
  - `FUN_00B55520(index)` returns
    `*((&DAT_011F91C8)[index] + 0x134)`, proving the active scene-node
    `+0x134` fog-property pointer path.
  - `BSFogProperty` vtable is `0x010B9E38`; constructors
    `0x00BB8180/0x00BB8250` write that vtable.
  - The constructor initializes float fields at `+0x2C`, `+0x30`, and `+0x60`,
    and deletes object size `0x64`.
  - Stewie and Vanilla Plus AO prior art names those fields as
    `fStartDistance @ +0x2C`, `fEndDistance @ +0x30`, and
    `fPower @ +0x60`.
- Runtime must still validate the scene index, scene node pointer, fog property
  pointer, vtable, and float ranges. If validation fails, fog constants should
  be marked unavailable instead of guessing from `TESWeather`.
- Fog color is still not proven through this path. AO fade only needs distance
  and power; volumetric fog/godrays still need a separate fog color contract.

## Research Directory Knowledge

### TESReloaded/NewVegasReloaded

Source directory:

- `.research/TESReloaded10-master`

Useful ideas:

- native shader creation hooks:
  - `CreateVertexShader`
  - `CreatePixelShader`
  - `SetShaderPackage`
- render hooks:
  - `Render`
  - `ProcessImageSpaceShaders`
  - `RenderWorldSceneGraph`
  - `RenderFirstPerson`
  - `SetShaders`
  - `SetSamplerState`
  - `RenderReflections`
- `RenderHook` updates shader constants before rendering.
- `SetShadersHook` sees the current `NiD3DPass @ 0x0126F74C` and current
  geometry slot around `0x011F91E0`, then swaps/restores shader handles.
- `RenderWorldSceneGraphHook` resolves depth after world rendering.
- `RenderFirstPersonHook` resolves depth, clears z, calls first-person setup,
  then renders first-person again.
- `ShaderManager::RenderEffects` orders complex effects intentionally.
- `RenderManager::SetupSceneCamera` builds view/projection/inverse projection
  matrices, camera vectors, and depth reconstruction constants.

Important TESReloaded constants we likely need equivalents for:

- `TESR_ViewTransform`
- `TESR_ProjectionTransform`
- `TESR_InvProjectionTransform`
- `TESR_CameraForward`
- `TESR_CameraPosition`
- `TESR_DepthConstants`
- `TESR_CameraData`
- `TESR_SunDirection`
- `TESR_SunColor`
- `TESR_FogColor`
- `TESR_FogData`
- `TESR_FogDistance`

Important TESReloaded effect order:

- wet/snow accumulation;
- ambient occlusion;
- shadows;
- coloring/specular/bloom;
- underwater/rain/snow;
- godrays;
- volumetric fog;
- depth of field;
- lens/motion/sharpen/final effects.

This order is the main lesson for the current AO bug: AO is not a final overlay.
It belongs before later fog/volumetric/final composition.

Compatibility hazards in TESReloaded that Psycho should not copy by default:

- extending `NiD3DVertexShader`/`NiD3DPixelShader` object sizes with raw writes;
- patching `0x008751C0` to stop first-person depth clear;
- broad global SafeWrite patches for unrelated graphics behavior;
- assuming exclusive ownership of native shader objects.

### Fallout Shader Loader

Source directory:

- `.research/Fallout-Shader-Loader-main`

Useful ideas:

- hooks `BSShader::CreateVertexShader @ 0x00BE0FE0`;
- hooks `BSShader::CreatePixelShader @ 0x00BE1750`;
- hooks `ImageSpaceManager::RenderEndOfFrameEffects @ 0x00B97900`;
- loads loose shaders from `Data\Shaders\Loose`;
- exports shader creation helpers;
- detects NVR and fills NVR-specific shader fields when needed;
- provides pre/post end-of-frame image-space messages.

Compatibility lesson:

- these hook points are already used by active graphics mods;
- if Psycho later uses them, it must chain cleanly or disable that feature;
- native shader loading must not assume sole ownership.

### DepthResolve

Source directory:

- `.research/fnv-depth-resolve-main`

Useful ideas:

- INTZ depth texture;
- RESZ/NvAPI depth copy paths;
- exported post-depth effect list:
  - `PrependPostDepthEffect`
  - `AppendPostDepthEffect`
- post-depth effects are rendered through `ImageSpaceManager::RenderEffect`.

Compatibility hazards:

- replaces `ImageSpaceManager::GetDepthTexture @ 0x00B54090`;
- patches `0x00B64057`, `0x00B65C43`, `0x00B65C4C`;
- replaces calls at `0x00B6657D` and `0x00B665AC`.

Psycho's current independent active-depth resolve is preferable for
compatibility. We should not depend on DepthResolve being installed.

### Vanilla Plus AO

Source directory:

- `.research/fnv-vanilla-plus-ao-main`

Useful ideas:

- AO is a staged pipeline:
  - linearize depth;
  - downsample depth;
  - SAO;
  - bilateral blur;
  - apply AO;
- it reads fog data and fades/applies AO with fog awareness;
- it uses DepthResolve's `AppendPostDepthEffect` and Fallout Shader Loader's
  shader creation exports.

Compatibility lesson:

- staged AO is worthwhile;
- hard dependencies on Shader Loader and DepthResolve are not acceptable for
  Psycho's compatibility goal;
- fog-aware AO logic is necessary even when AO is moved earlier.

## Compatibility-First Rules

These rules override feature ambition.

1. Default mode must be non-invasive.

   Default Psycho graphics should use independent depth resolve, fullscreen
   passes, robust state restore, and read-only game data. It must not require
   native shader replacement.

2. Native shader replacement is opt-in.

   PBR/material work should be disabled unless explicitly enabled. If another
   graphics mod owns the same surface, Psycho should log and disable that layer
   unless a tested compatibility path exists.

3. Do not extend native object layouts by default.

   TESReloaded extends shader object sizes. Psycho should prefer side tables
   keyed by native pointers.

4. Do not patch DepthResolve-owned callsites.

   Keep using independent depth resolve. Do not patch or depend on:

   - `0x00B54090`
   - `0x00B6657D`
   - `0x00B665AC`
   - `0x00B64057`
   - `0x00B65C43`
   - `0x00B65C4C`

5. Do not patch first-person depth clear in the first milestone.

   Keep world and first-person depth separate. Use masks. Revisit first-person
   re-rendering only if a specific feature cannot be solved otherwise.

6. Restore D3D state completely.

   Every custom draw must restore:

   - render targets;
   - depth stencil surface;
   - viewport/scissor;
   - vertex shader and pixel shader;
   - FVF/declaration/stream source;
   - textures and samplers;
   - shader constants;
   - render states;
   - texture-stage states.

7. Detect graphics mods.

   Add runtime detection and logging for at least:

   - TESReloaded/NewVegasReloaded;
   - Fallout Shader Loader;
   - DepthResolve;
   - ENB/ReShade-style D3D9 chains where detectable;
   - DXVK/Proton relevant depth path constraints.

8. Silent conflict is not acceptable.

   If a feature cannot be installed safely, disable that feature and log the
   exact reason.

## Target Architecture

### Pass Phases

Add explicit pass phases:

- `scene_pre_image_space`
  - AO;
  - contact shadows;
  - depth-aware pre-fog effects;
  - godray occlusion/mask preparation if needed.

- `scene_post_image_space`
  - effects that intentionally run after vanilla image-space, but before final
    UI/menu overlays if such a boundary is available.

- `final_image_space`
  - CAS;
  - FXAA;
  - color grading;
  - debug overlays;
  - user final passes.

- `native_material`
  - future native shader replacement;
  - PBR-like material lighting;
  - optional and compatibility-gated.

The current single `draw_passes` path should become a phase-aware dispatcher.

### Shader Metadata

Extend shader TOML with fields similar to:

```toml
[shader]
enabled = true
phase = "scene_pre_image_space"
priority = 100
passes = 2
needs_depth = true
needs_first_person_depth = true
needs_world_color = true
needs_environment = true
compatibility = "non_invasive"
```

Possible compatibility values:

- `non_invasive`
- `requires_native_shader_hook`
- `requires_image_space_hook`
- `exclusive`

The runtime should refuse to enable a shader if its required phase or inputs are
not available.

### Frame Inputs

Replace the small `FrameInputs` model with a richer structure:

- camera:
  - near/far;
  - aspect ratio;
  - FOV;
  - position;
  - forward/right/up;
  - view matrix;
  - projection matrix;
  - inverse projection matrix;
  - view-projection matrix;
  - inverse view-projection matrix;

- depth:
  - world depth;
  - first-person depth;
  - provider id;
  - depth encoding/reversed flag;
  - resolution;

- environment:
  - exterior/interior flag;
  - fog color;
  - fog start/end/density/power;
  - weather transition percent;
  - sun direction;
  - sun color;
  - sun screen UV;
  - sun visibility/glare amount;
  - game time;

- water/weather later:
  - underwater flag;
  - water height;
  - rain/snow amount.

### Constant Binding

The fixed `c0`/`c1`/`c2` model should remain only as a legacy path.

For complex shaders, add a named binding model inspired by TESReloaded:

- built-in constants are assigned by semantic names;
- shader sidecar can request named blocks;
- native material replacement can use parsed shader constant tables later.

Example names for Psycho:

- `PSY_View`
- `PSY_Projection`
- `PSY_InvProjection`
- `PSY_CameraData`
- `PSY_DepthData`
- `PSY_SunDirection`
- `PSY_SunColor`
- `PSY_FogColor`
- `PSY_FogData`
- `PSY_FrameData`

This avoids hard-coding every advanced shader to fragile manual registers.

## Implementation Stages

### Stage 1: Phase System And AO Timing

Goal:

- move AO out of the final post-image-space phase;
- keep CAS/FXAA in the final phase;
- preserve compatibility.

Tasks:

- add phase metadata to shader config;
- split runtime draw path by phase;
- run `scene_pre_image_space` immediately before vanilla
  `ProcessImageSpaceShaders`;
- draw `scene_pre_image_space` into the image-space source `BSRenderedTexture`,
  not the current D3D render target;
- keep current final `ProcessImageSpaceShaders` hook for final passes;
- keep world and first-person depth resolves as they are;
- log phase install/apply decisions.

Rejected first milestone options:

- post-world/pre-first-person draw after `RenderWorldSceneGraph`: useful as a
  conservative fallback, but it misses first-person composition;
- patching `BSShaderAccumulator::RenderPostDepthGroups @ 0x00B65C60` callers:
  overlaps DepthResolve-owned addresses and should not be default;
- native shader replacement: unnecessary for AO timing and too invasive for the
  default path.

Risk:

- the pre-image-space hook is still a broad function hook used by other graphics
  mods, so runtime chaining/detection remains important.

Mitigation:

- use separate first-person depth masking;
- keep the initial pass optional;
- add debug views for world depth, first-person depth, and phase timing.

### Stage 2: Fog-Aware AO

Goal:

- AO should not produce dark lines in far fog, even if phase ordering is not
  perfect in every case.

Tasks:

- add fog constants to `FrameInputs`;
- read fog range/power from the validated active scene `BSFogProperty` path:
  `ucSceneGraph -> ShadowSceneNode[scene] -> +0x134 -> BSFogProperty`;
- fade AO by fog distance/density;
- add separate exterior/interior AO settings;
- add debug overlay for fog start/end and AO fade.

References:

- TESReloaded AO shader uses `TESR_FogDistance` and `TESR_FogColor`.
- Vanilla Plus AO reads a fog property and passes fog distance/power to its
  apply shader.

Implementation note:

- Psycho now exposes `EnvironmentData` in pixel shader constant `c6` as
  `fog_start`, `fog_end`, `fog_power`, and `fog_available`.
- AO/contact AO multiply their darkening by a fog visibility term so far-fog
  pixels fade back toward unmodified color.
- This is intentionally read-only and non-invasive. It does not patch the
  vanilla fog pass or walk raw weather data at runtime.

### Stage 3: Camera Matrices And Environment Constants

Goal:

- provide the data required for real screen-space reconstruction and sun effects.

Tasks:

- build view/projection/inverse projection matrices from proven FNV camera data;
- expose camera position and basis vectors;
- expose stable near/far/FOV/aspect;
- log and debug-render matrix-derived reconstruction;
- make constants phase-specific where first-person camera differs from world.

Current blocker:

- `camera + 0x8C/+0x90/+0x94` is position/vector data, not a proven
  world-to-camera matrix.
- Do not expose `PSY_View`, `PSY_Projection`, or `PSY_InvProjection` until a
  direct frustum/matrix audit proves the exact fields.

Reference:

- TESReloaded `RenderManager::SetupSceneCamera` is the model for the math.

Compatibility:

- read data only;
- no native object layout changes;
- no first-person depth-clear patch.

### Stage 4: Sun Data And Godrays

Goal:

- implement godrays/sunshafts from real sun and camera data.

Tasks:

- prove/read sun direction and color;
- project sun to screen UV on CPU;
- add debug overlay for sun direction and projected sun position;
- add godray occlusion/mask pass;
- add radial shaft pass;
- combine with sun/fog/weather color;
- disable in interiors unless explicitly supported.

References:

- TESReloaded `GodRays.fx.hlsl` uses:
  - view transform;
  - projection transform;
  - camera forward;
  - sun direction;
  - game time;
  - sun color;
  - sun amount.

Compatibility:

- screen-space godrays can remain non-invasive;
- do not require native shader replacement.

### Stage 5: Native Shader Replacement Layer

Goal:

- prepare for PBR-like material work without making basic effects incompatible.

Tasks:

- add optional hooks for:
  - `BSShader::CreateVertexShader @ 0x00BE0FE0`
  - `BSShader::CreatePixelShader @ 0x00BE1750`
  - shader binding / `SetShaders`
- use an external side table keyed by native shader object pointer;
- never resize native shader objects by default;
- detect Fallout Shader Loader and NVR/TESReloaded;
- chain or disable when hook ownership is unsafe;
- log each native shader replacement decision.

Expected implementation model:

- when vanilla creates a shader, record name/path and native handle;
- if a Psycho replacement exists, create a replacement D3D shader;
- during `SetShaders`, bind replacement handles and constants;
- restore/chain cleanly.

This layer should be disabled by default until tested with common graphics mod
combinations.

### Stage 6: PBR-Like Material Work

Goal:

- move beyond fullscreen post effects into material lighting.

Reality:

- true PBR is not possible as a simple post-process;
- FNV does not provide a modern G-buffer;
- full deferred PBR would require much larger render architecture changes;
- a practical first version is native material shader replacement for selected
  shader families.

Initial scope:

- terrain/static geometry lighting shaders;
- normal/spec/gloss interpretation;
- optional roughness/metalness conventions from extra textures;
- physically-inspired lighting, not a full physically correct deferred renderer.

Compatibility:

- opt-in only;
- disable if NVR/TESReloaded owns the same material shader path unless a tested
  compatibility mode exists;
- keep screen-space AO/godrays usable without PBR.

## Research Work Still Needed

Because the compatibility target is stricter than TESReloaded's target, the next
research is about safe attachment and data contracts, not about proving that
TESReloaded's concepts work.

### Script: Effect Phase Contract

Proposed script:

- `analysis/ghidra/scripts/graphics_fnv_effect_phase_contract_audit.py`

Questions:

- What is the safest callable/hookable boundary before
  `ProcessImageSpaceShaders`?
- Can we draw to the current render target after post-depth groups without
  colliding with DepthResolve?
- Where exactly are fog/image-space effects applied?
- Is there a stable boundary after first-person composition but before vanilla
  final image-space?
- Which callsites are already used by DepthResolve/Shader Loader/NVR?

### Script: Sun/Weather/Fog Layout Contract

Proposed script:

- `analysis/ghidra/scripts/graphics_fnv_sun_weather_layout_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_weather_fog_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_camera_matrix_contract_audit.py`

Questions:

- exact `Sky` singleton and `Sky::sun` layout;
- sun node local/world transform fields;
- fog color/start/end/power source;
- weather transition/current weather fields;
- game time source;
- camera matrix/frustum fields at each phase.

Follow-up scripts now needed:

- `analysis/ghidra/scripts/graphics_fnv_fog_weather_deep_field_audit.py`
  - search real string/ref callsites for fog/weather fields;
  - prove weather blend/current weather object and fog near/far/color accessors.
- `analysis/ghidra/scripts/graphics_fnv_camera_near_far_frustum_audit.py`
  - prove camera near/far offsets;
  - prove frustum and projection fields separately from camera position vectors.
- `analysis/ghidra/scripts/graphics_fnv_environment_contract_followup_audit.py`
  - follow `FUN_0050F9A0`, `FUN_0063F790`, `FUN_005822A0`,
    `FUN_00532FF0`, `FUN_006447D0`, `FUN_0044EDB0`, and `FUN_006838B0`;
  - decompile callers to `SetCameraDepthValues_00C52020`;
  - prove the object that owns weather slots, transition percent, and fog
    fields;
  - prove whether `param_4 + 0xFC/+0x110` or camera fields are usable as a
    shader-facing near/far/frustum source.

Completed fog-property scripts:

- `analysis/ghidra/scripts/graphics_fnv_scene_fog_property_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_bsfogproperty_layout_audit.py`

They prove the active scene index, shadow scene node array, scene-node
`+0x134` fog-property pointer, `BSFogProperty` vtable, object size, and the
float fields used by AO fog fade. They do not prove fog color or a full
weather/environment constant block.

### Runtime Telemetry

Add logs/debug views for:

- active phase;
- current render target and scene-pre source texture size/format;
- depth texture availability;
- world/first-person depth state;
- camera near/far/FOV;
- fog start/end/power/color;
- sun direction and projected UV;
- detected graphics mods;
- disabled feature reason.

## Compatibility Matrix To Test

Minimum runtime combinations:

- vanilla only;
- xNVSE only;
- Fallout Shader Loader;
- DepthResolve;
- Vanilla Plus AO;
- NewVegasReloaded/TESReloaded;
- ReShade/ENB-style D3D9 wrapper;
- DXVK/Proton without those graphics mods;
- DXVK/Proton with common graphics mods.

Minimum visual scenes:

- foggy exterior with far mountains;
- bright desert noon;
- sunset/sunrise with visible sun;
- interiors;
- first-person weapon near walls;
- water/refraction;
- vanilla depth of field;
- menus/Pip-Boy;
- alt-tab/reset path.

## Immediate Next Code Milestone

Do this first:

1. Add shader `phase` metadata.
2. Keep existing final hook for final passes.
3. Add one pre-image-space scene phase using the safest proven boundary.
4. Move AO/contact AO into that phase.
5. Keep CAS/FXAA in final phase.
6. Add phase/depth/fog debug logging.
7. Do not add native shader replacement yet.
8. Do not patch first-person depth clear.
9. Do not patch DepthResolve-owned addresses.

Expected result:

- AO no longer draws as dark lines over solid far fog;
- final sharpening/AA still behaves like current post-processing;
- other graphics mods are less likely to break because the invasive layer is not
  enabled.

## Final Direction

Psycho should become a phase-aware graphics runtime first and a native shader
replacement system second.

The correct order is:

1. phase-aware fullscreen effects;
2. fog/camera/environment constants;
3. screen-space godrays;
4. optional native shader replacement;
5. optional PBR-like material shaders.

This keeps the useful features available to broad mod setups while reserving
the risky material-layer work for explicit compatibility-gated modes.

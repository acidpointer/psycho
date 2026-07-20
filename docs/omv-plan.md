# OMV Research And Implementation Plan

Date: 2026-06-08

This document records the current research state and implementation plan for
`omv`. The target is not another final-frame post-processor. The
target is a graphics layer that can run early enough in the FNV render pipeline
to cooperate with vanilla fog/image-space effects, while remaining compatible
with other graphics mods.

## Primary Goal

`omv` must support deeper graphics features than the current
screen-space final pass:

- ambient occlusion that is composed before vanilla fog/image-space effects;
- sunshafts/godrays using real game sun, camera, fog, and weather data;
- future material-level work for PBR-like rendering;
- live shader loading and configuration without breaking other graphics mods.

The hard requirement is compatibility. TESReloaded/NewVegasReloaded is trusted
prior art and is time proven, but OMV must not blindly copy its invasive
patching model. We should reuse the ideas and avoid the compatibility hazards.

## Current Problem

The current AO path is applied after the game's image-space pipeline. That makes
AO darken already-fogged pixels. In far fog this produces visible dark shadow
lines over a solid fog color, which looks like a ReShade overlay rather than a
real engine effect.

Current hook path:

- `omv/src/fnv_render.rs`
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

## Current OMV Implementation Baseline

### Hooks

`omv/src/fnv_render.rs` installs three hooks:

- `0x00B55AC0` - `ImageSpaceManager::ProcessImageSpaceShaders`
- `0x00873200` - `Main::RenderWorldSceneGraph`
- `0x00875110` - `Main::RenderFirstPerson`

Current behavior:

- after `RenderWorldSceneGraph`, OMV resolves world depth and captures world
  color;
- after `RenderFirstPerson`, OMV resolves first-person depth;
- at the start of `ProcessImageSpaceShaders`, OMV draws
  `scene_pre_image_space` passes into the vanilla source `BSRenderedTexture`
  before vanilla image-space effects consume it;
- after `ProcessImageSpaceShaders`, OMV draws `scene_post_image_space` and
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

`omv/src/backend/fnv.rs` currently resolves the active D3D depth
surface using INTZ/RESZ:

- D3D device is read from `NiDX9Renderer::singleton @ 0x011C73B4`.
- Camera pointer is read from `BSShaderManager::pCurrentCamera @ 0x011F917C`.
- Near/far are read from camera offsets `0xEC` and `0xF0`.
- World and first-person depth textures are stored separately.

Important: OMV's depth chain is independent from DepthResolve. This is good
for compatibility and should remain true.

### Runtime Shader Model

`omv/src/runtime.rs` currently treats every shader as the same kind
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

- OMV should not require DepthResolve's
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
That may be valid for NVR, but it is not compatibility-first. OMV should keep
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
the concept works, but we still need a safe OMV data contract before shipping
code that dereferences game memory and advertises compatibility.

Current sunshafts runtime finding:

- the previously deployed `09_sunshafts_lite` was not tracked in the repo. It
  survived because `build_fnv.sh` copies current shader files over the target
  directory but does not delete old shader files;
- that shader did not auto-detect the sun. It used manual screen UV sliders at
  `c4.xy`;
- the shader read its third option block from `c6`, but OMV reserves `c6` for
  environment constants. Its TOML wrote `sun_sample_px` and `glare_radius` to
  `c7`, so the shader was reading fog data where it expected sunshafts options;
- the tracked interim `09_sunshafts_lite` fixed the option register to `c7`,
  previously kept manual sun UV sliders as a fallback, and exposed a debug mask
  that shows sun visibility, source brightness, and radial light;
- CPU-fed sun constants are now implemented after the deeper audit. Runtime
  screenshots confirm that sun positioning is correct;
- the first CPU-sun shader technically worked but had unacceptable quality:
  hard low-sample bands, giant additive glare, and ugly screen-space silhouettes
  when the full scene color was treated as radial source data;
- the next stronger CPU-sun shader failed runtime testing. It still behaved like
  a broad additive sky haze, not an occlusion shaft model. The direct causes:
  - `ReceiverMask()` allowed at least `0.52` on solid world pixels;
  - first-person pixels were only attenuated to roughly `0.46..0.72`, so the
    weapon/hand received the additive shaft color and looked transparent;
  - `RadialShaft()` sampled only world `SkyMask`, so first-person depth could
    never cast into or block the shaft path;
  - the source term was not constrained tightly enough around the sun, so bright
    sky/fog became a large full-screen wash.
- the following single-pass shader was still the wrong architecture. It used:
  - CPU-projected sun UV from `c8`;
  - a sun-local emitter mask from bright open sky near the sun;
  - world depth and first-person depth as blockers in every radial tap;
  - a hard first-person receiver reject so weapon/hand pixels keep their
    original color;
  - fog-only limited receiving on solid world pixels;
  - compressed/clamped energy so the `Force` slider cannot create the previous
    full-screen white/gold plate.
- Runtime testing then exposed an anchor-dot failure: first-person depth crossing
  the projected sun point stopped most shafts because sun visibility and source
  sampling both used the same first-person-aware sky mask. The shader now splits
  that contract:
  - `SourceSkyMask` is world-depth-only and decides whether the sun source exists;
  - `PathOpenMask` includes first-person depth and attenuates individual ray
    taps;
  - `ReceiverMask` still hard-rejects current first-person pixels;
  - `SunCoreRepair` adds a tiny sky-only core around the CPU sun UV to cover the
    native dark sun/glare dot without drawing a large disk.
- Runtime testing after the shaft-strength follow-up exposed the real
  architectural failure: first-person silhouettes were stamped repeatedly along
  the ray path, producing a low-sample "slideshow" rather than soft shafts.
  This was caused by trying to solve a multi-buffer effect inside the generic
  single-pass shader path. That path is now considered invalid for sunshafts.
- `09_sunshafts_lite` now runs in `scene_post_image_space`, so it is composed
  after vanilla image-space but before OMV final passes such as bloom/AA.
  This is closer to a lighting contribution than a final overlay.
- `.research/soc_shaders` contains a strong S.T.A.L.K.E.R. SoC reference
  implementation in `shaders/r2/_sun_shafts.h`, `shafts.h`, and
  `_shafts_config.h`. Its useful transferable ideas are GPU-Gems-style radial
  sampling, sun-distance exposure fades, low-luminance boost, high-luminance
  compression, sun-color/halo contribution, and composing before final
  bloom/combine. Its 100-160 sample paths and multiple engine textures are not
  appropriate for the current OMV single-pass `ps_3_0` full-resolution path.
- The current OMV variant no longer treats sunshafts as a normal live
  screen-space shader. `09_sunshafts_lite.hlsl` is only a config/menu anchor;
  the actual effect is a named engine-side runtime pipeline in
  `omv/src/effects/sunshafts.rs`.
- The engine-side pipeline owns the missing SoC-like buffers:
  - half-resolution source/occlusion mask render target;
  - half-resolution radial accumulation render target;
  - half-resolution blur ping-pong render target;
  - final full-resolution compose pass.
- The internal mask shader separates source availability from ray-path
  openness: world depth decides whether sky/sun source exists, while
  first-person depth only blocks individual ray taps. This prevents weapon/hand
  depth from hiding the whole sun source.
- The internal radial shader accumulates the low-resolution mask with a fixed
  multi-sample ray march and SoC-style decay near/above `1.0`, then the blur
  stages smooth the discrete taps before compose. This is the engine-side
  structure needed to avoid repeated first-person silhouette stamps.
- The compose pass samples the blurred shaft buffer, applies receiver gating
  from world/first-person depth, and keeps sun-core repair separate from ray
  energy so tuning rays does not recreate a giant additive sun plate.
- Latest runtime tuning confirms the multi-pass path can produce smooth shafts,
  but also exposed three SoC-parity issues:
  - exact projected sun-center classification still leaked as a visible dark
    dot and could make the effect disappear when the weapon/hand crossed that
    one pixel;
  - visible sun radius changed too sharply with look angle because source
    strength still partially depended on the native rendered sun/glare pixel;
  - power lines and other thin geometry could blink the shafts because one
    closed radial tap decayed the remaining accumulation too hard.
- The current follow-up removes that exact-center dependency:
  - source/compose visibility now use CPU sun availability plus smooth
    screen-edge fade, not depth classification at the exact sun point;
  - world and first-person depth are ray-path and receiver masks only; they do
    not decide whether the sun exists globally;
  - the procedural sun source dominates over scene brightness, so native sun
    sprite/glare size no longer drives shaft source diameter;
  - sun-core repair no longer requires the exact native sun pixel to classify
    as endpoint sky, but it is constrained to sky/far-depth surfaces and still
    refuses to repaint first-person or nearby opaque world pixels;
  - radial accumulation uses more half-resolution taps and a less binary
    blocked-decay curve so thin wires attenuate shafts instead of instantly
    killing the whole light chain.
- User in-game tuning was used as the new baseline rather than the earlier bad
  defaults: intensity around `0.34`, exposure around `0.52`, force around
  `2.05`, decay around `1.005`, density around `1.08`, wider sun sampling, and
  softer occlusion. This is intentionally closer to SoC's broad, smooth shaft
  feel while staying within OMV's current buffer contract.
- Remaining gap against SoC: OMV still does not have SoC's material/alpha
  buffers, weather sun color, cloud mask, dust/noise textures, or shadow-map
  sun visibility. Those require new engine-side contracts before shader work.

Current Blooming HDR runtime finding:

- The deployed `07_blooming_hdr_lite` was another stale shader that was not
  tracked in the repo. It was a compact single-pass ReShade/AstrayFX-inspired
  port with only the center pixel plus four neighbor samples. That is cheap,
  but it cannot create broad atmospheric bloom; it mostly creates local
  highlight softening.
- The current implementation treats `07_blooming_hdr_lite.hlsl` as a
  config/menu anchor. The actual effect is a named engine-side final-image
  pipeline in `omv/src/effects/blooming_hdr.rs`.
- The Blooming HDR pipeline owns the missing buffers:
  - quarter-resolution bright/atmosphere extraction target;
  - quarter-resolution blur ping-pong target;
  - final full-resolution HDR compose pass.
- The extraction pass combines soft bright-threshold bloom with a restrained
  midtone atmosphere term. This is intentionally not physically strict: for
  Fallout NV, the goal is dusty post-apocalyptic mood and retro cinematic glow,
  not modern camera realism.
- Bloom exposure, lift, warm/cool tint, saturation, and blend controls shape
  only the Bloom branch. They do not grade the untouched scene base. The
  separate `Color Grade and Film` config owns full-frame exposure/color/film
  response and is fused into this compose draw when enabled.
- The fused compose attenuates Bloom over first-person pixels, preserves source
  alpha, applies the selected original OMV 32-cube LUT with display-referred
  trilinear sampling, and optionally adds flat-region debanding, grain,
  vignette, and Bloom-derived halation. It does not add adaptive exposure or a
  second tonemapper after vanilla image-space processing. See
  `docs/graphics_fnv_color_grading.md` for the exact phase, ABI, LUT,
  redistribution, quality, and performance contract.
- This is still intentionally cheap: the expensive blur work happens at
  quarter resolution with two separable 9-tap passes, instead of full-screen
  wide sampling or a deep bloom mip chain.

Current sunshaft daylight contract:

- `Sky::sun` projection alone is not a valid sunshaft enable signal. Runtime
  testing proved that a night celestial object can still project through the
  same path, producing moon/night shafts.
- `SunFrame` now gates availability through the Ghidra-proven time contract:
  `Sky + 0xEC` for current hour, with `TimeGlobals + 0x0C` only as fallback,
  and cached sunrise/sunset globals `0x011CA9E8..0x011CA9F4`. If cached values
  are not initialized, it falls back to the same climate time bytes used by
  `Sky::GetSunriseBegin/End` and `Sky::GetSunsetBegin/End`, divided by the same
  game divisor at `0x01034208`.
- These values are hour-domain values in the `0..24` range, not normalized
  `0..1` fractions. Treating them as normalized rejects normal schedules like
  `6, 8, 18, 20` and makes sunshafts fail closed all day.
- Sunshafts fail closed at night and fade smoothly during sunrise/sunset. The
  shader-side `c8.w` lane now means daylight strength, not a generic facing
  value.

Follow-up script prepared:

- `analysis/ghidra/scripts/graphics_fnv_sun_projection_deep_contract_audit.py`
- expected output:
  `analysis/ghidra/output/perf/graphics_fnv_sun_projection_deep_contract_audit.txt`
- this script traces `Sky::singleton`, current camera globals, camera basis
  copies, near/far readers, and the image-space boundary so the next
  implementation can project sun direction on the CPU without using guessed
  matrix offsets.

Follow-up result:

- `graphics_fnv_sun_projection_deep_contract_audit.txt` proves
  `Sky sun/current object getter @ 0x0045CD60` returns `Sky + 0x28`.
- Vanilla render path `0x00870BD0` checks `Sky::singleton @ 0x011DEA20`, calls
  `0x0045CD60`, calls the returned sky object's vtable `+0x04`, then calls
  `0x0045BB80`, which returns the returned `NiAVObject + 0x8C` vector. This is
  the vanilla path for the sun world vector used before image-space.
- The same audit confirms `CameraWriter_00B5E870` publishes the active camera
  and copies position/basis fields:
  - position: `camera + 0x8C/+0x90/+0x94`;
  - forward: `camera + 0x68/+0x74/+0x80`;
  - right: `camera + 0x70/+0x7C/+0x88`;
  - up is the remaining matrix column at `camera + 0x6C/+0x78/+0x84`, matching
    TESReloaded's `RenderManager::SetupSceneCamera`.
- The initial implementation now reads the sun root pointer as `Sun + 0x04`,
  reads `sunRoot + 0x8C` as world position, reads the active camera position and
  basis, reads the camera frustum at `+0xDC/+0xE0/+0xE4/+0xE8` with proven
  near/far at `+0xEC/+0xF0`, and CPU-projects sun UV.
- Runtime built-in constants now reserve:
  - `c6`: fog/environment data;
  - `c8`: sun screen data `(uv.x, uv.y, available, daylight)`.
- Shader option auto-binding skips `c6` and `c8`; `09_sunshafts_lite` keeps its
  own options on `c3`, `c4`, `c5`, and `c7`.
- If any sun/camera/frustum read fails validation, `c8.z` is `0` and the shader
  skips sunshafts for that frame. Manual sun UV sliders were removed because CPU
  sun projection is now the contract.
- Current sunshafts option layout:
  - `c3`: intensity, exposure, decay, density;
  - `c4`: force, unused, source brightness threshold, warmth;
  - `c5`: first-person occlusion, shaft falloff, reversed depth flag, debug mask;
  - `c7`: sun visibility sample radius, sun repair radius, unused, occlusion
    softness.
- `09_sunshafts_lite` debug mask is diagnostic only. When enabled, it replaces
  the final image with `(sunVisibility, receiverMask, blurredShaftLight)`, so a
  red/orange full-screen view means the mask is being visualized rather than the
  normal godray compose.

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

- OMV should not expose raw sky/weather fields directly to shaders.
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

Compatibility hazards in TESReloaded that OMV should not copy by default:

- extending `NiD3DVertexShader`/`NiD3DPixelShader` object sizes with raw writes;
- patching `0x008751C0` to stop first-person depth clear;
- broad global SafeWrite patches for unrelated graphics behavior;
- assuming exclusive ownership of native shader objects.

Ghidra-backed NewVegasReloaded contract findings:

- NewVegasReloaded source does not contain a true roughness/metalness/BRDF PBR
  implementation. Its useful material prior art is native shader replacement,
  screen-space specular, wet/snow accumulation, water Fresnel/refraction, and
  TESR-style camera/environment constants.
- `graphics_fnv_nvr_shader_replacement_contract_audit.txt` proves NVR's shader
  object layout patches target vanilla allocation sizes:
  - `BSShader::CreateVertexShader @ 0x00BE0FE0` allocates `0x3C` bytes at the
    `0x00BE1690` immediate;
  - `BSShader::CreatePixelShader @ 0x00BE1750` allocates `0x30` bytes at the
    `0x00BE1DFB` immediate.
- OMV must not copy those allocation-size patches for the compatibility
  target. Store replacement metadata in side tables keyed by native shader
  object pointer.
- `BSShader::SetShaders @ 0x00BE1F90` is a valid draw-time bind point. Its
  disassembly reads `NiD3DPass @ 0x0126F74C`, then uses pass `+0x5C` as the
  vertex shader and pass `+0x44` as the pixel shader.
- `0x0126F74C` is current-pass scratch state with many writers. It is usable
  only during the draw hook and must not be cached outside that call.
- `0x011F91E0` is not always a stable `NiGeometry*`. One audited path,
  `FUN_00B651E0`, writes it to a stack object (`&uStack_34`). Any material
  context read from this global must be optional and validated by pointer range,
  vtable, and expected fields before use.
- `graphics_fnv_native_material_draw_contract_followup_audit.txt` sharpens this:
  `FUN_00B63320` stores a real caller-provided material/geometry context and
  reads count-like byte `+0x09`, pointer slot `+0x0C`, and vtable method
  `+0xDC`, but `FUN_00B651E0` stores a stack proxy and uses shader mode ids
  `0x25A/0x259/0x25B`. Native material replacement must skip or separately
  classify these proxy modes.
- `SetShaderPackage @ 0x00B4F710` writes shader package globals
  `0x011F91BC/0x011F91C0`, and many shader setup paths read them. NVR forcing
  package `7` is a global behavior change; OMV should not do this in default
  mode.
- `NiDX9RenderState::SetSamplerState @ 0x00E910A0` uses TypeMap
  `0x0126F92C` and tracks only mapped states with index `< 5`. Extra PBR
  samplers/textures need explicit capture/restore when they are outside the
  engine backup table.
- `graphics_fnv_native_texture_binding_contract_audit.txt` proves sampler writes
  reach the D3D device through render-state object `+0x10F8` and D3D vtable
  slot `+0x114`.
- `graphics_fnv_native_texture_stage_state_followup_audit.txt` proves
  texture-stage state uses separate TypeMap `0x0126F958` with mapped indices
  `< 8`. `FUN_00E88930` calls the D3D device through render-state object
  `+0x10F8` and vtable slot `+0x10C`, then caches values under render-state
  `+0xA20`; the inline getter at `0x00E88980` reads that cache. `FUN_00E88FC0`
  and `FUN_00E89060` manage the engine backup/current stage-state slots at
  `+0x0C/+0x3C` with flags at `+0x2C/+0x5C`.
- The broad device-method scans in the texture scripts are not strong proof by
  themselves because many ordinary engine structs also have fields at
  `+0x104/+0x10C/+0x114`. Use the decompiled render-state functions as the
  contract.
- `graphics_fnv_nvr_environment_color_contract_audit.txt` proves the weather
  controller is the `0x138` object at `0x011CCB78`, `GetCurrentWeather`
  returns `controller +0x10`, `CurrentWeatherPercent` reads `controller
  +0xF4`, and `Sky::singleton @ 0x011DEA20` remains the render-owned sky
  object source.
- The same audit proves vanilla weather color/range blending is not the simple
  NVR source recipe of `Sky::firstWeather`, `secondWeather`, `weatherPercent`,
  and `TESWeather::colors[10] @ +0x108`. `FUN_00532220` blends generated
  weather records through object slots like `+0x114 + index*0x30`,
  `+0x504`, `+0x534`, `+0x60C`, optional fallback flags at `+0xE8/+0x100`,
  and downstream setters `0x00B8AF10/0x00B8AFB0/0x00B8B000/0x00B8B0D0`.
  OMV should not reproduce NVR's raw weather color walk for compatibility.
- `graphics_fnv_native_render_state_fog_color_contract_audit.txt` proves
  renderer-owned final fog color. `NiDX9RenderState::SetFog @ 0x00E87C50`
  writes the final fog color into `NiDX9RenderState +0x8C/+0x90/+0x94`, packs
  it into `+0x98`, and sends it through `SetRenderState(0x22,
  D3DRS_FOGCOLOR)`. `GetRenderState @ 0x00E88860` reads the packed cache at
  `+0x120 + state*8`, so `+0x8C/+0x90/+0x94` is the cleaner normalized
  `PSY_FogColor` source.
- `graphics_fnv_native_sun_light_contract_audit.txt` is a partial sun contract,
  not a final material-lighting contract. It proves `Sky sun/current object
  getter @ 0x0045CD60` returns `Sky +0x28`, and the world render path
  `FUN_00870BD0` uses that object to compute a downstream screen-space sun
  value written by `FUN_00B8B1E0` into globals `0x012023F4/0x012023F8`.
  Treat those globals as projected/screen sun data only.
- The same sun-light audit does not prove `Sky +0x6C`, `Sun +0x1C`,
  `Main +0x1C`, `NiDirectionalLight +0xD4`, or `NiDirectionalLight +0xF0`.
  At that point those fields remained NVR-source candidates, not native
  compatibility contracts; later alias/provenance audits reject the
  `Sun +0x1C/Main +0x1C` path for default PBR.
- `graphics_fnv_native_sun_light_deep_contract_audit.txt` closes some of the
  missing native sky/update contract but still does not close final sun color.
  `Sky update downstream candidate @ 0x0063A630` destroys/replaces
  `Sky +0x28` and constructs the sun object through `FUN_006404F0`, so the
  `Sky +0x28` ownership path is now stronger.
- `graphics_fnv_native_sun_color_direction_followup_audit.txt` proves
  `0x012023F4/0x012023F8` are screen-space sun coordinates, not color or
  direction. `FUN_00B8B1E0` copies X/Y from its input vector, `FUN_00C03410`
  and raw code near `0x00C03363` pass them into `FUN_00B8A790`, and the
  previously unknown writer near `0x00FBAE5B/0x00FBAE60` only restores defaults
  from `0x011F4980/0x011F4984`.
- The same follow-up proves `FUN_0063BCE0` writes `Sky +0xD4/+0xD8/+0xE8` as
  fog/range/power-style fields, not sun color. The direct helpers return
  `weather +0x114` and `weather +0x118`; the interior/exterior path calls
  active fog near/far/power helpers; and the time blend path reads scalar table
  entries at `weather +0xF0 + index*4`.
- `FUN_0063C690` is not a final sun-color source for PBR. In the audited sky
  update it is called with `Sky +0x48`, so it writes a sky/weather vector slot
  distinct from NVR's claimed `Sky +0x6C sunDirectional`.
- `FUN_00532220` blends generated/weather records and feeds downstream setters
  `0x00B8AF10/0x00B8AFB0/0x00B8B000/0x00B8B0D0`, which cache values under
  object fields like `+0x25C`, `+0x264`, `+0x26C`, and `+0x2A4`. That is
  useful weather pipeline evidence, but it is not a shader-facing native sun
  color contract.
- The Reloaded header claim that `Sun +0x1C` aliases `Main +0x1C
  directionalLight`, and the `NiDirectionalLight +0xD4/+0xF0` color/direction
  offsets, entered the alias follow-up as source-level candidates only. That
  follow-up decompiled the sun constructor `FUN_006404F0`; it sets the Sun
  vtable and initializes fields but does not prove the `+0x1C` alias.
- `graphics_fnv_native_directional_light_alias_audit.txt` pushes that further:
  the Sun vtable at `0x0104F298` has four valid code entries
  (`0x00640670`, `0x007FA950`, `0x00640810`, `0x00641830`); slot `+0x10` and
  beyond are adjacent `D:\_Fallout3\...\Sun.cpp` string bytes, not methods.
  References to the Sun vtable are only the constructor `FUN_006404F0` and
  destructor/reset helper `FUN_006406A0`.
- The same alias audit proves `FUN_00633C90` and `FUN_0066B0D0` are managed
  reference-slot helpers: initialize/assign a pointer, release the old value,
  and addref the new value. The Sun constructor initializes ref slots
  `+0x08/+0x0C/+0x10/+0x14/+0x1C/+0x28`, assigns null into
  `+0x04/+0x08/+0x0C/+0x10/+0x14/+0x1C`, zeros `+0x18/+0x20/+0x24`, and then
  stores an allocated `0x280` object into `+0x28`. This proves `Sun +0x1C` is
  a managed object reference slot, not a raw directional-light constant by
  layout alone.
- `FUN_006FB3D0` treats `param_1 +0x1C` and `param_1 +0x20` symmetrically as
  owned object references to remove/release/clear. That is generic ref-slot
  cleanup evidence, not proof that `Main +0x1C` is the renderer directional
  light or that it aliases `Sun +0x1C`.
- `graphics_fnv_native_sun_refslot_writer_provenance_audit.txt` rejects the
  `Main +0x1C` alias path for this executable contract. `FUN_0044FB20` is the
  Main/TES constructor candidate, but its decompiled `param_1 +0x1C/+0x1E`
  fields receive allocated pointer tables and are then zero-filled in loops.
  They are not a directional-light object. The supposed Main/TES vtable address
  `0x010724E8` is adjacent string/data passed into construction code, not a
  vtable.
- The same provenance audit reinforces `Sky +0x28` as the real Sun object
  source. `FUN_0063A630` constructs/replaces `Sky +0x20`, `Sky +0x24`,
  `Sky +0x28`, and later sky fields; `Sky +0x28` is constructed through
  `FUN_006404F0`. This path does not involve `Main +0x1C`.
- `FUN_00640810`, the Sun vtable slot 02 setup/update method, maps the Sun
  managed slots by writer: `+0x10/+0x14` receive objects from `FUN_00A74410`,
  `+0x08/+0x0C` receive objects from `FUN_0051CF00`, `+0x1C` receives an
  object from `FUN_00A75C20`, and `+0x28` is created in the constructor through
  `FUN_00B660D0`. No observed writer assigns `Main +0x1C` into `Sun +0x1C`.
- The constructors and raw scans still do not prove `NiLight +0xD4` diffuse
  color or `NiDirectionalLight +0xF0` direction. The `d4/f0` hits in the Sun
  update output are stack locals or unrelated values, not stable native light
  fields.
- The alias audit's targeted scans found no matching `Sky` singleton or Sun
  vtable references that prove light fields, and no proven reads of
  `NiLight +0xD4` diffuse color or `NiDirectionalLight +0xF0` direction from an
  aliased native object. `PSY_SunDirection` should continue to use the already
  proven sky sun root/projection path; `PSY_SunColor` should remain unavailable
  or conservative until a real renderer-owned light color source is proven.
- Conclusion for OMV PBR: close the Reloaded `Sun +0x1C/Main +0x1C`
  directional-light alias path. Do not use `Sun +0x1C`, `Main +0x1C`,
  `NiLight +0xD4`, or `NiDirectionalLight +0xF0` as default material constants,
  and do not spend more scripts chasing that alias unless a different executable
  proof appears.
- `TESR_SunColor` as a Reloaded-style persistent environment constant remains
  unsuitable for default native material lighting. NewVegasReloaded computes it
  from raw `TESWeather::colors[eColor_Sun]`, while OMV should prefer
  renderer-owned draw-time light data when native material replacement is
  active.
- `graphics_fnv_final_sun_color_renderer_contract_audit.txt` proves the final
  renderer-owned light constant path, but not a phase-stable global sun color.
  `FUN_00B7E430` registers `LightColors` at `0x011FA0D0` and `Light
  Direction`/`LightData` at `0x011FD9A8`; `FUN_00BD3000` registers
  `Ambient Color`, `Diff Color 0/1`, `DirectronalLightDir`, `PointLightPos`,
  and `LightRadius`; `FUN_00BD5A60` registers `Diffuse Light direction` and
  `Diffuse Light color` from shader-object fields.
- The same renderer audit finally proves `NiLight +0xD4/+0xD8/+0xDC` as a real
  diffuse-color input in the native light-list path. `FUN_00B70820` computes
  `0x011FA0D0` light colors from light fields, dimmer `+0xC4`, radius/intensity
  data, and per-draw attenuation; `FUN_00B78A90` walks the active light list,
  fills `0x011FD9A8` direction/position vectors, and updates shader constant
  counts through cached handles like `DAT_011FEC38`.
- For OMV this is a draw-time material-lighting contract only. The globals
  `0x011FA0D0` and `0x011FD9A8` are renderer-owned per-draw arrays that can be
  consumed or mirrored only inside validated material/shader draw hooks. They
  must not be exposed as persistent `PSY_SunColor`/`PSY_SunDirection`, and they
  do not resurrect the rejected `Sun +0x1C/Main +0x1C` Reloaded alias.
- `graphics_fnv_material_texture_property_contract_audit.txt` proves the
  high-level `BSShaderPPLighting` material setup branch, but not the final mesh
  texture slot layout. `FUN_00BDF790` reads shader flags from `param_1[8]` and
  `param_1[9]`, uses `FUN_00A59D30` to walk the geometry property list by
  virtual property type, falls back to `param_2 +0x9C`, and tests property
  flags at `+0x18` including bit 0 and bit 9.
- The material audit also proves `FUN_00BA9EE0` is a pass-entry/state builder,
  not a texture-discovery function. `FUN_00BD9F90` emits pass ID `4` or `5`,
  and `FUN_00BDF790` calls it only when shader object `param_1[0x37]`
  (byte offset `+0xDC`) exists and that object has nonzero `+0x6C`. That is the
  next concrete texture/material contract gap: identify the `+0xDC` object,
  its ownership, and whether its fields map to diffuse/normal/glow/specular or
  some other material resource.
- Separate landscape/record code proves `BGSTextureSet`-style slot validation
  through a virtual getter at `TextureSet +0x30 -> vtable +0x8C` for diffuse
  slot `0` and normal slot `1`, and `FUN_0046E910` enumerates named maps such
  as `Detail Map`, `Bump Map`, `Glow Map`, `Gloss Map`, `Dark Map`, and
  `Decal Map`. Those are useful source-material clues, but they are not yet a
  draw-time mesh PPLighting texture binding contract for PBR.
- `graphics_fnv_material_texture_slot_layout_followup_audit.txt` strengthens
  the source material/texture-set side. `FUN_00A6B410` initializes canonical
  map names: `Base`, `Dark`, `Detail`, `Gloss`, `Glow`, `Bump`, `Normal`,
  `Parallax`, `Decal`, and `Shader`. The named map accessors prove record-side
  slot IDs: `Dark=1`, `Detail=2`, `Gloss=3`, `Glow=4`, `Bump=5`, and
  `Decal=index+8`, all through `FUN_00877A30`, which returns the address of
  4-byte slot storage at `*(TextureSet+4) + slot*4` rather than the texture
  object itself. Texture-set count is at `+0x0A` (`FUN_00658930`), while cleanup
  clears indexed slot storage and zeroes the count/capacity fields around
  `+0x0A/+0x0C`. `FUN_0046E910` enumerates those maps recursively over geometry
  and calls `FUN_0046E8E0`, which routes existing maps through `FUN_005585E0`
  and `FUN_00653270(&DAT_011F444C, ...)`.
- `graphics_fnv_pplighting_texture_runtime_binding_followup_audit.txt` closes
  part of the runtime setup contract, but not the writer provenance. Seven
  vtable/data windows pair `FUN_00BDB4A0` immediately before `FUN_00BDF790`
  across PPLighting-like shader-property classes including SpeedTree and Beam
  variants. `FUN_00BDB4A0` uses byte offset `+0xDC`; `FUN_00BDF790` uses the
  same field as `param_1[0x37]`. In both setup variants, `+0xDC+0x6C` gates
  `FUN_00BD9F90`, and nonzero `+0xDC` gates the late branch. `FUN_00BD9F90`
  emits pass IDs `4/5`; `FUN_00BDC030` emits pass IDs `0x250/0x251`.
- `graphics_fnv_pplighting_dc_field_writer_provenance_audit.txt` proves the
  first vtable-provenance attempt was too broad. Ghidra reports zero refs to
  the previously assumed PPLighting-like vtable starts and zero refs to their
  setup-slot addresses; refs to `FUN_00BDB4A0` and `FUN_00BDF790` remain
  data-only vtable entries. Broad writers like `FUN_00B5E0F0`/`FUN_00B5AAC0`
  are therefore not proven `BSShaderPPLighting +0xDC` writers, but the audit
  exposes the real B-range constructor cluster at
  `FUN_00539960 -> FUN_00B66F50`.
- `graphics_fnv_pplighting_brange_constructor_dc_deep_audit.txt` closes that
  B-range object contract. `FUN_00B66F50` constructs the `0x104` shader-property
  object and assigns vptr `0x010AE0D0`. The earlier addresses such as
  `0x010AE1B8` are not true object vtable starts; they are method-table slices
  inside the same table, with `FUN_00BDB4A0`/`FUN_00BDF790` later in that vtable
  at `0x010AE1E4/0x010AE1E8`. `FUN_00B66F50`, `FUN_00B67380`,
  `FUN_00B675C0`, and `FUN_00B676A0` prove refcounted ownership, setter,
  destructor, and copy semantics for byte offset `+0xDC`.
- The same B-range audit identifies `+0xDC` as `spTexEffectData`, not material
  texture data. `FUN_00B690D0` serializes that field under the exact
  `spTexEffectData` name and reads Fill Color fields at `+0x0C..+0x18`, Edge
  Color fields at `+0x1C..+0x28`, and Edge Falloff at `+0x54`. Therefore
  `+0xDC`, `+0xDC+0x6C`, pass IDs `4/5`, and pass IDs `0x250/0x251` are special
  texture-effect branches. They must not be used as roughness/metalness or
  general PBR map discovery.
- The useful runtime texture lead is now the six texture pointer arrays owned by
  the same object: count `+0xA8`, arrays `+0xAC`, `+0xB0`, `+0xB4`, `+0xB8`,
  `+0xBC`, and `+0xC0`, and byte flag arrays `+0xC4/+0xCC`. `FUN_00B68660`
  fills those arrays by calling the source texture provider virtual at `+0x90`
  for each of six array kinds, while `FUN_00B66640` initializes nine per-layer
  flags at `+0xC4` for landscape texturing. `FUN_00B690D0` labels the arrays as
  base/diffuse, normal, glow or skin/hair layer, heightmap, envmap, and envmap
  mask on the serialization path. This proves runtime slot layout, but not yet
  final draw-time D3D stage ownership.
- `FUN_00BC3E40` is an additional non-vtable caller of `FUN_00BD9D00`, but it
  only runs when `+0xDC`/`spTexEffectData` is nonzero. It does not change the
  material texture contract for PBR.
- `graphics_fnv_pplighting_texture_array_stage_binding_audit.txt` corrects the
  remaining six-array hypothesis. `FUN_00B70590`, `FUN_00B70600`,
  `FUN_00B70680`, `FUN_00B70700`, and `FUN_00B707D0` are active object/list
  iterators over `this +0x60`, not iterators over the texture arrays at
  `+0xAC..+0xC0`. They filter list objects by `object +0x110 != 0xFF` and by a
  property flag at `*(object +0xF8) +0x30`; the `B70600`/`B70700`/`B707D0`
  variants also exclude objects with byte `+0xEC == 1`.
- In the same audit, the only high-level direct six-array draw-setup use found
  in `FUN_00BDB4A0`/`FUN_00BDF790` is the first entry of `+0xB4` as a branch
  flag for glow/skin/hair-layer handling. The pass builders are driven by the
  active object iterators and branch flags, not by a direct final-stage walk of
  base/normal/glow/height/env/env-mask arrays.
- `FUN_00BDF790` has a special branch for active objects with nonzero `+0xEC`:
  it calls `FUN_00BA9EE0(param_2, 0, 1, 1, object, 0, 0, 0)`, then overwrites
  the created pass entry with IDs `0x231`/`0x232`/`0x233` and sets byte `+8`.
  This is object/pass-state construction, not a material texture slot binding.
- `FUN_00BA9EE0` is now proven as a pass-entry append/reuse helper. It reuses or
  allocates a 0x10-byte pass entry, writes the pass/mode id at `+0`, writes the
  short parameter at `+4`, writes byte `+7`, resets bytes `+6`, `+8`, and
  `+0x0B`, and delegates the remaining parameter storage to
  `FUN_00BA8C50`/`FUN_00BA8EC0`. The next texture-binding gap is therefore the
  pass-entry layout and apply path, not the PPLighting array layout.
- PBR rule from this audit: the six runtime arrays are source/runtime layout
  evidence only. A compatible OMV implementation should rely on validated
  draw-time pass state and already-bound vanilla texture stages until the
  pass-entry apply path proves exact D3D stage ownership. Do not treat
  `+0xAC..+0xC0` as a direct PBR map feed from a generic draw hook.
- `graphics_fnv_pplighting_pass_entry_apply_contract_audit.txt` closes the
  0x10-byte pass-entry storage contract. `FUN_00BA8EC0` constructs entries
  with pass/mode id at `+0x00`, short parameter at `+0x04`, byte parameter at
  `+0x07`, used vararg count at `+0x09`, capacity at `+0x0A`, and a heap
  vararg dword array pointer at `+0x0C`. `FUN_00BA8C50` is the reused-entry
  vararg setter, `FUN_00BA8CD0` releases the vararg array, and
  `FUN_00BA9EE0` is confirmed as pass-entry construction/list management only.
- The same pass-entry apply audit proves `BSShader::SetShaders @ 0x00BE1F90`
  is shader-only. It reads the current `NiD3DPass` global `0x0126F74C`, applies
  the pass pixel shader at `+0x44` and vertex shader at `+0x5C`, and does not
  bind material textures or sampler state.
- `FUN_00BD1C50` writes the current pass global and updates pass `+0x44` pixel
  shader ownership; `FUN_00BD4BA0`, `FUN_00BE2170`, `FUN_00BE21B0`,
  `FUN_00E811D0`, and `FUN_00E814B0` are pass/shader apply helpers. They are
  useful draw-context evidence, but not final material texture binders.
- Final texture-stage ownership is now anchored at
  `NiDX9RenderState::SetTexture @ 0x00E88A20`: it caches 16 texture slots at
  `renderState +0x10A0 + stage*4` and calls the D3D device vtable `+0x104`
  only when the cached texture changes. `FUN_00E88930` is the texture-stage
  state setter and `FUN_00E910A0` is the sampler-state setter. The earlier
  `0x00DA2990` D3D SetTexture lead is rejected as a diagnostics/error-report
  path, not a material draw texture binder.
- At this stage, the remaining PBR texture gap was to map the B7 pass
  dispatcher and `FUN_00E7EB00` apply path from pass-entry fields to final
  `E88A20` stage calls. Until that is proven, the compatible default is to
  observe/capture vanilla texture bindings through `E88A20` in draw scope
  rather than infer stages from PPLighting runtime arrays or pass-entry IDs.
- `graphics_fnv_pplighting_pass_dispatch_texture_stage_contract_audit.txt`
  closes the high-level B7 dispatcher shape but not the final low-level
  texture-stage mutation. `FUN_00B7DD50` applies one current-pass entry through
  `E7EB00`, then runs `B7C3A0/B7C510/B7C580/B7C600` and the current pixel
  shader constant path. `FUN_00B7DDE0`, `FUN_00B7DED0`, `FUN_00B7DFE0`, and
  `FUN_00B7E150` write current pass `+0x24` entry `+8` values from the active
  object (`param +0x0C`, object `+0xAC`, virtual `+0xE0/+0xF4`, or
  `FUN_00C03230`) and then call `E7DE90` and `E7EB00`.
- The same dispatcher audit proves the B7 helper family is mostly shader
  constant and light-data upload, not texture binding. `B7C3A0`, `B7C750`,
  `B7C7B0`, `B7C850`, and `B7CB00` write per-draw constants through the
  current vertex shader constant table (`pass +0x5C -> +0x20 -> vtable
  +0x178`) and renderer globals such as `0x011FA0C0`, `0x011FA0D0`, and
  `0x011FD9A8`. `B7C510` updates byte `+8` on shader constant/resource records
  in the `0x011FEC34..0x011FEC8C` range from the shader-mode bit table
  `0x011FC0A0`.
- `E7DE90` is now proven as a small pass-state helper that calls
  `E890C0(1, table[mode].x, 0, 0)` and `E890C0(2, table[mode].y, 0, 0)` using
  the `0x0126F0B0/0x0126F0B4` mode table. `E7EB00` is a cache/apply helper for
  pass-entry `+0x04/+0x08`: it compares entry `+8` against cache table
  `0x0126F680 + entry[+4]*4`, updates the cache, calls `E89410(entry[+4])`,
  and, if needed, calls `E7EA00`.
- `E7EB00` itself does not call `E88A20`. The script found `E88A20` only as
  data in the two render-state vtables at `0x010EF6E8` and `0x010F0968`, with
  zero references to those vtable addresses. Therefore the remaining exact
  texture gap moved down one level: prove what `E890C0`, `E89410`, and
  `E7EA00` apply, and whether any of them reach texture, texture-stage,
  sampler, or render-state device calls.
- `graphics_fnv_pplighting_render_state_lowlevel_apply_contract_audit.txt`
  closes most of that lower-level helper path. `E88FC0` and `E89060` are
  texture-stage-state tracker setter/getter helpers using the TypeMap at
  `0x0126F958`; they update/read tracked current and backup values under
  `+0x0C/+0x3C`, flags under `+0x2C/+0x5C`, and counters under `+0x04/+0x34`.
  They do not call D3D or `NiDX9RenderState::SetTexture`.
- The same low-level audit proves `E890C0` is the matching sampler-state
  tracker helper, using the TypeMap at `0x0126F92C` and storing current/backup
  values under `+0x6C/+0x90`, flags under `+0x80/+0xA4/+0xB0`, and counters
  under `+0x64/+0x88/+0xAC`. `E7DE90` therefore mutates tracked sampler-state
  records from the pass-mode table; it is not a final material texture binder.
- `E7EA00` is now proven as a downstream pass-entry apply helper, but not yet
  as a texture-stage owner. It checks tracked texture-stage state through
  `E89060`, then calls virtual slots on renderer globals:
  `DAT_0126F6C8 +0xC0/+0xDC/+0xCC`, `DAT_0126F6C4 +0x8C4 -> vtable +0x0C`,
  and, when entry type is `6`, `DAT_0126F6C0 +0x114` with
  `DAT_011A9608`. `E89410` only dispatches to `E89250` and `E892D0`. Object
  identities for `DAT_0126F6C0/4/8` are still unproven, so their virtual slots
  must not be treated as `NiDX9RenderState` or D3D calls by address similarity.
- The low-level audit again found `E88930`, `E88A20`, `E88A50`, `E88A60`, and
  `E910A0` only as vtable data refs, with no static direct calls from the
  B7/E7DE90/E7EB00 path. Immediate rule from this audit: pass-entry IDs and
  the E7 apply helpers are not a direct PBR texture map. Compatible default PBR
  should observe/capture actual vanilla texture pointers at `E88A20` in draw
  scope until the renderer-global virtual methods are identified.
- `graphics_fnv_pplighting_renderer_global_virtual_apply_contract_audit.txt`
  proves the renderer-global writer but leaves one final identity gap.
  `FUN_00E7E8D0(param_1)` sets `DAT_0126F6C4 = param_1`, moves
  `*(param_1 +0x288)` into `DAT_0126F6C0` with addref/release calls through
  vtable slots `+0x04/+0x08`, and sets `DAT_0126F6C8 = *(param_1 +0x8B8)`.
  Passing null releases `DAT_0126F6C0`, clears it, and clears `DAT_0126F6C8`.
- The same virtual-global audit proves the E7 apply helper cluster is
  resource/state application, not source-material discovery. `E7EA00` resolves
  pass-entry resource pointer `param_1[2]` through
  `DAT_0126F6C4 +0x8C4 -> vtable +0x0C`, applies it through
  `DAT_0126F6C8 +0xDC`, restores/sets stage and sampler-like state through
  `DAT_0126F6C8 +0xC0/+0xCC`, then optionally calls `E7DC90` and `E7E940`.
  For entry type `6`, it also calls `DAT_0126F6C0 +0x114` with
  `DAT_011A9608`.
- `E7DC90` conditionally uses `DAT_0126F6C4 +0xA0` flags and calls
  `DAT_0126F6C8 +0xCC` plus `+0x68`; `E7DD50` resets ranges through
  `DAT_0126F6C8 +0xDC/+0xC0`; and `E7E940` either clears state `0x18` through
  `DAT_0126F6C8 +0xC0` or uploads a transformed `0x40`-byte matrix block
  through `DAT_0126F6C0 +0xB0`. `E7DF90` builds that block at
  `0x0126F6D0..0x0126F70C` from renderer matrix fields
  `DAT_0126F6C4 +0xA40..+0xA78` and the pass input matrix.
- `E89250` and `E892D0` are now proven as the final flush helpers for the
  tracked state records created by `E88FC0` and `E890C0`: `E89250` walks eight
  texture-stage tracker slots and calls `DAT_0126F99C +0xC0` using table
  `0x0126F948`, while `E892D0` walks five sampler tracker slots and calls
  `DAT_0126F99C +0xCC` using table `0x0126F918`. The later constructor audit
  proves these virtual routes dispatch through vtable B into `E88930` and
  `E910A0`.
- `graphics_fnv_pplighting_render_state_global_identity_followup_audit.txt`
  proves both render-state globals are seeded from the same renderer field.
  `E81940` loads `*(renderer +0x8B8)` into `EDI`, calls `E7E8D0(renderer)`,
  writes `DAT_0126F99C = EDI`, then calls virtual slot `+0x100` on that same
  object. `E7E8D0(renderer)` independently writes
  `DAT_0126F6C8 = *(renderer +0x8B8)`, so `DAT_0126F99C` and `DAT_0126F6C8`
  share the exact runtime pointer during renderer setup. `E819F0` clears
  `DAT_0126F99C` after `E7E8D0(0)`, matching the shutdown/clear path.
- The same identity follow-up splits the candidate vtables. Vtable A at
  `0x010EF60C` maps `+0xC0 -> E88930` and `+0xDC -> E88A20`, but
  `+0xCC -> 0x00EC60FA`, not the sampler setter. Vtable B at `0x010F088C`
  maps `+0xC0 -> E88930`, `+0xCC -> E910A0`, and `+0xDC -> E88A20`. `E881A0`
  constructs vtable A and initializes the texture-stage/sampler TypeMaps and
  flush tables.
- `graphics_fnv_pplighting_renderer_8b8_render_state_constructor_audit.txt`
  closes the remaining texture-stage identity gap. In
  `NiDX9Renderer::Initialize` candidate `E72E60`, raw code calls
  `E91590(renderer, renderer +0x28C, 1)`, then writes the returned object into
  `renderer +0x8B8`, then immediately calls `E81940(renderer)`. `E91590`
  allocates `0x1248`, calls the vtable-A base constructor `E881A0` on the new
  object, overwrites the vptr with vtable B `0x010F088C`, copies `0x130` bytes
  of renderer/device setup data into object `+0x1118`, and calls virtual
  `+0x104` before returning the object.
- Therefore `DAT_0126F6C8` and `DAT_0126F99C` are proven vtable-B render-state
  globals during renderer setup. `E81940`'s virtual `+0x100` setup call reaches
  vtable-B target `E911E0`, not vtable-A target `E87AB0`. The renderer teardown
  path `E75A70` calls `E819F0`, releases the `renderer +0x8B8` object through
  vtable slot `+0x00`, and clears `renderer +0x8B8`.
- Final PPLighting texture contract: `E7EA00` resolves pass-entry resource
  pointer `param_1[2]` through `renderer +0x8C4 -> vtable +0x0C`, then calls
  vtable-B `DAT_0126F6C8 +0xDC`, which is
  `NiDX9RenderState::SetTexture @ 0x00E88A20`, with stage `param_1[1]` and the
  resolved texture pointer. Its `+0xC0` calls are final
  `NiDX9RenderState::SetTextureStageState @ 0x00E88930`, and its `+0xCC` calls
  are final `NiDX9RenderState::SetSamplerState @ 0x00E910A0`.
- Current PBR rule: native replacement may use vanilla-bound textures and
  renderer light constants inside `SetShaders`/draw-time scope. It must not add
  roughness/metalness discovery through `0x011F91E0`, `NiTexturingProperty`, or
  `param_1[0x37]`/`+0xDC`. Final texture-stage ownership is now proven through
  `E7EA00` and `E88A20`, but additional map semantics still need an explicit
  stage policy or observed final stage bindings; do not resurrect source-array
  or `spTexEffectData` guesses as PBR map discovery.
- `graphics_fnv_pbr_shader_interface_contract_audit.txt` proves
  `BSShader::SetShaders @ 0x00BE1F90` is only a shader-handle binder. It reads
  current pass `0x0126F74C`, calls the vertex shader object vtable `+0x84`,
  binds the returned handle through renderer helper `+0x8C`, then calls the
  pixel shader object vtable `+0x7C` and binds that handle through renderer
  helper `+0x7C`. It does not upload PBR constants, select texture stages, or
  provide a pixel-input semantic contract.
- The same PBR interface audit confirms vanilla shader object allocation
  sizes: pixel shader objects are allocated at `0x30` bytes and initialized via
  `FUN_00BE08F0`; vertex shader objects are allocated at `0x3C` bytes and
  initialized via `FUN_00BE0B30`. OMV must keep using side tables/replacement
  handles rather than extending native object layouts.
- `FUN_00BD1C50` is confirmed as the current-pass writer and pass `+0x44`
  pixel-shader ownership updater. `FUN_00BD4BA0` is the stronger PBR lead: it
  calls the B7 pass dispatcher, resolves the current geometry/proxy slot through
  `0x011F91E0`, and invokes shader-interface virtual slot `+0x78` with the
  current pass pixel/vertex shader objects plus draw context. That is the
  likely constant/interface application boundary, not `SetShaders`.
- `graphics_fnv_pbr_shader_virtual_interface_followup_audit.txt` proves
  `FUN_00B55560` is a lazy selector cache over `0x011F9548 + index * 4`.
  Selector index `1` is created by `FUN_00B7A380`; `FUN_00BD4BA0` reads this
  selector and calls its `+0x30/+0x34` shader-interface objects through virtual
  slot `+0x78`, then optionally calls the draw parameter's own
  `+0x30/+0x34` interfaces the same way. The audit also confirms
  `FUN_00B7A870` and related setup paths initialize per-effect resources and
  constants through this selector family. It still does not prove the concrete
  vtables installed into the selector's `+0x30/+0x34` fields or the exact
  `+0x78` target bodies.
- `graphics_fnv_pbr_shader_interface_object_vtable_audit.txt` proves the
  selector index `1` factory path in more detail: `FUN_00B7A380` builds four
  stage-layout objects through `FUN_00E76700`, initializes their semantic
  layouts through virtual slots `+0x8C/+0x94`, allocates an `0x8C` selector
  object, and calls `FUN_00B79B00`. The audit also tightens the shader object
  ABI: `NiD3DPixelShader` is a `0x30` object with its native handle stored at
  `+0x2C`, and `NiD3DVertexShader` is a `0x3C` object with native handles in
  the `+0x30/+0x34/+0x38` range. This is useful for replacement side tables,
  but it is still not enough to replace shaders visibly because
  `FUN_00B79B00`, vtables `0x010EF544/0x010F003C`, and the concrete
  selector-field `+0x78` bodies remain unresolved.
- `graphics_fnv_pbr_selector_object_constructor_vtable_audit.txt` proves
  `FUN_00B79B00` is a base selector constructor, not the final setup owner for
  `+0x30/+0x34`. It installs selector vtable `0x010AF2F8`, stores the factory
  stage-layout objects into selector fields `+0x28`, `+0x6C`, `+0x70`,
  `+0x74`, and `+0x78`, and leaves later selector virtual setup calls to build
  or assign shader-interface fields. The same audit proves the concrete
  `0x010EF544 + 0x78` target is `FUN_00E826D0`, a shader-interface constant
  apply dispatcher that iterates constant records and routes type-specific
  uploads through helper slots such as `+0x8C/+0x90/+0x94/+0x98/+0x9C/+0xA4`.
  This confirms the vanilla constant application family, but it still does not
  prove the selector vtable setup slots `+0x4C/+0xC0/+0x11C/+0x144/+0x150` or
  a safe shader replacement lifecycle.
- `graphics_fnv_pbr_selector_setup_vtable_deep_audit.txt` proves selector
  setup slot `+0x11C` is the final owner for the PPLighting selector
  shader-interface fields. It allocates `0x44` byte `FUN_00B7E330` objects for
  selector `+0x34` (vertex, constructor mode `0`) and `+0x30` (pixel,
  constructor mode `2`), registers the vanilla PPLighting constant records, and
  copies those pointers into `+0x88` and `+0x84`. It also builds the alternate
  `+0x80` vertex and `+0x7C` pixel interfaces. These objects use the proven
  `0x010EF544 -> 0x00E826D0` constant apply dispatcher. Slot `+0x4C` is a
  global constant/resource cache reset. Slot `+0x144` is only a wrapper around
  selector virtual `+0x148` then `+0x14C`. Ghidra did not bind functions for
  raw slots `+0xC0` (`0x00E81420`) or `+0x150` (`0x00B7A730`) in this output,
  so those remain unresolved before visible replacement.
- `graphics_fnv_pbr_selector_setup_raw_slot_followup_audit.txt` narrows the
  late selector setup contract. Raw slot `+0xC0` at `0x00E81420` is code even
  though Ghidra did not bind a function; its entry block is a ref-counted setter
  for selector `+0x28`, not shader creation. Slot `+0x144` is only a wrapper:
  call selector virtual `+0x148`, then tail-jump `+0x14C`. Slot `+0x148`
  (`FUN_00B71BF0`) is a large recognized setup function that calls
  `BSShader::CreateVertexShader @ 0x00BE0FE0` three times with `"vs_2_0"`.
  Slot `+0x150` starts by propagating global resource records through the
  selector family and then calls many `BE/BF/C0` setup helpers; adjacent helper
  `FUN_00B7A870` copies selector `+0x30 -> +0x7C` and `+0x34 -> +0x80` for
  selector indices `1`, `0xE`, `0xF`, and `0xD`. Raw slot `+0x14C` begins a
  very large setup function that Ghidra still did not bind/decompile; nearby
  unknown calls to `BSShader::CreatePixelShader @ 0x00BE1750` remain the next
  shader-creation lifecycle target.
- Remaining hard gap: prove exact `CreateVertexShader`/`CreatePixelShader`
  signatures, call-site argument/return ownership, which selector fields receive
  created shader objects, and draw-time restore timing. Visible native PBR
  replacement stays disabled until that contract is proven.
- `graphics_fnv_pbr_shader_creation_lifecycle_followup_audit.txt` proves the
  native shader creation ABI. `BSShader::CreateVertexShader @ 0x00BE0FE0`
  takes `(source_path, defines, profile, cache_name)`, compiles/caches through
  `D3DXCompileShader`, creates a native D3D vertex shader via renderer device
  vtable `+0x16C`, allocates a `0x3C` `NiD3DVertexShader`, initializes it with
  vtable `0x010EF87C`, and stores the native handle through its virtual
  `+0x88` setter. `BSShader::CreatePixelShader @ 0x00BE1750` takes
  `(source_path, defines, profile, cache_name)`, optionally substitutes the
  `ps_2_0` profile through `FUN_00B4F380(1)`, creates a native D3D pixel
  shader via renderer device vtable `+0x1A8`, allocates a `0x30`
  `NiD3DPixelShader`, initializes it with vtable `0x010EF7D4`, and stores the
  native handle through virtual `+0x80`. Selector `+0x148` writes returned
  vertex shader objects into global arrays `0x011FDD88`, `0x011FDE04`, and
  `0x011FDE5C` with ref-count handoff. Selector `+0x14C` writes returned pixel
  shader objects into global arrays `0x011FDA48` and `0x011FDB08`, also with
  ref-count handoff. This strongly supports a replacement side table keyed by
  returned `NiD3D*Shader` object pointer rather than mutating object layout, but
  the exact PPLighting callsite arguments and handle getter/setter slots still
  need one more focused audit.
- `graphics_fnv_pbr_shader_creation_callsite_args_audit.txt` proves the
  concrete PPLighting shader creation groups. Selector `+0x148` creates vertex
  group A at `0x00B74000` into global array `0x011FDD88` (`0x1F` entries,
  `lighting\1x\v\base.v.hlsl`, cache `SLS1%03i.vso`, profile `vs_2_0`),
  group B at `0x00B740B3` into `0x011FDE04` (`0x16` entries, cache
  `SLS1S%03i.vso`, profile `vs_2_0`), and group C at `0x00B7419F` into
  `0x011FDE5C` (`0x67` entries, cache `SLS2%03i.vso`, profile `vs_2_0`,
  with old-entry clearing when the source descriptor is null). Selector
  `+0x14C` creates pixel group A at `0x00B78720` into `0x011FDA48` (`0x30`
  entries, `lighting\1x\p\base.p.hlsl`/`diffusePt.p.hlsl`, cache
  `SLS1%03i.pso`, profile `ps_2_0`) and pixel group B at `0x00B78907` into
  `0x011FDB08` (`0xA0` entries, cache `SLS2%03i.pso` or
  `SLS2%03is%01i.pso`, profile `ps_2_0`). All five groups use the same
  ref-count handoff shape: read old array entry, release old object if needed,
  store the returned object, then addref the new object.
- The same callsite-args audit tightens the handle-slot contract. Pixel shader
  vtable `0x010EF7D4 +0x80` writes the native handle to object `+0x2C`;
  `+0x84` is a release/check slot that tests `+0x2C`; `+0x7C` is still the
  getter candidate used by `SetShaders`, but Ghidra did not bind it as a
  function in this output. Vertex shader vtable `0x010EF87C +0x88` writes the
  create-time native handle to object `+0x34`; `+0x80` writes `+0x30`, `+0x90`
  writes `+0x38`, and `+0x98` writes byte `+0x2C`. Vertex `+0x84` remains the
  getter candidate used by `SetShaders`, but it also needs raw disassembly
  proof because Ghidra did not bind `0x00E95D50` as a function here.
- Remaining hard gap after creation callsite proof: raw-disassemble the
  unbound getter thunks (`0x00BE0B10`, `0x00E95D50`, and adjacent tiny slots),
  re-prove the `BSShader::SetShaders @ 0x00BE1F90` bind sequence from raw
  instructions because this output did not bind it as a function, and choose
  the least invasive replacement/restore point. Visible native PBR replacement
  stays disabled until those facts are concrete.
- `graphics_fnv_pbr_shader_handle_getter_setshaders_contract_audit.txt` closes
  the vanilla shader-handle binding contract. Pixel shader vtable
  `0x010EF7D4 +0x7C` points at raw thunk `0x00BE0B10`
  (`mov eax, [ecx+0x2C]; ret`) and `+0x80` writes the same `+0x2C` native
  handle. Vertex shader vtable `0x010EF87C +0x84` points at raw thunk
  `0x00E95D50` (`mov eax, [ecx+0x34]; ret`) and create-time setter `+0x88`
  writes the same `+0x34` native handle. Vertex `+0x7C/+0x80` get/set `+0x30`,
  `+0x8C/+0x90` get/set `+0x38`, and `+0x94/+0x98` get/set byte `+0x2C`.
- The same handle audit raw-disassembles `BSShader::SetShaders @ 0x00BE1F90`:
  it reads current pass global `0x0126F74C`, gets the renderer helper through
  `0x00E7F7C0`, binds the vertex handle from pass `+0x5C -> vtable +0x84`
  through renderer helper vtable `+0x8C`, then, if pass `+0x44` is non-null,
  binds the pixel handle from pass `+0x44 -> vtable +0x7C` through renderer
  helper vtable `+0x7C`. It returns immediately after those binds. This makes
  `SetShaders` a proven post-constant shader-handle binding boundary.
- NewVegasReloaded's source path is now explicitly rejected as a compatibility
  model for OMV: it casts vanilla `NiD3DVertexShader`/`NiD3DPixelShader`
  allocations to larger `NiD3D*ShaderEx` structs and appends fields such as
  replacement shader records, backup handles, and names after the vanilla
  object. Ghidra proves vanilla allocations are only `0x3C` and `0x30`, so
  OMV must not extend those objects. The compatible model is a side table
  keyed by vanilla shader object pointer plus draw-scoped native handle binding.
- `graphics_fnv_pbr_pplighting_pass_shader_pair_contract_audit.txt` closes the
  first safe PPLighting family-detection contract. Runtime pass writers
  `FUN_00BE22B0`, `FUN_00BEB070`, and `FUN_00BEB830` copy vertex shader
  globals `0x011FDD88`/`0x011FDE04` into pass `+0x5C` and pair them with pixel
  shader global `0x011FDA48` in pass `+0x44`, using the vanilla refcount
  handoff. `FUN_00BEBD20` and `FUN_00C17510` cover the advanced family by
  pairing vertex global `0x011FDE5C` with pixel global `0x011FDB08`. The audit
  also confirms `FUN_00BD1C50` is only the current-pass/global owner updater,
  while `FUN_00BD4BA0` applies the current pass interfaces and
  `BSShader::SetShaders @ 0x00BE1F90` binds the same pass `+0x5C/+0x44`
  shader handles.
- Safe target detection for native PBR is therefore array membership of the
  current pass shader object pointers, not guessed shader names or Reloaded
  extended object fields. Current proven families are:
  `vertex A + pixel A`, `vertex B + pixel A`, and `vertex C + pixel B`.
- `graphics_fnv_pbr_pplighting_shader_input_signature_followup_audit.txt`
  proves the shader creation identity and generic constant-dispatch boundary,
  but it does not yet close a visible replacement signature. Vertex group A is
  created from `lighting\1x\v\base.v.hlsl`, profile `vs_2_0`, cache
  `SLS1%03i.vso`; vertex group B uses cache `SLS1S%03i.vso`, profile
  `vs_2_0`; vertex group C uses cache `SLS2%03i.vso`, profile `vs_2_0`.
  Pixel group A is created from the 1x pixel source table including
  `lighting\1x\p\base.p.hlsl` / `lighting\1x\p\diffusePt.p.hlsl`, profile
  `ps_2_0`, cache `SLS1%03i.pso`; pixel group B uses profile `ps_2_0` and
  cache pattern `SLS2%03is%01i.pso`.
- The same input-signature follow-up confirms `FUN_00BD4BA0` applies the
  current pass pixel and vertex shader-interface records before
  `BSShader::SetShaders`, and confirms `FUN_00E826D0` as the generic
  record dispatcher. `FUN_00E826D0` iterates enabled records, filters by
  record type class `record +0x14 & 0xF0000000`, uses `record +0x1C` as the
  register slot when present, and dispatches type classes through the
  shader-interface vtable helpers `+0x8C/+0x90/+0x94/+0x98/+0x9C/+0xA4` plus
  renderer constant upload slots. This proves how vanilla applies records, but
  not the complete per-family record table.
- `graphics_fnv_pbr_pplighting_interface_record_table_audit.txt` proves the
  shader-interface record registration and dispatcher shape in more detail.
  `FUN_00E7F430` is the record register/finalize helper: ECX is the
  shader-interface owner, stack arg 0 is the record key, stack arg 1 is the
  record value, and stack arg 2 selects the record list. It writes record
  node `+0` key and `+4` value, then links the node into either the owner
  `+8/+4` list or owner `+10/+0C` list. The same audit resolves the concrete
  `0x010EF544` vtable dispatch chain used by `FUN_00E826D0`: slot `+0x78`
  is `FUN_00E826D0`, type `0x20000000` goes through slot `+0x8C`
  (`0x00E83DB0`), type `0x10000000` through `+0x90` (`0x00E84B60`),
  type `0x30000000` through `+0x94` (`0x00E84BA0`), type `0x40000000`
  through `+0x98` (`0x00E84D00`), type `0x50000000` through `+0x9C`
  (`0x00E87220`), and type `0x60000000` through `+0xA4` (`0x00E85C40`).
- The interface-record audit also decompiles the PPLighting pass-entry helper
  family and shows the entry IDs passed to `FUN_00BA9EE0`, but it is still not
  a complete visible PBR contract. It does not normalize the ECX owner and
  stack-argument order for every callsite, and it does not yet correlate the
  `FUN_00BA9EE0` entry array values with final `NiDX9RenderState::SetTexture`
  stages for one shader family.
- `graphics_fnv_pbr_pplighting_pass_entry_arg_table_followup_audit.txt`
  normalizes that callsite contract. For `FUN_00E7F430`, ECX is the
  shader-interface owner and stack args are record key, record value, then
  list flag. For `FUN_00BA9EE0`, ECX is the pass-entry list owner and stack
  args map to entry `+0`, entry `+4`, entry `+7`, entry `+9` array count, then
  entry `+0x0C` array values. The important correction is that the many
  constants in rows such as `0x58..0x60`, `0x64..0x92`, `0x95..0xC0`,
  `0xD7..0xFA`, `0x116..0x177`, and `0x1E2..0x256` are usually entry `+4`
  stage/key values, not necessarily entry `+0` type IDs. Some rows still carry
  register values or unresolved `?` entries, so they need a stage/resource
  correlation pass before assigning material semantics.
- `graphics_fnv_pbr_shader_interface_missing_vfunc_followup_audit.txt` closes
  the unresolved shader-interface vtable-helper gap. All expected
  `0x010EF544` slots match the previous audit, including `+0x98 ->
  0x00E84D00` and `+0xA4 -> 0x00E85C40`. `0x00E84D00` is a constant/data pack
  helper: it reads record type metadata from `0x011F5FC4`, copies scalar,
  vector, or matrix-shaped source data from record `+0x30` into scratch globals
  such as `0x0126F7B0`, `0x0126F7CC`, and `0x0126F7E0`, then uploads through
  shader-interface virtual slot `+0x74`. `0x00E85C40` resolves source data via
  `0x00A9C130`/`0x00A9BCD0`, builds a transformed block through
  `0x00E84ED0`, and uploads it through the same `+0x74` route. Neither helper
  binds textures or owns sampler/render-state mutation.
- `graphics_fnv_pbr_pplighting_pass_id_stage_correlation_audit.txt` confirms
  the final field-to-stage contract but still does not assign material-map
  semantics. `FUN_00E7EB00` compares entry `+8` against cache table
  `0x0126F680[entry +4]`, writes the new `+8`, flushes tracked state through
  `FUN_00E89410(entry +4)`, then calls `FUN_00E7EA00`. `FUN_00E7EA00`
  consumes entry `+4` as `param_1[1]`, resolves nonzero entry `+8` through
  `DAT_0126F6C4 +0x8C4 -> vtable +0x0C`, then calls render-state vtable B
  `+0xDC`, proven as `NiDX9RenderState::SetTexture @ 0x00E88A20`, with
  `(entry +4, resolved_texture)`. Vtable B also maps `+0xC0` to
  `SetTextureStageState` and `+0xCC` to `SetSamplerState`.
- The same correlation audit emits 275 static entry `+4` stage/key values and
  finds only eight rows where the local push window cannot resolve entry `+4`.
  This is enough to prove final stage ownership, but not enough for visible PBR:
  most nonzero resource arrays still pass register values such as `EAX`, `EDX`,
  or `ECX` into entry `+0x0C`, and those registers must be traced back to
  source texture providers, active-object getters, fallback globals, or
  non-texture state before assigning albedo/normal/glow/height/env semantics.
- `graphics_fnv_pbr_pplighting_pass_resource_provenance_followup_audit.txt`
  narrows that gap. It scans 285 `FUN_00BA9EE0` PPLighting construction calls
  and prints 246 resource-bearing or unresolved rows. The important result is
  that most resource-bearing entries are not direct material field reads at the
  `BA9EE0` callsite. They are wrapper/helper parameters forwarded as
  `param_2`, `param_3`, `param_4`, or local values produced earlier by the
  selector driver. Examples include `00BD9540` forwarding one resource
  parameter across stage keys `0x58..0x60`, `00BDA0A0` forwarding one resource
  parameter across `0x64..0x92`, `00BDC0D0` forwarding two resources across
  `0xD7..0xE8`, `00BDC530` forwarding three resources across `0xE9..0xFA`,
  and `00BDD050`/`00BDD520` forwarding one or two resources across
  `0x95..0xC0`.
- `graphics_fnv_pbr_pplighting_selector_driver_arg_provenance_audit.txt`
  follows that trail into `FUN_00BDF790` and prints 65 direct helper-call
  provenance rows. It confirms `param_1[8]`/`param_1[9]` are shader flags,
  `param_2` is the pass-entry/list owner passed as ECX into helper families,
  `param_2 +0x60` owns the active object/resource list, and
  `local_60 = *(DAT_011F95EC +0x194) +0xE0`. The helper family
  `00B70590`/`00B70600`/`00B70680`/`00B70700`/`00B707D0` is not a material
  texture array path; it walks active objects from `param_2 +0x60` and filters
  on fields such as object `+0x110`, `+0xEC`, and `*(object +0xF8) +0x30`.
- The same selector-driver audit shows the active-object `+0xEC` branch calls
  `FUN_00BA9EE0` and then overwrites the created entry with pass/stage IDs
  `0x231`, `0x232`, or `0x233`. BDF790 forwards resource-helper results into
  helper families, but this is active-object/light/resource provenance, not a
  safe albedo/normal/glow/height/environment map semantic table.
- Current hard gap for visible native PBR replacement: `FUN_00E7EA00` is proven
  to pass `entry +8` through the `renderer +0x8C4` resolver and then bind the
  returned pointer with `NiDX9RenderState::SetTexture(stage = entry +4)`. The
  resolver object itself is now identified, but the concrete renderer-data
  vtables below `entry +8 +0x24` still need to be proven before assigning
  material-map meanings or emitting a replacement BRDF shader.
- `graphics_fnv_pbr_pplighting_resource_resolver_vtable_audit.txt` proves the
  `renderer +0x8C4` lifecycle more narrowly. Renderer init `FUN_00E6B990`
  zeroes it. Device setup `FUN_00E72E60` allocates `0x10` bytes with
  `FUN_00AA13E0`, calls `FUN_00E90A80` with `ECX = allocation` and stack arg
  `renderer`, then stores the return value at `renderer +0x8C4`. Renderer
  teardown `FUN_00E75A70` calls the object vtable slot `+0x00` with argument
  `1` and nulls the field. `FUN_00E7EA00` uses vtable slot `+0x0C` for
  `entry +8` resolution, while renderer main vtable slot `+0xE0` at
  `FUN_00E69640` loads `renderer +0x8C4` and jumps to resolver vtable
  slot `+0x10`.
- `graphics_fnv_pbr_pplighting_resolver_constructor_slot_followup_audit.txt`
  closes the `+0x8C4` resolver identity gap. `FUN_00E90A80` first initializes
  the 16-byte allocation as base vtable `0x0101DCE4`, then overwrites it with
  the live resolver vtable `0x010F086C`. Object fields are:
  `+0x08 = *(renderer +0x288)` with a virtual add-ref through slot `+0x04`,
  and `+0x0C = renderer`. The live vtable maps slot `+0x00` to
  `FUN_00E90AC0` (release `+0x08`, decrement the base refcount, optionally
  free the 16-byte object), slot `+0x08` to `FUN_00BA8A90`, slot `+0x0C` to
  `FUN_00E90B10`, slot `+0x10` to `FUN_00E90C70`, and slot `+0x14` to
  `FUN_00E90D20`.
- `FUN_00E90B10` is the proven resource resolver used by `FUN_00E7EA00`.
  It clears three output flags, locks `DAT_011F4748 +0x180`, reads the
  source/resource object's renderer-data pointer at `resource +0x24`, and if
  missing uses the `DAT_011F444C` lookup path plus `FUN_00E68EF0` to create
  renderer data and write it back to `resource +0x24`. It then resolves a
  returned bindable pointer through renderer-data virtual slots
  `+0xA4/+0xAC/+0xA8` and wrapper/texture virtual slots `+0x9C/+0xB4`, with
  extra flags based on renderer-data fields `+0x0C/+0x10` and `resource +0x40`.
  `FUN_00E90C70` uses the same `resource +0x24`/`FUN_00E68EF0` path as a
  validity/helper route from renderer main vtable slot `+0xE0`.
- `graphics_fnv_pbr_pplighting_resolver_texturedata_vtable_followup_audit.txt`
  closes the concrete source-texture renderer-data path under `entry +8`.
  `FUN_00E68EF0` allocates a 0x84-byte renderer-data object, writes vtable
  `0x010ED37C`, stores the source/resource pointer at `+0x08`, width/height at
  `+0x0C/+0x10`, the bindable texture/wrapper pointer at `+0x64`, and writes
  the object back to `source +0x24`. `FUN_00E68A80` is a real D3D load path:
  it uses `D3DXGetImageInfoFromFileInMemory` and creates 2D/cube/volume
  textures with the corresponding `D3DXCreate*FromFileInMemory` calls.
- For the `0x010ED37C` renderer-data vtable created by `FUN_00E68EF0`,
  `FUN_00E90B10` takes the final branch: slot `+0xA4` returns null, slot
  `+0xAC` returns null, slot `+0xA8` returns `this`, slot `+0xB4` can refresh
  or rebuild the wrapper, slot `+0x98` returns `*(this +0x68)`, and slot
  `+0x9C` returns `*(this +0x64)`. Therefore the proven source-texture bind
  path is now:
  `BA9EE0 entry +8 resource -> resource +0x24 renderer data ->
  *(rendererData +0x64) -> NiDX9RenderState::SetTexture(stage = entry +4)`.
  Other renderer-data vtables may still use non-null `+0xA4/+0xAC` paths, but
  the normal source-texture path no longer requires guesswork.
- Updated hard gap: map resource-bearing `FUN_00BA9EE0` rows and their
  `entry +4` stage keys back to material semantics for one safe PPLighting
  family. The remaining unknown is no longer the final texture wrapper
  returned to D3D; it is whether a given `entry +8` resource came from diffuse,
  bump/normal, glow, gloss, dark/detail/decal, an active-object resource, or a
  fallback/non-material source. Visible native PBR remains blocked until that
  semantic map is proven.
- `graphics_fnv_pbr_pplighting_texture_semantic_stage_followup_audit.txt`
  rejects the obvious named-map shortcut. The named getters for
  `Dark/Detail/Gloss/Glow/Bump/Decal Map` are referenced only from
  `FUN_0046E910`, and `FUN_0046E910` only enumerates extra maps and attaches
  them through `FUN_0046E8E0 -> FUN_00653270(&DAT_011F444C, texture)`.
  That is relevant to source-texture renderer data, but it is not the
  PPLighting draw-stage builder and it does not directly label `BA9EE0`
  resource rows.
- The same semantic-stage follow-up confirms the PPLighting rows remain
  helper-driven. `FUN_00BDF790` reads `FUN_00653290(&DAT_01200788)`,
  `FUN_00653290(&DAT_012024C8)`, `FUN_00653290(&DAT_012007A0)`, fetches
  property type `0` through `FUN_00A59D30(0)`, and forwards `local_60 =
  *(FUN_00B4F5C0() +0x194) +0xE0` through many helper families. The direct
  active-object branch calls `FUN_00B70590`, appends a `BA9EE0` resource row,
  then overwrites the final stage to `0x231`, `0x232`, or `0x233`; this is
  active-object provenance, not an albedo/normal/glow map.
- `FUN_00BDAF10` is the strongest material-property lead from the new output.
  It fetches property type `3` with `FUN_00A59D30(3)`, tests arrays under
  `property +0xAC` and `property +0xB4`, emits stage keys
  `0x93/0x94/0x1EF/0x1F1/0x1F2/0x1F3/0x1F4/0x1F5`, and sometimes forwards
  `param_3` or active-object iterator results into `BA9EE0`. This proves the
  next research target is producer-side field layout under the type-3 property
  and the texture-array writer path, not final D3D binding.
- Updated hard gap after semantic-stage follow-up: prove how source
  `BGSTextureSet` slots and the runtime arrays `+0xAC..+0xC0` populate the
  type-3 property fields consumed by `FUN_00BDAF10`/`FUN_00BDF790`. The
  strongest proven source-material clue remains the texture-set virtual getter
  at `TextureSet +0x30 -> vtable +0x8C`, where landscape validation calls
  index `0` as diffuse and index `1` as normal, plus the known record-side
  extra-map slot IDs from `FUN_00877A30`. Visible native PBR is still blocked
  until these producer fields are mapped to the final `entry +4` stages.
- `graphics_fnv_pbr_pplighting_texture_property_field_source_audit.txt`
  closes the anonymous field-layout part of that gap. `FUN_00B690D0`
  serializes the type-3 property arrays with engine-authored labels:
  `+0xAC`/`param_1[0x2B]` is base diffuse/base texture, `+0xB0` is base
  normal/normal map, `+0xB4` is glow map or glow/skin/hair layer texture,
  `+0xB8` is heightmap texture, `+0xBC` is envmap texture, and `+0xC0` is
  envmap mask texture. For landscape mode, `+0xA8` is the texture count and the
  same diffuse/normal/glow arrays are indexed per layer.
- The same audit proves `FUN_00B68660` is the runtime writer for the six
  texture arrays beginning at `+0xAC`: it ensures allocation, clears the
  per-index byte arrays at `+0xC4/+0xCC`, calls a resolver object's virtual
  slot `+0x90` with texture kind `0..5` and an output pointer, and then derives
  a normal/specular-like byte flag from the normal-map renderer-data type.
  `FUN_00B66640` separately initializes the nine `+0xC4` landscape byte flags.
- The new hard gap is therefore narrower: decompile the two producer callsites
  `FUN_00539960` and `FUN_0053A090`, recover the exact arguments passed to
  `FUN_00B68660`/`FUN_00B66640`, and identify the resolver object whose vtable
  slot `+0x90` fills each array. Until that writer path is connected to
  `BGSTextureSet +0x30 -> +0x8C` slot indexes or another proven texture source,
  visible PBR must still avoid treating the type-3 arrays as generic BRDF map
  inputs.
- `graphics_fnv_pbr_pplighting_texture_writer_callsite_deep_audit.txt`
  closes the producer-side callsite shape. Both `FUN_00539960` and
  `FUN_0053A090` build a type-3 PPLighting property, pass that property as ECX
  to `FUN_00B68660`, and use stack arg 0 as the destination array index:
  index `0` for the base texture source at `land/owner +0x20`, then indexes
  `1..6` for layer sources read from `land/owner +0x30 + layer*4 - 4`.
  Stack arg 1 is either zero, which clears that indexed entry in all six
  arrays, or the result of `FUN_00592CF0(FUN_009611E0(textureSource))`.
  Fallback paths use `FUN_00535AE0() -> FUN_009611E0() -> FUN_00592CF0()` for
  base index `0`. `FUN_00B66640` then initializes the per-index `+0xC4` flags
  from `FUN_00541590()` tests over the same base/layer source pointers.
- The same audit corrects the resolver identity: the renderer-side vtable
  `0x010F086C +0x90 -> 0x00E90D80` is not the callback object passed by these
  producer calls. The proven source callback candidate is the
  `BGSTextureSet +0x30` slot-interface vtable at `0x01033C7C`, where
  `+0x8C -> FUN_00592E70` returns indexed texture filenames and
  `+0x90 -> FUN_00592F30` prefixes `Data\\Textures\\`, calls `FUN_00B55840`,
  and then calls `FUN_006E5CC0` on the loaded smart pointer. The decompiler does
  not show the second `FUN_00B68660` callback argument being consumed, so the
  remaining contract gap is raw stack/RET proof that `FUN_00592F30` writes the
  loaded resource to the `piVar7` out pointer and to map callback kind `0..5`
  exactly to the engine-labeled diffuse/normal/glow/height/env/env-mask arrays.
- `graphics_fnv_pbr_pplighting_texture_source_callback_contract_audit.txt`
  closes that raw callback gap. `FUN_00592CF0` is only a slot-interface getter:
  it returns `textureSourceRenderer +0x30`. Raw `FUN_00592F30` proves the
  hidden callback signature as `+0x90(kind, outSlot)`: `[EBP+0x8]` is the
  callback kind, `[EBP+0xC]` is the caller's output smart-pointer slot, and the
  function returns with `RET 0x8`. It calls `+0x8C` to fetch a texture path,
  builds `Data\\Textures\\...`, calls
  `FUN_00B55840(path, 1, &localSmartPtr, 1, 0)`, then
  `FUN_006E5CC0(outSlot, &localSmartPtr)`. `FUN_006E5CC0` is a refcounted
  smart-pointer copy helper; `FUN_00B55840` may leave the result null for a
  missing, invalid, or no-mip texture.
- The proven callback-kind map is now:
  `0 -> +0xAC diffuse/base -> source element 0 (slot-interface +0x08)`,
  `1 -> +0xB0 normal -> source element 1 (+0x14)`,
  `2 -> +0xB4 glow/skin/hair layer -> source element 3 (+0x2C)`,
  `3 -> +0xB8 heightmap -> source element 4 (+0x38)`,
  `4 -> +0xBC envmap -> source element 5 (+0x44)`,
  `5 -> +0xC0 envmap mask -> source element 2 (+0x20)`. This is the standard
  `BGSTextureSet` source order used by the callback, not the separate
  record-side extra-map getter order.
- Remaining visible PBR implementation gap after the source callback proof:
  the material texture source contract is closed, but visible BRDF replacement
  still needs a concrete replacement shader contract for at least one safe
  shader family: which material arrays become final texture stages, input
  semantics, constants, sampler policy, fallback behavior, and shader
  source/bytecode ownership. Until that exists, replacement may capture handles
  and texture state but must not rebind a guessed material shader.
- `graphics_fnv_pbr_pplighting_material_array_stage_contract_audit.txt`
  proves `FUN_00BDAF10` is not the missing normal/height/env material texture
  binder. It is called only from `FUN_00BDB4A0 @ 0x00BDBAA7`; raw caller state
  passes ECX from `ESI` and stack args from the surrounding pass-builder state.
  Inside `FUN_00BDAF10`, the only type-3 material arrays read are
  `+0xAC` diffuse/base and `+0xB4` glow/skin/hair layer. There are no
  `+0xB0` normal, `+0xB8` heightmap, `+0xBC` envmap, or `+0xC0` env-mask reads
  in this helper.
- The `FUN_00BDAF10 -> FUN_00BA9EE0` stage keys are now classified. `0x93`
  and `0x94` are base material rows using `param_3` as the single resource
  when the row count is `1`. `0x1F2` and `0x1F3` are layer rows gated by
  `+0xAC[index+1]`; they also use `param_3` as the single resource in the
  normal non-`DAT_011F91A7` path. `0x1F1` is a zero-resource row gated by base
  `+0xB4[0]`, and `0x1F4` is a zero-resource row gated by both
  `+0xAC[index+1]` and `+0xB4[index+1]`. `0x1EF` and `0x1F5` are active-object
  resource rows from `FUN_00B70600`/`FUN_00B70700`, not material texture array
  resources.
- Updated hard gap: find every draw-time consumer of the remaining material
  arrays `+0xB0/+0xB8/+0xBC/+0xC0`, or prove they are only serialized/runtime
  flags and not bound by vanilla PPLighting. Until that is closed, the safe
  visible PBR target is still not available even though diffuse/glow predicate
  behavior in `FUN_00BDAF10` is known.
- `graphics_fnv_pbr_pplighting_remaining_array_consumer_followup_audit.txt`
  narrows the remaining-array gap. `FUN_00B68660` is confirmed as the
  non-draw writer for all six arrays and the only direct `+0xB0` consumer in
  the printed draw-adjacent set: it uses the normal array at index `1` only to
  derive the per-index byte at `+0xCC` when the normal texture renderer data
  reports type `5`, `6`, or `1`. `FUN_00B690D0` labels and serializes
  diffuse/base, normal, glow/layer, heightmap, envmap, and envmap-mask fields,
  but it has no `FUN_00BA9EE0` calls and is not draw binding.
- The same audit shows the real draw selectors treat the remaining arrays
  mostly as predicates, not direct resource rows. `FUN_00B69FF0` reads
  `param_2 +0xB8 +0x28` to choose height-related stage keys but emits
  zero-resource `FUN_00BA9EE0` rows. `FUN_00BB41E0` tests `+0xBC` to select
  `0x24C` versus `0x24D`, again with no material resource. The long selector
  variants `FUN_00BB4740` and `FUN_00C058F0` read `+0xB8`, `+0xBC`, and
  `+0xB4[0]` as branch predicates for stage families such as
  `0x1C8..0x1D6`, `0x1BB..0x1BC`, `0x1D0..0x1E0`, and `0x17F..0x1BA`; their
  resource-bearing rows use fallback/global resources or active-object
  iterator results, not direct `+0xB0/+0xB8/+0xBC/+0xC0` texture-array slots.
- `FUN_00BDF790` is more subtle: the decompile only confirms real material
  reads from `param_2 +0xB8`, `param_2 +0xBC`, and `param_1 +0xB4` as
  predicates. The raw `[ESP +0xB0/+0xBC/+0xC0]` windows in that function are
  helper-call stack argument offsets after many pushes, so they must not be
  treated as direct normal/env/env-mask material-field reads. No draw-stage
  `+0xC0` env-mask consumer is proven yet, and no direct normal-array
  `FUN_00BA9EE0` resource row is proven.
- Updated hard gap: the material source and writer contracts are known, and the
  final `FUN_00E7EA00 -> NiDX9RenderState::SetTexture` route is known, but the
  safe PBR replacement still needs an exact semantic closure at the selector
  boundary: real material-object reads versus stack offsets, pass index
  ownership, final stage/key, resource count, and fallback behavior for each
  target row. Until that is proven, runtime code may capture PPLighting state
  but must not rebind a visible BRDF shader.
- `graphics_fnv_pbr_pplighting_material_semantic_stage_closure_audit.txt`
  strengthens that blocker instead of clearing it. The audit separates real
  material-object reads from stack-offset false positives. The only real
  material reads in `FUN_00BDF790` are `param_1 +0xB4`,
  `param_2 +0xB8`, and `param_2 +0xBC`, and they are branch predicates.
  The apparent `[ESP +0xB0]`, `[ESP +0xBC]`, and `[ESP +0xC0]` reads are
  helper-call stack offsets. They forward already-selected arguments into
  helpers such as `FUN_00BDD050`, `FUN_00BDD520`, `FUN_00BDE1D0`,
  `FUN_00BDCA60`, `FUN_00BDC0D0`, `FUN_00BDC530`, `FUN_00BDDD80`, and
  `FUN_00BDBF60`; they are not direct normal/env/env-mask material fields.
- The same closure audit proves that most helper families have no direct
  material-array reads at all. They emit `FUN_00BA9EE0` rows from helper
  parameters, active-object iterators, globals, or zero-resource stage rows.
  `FUN_00BDAF10` remains the only direct material-array helper in the scanned
  late family, and it reads only `+0xAC` diffuse/base and `+0xB4`
  glow/layer arrays as predicates. It emits stage keys
  `0x93`, `0x94`, `0x1EF`, and `0x1F1..0x1F5`, but the resource-bearing rows
  use either `BDAF10` parameter `param_3` or active-object iterator results;
  the direct material-array slots are not passed as resources in the printed
  rows.
- New hard gap after semantic closure: normalize the only
  `FUN_00BDB4A0 -> FUN_00BDAF10` callsite with the correct `thiscall`
  boundary. The broad helper-call table over-collects previous pushes, so the
  exact ECX owner and six stack arguments at `0x00BDBAA7` must be printed
  directly. In particular, prove whether `BDAF10` `param_3`, used by rows
  `0x93/0x94/0x1F2/0x1F3` as the single `entry +8` resource, is the
  `FUN_00BDB4A0` value `uVar1 = *(FUN_00B4F5C0() +0x194) +0xE0` rather than a
  direct material texture array. If it is the global/fallback resource, then
  `BDAF10` is a material predicate helper only, not the safe PBR material-map
  binding contract.
- `graphics_fnv_pbr_pplighting_bdaf10_callsite_param_closure_audit.txt`
  closes that callsite. There is exactly one reference to `FUN_00BDAF10`:
  `UNCONDITIONAL_CALL @ 0x00BDBAA7` inside `FUN_00BDB4A0`. The raw call
  sequence loads `ECX = ESI`, then pushes six stack arguments:
  `param_2 = EDX from [ESP+0x4C]`, `param_3 = ECX from [ESP+0x20]`,
  `param_4 = EDI`, `param_5 = EBP`, `param_6 = EAX = [ESP+0x5C]`, and
  `param_7 = 0`.
- The same audit proves `BDAF10` `param_3` is the `FUN_00BDB4A0` local
  `uVar1`, not a direct material-array texture. `uVar1` is assigned as
  `*(FUN_00B4F5C0() +0x194) +0xE0`, and `FUN_00B4F5C0` is only
  `return DAT_011F95EC`. The raw stack write at `0x00BDB6D5` stores that
  value into `[ESP+0x20]`, which is the later `PUSH ECX` for `BDAF10`
  `param_3`.
- `FUN_00BDAF10` therefore emits stage rows from material predicates, but its
  resource-bearing rows are not proof of material texture binding.
  `0x93`, `0x94`, `0x1F2`, and `0x1F3` use `param_3`; the
  `DAT_011F91A7` path emits zero-resource `0x93`/`0x1F2`; `0x1F1` and
  `0x1F4` are zero-resource rows gated by glow/diffuse predicates; and
  `0x1EF`/`0x1F5` use active-object iterator resources from the
  `FUN_00B70600`/`FUN_00B70700` paths. The only direct type-3 material reads
  inside `BDAF10` remain `+0xAC` and `+0xB4` as predicates.
- Updated hard gap: native row replacement is not proven as a visible PBR
  path. The first safe implementation contract must either capture the known
  type-3 arrays (`+0xAC/+0xB0/+0xB4/+0xB8/+0xBC/+0xC0`) at a proven draw
  scope and bind extra PBR textures through a side table with a proven
  lifetime key, or prove another native row that really carries those material
  arrays into final apply. Current evidence increasingly rejects
  `FUN_00BDAF10` as that binder.
- `graphics_fnv_pbr_pplighting_draw_scope_material_pointer_contract_audit.txt`
  proves useful structure but does not clear the safe bind contract. The
  `FUN_00BA8EC0` constructor confirms the `FUN_00BA9EE0` pass-entry layout:
  `+0` stage/key, `+4` word parameter, `+7` byte parameter, `+9` resource
  count, `+0x0C` resource array pointer, and `+0x0B` initialized/reset to
  zero. `FUN_00BA9EE0` resets `+0x0B` for reused entries, and
  `FUN_00BDAF10` is still the only audited writer that stores the layer byte
  into the most recently appended entry after `0x1F2`, `0x1F3`, `0x1F4`, and
  `0x1F5` rows.
- The same audit shows `FUN_00BD4BA0` is not a material-map recovery point.
  It reads the current geometry/global draw context from `*DAT_011F91E0`,
  pulls `*(iVar1 +0xB8)+0x34` and `iVar1 +0xBC`, then dispatches shader
  interface `vtable +0x78` calls for current pass shader objects at
  `DAT_0126F74C +0x44/+0x5C`. It does not call `FUN_00A59D30(3)` and does
  not expose the type-3 material texture arrays.
- The low-level `FUN_00E7EB00 -> FUN_00E7EA00` route is also not the
  `FUN_00BA9EE0` pass-entry structure. `FUN_00E7EB00` compares/caches
  `record +0x8` by `record +0x4`, then calls `FUN_00E7EA00` with `ECX` set to
  that record. `FUN_00E7EA00` uses `param_1[1]` as the texture stage and
  `param_1[2]` as the resource/object to resolve and bind. The apparent
  `+0xC0/+0xCC` hits there are vtable/resolver offsets, not material-array
  fields. No material property pointer, `FUN_00BA9EE0` entry pointer, or
  `BDAF10` `entry +0x0B` layer byte is proven to survive into this final
  low-level apply path.
- New hard gap after draw-scope audit: prove the bridge from
  `FUN_00BA9EE0` PPLighting rows to the low-level texture-record apply
  functions (`FUN_00B7DD50`, `FUN_00B7DDE0`, `FUN_00B7E150`,
  `FUN_00E7EB00`, `FUN_00E7EA00`). If that bridge discards the material
  pointer and PPLighting entry identity, the PBR implementation must capture
  material arrays before the bridge and use a separate, generation-safe
  side-table instead of trying to infer material maps from final
  `SetTexture`-level state.
- `graphics_fnv_pbr_pplighting_entry_to_texture_record_bridge_audit.txt`
  proves the bridge is not a direct `FUN_00BA9EE0` entry handoff. There are
  no calls from `FUN_00BA9EE0`, `FUN_00BD4BA0`, or
  `FUN_00E826D0` into `FUN_00E7EB00`. The audited bridge calls load `ECX`
  from fixed records under `DAT_0126F74C +0x24`, then call
  `FUN_00E7EB00(0)`. `FUN_00E7EB00` caches `record +0x8` in
  `DAT_0126F680[record +0x4]`, validates `record +0x4` through
  `FUN_00E89410`, and forwards the same record in `ECX` to `FUN_00E7EA00`.
- The exact current-pass texture-record slots are now partly known.
  `FUN_00B7DD50` applies the record at `*(DAT_0126F74C +0x24) +0x14`.
  `FUN_00B7DDE0` writes and applies records at offsets `+0` and `+4` under
  `*(DAT_0126F74C +0x24)`: slot `+0` gets resource `piVar1[0x2B][0]`, and
  slot `+4` gets the result of `FUN_00C03230(piVar1, 0)`. `FUN_00B7E150`
  does the same for slots `+0` and `+4`, and additionally writes/applies slot
  `+0xC` from `piVar1` vtable `+0xF4(3, 0)` or fallback `DAT_011F951C`.
  In all cases `piVar1 = *(param_1 +0x0C)`.
- This closes the final-apply side as a lossy texture-record route for native
  PBR. `FUN_00E7EA00` only sees record type/key, stage, and resource; it does
  not see the original `FUN_00BA9EE0` row pointer, the `BDAF10` `entry +0x0B`
  layer byte, or a type-3 material property pointer. Therefore final
  `SetTexture`-level interception can observe/override a texture stage, but it
  cannot independently recover which material-array slot should supply PBR
  normal/height/env/env-mask maps.
- New hard gap after bridge audit: prove current-pass texture-record slot
  provenance. Specifically, classify every `FUN_00E7EB00` caller and trace
  the source object passed to `FUN_00B7DDE0`/`FUN_00B7E150` as
  `param_1 +0x0C`. If that source object cannot be tied back to the exact
  type-3 material arrays and layer index, the compatible PBR design must
  capture material arrays at selector/pass-row construction time and bind
  them later through a generation-safe side table keyed by a proven current
  draw/pass identity.
- `graphics_fnv_pbr_pplighting_current_pass_texture_record_slot_provenance_audit.txt`
  closes that slot-provenance gap on the final-apply side. The script found no
  errors and confirmed the same 22 references into `FUN_00E7EB00`. The
  material-looking slots are written by current-pass helpers, not by direct
  `FUN_00BA9EE0` pass-entry handoff.
- `FUN_00B98E80` is the normal caller for `FUN_00B7DDE0`,
  `FUN_00B7E150`, `FUN_00B7DED0`, and `FUN_00B7DFE0`. It builds the helper
  context as `piVar1 = piVar3 +0x27`, stores that pointer to
  `DAT_011F4748 +0x0C`, and passes the same pointer to those helpers. The
  helpers then read `*(param +0x0C)` and use that object as `piVar1`. This is
  a current pass/shader context object derived from the active draw record,
  not a proven type-3 material property pointer.
- The current-pass record slots are now concrete: `FUN_00B7DDE0`,
  `FUN_00B7DED0`, and `FUN_00B7DFE0` write/apply slots `+0` and `+4` under
  `*(DAT_0126F74C +0x24)` from `piVar1[0x2B][0]` and
  `FUN_00C03230(piVar1, 0)`. `FUN_00B7E150` writes/applies those same slots
  and additionally writes/applies slot `+0x0C` from `piVar1` vtable
  `+0xF4(3, 0)` or fallback `DAT_011F951C`. `FUN_00B7DD50` only applies its
  fixed record slot and does not recover material-array state.
- Important implementation constraint: `NiDX9RenderState::SetTexture` or
  `FUN_00E7EA00` hooks can see final resources/stages, but cannot infer the
  source material array, selector row, or layer byte once execution has
  reached the low-level texture-record cache. A compatible native PBR design
  must capture the type-3 arrays at selector/pass-row construction or another
  proven earlier draw-scope point, then carry them to final bind time through
  a generation-safe side table. It must not guess PBR maps from the final
  stage/resource pair alone.
- New hard gap after current-pass slot audit: prove the side-table key.
  Specifically, find whether `DAT_011F4748 +0x0C`, `*DAT_011F91E0`,
  `DAT_0126F74C`, the `FUN_00BA9EE0` list owner, or the selector/draw context
  can safely correlate captured material arrays with the later pass apply. If
  no stable identity survives, the implementation needs a narrower hook point
  where the material arrays and final bind action are both in scope.
- `graphics_fnv_pbr_pplighting_selector_side_table_key_contract_audit.txt`
  narrows the key but does not yet prove the final implementation contract.
  It found no script errors. `FUN_00B98E80` and `FUN_00B99390` each have one
  normal caller, `FUN_00B994F0`, so current-pass setup and current-pass draw
  dispatch share one draw dispatcher boundary.
- `FUN_00B994F0` writes `DAT_011F91E0 = param_1`, checks the current selector
  object at `*( *param_1 +0xC0)`, calls `FUN_00B99390(param_2,
  *( *param_1 +0xC0))` when the selector/pass object changes, and then calls
  `FUN_00B98E80(param_1, ...)` for the normal draw path. Inside `FUN_00B98E80`,
  `piVar3 = *param_1`, `piVar5 = piVar3[0x30]`, and `piVar3[0x30]` is the same
  `+0xC0` selector object field. This makes the selector object pointer the
  leading side-table key candidate.
- Selector-side row construction is still rooted in the selector object, not in
  final texture-record state. `FUN_00BDB4A0` receives the selector object as
  `this`, reads the type-3 material arrays and pass-entry list from that object
  (`+0xAC/+0xB4` and `+0x3C` in the audited paths), and calls
  `FUN_00BDAF10`. `FUN_00BDAF10` appends to `this +0x3C`, then re-reads the
  last entry from that list to write `entry +0x0B` layer bytes. `FUN_00BDF790`
  follows the same selector-object model with `param_1[0xF]` / `+0x3C` as the
  pass-entry list.
- `FUN_00BD4BA0` is useful for final apply only because it reads
  `*DAT_011F91E0`, `iVar1 +0xBC`, and `*(iVar1 +0xB8)+0x34`, then calls
  shader-interface `+0x78` on pass objects from `DAT_0126F74C`. It still does
  not expose the material arrays directly. `DAT_011F4748 +0x0C` is also not a
  sufficient stable key by itself: it is current-pass helper state derived as
  `*current_draw +0x9C`, not the selector object that owns material arrays and
  the pass-entry list.
- `graphics_fnv_pbr_pplighting_selector_vtable_draw_identity_bridge_audit.txt`
  closes the side-table key contract. It found no script errors. Every
  candidate selector vtable that references `FUN_00BDB4A0` and
  `FUN_00BDF790` places them at slots `+0xF0` and `+0xF4` respectively:
  `0x010AE0F4`, `0x010B8354`, `0x010B935C`, `0x010B94B4`, `0x010B9934`,
  `0x010BAC1C`, and `0x010BCB84` all share that setup pair. The separate
  apply tables with `FUN_00BD4BA0` and `FUN_00E826D0` at `+0x78` are not the
  selector setup table.
- `FUN_00B99390(pass_id, selector)` calls selector vtable `+0xF0`, clears the
  texture-record cache at `DAT_0126F680..DAT_0126F6BC`, performs current-pass
  setup, calls selector vtable `+0xF4`, and then stores
  `DAT_011FFE30 = pass_id`, `DAT_011FFE2C = selector`, and
  `DAT_011AD8EC = 1`. Raw disassembly confirms the calls are
  `MOV EAX, [vtable +0xF0/+0xF4]; MOV ECX, selector; CALL EAX`, so
  `FUN_00BDB4A0` and `FUN_00BDF790` are selector-object setup callbacks.
- `FUN_00B994F0` supplies the same selector identity to setup and draw:
  it writes `DAT_011F91E0 = current_draw`, obtains the selector object from
  `*( *current_draw +0xC0)`, passes it to `FUN_00B99390` when the selector/pass
  changes, and then calls `FUN_00B98E80(current_draw, ...)`. `FUN_00B98E80`
  re-reads the selector as `*( *current_draw +0xC0)` (`piVar3[0x30]`) and uses
  that same object for the apply virtuals at `+0x78/+0x7C/+0x80/+0x84/+0x88`
  and `+0x8C`.
- `FUN_00BD4BA0` is a final shader-interface apply scope, not the material
  owner. It reads `DAT_011F91E0`, loads `ESI = *current_draw`, and then uses
  pass objects from `DAT_0126F74C +0x44/+0x5C` and interface fields
  `param_2 +0x30/+0x34`. It can recover the current selector as
  `*(ESI +0xC0)`, but it does not directly expose the type-3 material arrays.
- Native PBR implementation rule from the closed bridge: capture material-array
  state while selector setup callbacks are in scope, key it by selector object
  pointer, and recover that key during final apply/bind from
  `*( *DAT_011F91E0 +0xC0)`. `DAT_011FFE2C` is only a last-selector cache and
  should be treated as telemetry/diagnostic state, not the primary ownership
  key. Low-level `SetTexture`/`FUN_00E7EA00` hooks may only bind extra PBR
  resources when the current selector key has a live captured record; otherwise
  they must no-op to preserve compatibility with arbitrary graphics mods.
- `graphics_fnv_pbr_pplighting_runtime_variant_abi_audit.txt` and
  `graphics_fnv_pbr_pplighting_pixel_group_b_runtime_variant_followup.txt`
  close the first visible replacement target. Runtime-visible object PBR
  draws use PPLighting family 3: vertex group C (`SLS2%03i.vso`) plus pixel
  group B (`SLS2%03i.pso`). NewVegasReloaded_release maps the first safe
  ADTS specular pair to vertex index `12` (`SLS2012`, `SPECULAR`) and pixel
  index `17` (`SLS2017`, `SPECULAR`). That low-light pair carries
  `TEXCOORD1` light direction, `TEXCOORD6` view direction, `COLOR0` vertex
  color, `COLOR1` fog, `c1` ambient, `c3` light colors, `c27` toggles, and
  NVR PBR constants at `c32/c33`. The visible-runtime follow-up logs also show
  a common ADTS10 `LIGHTS=4` pair at vertex index `22` and pixel index `31`;
  that pair uses a different packed input ABI and requires a separate
  replacement shader.
- Current OMV implementation state: Native PBR hooks are installed
  automatically at startup when all target prologues are vanilla. The runtime
  `graphics.native_pbr.enabled` option controls only the visible material
  shader. The hook path captures the proven contract at
  selector setup slots `FUN_00BDB4A0`/`FUN_00BDF790`, `BSShader::SetShaders`,
  `FUN_00BD4BA0`, and `NiDX9RenderState::SetTexture`. Selector setup capture
  is keyed by the proven draw selector pointer from `*( *DAT_011F91E0 +0xC0)`
  and records the six material-array pointer fields `+0xAC..+0xC0` plus the
  pass-entry list at `+0x3C`. It now also captures selector index `1`,
  selector/draw-param `+0x30/+0x34` interface pointers, selector alternate
  fields `+0x7C/+0x80`, active copies `+0x84/+0x88`, and their `vtable +0x78`
  function pointers for telemetry. It classifies whether those interfaces match
  the proven vanilla `0x010EF544 -> 0x00E826D0` constant dispatcher, and it
  captures the final vanilla D3D shader handles from pass `+0x5C` vertex object
  `+0x34` and pass `+0x44` pixel object `+0x2C` only when their vtables match
  the proven vanilla `0x010EF87C`/`0x010EF7D4` objects. It now also classifies
  the current draw's PPLighting family and array indexes from the proven global
  shader arrays. The first visible replacement path uses the NewVegasReloaded
  `SetShaders` model: for opt-in PPLighting family-3 ADTS specular draws
  (`v12/p17` and skinned `v13/p17`) and ADTS10 `LIGHTS=4` draws (`v22/p31`),
  with vanilla diffuse `s0` bound and a selector/vanilla normal source
  available, OMV binds selector material resources through the proven
  renderer `+0x8C4` resolver, temporarily swaps the native
  `NiD3DPixelShader +0x2C` handle to an embedded NVR-compatible PBR pixel
  shader, calls vanilla `BSShader::SetShaders`, uploads the
  OMV-owned `c31` material flags and NVR-compatible `c32/c33` PBR defaults,
  and restores the vanilla handle immediately. The low-light embedded shader
  follows the Reloaded SLS2017 specular object shader ABI: `c1` ambient,
  `c3` primary light color array, `c27` toggles, `c32/c33` PBR data, `s0`
  diffuse/base, `s1` normal, `COLOR0` vertex color, `COLOR1` fog,
  `TEXCOORD0` UV, `TEXCOORD1` tangent-space light, and `TEXCOORD6`
  tangent-space view. The ADTS10 shader follows the packed `LIGHTS=4` pixel
  ABI with local position in `TEXCOORD1`, packed view direction in
  `TEXCOORD2..4.w`, point-light vectors in `TEXCOORD3..5`, and
  `PSLightPosition` at `c19`. Texture resolution is cached by
  resolver/resource pointer to avoid repeated resolver work on repeated
  material draws.
  Unsupported families, unsupported vertex indexes, and draws without the
  required material sources fall back to unmodified vanilla binding.

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
- if OMV later uses them, it must chain cleanly or disable that feature;
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

OMV's current independent active-depth resolve is preferable for
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
  OMV's compatibility goal;
- fog-aware AO logic is necessary even when AO is moved earlier.

## Compatibility-First Rules

These rules override feature ambition.

1. Default mode must be non-invasive.

   Default OMV graphics should use independent depth resolve, fullscreen
   passes, robust state restore, and read-only game data. It must not require
   native shader replacement.

2. Native shader replacement is opt-in.

   PBR/material work should be disabled unless explicitly enabled. If another
   graphics mod owns the same surface, OMV should log and disable that layer
   unless a tested compatibility path exists.

3. Do not extend native object layouts by default.

   TESReloaded extends shader object sizes. OMV should prefer side tables
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

Example names for OMV:

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

- OMV now exposes `EnvironmentData` in pixel shader constant `c6` as
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
- if a OMV replacement exists, create a replacement D3D shader;
- during the proven shader-interface/`SetShaders` boundary, bind replacement
  handles and constants only after the virtual `+0x78` contract is proven;
- restore/chain cleanly.
- never patch vanilla `NiD3DVertexShader`/`NiD3DPixelShader` allocation sizes;
- validate `0x0126F74C` only inside the draw hook;
- treat `0x011F91E0` as optional material context, not a guaranteed geometry
  pointer;
- leave `0x011F91BC/0x011F91C0` untouched unless a separate opt-in mode proves
  that forcing shader package selection is required and compatible.

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

Prepared follow-up scripts to run/analyze:

- `analysis/ghidra/scripts/graphics_fnv_effect_phase_contract_audit.py`
  - prove the safest scene/final image-space boundary;
  - identify DepthResolve/Shader Loader/NVR collision surfaces;
  - decide whether a post-first-person, pre-image-space hook is viable.
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

Completed native material/texture scripts:

- `analysis/ghidra/scripts/graphics_fnv_nvr_shader_replacement_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_nvr_material_texture_state_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_nvr_environment_color_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_material_draw_contract_followup_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_directional_light_alias_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_render_state_fog_color_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_sun_color_direction_followup_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_sun_light_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_sun_light_deep_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_sun_refslot_writer_provenance_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_texture_binding_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_native_texture_stage_state_followup_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_final_sun_color_renderer_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_material_texture_property_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_material_texture_slot_layout_followup_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_texture_runtime_binding_followup_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_dc_field_writer_provenance_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_brange_constructor_dc_deep_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_texture_array_stage_binding_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_pass_entry_apply_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_pass_dispatch_texture_stage_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_render_state_lowlevel_apply_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_renderer_global_virtual_apply_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_render_state_global_identity_followup_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pplighting_renderer_8b8_render_state_constructor_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_pbr_shader_interface_contract_audit.py`

They prove the safe draw-time shader bind point, the unsafe/proxy nature of
`0x011F91E0`, the shader object allocation-size hazard, and the render-state
sampler/texture-stage tracking maps. They also prove the high-level weather
controller and transition-percent ownership, while rejecting a simple NVR raw
weather color walk as a safe compatibility contract. Final renderer fog color is
now proven through `NiDX9RenderState::SetFog`. The sun-light scripts prove the
native sky sun object path, screen-space sun coordinates, and some fog/range
sky fields. They also prove `Sun +0x1C` is a managed reference slot, not a
layout-safe PBR constant, and reject the Reloaded `Sun +0x1C/Main +0x1C` alias
path for default PBR. The final sun/color renderer audit proves renderer-owned
per-draw light arrays (`LightColors`/`LightData`) and real `NiLight +0xD4`
diffuse-color input through the native light list, but those arrays are
draw-local constants, not persistent `PSY_SunColor`. The material texture
property audit proves `BSShaderPPLighting` branch ownership and the
`param_1[0x37]`/`+0x6C` gate. The slot-layout follow-up proves canonical source
map names, record-side slot IDs, and the `FUN_00877A30` slot-storage pointer
layout. The runtime binding follow-up proves the paired `FUN_00BDB4A0` /
`FUN_00BDF790` setup variants and pass IDs `4/5` plus `0x250/0x251`. The first
`+0xDC` provenance audit rejects broad renderer writers as unproven because no
candidate writer references the PPLighting-like vtables, but it exposes
`FUN_00539960 -> FUN_00B66F50` and the adjacent B-range `+0xDC` helper cluster
as the next concrete lead. The B-range deep audit proves the real vtable base
`0x010AE0D0`, corrects the earlier method-slice addresses, establishes
constructor/setter/destructor/copy ownership for `+0xDC`, and identifies that
field as `spTexEffectData` rather than material texture data. The remaining PBR
texture gap is no longer the six runtime arrays themselves or the pass-entry
layout: the texture-array stage audit proves the `B70590` helper family is an
active object-list iterator, and the pass-entry apply audit proves
`BA8C50`/`BA8EC0` storage plus `BA9EE0` construction. The pass-dispatch audit
proves the B7 dispatcher mutates pass entries and shader constants but does not
itself reach `E88A20`. The low-level apply audit proves
`E88FC0`/`E89060` and `E890C0` are tracked texture-stage/sampler-state cache
helpers. The renderer-global virtual audit proves `E7E8D0` seeds
`DAT_0126F6C4` from the renderer object, `DAT_0126F6C0` from renderer `+0x288`,
and `DAT_0126F6C8` from renderer `+0x8B8`; it also proves `E89250/E892D0`
flush tracked state through `DAT_0126F99C +0xC0/+0xCC`. The global identity
follow-up proves `DAT_0126F99C` and `DAT_0126F6C8` are both seeded from the
same `renderer +0x8B8` pointer during renderer setup. The constructor audit
proves `renderer +0x8B8` is the vtable-B render-state object created by
`E91590` in `E72E60`, so `E7EA00 +0xDC` is now the final
`NiDX9RenderState::SetTexture @ 0x00E88A20` route for PPLighting pass-entry
resources. The selector side-table and vtable bridge audits close the PBR
identity gap: `BDB4A0`/`BDF790` are selector vtable `+0xF0/+0xF4` setup slots,
`B994F0` passes the selector from `*( *current_draw +0xC0)` into setup and
draw, `B98E80` uses that same selector for apply virtuals, and final apply can
recover it through `*DAT_011F91E0`. Native PBR state must therefore be captured
at selector setup time and keyed by selector object pointer; final texture bind
is allowed to use only a live captured record for that selector and must
otherwise no-op.

Prepared native PBR follow-up scripts:

- `analysis/ghidra/scripts/graphics_fnv_pbr_shader_virtual_interface_followup_audit.py`
  - resolve `FUN_00B55560(1)` object identity and the writers for its
    `+0x30/+0x34` shader-interface fields;
  - identify concrete virtual `+0x78` targets;
  - prove whether those targets upload constants, bind textures, or mutate
    shader objects.
- `analysis/ghidra/scripts/graphics_fnv_pbr_shader_interface_object_vtable_audit.py`
  - decompile selector index `1` factory `FUN_00B7A380`;
  - trace `+0x30/+0x34` interface writers and factories such as
    `FUN_00B7E330`, `FUN_00E7F5D0`, and `FUN_00E7F430`;
  - print/decompile `NiD3DPixelShader` and `NiD3DVertexShader` vtable windows
    around the handle getter/setter and apply-adjacent slots.
- `analysis/ghidra/scripts/graphics_fnv_pbr_selector_object_constructor_vtable_audit.py`
  - decompile selector constructors `FUN_00B79B00` and `FUN_00BD44C0`;
  - print data windows for shader-interface vtable candidates
    `0x010EF544/0x010F003C`;
  - decompile functions reached from those vtable windows, especially the
    candidate `+0x78` apply slots and shader handle getter/setter slots.
- `analysis/ghidra/scripts/graphics_fnv_pbr_selector_setup_vtable_deep_audit.py`
  - print/decompile selector vtable `0x010AF2F8`, especially setup slots
    `+0x4C/+0xC0/+0x11C/+0x144/+0x150`;
  - trace which setup slots create or assign selector `+0x30/+0x34`;
  - prove whether those slots only manage constant/interface records or also
    mutate native shader handles.
- `analysis/ghidra/scripts/graphics_fnv_pbr_selector_setup_raw_slot_followup_audit.py`
  - raw-disassemble unresolved selector setup slots `+0xC0` and `+0x150`;
  - decompile wrapper children `+0x148` and `+0x14C`;
  - prove whether any late selector setup/finalize path mutates native shader
    handles after the `+0x11C` constant-interface setup.
- `analysis/ghidra/scripts/graphics_fnv_pbr_shader_creation_lifecycle_followup_audit.py`
  - decompile `BSShader::CreateVertexShader` and `BSShader::CreatePixelShader`;
  - print call-site windows inside selector slots `+0x148/+0x14C`;
  - prove creation return ownership and whether a side-table replacement model
    can stay layout-compatible with other graphics mods.
- `analysis/ghidra/scripts/graphics_fnv_pbr_shader_creation_callsite_args_audit.py`
  - print backward/forward instruction windows around the five PPLighting shader
    create calls;
  - identify concrete HLSL paths, define arrays, profiles, cache names, and
    global array destinations;
  - decompile `NiD3DVertexShader`/`NiD3DPixelShader` handle getter/setter vtable
    slots used by creation and `SetShaders`.
- `analysis/ghidra/scripts/graphics_fnv_pbr_shader_handle_getter_setshaders_contract_audit.py`
  - dump raw bytes and disassembly for unbound shader handle getter/setter
    thunks including `0x00BE0B10`, `0x00E95D50`, and adjacent tiny slots;
  - raw-disassemble `BSShader::SetShaders @ 0x00BE1F90` even when Ghidra has
    not created a function for it;
  - prove whether PBR replacement should hook getter slots, substitute handles
    inside `SetShaders`, or avoid mutation until a safer binding point exists.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_pass_shader_pair_contract_audit.py`
  - enumerate all functions that read the PPLighting vertex/pixel global shader
    arrays after creation;
  - prove how vertex groups `0x011FDD88/0x011FDE04/0x011FDE5C` are paired with
    pixel groups `0x011FDA48/0x011FDB08`;
  - prove which pair is written into current pass `+0x5C/+0x44` before
    `SetShaders`, so the first visible replacement can target one known-safe
    shader family instead of guessing from array names.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_shader_input_signature_followup_audit.py`
  - inspect PPLighting shader creation callsite windows for source/profile/
    define arguments that identify a first replacement target family;
  - trace the current-pass shader-interface apply path and constant-interface
    helpers that run before `BSShader::SetShaders`;
  - dump call windows for texture-stage and sampler-state helpers so the first
    visible replacement can use a proven input/register/texture contract.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_shader_abi_closure_audit.py`
  - close the replacement ABI by matching vanilla shader source/profile tables
    to PPLighting global-array indexes;
  - prove that the current PBR pixel ABI can only target regular/skinned
    specular vertex indexes `8` and `9` until additional vertex outputs are
    proven;
  - record the `vs_2_0`/`ps_2_0` vanilla profile facts and the intentional
    embedded `ps_3_0` replacement boundary.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_interface_record_table_audit.py`
  - reduce `FUN_00E7F430` record-registration calls in PPLighting setup
    functions into record-key/value/list tables;
  - decompile the `0x010EF544` shader-interface vtable helper slots used by
    `FUN_00E826D0` for record type classes;
  - decompile the PPLighting pass-entry helper family and print calls to
    `BA8C50`/`BA8EC0`/`BA9EE0` so texture-stage/resource ownership can be
    mapped for one replacement family.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_pass_entry_arg_table_followup_audit.py`
  - decompile `E7F430`, `BA9EE0`, `BA8EC0`, and `BA8C50` together so their
    field writes and variable-array behavior are visible in one output;
  - emit normalized callsite tables where `stack_arg0` is the callee's first
    stack argument and ECX owner writes are shown separately for thiscall
    helpers;
  - reduce unique `E7F430` record tuples and `BA9EE0` pass-entry tuples by
    PPLighting setup/helper function without assigning unproven material-map
    semantics.
- `analysis/ghidra/scripts/graphics_fnv_pbr_shader_interface_missing_vfunc_followup_audit.py`
  - verify the `0x010EF544` shader-interface vtable slots after the
    interface-record audit;
  - force-create/decompile raw helper targets `0x00E84D00` and `0x00E85C40`
    where the previous audit resolved slot pointers but Ghidra had no function
    body;
  - determine whether record type classes `0x40000000` and `0x60000000`
    perform texture binding, constants, render state, or another operation.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_pass_id_stage_correlation_audit.py`
  - make the entry `+0` versus entry `+4` distinction explicit for all scanned
    `FUN_00BA9EE0` PPLighting pass-entry construction rows;
  - correlate the normalized constructor rows with the proven
    `FUN_00E7EB00 -> FUN_00E7EA00` apply path, where entry `+4` is consumed as
    the final texture stage/key on the `NiDX9RenderState::SetTexture` route;
  - re-print render-state vtable A/B slots and the `E7EA00` matched lines so
    the remaining output can prove or reject a stage/resource policy before
    any visible BRDF shader replacement is enabled.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_pass_resource_provenance_followup_audit.py`
  - backtrack register-valued `FUN_00BA9EE0` arguments at resource-bearing or
    unresolved PPLighting pass-entry construction rows;
  - identify whether entry `+0x0C` resource-array values originate from source
    texture arrays, active-object virtual getters, fallback globals, or
    non-texture state;
  - keep the visible BRDF replacement blocked until entry `+4` stage keys have
    concrete resource provenance on the proven `E7EA00 -> E88A20` route.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_selector_driver_arg_provenance_audit.py`
  - decompile `FUN_00BDF790`, the PPLighting selector/pass-entry driver now
    shown to call the relevant helper families;
  - normalize the direct arguments passed from `BDF790` into helper families
    and resource helpers such as `00B70590`, `00B70600`, `00B70680`,
    `00B70700`, and `00B707D0`;
  - trace forwarded helper parameters back toward concrete material fields or
    getters before assigning albedo/normal/glow/height/environment semantics.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_resource_resolver_vtable_audit.py`
  - audit the `FUN_00E7EA00` resource resolver path
    `DAT_0126F6C4 +0x8C4 -> vtable +0x0C`;
  - find `renderer +0x8C4` writers/destructors and dump candidate
    `0x010EDAxx`/`0x010EDBxx` vtables, especially slot `+0x0C`;
  - prove whether `entry +8` resources resolve to texture objects, persistent
    source textures, render targets, or non-material resources before visible
    PBR shader replacement is enabled.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_resolver_constructor_slot_followup_audit.py`
  - force-create/decompile `FUN_00E90A80`, `FUN_00E88EB0`,
    `FUN_00E69640`, and unresolved adjacent target candidates from the broad
    resolver audit;
  - re-print the `FUN_00E72E60` allocation path around
    `FUN_00AA13E0(0x10) -> FUN_00E90A80 -> renderer +0x8C4`;
  - scan `FUN_00E90A80` for constructor-written vtable immediates, dump slots
    `+0x00`, `+0x0C`, and `+0x10`, and decompile those slot targets;
  - distinguish the actual 16-byte resolver object from adjacent persistent
    source texture renderer-data teardown records before assigning PBR texture
    semantics.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_resolver_texturedata_vtable_followup_audit.py`
  - follow `FUN_00E90B10` below the proven resolver slot into
    `resource +0x24` renderer data and the `FUN_00E68EF0` creation path;
  - scan `FUN_00E68EF0`, `FUN_00E68A80`, `FUN_00E88EB0`, `FUN_00E90A80`, and
    `FUN_00BA8A90` for vtable immediates, while also dumping the fixed
    `0x010EDAxx`/`0x010EDBxx`, `0x010EF718`, and `0x010F086C` candidates;
  - decompile renderer-data and returned-wrapper slot targets for
    `+0x98`, `+0x9C`, `+0xA4`, `+0xA8`, `+0xAC`, and `+0xB4`;
  - prove the final object returned to `NiDX9RenderState::SetTexture` before
    assigning PBR texture semantics.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_texture_semantic_stage_followup_audit.py`
  - correlate resource-bearing `FUN_00BA9EE0` rows with material texture
    getters such as Dark/Detail/Gloss/Glow/Bump/Decal Map or active-object
    resource helpers;
  - print stage-key/resource callsite windows while preserving the proven
    `BA9EE0 -> E7EB00/E7EA00 -> E90B10 -> SetTexture` final bind chain;
  - determine whether one PPLighting family has enough material semantic proof
    to safely enable a visible BRDF replacement.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_texture_property_field_source_audit.py`
  - audit the producer-side material texture contract after the semantic-stage
    follow-up rejected direct named-map usage;
  - dump `BGSTextureSet` vtables, especially `TextureSet +0x30 -> vtable
    +0x8C`, and decompile texture-set slot helpers such as `FUN_00877A30` and
    `FUN_0046EBF0`;
  - decompile and pattern-scan `FUN_00B66640`, `FUN_00B68660`,
    `FUN_00B690D0`, `FUN_00BDAF10`, `FUN_00BDB4A0`, and `FUN_00BDF790` to map
    property type `3` fields and arrays `+0xAC..+0xC0` back to
    diffuse/normal/glow/height/env resources.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_texture_writer_callsite_deep_audit.py`
  - deep-audit `FUN_00539960` and `FUN_0053A090`, the two producer callsites
    now proven to call both `FUN_00B68660` and `FUN_00B66640`;
  - recover ECX and stack arguments for each texture-array writer/flag
    initializer call so the property object, layer/index, and resolver object
    are explicit;
  - inspect the resolver virtual slot `+0x90` used by `FUN_00B68660` to fill
    the six `+0xAC..+0xC0` arrays;
  - determine whether these writer callsites connect the engine-labeled
    diffuse/normal/glow/height/env arrays to `BGSTextureSet` slot indexes or to
    another source-texture producer before visible native PBR is enabled.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_texture_source_callback_contract_audit.py`
  - follow the proven `FUN_00592CF0` object passed into `FUN_00B68660` instead
    of the unrelated renderer-side `0x010F086C` vtable;
  - raw-disassemble `FUN_00592F30`, `FUN_006E5CC0`, `FUN_00B55840`,
    `FUN_00592CF0`, and the `BGSTextureSet +0x30` `+0x8C/+0x90/+0x94` slots;
  - print barrier-limited stack arguments and RET cleanup for the exact
    `FUN_00B68660`/`FUN_00B66640` callsites and for the texture-load callback;
  - prove whether `FUN_00592F30` consumes the second callback argument as the
    output smart-pointer slot and whether callback kinds `0..5` map directly to
    diffuse/normal/glow/height/env/env-mask before visible native PBR uses those
    resources.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_material_array_stage_contract_audit.py`
  - use the now-proven material texture arrays as the input contract and focus
    on `FUN_00BDAF10`, the material/property helper reached by
    `FUN_00BDF790`;
  - print raw `FUN_00BA9EE0` call windows from `FUN_00BDAF10`, including
    stack args, nearby material array reads, and stage-key pushes for
    `0x93/0x94/0x1EF/0x1F1..0x1F5`;
  - prove whether `FUN_00BDAF10` consumes only diffuse/glow arrays or also
    normal/height/env/env-mask arrays before the first visible native PBR shader
    relies on those stages.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_remaining_array_consumer_followup_audit.py`
  - scan every `FUN_00BA9EE0` caller plus the known PPLighting pass-helper
    family for remaining material array reads `+0xB0/+0xB8/+0xBC/+0xC0`;
  - print candidate summaries, decompile matches, raw material-offset windows,
    and `FUN_00BA9EE0` stack-argument windows so unrelated stack/object offsets
    can be separated from real type-3 material-array consumers;
  - prove whether normal/height/env/env-mask arrays feed any draw-stage
    resource rows or only writer flags/serialization before visible PBR binds
    replacement shaders.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_material_semantic_stage_closure_audit.py`
  - filter the remaining-array findings into real material-object field reads
    versus `[ESP +...]` helper-call stack offsets;
  - print interpreted `FUN_00BA9EE0` rows with the proven field mapping
    (`entry +0`, `entry +4`, `entry +7`, `entry +9`, and resource slots at
    `entry +0x0C`);
  - print selector-driver helper calls from `FUN_00BDF790`, `FUN_00BB4740`,
    and `FUN_00C058F0`, then decompile the helper families that emit final
    stage/key rows, so one safe material-map-to-stage semantic contract can be
    proven before any visible PBR shader replacement.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_bdaf10_callsite_param_closure_audit.py`
  - normalize the exact `FUN_00BDB4A0 -> FUN_00BDAF10` callsite at
    `0x00BDBAA7` as a `thiscall`, separating ECX from the six stack arguments;
  - trace the `BDAF10` `param_3` resource used by stage rows
    `0x93/0x94/0x1F2/0x1F3` back to its `FUN_00BDB4A0` source;
  - prove whether `FUN_00BDAF10` binds a material texture resource or only
    emits predicate-selected rows that use a renderer/global fallback resource
    and active-object iterator resources.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_draw_scope_material_pointer_contract_audit.py`
  - scan `FUN_00BA8C50`, `FUN_00BA8EC0`, `FUN_00BA9EE0`,
    `FUN_00BDAF10`, `FUN_00BDB4A0`, `FUN_00BDF790`, `FUN_00BD4BA0`,
    `BSShader::SetShaders @ 0x00BE1F90`, `FUN_00E7EA00`,
    `FUN_00E7EB00`, `FUN_00E826D0`, and
    `NiDX9RenderState::SetTexture @ 0x00E88A20`;
  - prove whether final apply still has a recoverable type-3 material property
    pointer, whether `entry +0x0B` layer bytes written by `FUN_00BDAF10` are
    read later, and which pass-entry fields are consumed at draw time;
  - decide whether a safe native PBR implementation can key a side table by
    pass-entry owner, entry pointer, shader interface, or current draw scope
    before binding any extra material textures.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_entry_to_texture_record_bridge_audit.py`
  - focus on the bridge from PPLighting pass-entry rows to low-level
    texture-record apply by decompiling and printing raw call windows for
    `FUN_00B7DD50`, `FUN_00B7DDE0`, `FUN_00B7E150`, `FUN_00E7EB00`,
    `FUN_00E7EA00`, `FUN_00E826D0`, and `FUN_00BD4BA0`;
  - print register state at every `FUN_00E7EB00` call and at the
    `FUN_00E7EB00 -> FUN_00E7EA00` transition, especially `ECX`, `EDI`, and
    stack arguments;
  - prove whether the low-level texture-record apply path retains a pointer to
    the original `FUN_00BA9EE0` entry, `entry +0x0B` layer byte, or type-3
    material property, or whether native PBR must capture those before the
    bridge.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_current_pass_texture_record_slot_provenance_audit.py`
  - classify every known `FUN_00E7EB00` callsite, including
    `FUN_00B7DD50`, `FUN_00B7DDE0`, `FUN_00B7DED0`, `FUN_00B7DFE0`,
    `FUN_00B7E150`, `FUN_00BCA760`, `FUN_00BE2170`, `FUN_00BE21B0`, and
    `FUN_00C04310`;
  - trace writers for records under `*(DAT_0126F74C +0x24)`, especially
    slots `+0`, `+4`, `+0xC`, and `+0x14`, and print call argument/register
    windows for `FUN_00B7DD50`, `FUN_00B7DDE0`, `FUN_00B7E150`,
    `FUN_00C03230`, `FUN_00E7DE90`, and `FUN_00E7EB00`;
  - prove whether the source object at `FUN_00B7DDE0`/`FUN_00B7E150`
    `param_1 +0x0C` can be tied back to type-3 material arrays and the
    `BDAF10` layer byte, or whether final texture-record state is too lossy
    for visible PBR material recovery.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_selector_side_table_key_contract_audit.py`
  - trace `FUN_00B98E80`, `FUN_00B99390`, `FUN_00B994F0`,
    `FUN_00BD4BA0`, `FUN_00BDB4A0`, `FUN_00BDF790`, `FUN_00BDAF10`,
    `FUN_00BA9EE0`, `FUN_00BA8EC0`, `FUN_00E826D0`, and the
    `DAT_011F4748`, `DAT_011F91E0`, and `DAT_0126F74C` globals;
  - prove whether the current-pass context (`piVar3 +0x27` /
    `DAT_011F4748 +0x0C`) can be correlated with the selector material arrays,
    current draw identity, or `FUN_00BA9EE0` pass-entry list owner;
  - decide which side-table key is safe for native PBR texture capture, or
    prove that the implementation needs a hook closer to selector/pass-row
    construction because no stable later identity exists.
- `analysis/ghidra/scripts/graphics_fnv_pbr_pplighting_selector_vtable_draw_identity_bridge_audit.py`
  - decode the data references to `FUN_00BDB4A0` and `FUN_00BDF790` as
    selector-object vtable slots, especially candidate slots `+0xF0/+0xF4`
    called by `FUN_00B99390`;
  - prove whether `FUN_00B994F0` passes the same selector object pointer
    `*( *current_draw +0xC0)` into setup (`FUN_00B99390`) and current draw
    dispatch (`FUN_00B98E80` / `piVar3[0x30]`);
  - prove whether final apply can recover that same selector object pointer
    from `*DAT_011F91E0`, making it a safe side-table key for captured PBR
    material arrays.
  - result: proven. All seven candidate selector vtables put
    `FUN_00BDB4A0` at `+0xF0` and `FUN_00BDF790` at `+0xF4`; `FUN_00B99390`,
    `FUN_00B994F0`, `FUN_00B98E80`, and `FUN_00BD4BA0` preserve/recover the
    same selector identity needed for a side-table key.

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

OMV should become a phase-aware graphics runtime first and a native shader
replacement system second.

The correct order is:

1. phase-aware fullscreen effects;
2. fog/camera/environment constants;
3. screen-space godrays;
4. optional native shader replacement;
5. optional PBR-like material shaders.

This keeps the useful features available to broad mod setups while reserving
the risky material-layer work for explicit compatibility-gated modes.

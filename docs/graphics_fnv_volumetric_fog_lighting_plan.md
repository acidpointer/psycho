# FNV volumetric fog and lighting research plan

Date: 2026-07-17

Scope: best-quality volumetric fog and volumetric lighting for OMV, using
Anomaly Screen Space Shaders 23.5, TESReloaded/NVR, OMV's proven FNV contracts,
and permissively licensed post-process references as research inputs.

## Executive decision

OMV can implement both effects, but they must share one engine-owned atmosphere
pipeline rather than be two unrelated fullscreen shaders.

Implementable after Phase 0 closes the listed composition contract:

- depth-terminated distance and exponential height fog;
- heterogeneous world-anchored fog density;
- linear-radiance extinction and in-scattering after Phase 0 proves the source
  transfer function and exposure state;
- directional sun in-scattering using native FNV sun/sky/fog data;
- screen-space occluded shafts used as a final directional-scattering modulation;
- half-resolution integration, temporal reprojection, and bilateral upsampling;
- world-only composition before first-person and UI rendering.

Not yet implementable honestly:

- true shadow-map-marched directional volumetric lighting;
- shadowed point/spot volumetric lights;
- complete replacement of native fog on every opaque, transparent, water, sky,
  and forward-rendered path.

Those require engine resource and ownership contracts that are not currently
proven. They are later phases, not shader guesses.

## What Anomaly SSS actually provides

The useful source root is:

`.research/Anomaly - SSS 23.5`

### Fog

The main height-fog logic is in:

`92 - FOG/gamedata/shaders/r3/screenspace_fog.h`

It adds a height term to existing distance fog and blends fog color toward the
sun color. It is inexpensive and useful as a visual reference, but it is not
volumetric integration: it has no transmittance integration, density volume,
shadow sampling, or temporal accumulation.

The package's "fog scattering" pipeline is:

- `92 - FOG/gamedata/shaders/r3/ssfx_fog_scattering_blur.ps`
- `92 - FOG/gamedata/shaders/r3/ssfx_fog_scattering.ps`

It blurs scene color at reduced resolution and spreads bright color where fog
is dense. It is not physically based scattering and is not depth-bilateral. It
also contains an out-of-bounds offset loop. OMV should not port this as its
primary volumetric fog.

### Directional volumetric sun

The strongest directional reference is:

`08 - New Shadow & Light Features/gamedata/shaders/r3/accum_volumetric_sun.ps`

It ray-marches the camera ray through the active sun shadow map using 15, 25,
or 30 samples, jittered by an engine-provided texture. This is genuine shadowed
directional volumetric lighting, but its result depends on engine-owned linear
depth, the active cascade shadow texture, `m_shadow`, sun constants, and a
dedicated volumetric accumulator.

### Local volumetric lights

The local-light implementation is centered on:

- `08 - New Shadow & Light Features/gamedata/shaders/r3/accum_volumetric.vs`
- `08 - New Shadow & Light Features/gamedata/shaders/r3/accum_volumetric.ps`
- `08 - New Shadow & Light Features/gamedata/shaders/r3/ssfx_volumetric_blur.ps`
- `08 - New Shadow & Light Features/gamedata/shaders/r3/ssfx_volumetric_combine.ps`

The engine renders 24-120 slices through each point/spot light volume into a
one-eighth-resolution FP16 target. The shader consumes per-light bounds,
position/radius, color, cookie projection, light shadow map, and light shadow
matrix. This is not portable without equivalent engine ownership.

### Temporal and noise lessons

Anomaly's whole-scene TAA depends on four MRT G-buffer outputs and motion vectors
for static, skinned, foliage, sky, HUD, and procedural animation paths. That
contract does not transfer to FNV.

Transferable ideas are:

- jitter ray starts with blue/interleaved noise;
- render expensive volume integration below full resolution;
- retain unsharpened history;
- reject history at depth and geometry discontinuities;
- apply volume effects before the final post-process chain.

There is no atmospheric Rayleigh/Mie LUT system or volumetric-cloud renderer in
this Anomaly package.

## Other references

### TESReloaded/NVR

`.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/VolumetricFog.fx.hlsl`
is the closest FNV-specific fog reference. It proves useful input selection:
active fog color/range/power, sky upper/lower/horizon colors, sun direction,
sun light/disk colors, daylight, camera position, and exterior state.

Its 32-step height layer and tuned formulas should not be copied directly. OMV
can integrate exponential height density analytically and use samples only for
heterogeneous density until it owns a true per-sample shadow visibility source.

NVR's sun and local shadow code is valuable as an ownership map, but NVR creates
and owns its own cascade atlas, point cubemaps, spotlight maps, matrices, formats,
and update lifetime. OMV cannot sample those resources as if they were vanilla.

NVR is GPL-3.0-or-later with additional terms. Treat it as an architecture and
contract reference unless licensing requirements are deliberately adopted.

### GShade/ReShade research

The CC0/MIT fog examples under `.research/GShade-master/Shaders` are useful for
depth-aware composition and fallback modes. They are not the target quality.
Use independently sourced CC0 blue noise rather than copying an asset with
unclear provenance.

No explicit license was found in the Anomaly SSS package root. Its code should
be treated as research/architecture input, not copied into OMV.

## Proven OMV/FNV inputs

OMV already owns:

- full-resolution world INTZ depth after `RenderWorldSceneGraph`;
- first-person INTZ depth after `RenderFirstPerson`;
- exact near/far, frustum, depth direction, and camera world transform;
- capture epochs and camera-cut/teleport rejection patterns;
- fog start/end/power from the active `BSFogProperty`;
- projected sun screen position and daylight;
- native sky upper/lower/horizon colors;
- native directional sun and sun-disk colors;
- native sun direction;
- exterior/interior state;
- FP16 half-resolution render targets and temporal history patterns;
- a world-only post-world/pre-first-person boundary;
- an HDR world target in observed runtime paths before vanilla image space.

The HDR target format does not by itself prove linear radiance. Phase 0 must
still establish the scene transfer function, native color encoding, exposure
state, and alpha semantics on the active DXVK path before physical composition
is enabled.

Authoritative fog evidence also proves that active `BSFogProperty` fields are:

- `+0x20/+0x24/+0x28`: RGB fog color;
- `+0x2C`: fog start;
- `+0x30`: fog end;
- `+0x60`: fog power.

The color fields are populated by the constructor and published by the camera
writer into the native fog shader constants. `EnvironmentFrame` can therefore
be extended with validated RGB from the same already validated object.

The completed stage-ownership audit further proves:

- `BSShaderManager` camera publication copies `BSFogProperty +0x20/+0x24/+0x28`
  into the active fog constant block before world drawing;
- there are nine direct write sites for active fog R and seven each for G/B,
  with the extra R writes belonging to default-versus-active branches rather
  than a separate color source;
- all 14 source-derived NVR fog-removal sites replace direct calls to
  `GetFogProperty @ 0x00B55520` across multiple shader families;
- `NiDX9RenderState::SetFog @ 0x00E87C50` consumes the selected property's fog
  enable/mode/range/color and emits D3D9 fog render states per draw;
- NVR's underwater intervention replaces a separate two-float writer at
  `0x004EC8EE`, so underwater fog is not covered by the scene fog-property
  replacement alone.

This proves broad per-draw native fog ownership, not exhaustive draw-class
coverage. It strengthens the supplemental-fog decision and rejects a guessed
single global render-state toggle as a safe full replacement.

## Missing contracts

### Color space and exposure

Beer-Lambert composition is valid only when source color, fog/sky/sun inputs,
and in-scattered radiance share one linear space. OMV's native-sky path currently
linearizes native colors explicitly, and NVR's fog reference linearizes both its
source and fog color before composition. Required runtime contract:

- world-source transfer function and channel range;
- whether vanilla image space or DXVK has applied exposure or tonemapping;
- native fog, sky, and sun color encoding;
- world-target alpha meaning and preservation rule;
- a fail-closed bypass when these facts disagree or are unavailable.

### Native fog replacement

Native fog is already applied across engine draw paths. Applying a full distance
fog replacement afterward can double extinction and color. A safe first version
must add only a supplemental heterogeneous/height medium while preserving native
distance fog.

A full replacement needs proof of:

- every opaque, alpha-tested, transparent, water, sky, particle, and forward fog path;
- one intervention point that disables native fog without losing coverage;
- restoration behavior for first person, UI, image space, and other plugins;
- underwater and interior ownership.

Static audit status: the 14 known NVR `GetFogProperty` interception sites and
the separate underwater site are now mapped. Runtime draw coverage is still
required to show that this source-derived list covers every relevant draw class
and that disabling those paths does not leave mixed native/post fog.

### Directional shadows

No shader-readable vanilla sun shadow texture contract is proven. The existing
`ShadowProj` global is a matrix, not a texture. NVR replaces vanilla shadow-map
ownership with its own resources.

Required contract:

- texture handle and lifetime;
- depth/VSM/EVSM encoding;
- light-space matrix;
- cascade count, split/containment, atlas layout, and transition rules;
- comparison/bias behavior;
- active render phase and compatibility owner.

### Local lights

`ShadowLightShader::UpdateLights @ 0x00B78A90` publishes draw-scoped arrays for
up to ten lights selected for a material/pass. That is not yet a stable scene
light list.

Required contract:

- stable visible-light enumeration or a safe bounded value-copy hook;
- world-space position, direction, type, radius, and color semantics;
- deduplication identity and frame lifetime;
- spot cookie and shadow resources;
- behavior for player, muzzle, projectile, and scripted lights.

The first light-resource audit confirms that `UpdateLights` is called from the
current PPLighting draw setup, reads the current pass's bounded light array, and
writes up to ten draw-scoped transformed constants. It is not a persistent
scene-visible light list. `ShadowProj` is likewise a per-draw matrix constant,
not a shadow texture.

The focused lifecycle audit closes one local-light ownership link. Each selected
shadow-light object is a `0x250`-byte object constructed by `0x00B9FDA0`; its
refcounted `+0x10C` rendered texture is initialized null, lazily acquired by
`0x00B6D3F0`, assigned by `0x00B5AEE0`, and returned through `0x00B6D4C0` on
invalidation or destruction. The manager grows this reusable pool with rendered
texture type `0x2B`. `0x00B9F780` waits for the queued shadow render, renders
offscreen into `+0x10C`, applies image-space effect `0x11` in place, and can
publish the resulting texture through shader-interface selector 9. Type `0x2B`
resolves to a 1024x1024 texture. Its default format value is `0x72`
(`D3DFMT_D24X8`); `SetShaderPackage @ 0x00B4F710` changes it to `0x15`
(`D3DFMT_A8R8G8B8`) for the ATI compatibility path, so depth representation and
sampling cannot be assumed portable across renderer modes. The paired
`0x00BA30F0`/`0x00BA3130` calls are semaphore signal/wait operations for queued
render work, not texture-slot bindings. This proves a retained per-local-light
rendered texture, not a directional sun shadow texture. Selector 9 builds an
image-space copy shader (`base_old.v.hlsl` plus `copy.p.hlsl`), and the
`+0x124` branch that publishes through it defaults off; it is not proof of the
normal local-shadow sampler. The normal shader consumer, depth comparison
semantics, projection pairing, and safe cross-plugin lifetime still require
closure before OMV consumes the resource.

The `SimpleShadow` sampling audit identifies the native shader packages without
closing that resource link. `PPLighting` vertex group C entries 89-91 are three
`lighting\2x\v\SimpleShadow.v.hlsl` variants. `FUN_00BF0720` installs each one
through the refcounted vertex-shader setter `0x00B79950` and pairs each with the
pixel family rooted at group B entry 152 through the refcounted pixel-shader
setter `0x00B80600`. When shader mode `0x011F91B0` is 3, the observed pixel
lookup is `0x011FDD68 + 0x011F948C * 8`; otherwise it uses entry 152 directly.
The other five `SimpleShadow.p.hlsl` descriptors have no direct code references
in the audit, so descriptor construction alone does not establish that every
variant is reachable.

This is shader-package setup, not texture binding. `0x00B80600` only updates the
package pixel-shader pointer at `+0x44`; it never calls D3D `SetTexture`.
`PROJ_SHADOW` is a shader compile define, while `ShadowProj` backing
`0x011FD968` is populated separately by the per-draw matrix writer
`0x00B7B930`. The diagnostic current-shadow global `0x011F9174` has one write
from the selected-light render loop and no read references. No audited path
therefore carries the selected object's `+0x10C` type `0x2B` texture into a
`SimpleShadow` sampler. Texture stage, sampler/comparison state, projection
pairing, and safe lifetime remain unproven.

The runtime-consumer follow-up provides negative closure for reusing these
resources in OMV. The descriptors resolve `SHADOWMAP` as the entry point and
compile `SimpleShadow.p.hlsl` variants with `DEPTHBIAS=-0.1`, `SAMPLE`,
`PASSES`, `SHADOWMODE`, and optional `ALPHATEST` controls. The three configured
shader-interface pointers are consecutive globals `0x011FE8BC`, `0x011FE8C0`,
and `0x011FE8C4`. `0x00BA53C0` merely copies one of those refcounted pointers
into a setup local; none of the three globals has an outside direct reference.
The package blocks register D3D render states, not texture-stage or sampler
records, and contain no `+0x10C` field access.

The D3D `SetTexture` and sampler-state wrappers are reached through renderer
vtables, so the lack of direct calls alone is not proof that the native shader
never samples a shadow texture. The stronger result is that every identified
per-light `+0x10C` read remains in allocation, rendering/filtering, optional
selector-9 publication, invalidation, or destruction code. The apparent
`+0x10C` hits in PPLighting draw helpers are unrelated address/vtable offsets;
for example, `0x00B7C120` binds the current rendered texture returned by
`0x004BC320`, and the already rejected `0x00B7CB14` hit is a vtable method call.

`ShadowProj` is also not the missing pair. `0x00B7E430` registers it as four
vertex constant vectors at register `0x12`, backed by `0x011FD968`, and
`0x00B7B930` is the only writer. No path copies the local-shadow object's
matrices at `+0x10`, `+0x50`, or `+0x90` into that backing block. The native
engine may complete an indirect internal sampling path that static references
do not expose, but no stable texture-plus-projection ABI is available to OMV.
Accordingly, OMV must not retain or sample type `0x2B`; Phase 6 remains blocked
until OMV owns explicit local-light shadow resources or a later audit proves a
complete native draw-scoped value-copy contract.

Rendered-texture type `0x2D` in the `RenderShadowMaps` tail is a separate
borrow passed into a refcounted global/member setter at `0x0066B0D0`. It does
not flow into the per-light `+0x10C` pool in the proven chain; its exact purpose
remains unclassified but it is not evidence for local-shadow ownership.

## Target architecture

Create one `AtmosphereEffect` engine pipeline with two independently configurable
components:

1. `volumetric_fog`
2. `volumetric_lighting`

They share medium integration, depth, native colors, noise, history, and
composition. Running two complete raymarchers would waste bandwidth and make
extinction/composition inconsistent.

### Render boundary

Primary target: the existing world-only boundary after world depth capture and
TAA resolve, but before first-person/UI rendering.

Reasons:

- first-person geometry remains naturally un-fogged instead of requiring a mask;
- the world source is still HDR on observed paths;
- vanilla image-space, bloom, grading, and UI run afterward;
- world depth and camera projection correspond to the rendered scene;
- transparent/world composition is already present as far as the world pass
  provides it.

The atmosphere effect needs its own temporal history because current world TAA
resolves before it. Do not move TAA or include first-person/UI to hide noise.

### Resources

Preferred quality path:

- half-resolution `G16R16F` logarithmically encoded current depth min/max,
  normalized against the frame's bounded atmosphere distance;
- half-resolution `A16B16G16R16F` integrated atmosphere;
- two half-resolution `A16B16G16R16F` temporal history targets;
- half-resolution previous depth min/max for disocclusion;
- quarter- or half-resolution screen-space shaft-factor target;
- source-format world color copy only when the pipeline runs;
- small CC0 blue-noise texture;
- optional generated tileable two-channel density-noise texture.

Atmosphere RGB stores in-scattered radiance. Alpha stores transmittance. This
keeps composition physically coherent only after the linear-radiance contract
is proven:

`output.rgb = scene.rgb * transmittance + scattering`

FP16 is required for the high-quality path. If it or the linear-radiance source
contract is unavailable, bypass rather than silently reducing atmospheric
history precision or composing in an unknown transfer space.

### Passes

#### 1. Depth reduction

Convert world hardware depth to linear ray distance at half resolution. Clamp
to the frame's bounded atmosphere distance, then store logarithmically encoded
nearest and farthest depth from each 2x2 footprint. Decode before integration,
temporal rejection, and upsampling. Raw half-float world units are forbidden:
they overflow above 65,504 and lose useful far-distance precision. Min/max
depth supports silhouette rejection and bilateral upsampling better than one
point sample.

Use one explicit frame ABI for distance `d` and atmosphere bound `D`:

`encoded = log2(1 + clamp(d, 0, D)) / log2(1 + D)`

`decoded = exp2(encoded * log2(1 + D)) - 1`

Compute the 2x2 nearest/farthest values before encoding. Store `D` with the
atmosphere frame and invalidate depth/history whenever it changes materially.

Sky gets a bounded atmosphere distance derived from active fog end, camera far,
and a user maximum. Never march to arbitrary `far_z` values such as 350 km.

#### 2. Screen-space shaft factor

Upgrade the existing sunshaft mask instead of adding another unrelated god-ray
effect:

- derive sky/open-path visibility from world depth;
- use native sun position/direction and native sun colors;
- use a compile-time quality variant for radial sample counts;
- make the existing `sun_sample_px` option real or replace it with a quality enum;
- use frame-varying blue-noise jitter only once temporal history is active;
- retain current screen-edge, daylight, exterior, and failure gating.

This produces a 2D screen-space shaft factor, not true shadow visibility along
the 3D camera ray. Every integration point on one camera ray projects to the
same screen pixel, so this factor cannot locate or vary around a blocker in ray
depth. Label it accurately in diagnostics and settings, and apply it only as a
final modulation of integrated directional scattering.

#### 3. Medium integration

For each half-resolution pixel, reconstruct the world ray and integrate to the
depth endpoint.

Density model:

- user-controlled supplemental exponential height density around a configurable
  world height, with weather and native fog values used only for gating and
  bounded calibration;
- optional low-frequency world-anchored heterogeneous density;
- bounded distance fade and interior gating.

Lighting model:

- Beer-Lambert transmittance;
- fog/sky ambient in-scattering;
- Henyey-Greenstein directional sun phase term;
- native sun light/disk color and daylight;
- screen-space shaft modulation from pass 2;
- energy-conserving scattering albedo and bounded exposure.

While native distance fog remains active, do not derive or apply another global
distance-extinction term from native fog start/end/power. Use analytic
integration for supplemental exponential-height density. Spend ray samples only
on heterogeneous density; apply the 2D shaft factor after directional
integration. This should outperform a blind 32-step NVR-style height loop while
avoiding deliberate double extinction.

Suggested fixed shader variants:

| Quality | Resolution | Heterogeneous samples | Shaft radial samples |
|---|---:|---:|---:|
| Performance | quarter | 8 | 24 |
| High | half | 12 | 40 |
| Ultra | half | 20 | 56 |

Compile fixed variants for `ps_3_0`; do not rely on large runtime-variable loops.

#### 4. Temporal resolve

Reuse OMV's camera reprojection and history invalidation concepts, not Anomaly's
MRT motion-vector system.

Requirements:

- camera-only reprojection of the world-anchored medium;
- previous depth rejection at silhouettes;
- capture-epoch, camera-cut, FOV, format, and resolution invalidation;
- neighborhood clamp of scattering and transmittance;
- lower history weight when density noise moves;
- no history across interior/exterior or major weather discontinuities;
- current-frame fallback on any missing contract.

Dynamic objects cannot supply true motion vectors. Depth rejection and low
history weight near boundaries are required to avoid trails.

#### 5. Bilateral composition

Upsample with full-resolution world depth and half-resolution min/max depth.
Reject taps that cross geometry silhouettes. Composite scattering/transmittance
onto the HDR world target and preserve source alpha until its engine semantics
are proven.

Do not use Anomaly's non-bilateral fog-scattering blur.

## Component behavior

### Volumetric fog enabled, lighting disabled

Integrate native fog/sky ambient color with user-controlled supplemental height
and optional heterogeneous density. Preserve native distance fog initially and
do not infer a second global extinction term from its range/power.

### Volumetric lighting enabled, fog disabled

Use a low-density participating medium dedicated to directional in-scattering.
The effect still needs a medium density; "light in empty space" is not physical.
Expose a separate lighting-medium density rather than silently enabling visual
distance fog.

### Both enabled

Run one integration. Add directional radiance inside the fog medium and compose
once. This is the intended and highest-quality configuration.

## Phased implementation

### Phase 0: close engine contracts and add telemetry

1. Complete the targeted shadow-resource helper-chain audit. The fog ownership
   audit is complete; the first light audit closed draw-scoped light and matrix
   semantics. The focused lifecycle follow-up proves retained type `0x2B`
   per-local-light texture ownership plus its 1024x1024 default/fallback format
   contract. The `SimpleShadow` audit closes the three native shader-package
   identities, and the runtime-consumer follow-up closes the current reuse
   decision negatively: `0x00B80600` is not a texture binder, no `+0x10C`
   consumer link exists in the audited paths, and the separately published
   `ShadowProj` matrix is not sourced from the local-shadow object. Native type
   `0x2B` reuse is therefore excluded from the implementation plan. Directional
   sun shadow ownership remains unproven.
2. Add runtime logging for world target format, atmosphere phase count per
   Present, fog RGB/range/power, exterior transitions, and missing contracts.
3. Verify source transfer function, exposure/tonemapping state, native color
   encoding, HDR format, and alpha preservation on the actual DXVK path.
4. Capture water, transparency, sky, and interior depth behavior.
5. Compare the static fog intervention sites against runtime draw coverage; the
   prepared audits are evidence collectors, not proof of exhaustive coverage.

Prepared scripts:

- `analysis/ghidra/scripts/graphics_fnv_volumetric_fog_stage_ownership_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_volumetric_light_shadow_resource_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_volumetric_shadow_texture_lifecycle_followup_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_volumetric_local_shadow_sampling_contract_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_volumetric_local_shadow_runtime_consumer_followup_audit.py`

Expected outputs:

- `analysis/ghidra/output/perf/graphics_fnv_volumetric_fog_stage_ownership_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_light_shadow_resource_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_shadow_texture_lifecycle_followup_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_shadow_sampling_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_shadow_runtime_consumer_followup_audit.txt`

### Phase 1: atmospheric input and world-stage contract

1. Extend `EnvironmentFrame` with validated active fog RGB.
2. Publish one compact atmosphere frame containing fog, sky, sun, camera, depth,
   exterior, and frame epoch.
3. Add explicit per-effect input requirements for world depth and world color.
4. Add a post-TAA/pre-first-person atmosphere callback with one-call-per-Present
   ownership and state restoration.
5. Fail closed to unchanged world color when any required contract is missing.

### Phase 2: high-quality supplemental volumetric fog

1. Add depth min/max reduction.
2. Add supplemental analytic height extinction and native-color in-scattering
   in the proven linear-radiance space.
3. Add world-anchored heterogeneous density and static blue-noise ray jitter.
4. Add depth-bilateral upsampling and HDR composition.
5. Keep native distance fog; default to supplemental height/heterogeneous fog.

This phase is useful and honest without shadow maps.

### Phase 3: directional volumetric lighting

1. Refactor current sunshafts into the shared atmosphere pipeline.
2. Replace fixed shaft tint with native sun light/disk/horizon colors.
3. Produce a temporally stable screen-space shaft field.
4. Integrate Henyey-Greenstein sun in-scattering through the same medium, then
   use the shaft field only as a 2D directional-scattering modulation.
5. Keep the existing sunshaft pipeline as a compatibility fallback until the
   new path passes quality/performance gates.

This delivers convincing screen-space volumetric lighting, but diagnostics must
call the input a shaft factor rather than shadow-map or per-ray visibility.

### Phase 4: temporal stability and quality tiers

1. Add atmosphere history and previous half-depth.
2. Animate blue-noise jitter only after history works.
3. Add High/Ultra fixed shader variants and instrument GPU/CPU cost.
4. Tune separate sky, horizon, ground, interior, and weather-transition behavior.

### Phase 5: true directional shadowed volumetrics

Only after the shadow audit proves or OMV implements the complete resource
contract:

1. Own or adopt a sun cascade atlas explicitly.
2. Publish matrices, cascade bounds, encoding, and bias.
3. March shadow visibility along the view ray as Anomaly does.
4. Blend cascades without seams and retain the screen-space shaft factor as a near
   contact/detail term.
5. Fall back to the Phase 3 screen-space path when shadow resources are absent.

### Phase 6: local volumetric lights

Only after stable light-list and light-visibility contracts exist:

1. Copy a bounded list of visible light values; never retain raw engine pointers.
2. Prove shadow-map/cookie ownership or another conservative occlusion source;
   camera depth alone does not prevent light leaking through walls.
3. Integrate shadow-aware point/spot ray-sphere/cone volumes at half/quarter
   resolution.
4. Cull by screen bounds, distance, intensity, and contribution.
5. Cap light count and expose overflow telemetry.

An unshadowed implementation is permitted only as an explicitly labelled debug
view for contract validation, not as the shipped local-light quality path.

Do not port Anomaly's slice renderer until FNV provides equivalent volume and
shadow inputs. A fullscreen ray-volume intersection may fit OMV better once the
light list is available.

### Phase 7: optional full native-fog replacement

Only after the fog ownership audit and runtime coverage tests prove all affected
draw classes:

1. disable native fog for the world render transaction;
2. reproduce distance fog, height fog, sky transition, transparency, water,
   particles, and forward paths;
3. restore native state before first person/UI and on every failure;
4. retain a compatibility switch and native fallback.

This is not required for excellent supplemental volumetrics and should not block
Phases 1-4.

## Configuration plan

Add dedicated sections rather than overloading current sunshaft controls:

`graphics.embedded_effects.volumetric_fog`:

- enabled;
- quality;
- density;
- height_density;
- height_falloff;
- base_height;
- max_distance;
- scattering_albedo;
- noise_amount;
- noise_scale;
- noise_speed;
- temporal_stability;
- debug_view.

`graphics.embedded_effects.volumetric_lighting`:

- enabled;
- intensity;
- medium_density;
- anisotropy;
- shaft_strength;
- sun_disk_boost;
- shaft_quality;
- temporal_stability;
- debug_view.

Keep physical ranges bounded. Offer a small number of quality presets rather
than exposing raw sample loops.

## Compatibility and failure behavior

- Do not depend on NVR, VPT, or FalloutShaderLoader resources implicitly.
- Detect another shadow owner before installing future shadow hooks.
- Preserve world target alpha.
- Bypass physical composition when source/native color-space or exposure
  contracts are unknown.
- Never render volume over first-person/UI in the world-only path.
- Disable directional scattering in interiors unless a proven interior light
  source is available.
- Invalidate history on loading screens, camera cuts, teleports, FOV changes,
  resize, reset, weather discontinuity, and exterior transition.
- Missing fog color may fall back to guarded horizon/sky color; missing depth or
  camera must bypass the pass entirely.
- Resource creation failure must leave the original world color unchanged.

## Quality and performance gates

Required scenes:

- clear midday, sunrise/sunset, night, overcast, rain/fog weather;
- desert horizon, dense geometry, interiors and transitions;
- water surfaces and underwater transitions;
- alpha-tested foliage, particles, smoke, transparencies;
- stationary camera, slow pan, fast rotation, translation, teleport, FOV change;
- weapon silhouettes, scopes, VATS, dialogue, menus, loading screens;
- bright local lights when local-volume phases are added.

Reject the implementation if it causes:

- halos or fog leaking across silhouettes;
- temporal trails behind actors/foliage;
- noise swimming in screen space;
- double fog or horizon discontinuities;
- composition in an unproven nonlinear or pre/post-exposed color space;
- first-person/UI contamination;
- shadow cascade seams;
- sky washout or negative/overbright HDR values;
- silent A8 fallback for FP16 volume history;
- excessive full-resolution copies or unbounded per-light work.

Instrument each pass separately: depth reduction, shaft factor, integration,
temporal resolve, and composition. Record resource formats and dimensions.

## Final recommendation

Proceed with Phase 0 first. Proceed with Phases 1-4 as one feature effort only
after Phase 0 proves the linear-radiance composition contract. Those phases can
then provide excellent supplemental volumetric fog and convincing screen-space
directional volumetric lighting using contracts OMV mostly owns.

Do not block that work on native shadow maps or local lights. Treat true
shadow-marched sun volumes, local volumetric lights, and full native-fog
replacement as explicit later upgrades whose engine contracts must be proven
first.

# FNV atmosphere Phase 3 directional volumetric lighting plan

Date: 2026-07-18

Implementation status: implemented with fixed `ps_3_0` variants compiled by
the real D3D compiler in the i686 Wine test run. Behavioral regressions own the
native-radiance and projection contracts; the feature-first playtest remains
the final pixel-quality gate.

## Shared medium and authored emitter correction

### World-space sunlight shadowing

Directional haze now borrows the existing four-cascade static EVSM4 atlas and
three actor overlays from the common shadow producer. The existing world
requirements word requests this producer whenever enabled directional lighting
has a nonempty shared medium, positive intensity and positive shaft strength.
This also covers medium supplied by fog. Surface Sun Shadows remains independent:
the surface consumer masks its copied publication with that receiver setting.
No configuration field, static owner, hook or startup initialization is added.

The stack packet retains three COM textures, rebases the published matrices to
the consumer camera origin, and carries cascade splits and actor crops. Busy,
missing, stale, reset-generation, wrong-device or mismatched-sun publications
are rejected. One retained packet serves both near/far integrations. Existing
world state restoration covers the additional samplers and constants.

The prepared shaft-mask slot now owns a combined world-field/projected-mask
program, preserving the bytecode static's layout and preparation lifecycle.
The existing quarter-resolution targets are reused: radial stores the full
4x4-cell near/far reduced depth, and mask stores FP16 blocked-scattering amounts
in RG plus log-depth interval keys in BA. This promotes mask from RG16 to RGBA16
without adding a target. The ordinary near/far haze targets retain their quality
resolution. One quarter-resolution reduction and one field draw precede haze.
Equal near/far ray intervals inside the atlas share one march.

World-field generation binds static/actor maps at `s4..s6`, matrices at
`c18..c33`, texels/actor admission/crops at `c35..c40`, and admission/strength/
8,12,20 sample count at `c42`. The haze consumers read only the retained field at
`s2`, with its dimensions at `c43`; four point-sampled, spatially weighted taps
match the production near/far depth intervals. Depth tolerance follows the
existing composition policy (256 world units or 2 percent at quarter scale).
The consumer subtracts blocked scattering from its existing total energy.
Extinction, HG phase, native source color and sky response remain unchanged.

World lookup selects the finest actual projected map containing each sample
and blends to coarser maps at their boundaries. It no longer rejects a sample
by a camera-depth split. Ray extent is clipped against the outer orthographic
atlas's real XYZ box, replacing the split-distance/view-cosine cutoff. EVSM4 and
actor coverage follow the surface receiver contract; bilinear resolved moments
omit that receiver's extra three-tap edge refinement. Samples outside published
coverage remain lit. Natural phase brightness remains angular. Missing maps
retain the projected fallback and its viewport limitations; legacy scene-post
shafts also remain screen-space. Debug shaft-mask views describe that fallback,
not the world field. Game-only image behavior has not been executed.

The existing directional producer and caster work remain required even with
surface Sun Shadows off. Its static atlas alone is 128 MiB; its additional work,
resolve, depth, actor and strip resources remain. The field mask promotion adds
four bytes per quarter-resolution pixel (about 0.49 MiB at 1920x1080).
At default High quality and 1920x1080, the old two half-resolution marches used
12,441,600 shadow steps. The quarter field uses at most 3,110,400 steps, or
1,555,200 when both intervals have the same atlas extent. A sample tests up to
four static maps and three actor maps plus density noise, with early exit once
covered; the older blend tested up to two static/actor maps plus noise.
Haze now uses four field reads instead of a repeated atlas march. Field
reconstruction uses the documented low-resolution/depth-aware approach:
[NVIDIA, Fast Flexible Physically-Based Volumetric Light Scattering](https://developer.download.nvidia.com/assets/gameworks/papers/Fast_Flexible_Physically-Based_Volumetric_Light_Scattering.pdf).
These bounds describe deterministic work, not measured GPU time or FPS. The
owner's 30+ FPS loss is a runtime observation; attribution between producer,
field integration and driver cost remains unresolved without runtime timings.

Screen-space radial sampling has documented view limitations:
[NVIDIA GPU Gems 3, chapter 13](https://developer.nvidia.com/gpugems/gpugems3/part-ii-light-and-shadows/chapter-13-volumetric-light-scattering-post-process).
Directional shadow maps are also the sunlight-occlusion source described by
[Epic's Sky Atmosphere documentation](https://dev.epicgames.com/documentation/en-us/unreal-engine/sky-atmosphere?application_version=4.27).

This correction replaces the July independent lighting optical-depth floor
with a minimum in the shared extinction field. Scattering and extinction now describe one medium:
`directional_amount = (1 - transmittance) * scattering_albedo`, using the same
uniform, height and noise optical depth that produced transmittance. When
lighting or local lights are enabled, uniform extinction is the maximum of
active fog density and lighting medium density. This aerosol lower bound also
feeds the local-light integrator; enabling height fog cannot remove it. With
fog inactive, lighting density supplies uniform extinction and unit albedo. The normalized HG phase and established
`4 pi` engine-light conversion remain, as does off-screen base scattering.
This follows the extinction/scattering distinction in
[PBRT's volume processes](https://www.pbr-book.org/4ed/Volume_Scattering/Volume_Scattering_Processes).

The projected fallback's shaft visibility retains the accepted
`lerp(1, exp(-12 * blocked_fraction), edge_fade * strength)` curve. This is
an artistic screen-space occlusion estimate, not physical optical depth.
Moving strength inside the exponential removed its neutral component and
crushed world rays; replacing the curve with linear coverage weakened the
thin-occluder response established by the July runtime correction. Zero
strength remains identity. Stable stratified taps stay inside their path
segments instead of stepping beyond the sun endpoint.
The 24/40/56-tap quarter-resolution variants and two shaft passes remain.

Disk boost reads the authored disk texture through the native geometry UV map,
replacing the fixed angular lobe. Integration uses sampler `s3`, maps `c15..c17`;
debug uses `s5`, maps `c12..c14`. The last map component carries native visibility.
One owned packet serves both near/far integrations; debug obtains its own only
when needed. A missing packet zeroes disk enhancement, never base scattering.
The existing pre-alpha phase, layered FP16 targets, medium composition, native
sun-color compatibility resolver, config schema/layout and static owners remain.

Compared with the former default integration, compiled work adds one native
texture instruction, projective coverage arithmetic and exact source decoding. There is no new pass,
target, texture allocation or render-time compilation. Lookup uses existing
range validation, and the native texture is retained only across its consumers.
The earlier source-string ABI checks and mirrored legacy radial reference do
not qualify these changed equations. Production variant compilation/budgets
provide static support; the existing GPU pipeline fixtures remain independent
support fixtures and are not matching game captures. The owner's glow/ray
report is the game-only requirement. Image tests and gameplay were not run
under the owner's static-only restriction; compilation is not visual proof.

Native-radiance compatibility correction on 2026-08-18: the earlier claim that
`Sky +0x6C` was an executable-proven final directional color was incorrect.
The authoritative follow-up audit proves a different interpolation write at
`Sky +0x48` and leaves `Sky +0x6C/+0x78` as Reloaded-derived candidates. The
previous shader fixtures injected bright values into those candidates, so they
passed while a valid exterior daylight frame with black candidates made both
directional volumetrics and legacy godrays produce black pixels.

`NativeSkyFrame` now resolves one shared post-process sun color. A viable
directional candidate wins, followed by a viable disk candidate. If both are
black, the resolver keeps the native horizon/sky hue and scales it by the
finite daylight value; a neutral daylight tint is the last fallback. Exterior
and daylight admission remains mandatory, so the compatibility path cannot
enable directional effects in interiors or at night. Atmosphere and legacy
Sunshafts consume the same resolved color.

Two independent shipped-HLSL behavior gates own the correction. The atmosphere
gate executes depth reduction, shaft mask/radial passes, layered integration,
and HDR composition. It requires broad off-disk scattering, blocker-shaped
occlusion outside the blocker pixels, and movement with native sun direction.
The legacy gate executes mask, radial, both blur passes, and composition into
the observed `X8R8G8B8` scene-post format, with the same occlusion and movement
requirements. Both fixtures set `sun_light` and `sun_disk` to black while
retaining valid exterior, daylight, camera, and depth inputs; both produced
exactly black output before the resolver correction.

Runtime rejection and projection-scope correction on 2026-08-17: the installed
build logged successful atmosphere integration and composition, but Volumetric
Lighting was not visibly effective. Production had routed the complete
directional-scattering contribution through the projected-sun viewport gate.
That contradicted the epoch-coherent projection contract below: screen
projection describes only the radial shaft mask, while medium scattering is a
view-independent response to the native sun direction and color.

Base directional scattering now remains available when the sun is behind or
outside the viewport. Only radial shaft allocation and modulation require a
front-facing, on-screen projection and use the edge fade. This correction
supersedes the 2026-07-19 edge policy below that faded the entire directional
light to zero; that policy incorrectly fixed an unoccluded-wash symptom by
removing the requested physical contribution. Logs, draw calls, and static
tests still cannot accept final pixels. The required installed comparison
rotates the sun from screen center through every edge and behind the camera:
base scattering must remain stable and visibly respond to the toggle, while
the radial shafts alone fade at the projection boundary.

Screen-entrance correction on 2026-07-20: ordinary camera motion could move the
projected sun through the old 3.5% viewport-edge ramp in one or two frames.
Although that mapping was mathematically continuous, directional scattering,
the disk lobe, and both shaft pipelines consequently looked as if they switched
on when the sun entered the screen. The shared `project_world_direction` edge
weight now uses a smooth 12% viewport ramp. At 4% inside the viewport the new
weight is about 0.26 instead of the old 1.0, and it remains exactly zero on and
beyond the edge. This preserves the accepted protection against off-screen,
unoccluded yellow wash while giving normal head movement enough screen distance
to reveal the sun progressively.

The correction is owned by `omv/src/backend/mod.rs`; atmosphere and legacy
Sunshafts consume the same copied projection weight, so the disk lighting and
both ray systems cannot disagree at the boundary. It adds no render pass,
texture, allocation, lock, history, or per-pixel work. The deterministic
`directional_lighting_entrance_spans_meaningful_viewport_distance` regression
includes the old 3.5% mapping as a negative control, proves monotonic bounded
growth, and proves full native daylight is recovered away from the edge. Static
validation cannot prove the perceived timing under a player's mouse/controller;
the final runtime acceptance is a normal slow and fast look through each screen
edge with Volumetric Lighting and optional legacy Sunshafts enabled.

Static validation on 2026-07-20 passed all 179 OMV tests under
`i686-pc-windows-gnu`, including the real HLSL compiler tests, and the explicit
optimized `i686-pc-windows-gnu` OMV release build. Perceived entrance timing and
final pixels remain the ordinary in-game acceptance gate described above.

Runtime correction on 2026-07-19: the first deployed build completed its draw
but was visually ineffective. It applied a normalized per-steradian phase
directly to FNV's irradiance-scale direct-light RGB, reducing isotropic response
to `1 / (4 pi)`, and its averaged radial mask barely reacted to thin blockers.
The production/debug response now retains normalized HG internally but converts
the engine light with a `4 pi` factor, giving unit isotropic response, while the
shaft field converts blocked-sample fraction to Beer-like visibility. Automatic
legacy Sunshafts suppression was removed: successful composition alone cannot
prove that Phase 3 visibly replaces that independent artistic pass.

Composition correction on 2026-07-19: the first accepted visual build exposed
three coupled contracts. Phase 3 and legacy Sunshafts used different sun
projection sources, fog albedo could reduce the directional scattering amount,
and atmosphere composed after coverage-sensitive foliage. The two ray systems
now share native sun direction/color and the captured depth camera. Lighting
uses its own medium optical depth as a lower bound, while active fog can only
increase its scatter amount. Legacy shafts no longer derive their source from
fog-altered scene brightness and expose a bounded `Fog visibility gain`.

The authoritative alpha-coverage audits prove the engine stage correction:
`FUN_00b98540` writes vendor `ATOC`/`A2M0` state, `0x00B65AE0` completes the
opaque/pre-depth portion, and `0x00B65C60` owns the post-depth and sorted-alpha
groups. Atmosphere now composes between those two functions; world TAA stays at
the complete-world boundary. This prevents a single resolved depth sample from
misclassifying alpha-to-coverage foliage. First-person geometry is later than
Phase 3 and therefore covers it naturally; legacy shafts require exact
first-person depth/projection and fail closed if that requested mask is absent.

Edge/first-person correction on 2026-07-19: Phase 3 previously kept full
directional scattering after its on-screen shaft field became unavailable, so
crossing the screen edge discontinuously replaced occluded lighting with an
unoccluded yellow wash. Native late alpha groups could also leave vendor
`ATOC`/`A2M1` state active for OMV full-screen draws. Directional light now
fades continuously with the shared projected-sun edge weight and contributes
nothing at or beyond the projection boundary. The atmosphere and Sunshafts
draws explicitly disable the researched NVIDIA/AMD alpha-to-coverage mode
inside their captured state blocks.

Legacy Sunshafts now distinguish "no first-person geometry this epoch" from
"first-person geometry rendered but its current depth capture failed." The
former needs no hand mask; the latter fails closed. Their shader consumes raw
first-person depth endpoints only, so camera/projection metadata no longer
incorrectly gates the whole pass. The native-sun source response is smooth and
bounded instead of using an absolute brightness cutoff that could silently
remove shafts as weather lighting changed.

## Outcome

Implement the currently non-functional `Volumetric Lighting` toggle as
directional single scattering inside OMV's proven world-only atmosphere pass.
The result must use native FNV sun direction and colors, the same medium and
dual reduced-depth layers as volumetric fog, and a conservative screen-space
shaft visibility field. It composes after native opaque/pre-depth geometry and
before coverage-sensitive alpha geometry, first-person, native image space,
HUD, and UI. World TAA runs after the complete world, including atmosphere and
late alpha groups.

This phase is complete only when all of the following are true:

1. Lighting enabled with fog disabled visibly adds directional scattering in a
   low-density participating medium.
2. Lighting and fog enabled run one shared integration and one composition;
   lighting does not start a second atmosphere ray marcher or double the fog
   extinction.
3. Lighting disabled preserves the current, accepted volumetric-fog result.
4. Fog remains stable when lighting inputs are missing, the sun is off-screen,
   or the shaft resource cannot be created. A lighting failure cannot bypass a
   valid fog frame.
5. The shaft field and sun projection remain stable while rotating or moving
   near fences, foliage, terrain transitions, and the previous mixed-depth
   trigger.
6. First-person geometry and later image-space/UI passes remain outside the
   atmosphere write.
7. Every generated `ps_3_0` variant compiles with the real D3D HLSL compiler in
   the i686 Wine test run before a DLL is deployed.
8. Performance, High, and Ultra have fixed, bounded work and pass the explicit
   sample, allocation, and runtime performance gates below.

Static shader compilation proves shader syntax, profile, stage, register
legality, and compiler acceptance. CPU regressions prove the corresponding
math and state-selection rules. Neither can prove final pixels on DXVK, so the
last gate remains one feature-first playtest after every static gate passes.

## Research decision

No additional Ghidra run is required for this phase. Existing authoritative
outputs and the implemented backend close every engine input needed by the
screen-space directional path:

- `graphics_fnv_native_sun_light_contract_audit.txt` and its deep/final
  follow-ups establish the native Sky/Sun object chain and renderer constants;
- `graphics_fnv_native_sun_color_direction_followup_audit.txt` establishes the
  native directional and disk colors plus the Sun root direction;
- `graphics_fnv_sun_projection_contract_audit.txt` and its deep follow-up
  establish the camera basis/frustum projection contract;
- `graphics_fnv_atmosphere_phase2_contract_audit.txt` and its follow-up
  establish the world-only color/depth/composition boundary;
- the volumetric shadow-resource, lifecycle, sampler, and runtime-consumer
  audits conclusively reject treating native type `0x2B`, `ShadowProj`, or the
  `SimpleShadow` package as a stable OMV sun-shadow ABI.

OMV already copies and validates:

- exact captured world camera, frustum, transform, near/far, depth direction,
  depth texture, capture epoch, and atmosphere distance bound;
- native sun direction, directional color, disk color, daylight, sky colors,
  and exterior state;
- projected sun data for the existing legacy sunshaft pass;
- an FP16 HDR world target and source-alpha-preserving composition;
- same-epoch above/underwater state;
- logarithmic nearest/farthest reduced depth and the dual-layer composition
  that fixed mixed foreground/sky blinking.

The phase therefore does not need a native shadow hook. It implements honest
screen-space directional volumetrics and labels the occlusion input as shaft
visibility, not a shadow map or per-sample 3D visibility.

## Hard scope boundary

Included:

- native-color directional sun single scattering;
- normalized Henyey-Greenstein phase response calibrated to FNV's
  irradiance-scale direct light;
- a deterministic, depth-derived screen-space shaft field;
- lighting-only, fog-only, and combined medium behavior;
- fixed quality variants, resource gating, diagnostics, menu/config wiring,
  compatibility fallback, static shader compilation, CPU regressions, and
  runtime acceptance.

Excluded:

- retaining or sampling vanilla type `0x2B` local-shadow textures;
- treating `ShadowProj` as a sun cascade contract;
- true shadow-map-marched sun lighting;
- local point/spot volumetric lights;
- native fog replacement;
- animated ray jitter or atmosphere history;
- a post-first-person or post-UI composition shortcut.

Temporal history is deliberately not required here. The medium noise and shaft
sampling are deterministic, so Phase 3 does not need animated jitter to hide
undersampling. Adding camera-only history without motion vectors would trade
stable current pixels for trails on foliage, actors, and particles. The
existing serialized `temporal_stability` values remain compatibility-reserved
and must be hidden or explicitly marked inactive in the UI; they must not be
silently applied as an unrelated spatial control.

## Rendering model

### Shared medium

There is one extinction field and one atmosphere composition:

- fog only: use the current uniform, exponential-height, and heterogeneous fog
  density and current ambient medium color;
- lighting only: use `medium_density` as a bounded uniform lighting medium,
  with no hidden fog noise or ambient fog scattering;
- both enabled: use `max(fog.density, lighting.medium_density)` as the shared
  uniform density, plus fog height/noise terms, for ambient, directional and
  local scattering. The lighting medium is a lower bound, not additive density.

This rule prevents double extinction and makes the two toggles independent.
The lighting-only medium still attenuates the scene because visible light in
empty space is not physically meaningful.

For optical depth `tau`, transmittance remains:

`T = exp(-tau)`

Ambient fog remains:

`L_ambient = medium_color * fog_albedo * (1 - T)`

Directional single scattering is:

`L_sun = sun_radiance * phase(mu, g) * sun_albedo * (1 - T) * shaft_visibility`

where `mu` is the dot product between the camera-to-sample world ray and the
world direction toward the sun. Positive anisotropy therefore peaks while
looking toward the sun.

Use the normalized Henyey-Greenstein function:

`phase(mu, g) = (1 - g^2) / (4*pi*(1 + g^2 - 2*g*mu)^(3/2))`

Clamp the public anisotropy range to the existing `[-0.8, 0.9]`, guard the
denominator, reject non-finite inputs, and keep HDR radiance unsaturated.

### Native sun radiance

Decode `NativeSkyFrame.sun_light` and `sun_disk` with the same proven extended
sRGB transfer used by fog and native sky. Directional scattering uses the
already time/weather-interpolated directional color as its base radiance,
multiplied by the user intensity. Validated daylight admits day-active native
lighting but is not a second radiance multiplier.

`sun_disk_boost` affects only a narrow, smooth angular lobe around the sun. It
must not add the disk color uniformly across the screen. Use the positive
difference between disk and directional color so the control cannot subtract
light or recolor the entire medium.

All intermediate values must be finite and nonnegative. Preserve valid
overbright FP16 output; do not `saturate` final radiance merely to hide a bad
calibration.

### Epoch-coherent sun projection

Do not feed the atmosphere shaft pass from the legacy live `SunFrame` screen
position. That projection can be read from a different camera/frustum state
than the captured world depth, especially around TAA jitter publication and
restoration.

Add a pure CPU helper that projects `NativeSkyFrame.sun_direction` with the
exact `AtmosphereFrame.camera` captured beside the world depth:

- camera forward is world-rotation column 0;
- camera up is column 1;
- camera right is column 2;
- use the captured left/right/top/bottom frustum values;
- return facing, UV, on-screen edge fade, and availability as copied values;
- never read an engine pointer from the effect.

This makes depth, view rays, and sun UV one coherent frame contract. A sun
behind or outside the screen disables only screen-space shaft modulation. It
does not disable directional scattering and can never disable fog.

## Pass architecture

### 1. Existing depth reduction

Keep the accepted logarithmic nearest/farthest reduction unchanged. Do not
replace the dual-layer fix, return to a nearest-only composition test, or add a
new full-resolution depth copy.

The shaft mask uses the conservative nearest member of each reduced interval
for blockers and the far member for sky confidence. A mixed fence/sky cell is
therefore treated as partially/conservatively blocked instead of randomly
open. The mask must use smooth thresholds and a bounded footprint; it must not
toggle the whole atmosphere integration gate.

### 2. Quarter-resolution shaft mask

Add `atmosphere_shaft_mask.hlsl` and a quarter-resolution `G16R16F` target.
It consumes only the reduced logarithmic depth and current frame constants.
Suggested channels:

- R: conservative open-path value;
- G: sky confidence/coverage used to soften subpixel silhouettes.

The pass is deterministic. It contains no frame index, animated noise, scene
brightness threshold, first-person depth, or legacy sunshaft option ABI.
Unlike the legacy post-image-space mask, this mask is created before
first-person rendering and must not pretend that a first-person texture exists.

### 3. Quarter-resolution radial visibility

Add `atmosphere_shaft_radial.hlsl` and a second quarter-resolution `G16R16F`
target. March from each pixel toward the epoch-coherent sun UV through the mask
and output a bounded visibility/confidence pair.

Use compile-time sample-count variants:

| Quality | Shaft resolution | Radial samples |
|---|---:|---:|
| Performance | quarter | 24 |
| High | quarter | 40 |
| Ultra | quarter | 56 |

The count is a compile-time define. No user value may create an unbounded loop.
Use a stable pixel-derived offset only if needed to break bands; it must not
depend on frame number. Bilinear sampling during integration supplies the final
small spatial smoothing, so do not copy the legacy pair of nine-tap blur passes
unless the feature playtest proves they are necessary.

The neutral field is 1.0. When the sun is off-screen, behind the camera, below
the daylight threshold, `shaft_strength == 0`, or the radial path is not
required, skip both shaft draws and bind neutral visibility. Shaft strength
must interpolate from neutral toward the bounded field and can never create a
negative multiplier.

### 4. Shared near/far integration

Extend `atmosphere_integrate.hlsl` rather than adding a second fullscreen
lighting integrator. Bind shaft visibility at a new fixed sampler slot and add
explicit lighting constants after the existing ABI.

For each reduced near/far endpoint:

1. reconstruct the same validated world ray;
2. evaluate the existing optical depth exactly once;
3. compute transmittance exactly once;
4. add ambient scattering only when fog is enabled;
5. add directional scattering only when the lighting contract is ready;
6. return combined scattering in RGB and shared transmittance in alpha.

The directional source is constant along the camera ray for this screen-space
model, so it uses the analytic `(1 - T)` integral. Do not spend another 8/12/20
samples evaluating the same sun direction. Existing heterogeneous samples
remain solely for medium density.

### 5. Existing dual-layer composition

Keep `atmosphere_compose.hlsl` as the single production composition and retain
the exact near/far interval interpolation that fixed blinking. It continues to
decode the FP16 world source, apply `source*T + scattering`, encode extended
sRGB, and copy source alpha exactly.

No lighting code may reintroduce a nearest-only reject, a sky special-case that
skips composition, or a second full-resolution color copy.

## Independent gates and failure behavior

Replace the fog-only integration decision with three decisions:

1. common atmosphere contract;
2. fog contribution contract;
3. directional-lighting contribution contract.

The common contract requires current depth/camera/transform, a valid distance
bound, exterior state, current above-water publication, FP16 world color, and
source-alpha readiness.

Fog readiness keeps its current medium-color rules. Lighting readiness requires
a valid exterior `NativeSkyFrame`, normalized finite sun direction, finite
native colors, bounded daylight, finite settings, and a non-empty effective
medium.

Required truth table:

| Fog | Lighting | Sun/shaft state | Result |
|---|---|---|---|
| off | off | any | unchanged world |
| on | off | any | current fog result |
| off | on | valid sun | directional lighting medium |
| off | on | missing sun | unchanged world; legacy fallback remains eligible |
| on | on | valid sun | one combined atmosphere composition |
| on | on | missing sun | fog-only composition; never a full bypass |
| on | on | shaft unavailable | fog plus safe unmodulated/off-screen policy, or fog-only if the sun is on-screen and occlusion is mandatory |

Resource creation is transactional. Keep existing atmosphere targets when
only the optional shaft allocation fails. Never clear or replace current fog
resources with a partially constructed target set.

## Compatibility with legacy Sunshafts

The current `sunshafts` feature runs later at `scene_post_image_space`, uses
first-person depth, and has a separate artistic composition. Preserve it as an
independent complementary pass; do not merge its config constants into the
world atmosphere ABI and do not suppress it based on Phase 3 draw completion.
Each effect remains controlled by its own user-facing toggle. This preserves
the existing artistic rays while Phase 3 supplies world-medium directional
scattering and depth-derived visibility.

## Configuration and ImGui

Wire every active lighting control through TOML, sanitized config, embedded
option constants, menu editing, save/reset, and runtime settings:

- `enabled`;
- `intensity`;
- `medium_density`;
- `max_distance` (new; removes the hidden dependency on disabled fog settings
  for lighting-only operation);
- `anisotropy`;
- `shaft_strength`;
- `sun_disk_boost`;
- `shaft_quality`;
- `debug_view`.

Keep the controls bounded and use the existing logarithmic editor for medium
density with an exact zero. Tighten `shaft_strength` to a physically safe
range or apply a bounded mapping internally; values above one must never make
visibility negative.

Do not expose an inactive `temporal_stability` slider as though it changes the
image. Preserve old TOML input compatibility, but hide or label the value as
reserved until a real reprojection/history phase exists.

Lighting debug views:

1. shaft openness/confidence mask;
2. radial shaft visibility;
3. Henyey-Greenstein phase response;
4. directional scattering before composition;
5. combined atmosphere result/acceptance.

Represent fog and lighting debug selection explicitly. Do not combine their
numeric values with `max()`, because equal numbers have different meanings.
If both menus request a view, choose and report one deterministic precedence.

Replace every "planned Phase 3" description in the runtime UI, default TOML,
and README after implementation. The UI status should show the active quality,
effective integration scale, shaft scale/sample count, effective medium mode,
sun readiness, and whether the legacy fallback is eligible.

## Static shader and CPU validation

### Real HLSL compiler tests

Extend the existing atmosphere compiler test so the i686 Wine run invokes the
real D3D compiler for:

- depth reduction at scale 2 and 4;
- shaft mask `ps_3_0`;
- shaft radial variants at 24, 40, and 56 samples;
- atmosphere integration variants at 8, 12, and 20 density samples with the
  lighting ABI present;
- composition and every debug shader.

Each test must assert successful compilation, `ps_3_0` stage/version, nonempty
bytecode, and the intended generated variant label. A shader compilation
failure blocks build/deploy.

Add narrow source/ABI assertions for:

- fixed sampler slots and no register overlap;
- shaft variants using their compile-time sample definition;
- integration retaining the dual reduced-depth layer selection;
- composition retaining both near/far samplers and interval clamping;
- final composition preserving source alpha;
- no frame-index input in deterministic shaft shaders.

### CPU regression tests

Add deterministic tests for:

- normalized HG isotropic value and approximate spherical integral;
- finite, nonnegative phase values over all public `g` and `mu` bounds;
- increasing forward response for positive anisotropy and the mirrored
  backward response for negative anisotropy;
- captured-camera sun projection for identity, rotated, asymmetric, jittered,
  behind-camera, and off-screen cases;
- shaft modulation neutrality at strength zero and bounds at every public
  strength;
- disk boost locality, nonnegativity, and finite overbright behavior;
- lighting-only, fog-only, combined, missing-sun, and missing-shaft truth-table
  outcomes;
- combined mode retaining the lighting aerosol minimum without additive density;
- lighting failure preserving a ready fog contribution;
- explicit fog-versus-lighting debug mapping;
- config/menu round-trip and sanitized non-finite inputs;
- exact quality dimensions, fixed sample counts, draw count, and a static
  3440x1440 sample-work ceiling;
- independent legacy Sunshafts eligibility regardless of Phase 3 draw outcome;
- reset/resource failure leaving the original world and later passes intact.

## Performance budget

At 3440x1440, a quarter-resolution shaft target is 860x360 (309,600 pixels).
The radial fetch budgets are therefore approximately:

- Performance: 7.43 million mask samples;
- High: 12.38 million mask samples;
- Ultra: 17.34 million mask samples.

Two quarter-resolution `G16R16F` targets cost about 2.36 MiB total. They are
allocated lazily only when screen-space shafts are requested. Fog-only mode
must allocate none of them and execute no new lighting passes.

Target draw budget:

- fog only: unchanged depth reduction + two layered integrations + one
  composition;
- lighting with `shaft_strength == 0` or off-screen sun: the same four draws;
- lighting with screen-space shafts: two additional quarter-resolution draws
  (mask and radial), still one pair of integrations and one composition.

Do not add:

- a second full-resolution scene copy;
- full-resolution shaft marching;
- separate fog and lighting integrations;
- runtime-variable sample loops;
- per-pixel engine memory reads;
- per-frame texture allocation;
- a temporal history allocation in this phase.

Log target creation, selected fixed variants, draw counters, and lighting gate
changes. Keep logs transition-based/rate-limited; do not add per-frame or
per-pixel diagnostics. Runtime performance acceptance compares disabled,
lighting-only Performance/High/Ultra, fog-only, and combined High in the same
scene. High is rejected if its cost is disproportionate to the explicit work
budget or if it causes visible frame-pacing instability under VRR.

## Exact file plan

| File | Change |
|---|---|
| `omv/src/effects/atmosphere.rs` | Add lighting settings/gates, captured-camera sun projection, HG/disk CPU helpers, shaft shaders/resources/passes, independent fog/light outcomes, diagnostics, static tests, and fixed budgets. |
| `omv/shaders/embedded/atmosphere_integrate.hlsl` | Add bounded native-sun single scattering and shaft visibility to the existing shared near/far medium integration. |
| `omv/shaders/embedded/atmosphere_shaft_mask.hlsl` | New deterministic conservative reduced-depth openness mask. |
| `omv/shaders/embedded/atmosphere_shaft_radial.hlsl` | New fixed-count quarter-resolution radial visibility pass. |
| `omv/shaders/embedded/atmosphere_debug.hlsl` | Add lighting-specific mask, visibility, phase, radiance, and combined views without changing production composition. |
| `omv/shaders/embedded/atmosphere_compose.hlsl` | Preserve the accepted dual-layer path; only ABI changes proven necessary by combined integration are allowed. |
| `omv/src/config.rs` | Add lighting `max_distance`, sanitize all active fields, preserve old config compatibility, and remove misleading active treatment of reserved temporal control. |
| `omv/src/shaders.rs` | Complete embedded option bindings, lighting debug choices, reset/save synchronization, and effect description. |
| `omv/src/fnv_world_pipeline.rs` | Request coherent world inputs for lighting and test nonblocking behavior. |
| `omv/src/runtime.rs` | Preserve independent legacy Sunshafts execution and update UI status text. |
| `omv/src/backend/mod.rs` / `omv/src/backend/fnv.rs` | Reuse copied native sky values; only add typed value fields if needed. Do not add raw shadow/resource pointers or a new lock. |
| `omv/config/omv.toml` | Ship bounded lighting defaults, new distance control, accurate debug labels, and no false Phase 3 warning. |
| `omv/README.md` and parent atmosphere plans | Document implemented directional lighting, performance tiers, legacy fallback, honest screen-space limitation, and static validation. |

No change belongs in `psycho-engine-fixes-helper`, xNVSE glue, native PBR,
gheap, or a vanilla shadow hook.

## Implementation order and stop gates

1. Add pure CPU sun projection, HG, medium selection, gate truth table, option
   ABI, and unit tests. Stop if any engine input would require an unproven raw
   pointer or shadow resource.
2. Add shaft mask/radial HLSL and compile all fixed variants with the real D3D
   compiler. Stop on any `ps_3_0` failure or instruction/profile limitation;
   reduce the fixed Ultra count rather than moving to an unbounded loop.
3. Add transactional quarter-resolution resources and passes. Prove fog-only
   does not allocate or draw them.
4. Extend the existing near/far integration with analytic directional
   scattering. Re-run the mixed foreground/sky regression before touching
   production composition.
5. Add lighting diagnostics and explicit fog/light debug selection.
6. Preserve independent legacy Sunshafts execution and add nonblocking/reset
   tests.
7. Complete TOML, ImGui, reset/save, status, README, and parent-plan updates.
8. Run formatting, diff checks, all i686 OMV tests under Wine, and the explicit
   i686 release build. Do not deploy if any static gate fails.
9. Build/install with `build_fnv.sh` only after the implementation and static
   gates are clean, then perform the feature-first acceptance run below.

## Feature-first playtest acceptance

This is not a diagnostics-only run. Begin with debug view Off and validate the
visible feature first:

1. clear exterior midday: lighting toggle visibly changes the medium without
   gray washout or sky blinking;
2. the old fence/mixed-depth camera angles: no high-frequency flashing, whole
   effect loss, or near/far layer switch;
3. lighting-only, fog-only, and combined: each is distinct, and combined does
   not double extinction;
4. rotate through on-screen, edge, off-screen, and behind-camera sun positions:
   shafts fade smoothly while base directional scattering and fog remain
   stable;
5. sunrise/sunset, overcast, night: native color/daylight transitions remain
   bounded and do not pop;
6. interior, underwater, loading, menu, FOV, teleport, and first-person weapon:
   the established fail-closed and world-only boundaries remain intact;
7. foliage, particles, water edges, terrain LOD boundaries, and distant sky:
   no silhouette halo, swimming shaft mask, or mixed-cell dropout;
8. compare Performance, High, and Ultra with VRR enabled; High must be the
   production default and must not create frame-pacing jitter.

Lighting debug views may be checked during the same run after ordinary output
passes. They are not a prerequisite for seeing a real effect.

## Do not repeat

- Do not sample native type `0x2B`, call `ShadowProj` a sun shadow map, or infer
  cascade data that the audits did not prove.
- Do not use the legacy live sun UV with a separately captured depth camera.
- Do not make a missing/off-screen sun bypass valid fog.
- Do not add `medium_density` on top of enabled fog extinction.
- Do not create a second lighting ray marcher or composition pass.
- Do not return to nearest-only reduced-depth rejection.
- Do not use frame-varying jitter without a proven atmosphere history.
- Do not run the new effect after first-person/UI to obtain an easier mask.
- Do not automatically suppress legacy Sunshafts based on successful Phase 3
  composition; the passes have different inputs, stages, and visual roles.
- Do not claim static shader compilation proves runtime pixels. It is a strong
  pre-deployment gate, not a replacement for the final feature playtest.

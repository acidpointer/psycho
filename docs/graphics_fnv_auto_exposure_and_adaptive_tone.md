# OMV automatic exposure and display tone mapping

## Purpose and domain

OMV adds bounded transient adaptation and a contrast-preserving display curve
inside its existing final-color transaction. Fallout's native image-space
pipeline has already tone-mapped the scene at this boundary. OMV cannot recover
clipped radiance here and does not claim physical scene-referred auto exposure.
Genuine HDR exposure requires separately proven ownership of the pre-tone
resource, native adaptation, transfer function, and HDR blend variants.

The owner requested bright sky/dark ground separation in mixed views as well as
sky-heavy views. Controlled visual-effect fixtures through compiled production
shaders are explicitly authorized for this correction. They are design and
regression evidence, not captures of the reported gameplay scene. Game-only
image, integration, startup, and performance behavior remains unrun; the root
OMV no-game-runtime exception applies.

## Findings and evidence

The owner reported a dull sky, brighter-looking ground, and an overall grey
appearance at approximately 40-50 percent sky coverage. Persistence after a
stationary view was unknown. The inspected game log confirmed successful
automatic-response initialization. Saved settings had exposure range about
0.419, adaptation speed about 0.482, tone strength about 0.676, and Bloom,
analytic grading, a LUT, and halation enabled. These are saved settings, not
proof of the live values at the reported instant.

Evidence locations:

- `/data/storage0/Games/FalloutNV_TTW/FalloutNV/omv-latest.log`
- `/data/storage0/Games/FalloutNV_TTW/mods/omv/NVSE/plugins/omv/omv.toml`
- `omv/src/effects/adaptive_display_tests.rs`: executed production-path visual
  and temporal regressions, including the saved adaptation settings.

The correction addresses three demonstrated mechanisms:

1. The former extended-Reinhard ratio compressed ordinary display luminance
   after native tone mapping. Its strength also changed with bright-pixel
   occupancy, so framing changed the entire image's look. The unchanged
   production shader mapped the controlled 0.80 sky to approximately 0.731.
   The old "visible tone" CPU test rewarded sky darkening instead of testing
   retained sky/ground contrast.
2. The old 4x4 LOD-zero meter sampled small neighborhoods, not screen regions.
   Moving a horizontal boundary by two rows on the controlled 256-square
   input changed its log-luminance anchor by approximately 0.546. There was
   no special 50-percent mode switch; crossing a meter row changed a large
   fraction of its samples at once.
3. A single FP16 adapted-log value lost small temporal increments. At the
   saved slow adaptation speed, the executed dark-transition regression still
   held approximately -0.413 EV after 45 seconds. Merely changing metering or
   the tone curve cannot repair that persistent temporal error. Split storage
   now retains the fine increments in the same response texture.

The exact relative contributions of native adaptation, Bloom, creative grading,
and these OMV mechanisms to the owner's original scene are not isolated.
"Grey" does not establish lost chroma: the old scalar tone response reduced
brightness separation while preserving RGB ratios until clipping. At neutral
exposure it could only darken nonnegative inputs, so it alone does not prove
absolute ground brightening in the report.

## Ownership and order

`fnv_render.rs::hook_process_image_space_shaders` invokes native image-space
processing before OMV's scene-post and final-image phases. The established
native phase evidence is in
`analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt` and
`analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`.
This correction changes no native hook, address, engine layout, or phase.

The final-image order is:

1. Bloom extraction and two-axis blur, when Bloom or halation needs them.
2. At most 60 times per second, meter ungraded scene plus optional Bloom,
   reduce statistics, and generate the response/history texture.
3. Fused composition: deband and Bloom, analytic grading, LUT, halation,
   vignette, display response, grain, dither, final quantization.
4. Existing chromatic aberration, spatial AA, and external final shaders.

`blooming_hdr.rs` owns preparation, resource lifetime, bindings, timing, and
fallback. `adaptive_meter.hlsl` owns spatial metering and reduction;
`adaptive_tone.hlsl` owns temporal adaptation and response generation;
`display_tone.hlsl` is the shared curve source prepended to both fixed and
adaptive production shaders. `bloom_hdr_compose.hlsl` applies the response.

Exposure does not meter OMV's creative grading, LUT, grain, or its own output.
This avoids self-feedback. The highlight meter estimates scene/Bloom peaks
before creative finishing and omits first-person Bloom attenuation, as before.
It is not an exact measurement of post-LUT highlights. The per-pixel shoulder
still acts on actual finished color, including highlights absent from the meter.

## Metering and temporal response

A 64x64 stratified grid covers the source. Each 16x16 meter texel integrates
4x4 bilinear source samples. It computes Rec. 709 display luminance and its log
before averaging. A second 1x1 pass reduces the tile sums once, retaining
weighted log sum, weight, and maximum scene/Bloom channel. This is bounded
spatial integration, not an exact average of every full-resolution pixel;
sub-grid highlights can still escape the global meter.

Exposure retains center weighting from 1.0 toward 0.40, smooth black exclusion
between 1/255 and 4/255, and per-sample winsorization within +/-2.5 display-log
units of the previous adapted anchor. Invalid scene/Bloom samples are rejected
before logarithms and accumulation. A black frame holds valid history; an
initial black frame keeps the uninitialized sentinel.

The adapted log follows the current metered log, using half-lives of 0.52 s
for brighter input and 1.05 s for darker input. The target transient exposure
is their residual, converted to approximate display-linear stops using the
existing gamma-2.2 convention. A smooth 0.035..0.155-stop deadband suppresses
small changes; applied exposure follows with a 0.14 s half-life. Range clamps
that transient symmetrically. Display gain is `2^(EV/2.2)`, rather than applying
`2^EV` directly to encoded RGB. With tone off, sampled highlight headroom also
bounds positive target exposure.

Negative transient exposure now acts fully through the display midpoint 0.5,
then smoothly returns to neutral gain over input channel peaks 0.5..0.7.
Bright response entries at or above 0.7 therefore retain their authored tone
when the camera includes more dark ground. The unchanged global metering and
history still drive shadow/midtone adaptation. This is a display-curve policy,
not a sky classifier or an estimate of weather. It preserves scalar RGB ratios
and source alpha, adds no full-resolution work, and leaves positive exposure,
user tone strength, resource layout, and update cadence unchanged.

The owner reported possible sky dimming when ground occupies more than half
the frame. The unchanged production path reproduced that valid case with fixed
sky/ground inputs: moving from 48 to 26 sky rows lowered unchanged sky output
from approximately 0.8745 to 0.8657 as negative exposure began. The prior settled
mixed-view tests disabled exposure and could not catch this transient. New
production-path regressions retain bright values during continuous 48/26/16/8
row transitions with default, saved, and maximum exposure ranges; they cover
FP16 and UNORM output, gradients, color, alpha, and retained dark adaptation.
This establishes an OMV mechanism, not the exact contribution of weather or
native adaptation to the owner's gameplay view.

The wider bright range is an intentional display calibration: the previous
0.8 endpoint still allowed an unchanged 179/255 input to fall from 0.7017 to
0.5654 in the executed maximum-range negative-adaptation regression. The
0.7 endpoint now keeps the 179..255 gradient within two output codes of its
neutral response across all tone modes, zero/default/maximum strength, and
FP16/UNORM output. Continuous coverage tests use the lower 179/255 sky value;
colored fixtures include that same channel peak. The whole gradient remains
nondecreasing, alpha and color ratios are retained, and the 77/255 dark input
still responds to negative adaptation. The smooth join and unchanged positive
gain preserve the monotone response; no pass, sample, or resource is added.

These are display-adaptation stops, not scene radiance or EV100. A settled
view returns to neutral exposure. The correction retains the requested brief
bright/dark transition behavior instead of introducing a second absolute
exposure controller behind Fallout's own controller.

Automatic tone observes over-range peak energy including positive transient
exposure. Negative exposure does not lower that highlight signal, because the
bright entries themselves are protected from negative gain. The over-range
regression verifies retained shoulder activity and unchanged bright output
while camera coverage drives negative history.
Its target is smoothstep over peaks 1..2; it rises with a 0.22 s half-life and
releases with a 0.72 s half-life. Ordinary 0..1 sky occupancy does not change
contrast. The speed control scales all temporal rates.

The existing scheduler integrates successful consecutive Present intervals,
clamps intervals to 1/240..1/20 s, and updates at most 60 Hz. Its fractional
phase and elapsed integration time remain separate. Missing frames, resize,
disablement, and device recreation invalidate history and seed neutrally.

## Contrast and highlight curve

The curve is an authored display look, calibrated by the controlled-image
requirements. Its midpoint 0.5 is a display-space contrast pivot, not a claim
about photographic 18-percent grey or Fallout scene lighting.

For strength `s`, let `a = s/(1+s)`, slope `c = 1+a`, and shoulder reserve
`r = min(a/2 * (1 + activity/2), 0.4)`. Fixed neutral mode uses zero activity.
The scalar input `P` is the maximum finished RGB channel after transient
exposure, rather than luminance. Below the midpoint, with `q = 1-2*P`:

`T(P) = P / (1 + a*q - (a*a/2)*q*q)`

Above the midpoint, let `L = 0.5 + c*(P-0.5)` and
`d = max(L - (1-r), 0)`:

`T(P) = min(L, 1 - r*r/(r+d))`

The implementation protects the denominator at vanishing strength. The latter
expression is algebraically the same rational shoulder as `L-d*d/(r+d)` when
the shoulder is active, but avoids subtracting large, nearly equal quantities.
The larger reserve keeps useful code separation in bright gradients. Its cap
retains the accepted 0.8 sky boundary at maximum strength with fully active
highlights. Toe curvature relieves deep compression while retaining darkness,
the midpoint slope, and exact black; it is not an additive shadow lift.

Black and the midpoint remain fixed. The toe darkens lower values; the middle
slope expands separation; the shoulder approaches display white smoothly.
Value and first derivative agree at both joins, and response is monotonic
through the supported strengths. Zero strength bypasses tone exactly.
Automatic activity changes only shoulder reserve, never toe, pivot, or middle
slope. This avoids both unconditional broad dimming and the older ineffective
near-white-only correction.

RGB is multiplied by `T(P)/P`, with exposure included in the adaptive response.
This bounds all channels smoothly and preserves their ratios before display
noise and quantization. The former luminance scale followed by a hard peak cap
flattened colored highlights once the cap dominated; it has been removed.
Finite output precision still limits distinguishable extreme levels. Grain
and dither remain later.

With tone or automatic exposure active, analytic grading retains positive
over-white values until final mapping. Negative graded components remain
clamped before its existing rational rolloff. LUT coordinates still clamp to
the declared display domain. The LUT result additionally retains the positive
per-channel residual `max(color-domain_max, 0)`, with the existing LUT/master
blend applied afterward. In-domain LUT behavior is unchanged. This is a
continuous, unit-slope extension of an existing display LUT, not recovered HDR
radiance or an extrapolation of its authored colors. The legacy compose
variant preserves its original grading clamp and LUT behavior when adaptation
and tone are inactive.

Fixed mode prepares slope and reserve on the CPU, outside per-pixel shading.
Automatic mode prepares them in the response generator. Both execute the same
HLSL curve source. Neutral tone with active automatic exposure still uses that
fixed curve through the response lookup.

## Resources, ABI, and precision

All metering/history targets are `D3DFMT_A16B16G16R16F`:

| Resource | Dimensions | Payload |
|---|---:|---:|
| Spatial statistics | 16x16 | 2,048 bytes |
| Reduced statistics | 1x1 | 8 bytes |
| Two response/history targets | 512x1 each | 8,192 bytes |

Total payload is 10,248 bytes, excluding driver overhead. The 512-entry curve
uses compact input coordinate `u=P/(1+P)`, with inverse `P=u/(1-u)` in response
generation. Texel centers include black and the white asymptote. The terminal
texel stores zero white headroom explicitly; intermediate scalar generation
uses the existing FP16 finite bound to protect the inverse denominator. The
lookup no longer clamps input at 4. Fixed-versus-filtered comparisons retain
the 0.002 output-error bound across supported strengths in 0..4 and the tested
4..16 highlight extension.

Response R contains nonnegative white headroom `max(1-T(P*gain), 0)` indexed by
the unexposed peak. Compose reconstructs the mapped peak as `1-R` and divides
by its actual input peak. Headroom provides finer FP16 precision near white
than storing mapped output or a decreasing gain: those alternatives exhibited
one-code reversals in the executed UNORM ramps. B and A replicate exposure EV
and shoulder activity. G stores coarse adapted log luminance, except texel 1,
which stores its fine remainder. The coarse part is quantized to multiples of
1/64, exactly representable throughout the metered [-10, 0] interval. Summing
the two point-sampled components preserves slow adaptation increments that a
single FP16 value loses. Coarse G=+1 remains the initial-black sentinel.

Metering uses scene at s0, previous history at point-sampled s1, and optional
Bloom at s4. Reduction samples tile centers at s0. Response generation uses
reduced statistics at s0 and point-sampled history at s1. Constants c0..c3
retain timing, exposure, tone, and Bloom policy; c1.w supplies inverse response
width. Fused composition linearly samples R at s7. The response has one row
and clamp addressing on both axes, so compose reuses U as V. Fixed-mode c19
contains contrast amount, reserve, inverse response width, and toe curvature.
Adaptive-mode c19.x/y contain the prepared scale/bias for
`rcp(1+P)*(1/width-1) + (1-0.5/width)`. Compose reuses existing c9 for the LUT's
validated upper domain; extraction/blur retain their per-pass c9 dimensions.
No persistent field or additional constant slot is introduced. sRGB decoding
and writes are disabled consistently with the existing display-color contract.

Every target change clears source aliases before binding RT0. History targets
ping-pong and publish only after a successful response draw. The complete
meter/history allocation is transactional. The effect owns all device objects
and drops them at the existing reset/device-loss boundary.

## Failure, compatibility, and cost

The existing live-device FP16 render/filter capability check remains. Missing
capability, shader creation failure, or partial target allocation failure
retains fixed neutral mapping and the rest of final-color processing; automatic
exposure becomes inactive. No partial meter/history set is published. The
existing one-time initialization/failure logging remains on the established
render-resource lifecycle boundary.

No configuration field, schema, preset payload, static owner, TLS value,
worker, hook, admission bit, or phase changes. The new device-owned metering
shaders/resources sit behind a box that replaces the previous compose-shader
pointer inside `AdaptiveTonePipeline`; a compile-time size invariant preserves
that owner's original two-pointer inline footprint and therefore the enclosing
runtime layout. The existing preparation worker compiles two additional shader
variants; no compilation occurs in a render callback. The last documented
startup baseline remains `9975b2e`; static qualification does not establish a
new gameplay-tested startup baseline.

Automatic updates cost three small draws instead of one: 256 meter pixels,
one reduction pixel, and 512 response pixels. Worst-case texture fetches per
update are 8,704 for scene/Bloom metering and two history reads per tile, 256
for reduction, and 1,536 for response generation: 10,496 total. Without Bloom,
subtract 4,096. This replaces 4,224 worst-case fetches over just 16 source
locations with 4,096 scene locations. The extra two target switches/draws are
an explicit quality cost. Steady-state allocation, shader compilation, CPU
readback, file I/O, and blocking remain absent.

Full-resolution adaptive compose retains one response lookup and stays within
its existing 515-instruction / 15-texture-op ceiling and 16-instruction delta
from legacy. Fixed compose retains its 530 / 14 ceiling by preparing policy
coefficients on the CPU. Meter, reduction, and response variants have separate
compiled instruction/texture budgets. Disabled adaptation schedules no meter
or response work. These bounds do not establish frame time or an FPS gain.

## Validation contract

The offline suite executes the shipped shaders and Rust draw/resource path,
including FP16 storage and filtering. Required properties include:

- bright/dark separation at 75%, 50%, and approximately 40% sky coverage;
- no settled tone change from ordinary sky occupancy;
- bounded meter response when a horizon crosses an old sparse sample row;
- bounded transient signs, frame-rate consistency, and neutral convergence;
- slow dark adaptation at the saved settings without FP16 stalling;
- black/invalid-history recovery and neutral restart;
- monotonic, finite output across strengths, preserved alpha and color ratios;
- agreement between fixed and filtered curves within 0.002 output units;
- actual over-range input, Bloom extraction/blur, creative finishing, and fixed
  capability fallback;
- production shader compilation and compiled budgets, affected and complete
  OMV suites, explicit 32-bit release build, formatting, and diff review.

Controlled fixtures do not reproduce the owner's exact gameplay frame. The
work may be reported as offline-qualified after these gates, with game-only
behavior identified as unrun. It does not require an owner gameplay run.

## Design references

- [Epic's auto-exposure design](https://www.unrealengine.com/tech-blog/how-epic-games-is-handling-auto-exposure-in-4-25)
  distinguishes metering, middle-grey targeting, compensation, and spatial
  masks. Conventional camera exposure may darken sky-heavy views; that sign
  alone does not establish a defect.
- [Filament's imaging pipeline](https://google.github.io/filament/main/filament.html#imagingpipeline)
  separates scene luminance, exposure normalization, temporal metering, and
  display processing. These principles do not supply FNV-specific calibration.

## Highlight-detail improvement and remaining research

The owner requested a more atmospheric and immersive result that respects sky
and other bright surfaces. The selected change preserves luminous sky/ground
separation, colored highlight gradients, environmental darkness, and creative
finishing headroom. It retains the neutral-converging transient exposure,
current strength control, configuration shape, native phases, and resources.
The final equations and ABI above describe this implementation.

### Demonstrated failures and selected response

Maintained controlled fixtures in `adaptive_display_tests.rs` executed the
unchanged production Rust/D3D9 path before production edits. Blue/cyan/sunset
and neutral ramps cover the white boundary through 4, both fixed and automatic
variants, initial response and settled activity, FP16 and final UNORM output.
The color regression failed when proportional blue highlights collapsed to
identical RGB. Full-strength analytic grading failed when its intermediate
clamp collapsed the bright ramp. The shipped neutral and Mojave Natural LUT
regression also failed at full LUT strength. These are authorized design
fixtures, not gameplay captures or attribution of the owner's image.

The selected ratio-preserving peak shoulder repairs the colored plateau
without introducing a highlight desaturation policy. Retaining analytic
positive headroom and the LUT's upper-domain residual repairs the earlier
information loss. A domain-remapped LUT would alter its authored in-range
color relationship; that alternative was not implemented. A joint chroma
response was not selected because the peak response satisfies the executed
ordinary-color ratio and highlight-detail requirements without changing hue.
These are scoped design decisions, not claims of subjective visual superiority.

The regressions observe strictly ordered early/middle/late highlight levels,
nondecreasing ramps within FP16 tolerance, bounded finite output, alpha, and
RGB ratios before quantization. The UNORM cases retain visible level separation.
Additional fixtures exercise 4..16 highlights, fixed-versus-filtered agreement,
and fully active over-range shoulders with 0.8 sky and 0.3 ground at several
strengths and bright-area coverages. Existing Bloom/halation/grade/LUT,
exposure-settling, history/reset, disabled-path, and sky-coverage regressions
remain the integration acceptance. They do not prove final gameplay imagery.

No draw, allocation, sampler, response resolution, or constant-register count
is added by this highlight correction. Compiled legacy, fixed, adaptive,
meter, reduction, and response budget gates retain their original ceilings.
The earlier source-string alpha/lookup contract was replaced by actual output
alpha checks and existing compiled/runtime work budgets; textual matching is
not image evidence.

### Distribution metering remains an unselected extension

The existing weighted log statistic and sampled maximum remain unchanged.
The executed coverage fixture retains the same sky response with an over-range
strip occupying 1, 8, or 16 of 64 rows, while ordinary sky never activates the
shoulder. The new per-pixel curve protects all sampled output pixels even when
a small source escapes the coarse meter. This closes the demonstrated
highlight-detail failures without adding a global distribution controller.

A temporary compiled upper-tail candidate accumulated the current local
`smoothstep(peak-1)` signal in unused meter A, reduced it as an area mean, and
used that result for shoulder activity. The actual D3D9 pipeline retained its
production log anchor, peak, resources, history, and composition; only the
candidate metering/response shaders differed. It passed the existing meter
instruction/fetch ceiling but failed the same 0.001 sky-invariance requirement.
At maximum strength, increasing the 2.0 strip from 1 to 8 to 16 rows changed
the candidate's settled 0.8 sky output from approximately 0.8169 to 0.8066 to
0.8057. The peak controller stayed at approximately 0.8057 in all three views.
This candidate reintroduced framing-dependent sky brightness without repairing
an additional demonstrated detail failure, so it was not adopted. The
temporary comparison code is not a maintained substitute for production tests.

A compact histogram or upper-tail controller still requires an executed
comparison showing a quality benefit over this baseline, with a defined
bright-area/peak policy and accepted frame-rate/transition behavior. That
multi-bin/percentile comparison has not been completed. No bin count, percentile threshold, or
coverage-dependent response is approved calibration merely by analogy with a
scene-linear renderer. D3D9 reduction, additional targets/draws, sampler work,
memory, and temporal costs must be measured before adoption. Preserve the
split FP16 anchor, neutral restart/settling, independent creative metering, and
per-pixel protection in any such comparison.

### Sky classification and local exposure

Sky-aware metering requires proof of coherent classification at the final
image boundary, including clear/background endpoints, clouds, transparency,
first-person geometry, resolution, depth conventions, and unavailable inputs.
Brightness is not a semantic sky classifier. Once proven, evaluate separately
bounded sky/ground influence while retaining sky in highlight protection.

Local exposure remains a separate mixed interior/exterior extension. Establish
actual-path detail, halo, and temporal acceptance before editing. Edge-aware
base/detail adjustment must preserve foliage, horizons, windows, transparency,
haze, and motion. Its resources, filtering, temporal, and performance contracts
remain open. Neither extension recovers detail clipped by native tone mapping.

### Qualification boundary

Qualify production changes with the maintained behavioral regressions, all
shader variants and unchanged budgets, formatting, the full OMV crate suite,
and the supported 32-bit release build. Inspect the diff and preserve concurrent
user work. Passing focused checks alone does not clear an unrelated failing
full-suite or formatting gate in the current worktree. Game-only image,
integration, startup, and performance behavior remains not run under the root
OMV exception; owner gameplay validation is never an agent gate. This work
authorizes no commit, deployment, or packaging.

Additional design references:

- [Khronos PBR Neutral specification](https://github.com/KhronosGroup/ToneMapping/blob/main/PBR_Neutral/README.md)
  provides smooth highlight/color handling for nonnegative linear Rec. 709
  input; it is not a drop-in contract for OMV's display-referred input.
- [ACES gamut compression](https://docs.acescentral.com/system-components/output-transforms/technical-details/gamut-compression/)
  separates tone and gamut constraints while preserving perceived hue.
- [Epic's exposure documentation](https://dev.epicgames.com/documentation/en-us/unreal-engine/auto-exposure-in-unreal-engine)
  describes distribution metering and local base/detail exposure; native FNV
  ownership and D3D9 feasibility require independent proof.

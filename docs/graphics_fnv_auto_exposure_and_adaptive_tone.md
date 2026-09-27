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

These are display-adaptation stops, not scene radiance or EV100. A settled
view returns to neutral exposure. The correction retains the requested brief
bright/dark transition behavior instead of introducing a second absolute
exposure controller behind Fallout's own controller.

Automatic tone observes only over-range peak energy after transient exposure.
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
`r = a/4 * (1 + activity/2)`. Fixed neutral mode uses zero activity. Below the
midpoint, mapped luminance is:

`T(Y) = Y / (c + 2*(1-c)*Y)`

Above the midpoint, let `L = 0.5 + c*(Y-0.5)` and
`d = max(L - (1-r), 0)`:

`T(Y) = L - d*d/(r+d)`

Black and the midpoint remain fixed. The toe darkens lower values; the middle
slope expands separation; the shoulder approaches display white smoothly.
Value and first derivative agree at both joins, and response is monotonic
through the supported strengths. Zero strength bypasses tone exactly.
Automatic activity changes only shoulder reserve, never toe, pivot, or middle
slope. This avoids both unconditional broad dimming and the older ineffective
near-white-only correction.

RGB is multiplied by the shared luminance scale. A uniform peak limit prevents
independent channel clipping from bleaching bright saturated colors; this
preserves ratios but cannot retain unlimited brightness differences once a
color reaches the display gamut boundary. Grain and dither remain later.

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
covers input luminance 0..4. An executed fixed-versus-filtered comparison found
that 128 entries exceeded the 0.002 output-error bound at low strength; 512
resolves the narrow shoulder without adding a full-resolution lookup.

Response R contains the luminance-indexed scale. B and A replicate exposure EV
and shoulder activity. G stores coarse adapted log luminance, except texel 1,
which stores its fine remainder. The coarse part is quantized to multiples of
1/64, exactly representable throughout the metered [-10, 0] interval. Summing
the two point-sampled components preserves slow adaptation increments that a
single FP16 value loses. Coarse G=+1 remains the initial-black sentinel.

Metering uses scene at s0, previous history at point-sampled s1, and optional
Bloom at s4. Reduction samples tile centers at s0. Response generation uses
reduced statistics at s0 and point-sampled history at s1. Constants c0..c3
retain timing, exposure, tone, and Bloom policy; c1.w supplies inverse response
width. Fused composition linearly samples R at s7. Fixed-mode c19 contains
slope, reserve, strength, and a reserved lane. sRGB decoding and writes are
disabled consistently with the existing display-color contract.

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

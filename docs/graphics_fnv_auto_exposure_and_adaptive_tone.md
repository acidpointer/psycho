# OMV automatic exposure and adaptive tone mapping

Status: third correction implemented in the 2026-08-12 worktree. The latest
RX 6800 XT playtest confirmed that transient exposure was plausible, but
automatic tone remained visually inert. Its log and deployed Current Look now
establish why: the adaptive route had no positive initialization evidence, and
the selected curve was exact identity through most of Fallout's post-native
display range. Repository tests and the supported release build are static
acceptance gates. Visual behavior, frame time, device reset, cross-vendor
behavior, and pre-`DeferredInit` compatibility still require the playtests
listed below.

## Purpose and scope

OMV adds a restrained, eye-like transition when camera motion changes the
displayed brightness, plus a smooth photographic luminance response whose
automatic mode deepens gently when the native image and OMV Bloom contain more
highlight energy. Both features run inside the existing final-color
transaction. They do not add an engine hook, CPU readback, native shader
replacement, or another full-resolution pass.

This is a display-referred effect. Fallout New Vegas' native image-space work
has already mapped the scene before OMV's final-image phase, so OMV cannot
recover scene radiance which the native pipeline clipped. In this phase,
"exposure" means a short-lived perceptual response between successive views,
and "tone mapping" means a final display-referred luminance curve. Neither term
claims physical EV100 camera control or a replacement for Fallout's native HDR
family.

The workbench retains the released controls:

- `Auto Exposure`: enable, symmetric transient range, and adaptation speed;
- `Tone Mapping`: off, fixed neutral, or automatic, plus response strength.

Defaults remain automatic exposure, `0.75 EV`, speed `1.0`, automatic tone,
and strength `0.65`. The values remain Current Look preferences outside
shareable visual presets. No schema, field order/type, manifest, migration, or
built-in preset payload changed during this correction.

## Root-cause review

### Reversed visible response

The first implementation used an absolute gray-key camera equation:

`target_ev = log2(0.36) - mean_log_luminance`

That equation is conventional for a camera trying to make every view approach
the same middle gray, but it is the opposite of the requested transient
adaptation in OMV's post-native display phase. A bright sky produces a negative
target and is darkened; a darker ground produces a positive target and is
brightened. The old tests explicitly expected those signs, so the defect was a
wrong behavioral model rather than an arithmetic typo.

Automatic tone reinforced the result. It treated native near-white occupancy
as a request to lower its shoulder from `0.82` toward `0.66`, so an ordinary
bright sky could activate a second global darkening response even when OMV had
created no over-range highlight to preserve.

The corrected negative-control test first reproduces both old signs, then
requires the new model to make a dark-to-bright transition positive, a
bright-to-dark transition negative, and a settled view exactly neutral.

### Invisible automatic tone

The first correction detected only Bloom-composed peaks above `1.0` and reused
exposure's outlier suppression for tone activity. That excluded the exact
upper-tail values a display mapper must shape. It then attenuated the result
twice: activity barely moved the shoulder and a second smooth gate blended the
small correction back toward identity. At shipped defaults, the reproduced
uniform-white Bloom peak was about `1.092`; the old response left it at about
`1.054`, so both values quantized to display white.

Tone also ran before analytic grading, the LUT, halation, and vignette. Those
families could recreate over-white values after mapping, and the final
`saturate` erased their distinction. The new regression retains the old curve
as a negative control, requires the shipped-default case to reserve at least
five UNORM8 codes of headroom, and verifies source order: finishing, tone,
grain, then final clamp.

### Still invisible in the 2026-08-11 playtest

The next implementation fixed ordering and over-white saturation but retained
the wrong calibration domain. Its curve used an RGB-peak knee and validated an
exaggerated `1.25` fixture. Fallout's native HDR blend had already produced the
post-native display image consumed by OMV, so ordinary sky and terrain values
were predominantly inside `0..1`.

The deployed Current Look used auto exposure `false`, automatic tone strength
`0.994582`, and Color Grade master `0.68`. At low automatic activity the code
computed a tone level of approximately
`0.994582 * 0.68 * 0.30 = 0.203`, placing the knee at about `0.939`. A `0.80`
sky value was therefore exact identity. Even display white mapped only to
about `0.970`. That three-percent endpoint change, confined to the last six
percent of the signal, explains the user's report that the feature did not
work. The prior `1.25` regression could pass while the actual 0-1 image was
unchanged.

The same code incorrectly treated top-level adaptive-display controls as
sub-controls of creative grading. Color Grade master strength attenuated both
transient EV and tone, and a zero creative master disabled their work plan and
Present clock. Sharing one fused source is an optimization, not an ownership
relationship; the independent Current Look values must not inherit that
master.

The 2026-08-11 log at
`/data/storage0/Games/FalloutNV_TTW/FalloutNV/omv-latest.log` is direct runtime
evidence for the surrounding route. Dirty release build
`288293ccbec02af8fe9ecb225c5c162457fa123d` reached DeferredInit, initialized
the final-color pipeline at 3440x1440, uploaded the LUT, created Bloom targets,
and later reported 13,800 Presents with zero world-pipeline failures. It
contained neither adaptive failure nor positive adaptive-target initialization
evidence. This correction adds one device-lifetime success line when both FP16
response targets are created, without adding per-frame diagnostics.

### Vanilla Plus Tonemapper comparison

The installed Vanilla Plus Tonemapper 1.1.2 files are reference evidence, not
an active conflict: the MO2 profile marks both the main mod and Sky Brightness
Tweak disabled. The main mod replaces Fallout's three native
`ISHDRBLENDINSHADER*` pixel shaders. Local bytecode disassembly matches its
published source: clamp negative IMOD output, linearize with gamma 2.2, add
slight log-space contrast, apply luminance-only extended Reinhard with white
point 2.5, and encode back to display space. It therefore operates while the
native HDR blend still owns over-range scene information. The optional script
multiplies daytime weather IMOD sky-dimmer traits 19 and 20 by 1.25; it
compensates the intentional broad dimming of a working curve rather than
providing tone mapping itself.

OMV deliberately keeps its established post-native hook and cannot recover
already clipped radiance. The reusable lesson is nevertheless decisive: a
visible photographic curve must shape ordinary midtones and highlights, not
wait for values which rarely survive the native blend.

### Frame-time regression

The prior compiled `ps_3_0` audit measured 499 instructions and 14 texture
opcodes for exact legacy compose, versus 555 instructions and 15 texture
opcodes for adaptive compose. Thus every display pixel paid an additional 56
instructions, including `exp2`, a rational divide, and dynamic policy branches.
The 1x1 meter itself was small, but its draw and render-target switch added
fixed driver work. A loss from 120 FPS to 117 or 115 FPS represents about
0.21-0.36 ms, which is consistent with a small full-resolution shader increase
plus fixed submission overhead. Because the same degradation was observed on
AMD, the correction is vendor-neutral rather than an NVIDIA policy path.

The remaining fixed costs were unnecessarily repeated at every Present. The
256 response pixels each repeated two 32-sample exposure passes, Bloom reads,
and a history read: 24,832 worst-case texture fetches, plus a render-target
transition and draw. The correction reduces this to a single 4x4 pass over 128
response pixels and caps updates at 60 Hz. The retained response lookup can
still have measurable cost on a real driver; only comparative GPU frame-time
can close performance acceptance.

## Ownership and ordering

- `omv/src/config.rs` owns `AdaptiveToneConfig`, `ToneMapperMode`, stable
  persistence, and finite bounds.
- `omv/src/shaders.rs` projects those preferences into the existing fused
  final-color menu source and keeps them out of preset payloads.
- `omv/src/runtime.rs` owns the workbench editors and the existing post-
  Deferred Present timing/continuity publication.
- `omv/src/effects/blooming_hdr.rs` owns variant selection, live-device format
  capability checks, response resources, bindings, ordering, and fail-soft
  behavior.
- `omv/shaders/embedded/adaptive_tone.hlsl` owns bounded metering, independent
  highlight-tail measurement, temporal state, and response-curve generation.
- `omv/shaders/embedded/bloom_hdr_compose.hlsl` owns the one-lookup adaptive
  application and the separate fixed-neutral curve.
- `libpsycho/src/os/windows/directx9.rs` owns the safe public D3D9 capability
  query used to prove that the live device supports both FP16 rendering and
  linear filtering.

The fixed final-image order is:

1. native image-space and earlier OMV phases produce display-referred color;
2. Bloom extraction and two-axis blur run when Bloom or halation needs them;
3. at no more than 60 Hz, one 128x1 response draw meters ungraded scene color
   and, when active, the completed Bloom texture;
4. fused compose applies deband and Bloom, creative grade, LUT, halation, and
   vignette, then samples the final display response before grain, dither, and
   final quantization;
5. optional chromatic aberration, built-in spatial AA, and external final
   shaders keep their established order.

Exposure never meters OMV grading, LUT, grain, vignette, or its own prior
output, so those families cannot create a feedback loop. Automatic tone uses a
separate native/Bloom upper-tail signal; exposure's black and outlier policy
cannot suppress real lamps, signs, clouds, or Bloom highlights.
Creative exposure remains inside analytic grading before the LUT. The final
adaptive response contains only transient exposure and tone; this avoids both
double exposure and changing which colors enter the creative LUT.

## Bounded exposure metering

Every response texel repeats the same fixed, resolution-independent `4x4`
meter. Exposure clamps each log-luminance sample to `+/-2.5 EV` around the
previous adapted anchor. This winsorization bounds an isolated extreme without
discarding it: a genuine whole-screen transition still advances the anchor on
every update. The first valid frame has no historical clamp and seeds itself
from the current image. This avoids a second sampling pass, histogram texture,
random temporal sampling, and CPU readback.

Metering uses Rec. 709 luminance. Values below `1/255` are smoothly rejected
through `4/255`, and center weight falls from `1.0` toward `0.40`. A black or
otherwise invalid frame holds valid temporal state; the first invalid frame
starts neutral. Fixed sample coordinates avoid temporal noise.

The automatic exposure target is now the transient residual:

`target_ev = clamp(current_mean_log - adapted_mean_log, -range, range)`

After looking from dark ground to a bright sky, current mean is greater than
the adapted reference and the transient is positive. The reverse transition
is negative. As the adapted reference reaches the new view, the residual
returns to zero, restoring Fallout's authored baseline instead of forcing the
view toward an OMV gray key. A smooth `0.035..0.155 EV` deadband prevents tiny
camera or quantization changes from pumping exposure.

## Temporal response

Adapted log luminance uses exponential half-lives of `0.52 s` toward brighter
views and `1.05 s` toward darker views. The slower dark response models gradual
dark adaptation; neither direction is an unbounded rate or a camera cut.
Applied exposure follows the residual with a `0.14 s` half-life. This second
state prevents an abrupt camera turn from applying the full configured range
in one frame. The user's `0.10..4.0` speed scalar multiplies all adaptive rates;
the wider endpoints retain the same exponential half-life model rather than
introducing a linear snap.

Automatic tone activity rises with a `0.22 s` half-life and releases with a
`0.72 s` half-life. Fast onset protects new highlights; slower release
avoids visible curve-strength flicker as a bright source crosses the frame
edge.

All temporal math uses accumulated successful consecutive Present intervals,
with each input clamped to `1/240..1/20 s`. Response updates run every frame at
60 Hz or below and at no more than 60 updates per second above that rate. At
120 Hz, for example, one update integrates two frame intervals. Fractional
scheduling phase is retained separately from elapsed integration time, keeping
75, 90, and 144 Hz smooth without counting time twice. A failed or missing
Present, resize, disabled final color, device recreation, or other render-epoch
gap invalidates state and forces an immediate neutral seed. The first valid
image seeds its current mean with zero transient exposure and zero automatic-
tone activity, so it cannot snap to historical correction.

## Automatic tone response

The meter reconstructs the mask-independent part of the existing Bloom
composition at its fixed sample points, but its signal is independent from
exposure. Mean upper-tail occupancy rises smoothly over peaks `0.72..0.98`; a
localized clip-risk term rises over `0.94..1.10`. Their weighted combination
lets broad bright skies engage gently while preserving a prompt response to a
small lamp, sign, sun, or Bloom source. Center weighting reduces edge flashes.
The meter deliberately omits localized first-person depth attenuation: adding
that mask would require depth-neighborhood work in every response pixel, while
the unmasked estimate is conservatively safe.

The corrected curve is an independently derived, display-referred extended
Reinhard approximation. For nonnegative Rec. 709 display luminance `Y`, it
computes:

`L = Y^2.2`

`R = (1 + L / 6.25) / (1 + L)`

`scale = R^(S / 2.2)`

and multiplies every RGB channel by the same `scale`. `6.25` is white point
`2.5` squared. Strength is an exponent rather than a blend, so zero is exact
identity, one is the calibrated curve, and the expanded `1..3` region deepens
the same monotonic bounded response without extrapolating through black. This
scalar-luminance approximation avoids three per-channel gamma conversions and
preserves channel order and RGB ratios exactly.

In automatic mode, `S` is configured tone strength multiplied by a temporally
filtered activity scale from `0.70` to `1.30`. A nonzero setting therefore
remains a real mapper in an ordinary or dark view; bright content changes its
authority by only plus or minus 30 percent. At the reported strength `0.995`,
the regression requires a representative `0.80` sky value to move by at least
eight UNORM8 codes even before activity reaches its bright-view maximum. The
fixed `neutral` mode uses the same photographic equation at the configured
strength without temporal modulation.

Tone and transient exposure no longer consume the creative Color Grade master.
The final output source enable still provides the explicit family-wide bypass,
but changing creative grade strength cannot attenuate or stop the independent
Current Look features. Both modes run after analytic grade, LUT, halation, and
vignette, so the final clamp cannot erase later-created highlights.

## Response-curve performance design

Automatic mode renders a 128x1 `D3DFMT_A16B16G16R16F` response texture. Its R
lane stores a scale indexed by input luminance over `0..4`; G/B/A replicate adapted
log luminance, applied exposure EV, and tone activity. G uses a positive
sentinel only until the first non-black meter result, because valid metered log
luminance is never positive. Two textures ping-pong
because D3D9 forbids sampling a texture while rendering to it. Total payload is
2 KiB, plus driver object overhead.

The generator performs at most 4,224 texture fetches per update: 16 scene reads,
up to 16 Bloom reads, and one history read, repeated over 128 output texels.
That is an 83% reduction from 24,832 and remains independent of display
resolution. Above 60 FPS the update ceiling reduces draw and render-target
transition frequency as well. The existing transaction already establishes
the scene/history sampler states, so response drawing no longer reissues those
redundant state writes.

Full-resolution adaptive compose now computes Rec. 709 luminance, performs one
linearly filtered curve lookup, and multiplies RGB once. Gamma conversion,
extended-Reinhard division, exposure `exp2`, and strength exponentiation remain
in the 128-pixel generator. A 128-sample CPU reference sweep over the `0..4`
domain requires maximum filtered-curve error below `0.002` relative to the
analytic mapping.

Compiled `ps_3_0` ceilings are:

| Pass | Instruction ceiling | Texture opcodes |
|---|---:|---:|
| Exact legacy fused compose | 500 | 14 |
| Fixed-neutral fused compose | 530 | 14 |
| Adaptive fused compose | 515 | 15 |
| 128x1 response generator | 420 | 4 |

A separate assertion limits adaptive compose to at most 16 instructions above
the compiled legacy shader. Disabled auto exposure plus tone `off` still
selects the exact legacy bytecode and schedules no response draw. Automatic
mode retains at most 60 extra low-resolution draws per second and one extra
full-resolution texture lookup per displayed frame; this is the remaining cost
to measure in playtesting. Fixed neutral mode avoids the response draw and
texture lookup; its compose variant evaluates two scalar power operations and
one rational luminance curve per pixel within the separate compiled budget.

## D3D9 ABI, lifetime, and failure behavior

Response generation binds scene color at `s0`, previous response at point-
sampled `s1`, optional completed Bloom at `s4`, and four constant rows at
`c0..c3`. Adaptive compose binds the current response at linearly filtered
`s7`; its policy ABI remains at `c19`. Addressing, min/mag/mip filtering, and
sRGB sampling are explicit.

Capability is queried from the live D3D9 device's creation adapter and device
type, not assumed from adapter-zero HAL. Both `D3DUSAGE_RENDERTARGET` and
`D3DUSAGE_QUERY_FILTER` must succeed for FP16. Unsupported filtering/rendering,
shader creation failure, or response-target creation failure logs once and
degrades automatic tone to fixed neutral. Automatic exposure becomes a no-op;
Bloom, grade, LUT, grain, and chromatic aberration remain available. No partial
adaptive resource set is published.

Response textures are created lazily on the first active automatic draw after
the established DeferredInit boundary and are released on device loss. That
one-time transaction emits
`[FINAL_COLOR] Automatic exposure/tone response initialized (128x1 FP16)` only
after both targets exist. Steady-state draws perform no capability query,
allocation, lock, file I/O, logging, shader compilation, readback, or query
polling.

## Configuration and startup compatibility

Persisted schema-one keys remain under `[graphics.adaptive_tone]`:

| Key | Range/default | Meaning |
|---|---|---|
| `auto_exposure_enabled` | `true` | Enables transient display adaptation. |
| `exposure_range_ev` | `0..3`, `0.75` | Maximum symmetric transient EV. |
| `adaptation_speed` | `0.10..4.0`, `1.0` | Calibrated temporal-rate scalar. |
| `tone_mapper_mode` | `off`, `neutral`, `automatic` | Highlight policy. |
| `tone_mapper_strength` | `0..3`, `0.65` | Photographic curve exponent. |

Invalid floats receive finite defaults and every render-boundary lane is
clamped independently. An invalid menu mode fails closed to `off`. Range zero
is an exact automatic-exposure bypass.

The correction changes finite bounds for existing fields but adds no config
field, layout change, static owner, TLS value, mutex, worker, scanner, hook,
early publication, or admission bit. `NVSEPlugin_Load` retains the established
timing gate and adaptive timing opens at DeferredInit. Shader payload and OMV
code do change the final DLL footprint, so static checks cannot declare startup
safety. Commit `9975b2e` remains the last documented load-to-gameplay startup
baseline until a reviewed artifact passes the required BaseObjectSwapper test.

## Validation and remaining acceptance

Automated coverage includes both historical negative controls, corrected
transition signs, exact steady-state neutrality, deadband, winsorized meter
progress, independent native/Bloom highlight-tail detection, bounded
first-frame response, asymmetric convergence, 30/60/120 Hz temporal stability,
30/60/75/90/120/144/240 Hz update cadence and elapsed-time conservation, tone
rise/release, the reported `0.80`/`0.995` playtest case, independence from
creative master strength, expanded finite bounds, shipped-default UNORM8
headroom, final-stage source order, RGB-ratio preservation, filtered curve
accuracy, shader compilation, compiled instruction/sample budgets, response
memory, exact legacy bypass, live-setting sanitization, black/gap/resize
invalidation, Current Look round trips, preset exclusion, and DeferredInit
source ordering.

Static validation recorded on 2026-08-12:

- `cargo test --target i686-pc-windows-gnu -p omv`: the full suite passed;
- `cargo test --target i686-pc-windows-gnu -p libpsycho --lib`: 28 tests
  passed for the D3D9 capability-wrapper crate;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed;
- `rustfmt --edition 2024 --check` on every changed Rust source and
  `git diff --check`: passed. The repository-wide formatting check currently
  also reports unrelated, untracked shadow-module work in the shared tree.

The broader `libpsycho` command also runs pre-existing logger doctests; one
unrelated example rejects the unsuffixed `0xDEADBEEF` literal as an overflowing
`i32`. The library unit gate above is clean, and this graphics change does not
alter that logger documentation. Compilation and CPU references do not prove
image quality or frame time.

Runtime image/performance acceptance must compare `off`, `neutral`, and
`automatic` at tone strengths `0.65`, `1`, `2`, and `3` at identical camera
positions on the reported RX 6800 XT and at least one NVIDIA GPU, with native
D3D9 and DXVK when available. Capture GPU frame time as well as FPS around the
prior 120 FPS case. Test rapid turns
between noon sky and ground, deep shade and bright doors, dark interiors,
neon nights, muzzle flashes, dialogue faces, loading fades, menus, and
letterboxed views at 30, 60, 120, and uncapped rates. Confirm:

- sky transitions begin slightly brighter, ground/dark transitions slightly
  darker, and both return smoothly to the authored baseline;
- steady views do not continue drifting toward a gray key;
- neutral and automatic modes visibly reshape ordinary 0-1 sky/highlight
  values, with monotonic authority across the expanded strength range;
- lamps, sun, signs, and Bloom highlights roll off without hue rotation,
  pumping, band steps, or crushed detail;
- automatic mode logs exactly one successful 128x1 FP16 response
  initialization per device lifetime and no adaptive failure;
- the earlier 3-5 FPS loss is absent or reduced to measurement noise;
- alt-tab, resize, mode toggle, and device reset restart neutrally.

Startup acceptance requires at least three cold Proton load-to-gameplay runs
with BaseObjectSwapper installed. Logs must reach `[INIT] Deferred OMV graphics
hooks initialized`, normal gameplay, and live Presents without the known
`BaseObjectSwapper +0x4990` crash. Record artifact hashes and results before
calling the new state runtime-accepted.

## Design references

- Microsoft, "HDR Lighting" for the separation between HDR scene work and
  display mapping: <https://learn.microsoft.com/en-us/windows/win32/direct3d9/hdr-lighting>
- Unreal Engine 4.27, "Auto Exposure (Eye Adaptation)" for robust metering and
  spatial weighting concepts: <https://dev.epicgames.com/documentation/en-us/unreal-engine/auto-exposure-eye-adaptation?application_version=4.27>
- Reinhard et al., "Photographic Tone Reproduction for Digital Images" for
  log-average luminance and monotonic global response foundations:
  <https://www-old.cs.utah.edu/docs/techreports/2002/pdf/UUCS-02-001.pdf>
- NVIDIA GPU Gems 2, Chapter 24, for moving stable nonlinear color work into a
  filtered lookup table: <https://developer.nvidia.com/gpugems/gpugems2/part-iii-high-quality-rendering/chapter-24-using-lookup-tables-accelerate-color>
- Khronos PBR Neutral, for a bounded, smooth, hue-stable display shoulder:
  <https://github.com/KhronosGroup/ToneMapping/blob/main/PBR_Neutral/README.md>
- ACES output transforms, for the separation and ordering of creative color
  work and the final display rendering transform:
  <https://docs.acescentral.com/system-components/output-transforms/>
- Pr0bability, "Vanilla Plus Tonemapper," for the native
  `ISHDRBLENDINSHADER*` placement and extended-Reinhard comparison:
  <https://github.com/pr0bability/fnv-vanilla-plus-tonemapper/blob/main/src/shaders/TonemapperTemplate.hlsl>
- The corresponding mod page documents the 1.1.2 curve and optional sky
  compensation behavior:
  <https://www.nexusmods.com/newvegas/mods/91500>
- Timothy Lottes, "Advanced Techniques and Optimization of HDR Color
  Pipelines" for stable exposure anchors and bounded display response:
  <https://gpuopen.com/wp-content/uploads/2016/03/GdcVdrLottes.pdf>

NVR comparison sources remain read-only under `.research/`. They confirm that
NVR meters luminance before its own tone-mapping stage. OMV cannot copy that
scene-referred placement because its established compatible hook is post-native;
the corrected transient model explicitly respects that difference.

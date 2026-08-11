# OMV automatic exposure and adaptive tone mapping

Status: implemented on 2026-08-11. Deterministic CPU references, shader
compilation, compiled bytecode budgets, configuration round trips, preset-shape
checks, and the supported i686 release build are the static acceptance gates.
Runtime visual, frame-rate, device-reset, and pre-`DeferredInit` compatibility
acceptance remain playtest requirements; this document does not claim those
observations before they are supplied.

## Purpose and visible behavior

OMV adds restrained display adaptation to its existing final-color stage. The
goal is an eye-like response when a camera moves between bright and dark views,
plus gentle highlight shaping that makes lighting and weather changes feel more
photographic. It is deliberately slow enough to avoid pumping and fast enough
to settle during ordinary camera movement.

This is not a replacement for Fallout New Vegas' native HDR implementation.
The established final-image hook runs after native image-space processing, so
OMV receives a clamped, display-referred image. The meter and curve operate on
that remaining display range and cannot recover native scene radiance that was
already clipped. No new engine address, layout, hook, or native shader ABI was
inferred for this feature.

The workbench exposes two editors over the existing `Final Color Pipeline`:

- `Auto Exposure`: enable, symmetric correction range, and adaptation speed;
- `Tone Mapping`: off, fixed neutral, or automatic mode and curve strength.

Shipped defaults enable automatic exposure with a `0.75 EV` range and speed
`1.0`. Tone mapping defaults to `automatic` at strength `0.65`. The controls
are part of Current Look, but are intentionally excluded from shareable visual
presets. Applying a preset therefore changes the creative look without changing
the player's camera/display adaptation preference.

## Ownership and ordering

- `omv/src/config.rs` owns `AdaptiveToneConfig`, `ToneMapperMode`, finite
  bounds, TOML spelling, and Current Look persistence.
- `omv/src/shaders.rs` projects those values into the fused final-color menu
  source and synchronizes live edits back to non-preset configuration.
- `omv/src/runtime.rs` owns the two virtual editors and reuses the existing
  production Present clock for frame time and continuity.
- `omv/src/effects/blooming_hdr.rs` owns capability checks, shader variants,
  one-pixel history resources, explicit D3D9 bindings, and fail-soft selection.
- `omv/shaders/embedded/adaptive_tone.hlsl` owns metering and temporal
  adaptation. `bloom_hdr_compose.hlsl` owns exposure application and the
  neutral display shoulder.

The fixed final-image order is:

1. native image-space and earlier OMV stages produce display-referred color;
2. the one-pixel meter reads that ungraded scene when adaptation is required;
3. Bloom extraction/blur runs when Bloom or halation requires it;
4. fused compose applies automatic exposure, neutral tone mapping, creative
   grading/LUT/halation/vignette/grain, and final quantization;
5. optional chromatic aberration, built-in spatial AA, and external final
   shaders retain their established order.

The meter is before OMV grading, LUTs, Bloom composition, grain, and vignette.
Those effects therefore cannot feed their own result back into exposure on the
next frame.

## Metering contract

One `1x1` draw reads a fixed `8x8` grid: exactly 64 scene samples and one
previous-history sample. Normalized, fixed sample coordinates avoid temporal
sample noise and make cost independent of output resolution. Center weighting
falls from `1.0` toward `0.35`, limiting the influence of a bright object near
the screen edge without making the center a brittle spot meter.

The meter uses Rec. 709 luminance and a weighted log average. Values below
`1/255` are rejected smoothly through `4/255`, so letterboxing, menus, black
loading frames, and large empty borders do not force exposure open. It also
derives bounded log-luminance variance and highlight occupancy. These signals
change only the parameters of one neutral shoulder; they do not switch curve
families, white balance, LUTs, or creative color controls.

The display key is `0.36`. Target exposure is
`clamp(log2(0.36) - mean_log_luminance, -range, range)`. The configured range
is `0..1.5 EV`; range zero is an exact automatic-exposure work bypass.

## Temporal response

History is two ping-pong `1x1 D3DFMT_A16B16G16R16F` render-target textures.
The previous texture is never the current render target, satisfying D3D9's
read/write feedback prohibition. There is no CPU readback, query, staging
surface, routine allocation, lock, or file I/O.

Exposure uses a hybrid response. More than `0.50 EV` from target, it advances
at a bounded rate. Within that distance, it uses an exponential tail whose
derivative matches the outer rate at the transition, so it cannot overshoot or
jitter around the target. Bright-scene closure is `0.90 EV/s`; dark-scene
opening is `0.45 EV/s`. The user's `0.25..2.0` speed scalar multiplies both.
This asymmetry protects the eye from abrupt brightness increases while still
recovering highlights promptly.

Automatic shoulder start and crosstalk use an `0.85 s` half-life. All temporal
math consumes the prior successful consecutive Present interval, clamped to
`1/240..1/20 s`, so response is stable across ordinary frame rates and a hitch
cannot produce a large jump. A missing Present callback, failed Present,
resolution change, disabled pipeline, or device recreation invalidates
continuity. The first valid frame seeds neutral exposure and neutral shoulder
parameters; it never snaps directly to the newly measured target. A fully
black frame holds valid history, or remains neutral if no valid history exists.

## Neutral tone curve

The curve works from peak RGB rather than mapping channels independently. For
peak `p`, shoulder start `s`, overage `o = max(p - s, 0)`, and remaining range
`r = 1 - s`, the compressed peak is:

`p' = p - o + o*r/(r + o)`

This branch-free rational curve is identity with unit derivative at its start,
is monotonic, and approaches display white. Scaling all channels by `p'/p`
preserves RGB ratios. A separately bounded `0..0.15` near-white crosstalk then
moves extreme colored highlights slightly toward their compressed peak; it
cannot reorder channels or create an unrelated hue.

Fixed mode uses shoulder `0.76` and crosstalk `0.05`. Automatic mode moves the
shoulder within `0.82..0.66` and crosstalk within `0.03..0.10` according to the
smoothed highlight/contrast signal. Mode changes alter only these small
parameters and share the same temporal response.

## Configuration and compatibility

Persisted keys live under `[graphics.adaptive_tone]`:

| Key | Range/default | Meaning |
|---|---|---|
| `auto_exposure_enabled` | `true` | Enables metered exposure. |
| `exposure_range_ev` | `0..1.5`, default `0.75` | Symmetric correction limit. |
| `adaptation_speed` | `0.25..2.0`, default `1.0` | Calibrated-rate scalar. |
| `tone_mapper_mode` | `off`, `neutral`, `automatic` | Curve policy. |
| `tone_mapper_strength` | `0..1`, default `0.65` | Curve blend. |

The fields are appended to top-level graphics configuration, not
`EmbeddedEffectsConfig`. The released schema remains `1`; preset settings,
manifest, migration rules, and built-in preset payload remain unchanged.
Legacy working configurations without the table receive shipped defaults.
Invalid floats are replaced with finite defaults and every render-boundary
value is clamped independently. An invalid menu mode fails closed to `off`.

The pre-`DeferredInit` contract remains gated. `NVSEPlugin_Load` retains the
old DOF-only Present-time publication. Adaptive timing is enabled at
`DeferredInit`, immediately before resident render hooks can become reachable,
and menu changes update only the existing atomic gate. The feature adds no
static owner, TLS value, mutex, worker, scanner, hook, or early world-pipeline
publication. Because configuration layout and background shader payload did
change, BaseObjectSwapper load-to-gameplay playtesting is still mandatory under
`graphics_fnv_atmosphere_startup_crash_errata.md`.

## D3D9 ABI, lifetime, and failure behavior

Meter bindings are scene color `s0`, prior history `s1`, and two constant rows
at `c0..c1`. Adaptive compose adds current history at point-sampled `s7` and
adaptive policy at `c19`; every sampler address/filter/sRGB state is explicit.
The fixed mode uses a specialized compose shader with no history sample.

Both history textures are created lazily with the final-color effect and are
released on device loss. Their texel payload is 16 bytes total, plus normal
D3D9 object/driver overhead. FP16 render-target support is checked once at
effect creation. Unsupported FP16, shader creation failure, or one-pixel target
creation failure logs once and degrades automatic tone mapping to the fixed
neutral curve. Automatic exposure alone becomes a no-op; Bloom, grading, LUT,
grain, and chromatic aberration remain available. No partial adaptive resource
set is published.

## Performance contract

Disabled auto exposure plus tone mode `off` selects the raw legacy compose
bytecode and schedules no meter draw. Fixed-neutral mode adds only curve math
to the existing full-resolution compose. Automatic exposure or automatic tone
adds one `1x1` draw with 65 executed texture reads and one point-sampled history
read in the existing full-resolution compose. It never adds another
full-resolution pass or scene copy.

Compiled `ps_3_0` ceilings are:

| Pass | Instruction ceiling | Texture opcodes |
|---|---:|---:|
| Legacy fused compose | 500 | 14 |
| Fixed-neutral fused compose | 530 | 14 |
| Adaptive fused compose | 560 | 15 |
| One-pixel meter | 240 | 2 |

The meter's loop executes 64 scene reads even though compiled bytecode contains
one looped scene texture opcode; tests assert both facts separately. With the
shipped Bloom, grade, and chromatic settings, automatic mode changes the
existing five-effect-draw plan to six draws, but the added draw covers one
pixel. Disabling adaptation restores the previous plan exactly.

## Static validation and runtime acceptance

Repository tests cover shader compilation for all three compose variants and
the meter, bytecode budgets, fixed sample count, no derivatives, alpha and
register ABI, exact disabled/static/adaptive work plans, finite render-boundary
sanitization, frame-rate invariance at 30/60/120 Hz, asymmetric convergence,
no overshoot, black-frame history hold, neutral first frame, tone half-life,
monotonic curve output, RGB-ratio preservation, menu synchronization, Current
Look round trips, preset exclusion, DeferredInit source ordering, and Present
continuity gaps.

Static validation recorded on 2026-08-11:

- `cargo test --target i686-pc-windows-gnu -p omv -- --quiet`: 477 tests
  passed.
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed.
- `cargo fmt -p omv -- --check` and `git diff --check`: passed.

These results prove the repository-local contracts and supported release build;
they do not replace the GPU and startup playtests below.

Runtime acceptance must compare `off`, `neutral`, and `automatic` at the same
camera positions and capture FPS/frame-time on both the reported RX 6800 XT and
at least one NVIDIA GPU, with native D3D9 and DXVK when available. Test rapid
camera turns between noon sun, deep shade, dark interiors, bright doors/windows,
neon nights, muzzle flashes, dialogue faces, loading fades, menus, and
letterboxed views. Confirm no brightness pumping, flash-induced opening,
single-frame enable jump, hue inversion, crushed signs, or distracting slow
color drift. Repeat across 30, 60, 120, and uncapped frame rates, then after
alt-tab, resolution change, and device reset.

Startup acceptance requires at least three cold load-to-gameplay runs with
BaseObjectSwapper installed, reaching `[INIT] Deferred OMV graphics hooks
initialized` and normal gameplay. Until those observations and the cross-vendor
performance comparison are supplied, the implementation is statically
validated but not runtime-accepted.

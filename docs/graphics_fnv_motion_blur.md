# FNV motion blur

## Status and scope

OMV owns a depth-aware camera motion-blur pass for Fallout: New Vegas. It
reconstructs screen motion from consecutive camera transforms and the current
resolved depth. It supports camera rotation, translation parallax, projection
changes, infinitely distant sky rotation, and an independent first-person
camera without allocating a velocity buffer or color history.

The effect deliberately does not claim per-object motion. OMV has no proven
engine velocity buffer or previous skeletal/object transform stream at this
render boundary. Independently animated characters, foliage, particles, and
water therefore receive camera motion only. Adding object motion is separate
engine research and is not a safe extension of this pass.

Source ownership is:

- `omv/src/config.rs`: persisted values, defaults, and finite bounds;
- `omv/src/shaders.rs`: in-game menu schema, ordering, and round-trip sync;
- `omv/src/runtime.rs`: phase preflight, source ordering, color-copy ownership,
  shader lifecycle, device loss, and draw scheduling;
- `omv/src/effects/motion_blur.rs`: temporal camera ownership, cut rejection,
  CPU work preflight, shader preparation, D3D9 state, and the CPU reference
  tests;
- `omv/shaders/embedded/motion_blur.hlsl`: depth reconstruction, layer
  classification, exposure sampling, and edge rejection.

## User-visible behavior and controls

The shipped profile is enabled and uses a seven-tap, 360-degree trailing
exposure with a 36-pixel safety cap. A 0.15-pixel activation threshold keeps
slow pans readable, while 20% independent first-person strength gives weapons
a restrained trail. Users who prefer a sharp presentation can disable the
effect with zero effect-specific GPU work.

| Control | Range/default | Contract |
|---|---:|---|
| `enabled` | `true` | Master switch. Disabled performs no preparation, allocation, copy, or draw for this effect. |
| `quality` | `performance`, `high`, `ultra`; `high` | Selects fixed 5, 7, or 9-tap production shader variants. Edge, cut, sky, and layer logic is identical in every tier. |
| `shutter_angle` | `0..360`; `360` | Fraction of the current-to-previous frame interval integrated by the shutter. `0` disables all effect work, `180` uses half the interval, and `360` uses the complete interval. |
| `max_blur_pixels` | `0..48`; `36` | Hard output-pixel bound on the complete exposure path. `0` is a no-work configuration. |
| `minimum_velocity_pixels` | `0..2`; `0.15` | CPU phase-skip threshold. The shader uses a smooth activation above it to prevent a visible on/off step. |
| `first_person_strength` | `0..1`; `0.2` | Multiplier for the independent first-person camera path. Zero preserves weapon color while retaining layer isolation. |

Deserialization and menu synchronization preserve exactly the same bounds and
choice mapping. Non-finite persisted floats recover to their documented
defaults before rendering. Any config change primes a new camera pair so the
first frame cannot combine different exposure settings.

## Native phase and ordering

The supported executable is `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, image base `0x00400000`, size `16,084,808`, timestamp
`0x4E0D50ED`.

OMV uses the established outer
`ImageSpaceManager::ProcessImageSpaceShaders @ 0x00B55AC0` hook. Motion blur
has the fixed `scene_post_image_space` phase:

1. native image-space processing;
2. OMV depth of field, when applicable;
3. OMV motion blur;
4. final Bloom/halation and color grading;
5. chromatic aberration and spatial anti-aliasing;
6. loose final-image shaders and later UI ownership.

This placement lets the shutter integrate the visibly focused scene while
keeping final grading, AA, and UI stable. It does not patch native image-space,
depth resolve, first-person rendering, or UI callsites. The established phase
and depth evidence remains in:

- `analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`;
- `docs/graphics_fnv_aa_performance_research.md`.

No new native address, layout, or ownership inference was introduced for this
feature.

## Inputs, output, and shader ABI

The pass is `ps_3_0`, entry point `Main`, on one full-resolution D3D9
triangle strip. Its compile-time `MOTION_BLUR_SAMPLES` value is 5, 7, or 9.

| Register | Input |
|---|---|
| `s0` | Point-copied current scene color, sampled linearly and clamped. |
| `s1` | Current owned world-depth resolve, sampled at point-filtered texel centers. |
| `s2` | Optional current owned first-person-depth resolve, sampled at point-filtered texel centers. |
| `c0` | Output width, height, and reciprocal dimensions. |
| `c1` | Shutter fraction, maximum path pixels, minimum velocity, and first-person strength. |
| `c2` | World/first-person reversed-depth flags and first-person input/pair availability. |
| `c3..c4` | Current world frustum and near/far planes. |
| `c5..c7` | Current-world to previous-world view transform rows. |
| `c8..c9` | Previous world frustum and near/far planes. |
| `c10..c11` | Current first-person frustum and near/far planes. |
| `c12..c14` | Current-first-person to previous-first-person view transform rows. |
| `c15..c16` | Previous first-person frustum and near/far planes. |

The output replaces RGB on the current phase render target and preserves the
current alpha exactly. Dimensions and format match that target. The shared
phase color texture has the same dimensions and format and receives a
point-filtered `StretchRect`; this also supplies the readable non-MSAA source
when the phase target is multisampled. The pass writes with sRGB decode/write
disabled, matching OMV's established numeric scene-target space. It makes no
unsupported claim that this legacy target is photometrically linear.

The pass explicitly sets its vertex shader/FVF, triangle topology, viewport,
RT0 and unused MRTs, depth-stencil surface, depth/stencil tests and writes,
culling, scissor, blend, alpha test/coverage, color mask, multisample state,
sRGB state, and every used sampler state. The outer phase state block restores
native state. Inputs are unbound after drawing, so the next target copy cannot
feed back through a still-bound texture.

## Coordinate, depth, and reconstruction contract

The fullscreen quad uses D3D9's `-0.5` pixel-center positions. Every point
depth lookup first maps the requested UV to the actual source texel center.
Color remains linearly sampled along the exposure path. No derivative,
implicit-LOD, noise, or frame-varying sample rotation is used, so the
two-triangle diagonal and subpixel motion cannot change the reconstruction
equations.

World and first-person depth use their independently captured near/far and
standard/reversed convention. Geometry must lie strictly between normalized
depth endpoints. Standard-depth clear sky is `1`; reversed-depth clear sky is
`0`. The opposite endpoint and non-geometric values preserve current color.
The linearization equations are tested after D16- and D24-like quantization.

For geometry, the current view ray is multiplied by linear depth and transformed
into the previous camera basis. Projection through the previous frustum yields
the current-to-previous screen path. The path is multiplied by
`shutter_angle / 360`, bounded by `max_blur_pixels`, softly activated above
`minimum_velocity_pixels`, and clipped to valid texel-center viewport bounds.

Sky uses the same current/previous rotation but omits translation. Walking
therefore cannot smear infinitely distant sky; camera rotation still can.
First-person pixels use only the first-person camera pair. A missing or stale
first-person pair never falls back to world motion.

## Exposure filter and edge protection

Samples run from the current pixel toward its previous-frame position. This is
a causal trailing shutter, rather than a symmetric blur that invents a leading
trail without a future frame. Trapezoidal half weights on both exposure
endpoints approximate a uniform interval without over-weighting the present or
oldest sample. All accepted weights are normalized, and the current sample is
always retained, so rejected taps cannot darken an edge.

Each tap classifies first-person versus world before accepting color:

- first-person and world samples never cross;
- sky and geometry never cross;
- invalid endpoints never contribute;
- geometry compares relative linear depth, which remains meaningful over
  FNV's large near/far ratio;
- the relative tolerance begins at 2.5% and grows only modestly with a long
  shutter path, preserving shallow/grazing surfaces while rejecting true
  foreground/background discontinuities.

The color sample is deliberately still bilinear. A subpixel sample at a
silhouette can contain the bilinear footprint of both sides, but later
wrong-layer taps are rejected. Point-sampling color would remove that footprint
at the cost of visible stepping and banding, especially in the five-tap tier.
The deterministic thin-feature negative control verifies that the protected
filter retains the foreground while a naive gather averages it away.

## Temporal ownership and failure behavior

`MotionBlurTemporalState` is the sole previous-camera owner. A pair is usable
only when:

- both cameras and transforms are finite and valid;
- capture epochs are consecutive;
- target dimensions and configuration are unchanged;
- camera forward vectors remain at least `0.5` aligned;
- view-space translation remains no greater than the smaller of 25% of the
  two cameras' far planes and 4096 units.

The first frame, resize, config change, epoch gap, device reset, camera cut,
missing world depth, or invalid projection primes current state and performs no
blur. Intermittent first-person input invalidates only its own pair. The next
consecutive valid frame resumes normally.

World motion is defined on the fixed, unjittered output grid. When TAA has
jittered the depth-producing projection, OMV uses the restored output camera
for current/previous motion, following the already proven TAA invariant that a
stationary camera must produce a null vector. Depth remains the current
resolved geometric distance. First-person uses its independent live projection.

Shader source is compiled off the render thread and cached by source/family
hash. The render thread observes readiness through an atomic flag, takes the
published bytecode with `try_lock` only during one-time D3D shader creation, and
never compiles or performs file I/O in a render callback. Until bytecode is
ready, phase preflight rejects motion-blur-only work. Compilation/resource
failure leaves the native scene intact and follows the existing bounded OMV
error logging path.

## Performance contract

An accepted moving frame performs one full-resolution scene-color copy and one
full-resolution draw. There are no half-resolution setup passes, velocity
targets, tile buffers, color histories, per-frame GPU allocations, or shader
permutations beyond the three cached quality objects.

| Tier | Taps | Maximum texture fetches per output pixel |
|---|---:|---:|
| Performance | 5 | 15 |
| High | 7 | 21 |
| Ultra | 9 | 27 |

The maximum assumes world geometry while first-person depth is also available:
one color, first-person-depth, and world-depth lookup per shutter position.
Sky and first-person pixels execute fewer depth lookups. Each compiled variant
is constrained to at most 512 static shader opcodes, three samplers, seventeen
float constant registers, one interpolator, and a uniform compile-time-bounded
loop. The loop avoids expanding the substantial edge/layer rejection body in
the D3D9 instruction cache.

Persistent feature-specific GPU memory is three pixel-shader objects. A moving
frame also needs the existing scene-post full-resolution color-copy texture,
shared with other effects in that phase. CPU preflight evaluates a fixed 15
world projections and, when available, 15 first-person projections at
corners/center and representative near/far/sky depths. It performs no
allocation, file I/O, logging, or lock acquisition.

Disabled, zero-shutter, zero-cap, missing-depth, first, cut, stationary, and
sub-threshold frames are rejected before state-block capture and phase
color-target allocation when motion blur is the only applicable effect.
Enabling another scene-post effect does not make motion blur perform its copy
or draw on a rejected frame.

These are static work bounds, not measured frame-time or FPS claims.

## Validation and runtime acceptance

Automated OMV coverage proves:

- all 5/7/9-tap production variants compile as `ps_3_0` within instruction and
  texture-work budgets;
- the sampler/constant ABI, explicit LOD, alpha preservation, and prohibited
  history/derivative contract;
- finite stationary, translation-parallax, sky-translation, and subpixel
  rotation reprojection;
- first frame, epoch gap, cut, invalid camera, resize, config change, disabled,
  zero, and missing-input rejection;
- constant fields, positive/negative borders, odd/even half-pixel placement,
  gradients, steep discontinuities, thin features, sky, invalid values, and
  world/first-person isolation;
- standard/reversed depth after D16- and D24-like quantization;
- a naive depth-unaware negative control produces silhouette color bleed while
  the production reference rejects it;
- menu bounds, persistence, ordering, and exact round-trip synchronization.

Required final validation commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Ordinary playtesting remains necessary for perceptual acceptance. Test a slow
subpixel pan, a rapid mouse turn, lateral motion past near posts and distant
terrain, bright sky/building silhouettes, foliage and water, first-person
weapons at strengths 0 and 1, dialogue/VATS transitions, loading/teleport,
resolution reset, and all three tiers. Acceptance requires stable trailing
motion with no leading double image, fullscreen fill, diagonal seam, bands,
wall lines, speckles, crawling, flicker, cut ghost, sky translation smear,
foreground halo, or first-person/world leak.

## Evidence classification

Proven repository facts are the native phase, current depth/camera ownership,
fixed-output TAA camera contract, source ordering, D3D resource lifecycle, and
all automated properties listed above. The choice of 5/7/9 samples, 2.5-10%
adaptive depth tolerance, 4096-unit absolute cut cap, and default slider values
are engineering decisions supported by deterministic negative controls and
bounded-work analysis, not facts recovered from the executable.

No in-game capture or GPU timing result is claimed here. Perceptual smoothness,
comfort, compatibility with a user's complete mod stack, and actual low-end GPU
frame time remain runtime observations to establish through the normal
playtest matrix.

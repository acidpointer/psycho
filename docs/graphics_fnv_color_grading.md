# OMV final color grading and bundled LUT contract

Status: implemented on 2026-07-20; static validation passes, ordinary in-game
visual acceptance remains.

## Purpose and visible behavior

OMV owns a single final-color pipeline for atmospheric Bloom and the new
`Color Grade and Film` effect. Color grading can run alone in one full-resolution
draw, or share Bloom's existing compose draw. Enabling both therefore does not
add a second full-resolution composition draw or another scene-color copy.

The grade provides:

- bounded exposure, contrast, saturation, gamut-clamped vibrance,
  temperature/tint, black fade, and highlight rolloff;
- one selectable bundled 32x32x32 LUT with a continuous strength control;
- native day/night/interior response which smoothly reduces the LUT influence
  where a strong exterior-day look would be intrusive;
- flat-region debanding with output dither;
- optional luminance-weighted grain, vignette, and Bloom-derived halation;
- a before/after split for ordinary visual tuning.

`enabled = false` disables the feature. `strength = 0` is also a no-op and skips
final-color effect creation, the grade-only scene copy, and drawing. The shared
phase-copy target may already exist for other final effects. The Neutral LUT is
an identity shader bypass, and LUT strength zero skips its visual contribution.
The shader preserves source alpha in production and debug output.

## Ownership, phase, and ordering

Configuration is owned by
`graphics.embedded_effects.color_grade` in `Data/NVSE/plugins/omv/omv.toml`.
`omv/src/config.rs` owns serialization and bounds, `omv/src/shaders.rs` owns the
menu source/options, `omv/src/runtime.rs` owns ordering, and
`omv/src/effects/blooming_hdr.rs` plus
`omv/shaders/embedded/bloom_hdr_compose.hlsl` own resources and image math.

The fixed phase is `final_image_space`. The outer
`ImageSpaceManager::ProcessImageSpaceShaders @ 0x00B55AC0` hook calls the
original function first, then OMV's scene-post phase, then final-image phase.
Within the final phase the built-in order is Bloom, Color Grade, spatial AA,
then loose external shaders. Bloom and Color Grade are detected as one logical
pipeline and drawn once at their first position. This gives the following
observable order:

1. vanilla image-space and OMV scene-post work;
2. Bloom extraction/blur when enabled;
3. one final Bloom/color compose and grade;
4. enabled built-in spatial AA;
5. loose external final-image shaders.

The final source is the current backbuffer captured immediately before the
logical pipeline. It includes the image already produced by vanilla
image-space processing. No depth, normal, velocity, history, or world-color
texture is required by grade-only rendering. Bloom may use first-person depth
to suppress weapon/hand glow, as before. Later engine overlays remain owned by
their native ordering; this effect does not introduce a HUD mask or move a
world-only effect across the first-person/UI boundary.

The fixed address and phase statements apply to the supported
`fnv_reverse/FalloutNV.exe`: SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`, PE32
x86, image base `0x00400000`, file size `16,084,808`, timestamp `0x4E0D50ED`.
The established static evidence is
`analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt` and
`analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`.
It proves the `0x00876136 -> 0x00B55AC0` outer call, vanilla end-of-frame
effects inside `0x00B55AC0`, and first-person rendering before that owner. A
unit-tested dispatcher enforces `scene_pre -> vanilla -> scene_post -> final`
for the outer call and vanilla-only handling for nested calls. The executable
facts are static proof; the absence of a conflicting runtime detour from
another loaded mod remains a compatibility observation.

## Color and LUT contract

The final source is an LDR display-referred code-value buffer. OMV does not
claim that its transfer function is linear or reapply sRGB conversion:
`D3DSAMP_SRGBTEXTURE` and `D3DRS_SRGBWRITEENABLE` are explicitly disabled.
Analytic grading and LUT input/output operate on finite `0..1` code values.
This avoids double-tonemapping Fallout's existing image-space result. Adaptive
exposure, screen-average luminance, ACES/Reinhard replacement tonemapping, and
local-contrast operators are intentionally absent, so the grade cannot pump
when the camera crosses a bright object.

The built-in LUTs are original OMV recipes, not copied GShade textures:

| Index | Name | Intent |
|---:|---|---|
| 0 | Neutral | Exact identity control and compatibility fallback. |
| 1 | Mojave Natural | Subtle warm daylight, cool shadow separation, restrained contrast. |
| 2 | Dusty Western | Warm, lower-saturation western palette with dry highlights. |
| 3 | Bleached Wasteland | Raised blacks, firmer contrast, muted post-apocalyptic color. |
| 4 | Neon Nights | Cool/magenta shadow separation and stronger chroma for Strip nights. |

All five recipes are generated once from `generate_builtin_lut_pack` while the
screen runtime is constructed, before normal rendering. They are packed into
the OMV binary as project-owned behavior and uploaded on the first available
D3D9 device. There is no runtime LUT file read, GShade asset, third-party image,
or attribution dependency. The recipes can be redistributed with OMV under
the same terms chosen for the project itself; this repository currently has no
root license file, so this document does not claim a broader standalone asset
license.

Each LUT is a managed `D3DFMT_A8R8G8B8` 1024x32 texture representing a 32-cube.
Red advances within a slice, blue selects the horizontal slice, and green
selects the row. The shader uses hardware bilinear filtering inside the red/
green plane and two explicit blue-slice samples for trilinear interpolation.
Addressing is clamped and mip filtering is disabled. An invalid preset index
falls back to Neutral at both config-load and render boundaries.

Native environment response never examines rendered pixels. When the exterior
contract is known, the effective LUT strength multiplier is `0.70` indoors and
`lerp(0.78, 1.0, daylight)` outdoors. The configured
`environment_response` blends between no adjustment and that multiplier.
Unknown exterior state fails open at `1.0`; this avoids an arbitrary visual
change when native state is unavailable.

## Shader and D3D ABI

The production pixel shader is `Main`, target `ps_3_0`.

| Binding | Meaning |
|---|---|
| `s0` | Full-resolution scene-color copy, clamped linear sampling. |
| `s2` | Optional point-sampled first-person depth for Bloom suppression. |
| `s4` | Quarter-resolution blurred Bloom, or a managed black 1x1 texture. |
| `s5` | Selected flattened 32-cube LUT, clamped linear sampling. |
| `c0..c2` | Screen, frame, and camera data inherited from the Bloom pipeline. |
| `c3..c5` | Bloom controls; explicit zeros when Bloom is disabled. |
| `c9` | Bloom target texel/dimension data or neutral 1x1 values. |
| `c10..c14` | Grade, film, LUT, environment, debug, and enable constants. |

The fullscreen topology is a four-vertex `D3DPT_TRIANGLESTRIP` using the D3D9
half-pixel positions `(-0.5, -0.5)` through `(width-0.5, height-0.5)`. The pass
sets its viewport to the exact target and does not use derivatives, so the
shared triangle diagonal cannot alter reconstruction.

Every dependent state is explicit: vertex shader is cleared; FVF and culling
are set; alpha blend/test, depth, depth writes, and stencil are disabled;
scissor is disabled; the multisample mask is all bits; vendor alpha-to-coverage
is neutralized; sRGB read/write is disabled; all color channels are enabled;
depth-stencil and unused MRTs are unbound; and sampler address/filter/mip state
is set for `s0..s5`. The outer all-state block restores native state on success
or failure. Render-target inputs are cleared before a target becomes writable,
preventing feedback.

## Debanding and film finish

Debanding takes the center and four cross neighbors from the final source. It
averages only where the maximum local RGB delta remains below the fixed
flat-region threshold; edges smoothly drive the weight to zero. A strength-zero
negative control is exact identity. Dither is sub-one-code-value golden noise,
and grain is separately luminance weighted. Neither has temporal history or an
unbounded kernel. Halation reuses the already blurred Bloom contribution and
adds no pass or texture. When Bloom is disabled, halation receives black and is
therefore a no-op.

## Lifetime, failure, and performance

CPU LUT generation is one-time startup work: five cubes total 163,840 ARGB
texels or 655,360 bytes, plus vector metadata. GPU LUTs and the neutral Bloom
texture use the managed pool. Quarter-resolution Bloom render targets remain
default-pool resources and are recreated on size/format changes or device
reset. A new device releases and recreates the effect; the staged CPU LUT pack
is retained. Shader, texture, or target creation failure returns through the
existing final-phase failure path and the captured D3D state is restored.

Static work budgets:

| Mode | Scene copy | Draws | Resolution | Worst compiled compose work |
|---|---:|---:|---|---|
| Grade only | 1 | 1 | one full-resolution compose | at most 500 instructions and 13 texture opcodes with all dynamic families present |
| Bloom only | 1 | 4 | three quarter-resolution + one full-resolution | same shared compose; grade branch disabled |
| Bloom + grade | 1 | 4 | three quarter-resolution + one full-resolution | same as grade/Bloom compose; no extra grade draw |

The 13-opcode ceiling includes five scene samples for debanding, two LUT
samples, Bloom, and the five optional first-person-depth taps present in the
compiled dynamic shader. Runtime branches suppress unavailable families, but
the static budget does not assume driver branch elimination. There are no
routine allocations, file reads, locks, logs, or shader compilation requests
in the unchanged-size effect draw path. Target allocation is limited to first
use and size/format changes. Per-frame CPU option parsing is a fixed bounded
scan over the embedded source.

## Validation and remaining acceptance

Automated tests compile every embedded Bloom/final-color entry point. They cap
extract at 220 instructions/10 texture opcodes, blur at 80/9, and compose at
500/13. The CPU reference equations are paired with assertions for their exact
HLSL expressions, so changing shader math without updating its oracle rejects
the suite. Coverage includes:

- exposure, contrast/pivot, saturation, adaptive vibrance,
  temperature/tint, black fade, highlight shoulder monotonicity, master
  strength, vignette, Bloom-derived halation, grain and dither amplitude;
- Neutral identity, invalid-preset fallback, zero-strength/disabled skip
  behavior, and the Bloom-disabled negative control for the fused compose;
- all LUT output bounds, distinctness, monotonic neutral ramps, interpolation,
  blue-slice continuity, odd/even reference buffers, and finite output;
- constant-region and linear-gradient deband identity, an 8-bit banding
  negative control, hard-edge and thin-feature preservation, corners,
  odd/even dimensions, and strength-zero identity;
- exterior day/night/interior/unknown response and response-zero isolation;
- exact CPU-to-HLSL `c10..c14`/`s5` ABI, source alpha preservation, debug-split
  pre-grade ownership, absence of derivatives/screen adaptation, and explicit
  D3D state ownership;
- the real runtime work planner for disabled, grade-only, Bloom-only, and fused
  modes; target sizing; LUT byte count/shape; startup bytecode validity; no
  compilation, LUT generation, allocation, file I/O, or locks in the effect
  draw method; and staged CPU data survival across device-resource release;
- every menu option and LUT label, every config bound, menu sync, serde and
  disk-document persistence, final-phase order, scene-input requirements, the
  supported engine address/ABI, and outer-versus-nested engine callback order.

The supported `i686-pc-windows-gnu` OMV test suite and release build are the
static release gates. These close all deterministic repository, shader,
configuration, ABI, phase-planning, resource-ownership, and budget contracts.
An ordinary Fallout NV playtest must still inspect each
look at noon, sunset, night, representative interiors, dialogue/iron sights,
menus, and 16:9/ultrawide resolutions. It should confirm that the default is
subtle, the debug split is stable, debanding does not soften real edges, grain
does not crawl objectionably, and spatial AA/external final shaders retain the
documented order. Static tests cannot establish artistic preference or actual
frame time.

Validation evidence on 2026-07-20:

- `cargo test --target i686-pc-windows-gnu -p omv`: 212 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed without
  warnings;
- `cargo fmt -p omv -- --check` and `git diff --check`: passed;
- no generated shader-cache or LUT artifact exists under `omv/Data` or `Data`.

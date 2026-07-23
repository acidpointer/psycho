# OMV final color, external LUT, Bloom, and chromatic contract

Status: implemented on 2026-07-21; film grain completely replaced and creative
ranges revised on 2026-07-23. Deterministic repository, parser, menu,
resource-planning, CPU image-reference, shader compilation, bytecode-budget,
and packaging coverage is complete. Ordinary in-game visual acceptance
remains.

## Purpose and visible behavior

OMV owns a display-referred finishing stack after Fallout New Vegas' native
image-space work. `Bloom and HDR` and `Color Grade and Film` share the existing
final-color pipeline. The color effect has a master switch and strength plus an
independent switch for every family:

- analytic color grading: exposure, contrast, saturation, adaptive vibrance,
  temperature/tint, black fade, and highlight rolloff;
- external 3D LUT and LUT strength;
- flat-region debanding;
- coherent, luminance-aware monochrome film grain with independent particle
  size;
- vignette;
- independent bright-highlight halation using the shared Bloom blur resources;
- radial chromatic aberration.

The menu renders LUTs as a dropdown. It does not expose a fixed radio-button
list. LUT labels and count come from `.cube` files under
`Data/NVSE/plugins/omv/luts`; users may add any number of files. The list is
rebuilt in the same timed transaction as the loose shader scan. Selection is
persisted by a stable, case-insensitive filename ID rather than list index, so
adding or reordering other files does not change the saved look.

The master disabled state and master strength zero skip all finishing work.
Each family disabled or at zero strength skips its applicable contribution.
LUT-only work also skips when no valid selected file exists. Chromatic
aberration is a separate finishing pass. The accepted playtest settings enable
it by default, adding a full-resolution draw and backbuffer copy when combined
with Bloom or grading. Source alpha is preserved by every production path.

## Calibrated default look

The default is intended as restrained Mojave photography rather than a heavy
ReShade preset. Analytic grading uses `strength 0.68`, `contrast 0.045`,
`saturation 0.98`, `vibrance 0.075`, `temperature 0.015`, `tint 0.006`,
`black_fade 0.012`, and `highlight_rolloff 0.16`. `Mojave Natural` is selected
at `lut_strength 0.42`; environment response is `0.45`. Debanding is `0.55`,
grain strength `0.3544631` at particle size `1.743985`, vignette `0.035`, and
halation `0.2092626`. Chromatic aberration defaults enabled at `3.038874`
pixels. These four values are the user's accepted 2026-07-23 playtest settings,
promoted without rounding beyond their stored `f32` values. Quantized acceptance
requires the default grain to change at least half of exact eight-bit midtone
samples, remain within `1.75..2.50` code-value RMS, and hold absolute mean bias
below `0.15` code values. Flat-region deband dither changes about 33% with
effectively zero mean, halation adds at least two code values to a representative
bright-halo probe, and the default chromatic edge displacement is about `2.07`
pixels after master strength.

Bloom was recalibrated with the grade rather than treated as an independent
orange glow: intensity `0.34`, threshold `0.62`, radius `2.8`, knee `0.28`,
exposure `0.02`, shoulder `0.58`, saturation `0.92`, warmth `0.18`, shadow lift
`0.10`, dither `0.32`, and atmosphere response `0.24`. The higher threshold and
lower warmth preserve bright signage, sunsets, skin, and pale interiors without
washing the entire frame. These are authored defaults and deterministic static
quality targets; artistic acceptance still requires playtesting.

## Film-grain redesign and reference basis

The 2026-07-21 report exposed a validation gap: the original tests measured
floating-point shader changes before the final UNORM8 write. A later procedural
two-band correction passed those numeric checks but was rejected in playtesting:
its shared two-pixel cells read as blocky render corruption, its response looked
too dark, and its particle character was not convincing. That runtime
observation supersedes the earlier static acceptance; the two-band algorithm
and its shared-cell path have been removed.

The replacement follows established grain structure rather than the rejected
hash pattern. [Unity Post Processing v2 documents](https://docs.unity.cn/Packages/com.unity.postprocessing%402.3/manual/Grain.html)
film grain as coherent gradient noise with separate intensity, particle size,
and luminance response. Its published
[runtime](https://github.com/Unity-Technologies/PostProcessing/blob/v2/PostProcessing/Runtime/Effects/Grain.cs)
and [shader](https://github.com/Unity-Technologies/PostProcessing/blob/v2/PostProcessing/Shaders/Builtins/Uber.shader)
use a repeating bilinear grain texture, changing two-dimensional offsets,
multiplicative color modulation, and a `1 - sqrt(luminance)` response.
[ITU-T H Supplement 21](https://www.itu.int/epublications/publication/itu-t-h-suppl-21-2025-01-film-grain-synthesis-technology-for-video-applications)
describes the broader synthesis family in terms of Gaussian noise, spatial
correlation, and local-intensity adaptation. These are reference facts; OMV's
texture data and implementation are original.

OMV deterministically generates one 512-by-512 monochrome texture when the
effect object is created. Each texel sums twelve uniform pseudorandom values,
centers the result, clamps it to three standard deviations, and encodes the
near-Gaussian sample into `D3DFMT_A8R8G8B8`. A linear, wrapping sampler turns
the samples into continuous correlated particles without any shared square
cells. Two irrational frame-offset increments move through the texture every
frame. The source seed is fixed for reproducible tests and builds; the sampled
position still changes with frame index.

The shader applies one scalar sample to all RGB channels:
`color += color * grain * amount * master * (1 - sqrt(luma))`. This makes the
grain multiplicative rather than a dark overlay. The generated distribution is
balanced around zero, the same multiplier preserves RGB ratios before final
clamping, exact black remains black, and exact white is protected by the
luminance response. Particle size is independent of strength, defaults to
`1.743985`, and spans `0.3..3.0`; the strength remains `0..2`. The shipped
`0.3544631` amount with `0.68` master strength is required to survive UNORM8
while retaining low mean bias.

The local read-only GShade `FilmGrain.fx` was also audited for its Gaussian and
multiplicative response choices. No GShade texture, shader source, or preset is
copied. The old two-pixel algorithm remains only as a CPU negative control:
tests require it to exhibit repeated adjacent samples and require production
grain not to do so. Production tests also require a balanced near-Gaussian
distribution, coherent but non-identical neighbors, temporal change, preserved
black/white endpoints, and quantized default visibility.

The deband dither scale remains `4` code values peak-to-peak. Its shipped
flat-region peak is `0.748` code values and its full-strength peak is bounded
to two code values. The existing spatial averaging and discontinuity rejection
are unchanged. The discontinuity-derived flat weight is carried to the final
dither, so the stronger dither is applied to candidate banding regions and not
to rejected real edges or thin features. This mask placement also follows the
useful contract in the read-only GShade `Deband.fx` reference, without copying
its implementation.

Deterministic tests quantize CPU reference output to UNORM8 rather than stopping
at float-space non-zero checks. Deband still changes about `2711/8192` flat
samples with a `0.0004` code mean. The same audit isolates analytic grading,
the selected LUT, vignette, halation, and the selected chromatic response; their
curves were not changed. Chromatic is enabled by the accepted default settings.

## Creative ranges

Persisted configuration, menu metadata, and render-boundary sanitization agree
on `film_grain 0..2`, `film_grain_size 0.3..3`, and
`chromatic_aberration 0..12` pixels. Grain strength and particle size are
independent, allowing visible fine stock or coarse high-speed-film character
without changing the effect's brightness response. Chromatic aberration yields
up to `8.16` effective edge pixels at the shipped `0.68` master strength instead
of the former `2.72`; the accepted default uses about `2.07` effective edge
pixels and pays the separate pass's full-resolution cost.

The other grading ranges were audited but not widened: exposure already spans
`-1.5..1.5` stops, contrast `-0.5..0.5`, saturation `0..2`, and the remaining
signed or normalized controls already reach their complete authored response
at `-1` or `1`. Increasing those numeric ceilings without redesigning their
curves would only create clipping or redundant slider travel.

## Ownership, phase, and ordering

`omv/src/config.rs` owns persisted values and finite bounds.
`omv/src/luts.rs` owns `.cube` discovery, parsing, cache reuse, and stable IDs.
`omv/src/shaders.rs` owns dynamic menu options and stable-ID synchronization.
`omv/src/runtime.rs` performs the joint shader/LUT scan transaction and final
phase scheduling. `omv/src/effects/blooming_hdr.rs` owns D3D9 resources and CPU
constants. `bloom_hdr_compose.hlsl` owns fused Bloom/color composition;
`chromatic_aberration.hlsl` owns the optional optical pass.

The fixed native phase is `final_image_space`. The established outer
`ImageSpaceManager::ProcessImageSpaceShaders @ 0x00B55AC0` hook calls native
image-space first, then OMV scene-post and final-image phases. Built-in order is:

1. native image-space and OMV scene-post work;
2. highlight extraction and two-axis blur when Bloom or halation is enabled;
3. fused Bloom/color compose when either has work;
4. optional chromatic aberration;
5. built-in spatial AA;
6. loose external final-image shaders.

The supported executable is `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`, PE32
x86, image base `0x00400000`, size `16,084,808`, timestamp `0x4E0D50ED`.
Established phase evidence remains in
`analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt` and
`analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`.
No new engine address or native layout was inferred for this change.

Grade-only rendering needs current scene color and no depth, normal, velocity,
mask, or history. Bloom can consume the existing point-sampled first-person
depth to suppress weapon/hand glow. Chromatic aberration uses only final scene
color. Later native overlays retain their established owner; OMV does not claim
a new HUD mask.

## External LUT format and catalog transaction

OMV accepts text `.cube` 3D LUTs with:

- one `LUT_3D_SIZE` from 2 through 64;
- exactly `size^3` finite RGB triplets in standard red-fastest, then green,
  then blue order;
- optional `TITLE`, `DOMAIN_MIN`, and `DOMAIN_MAX`;
- UTF-8 text, comments beginning with `#`, and at most 64 MiB per file.

1D LUTs, missing/duplicate sizes, wrong sample counts, non-finite data, invalid
domains, and filename-ID collisions are rejected. Output values outside `0..1`
are intentionally clamped when quantized to the display-referred ARGB texture.
Files are sorted case-insensitively by filename. Title controls the displayed
label; filename controls stable identity.

The timed scanner first synchronizes unsaved embedded menu values into staged
config, scans shaders and LUT metadata, reuses `Arc`-owned pixel data for
unchanged files, parses only new/changed LUTs, then rebuilds the dynamic source
list from one catalog snapshot. An invalid edit retains the last-known-good
asset for that path and is retried on later scans. Removal drops the catalog
entry. A missing directory produces an empty fail-soft catalog. Warnings use the
existing bounded scan-log budget.

No artistic LUT is embedded in the release DLL. OMV ships fourteen original loose
files, regenerated by `omv/tools/generate_luts.rs`:

| File | Menu title | Intent |
|---|---|---|
| `00_neutral.cube` | Neutral | Identity/reference look. |
| `01_mojave_natural.cube` | Mojave Natural | Subtle warm daylight and cool shadow separation. |
| `02_dusty_western.cube` | Dusty Western | Dry warm highlights and restrained chroma. |
| `03_bleached_wasteland.cube` | Bleached Wasteland | Muted color, lifted blacks, firmer contrast. |
| `04_neon_nights.cube` | Neon Nights | Cool/magenta night separation and controlled neon color. |
| `05_high_desert_clarity.cube` | High Desert Clarity | Clear, colorful desert daylight without an orange veil. |
| `06_atomic_amber.cube` | Atomic Amber | Stronger retro-futurist amber with protected shadows. |
| `07_frontier_cinema.cube` | Frontier Cinema | Teal shadow and warm highlight separation for western framing. |
| `08_old_world_film.cube` | Old World Film | Faded mid-century print color and gently lifted blacks. |
| `09_vault_fluorescent.cube` | Vault Fluorescent | Cool cyan-green interior light with restrained saturation. |
| `10_sierra_sunset.cube` | Sierra Sunset | Warm-magenta sunset highlights with cooler shadow separation. |
| `11_zion_canyon.cube` | Zion Canyon | Rich red rock, vegetation, and open-sky color separation. |
| `12_divide_duststorm.cube` | Divide Duststorm | Dense copper dust, firm contrast, and strongly muted chroma. |
| `13_wasteland_noir.cube` | Wasteland Noir | Near-monochrome high-contrast wasteland photography. |

Each file declares itself original OMV data and redistributable with OMV. No
GShade texture or third-party LUT is copied. The build installer copies shipped
files without deleting user additions. Release packaging and the release
archive manifest require all fourteen files. Saving a migrated config removes the
obsolete `lut_preset` key and writes `lut_file_id`.

The response-curve audit used `.research/GShade-master/Shaders/Deband.fx`,
`FilmGrain.fx`, `Halation.fx`, and `ChromaticAberration.fx` only as algorithmic
references. [GShade's published licensing page](https://www.gshade.org/licensing)
states that some preset and texture redistribution permissions were granted
specifically to GShade, so those assets are not a safe source for OMV's
redistributable library. The new looks are parameterized OMV originals
generated from source in this repository.

## LUT resource and sampling contract

Catalog pixels live in CPU memory outside the effect draw path. Only the
selected LUT is uploaded to a managed `D3DFMT_A8R8G8B8` texture. For size `N`,
the flattened texture is `N*N` by `N`: red advances across X, blue selects the
X slice, and green selects Y. Hardware linear filtering resolves red/green and
two explicit samples interpolate adjacent blue slices. Addressing is clamped,
mips and sRGB decode are disabled, and domain scale/bias is precomputed on CPU.

The fourteen shipped 32-cubes occupy 1,835,008 bytes of CPU texels. One selected
32-cube occupies 131,072 bytes on GPU, rather than uploading the entire catalog.
The effect begins with a generated 2-cube identity safety texture, which is not
an artistic preset or menu item. LUT creation is attempted only when LUT work
is active. Creation failure keeps the prior texture and returns through the
normal state-restoring failure path.

Native environment response never reads framebuffer luminance. Known interiors
use weight `0.70`; known exteriors use `lerp(0.78, 1.0, daylight)`; unknown
state fails open at `1.0`. `environment_response` blends configured LUT strength
toward that weight.

## Shader and CPU/GPU ABI

All entry points are `Main`, `ps_3_0`.

Fused compose bindings:

| Binding | Meaning |
|---|---|
| `s0` | Full-resolution display-referred scene color, clamped linear. |
| `s2` | Optional first-person depth, point sampled. |
| `s4` | Quarter-resolution Bloom or managed black fallback. |
| `s5` | Selected flattened LUT, clamped linear. |
| `s6` | Generated 512-by-512 monochrome grain, wrapping linear. |
| `c0..c2` | Screen, frame, and camera data. |
| `c3..c5` | Bounded Bloom controls or explicit zeros. |
| `c9` | Bloom target dimensions/texel size. |
| `c10..c14` | Grade values, strengths, master/debug flags, environment state. |
| `c15..c16` | Independent family enable flags and grain particle size. |
| `c17..c18` | LUT input-domain scale/bias and LUT size. |

Chromatic bindings are `s0` scene color, `c0` dimensions/inverse dimensions,
and `c3.x` master-scaled displacement in pixels. It samples center plus
oppositely displaced red and blue. Displacement is zero at screen center and
rises smoothly toward edges; green and alpha come from center.

Both shaders use the four-vertex `D3DPT_TRIANGLESTRIP` and exact D3D9
half-pixel positions. No derivative is used. Viewport, FVF, shaders, RT0,
unused MRTs, depth-stencil, depth/stencil writes/tests, culling, blending, alpha
test, scissor, multisample state, vendor alpha coverage, color writes, sRGB,
and all used sampler states are explicit. Inputs are unbound before a surface
becomes writable; the outer all-state block restores native state on success or
failure.

## Image math and family isolation

Analytic controls operate on finite `0..1` display code values and end in a
bounded write. OMV does not reapply sRGB, replace Fallout's tonemapper, compute
screen-average exposure, or add temporal adaptation, so crossing a bright
object cannot pump exposure. CPU settings sanitize every untrusted numeric
value before constants are bound.

Debanding uses center plus four cross neighbors six pixels away, which reaches
through broad one-code-value bands; local RGB discontinuity rejection preserves
real edges and thin features. Its zero-mean final dither is multiplied by the
same flat-region weight, reaches about `0.748` code values at shipped settings,
and remains bounded to two code values at maximum strength. Film grain uses a
bounded `-1..1` texture sample, a zero-centered multiplicative response,
protected black and white endpoints, and changing frame offsets. Vignette is
aspect corrected.
Halation schedules highlight extraction and blur independently of visible
Bloom, then adds only a warm red-biased halo. Each family has an independent
dynamic shader gate; its disabled path performs no texture sampling specific to
that family. Chromatic aberration is a separate shader because adding its two
extra samples to the fused shader exceeded the accepted compose instruction
ceiling. Its radial weight reaches full strength at every screen edge rather
than only at diagonal corners.

## Lifetime, failure, and work budgets

Final shaders compile once during runtime construction, outside normal draw.
The LUT catalog contains CPU data only. First use uploads the selected managed
texture; a selection/content revision replaces it transactionally. The grain
generator and its one-MiB managed texture are created with the effect, never in
the routine draw path. A catalog change releases the effect so removed LUT and
grain resources cannot linger. Device loss releases the effect and default-pool
quarter-resolution Bloom targets; reset recreates them lazily. Resize/format
changes recreate only the two Bloom targets. There is no history or camera-cut
state. Grain texture allocation/upload failure aborts effect construction
through the existing error path, so no partially initialized resource set is
published.

Static upper bounds enforced from compiled bytecode are:

| Pass | Ceiling | Texture opcodes |
|---|---:|---:|
| Bloom extract | 220 instructions | 10 |
| Bloom blur | 80 instructions | 9 |
| Fused compose | 500 instructions | 14 |
| Chromatic aberration | 70 instructions | 3 |

Grade only is one phase copy plus one full-resolution draw. Bloom is one copy,
three quarter-resolution draws, and one full-resolution compose. Halation alone
uses the same four-draw shape so it remains functional when visible Bloom is
disabled; Bloom plus grade without chromatic remains four draws. Chromatic-only
adds one full-resolution draw and uses the already captured scene. Chromatic
after compose adds one backbuffer copy and one full-resolution draw. Because
chromatic aberration now defaults on, the shipped Bloom-plus-grade plan is five
effect draws and includes that copy. Disabling it returns to the four-draw plan.
The unchanged draw path performs no file I/O, shader compilation, locks, routine
allocation, or routine logging. LUT upload is configuration/revision work, not
per-frame work.

## Automated validation and remaining acceptance

The supported `i686-pc-windows-gnu` tests cover:

- compilation and bytecode inspection of extract, blur, compose, and chromatic
  entry points, including instruction/texture ceilings and prohibited
  derivatives;
- exact `c10..c18`, `s5..s6`, chromatic `c0/c3/s0`, alpha, half-pixel, sampler,
  render-target hazard, and explicit D3D state contracts;
- deterministic CPU images for analytic grading, actual shipped LUTs,
  six-pixel debanding, coherent Gaussian-texture grain and flat-gated dither,
  vignette, independent halation, Bloom composition, and radial chromatic
  sampling at borders, centers, odd/even sizes, and constant inputs;
- per-family UNORM8 output probes for analytic grade, LUT, deband, grain,
  vignette, halation, and enabled chromatic response, including changed-sample,
  RMS, mean-bias, black/white endpoints, temporal change, neighbor correlation,
  and rejected-edge checks;
- negative controls rejecting LUT seams/non-monotonic neutral ramps, banding
  no-op implementations, the removed shared-cell grain model, chromatic
  center-only sampling, edge softening, disabled-family work, missing-LUT work,
  and over-budget fused shaders;
- every family switch alone, master/zero strength, LUT availability,
  grade-only, Bloom-only, fused, chromatic-only, resize, device release, and
  phase/order planning;
- `.cube` axis order, finite/domain/count/size rejection, 17-file dynamic
  catalogs, add/remove, unchanged `Arc` reuse, last-known-good invalid reload,
  unique stable IDs, selection through catalog reorder, and fourteen actual
  shipped files with unique titles, pixel bounds, monotonic neutral axes, and
  pairwise non-redundancy metrics;
- menu schema/sync, dropdown choice IDs, config sanitization/round trip, legacy
  key removal, shipped-default equality, installer copy, release packaging, and
  archive manifest requirements;
- absence of compilation, parsing, file I/O, allocation, or locks in the effect
  draw method and bounded CPU/GPU memory accounting.

Static validation cannot prove subjective atmosphere or real GPU frame time.
An ordinary Fallout NV playtest should compare noon, sunset, night,
representative interiors, skin/dialogue, iron sights, menus, 1080p and a
higher-resolution output, and 16:9/ultrawide output; enable each family alone;
add/edit/remove a user `.cube` while the menu is open; and exercise
alt-tab/device reset. It should confirm that grain is clearly present without
darkening the frame, does not form square cells or sparkle in black/white
regions, particle size tracks its independent slider across resolutions, the
LUT dropdown refreshes, invalid edits preserve the prior look, chromatic
fringing stays edge-local, and later AA/external shaders retain order.

Final command evidence on 2026-07-23:

- `cargo test --target i686-pc-windows-gnu -p omv`: 269 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: succeeded
  without warnings;
- `cargo fmt -p omv -- --check` and `git diff --check`: passed.

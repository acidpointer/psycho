# OMV final color, external LUT, Bloom, and chromatic contract

Status: implemented on 2026-07-21. Deterministic repository, parser, menu,
resource-planning, CPU image-reference, shader compilation, bytecode-budget, and
packaging coverage is complete. Ordinary in-game visual acceptance remains.

## Purpose and visible behavior

OMV owns a display-referred finishing stack after Fallout New Vegas' native
image-space work. `Bloom and HDR` and `Color Grade and Film` share the existing
final-color pipeline. The color effect has a master switch and strength plus an
independent switch for every family:

- analytic color grading: exposure, contrast, saturation, adaptive vibrance,
  temperature/tint, black fade, and highlight rolloff;
- external 3D LUT and LUT strength;
- flat-region debanding;
- luminance-weighted film grain;
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
aberration is a separate opt-in finishing pass and is off by default because it
adds a full-resolution draw and backbuffer copy when combined with Bloom or
grading. Source alpha is preserved by every production path.

## Calibrated default look

The default is intended as restrained Mojave photography rather than a heavy
ReShade preset. Analytic grading uses `strength 0.68`, `contrast 0.045`,
`saturation 0.98`, `vibrance 0.075`, `temperature 0.015`, `tint 0.006`,
`black_fade 0.012`, and `highlight_rolloff 0.16`. `Mojave Natural` is selected
at `lut_strength 0.42`; environment response is `0.45`. Debanding is `0.55`,
grain `0.16`, vignette `0.035`, and halation `0.12`. Chromatic strength is
staged at `0.85` pixels but its switch defaults off. These revised response
curves make every enabled default objectively non-zero at display precision:
grain has at least a `0.20` code-value RMS on midtones, halation adds at least
two code values to a representative bright-halo probe, and chromatic shift is
at least half a pixel after master strength.

Bloom was recalibrated with the grade rather than treated as an independent
orange glow: intensity `0.34`, threshold `0.62`, radius `2.8`, knee `0.28`,
exposure `0.02`, shoulder `0.58`, saturation `0.92`, warmth `0.18`, shadow lift
`0.10`, dither `0.32`, and atmosphere response `0.24`. The higher threshold and
lower warmth preserve bright signage, sunsets, skin, and pale interiors without
washing the entire frame. These are authored defaults and deterministic static
quality targets; artistic acceptance still requires playtesting.

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
| `c0..c2` | Screen, frame, and camera data. |
| `c3..c5` | Bounded Bloom controls or explicit zeros. |
| `c9` | Bloom target dimensions/texel size. |
| `c10..c14` | Grade values, strengths, master/debug flags, environment state. |
| `c15..c16` | Independent family enable flags. |
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
real edges and thin features. Deband dither remains below one code value. Film
grain has a bounded six-code-value peak at maximum strength, is weighted away
from highlights, and changes with frame index. Vignette is aspect corrected.
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
texture; a selection/content revision replaces it transactionally. A catalog
change releases the effect so removed LUT resources cannot linger. Device loss
releases the effect and default-pool quarter-resolution Bloom targets; reset
recreates them lazily. Resize/format changes recreate only the two Bloom
targets. There is no history or camera-cut state.

Static upper bounds enforced from compiled bytecode are:

| Pass | Ceiling | Texture opcodes |
|---|---:|---:|
| Bloom extract | 220 instructions | 10 |
| Bloom blur | 80 instructions | 9 |
| Fused compose | 500 instructions | 13 |
| Chromatic aberration | 70 instructions | 3 |

Grade only is one phase copy plus one full-resolution draw. Bloom is one copy,
three quarter-resolution draws, and one full-resolution compose. Halation alone
uses the same four-draw shape so it remains functional when visible Bloom is
disabled; Bloom plus grade remains four draws. Chromatic-only adds one
full-resolution draw and uses the already captured scene. Chromatic after
compose adds one backbuffer copy and one full-resolution draw. Its default-off
state therefore has zero default cost. The unchanged draw path performs no file
I/O, shader compilation, locks, routine allocation, or routine logging. LUT
upload is configuration/revision work, not per-frame work.

## Automated validation and remaining acceptance

The supported `i686-pc-windows-gnu` tests cover:

- compilation and bytecode inspection of extract, blur, compose, and chromatic
  entry points, including instruction/texture ceilings and prohibited
  derivatives;
- exact `c10..c18`, `s5`, chromatic `c0/c3/s0`, alpha, half-pixel, sampler,
  render-target hazard, and explicit D3D state contracts;
- deterministic CPU images for analytic grading, actual shipped LUTs,
  six-pixel debanding, visible/bounded grain and dither, vignette, independent
  halation, Bloom composition, and radial
  chromatic sampling at borders, centers, odd/even sizes, and constant inputs;
- negative controls rejecting LUT seams/non-monotonic neutral ramps, banding
  no-op implementations, chromatic center-only sampling, edge softening,
  disabled-family work, missing-LUT work, and over-budget fused shaders;
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
An ordinary Fallout NV playtest should compare noon, sunset, night, representative
interiors, skin/dialogue, iron sights, menus, and 16:9/ultrawide output; enable
each family alone; add/edit/remove a user `.cube` while the menu is open; and
exercise alt-tab/device reset. It should confirm that the default is restrained,
the LUT dropdown refreshes, invalid edits preserve the prior look, chromatic
fringing stays edge-local, and later AA/external shaders retain order.

Final command evidence on 2026-07-21:

- `cargo test --target i686-pc-windows-gnu -p omv`: 230 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: succeeded
  without warnings;
- the standalone LUT generator reproduced all fourteen shipped files
  byte-for-byte;
- `cargo fmt --all -- --check`, shell syntax validation for the modified build
  and packaging scripts, and `git diff --check`: passed.

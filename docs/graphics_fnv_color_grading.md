# OMV final color, external LUT, Bloom, and chromatic contract

Status: implemented on 2026-07-21; film grain completely replaced and creative
ranges revised on 2026-07-23; the final-color resource transaction was
corrected on 2026-07-27 after a real-user terrain-corruption report; the
original atmospheric LUT library was expanded with Mojave, Capital Wasteland,
subterranean-survival, and exclusion-zone families on 2026-07-28.
Automatic exposure and adaptive tone mapping were integrated and then
corrected for transient behavior, visible final-stage tone response, and
bounded update cost on 2026-08-11. A 2026-08-12 playtest then proved the
near-white curve was still inert across ordinary display values; its
photographic response and independent-control correction is in
`graphics_fnv_auto_exposure_and_adaptive_tone.md`.
Deterministic repository, parser, menu, resource-planning, CPU image-reference,
shader compilation, bytecode-budget, and packaging coverage is complete.
Ordinary in-game visual acceptance of the transaction fix remains.

## Purpose and visible behavior

OMV owns a display-referred finishing stack after Fallout New Vegas' native
image-space work. `Bloom and HDR` and the `Final Color Pipeline` share the
existing final-color pipeline. Configuration presents the fused source as
separate effects instead of one misleading Color Grade and Film editor:

- Final Output: fused-source master enable, master strength, and before/after
  split;
- Auto Exposure;
- Tone Mapping;
- Color Grading;
- LUT;
- Debanding;
- Film Grain;
- Vignette;
- Halation;
- Chromatic Aberration.

Each family has an independent switch and relevant controls:

- analytic color grading: exposure, contrast, saturation, adaptive vibrance,
  temperature/tint, black fade, and highlight rolloff;
- external 3D LUT and LUT strength;
- flat-region debanding;
- coherent, luminance-aware monochrome film grain with independent particle
  size;
- vignette;
- independent bright-highlight halation using the shared Bloom blur resources;
- radial chromatic aberration.

This separation is UI ownership only. Creative values remain in the stored
`ColorGradeConfig` and frozen preset payload. Adaptive display values are
top-level Current Look preferences and are not captured by presets. All ten
editors still project into one fused final-color source; making each sidebar
entry a new D3D effect would duplicate phase copies and full-resolution work.

The LUT effect renders assets as a dropdown. It does not expose a fixed
radio-button list. LUT labels and count come from `.cube` files under
`Data/NVSE/plugins/omv/luts`; users may add any number of files. The list is
rebuilt in the same timed transaction as the loose shader scan. Selection is
persisted by a stable, case-insensitive filename ID rather than list index, so
adding or reordering other files does not change the saved look.

The Final Output master disabled state skips all finishing work. Master strength
zero skips creative grading, LUT, debanding, grain, vignette, halation, and
chromatic work, but it does not silently disable the independently configured
Auto Exposure or Tone Mapping families. Each family disabled or at zero
strength skips its applicable contribution. LUT-only work also skips when no
valid selected file exists. Chromatic aberration is a separate finishing pass.
The accepted playtest settings enable it by default, adding a full-resolution
draw and backbuffer copy when combined with Bloom or grading. Source alpha is
preserved by every production path.

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

Adaptive display is intentionally outside that creative-range policy. Its
existing schema-one fields now expose `0..3 EV`, `0.10..4.0` adaptation speed,
and `0..3` tone strength. These are independent Current Look controls; Final
Output enable remains their explicit family bypass, but Color Grade master
strength no longer attenuates or disables them.

## Ownership, phase, and ordering

`omv/src/config.rs` owns persisted values and finite bounds.
`omv/src/luts.rs` owns `.cube` discovery, parsing, cache reuse, and stable IDs.
`omv/src/shaders.rs` owns the one `Final Color Pipeline` source, dynamic option
metadata, and stable-ID synchronization. `omv/src/runtime.rs` owns the ten
virtual finishing selections, filters each detail editor to its controls,
performs the joint shader/LUT scan transaction, and schedules the final phase.
`omv/src/effects/blooming_hdr.rs` owns D3D9 resources and CPU constants.
`adaptive_tone.hlsl` owns bounded exposure metering, independent highlight-tail
measurement, temporal state, and the 128x1 response curve;
`bloom_hdr_compose.hlsl` owns fused Bloom/color/tone composition;
`chromatic_aberration.hlsl` owns the optional optical pass.

The fixed native phase is `final_image_space`. The established outer
`ImageSpaceManager::ProcessImageSpaceShaders @ 0x00B55AC0` hook calls native
image-space first, then OMV scene-post and final-image phases. Built-in order is:

1. native image-space and OMV scene-post work;
2. highlight extraction and two-axis blur when Bloom or halation is enabled;
3. low-resolution response generation, at no more than 60 Hz, when automatic
   exposure or tone requires it;
4. fused Bloom/color compose, creative finishing, then final display tone when
   any family has work;
5. optional chromatic aberration;
6. built-in spatial AA;
7. loose external final-image shaders.

The supported executable is `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`, PE32
x86, image base `0x00400000`, size `16,084,808`, timestamp `0x4E0D50ED`.
Established phase evidence remains in
`analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt` and
`analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`.
No new engine address or native layout was inferred for this change.

Grade-only rendering needs current scene color and no depth, normal, velocity,
or mask. Automatic display adaptation additionally owns 128x1 FP16 ping-pong
response curves; fixed tone and disabled adaptation do not. Bloom can consume
the existing point-sampled first-person depth to suppress weapon/hand glow.
Chromatic aberration uses only final scene color. Later native overlays retain
their established owner; OMV does not claim a new HUD mask.

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

No artistic LUT is embedded in the release DLL. OMV ships forty-two original
loose files, regenerated by `omv/tools/generate_luts.rs`:

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
| `14_midnight_mojave.cube` | Midnight Mojave | Moonlit cobalt shadows, restrained mids, and warm practical highlights. |
| `15_desert_noir.cube` | Desert Noir | Graphite shadows, subdued desert color, and warm sand/skin separation. |
| `16_vegas_after_dark.cube` | Vegas After Dark | Teal shadows, magenta neon, and amber practical-light separation. |
| `17_rain_on_freeside.cube` | Rain on Freeside | Steel-blue rain shadows, faded mids, and sodium-vapor highlights. |
| `18_sierra_madre_gilded.cube` | Sierra Madre Gilded | Aged gold and cream against cool, gently lifted print blacks. |
| `19_dead_money_poison.cube` | Dead Money Poison | Toxic green shadows and mids, pale gold highlights, and protected reds. |
| `20_mojave_blue_hour.cube` | Mojave Blue Hour | Navy/lavender shade balanced against peach horizon light. |
| `21_caravan_lantern.cube` | Caravan Lantern | A cool night bed with amber firelight and selectively retained reds. |
| `22_dust_and_blood.cube` | Dust and Blood | Subdued earth, vegetation, and sky with deliberate blood/rust retention. |
| `23_atomic_monochrome.cube` | Atomic Monochrome | Near-monochrome selenium shadows and warm paper highlights without grayscale crush. |
| `24_vault_noir.cube` | Vault Noir | Fluorescent cyan-green shade with restrained warm skin and highlights. |
| `25_lonesome_road_ash.cube` | Lonesome Road Ash | Steel and ash shadows, desaturated mids, and copper dust highlights. |
| `26_radioactive_dream.cube` | Radioactive Dream | Surreal cyan-green shadows and magenta highlights with controlled detail. |
| `27_old_world_detective.cube` | Old World Detective | Tobacco-print blacks, olive/steel shadows, and aged cream highlights. |
| `28_capital_wasteland_overcast.cube` | Capital Wasteland Overcast | Green-steel cloud light, restrained rubble color, and protected skin/earth reds. |
| `29_potomac_fog.cube` | Potomac Fog | Lifted blue-gray fog, softened contrast, and retained tonal separation. |
| `30_ruined_capitol_dusk.cube` | Ruined Capitol Dusk | Violet-blue ruins against warm sunset and practical-light highlights. |
| `31_dc_radstorm.cube` | DC Radstorm | Sickly green-yellow storm light with contained blue and red accents. |
| `32_underworld_embers.cube` | Underworld Embers | Sooty cool shadows, restrained mids, and rich orange firelight. |
| `33_subterranean_survival.cube` | Subterranean Survival | Cold tunnel shadows separated from warm lamps, faces, and worn metal. |
| `34_emergency_red.cube` | Emergency Red | Teal-black shade and assertive red emergency illumination without red-channel clipping. |
| `35_frozen_platform.cube` | Frozen Platform | Cyan-blue cold, pale fluorescent highlights, and readable dark structure. |
| `36_dry_sea_white_sun.cube` | Dry Sea White Sun | Bleached hard daylight, dusty copper shade, and a broad highlight shoulder. |
| `37_dead_city_blue.cube` | Dead City Blue | Near-monochrome steel-blue abandonment with subtle warm-neutral separation. |
| `38_exclusion_overcast.cube` | Exclusion Overcast | Damp green-gray daylight, subdued vegetation, and weathered warm detail. |
| `39_emission_warning.cube` | Emission Warning | Violet-red storm contrast with dark blue shade and protected warning colors. |
| `40_rusted_laboratory.cube` | Rusted Laboratory | Cyan-green fluorescent shadows set against rust and tungsten highlights. |
| `41_pripyat_memory.cube` | Pripyat Memory | Faded olive print color, lifted shadow detail, and aged cream highlights. |

Each file declares itself original OMV data and redistributable with OMV. No
GShade texture or third-party LUT is copied. The build installer copies shipped
files without deleting user additions. Release packaging and the release
archive manifest require all forty-two files. Saving a migrated config
removes the obsolete `lut_preset` key and writes `lut_file_id`.

The first twenty-eight generated files remain byte-for-byte unchanged by the
Capital Wasteland/subterranean/exclusion-zone expansion. The first fourteen
transforms also remain byte-for-byte stable relative to the original library.
Looks `14` through `41` use a second-generation cinematic recipe.
It applies a monotonic luminance toe/shoulder, separate shadow/midtone/highlight
chroma, three-way color separation, and limited dominant-hue retention.
Out-of-gamut colors are compressed around the transformed luminance rather than
clipped channel-by-channel. The intent is authored color contrast across tonal
regions, not a global darken or saturation filter. The generator remains an
offline build tool; none of this recipe math runs in game.

Looks `33` through `41` are original OMV interpretations of broad
post-apocalyptic photographic language: cold subterranean practical lighting,
bleached surface daylight, damp exclusion-zone overcast, emergency red, and
industrial fluorescent/rust separation. No LUT, screenshot, texture, numeric
curve, or other asset was extracted or copied from Metro or S.T.A.L.K.E.R.

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

The forty-two shipped 32-cubes occupy 5,505,024 bytes of CPU texels. One
selected 32-cube still occupies 131,072 bytes on GPU, rather than uploading the
entire catalog. The effect begins with a generated 2-cube identity safety
texture, which is not an artistic preset or menu item. LUT creation is
attempted only when LUT work is active. Creation failure keeps the prior texture
and returns through the normal state-restoring failure path.

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
| `s7` | Current linearly filtered FP16 response curve in the adaptive variant. |
| `c0..c2` | Screen, frame, and camera data. |
| `c3..c5` | Bounded Bloom controls or explicit zeros. |
| `c9` | Bloom target dimensions/texel size. |
| `c10..c14` | Grade values, strengths, master/debug flags, environment state. |
| `c15..c16` | Independent family enable flags and grain particle size. |
| `c17..c18` | LUT input-domain scale/bias and LUT size. |
| `c19` | Automatic-exposure enable, tone mode, and tone strength. |

Response generation binds display color at `s0`, previous point-sampled curve
at `s1`, completed Bloom at `s4`, and adaptation/Bloom values at `c0..c3`. Its
R lane stores luminance-indexed scale; G/B/A replicate adapted log luminance,
applied transient EV, and automatic-tone activity.

Chromatic bindings are `s0` scene color, `c0` dimensions/inverse dimensions,
and `c3.x` master-scaled displacement in pixels. It samples center plus
oppositely displaced red and blue. Displacement is zero at screen center and
rises smoothly toward edges; green and alpha come from center.

Both shaders use the four-vertex `D3DPT_TRIANGLESTRIP` and exact D3D9
half-pixel positions. No derivative is used. Viewport, FVF, shaders, RT0,
unused MRTs, depth-stencil, depth/stencil writes/tests, culling, blending, alpha
test, scissor, multisample state, vendor alpha coverage, color writes, sRGB,
and all used sampler states are explicit.

## Render transaction and feedback safety

The 2026-07-27 report supplied `.reports/terrain_artifacts.png`: Bloom alone
produced large geometry-shaped vertical blocks while the later menu and HUD
remained intact. The reported configuration disabled the world-color-consuming
volumetric effects. Static code tracing proved that the phase color-copy texture
was consequently bound at fallback sampler `s3`; the old copy path cleared only
`s0` before writing that same texture with `StretchRect`. Chromatic aberration
repeated the same alias after fused composition. This is direct code evidence;
the exact driver response that converted the feedback hazard into the pictured
columns remains a runtime observation.

`omv/src/render_state.rs` now owns the reusable phase-copy transaction. Every
write to the phase copy unbinds both ABI locations that can reference it, `s0`
and `s3`, before making its surface writable. Equal-size copies use
`D3DTEXF_NONE`; no scaling or optional StretchRect filter capability is needed.
Only after the write completes does the helper rebind `s3` to captured world
color or the documented current-color fallback. Bloom, grade, chromatic recopy,
the other embedded effects, and loose shader passes all use this one helper.

D3D9 `D3DSBT_ALL` state blocks do not own render targets or the depth-stencil
attachment. OMV therefore captures RT0, every supported auxiliary MRT, and the
optional depth-stencil surface separately before changing any target. It
detaches depth and supported auxiliary targets before RT0 changes, preventing
dimension or multisample incompatibility from failing a switch halfway through.
Restoration rebuilds attachments first and applies the state block last because
`SetRenderTarget` resets viewport and scissor state. Rejected work and invalid
source surfaces exit before any device state is changed. Once the transaction
begins, success, draw failures, and restore failures all run through the same
restoration path; the first failure is returned after every restore has been
attempted.

The supported MRT count comes from `D3DCAPS9::NumSimultaneousRTs`, is bounded to
the D3D9 range of one through four, and is cached once per device. Low-end
devices running the final-color path are never asked to access unsupported MRT
indices. A missing depth-stencil attachment is represented by Direct3D's
documented `D3DERR_NOTFOUND` result rather than being mistaken for a hard
failure.

## Image math and family isolation

Analytic controls operate on finite display code values and end in a bounded
write. OMV does not reapply sRGB or replace Fallout's native tonemapper. The
optional display-referred meter uses one fixed center-weighted 4x4 grid,
prior-anchored log-luminance winsorization, and bounded temporal response.
Exposure is isolated from OMV output. Automatic tone uses a separate native and
Bloom upper-tail signal to modulate an always-present extended-Reinhard display
curve. Its hue-preserving response runs after grade, LUT, halation, and
vignette so final saturation cannot erase it. CPU settings
sanitize every untrusted numeric value before constants are bound. The complete
adaptation and neutral curve math is documented in
`graphics_fnv_auto_exposure_and_adaptive_tone.md`.

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
changes recreate only the two Bloom targets. Automatic mode additionally owns
two persistent 128x1 FP16 response targets and invalidates them across
Present gaps, resize, disable, and device recreation. Grain texture
allocation/upload failure aborts effect construction
through the existing error path, so no partially initialized resource set is
published.

Static upper bounds enforced from compiled bytecode are:

| Pass | Ceiling | Texture opcodes |
|---|---:|---:|
| Bloom extract | 220 instructions | 10 |
| Bloom blur | 80 instructions | 9 |
| Fused compose | 500 instructions | 14 |
| Fixed tone compose | 530 instructions | 14 |
| Adaptive compose | 515 instructions | 15 |
| 128x1 response generator | 420 instructions | 4 |
| Chromatic aberration | 70 instructions | 3 |

Grade only is one phase copy plus one full-resolution draw. Bloom is one copy,
three quarter-resolution draws, and one full-resolution compose. Halation alone
uses the same four-draw shape so it remains functional when visible Bloom is
disabled; Bloom plus grade without chromatic remains four draws. Chromatic-only
adds one full-resolution draw and uses the already captured scene. Chromatic
after compose writes compose to its persistent renderable intermediate and
adds one full-resolution draw; it does not copy the backbuffer. Because
chromatic aberration now defaults on, the previous Bloom-plus-grade plan is
five effect draws. Shipped automatic adaptation adds one 128x1 draw when its
60 Hz scheduler is due, for at most six effect draws on that Present. At 120 Hz
the response draw normally runs every other Present. Disabling adaptive
exposure/tone restores the previous plan exactly; fixed-neutral tone changes
only the compose variant. The first active automatic draw creates both response
targets and logs one success line; steady-state operation performs no file I/O,
shader compilation, locks, routine allocation, capability queries, or routine
logging. The attachment transaction
adds owned COM references for the active native attachments once per applied
phase but allocates no Rust heap memory. LUT upload is configuration/revision
work, not per-frame work.

## Automated validation and remaining acceptance

The supported `i686-pc-windows-gnu` tests cover:

- compilation and bytecode inspection of extract, blur, all compose variants,
  the 128x1 response generator, and chromatic entry points, including
  instruction/texture ceilings and prohibited derivatives;
- exact `c10..c18`, `s5..s6`, chromatic `c0/c3/s0`, alpha, half-pixel, sampler,
  render-target hazard, and explicit D3D state contracts;
- a negative-control resource model proving that clearing only `s0` leaves the
  reported `s3` phase-copy alias, plus production checks requiring all phase
  copies and chromatic recopies to use the feedback-safe helper;
- capability normalization for one-, two-, and four-MRT devices, exact
  unfiltered phase copies, complete attachment capture, and attachment-before-
  state-block restoration ordering;
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
  unique stable IDs, selection through catalog reorder, and forty-two actual
  shipped files with unique titles, pixel bounds, monotonic neutral axes, and
  pairwise non-redundancy metrics;
- the twenty-eight cinematic additions against the actual flattened D3D
  sampler,
  requiring bounded output, meaningful image change, preserved micro-detail,
  restrained mean-luminance shift, distinct shadow/highlight color separation,
  at least 27 of 32 neutral luminance levels, and retained skin/earth,
  vegetation, and sky/neon chroma;
- menu schema/sync, dropdown choice IDs, config sanitization/round trip, legacy
  key removal, shipped-default equality, installer copy, release packaging, and
  archive manifest requirements;
- ten independently named finishing editors mapped back to one fused source,
  with no new preset field or render pass;
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
The Configuration sidebar must show all ten finishing entries separately;
each detail pane must expose only its own enable switch and controls, and
changing every entry must still persist through the existing final-color
config and preset schema.
For looks `14` through `41`, compare the same camera position with LUT strength
at zero and at the intended value. Confirm that dark clothing, faces, terrain
texture, cloud gradients, neon signs, and pale interiors retain readable
detail; that night looks do not merely lower exposure; and that the selective
red, green, and blue treatments do not posterize motion or produce hard hue
boundaries. This subjective in-game review remains required even though the
offline color-checker and deterministic image probes pass.

The 2026-07-27 artifact regression additionally requires the reported
1920-by-1080 configuration: Native PBR and Native Sky on; Volumetric Fog,
Volumetric Lighting, AO, and other screen effects off. Test Bloom alone, Color
Grade alone, both together, and grading with chromatic aberration both on and
off. Terrain, water, first-person geometry, HUD, and the workbench menu must
remain stable while moving the camera above and below terrain height. Repeat
after alt-tab and device reset. This ordinary playtest is the remaining evidence
needed to confirm the driver-visible artifact is gone.

Final command evidence on 2026-07-23:

- `cargo test --target i686-pc-windows-gnu -p omv`: 269 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: succeeded
  without warnings;
- `cargo fmt -p omv -- --check` and `git diff --check`: passed.

Transaction-fix command evidence on 2026-07-27:

- `cargo test --target i686-pc-windows-gnu -p omv`: 335 passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p libpsycho --lib`: 11 passed,
  0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: succeeded
  without warnings.

The broader `libpsycho` command reached 11 passing unit tests, then its
unrelated existing logger doctest rejected the unsuffixed `0xDEADBEEF` example
as an overflowing `i32`. This change does not modify that logger documentation;
the affected library suite above is green.

Finishing-navigation validation on 2026-07-28:

- `cargo test --target i686-pc-windows-gnu -p omv`: 368 passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p psycho-imgui`: 5 passed,
  0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: succeeded
  without warnings.

Atmospheric-library validation on 2026-07-28:

- separate-directory regeneration and recursive comparison proved that files
  `00` through `27` remained byte-for-byte unchanged;
- `cargo test --target i686-pc-windows-gnu -p omv`: 380 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: succeeded
  without warnings;
- `cargo fmt -p omv -- --check` passed.

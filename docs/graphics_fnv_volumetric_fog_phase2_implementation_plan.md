# FNV volumetric fog Phase 2 implementation plan

Date: 2026-07-17

## Outcome

The next stage ships production supplemental volumetric fog at the proven
post-world, post-TAA, pre-first-person boundary. It does not add directional
volumetric lighting, native fog replacement, shadow-map marching, or temporal
atmosphere history. Those remain later stages.

The stage is complete only when `volumetric_fog.enabled` changes the world
image, preserves source alpha, leaves first-person and UI untouched, and
fails closed to the original world color whenever a required contract is not
available.

## Why the stage starts with contract closure

The current implementation owns the world boundary, validated camera/depth,
active fog color/range/power, sky data, exterior state, strict FP16 reduced
depth, and debug presentation. It does not yet prove all facts needed for
physical composition:

- the exact transfer applied to world RGB before native HDR image space;
- preservation of the engine world-target alpha channel;
- a stable underwater-state value at the world boundary;
- water, transparent geometry, and sky behavior in the captured INTZ depth.

The native `ISHDRBLENDINSHADER` bytecode reads source alpha during final HDR
composition, while OMV TAA currently replaces that alpha with a private depth
key. Production atmosphere must not build on that violation.

## Explicit exclusions

Do not include any of these changes in Phase 2:

- sampling native local-light type `0x2B` textures;
- treating `ShadowProj` as a sun shadow texture contract;
- unshadowed local point or spot volumetrics;
- replacing native distance fog;
- disabling native fog through a global render-state switch;
- moving the atmosphere pass after first-person or UI;
- moving the atmosphere pass before the existing world TAA resolve;
- atmosphere temporal history or animated ray jitter;
- merging the existing sunshaft pipeline into atmosphere.

## Work package 1: close the remaining static contracts

Use the prepared script:

`analysis/ghidra/scripts/graphics_fnv_atmosphere_phase2_contract_audit.py`

The user runs it in Ghidra. Expected output:

`analysis/ghidra/output/perf/graphics_fnv_atmosphere_phase2_contract_audit.txt`

The output must answer:

1. Which native image-space input receives the post-world render target before
   HDR blend and exposure.
2. Which native image-space paths consume or replace source alpha.
3. Which branch and engine value select the underwater transaction around
   `0x004EC800`.
4. Whether OMV can read a bounded value-copy underwater flag at the post-world
   boundary without retaining an engine pointer.

Review the output together with:

- `analysis/shaders_disasm/shaderpackage010/ISHDRBLENDINSHADER.pso.dis`;
- `analysis/shaders_disasm/shaderpackage010/ISHDRADAPT.pso.dis`;
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_fog_stage_ownership_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_taa_projection_alpha_perf_contract_audit.txt`.

No engine reader is added for underwater state until the exact owner, field,
lifetime, and validation range are proven by the output.

## Work package 2: repair TAA alpha ownership

This is a prerequisite even when fog is disabled because the existing TAA
resolve copies its logarithmic depth key into world alpha.

### Resource change

Change `TemporalTargets` to own:

- current source color in the source format;
- two `A16B16G16R16F` color-history targets;
- two `R16F` depth-key history targets.

For an FP16/HDR source, failure to create FP16 color history or R16F key
history disables TAA for that target. Do not fall back to A8 history for an
FP16 source.

### Shader change

Update `aa_temporal.hlsl`:

- bind previous depth-key history separately from color history;
- sample the rejection key from that texture instead of color alpha;
- return resolved RGB with `CurrentColor.a` unchanged.

Add `aa_temporal_depth_key.hlsl`:

- read current hardware depth;
- use the same near/far/reversed-depth contract as the resolve;
- write the logarithmic key to `R16F`;
- use the bounded far distance already proven by TAA.

### Pass order

1. Copy the world target into current color.
2. Resolve RGB into the next color-history target while preserving source alpha.
3. Render the current depth key into the matching next R16F target.
4. Copy resolved color back to the world target.
5. Swap both history indices together.

Do not use mixed-format MRT in this stage. The extra key pass is simpler and
does not depend on the unproven DXVK mixed-MRT contract.

### Validation

- TAA color and depth history indices can never diverge.
- History invalidation clears validity for both resources.
- Resize, device reset, epoch gap, camera cut, FOV change, and creation failure
  invalidate both histories.
- An alpha debug view must be identical with TAA off and on, aside from real
  changes caused by the underlying scene.

Files:

- `omv/src/effects/temporal_aa.rs`;
- `omv/shaders/embedded/aa_temporal.hlsl`;
- new `omv/shaders/embedded/aa_temporal_depth_key.hlsl`.

## Work package 3: runtime composition probes

Extend atmosphere diagnostics before enabling production composition.

### Contract log

Log on contract changes, not every frame:

- source width, height, format, usage, multisample type, and quality;
- reduced target dimensions and formats;
- world-boundary calls per Present;
- camera transform availability and capture epoch;
- fog RGB/range/power;
- exterior and underwater known/value states;
- source color transfer selected by the validated FNV path;
- TAA enabled and alpha-preserving history available;
- the exact reason for a fail-closed bypass.

### Debug views

Expand atmosphere debug modes to:

1. nearest reduced depth;
2. reduced depth span;
3. reconstructed world-height bands;
4. source alpha;
5. overbright and negative RGB range;
6. current optical depth/transmittance;
7. integrated scattering;
8. bilateral tap acceptance.

The world-height view must remain fixed to world geometry while the camera
rotates and translates. This is the runtime proof for the view-to-world row
packing used by integration.

The RGB/alpha probes must be captured with TAA both off and on. Production
composition stays bypassed until:

- observed world format is `A16B16G16R16F` on the supported path;
- native image space is still downstream of the atmosphere boundary;
- source alpha is preserved by TAA and the atmosphere passthrough;
- the selected RGB transfer agrees with the shader-package and runtime evidence;
- water, sky, and transparent test scenes do not invalidate depth termination;
- underwater state is known and false, or the pass bypasses before drawing.

If numeric GPU readback is needed, add safe wrappers to
`libpsycho/src/os/windows/directx9.rs` for a 1x1 system-memory surface,
`GetRenderTargetData`, and bounded surface locking. Readback must be diagnostic,
rate-limited, and disabled during normal play.

Files:

- `libpsycho/src/os/windows/directx9.rs`, only for missing safe wrappers;
- `omv/src/backend/mod.rs`;
- `omv/src/backend/fnv.rs`, only after the underwater field is proven;
- `omv/src/effects/atmosphere.rs`;
- `omv/shaders/embedded/atmosphere_debug.hlsl`;
- `omv/src/config.rs`;
- `omv/src/shaders.rs`.

## Work package 4: production settings and fail-closed gate

Replace the current partial `AtmosphereSettings` with explicit component data.

Fog settings:

- enabled;
- quality;
- uniform supplemental density;
- height density;
- height falloff;
- base world height;
- maximum distance;
- scattering albedo;
- heterogeneous noise amount and scale;
- temporal stability and noise speed retained for the later temporal stage;
- debug view.

The production gate requires:

- fog enabled;
- world color copy available;
- valid world INTZ depth and depth direction;
- validated near/far/frustum and world camera transform;
- strict FP16 atmosphere targets available;
- proven source transfer selected;
- exterior state known and exterior true;
- underwater state known and false;
- finite bounded fog settings;
- one atmosphere callback in the current Present epoch.

Missing active fog color may use the validated native horizon color only when
native sky data and exterior state are both available. Otherwise bypass.

`requires_world_color()` becomes true for production fog, not only for debug.
The runtime therefore captures exactly one source-format world copy before the
atmosphere draw.

Do not add a user-facing switch that forces an unproven contract. Diagnostic
overrides may exist only in debug builds and must be labeled unsafe.

## Work package 5: resources and shader variants

Extend `AtmosphereTargets` with:

- reduced `G16R16F` logarithmic nearest/farthest depth, already implemented;
- reduced `A16B16G16R16F` integrated atmosphere;
- optional deterministic, generated, tileable `A8R8G8B8` density-noise texture.

Atmosphere RGB stores linear in-scattered radiance. Alpha stores transmittance.

Quality variants are compile-time shader variants:

| Quality | Scale | Heterogeneous samples |
|---|---:|---:|
| Performance | 4 | 8 |
| High | 2 | 12 |
| Ultra | 2 | 20 |

Compile all variants during `AtmosphereEffect::create`. A selected variant
must never use a runtime-variable large loop.

The generated noise texture avoids an external asset/license dependency. Add
a safe pitch-aware texture upload wrapper rather than calling D3D9 directly
from OMV. Noise is world anchored and static in Phase 2. `noise_speed` does not
animate it until atmosphere temporal history exists.

Target creation is transactional: create every required target first, then
replace the live target set. On any failure retain no partial set and leave
world color unchanged.

## Work package 6: fixed atmosphere shader ABI

Add `atmosphere_integrate.hlsl` with this sampler ABI:

- `s0`: reduced logarithmic depth min/max;
- `s1`: generated density noise.

Integration constants:

- full-resolution dimensions and reciprocals;
- reduced dimensions and reciprocals;
- near, far, reversed-depth flag, and atmosphere distance bound;
- current frustum left/right/bottom/top;
- three validated view-to-world rows including translation;
- camera world position and scale;
- fog density, height density, height falloff, and base height;
- maximum distance, scattering albedo, noise amount, and noise scale;
- linear active fog color and availability;
- linear sky upper/lower/horizon fallback colors;
- exterior/underwater gates and debug data.

Add `atmosphere_compose.hlsl` with this sampler ABI:

- `s0`: source world color;
- `s1`: full-resolution world depth;
- `s2`: reduced depth min/max;
- `s3`: integrated atmosphere.

The ABI is owned in one Rust constant-binding function per pass. Do not reuse
the generic screen-effect register layout or silently overlap fog and lighting
option arrays.

Shader compile tests cover every quality variant and both shaders under
`ps_3_0`.

## Work package 7: supplemental medium integration

Reconstruct a view ray from the proven frustum and transform it through the
validated current camera transform. Terminate at reduced nearest ray distance.
Sky terminates at the bounded atmosphere distance.

Use this medium only:

- optional uniform supplemental density from `density`;
- exponential height density around `base_height`;
- optional low-frequency world-anchored heterogeneity controlled by
  `noise_amount` and `noise_scale`.

Keep native distance fog active. Do not derive a second global extinction term
from native fog start/end/power.

For a homogeneous or analytic-height segment:

- compute optical depth in world units;
- compute transmittance as `exp(-optical_depth)`;
- compute ambient in-scattering as
  `fog_radiance * (1 - transmittance) * scattering_albedo`;
- clamp only physically bounded terms, not source HDR RGB.

Use heterogeneous samples only to modulate the supplemental density. The
midpoint and noise phase are fixed in Phase 2, so stationary output is stable
without temporal history.

Required numerical guards:

- horizontal-ray limit for analytic height integration;
- exponent bounds that avoid INF/NaN;
- nonnegative finite density;
- atmosphere endpoint clamped to the per-frame bound;
- transmittance in `[0, 1]`;
- finite scattering with no silent A8 fallback.

## Work package 8: depth-bilateral composition

For each full-resolution pixel:

1. Decode its full-resolution ray distance.
2. Gather the four neighboring reduced atmosphere taps.
3. Decode each tap's nearest/farthest depth interval.
4. Give a tap zero weight when the full-resolution distance lies outside its
   interval beyond the scale-aware threshold.
5. Combine accepted taps using spatial and depth weights.
6. If no tap is accepted, return source color unchanged rather than leaking
   fog across a silhouette.

After the runtime transfer contract selects the conversion:

1. convert source RGB into the proven linear space;
2. compute `linear_output = linear_source * transmittance + scattering`;
3. convert back into the native world-target transfer;
4. write source alpha exactly unchanged.

Do not saturate HDR RGB before native image space. Debug views may map values
for display, but production output must preserve the validated HDR range.

The compose pass writes directly to the original world target only after depth
reduction and integration succeeded. State-block and render-attachment restore
errors remain first-class failures and are logged once per failure signature.

## Work package 9: runtime, menu, and documentation

Runtime changes:

- pass frame index and the complete atmosphere frame/settings into the effect;
- capture world color whenever production fog or a color debug view needs it;
- keep one-call-per-Present ownership;
- record one reason when the pass bypasses;
- release all new default-pool resources on reset/device replacement;
- leave the original world target active after state restoration.

Menu/config changes:

- expand the debug-view enum and sanitization range;
- label Phase 2 as supplemental fog that preserves native distance fog;
- keep lighting settings present but clearly mark production lighting as the
  following stage;
- remove the current statement that all production atmosphere composition is
  bypassed only after the production gate passes;
- do not change existing user setting names or TOML compatibility.

Documentation changes:

- update `omv/README.md` with the render boundary, limitations, and fallback;
- update `omv/config/omv.toml` comments;
- update the parent volumetric research plan with Phase 2 completion evidence;
- record runtime evidence under `.reports/` during validation, not as guessed
  prose in `analysis/`.

## Work package 10: verification

### Static and build verification

- shader compile tests for depth, integration variants, compose, debug, TAA
  resolve, and TAA depth key;
- unit tests for option packing, quality selection, target matching, history
  invalidation, view-to-world row packing, and finite setting sanitization;
- `cargo fmt --check` for touched Rust files;
- supported build only:

```text
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

OMV must also be built through the repository's normal FNV build path if it is
not part of that workspace command. Never use the configured x86_64 default.

### Runtime contract matrix

Capture a fresh OMV log and controlled A/B images for:

- TAA off/on;
- fog off/on;
- Performance/High/Ultra;
- clear midday, sunrise/sunset, night, overcast, and native fog weather;
- desert horizon and dense near geometry;
- interior/exterior transitions;
- water viewed from above and underwater;
- alpha-tested foliage, particles, smoke, and transparencies;
- stationary camera, slow pan, fast rotation, translation, teleport, and FOV
  change;
- weapon, scopes, VATS, dialogue, menus, and loading screens.

Reject the stage for:

- fog over first-person or UI;
- silhouette halos or clear/fogged edge seams;
- double distance fog;
- screen-space swimming of world noise;
- sky washout, negative output, or clipped HDR highlights;
- changed source alpha;
- underwater application without a proven compatible contract;
- more than one atmosphere execution per Present;
- resource/state leakage after resize, reset, alt-tab, or shader failure.

### Performance accounting

Instrument CPU time and, if supported through safe wrappers, D3D9/DXVK GPU
time separately for:

- world-color capture;
- depth reduction;
- integration;
- composition.

Phase 2 permits exactly one source-format full-resolution world copy, one
reduced depth pass, one reduced integration pass, and one full-resolution
compose pass. It adds no blur and no temporal history copy.

Report measured frame-time deltas for each quality tier instead of claiming a
budget from shader instruction count alone.

## Implementation order and stop points

1. Run and analyze the new Ghidra audit. Stop if underwater ownership or native
   image-space input ownership remains unknown.
2. Repair TAA alpha and validate alpha debug with TAA off/on.
3. Add contract logs and expanded debug views. Stop until the user provides the
   runtime matrix needed to select the transfer and validate depth coverage.
4. Add transactional FP16 targets and fixed integration variants.
5. Add integration debug output without composing onto world color.
6. Validate world anchoring, optical depth, sky, water, and interior gates.
7. Add bilateral production composition with exact alpha preservation.
8. Tune defaults and quality tiers only after correctness passes.
9. Update user-facing documentation and mark Phase 2 complete.

The next stage after this plan is Phase 3 directional volumetric lighting. It
will reuse the Phase 2 medium and composition but must refactor the current
sunshaft mask into a native-color, quality-tiered shaft factor before adding
Henyey-Greenstein directional scattering.

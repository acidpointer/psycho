# FNV atmosphere Phase 2 Slice C feature plan

Date: 2026-07-18

## Outcome

Implement the real supplemental volumetric-fog medium behind OMV's completed
FNV atmosphere foundation. On every valid exterior, above-water world frame,
the new pipeline will reconstruct the current world ray, integrate uniform,
analytic height, and deterministic heterogeneous density, and publish a strict
FP16 reduced-resolution result containing linear in-scattered radiance and
transmittance.

This is a feature-development slice, not another debug-blink investigation.
The known camera/geometry-dependent diagnostic blink is deferred. It does not
block building the integration resource or executing the integration pass.

Slice C does not compose the result into the native world target. Modes 6 and
7 provide an integration preview through the existing diagnostic presentation
path. Production composition remains Slice D because the FNV pre-image-space
RGB transfer is still unproven; that is an independent color-contract gate,
not a reason to postpone the medium implementation.

## Implementation status

Implementation and static verification completed on 2026-07-18. Runtime
acceptance is pending the focused DXVK playtest, so this does not yet close
Slice C or Phase 2.

A fresh 2026-07-18 DXVK log now proves execution of the real medium path:
High quality selected half resolution and 12 samples, the 1720x720 FP16 depth
and integration targets were created, and the integration draw became active
under the valid exterior/above-water contract without shader or D3D failure.
The playtest used debug view 0, so integrated pixel content, anchoring, and
control response remain unobserved. This closes execution ownership, not
visual acceptance.

Implemented:

- safe pitch-aware bulk upload for one managed 64x64 deterministic density
  texture;
- strict `G16R16F` depth plus `A16B16G16R16F` integration target ownership;
- fixed Performance/High/Ultra integration variants with 8/12/20 samples;
- uniform, analytic exponential-height, and world-anchored heterogeneous
  optical-depth integration;
- finite fail-closed output, native fog/horizon color selection, exterior and
  same-epoch underwater gates;
- current-frame optical-depth/transmittance and scattering previews in modes 6
  and 7 with exact source-alpha preservation;
- option ABI, menu labels, config bounds, reset/resize behavior, logs, and
  focused unit coverage.

Verification:

- `cargo fmt --all -- --check` passes;
- `cargo test --target i686-pc-windows-gnu -p omv` passes all 57 tests under
  Wine, including every new `ps_3_0` variant;
- `cargo build --release --target i686-pc-windows-gnu -p syringe -p
  psycho-engine-fixes -p psycho-engine-fixes-helper -p omv` succeeds;
- `git diff --check` passes.

The managed noise is deliberately static in this slice. `noise_speed` and
`temporal_stability` remain serialized but inactive until atmosphere history
owns an animation/reprojection contract.

## Completion criteria

Slice C is complete when:

- `volumetric_fog.enabled` drives a real reduced integration pass whenever the
  complete medium contract is available;
- Performance, High, and Ultra select fixed 8, 12, and 20-sample shader
  variants at quarter, half, and half resolution respectively;
- the result target is `A16B16G16R16F`, with RGB storing linear in-scattered
  radiance and alpha storing transmittance in `[0, 1]`;
- uniform, exponential-height, and world-anchored heterogeneous density all
  respond to their existing settings;
- the medium is bypassed for interiors, unknown/stale underwater state,
  underwater cameras, missing camera transforms, missing color inputs, empty
  density, or resource failure;
- debug mode 6 presents optical depth/transmittance and mode 7 presents
  integrated scattering while copying current source alpha exactly;
- debug mode 0 leaves the native world target bit-for-bit untouched;
- reset, resize, device replacement, quality change, shader failure, and
  target creation failure retain no stale or partial live target set;
- shader tests, unit tests, formatting, and the supported i686 release build
  pass.

The visual blink may still affect preview modes. That is recorded, not treated
as a Slice C failure unless it prevents the integration pass itself from
executing or causes resource/state errors.

## Existing foundation reused unchanged

The slice builds on these completed contracts:

- the post-world, post-TAA, pre-first-person callback;
- at most one atmosphere execution per Present;
- current INTZ world depth and reversed-depth publication;
- camera near/far/frustum and value-copied world transform;
- epoch-tagged underwater publication from `0x004E2120`;
- active native fog color/range/power, sky colors, and exterior state;
- strict `G16R16F` logarithmic nearest/farthest depth reduction;
- source-alpha-preserving FP16 TAA history;
- D3D all-state and render-attachment restoration.

Do not rewrite the depth reducer, move the render phase, read
`0x011C7A59`, retain an engine pointer, or merge this work into the helper DLL.

## Explicit exclusions

Do not include these changes in Slice C:

- production world-color composition or bilateral upsampling;
- a guessed gamma/HDR transfer or forced output alpha;
- directional sun scattering or the volumetric-lighting toggle;
- refactoring the existing sunshaft pipeline;
- true sun/local shadow-map sampling;
- atmosphere temporal history, reprojection, or animated jitter;
- native distance-fog replacement;
- interior or underwater volumetrics;
- runtime state/blink snapshots, GPU readback, or a speculative MSAA fix;
- a new dependency or external texture asset.

Native distance fog remains enabled. The new medium is supplemental.

## Work package 1: complete fog settings and activation

Replace the partial `AtmosphereSettings` extraction with explicit immutable
values copied from the fog source's existing option ABI:

```text
c3 = density, height_density, height_falloff, base_height
c4 = max_distance, scattering_albedo, noise_amount, noise_scale
c5 = noise_speed, temporal_stability, quality, debug_view
```

Store:

- `fog_enabled`;
- `quality` as an internal enum rather than only a scale;
- uniform density;
- height density, falloff, and base height;
- maximum distance;
- scattering albedo;
- noise amount and world scale;
- serialized but inactive noise speed and temporal stability;
- debug view.

Apply finite bounds again at the effect boundary. Config sanitization is not a
render-thread trust boundary because menu values can be rebuilt independently.

Define these predicates explicitly:

- `requires_depth`: fog integration or any atmosphere debug view is active;
- `requires_integration`: fog is enabled and uniform or height density is
  greater than zero;
- `requires_world_color`: a debug view is active; integration by itself does
  not need a world-color copy in Slice C;
- `target_scale`: 4 for Performance, 2 for High and Ultra;
- `sample_count`: 8, 12, or 20, used only to select precompiled shaders.

Do not let `volumetric_lighting` settings silently change the fog density,
quality, or activation gate. Lighting remains the following feature stage.

## Work package 2: deterministic density texture support

Extend `libpsycho/src/os/windows/directx9.rs` with one safe bulk upload method
for a lockable level-0 `A8R8G8B8` texture:

```text
Texture9::write_level0_argb(width, height, pixels: &[u32])
```

The wrapper must:

- obtain and validate level-0 dimensions and `A8R8G8B8` format;
- require exactly `width * height` pixels with checked arithmetic;
- lock level 0 once;
- validate a non-null pointer and pitch of at least `width * 4`;
- copy one row at a time, respecting positive pitch;
- always unlock after a successful lock;
- preserve the first error if validation/copy and unlock both fail;
- expose no raw COM or WinAPI use to OMV.

Make the existing one-pixel writer call the bulk path for a 1x1 texture or
remove it only if all call sites are migrated in the same change. Re-export
`D3DTADDRESS_WRAP` for the noise sampler.

At `AtmosphereEffect::create`, generate one 64x64 deterministic tileable ARGB
density texture in `D3DPOOL_MANAGED`. Use a fixed integer hash/seed and fill
independent channels once. No file asset, runtime RNG, per-frame upload, or
license dependency is permitted.

Sample the texture with wrap addressing. Convert a 3D world position to one
stable 2D lookup using a fixed Z-dependent offset so the result is anchored in
world space without three texture reads per ray sample. Camera position and
frame index must not affect the noise coordinates.

If density-texture creation or upload fails, integration fails closed. Existing
depth-only diagnostics may remain available only if the resource ownership can
stay simple; do not keep a half-created integration pipeline.

## Work package 3: FP16 integration resources and shader variants

At effect creation, verify default-pool render-target texture support for both:

- `D3DFMT_G16R16F` reduced depth;
- `D3DFMT_A16B16G16R16F` integrated atmosphere.

Compile three `atmosphere_integrate.hlsl` variants:

| Variant | Reduction scale | Heterogeneous samples |
|---|---:|---:|
| Performance | 4 | 8 |
| High | 2 | 12 |
| Ultra | 2 | 20 |

Generate each source by prepending compile-time definitions. A large runtime
loop count is forbidden under `ps_3_0`.

Extend `AtmosphereTargets` with an `A16B16G16R16F` integration target beside
the existing `G16R16F` depth target. Target creation is transactional:

1. calculate checked reduced dimensions;
2. create depth texture/surface;
3. create integration texture/surface;
4. construct and replace the live target set only after every step succeeds.

The target match key is full width, full height, and scale. Quality changes
between High and Ultra reuse the same half-resolution targets but select a
different shader. Performance changes recreate targets at quarter resolution.

Keep the existing failed-size retry suppression, but clear it on device
replacement/reset and when the requested scale changes.

## Work package 4: fixed integration shader ABI

Add `omv/shaders/embedded/atmosphere_integrate.hlsl` with:

```text
s0 = reduced logarithmic nearest/farthest depth
s1 = deterministic density texture

c0 = reduced width, height, reciprocal width, reciprocal height
c1 = near, far, reversed-depth flag, atmosphere distance bound
c2 = frustum left, right, bottom, top
c3 = view-to-world row 0 including translation
c4 = view-to-world row 1 including translation
c5 = view-to-world row 2 including translation
c6 = uniform density, height density, height falloff, base height
c7 = maximum distance, scattering albedo, noise amount, noise scale
c8 = linear medium RGB, medium-color availability
c9 = exterior flag, underwater-contract-ready, underwater value, medium-color source
```

Own this packing in one Rust binding function. Do not reuse the generic screen
shader register layout and do not overlap future lighting constants.

Output ABI:

```text
RGB = finite nonnegative linear in-scattered radiance
A   = finite transmittance in [0, 1]
```

Use the same sRGB-to-linear conversion already used by OMV native sky for
native fog or horizon colors. This defines the integration target's internal
space; it does not assert that the native world source uses the same transfer.

## Work package 5: medium integration

For each reduced pixel:

1. Decode the reduced nearest distance using the current atmosphere bound.
2. Clamp the endpoint to `min(nearest, max_distance, distance_bound)`.
3. Reconstruct the normalized view ray from the current frustum.
4. Transform points through the validated current view-to-world rows.
5. Integrate the base medium analytically.
6. Add a fixed-sample heterogeneous correction.
7. Convert optical depth to transmittance and ambient in-scattering.

Base density is:

```text
density(z) = uniform_density
           + height_density * exp(-height_falloff * (z - base_height))
```

The uniform integral is `uniform_density * distance`.

For the height integral, use the closed form along the world-space ray. When
`abs(height_falloff * ray_direction.z * distance)` is small, use the horizontal
limit `density_at_camera_height * distance`. Bound exponential arguments before
evaluation and reject non-finite results.

Heterogeneous sampling uses fixed midpoint positions. At each point:

- evaluate the local nonnegative base density;
- sample the world-anchored density texture;
- remap the sample around zero;
- accumulate only the noise correction to the analytic base integral.

Clamp the final optical depth to a finite exponent-safe range. Then compute:

```text
transmittance = exp(-optical_depth)
scattering = medium_rgb * (1 - transmittance) * scattering_albedo
```

Clamp density, albedo, and transmittance to their physical domains. Do not
saturate FP16 scattering RGB. If any intermediate becomes non-finite, output
identity medium `(0, 0, 0, 1)` for that pixel.

The integration contains no sun phase term, shaft factor, temporal jitter, or
native distance-fog reconstruction.

## Work package 6: CPU gate and pass execution

Add a pure, testable `FogIntegrationGate` with exact outcomes:

- `Disabled`;
- `EmptyMedium`;
- `MissingDepthContract`;
- `MissingWorldTransform`;
- `ExteriorUnknown`;
- `Interior`;
- `UnderwaterUnknown`;
- `Underwater`;
- `MissingMediumColor`;
- `Ready`.

`Ready` requires:

- fog enabled with nonzero uniform or height density;
- the existing depth/camera contract;
- current world transform available;
- exterior known and true;
- underwater hook available, value known, and epoch equal to depth epoch;
- underwater false;
- active fog RGB finite and available, or an exterior native horizon fallback;
- finite bounded settings.

Resolve and linearize the medium color on the CPU once per draw. Prefer active
fog RGB. Use native horizon only when sky data and exterior state are both
valid. Never reuse a prior frame's color or underwater value.

Pass order becomes:

```text
depth reduction
-> fog integration when gate is Ready
-> optional debug presentation
```

Do not run integration for fog disabled or lighting-only configurations. Do not
set `atmosphere_called_this_frame` as proof of integration; record a bounded
gate transition and a successful integration count separately.

Logs are feature-status logs only:

- one target/noise/variant initialization record;
- gate transitions, capped and deduplicated;
- one bounded failure signature for target, shader, bind, draw, or restore
  failure;
- a periodic aggregate only while a new integration preview is selected.

Do not add the deferred blink state recorder in this slice.

## Work package 7: integration preview and user-facing state

Extend `atmosphere_debug.hlsl` with sampler `s2` for integrated atmosphere and
two modes:

- 6: optical-depth/transmittance preview derived from integration alpha;
- 7: tone-mapped integrated scattering preview.

Both modes must:

- be reachable only after successful current-frame integration;
- preserve current source alpha exactly;
- use display mapping only in the preview shader;
- never alter the stored FP16 integration target;
- never present a previous frame's integration after a gate rejection.

Keep modes 1 through 5 unchanged. Reserve mode 8 for the Slice D bilateral tap
acceptance view.

Update:

- config sanitization from range 0..5 to 0..7;
- menu choice labels and option packing;
- `omv.toml` comments;
- the effect description;
- README status.

Do not claim that enabling fog with debug mode 0 visibly composes fog yet.
Describe it as a completed medium-integration stage whose production
composition follows in Slice D.

## Work package 8: failure, reset, and state behavior

Every pass keeps the current all-state block and attachment capture/restore.
The first D3D failure remains authoritative if a later restore also fails.

On any integration failure:

- do not run modes 6 or 7;
- do not write the world target when debug mode is 0;
- do not mark the integration result current;
- retain no engine pointer;
- never reuse the previous integration target as current output.

Dropping `AtmosphereEffect` on device replacement/reset releases the default-
pool depth and integration resources. The managed noise texture is dropped with
the same effect so it cannot remain associated with the old device.

## File-level change map

| File | Required change |
|---|---|
| `libpsycho/src/os/windows/directx9.rs` | Add safe pitch-aware bulk ARGB upload, migrate the one-pixel helper, and export wrap addressing. |
| `omv/src/effects/atmosphere.rs` | Complete settings, gate integration, own noise/FP16 resources and fixed variants, bind the ABI, execute integration, and publish bounded outcomes. |
| `omv/shaders/embedded/atmosphere_integrate.hlsl` | New analytic-height plus fixed heterogeneous integration shader. |
| `omv/shaders/embedded/atmosphere_debug.hlsl` | Add current-frame transmittance and scattering previews while preserving source alpha. |
| `omv/src/config.rs` | Expand the fog debug range and tests; retain all existing TOML fields and inactive temporal values. |
| `omv/src/shaders.rs` | Add preview labels and keep the existing option-register ABI stable. |
| `omv/src/runtime.rs` | Request world color for preview only, distinguish integration success from callback execution, and keep reset ownership. |
| `omv/config/omv.toml` | Document the real integration stage, modes 6/7, and deferred composition/lighting. |
| `omv/README.md` | Document resources, quality tiers, gates, feature status, and limitations. |
| `docs/graphics_fnv_volumetric_fog_phase2_implementation_plan.md` | Record Slice C as the active feature slice and defer blink closure. |
| `docs/graphics_fnv_volumetric_fog_lighting_plan.md` | Update Phase 2 status without advancing directional lighting. |

No change belongs in `psycho-engine-fixes-helper`, `syringe`, PBR shaders, the
native sky renderer, or existing sunshafts.

## Tests and verification

Add focused tests for:

- complete fog-option extraction and finite fallback;
- quality to scale/sample-variant selection;
- integration-gate outcomes and same-epoch underwater enforcement;
- active fog color preference and guarded horizon fallback;
- sRGB-to-linear conversion for zero, threshold, one, negative, NaN, and INF;
- deterministic noise generation, fixed dimensions, and stable seed output;
- bulk upload length/checked-size validation where wrapper logic is testable;
- target matching across size and quality changes;
- debug range and labels 0 through 7;
- scene-input requirements: debug preview needs world color, integration-only
  does not;
- reset/release state and failed-target retry keys;
- compilation of depth scale 2/4, integration 8/12/20, and debug shaders under
  `ps_3_0`.

Run:

```text
cargo fmt --all -- --check
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
git diff --check
```

Always pass the explicit i686 target.

## Runtime handoff

The Slice C playtest is deliberately small:

1. Enable volumetric fog with default High quality.
2. Use mode 6, then mode 7, in one exterior above-water scene.
3. Change height density, base height, noise amount, and noise scale enough to
   see whether the integrated field responds during visible preview periods.
4. Cycle Performance, High, and Ultra and capture a fresh log.
5. Enter an interior and go underwater; the log must transition to bypass and
   no stale integration preview may remain.

If the known blink remains, record it and continue the feature assessment using
the visible intervals and integration outcome logs. Stop only for crashes,
device/resource errors, non-finite output, stale preview after rejection, or an
integration pass that never executes.

## Implementation order and stop points

1. Add the safe bulk upload wrapper and deterministic noise generator tests.
2. Complete settings extraction, quality selection, color resolution, and the
   pure integration gate.
3. Add FP16 target ownership and compile all three integration variants.
4. Implement and bind the fixed integration ABI.
5. Execute depth reduction followed by current-frame integration.
6. Add preview modes 6/7 and update menu/config/README text.
7. Run shader/unit tests and the full supported i686 release build.
8. Perform the small Slice C runtime handoff.
9. Record measured behavior and plan Slice D composition from the resulting
   integration and color-contract evidence.

Do not expand this slice when a stop condition is hit. A missing native value
causes a bounded bypass; an unknown engine contract does not become a shader
assumption.

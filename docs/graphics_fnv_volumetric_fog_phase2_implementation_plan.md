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

## Implementation status

Slices A and B were implemented on 2026-07-17.

Slice A now includes:

- the proven `0x004E2120` `__thiscall` value-copy hook;
- OMV-owned underwater state stamped with the depth backend's frame epoch;
- stale, missing, and hook-unavailable rejection without reading
  `0x011C7A59`;
- strict FP16 TAA color history plus paired `R16F` depth-key history;
- exact current-source alpha preservation on every TAA resolve branch;
- synchronized color/key history creation, invalidation, and index swaps.

Slice B now includes:

- target format/usage/multisample and unvalidated-transfer telemetry;
- world-boundary call-count, depth/camera/transform, fog, exterior,
  underwater-hook/value/epoch, and TAA alpha-history telemetry;
- exact depth-contract bypass reasons;
- debug views for nearest depth, depth span, reconstructed world-height bands,
  source alpha, and negative/overbright HDR range;
- updated menu/config/README text that distinguishes diagnostic fog from the
  later volumetric-lighting phase.

Static verification completed on 2026-07-17:

- `cargo fmt --all -- --check` passes;
- `git diff --check` passes;
- `cargo test --target i686-pc-windows-gnu -p omv` passes all 49 tests under
  Wine;
- `cargo build --release --target i686-pc-windows-gnu -p syringe -p
  psycho-engine-fixes -p psycho-engine-fixes-helper -p omv` succeeds.

The first DXVK playtest log was reviewed on 2026-07-18. It proves:

- the `0x004E2120` underwater publication hook installed;
- above-water publication was known, false, and matched the captured depth
  epoch;
- the world target was `A16B16G16R16F` (`D3DFMT` 113), render-target usage,
  with the active 8x multisample path;
- reversed INTZ depth, camera transform, world-color capture, native fog, sky,
  exterior state, strict FP16 history, and TAA alpha preservation were all
  available together;
- TAA on/off transitions preserved the alpha-ready contract;
- two frames contained a second engine world-boundary invocation, and the
  per-Present guard skipped both second invocations before any atmosphere
  resource or draw work. No frame executed atmosphere more than once.

The playtest used debug view 0, so it cannot yet prove RGB range/transfer,
alpha presentation, world anchoring, depth coverage, or underwater=true.

The second DXVK playtest used the diagnostic views and found a more fundamental
blocker: every atmosphere debug view can rapidly alternate between the debug
output and the ordinary world image as camera position or angle changes. A
nearby fence is a reliable trigger. The fresh log still reports a valid 8x
multisampled FP16 target and valid same-epoch atmosphere inputs, with no draw,
resource, reset, or duplicate-callback error. It does not report silent runtime
lock misses, per-stage outcomes, inherited D3D coverage state, actual surface
identity at native image-space entry, or a later overwrite.

Priority revision on 2026-07-18: the diagnostic blink is deferred so feature
development can continue. Slice C was implemented under the complete plan in
`docs/graphics_fnv_atmosphere_phase2_slice_c_feature_plan.md`. It may build and
execute the reduced FP16 medium integration because that work does not modify
production world color. The blink closure remains required before final Phase
2 acceptance if the symptom survives the feature work.

This priority change does not waive the RGB-transfer contract. Slice C must not
select a transfer or compose production fog. That independent gate remains for
Slice D.

Slice C static implementation completed on 2026-07-18:

- the fog toggle now drives a gated reduced FP16 medium pass;
- Performance, High, and Ultra select fixed quarter/half-resolution 8/12/20
  sample variants;
- the medium combines uniform, analytic exponential-height, and deterministic
  world-anchored heterogeneous density;
- RGB stores nonnegative in-scattered radiance and alpha stores transmittance;
- modes 6 and 7 present current-frame transmittance/optical depth and
  scattering without changing mode-0 world color;
- exterior, current underwater epoch/value, world transform, depth, medium
  color, and finite settings all fail closed.

The Slice C verification pass completed with all 57 OMV tests under Wine, all
new `ps_3_0` variants compiled, the explicit i686 release build succeeded, and
format/diff checks passed. Runtime DXVK acceptance remains pending.

The fresh 2026-07-18 DXVK log now proves the Slice C runtime execution path:
the complete exterior/above-water contract was Ready, High quality selected
half resolution and 12 samples, the 1720x720 FP16 targets were created, and
the integration draw became active without a shader, target, or D3D failure.
Because debug view 0 was selected, this evidence does not validate the
integrated pixels or change production world color.

Slice D is now planned in
`docs/graphics_fnv_atmosphere_phase2_slice_d_visual_composition_ui_plan.md`.
It owns the first production-visible fog composition, the remaining source
transfer closure, conservative depth-bilateral upsampling, and the related
resizable/wrapped OMV menu delivery.

During Slice C and the later blink-closure pass, the remaining user-run DXVK
evidence must show:

1. `Some(true)` underwater, with production still bypassed;
2. stable world-height bands during rotation and translation;
3. identical source-alpha presentation with TAA off and on;
4. whether the HDR-range view observes negative or overbright RGB;
5. usable depth termination for sky, water surfaces, foliage, particles, and
   nearby silhouettes;
6. no state/resource failure while cycling all seven views.

For the repeat pass, capture modes 1 through 7 in one exterior scene. Add mode
1 captures looking across a water surface, underwater, in an interior, and at
foliage or particles; compare mode 4 once with TAA off and once with TAA on;
rotate and translate the camera while observing mode 3; and change height
density, base height, noise amount, and noise scale while modes 6 and 7 are
visible. Provide those captures plus the fresh `omv-latest.log`.

## Contract status entering implementation

The three atmosphere audits now close the static engine-side ownership needed
for Phase 2: the exact native image-space source/destination lineage, the
downstream use of source alpha, the camera-underwater classification, its
value-copy publication point, and water-before-world ordering.

The current implementation already owns the world boundary, validated
camera/depth, active fog color/range/power, sky data, exterior state, strict
FP16 reduced depth, and debug presentation. The remaining gates are
implementation and runtime evidence:

- repair TAA so it preserves the engine world-target alpha channel;
- observe and select the exact RGB transfer/range at the proven pre-native-
  image-space boundary;
- validate water, transparent geometry, and sky behavior in captured INTZ
  depth;
- prove the new underwater publication hook installs and produces the same-
  epoch value during real gameplay.

The native `ISHDRBLENDINSHADER` bytecode reads source alpha during final HDR
composition, while OMV TAA currently replaces that alpha with a private depth
key. Production atmosphere must not build on that violation. Static research
is complete, but production composition remains fail-closed until the runtime
gates pass.

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

## Work package 1: static contracts (complete)

### First audit result

The first audit was run on 2026-07-17. It proves that
`0x00875FD0 -> 0x00B55AC0 -> 0x00B97900` owns the native image-space chain
and that `0x00B97900` ping-pongs an input and output target through enabled
effects. It does not trace the four `0x00875FD0` callers far enough to label
the first source and final destination arguments unambiguously.

The shader-package evidence closes one alpha question:
`ISHDRBLENDINSHADER` samples source alpha, bounds it against `c1.x`, and uses
its reciprocal to scale HDR color before writing a constant output alpha.
`ISHDRADAPT` does not preserve sampled alpha and also writes a constant output
alpha. Therefore OMV must preserve the pre-image-space source alpha exactly;
it cannot use that channel for TAA or atmosphere metadata.

The first audit also proves that `0x004EC800` is entered from the per-water
group loop in `0x004E21B0` only when group fields `+0x5D` and `+0x5E`, a
boolean setting value, and the `0x011C7A59` render mode pass. The two values
published at `0x011F9614` and `0x011F9618` are fog parameters derived from
object fields `+0xA4` and `+0xA8`, not a boolean underwater state. This is
not enough to equate the transaction or either group flag with the camera
being underwater at OMV's post-world boundary.

The remaining gaps are handled by:

`analysis/ghidra/scripts/graphics_fnv_atmosphere_phase2_contract_followup.py`

Expected output:

`analysis/ghidra/output/perf/graphics_fnv_atmosphere_phase2_contract_followup.txt`

Production implementation remains stopped until the follow-up either proves
a stable value-copy underwater boolean or identifies an exact engine point
where OMV can publish one safely for the current Present epoch.

### Follow-up audit result

The follow-up audit was run on 2026-07-17 and closes the render-target
lineage. In every supported Main caller, the first native image-space source
is the rendered texture returned by `0x00872F50`; the final destination is the
render target supplied by that caller. `0x00875FD0` passes those values through
`0x00B55AC0`, and `0x00B97900` starts with the `0x00872F50` target, ping-pongs
enabled effects, and forces the caller target for the last enabled effect.

The follow-up also proves that water-group fields `+0x5D` through `+0x60` are
rebuilt as per-group visibility/pass eligibility. They must not be retained or
read as camera-underwater state. The fog scalars at `0x011F9614` and
`0x011F9618` remain parameter values; zero/zero selects a fallback in two
consumers, but it is not a current-frame active flag.

The actual engine camera classification is `0x011C7A59`. In
`TESWater::RenderReflections` at `0x004E1BC0`, the engine compares current
camera Z with active water height, writes zero for above water and one for
below water, and also writes one for its forced underwater render mode. The
result is copied into native water shader state. A direct read at OMV's world
boundary is still unsafe because early-return paths can leave the global from
an older frame.

The bounded implementation contract is therefore an epoch-tagged value copy:

- publish only after the engine writes the classification for the current
  water/reflection pass;
- store `{frame_epoch, known, underwater}` in OMV-owned synchronized state;
- retain no water-group or camera pointer;
- accept the value only when its epoch matches the world depth/camera epoch;
- treat an absent publication, hook failure, reset, or epoch mismatch as
  unknown and bypass atmosphere composition.

`0x004E2120` is the common post-classification call and current Ghidra output
shows only the above-water, underwater, and explicit fallback callers. Its
exact function signature, prologue, and all-caller set must be confirmed
before using it as the publication detour. That final narrow check is:

`analysis/ghidra/scripts/graphics_fnv_atmosphere_underwater_epoch_publish_audit.py`

Expected output:

`analysis/ghidra/output/perf/graphics_fnv_atmosphere_underwater_epoch_publish_audit.txt`

Do not add a blind `0x011C7A59` reader if this hook contract fails. Choose a
different proven publication point instead.

### Final underwater publication audit result

The final audit was run on 2026-07-17 and closes the last static stop gate.
`0x004E2120` is a 25-byte `__thiscall` leaf with this contract:

```text
void SetWaterShaderUnderwater(void *water_shader_state, u8 underwater)
```

It stores the explicit byte argument at `water_shader_state + 0x167` and
returns with `RET 4`. Its prologue is a normal hookable function prologue, and
Ghidra finds exactly three direct callers:

- `0x004E1D7C`, after writing classified value `1` for below-water or forced
  underwater mode;
- `0x004E1DB1`, after writing classified value `0` for above water;
- `0x008728AE`, the explicit no-water/reflection fallback, passing `0`.

The fallback calls `0x004E2120(0)` before `0x00872930` clears
`0x011C7A59`. Therefore the detour must publish the explicit stack argument;
reading `0x011C7A59` inside the hook would be racy with the proven fallback
ordering and is forbidden.

All classified paths write `0x011C7A59` and pass the same value to
`0x004E2120`. The early returns in `0x004E1BC0` and the non-classified state
path through `0x004E2100` omit `0x004E2120`, so no same-epoch publication
correctly means unknown. `0x008727D0` has only the two supported Main callers,
and both call it before `0x00872F50` creates the rendered world texture and
before `0x00873200` renders the world scene graph.

The implementation is fixed as follows:

- add a `0x004E2120` `InlineHookContainer` in `omv/src/fnv_render.rs` with the
  exact `extern "thiscall" fn(*mut c_void, u8)` ABI;
- call the original function first, then publish the explicit byte as a bool;
- if hook initialization, enablement, or original lookup fails, publish
  nothing and leave the atmosphere underwater contract unknown;
- store only an OMV-owned `WaterClassificationFrame { frame_epoch, known,
  underwater }` in the FNV backend; never retain the `ECX` object pointer;
- stamp publication with the current `FnvDepthResolve::frame_epoch` under the
  existing backend mutex, then accept it only when it equals the captured
  world depth epoch;
- invalidate by epoch advancement at Present completion and explicitly clear
  on backend/device reset;
- log hook availability and classification contract transitions without
  logging every frame.

This closed the original static gates for implementing Phase 2. The later
debug-blink report created a new, bounded state/phase investigation documented
in `docs/graphics_fnv_atmosphere_debug_blink_contract_closure_plan.md`; it does
not reopen the proven underwater publication contract.

### Original audit

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

This gate is now satisfied by the final publication audit above. Implement the
value-copy hook contract; do not replace it with a global reader.

## Complete file-change manifest

These are the planned Phase 2 changes. Files marked new do not currently
exist. No dependency, build-script, or external texture-asset change is
required.

| File | Required change |
|---|---|
| `omv/src/fnv_render.rs` | Install the proven `0x004E2120` hook, call the original with the exact `__thiscall` ABI, publish its explicit byte argument after success, and expose bounded hook-status logging. |
| `omv/src/backend/fnv.rs` | Add OMV-owned epoch-tagged underwater state beside `FnvDepthResolve`, stamp it from the same frame epoch, reject stale values, clear it on release/reset, and add state-transition tests. |
| `omv/src/backend/mod.rs` | Add the public-to-OMV value type for underwater known/value/epoch, include it in `AtmosphereFrame`, and make the production contract require an exact depth-epoch match. |
| `omv/src/effects/temporal_aa.rs` | Split color history from depth-key history, create two strict `R16F` key targets, compile the key shader, keep both history indices transactional, and invalidate both together. |
| `omv/shaders/embedded/aa_temporal.hlsl` | Read the previous key from its own sampler and return the current source alpha unchanged on every branch. |
| `omv/shaders/embedded/aa_temporal_depth_key.hlsl` (new) | Encode the current logarithmic linear-depth rejection key into `R16F` using the same camera/depth convention as TAA resolve. |
| `omv/src/runtime.rs` | Request one world-color copy for production fog, build the complete frame/settings, enforce one call per Present, surface exact bypass reasons, preserve attachment/state restoration, and release every new default-pool resource. |
| `omv/src/effects/atmosphere.rs` | Replace foundation-only settings with the full fog settings, own transactional reduced-depth/integration/noise resources, compile fixed quality variants, execute reduce/integrate/compose, expand diagnostics, and preserve world color on every failure. |
| `omv/shaders/embedded/atmosphere_debug.hlsl` | Add world-height, alpha, HDR-range, optical-depth, scattering, and bilateral-acceptance views while preserving source alpha outside explicitly visualized output. |
| `omv/shaders/embedded/atmosphere_integrate.hlsl` (new) | Reconstruct world rays, integrate uniform/analytic-height/world-noise density with fixed sample counts, and output FP16 scattering plus transmittance. |
| `omv/shaders/embedded/atmosphere_compose.hlsl` (new) | Depth-bilaterally gather reduced atmosphere, compose in the runtime-proven transfer, preserve HDR range, and copy source alpha exactly. |
| `omv/src/config.rs` | Expand the debug enum/range, retain TOML compatibility, sanitize all finite bounds, and keep temporal/noise-speed values serialized but inactive until the later temporal phase. |
| `omv/src/shaders.rs` | Pack the full fog settings without register overlap, expose the expanded debug choices, and update option-packing tests. |
| `libpsycho/src/os/windows/directx9.rs` | Add a safe pitch-aware level-0 ARGB texture upload used by deterministic generated density noise; add diagnostic surface/readback wrappers only if numeric transfer probes prove necessary. |
| `omv/config/omv.toml` | Replace foundation-only comments, document supplemental/native-fog coexistence, document all debug values, and state that volumetric lighting remains a later phase. |
| `omv/README.md` | Document the render boundary, production gate, underwater/interior fallback, alpha/HDR ownership, performance tiers, and known Phase 2 limitations. |
| `docs/graphics_fnv_volumetric_fog_lighting_plan.md` | Record Phase 2 completion evidence and keep Phase 3 lighting/shadow requirements separate after runtime acceptance. |

`omv/shaders/embedded/atmosphere_depth_reduce.hlsl` retains its proven
logarithmic nearest/farthest ABI. Change it only if the runtime depth probes
find a concrete mismatch; do not rewrite it as part of integration work.

The generated `A8R8G8B8` texture is a deterministic tileable density field,
not a screen-space ray-jitter texture. Phase 2 uses fixed ray sample positions.
Animated or per-frame ray jitter waits for atmosphere history in the later
temporal phase.

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
- `omv/src/fnv_render.rs`, for the proven `0x004E2120` value-copy hook;
- `omv/src/backend/fnv.rs`, for epoch-tagged underwater publication;
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
- underwater state known, from `0x004E2120`, for the captured depth epoch and
  false;
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
4. Compare against the tap's nearest distance because Slice C integrates only
   to that endpoint. Use the min/max span to tighten confidence at mixed-depth
   tiles; being merely inside the interval is not sufficient.
5. Give a tap zero weight when its nearest endpoint does not match within the
   bounded absolute/relative threshold.
6. Combine accepted taps using spatial and depth weights.
7. If no tap is accepted, return source color unchanged rather than leaking
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

- install the proven underwater publication hook and feed its epoch-matched
  value into `AtmosphereFrame`;
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
- supported target only, including OMV in the full FNV build:

```text
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
```

`build_fnv.sh` is the build-and-install path for the user-run runtime matrix.
Never use the configured x86_64 default.

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

## Delivery slices and merge gates

### Slice A: native state and alpha correctness

Implement the underwater publication hook and TAA history split together.
This slice may merge only when:

- hook failure leaves underwater state unknown rather than reading a global;
- below-water, above-water, and fallback publications carry the captured depth
  epoch in backend tests;
- all TAA return paths preserve `CurrentColor.a`;
- color and key history cannot swap or invalidate independently;
- shader tests and the supported i686 build pass.

### Slice B: runtime evidence pipeline

Add contract logs and expanded debug views without production composition.
This slice produces the user-run evidence bundle under `.reports/`. Its
original stop gate is now split: source-independent Slice C integration may
proceed, while observed RGB transfer/range, alpha, depth coverage, and
underwater behavior still gate Slice D production composition.

### Slice C: reduced integration

The active implementation contract is
`docs/graphics_fnv_atmosphere_phase2_slice_c_feature_plan.md`.

Add transactional FP16 integration targets, generated density noise, fixed
quality variants, and integration debug output. Do not write integrated fog to
the world target yet. Merge only after world-height and density stay anchored,
all output is finite, and Performance/High/Ultra costs are measured.

### Slice D: production composition

The active implementation contract is
`docs/graphics_fnv_atmosphere_phase2_slice_d_visual_composition_ui_plan.md`.

Add depth-bilateral upsampling and HDR composition behind the complete
fail-closed gate. Merge only after controlled fog off/on captures prove a
visible result with unchanged alpha, no first-person/UI contamination, no
silhouette leaks, and unchanged world color for every rejected contract.

### Slice E: hardening and release evidence

Complete reset/device-change handling, menu text, config comments, README,
parent-plan status, runtime matrix, and per-pass timing. Phase 2 is complete
only after all reject conditions and quality tiers pass on the supported FNV
runtime.

## Implementation order and stop points

1. Add the proven `0x004E2120` hook, epoch-tagged value-copy state, and backend
   tests. At runtime, bypass production composition if the hook is unavailable
   or no classification matches the captured world epoch.
2. Repair TAA alpha and validate alpha debug with TAA off/on.
3. Retain the current contract logs and expanded debug views; defer the known
   presentation blink while Slice C builds source-independent integration.
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

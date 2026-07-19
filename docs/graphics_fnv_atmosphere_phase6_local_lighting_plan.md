# FNV atmosphere Phase 6 local volumetric lighting plan

Date: 2026-07-19

Status: scene-wide zero-shadow ownership correction accepted in game; scalable
shadowless batching and its zero-output texture-binding regression corrected;
all 125 i686 tests pass before runtime performance acceptance.

## Implementation record

The manager-epoch follow-up supersedes the original shadow-selected ownership
model recorded later in this document:

- DeferredInit hooks the complete world light/shadow transaction at
  `0x00871290`. This owner runs when native shadow counts are zero. At return,
  OMV walks the stable scene list at manager `+0xB4` (`next +0`, payload `+8`,
  count `+0xBC`) and copies positional-light scalars only.
- The zero-shadow branch clears manager `+0xC0` shadow candidates and native
  shadow resources, not the `+0xB4` scene list. `0x00B5B880` is conditional and
  is no longer used as the epoch owner.
- OMV scans at most 512 nodes, ranks a fixed 16-light candidate epoch by bounded
  camera contribution, and draws at most two Performance or four High/Ultra
  volumes. Published records retain no list node, manager, camera, or native
  light pointer.
- The native `0x00B9F780` completion hook is optional enrichment. If the engine
  already renders a matching shadow, OMV retains its `BSRenderedTexture` and
  matrices and joins it by copied identity during the same transaction. OMV
  does not enable native shadows or request additional shadow draws.
- A missed optional-shadow `try_lock`, missing shadow hook, unsupported format,
  or missing texture produces the cheaper shadowless shader path. It cannot
  discard or intermittently disable the scene-light epoch. A busy publication
  mailbox preserves the last complete epoch.
- The atmosphere pass analytically clips each light to its ray/sphere interval,
  opaque depth, configured distance, projected scissor, and fixed quality
  budget. It adds local RGB into the existing FP16 integration target while
  preserving its coverage alpha and the single accepted composition.
- R32F and ATI A8R8G8B8 shadows use the proven native projection, Y convention,
  red-channel compare, and format-specific bias. Unsupported or foreign-device
  resources fail closed for that light only.
- Performance, High, and Ultra are deterministic 4/6/10-step variants, compiled
  separately for shadowless batch sizes one through four and native-shadow
  sampling. One to four shadowless lights share a single near/far draw pair,
  depth decode, world-ray reconstruction, constant publication, and FP16 target
  traffic. Every light retains its full sample count and independent sphere
  interval. The render path uses fixed stack storage, no temporal jitter, no
  local history, and no additional render target or scene-color copy.
- Configuration, wrapped ImGui controls, local debug views, rejection and lock
  telemetry, reset ownership, and device validation keep local capture
  independent from the directional-sun toggle.
- Native shadow slots beyond four remain bounded optional-shadow overflow. They
  do not limit scene-wide light enumeration and cannot taint a shadowless epoch.

Static validation covers epoch rollover and busy-owner preservation, explicit
empty replacement, foreign-device invalidation, zero-native-shadow publication,
bounded deterministic ranking, native projection and compare math, ray/sphere
and batched-scissor edge cases, quality-tier energy invariance, constant
shadowless draw count, interior/exterior medium gating, and real D3D compilation
of all fifteen local shader variants. A bytecode regression test also proves
that every fixed-register batch remains inside the recorded shader-model-3
budget. Static validation cannot certify final game pixels, so runtime
acceptance remains.

The first two batched builds were rejected in game despite successful shader
compilation. Capture and draw telemetry remained correct, but all local
production and debug output was zero. The root cause was render-state ordering:
`bind_target` clears texture stages `s0..s4` to prevent render-target feedback,
while the batched path had already bound reduced depth, density noise, and the
optional native shadow. Both near and far draws therefore sampled null inputs.
The production path owns a complete local-layer draw in one helper: bind the
target first, then rebind every input, then draw. A static source-order test
rejects hoisting any local input bind ahead of the target hazard clear.

Fixed `c8..c15` position/color registers and compile-time-expanded light calls
remain useful shader-model-3 hardening; only the inner, fixed sample-count loop
is dynamic. Static shader tests reject relative light-array indexing, but that
ABI was not the cause of the zero-output regression.

The original design record below remains useful for the rendering, composition,
resource lifetime, UI, and quality contracts. Any statement below that makes
native shadow selection the enumeration owner, forbids shadowless production,
or excludes manager `+0xB4` is historical and superseded by this implementation
record.

## Outcome

Add scene-wide positional-light scattering to OMV's existing world atmosphere
pipeline. The normal zero-native-shadow configuration costs exactly two local
draws for one to four visible lights. It works in exteriors and interiors,
shares the active fog or lighting-only medium, optionally uses a native
per-light shadow texture when one already exists, and preserves the accepted
near/far alpha-coverage composition.

This phase is complete only when:

1. A native shadow-casting local light visibly illuminates the participating
   medium inside its radius, including in interiors.
2. Walls and other native shadow casters block the volume using the matching
   native shadow texture and matrix.
3. Fog, directional volumetric lighting, legacy Sunshafts, and local volumes
   remain independent contributions to one atmosphere composition.
4. Disabling local lights restores the current accepted fog and directional
   result exactly and adds no local-light draw or per-frame allocation.
5. Performance quality is suitable for low-end systems, while High and Ultra
   increase bounded sampling quality without changing the physical response.
6. A missing hook, busy non-blocking owner, invalid engine object, unsupported
   shadow format, reset, or device loss can only omit local lighting. It cannot
   corrupt or intermittently disable the existing atmosphere.
7. Every fixed `ps_3_0` shader variant compiles with the real D3D compiler and
   all CPU/state-machine regressions pass before deployment.

Static validation is a deployment gate, not a claim that final runtime pixels
have been observed. After all static gates pass, one feature-first playtest is
still required.

## Proven engine contract

No additional Ghidra run is required before implementation. The authoritative
research establishes the following production boundary:

- `0x00B5B880` walks the selected shadow-candidate list and calls
  `0x00B9F780` for every completed local shadow slot.
- The detour of `0x00B9F780` must call the original first. On return, one
  `ShadowSceneLight` owns a coherent set of finalized data: native light at
  `+0xF8`, composed shadow matrix at `+0x10`, component matrices at `+0x50`
  and `+0x90`, and rendered texture at `+0x10C`.
- The native light supplies world position at `+0x8C..+0x94`, direct-light RGB
  at `+0xD4..+0xDC`, radius at `+0xE0`, and its light dimmer at `+0xC4`.
  `ShadowSceneLight +0xD0` supplies the engine's per-shadow-light intensity or
  transition multiplier. The material-specific `UpdateLights` call multiplier
  is deliberately excluded.
- The slot argument used by `0x00B9F780` is a zero-based index converted by the
  engine to queued slot `index + 0x11`. `0x00B5B880` increments it for every
  selected light and has no four-light upper-bound check; its final loop merely
  clears unused slots until `0x14`. The fixed capacity of four is OMV's bounded
  render budget, not a native maximum.
- `+0x10C` is an intrusive-refcounted `BSRenderedTexture`. Holding one explicit
  reference keeps its texture alive without retaining a `ShadowSceneLight`,
  native light, camera, accumulator, or list node.
- `BSRenderedTexture +0x30` yields texture zero. The already-proven
  `NiTexture +0x24 -> NiDX9TextureData +0x64` chain yields the borrowed
  `IDirect3DBaseTexture9` used by OMV.
- Type `0x2B` is a 1024x1024 two-dimensional texture. Its normal format is
  `D3DFMT_R32F`; the ATI compatibility format is `D3DFMT_A8R8G8B8`.
- Both formats store the same shadow scalar in red. A8R8G8B8 is a quantized red
  value, not packed multi-channel depth.
- The native reader computes:

  `uv.x = 0.5 * shadow.x / shadow.w + 0.5`

  `uv.y = 0.5 - 0.5 * shadow.y / shadow.w`

  and treats the sample as lit when:

  `shadow.z < texture.r + bias`

- The installed shader packages use bias families `0.000195312503` and
  `0.00117187505`. The active high-quality package uses `0.00117187505`.
- Native shadow-map production already runs image-space effect `0x11` on the
  texture. The first OMV implementation therefore uses one exact shadow tap
  per volume sample instead of multiplying every ray step by native 5/9-tap
  PCF cost.

The manager-wide `ShadowSceneNode +0xB4` list is not part of this phase. It has
unresolved insertion/removal lifetime and contains lights without a matched
shadow resource. Production capture occurs only at the coherent
`0x00B9F780` return boundary.

## Hard scope boundary

Included:

- shadow-selected native positional lights;
- a fixed capacity of four coherent light records;
- interiors and exteriors;
- R32F and ATI A8R8G8B8 shadow textures;
- the current fog medium or the lighting-only fallback medium;
- deterministic scissored ray/sphere integration;
- Performance, High, and Ultra fixed budgets;
- bounded diagnostics and comprehensive static tests.

Excluded:

- walking `ShadowSceneNode +0xB4` in production;
- unshadowed arbitrary scene lights;
- cookies, cubemap point shadows, or an inferred spot-light ABI;
- changing native light selection, native shadow quality, or native shadow
  allocation;
- replacing native fog or legacy Sunshafts;
- animated ray jitter, a new temporal history, or motion-vector guesses;
- any helper-plugin, PBR, allocator, or gheap change.

If a captured record is not a proven positional/radius light, it is rejected.
An unshadowed view may exist only as an explicitly labelled debug mode and may
never become the production fallback.

## Engine capture and ownership

### Hook installation

Add a focused `fnv_local_lights` module and install its two inline hooks from
the existing DeferredInit graphics-hook path, after the first staged world
configuration publication. Do not touch this owner from `NVSEPlugin_Load`, a
DLL entry point, TLS callback, or preload callback.

Hook installation is all-or-nothing:

1. Initialize both hook containers.
2. Enable both hooks.
3. Publish `hooks_ready = true` only after both succeed.
4. If either step fails, disable any successfully enabled partner and leave
   local capture unavailable. Fog and directional lighting remain available.

The producer checks one atomic `capture_enabled && hooks_ready` gate before any
engine read. With local lighting disabled, its steady-state work is the branch
and the mandatory original function call only.

### Complete-epoch state machine

Use two preinitialized `parking_lot::Mutex` owners:

- a four-slot staging epoch used only during one `0x00B5B880` traversal;
- a published complete epoch consumed by the world atmosphere transaction.

Their `LazyLock` initialization must be forced during DeferredInit. Render
callbacks use `try_lock` only. Ordinary startup/configuration continues to use
its existing blocking lock.

`0x00B5B880` detour:

1. Try to acquire staging, clear all four slots, store the current render epoch
   and device identity, clear the tainted flag, then release staging.
2. Mark capture active and call the original without holding any OMV lock.
3. Clear capture active with a scope guard even on an early OMV rejection.
4. Try to take the completed staging record. If it is untainted, publish the
   whole epoch with one mailbox replacement. If it is tainted, drop it and keep
   the previous complete publication unchanged.

`0x00B9F780` detour:

1. Always call the original first.
2. Return immediately unless capture is active and enabled.
3. Retain native priority slots `0..=3`. A negative slot or duplicate retained
   slot taints the staging epoch. Any slot `>=4` is a valid native overflow:
   count and ignore it without reading its engine record or invalidating the
   first four.
4. Copy and validate all scalar and matrix values before retaining a texture.
5. Resolve and validate the rendered-texture chain and level-zero description.
6. AddRef the `BSRenderedTexture` only after the record is otherwise complete,
   then place the owned record in its exact slot.

No lock is held across an original engine function, D3D call, atmosphere draw,
or state restoration. A `try_lock` miss never clears a published epoch and
never publishes a partial list. It increments an atomic counter and leaves the
last complete state unchanged. This invariant is tested by deliberately
holding every owner in unit tests; it is not inferred from runtime logs.

### Record validation

Reject one record before AddRef when any of these is true:

- unreadable/null `ShadowSceneLight`, native light, rendered texture,
  `NiTexture`, renderer data, or D3D base texture;
- non-positional native light classification;
- non-finite position, RGB, dimmer, shadow transition, radius, or any copied
  matrix component;
- radius is non-positive;
- all effective RGB components are zero after nonnegative validation;
- texture is not a two-dimensional, single-level 1024x1024 resource;
- texture format is neither R32F nor A8R8G8B8;
- the D3D resource belongs to a different device epoch.

Copy all three matrices for contract completeness and telemetry, but production
sampling uses the composed `+0x10` matrix. Upload its four rows bit-for-bit and
compute each shadow component as a dot product of one row with
`float4(world_position, 1)`, matching the installed `SLS2089` reader bytecode.

The production RGB is native RGB multiplied by the copied native dimmer,
`ShadowSceneLight +0xD0`, and the user's local-light intensity. It remains in
the same direct-light space consumed by native PPLighting; do not apply the
sky/fog extended-sRGB decode to it. Negative and non-finite values are rejected,
while valid HDR values remain overbright within the explicit FP16 safety bound.

### Intrusive reference wrapper

Implement a small non-Clone RAII owner for the retained `BSRenderedTexture`:

- increment the aligned `NiRefObject` count atomically;
- decrement it on the render thread;
- when the count reaches zero, call the proven virtual destructor slot;
- expose only validated texture lookup, raw identity for diagnostics, and
  release-on-drop;
- permit ownership transfer through the private static mailbox because the
  proven refcount is interlocked, but keep D3D lookup, use, replacement, and
  final release on the render/reset path; the wrapper is never `Sync` and is
  never exposed to a configuration worker.

Use Rust atomics for the intrusive count. Do not introduce direct WinAPI calls.
Add only the missing borrowed D3D texture-description helper to `libpsycho` so
OMV can query resource kind, dimensions, levels, and format without taking an
unowned COM reference.

### Consumer and reset behavior

The world pipeline caches the last complete epoch only after a successful
mailbox `try_lock`. A busy mailbox leaves that cache unchanged. A successfully
published empty epoch clears it. Config disable, device change, reset, and
world-pipeline release drain staging, published, and cached references on the
render thread.

Reset joins the existing non-blocking reset transaction. If any involved owner
is busy, return the existing device-lost retry result and do not call the real
Reset yet. A successful Reset cannot occur while OMV retains one of these
rendered textures.

Every publication is tagged with render epoch and D3D device identity. A
different-device record is rejected. Render-epoch arithmetic uses wrapping
subtraction and is regression-tested at `u32::MAX` rollover.

## Medium and contribution gating

Refactor the current exterior-only gate into independently resolved
contributions:

- exterior fog: current accepted fog rules;
- exterior directional light: current accepted sun rules;
- local light: available in both known interiors and exteriors when a complete
  local-light epoch contains at least one usable record;
- underwater or unknown material state: local lighting fails closed with the
  existing atmosphere rules.

Medium selection is exact:

- exterior with volumetric fog enabled: fog density, height term, noise, and
  scattering albedo are shared by sun and local lights;
- exterior without fog: `volumetric_lighting.medium_density` supplies a uniform
  medium for sun and local lights;
- interior local lighting: use the uniform lighting medium, even if the
  exterior fog toggle is enabled;
- no valid fog, sun, or local contribution: do not attenuate or compose the
  scene merely because the master lighting toggle is enabled.

Local lighting must never start a second scene-color composition or add
`medium_density` on top of an active fog medium.

## Rendering architecture

### Reuse the accepted atmosphere buffers

Do not add a full-screen four-light loop, a new full-resolution copy, or a
local-light history. Render local scattering after the existing near and far
base integrations and before the existing composition. Add it directly to the
RGB channels of the existing half/quarter-resolution FP16 near and far
atmosphere targets.

For each accepted light:

1. Compute a conservative reduced-resolution screen scissor on the CPU.
2. Bind its shadow texture and constants once.
3. Draw the near layer inside that scissor.
4. Change only the target and depth-layer selector, then draw the far layer.

Use additive `ONE + ONE` blending, RGB color writes only, alpha writes disabled,
sRGB writes disabled, depth/stencil disabled, and the existing state block for
transactional restoration. Preserving atmosphere alpha preserves the existing
transmittance and near/far composition contract.

At effect creation, query FP16 post-pixel-shader blending support. If it is not
available, mark only the local-light pipeline unavailable. Do not silently fall
back to A8 output, a full-resolution path, or a shader-only unshadowed effect.

No new render target is allocated. Retaining a native shadow texture adds one
reference, not another 1024x1024 texture allocation.

### Conservative scissor

Transform the sphere center into the captured atmosphere camera. If
`center_z - radius <= near_z`, use the whole reduced viewport because the
sphere intersects the camera/near plane. Otherwise project the eight corners
of the view-space bounding cube, take their min/max UV, clip to the viewport,
and expand by one reduced pixel for raster/filter safety.

This box is conservative because it encloses the sphere and all projected
corners have positive depth. It is intentionally a little larger than the
analytic tangent rectangle, but is simpler and cannot cut a volume at steep
FOV or near-plane angles.

Cull only mathematically unavailable work:

- empty/off-screen scissor;
- ray/sphere interval entirely behind the camera;
- sphere entry beyond lighting maximum distance;
- zero effective radiance or empty medium;
- invalid texture/projection contract.

Do not add a camera-angle-dependent heuristic threshold that can make lights
pop. Native slot order is retained. Performance renders the first two valid
native slots; High and Ultra render all four.

### Ray integration

For each reduced pixel, reconstruct the same captured world ray used by the
base atmosphere. Intersect it analytically with the light sphere and clip the
interval to:

- zero/camera near side;
- the selected reduced near or far opaque depth endpoint;
- the configured lighting maximum distance;
- the sphere exit.

An empty or sub-epsilon interval returns zero before any shadow sample.

Use deterministic midpoint samples. There is no frame index, animated jitter,
or local temporal history. World TAA may filter the final composed result, but
Phase 6 does not depend on temporal accumulation for visibility or energy.

At each sample:

1. Evaluate the selected medium density. High/Ultra include the existing
   world-anchored fog variation when fog is the active exterior medium;
   lighting-only and Performance avoid that extra noise fetch.
2. Accumulate Beer-Lambert camera transmittance. Initialize transmittance at
   sphere entry with the analytic uniform/height optical depth, then accumulate
   exact per-step optical depth inside the sphere.
3. Use native point-light falloff
   `saturate(1 - distance_squared / radius_squared)` so the volumetric radius
   matches native direct lighting instead of inventing a second light range.
4. Compute local HG phase with `mu = dot(view_ray, direction_to_light)`. Reuse
   the directional `HG * 4*pi` calibration because native local RGB is also an
   irradiance-scale direct-light value.
5. Project with the copied matrix rows. If `w <= epsilon`, UV is outside
   `[0,1]`, or the projected values are non-finite, treat the sample as
   unshadowed without touching the texture. This avoids native edge-texel smear
   across the volume.
6. Otherwise sample shadow red with point/clamp/no-mip/no-sRGB state and apply
   the proven comparison direction.
7. Add
   `radiance * attenuation * phase * visibility * transmittance *
   (1 - exp(-step_optical_depth)) * albedo`.

R32F uses native high-quality bias `0.00117187505`. A8R8G8B8 uses the maximum
of that bias and one red-channel UNORM quantization step (`1/255`). No public
bias slider is added in this phase.

Clamp only the final per-light FP16 contribution to a documented HDR safety
ceiling of 8192 per channel. With four additive lights this leaves substantial
headroom below FP16 infinity for the existing fog/sun contribution. Do not use
`saturate` on HDR radiance.

## Fixed quality budgets

Quality is a preset, not a runtime-variable shader loop:

| Local quality | Target scale | Max lights | Samples per layer/light | Fog variation | Max local draws |
|---|---:|---:|---:|---|---:|
| Performance | quarter | 2 | 4 | off | 2 shadowless |
| High | half | 4 | 6 | on when fog supplies the medium | 2 shadowless |
| Ultra | half | 4 | 10 | on when fog supplies the medium | 2 shadowless |

The batch shares depth decoding and camera-ray reconstruction and writes each
FP16 near/far target once. Light integration remains physically bounded and
linear inside the shader because every light retains its full quality sample
count. A union scissor bounds the batch, and every per-light sphere miss exits
before noise or scattering samples. Native-shadow-enriched lights remain
separate because their textures differ; with the intended native shadow draws
disabled, all lights use the two-draw batch.

High remains the default. Performance is the explicit low-end path. Ultra
spends its budget on ray integration rather than multiplying every step by
4/9-tap PCF, extra full-screen passes, or history bandwidth.

When fog and local quality disagree, choose the highest requested spatial
resolution for the shared atmosphere targets, but keep fog, shaft, and local
sample counts independently fixed. A Performance local profile must not raise
an otherwise quarter-resolution atmosphere to half resolution.

Performance invariants:

- no heap allocation in either engine hook or per-frame local rendering;
- no per-light texture copy or render-target allocation;
- no full-resolution local ray march;
- no per-pixel engine memory reads;
- only compile-time-bounded light-count and sample-count loops;
- no shadow tap before sphere, depth, projection, and format rejection;
- no local work when disabled or when the complete epoch is empty;
- exactly two local draws for one to four shadowless lights; optional native
  shadow enrichment adds one near/far pair per enriched light.

## Configuration and ImGui

Extend `graphics.embedded_effects.volumetric_lighting` with:

- `local_lights_enabled` (`true` in the production atmosphere preset and independent from directional
  sun lighting; the global graphics switch still owns both);
- `local_lights_intensity` (`1.5` in the production atmosphere preset, sanitized to `0..4`);
- `local_lights_quality` (`high` by default).

Reuse existing `medium_density`, `max_distance`, and `anisotropy`. Do not expose
raw sample counts, maximum light count, shadow bias, scissor threshold, or
format controls.

Add a clearly separated `Local lights` group in ImGui rather than placing more
radio buttons on the existing directional row. It shows the three controls and
read-only current status:

- hooks available/unavailable;
- captured/accepted/rendered counts;
- R32F/A8/rejected-format counts;
- capture, publish, consume, and reset `try_lock` misses;
- selected quality, resolution, sample count, and draw ceiling.

Extend lighting debug choices with local bounds/acceptance, shadow visibility,
and local scattering views. Debug views use the same captured epoch and shader
math; they cannot enable unshadowed production fallback. Config load, reset,
save, embedded option constants, menu editing, and TOML serialization must all
round-trip every new field.

## Failure behavior

- Missing or partially installed hooks: local unavailable; base atmosphere
  unchanged.
- Local-light or global graphics toggle off: producer branch only, published
  resources drained on the render thread, zero local draws. The directional
  lighting toggle controls only the sun contribution.
- Capture/staging `try_lock` busy: taint current traversal, keep previous
  complete publication, never expose partial slots.
- Publish `try_lock` busy: keep previous complete publication.
- Consumer `try_lock` busy: keep the current cached complete epoch.
- Explicit empty epoch: clear local contribution without affecting fog/sun.
- Invalid one-light data or unsupported format: reject that light before draw;
  other valid records remain usable.
- Duplicate retained slot, negative slot, or epoch/device mismatch: reject the
  whole new epoch and keep the previous complete one until a valid/empty epoch
  arrives.
- Native slot `>=4`: count as bounded overflow and publish the coherent first
  four. Never taint an epoch merely because engine shadow-count settings exceed
  OMV's rendering budget.
- Predictable local capability/resource failure: skip local passes and continue
  valid base integration/composition.
- D3D draw/device-lost failure: restore attachments/state and leave the native
  world target unchanged for that failed transaction.
- Interior/exterior, underwater, loading, or camera-contract transition:
  reevaluate contribution gates from copied current-frame values; never reuse a
  stale environment pointer.
- Reset/device change: acquire every owner non-blockingly, release all retained
  textures, then allow Reset; otherwise return device-lost for retry.

Logs are transition-based and rate-limited. Correct output must not depend on a
log being emitted, and lock-busy behavior is validated by tests rather than
diagnosed from the absence of log lines.

## Test plan

### Capture and lifetime state machine

Add inline Rust tests using a fake intrusive resource with counted AddRef and
Release operations:

- original functions are called exactly once in enabled, disabled, invalid,
  and busy paths;
- capture occurs only after the per-light original returns;
- no engine fields are read when capture is disabled or hooks are incomplete;
- valid slots `0..=3` publish in native order;
- duplicate or negative slots taint the whole epoch;
- fifth and later native slots are ignored as overflow while the first four
  still publish;
- null/unreadable chain, invalid classification, zero/negative radius,
  non-finite scalar, non-finite matrix, wrong dimension/levels/type/format, and
  foreign device all reject without leaking a reference;
- staging, publish, and consumer locks deliberately held by the test preserve
  the prior complete state and never expose a partial epoch;
- successful empty publication clears cached lights;
- replacement, disable, reset, and device change release every reference once;
- failed reset ownership returns retry and releases nothing prematurely;
- render epoch wraparound does not misclassify the current publication.

### CPU math regressions

Add pure helpers and exhaustive table/property tests for:

- ray/sphere miss, tangent, camera-inside, camera-behind, near-plane, depth
  clipped, maximum-distance clipped, zero-radius, and extreme-scale cases;
- conservative scissor containment across aspect ratios, asymmetric frusta,
  FOV extremes, near-plane intersection, off-screen spheres, one-pixel spheres,
  and randomized deterministic points on each test sphere;
- exact matrix row upload and shadow projection UV/Y flip;
- `w <= epsilon`, non-finite, and out-of-atlas paths performing no sample;
- native comparison direction and both R32F/A8 bias rules at equality and one
  quantization step around the boundary;
- native radial attenuation at center, radius, and outside radius;
- HG response at `g=-0.8, 0, 0.9`, forward/backward directions, and all finite
  public limits;
- Beer-Lambert integration nonnegativity, monotonicity, convergence as samples
  increase, and approximate energy invariance between quality tiers;
- local-only, fog+local, sun+local, all-three, interior local, underwater, and
  empty-epoch contribution truth tables;
- maximum public color/intensity/density/radius inputs remaining finite and
  below the per-light FP16 ceiling.

### Static shader validation

Add `atmosphere_local_light.hlsl` and compile all Performance/High/Ultra
production and debug variants as `ps_3_0` with the real D3D compiler in the
i686 Wine test run.

Tests must assert:

- fixed compile-time sample counts `4/6/10`, batch sizes `1..4`, and no
  user-controlled loop bound;
- sampler ABI: reduced depth `s0`, optional density noise `s1`, native shadow
  red `s2`;
- constant ABI does not overlap the current atmosphere registers;
- exact row-dot projection, UV transform, comparison direction, bias constants,
  and A8 quantization floor;
- early ray/sphere/depth/projection rejection precedes shadow sampling;
- point/clamp/no-mip/no-sRGB sampler setup;
- output alpha is zero and local draw state writes RGB only;
- finite guards and the 8192 HDR ceiling exist in every variant;
- compiled bytecode remains within `ps_3_0` instruction, sampler, and constant
  limits with an explicit regression budget recorded after the first compile.

### Existing atmosphere regressions

Keep every current shader/unit test and add integration assertions that:

- fog/directional output and shader selection are byte-for-byte unchanged when
  local lights are disabled or unavailable;
- local-only requires depth/color/camera and a nonempty complete light epoch;
- local failure cannot turn a valid fog/sun gate into `Skipped`;
- near and far targets both receive local RGB while their alpha/transmittance is
  preserved;
- the composition shader and accepted alpha-coverage boundary remain unchanged;
- first-person, late alpha, UI, and image-space ordering remain unchanged;
- target scale selection follows the enabled highest-resolution request without
  changing independent sample budgets;
- reset/config busy simulations preserve the last complete configuration and
  local epoch rather than alternating feature state.

### Commands and deployment gate

Run, in order:

1. `cargo fmt --all --check`
2. `cargo test --target i686-pc-windows-gnu -p omv` under the configured Wine
   runner so the real D3D compiler executes every shader test.
3. `cargo build --release --target i686-pc-windows-gnu -p syringe -p
   psycho-engine-fixes -p psycho-engine-fixes-helper -p omv`
4. `git diff --check`

Always pass the explicit i686 target. Do not deploy if a shader variant, unit
test, state-machine edge case, or supported release build fails.

## Exact file plan

| File | Change |
|---|---|
| `omv/src/fnv_local_lights.rs` | New hook pair, fixed staging/published epochs, intrusive texture owner, validation, counters, reset drain, and state-machine tests. |
| `omv/src/fnv_render.rs` | Install/gate the local hook module at the existing DeferredInit scene-hook path and expose current render/device epoch values. |
| `omv/src/startup.rs` | Preserve first owner initialization at DeferredInit; no load-time publication. |
| `omv/src/backend/fnv.rs` | Add validated BSRenderedTexture/NiTexture/D3D lookup helpers and copied local-light value structures; never expose mutable engine lists. |
| `omv/src/backend/mod.rs` | Add typed copied local-light/scalar/matrix records without putting RAII resources into the Copy `AtmosphereFrame`. |
| `libpsycho/src/os/windows/directx9.rs` | Add safe borrowed base-texture kind/level-description and FP16 blend-capability wrappers required by OMV. |
| `omv/src/fnv_world_pipeline.rs` | Cache only complete epochs, preserve them on busy reads, drain on reset/device change, and pass a borrowed light slice into atmosphere draw. |
| `omv/src/effects/atmosphere.rs` | Add independent local contribution gates, interior medium selection, quality budgets, conservative scissor, local shaders/passes, additive RGB-only state, telemetry, and CPU/static tests. |
| `omv/shaders/embedded/atmosphere_local_light.hlsl` | New fixed-count shadowed sphere integration shader with production/debug variants. |
| `omv/shaders/embedded/atmosphere_integrate.hlsl` | Only the minimum ABI/gate changes needed for a local-only base medium; do not put four local lights in this fullscreen shader. |
| `omv/shaders/embedded/atmosphere_compose.hlsl` | No production math change expected; retain the accepted near/far and source-alpha contract. |
| `omv/shaders/embedded/atmosphere_debug.hlsl` | Add accurately labelled local acceptance/status integration where needed. |
| `omv/src/config.rs` | Add/sanitize/serialize local enable, intensity, and quality with backward-compatible defaults. |
| `omv/src/shaders.rs` | Add embedded option ABI, reset/save synchronization, descriptions, and local debug choices. |
| `omv/src/runtime.rs` | Add the separated ImGui local-light group and read-only status without a one-line radio-button overflow. |
| `omv/config/omv.toml` | Ship bounded local defaults. |
| `omv/README.md` | Document native-shadow requirement, quality tiers, interior behavior, and compatibility fallback. |
| `docs/graphics_fnv_volumetric_fog_lighting_plan.md` | Link this complete Phase 6 contract and update phase status. |

No change belongs in `psycho-engine-fixes-helper`, `psycho-engine-fixes`, PBR,
gheap, or the native shadow selector.

## Implementation order and stop gates

1. Add pure record layouts, intrusive owner, raw texture validation, and CPU
   tests. Stop if any runtime field would require an unproven engine pointer or
   if references cannot be balanced in every fake-resource test.
2. Add the paired hooks and complete-epoch state machine. Stop unless partial
   hook installation, every `try_lock` miss, overflow, reset, and device-change
   test is fail-safe.
3. Add configuration, atomic producer gate, serialization, and separated ImGui
   controls. Prove disabled steady state has no capture work.
4. Add CPU projection/scissor/ray/medium helpers and their edge/property tests.
   Stop on any non-conservative scissor or non-finite maximum-input result.
5. Add and statically compile all local shader variants. Stop on any compiler,
   `ps_3_0`, sampler/register, instruction-budget, or source-contract failure.
6. Add FP16 blend capability gating and scissored near/far local draws. Preserve
   alpha and state transactionally; do not alter composition.
7. Refactor contribution gating for interior local lights and all combined
   fog/sun/local truth-table cases.
8. Add telemetry, debug views, documentation, and performance-budget status.
9. Run formatting, every i686 Wine test, the full supported i686 release build,
   and diff checks. Only then build/install for one feature-first playtest.

## One feature-first playtest

Debug views start Off. This single run validates ordinary output first:

1. Interior with one shadowed lamp: visible bounded volume, stable camera pan,
   and wall occlusion.
2. Exterior at night with two to four native shadow lights: correct separate
   volumes without changing sky, PBR exposure, or legacy Sunshafts.
3. Clear daytime fog off/on and directional/local combinations: all components
   coexist; fog strengthens visible scattering instead of weakening it.
4. Cross a light radius, shadow edge, doorway, near plane, and screen edge:
   no pop, full-frame blink, atlas-edge smear, or camera-angle dropout.
5. Stand inside a light sphere and move through it: no NaN, center explosion,
   band reversal, or whole-screen scissor failure.
6. Foliage, fences, particles, water edges, first-person weapon, menus, loading,
   cell transition, FOV change, alt-tab, resize, and device reset: accepted
   world/alpha/first-person ordering remains intact.
7. Toggle local lights alone: current fog and directional lighting do not
   change, retained native resources drain cleanly, and they reappear without
   a one-frame alternating state. Toggle directional sun lighting separately.
8. Compare Performance, High, and Ultra with VRR enabled. Performance must be
   stable on the target low-end setup; High must be the practical default;
   Ultra must visibly reduce integration banding without changing brightness.

Only after ordinary output passes should the same run inspect local bounds,
shadow visibility, and scattering debug views. No separate diagnostics-only
playtest is planned.

## Do not repeat

- Do not walk `ShadowSceneNode +0xB4` or join two mutable engine collections.
- Do not retain a `ShadowSceneLight`, native light, camera, accumulator, or
  list node.
- Do not initialize the new owner or publish its first config from
  `NVSEPlugin_Load`.
- Do not take a blocking lock from either engine hook, reset callback, or
  atmosphere draw.
- Do not clear valid output because `try_lock` failed; preserve the last
  complete state.
- Do not hold a lock while calling an engine original, D3D method, or shader
  draw.
- Do not publish a partial four-light epoch.
- Do not treat A8R8G8B8 as packed depth or sample any channel other than red.
- Do not clamp shadow UV to the atlas edge and then call the result valid.
- Do not add per-step native PCF, a full-screen four-light loop, animated
  jitter, or local history to hide undersampling.
- Do not add local scattering in a second world-color composition or after
  first-person/UI.
- Do not make a local capability failure disable valid fog, directional light,
  or legacy Sunshafts.
- Do not expose raw loop counts or shadow bias as tuning sliders.
- Do not claim static shader compilation proves runtime pixels.

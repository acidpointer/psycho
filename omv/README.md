# Oh My Vegas!

Oh My Vegas! is a Fallout: New Vegas graphics plugin focused on controlled
Direct3D 9 post processing, engine-owned screen-space effects, and native shader
work built around proven renderer contracts.

The short project name is **OMV**. The DLL, config directory, log, and source
crate all use `omv`.

OMV is a separate modification inside the wider **psycho** Rust modding
toolchain. It is not an optional graphics module of Psycho Engine Fixes. Both
mods build in the same Linux-first workspace and use `libpsycho`, which gives
the shared library two very different production workloads: low-level engine
fixes and a complex Direct3D 9 renderer integration.

## Requirements

OMV requires:

- **xNVSE**: required. OMV is an xNVSE plugin.
- **Fallout Shader Loader**, plugin version `131` or newer.
- **Vanilla Plus Terrain**.
- **LOD Flicker Fix**.
- One D3DCompiler DLL visible to the game process:
  `d3dcompiler_47.dll`, `d3dcompiler_46.dll`, `d3dcompiler_43.dll`,
  `d3dcompiler_42.dll`, or `d3dcompiler_41.dll`.
- Fallout: New Vegas or TTW on Direct3D 9.
- Shader Model 3.0 support.

Fallout Shader Loader, Vanilla Plus Terrain and LOD Flicker Fix are direct OMV
dependencies. They provide the shader and terrain contracts which the current
OMV implementation expects.

**New Vegas Reloaded is not a dependency or a supported compatibility target.**
NVR remains useful source/reference material for shader contracts, but OMV does
not guarantee safe co-installation with `NewVegasReloaded.dll`.

## Features

- In-game OMV graphics menu, toggled with `Insert` by default.
- Loose screen-space shader loading from `Data/NVSE/plugins/omv/shaders`.
- Embedded ambient occlusion, contact AO, bloom/HDR, sunshafts, depth of field,
  world-only temporal AA, and selectable Fast FXAA, NFAA, AXAA, DLAA, and SMAA
  spatial anti-aliasing.
- Native PBR and Sky shader ports derived from New Vegas Reloaded, then
  refactored and optimized substantially for OMV.
- Dependency logging for VPT, Fallout Shader Loader, and LOD Flicker Fix.

OMV expects to own its installed graphics hooks. Co-installation with another
native graphics overhaul is not supported unless documented explicitly.

## Depth of Field

OMV depth of field runs after vanilla image-space effects and before final bloom
and UI rendering. It pairs world depth with the persistent World SceneGraph
camera and first-person depth with its render-phase projection. A full-resolution
FP16 circle-of-confusion buffer drives edge-aware half-resolution near/far
gathers, tile-max foreground expansion, and world-only gaze autofocus. `round` is an
aperture-style blur; `soft` reconstructs both near and far layers through a
filtered multiscale pyramid for broad frosted-glass softness.

`respect_vanilla_dof = true` is the compatibility default. Native dialogue,
iron-sight, VATS, and weather DOF keeps ownership while active, and OMV eases its
focus effect back in after native DOF ends. This query is read-only and uses the
existing image-space boundary hook. OMV does not patch native DOF, DepthResolve,
or `RenderEndOfFrameEffects`.

The in-game DOF entry provides Hybrid, Eye, and Souls Soft starting presets.
Quality levels use fixed 12, 24, and 36-tap gather shaders; Soft High and Ultra
also use distinct pyramid reconstruction kernels. FP16 render-target support is
required; unsupported devices bypass the effect rather than silently using a
lower-precision path. Shader bytecode is prepared asynchronously and cached by
source hash. Ordinary effect toggles retain shader objects and targets, so they
neither compile shaders nor reallocate the pipeline.

## Anti-Aliasing

OMV embeds temporal AA plus five spatial anti-aliasing choices. They are
disabled by default. The spatial choices run in the final image-space phase:
Fast FXAA, NFAA, AXAA, two-pass DLAA, and a three-pass, stencil-free, LUT-free
SMAA 1x adaptation. The in-game menu exposes each algorithm's implemented
controls and debug views. Enable one at a time for normal play; stacking is
retained for visual comparison but compounds blur and GPU cost.

Fast FXAA, NFAA, and AXAA read an owned copy of the current backbuffer and write
directly to the final target. DLAA owns one full-resolution intermediate. SMAA
owns full-resolution edge and blend-weight targets. Each shader is compiled
lazily and fails independently. The pipelines recreate resources after device
reset or resolution changes, do not clear or borrow the game's stencil, and are
enclosed by OMV's D3D9 state block.

Temporal AA uses the engine-side contract proven from the FNV render path. OMV
jitters the active world `NiCamera` frustum, captures the matching world depth,
and resolves history before the first-person scene and UI are rendered. It owns
a current-color copy, two full-resolution FP16 color histories, and two paired
R16F depth-key histories. Depth rejection never borrows the engine-owned scene
alpha channel. Capture gaps, large camera cuts, resize, and resource failure
invalidate color and depth-key history together. A newly enabled or resized
pipeline renders an unjittered priming frame; jitter starts only after the depth
convention, camera transform, and temporal shader have all succeeded. The
GShade shader named TAA is a work-in-progress temporal blur, so OMV does not use
it as the temporal implementation.

## Volumetric Atmosphere

OMV owns a world-only atmosphere boundary after native opaque/pre-depth groups
and before the late alpha-to-coverage, sorted-alpha, first-person, and UI
groups. It reduces resolved INTZ depth to strict
`G16R16F` logarithmic nearest/farthest intervals, then integrates a
supplemental uniform, exponential-height, and deterministic world-anchored
heterogeneous medium into an `A16B16G16R16F` target. Performance, High, and
Ultra use fixed 8, 12, and 20-sample variants at quarter, half, and half
resolution. The engine's explicit above/underwater classification is published
as an epoch-tagged value; OMV retains no engine water pointer and rejects stale
or missing publication.

The boundary is the researched split between FNV's `0x00B65AE0` pre-depth
finalizer and `0x00B65C60` post-depth groups. Late foliage uses vendor
alpha-to-coverage (`ATOC`/`A2M0`), which cannot be reconstructed correctly from
one resolved depth sample. Atmosphere therefore composes before that geometry;
native alpha-tested foliage then preserves its own coverage and fog behavior.
World TAA remains after the complete world, so it sees both atmosphere and late
alpha geometry. A missing contract at the early boundary stays pending for the
existing complete-world fallback instead of being recorded as a successful
atmosphere frame.

World TAA, source capture, and atmosphere composition share one focused
nonblocking owner. Present advances an atomic render epoch even when menu or
final-pass work is busy. A busy primary world/depth owner publishes an exact
epoch/target token and gets one retry at first-person entry; a retry that is no
longer safe fails closed before first-person instead of applying late. Reset
uses nonblocking nested ownership and returns device-lost until every affected
owner can release resources without a partial reset. The log emits periodic
`[FNV WORLD] Reliability` counters for playtest acceptance.

Debug view Off depth-bilaterally upsamples the current integration and composes
`linear_source * transmittance + scattering` directly onto the original FP16
world target. The proven pre-native-image-space transfer is decoded and encoded
explicitly as extended sRGB with hardware sRGB states disabled. Negative and
overbright RGB remain unsaturated, source alpha is copied unchanged, and a
full-resolution pixel with no safe nearest-depth tap returns its source color.
The pass also requires the exact render target captured before first-person;
interiors, underwater frames, stale epochs, unsupported targets, and missing
resources fail closed.

Directional volumetric lighting uses the copied native sun direction,
directional/disk colors, daylight, and the exact camera captured with world
depth. It evaluates normalized Henyey-Greenstein single scattering, calibrated
so FNV's irradiance-scale direct light has unit isotropic response, in the same
medium and integration as fog. Combined mode therefore does not double
extinction, and the lighting-only optical-depth response is a lower bound, so
enabling fog cannot weaken directional scattering. A deterministic
quarter-resolution depth mask and fixed
24/40/56-sample blocker-sensitive radial field provide conservative
screen-space shaft visibility. If that optional field is unavailable or the
sun approaches the screen boundary, directional scattering follows the same
continuous edge fade as its visibility field and reaches zero at or beyond the
projection edge. Fog remains valid independently. Legacy
Sunshafts remain an independent, complementary later pass and keep their own
toggle, but now use the same captured-camera/native-sun projection and native
sun color instead of a separate live screen position and scene-brightness
source. Their `Fog visibility gain` control makes a denser active medium
strengthen, rather than suppress, the artistic ray pass. Their native-sun
source response is continuous instead of using a weather-dependent absolute
cutoff. First-person occlusion is required only when first-person geometry was
actually rendered in the current epoch. A missing current depth capture then
fails closed; a third-person frame does not disable the pass. The earlier
atmosphere is naturally covered by first-person geometry drawn afterward.

The atmosphere and legacy Sunshafts full-screen passes explicitly disable the
native renderer's active vendor alpha-to-coverage mode (`ATOC` or `A2M1`) while
their captured D3D9 state blocks are active. Restoring the state block returns
ownership to the native late-alpha pipeline after the OMV draw.

Local volumetric lighting enumerates the engine's scene-wide positional-light
list in interiors and exteriors. It therefore remains functional when native
shadow drawing and both native shadow counts are disabled. OMV ranks and copies
up to 16 scalar-only candidates at the world light/shadow transaction, then
renders at most two lights on Performance or four on High/Ultra. A native
shadow texture, when the engine already produced one, is matched by light
identity and enriches only that volume; OMV never enables or requests an extra
native shadow draw.

Each draw clips integration to the light sphere, opaque scene depth, and a
conservative scissor, then adds scattering to the same FP16 atmosphere result
without changing coverage alpha. Performance, High, and Ultra use deterministic
fixed 4/6/10 sample budgets; the path has no temporal jitter, history texture,
per-frame allocation, additional render target, or scene-color copy. A busy
optional-shadow owner, unsupported shadow resource, or absent shadow hook falls
back to the cheaper shadowless volume and cannot erase the scene-light epoch.

Fog debug views cover reduced nearest depth, depth span, reconstructed
world-height bands, source alpha, negative/overbright HDR range, optical
depth/transmittance, integrated scattering, and production bilateral
acceptance. Lighting adds shaft mask, shaft visibility, phase response,
directional scattering, and combined-result views. Native distance fog remains
enabled. Atmosphere temporal history remains a later motion-aware phase; the
serialized stability value is compatibility-reserved and is not presented as
an active control.

The production wasteland defaults use zero uniform density and `0.0000025`
height density. The fog menu keeps exact zero as a distinct value,
uses logarithmic nonzero density controls, shows the current effective distance
bound and estimated horizontal transmission, and provides a fog-only reset to
the calibrated profile. Higher user values remain available for intentional
heavy-weather presets.

The graphics workbench opens at a compact centered size and can be resized up
to the current viewport work area. Its feature/details panes adapt to the
available width, and radio-button choice groups wrap instead of extending
beyond the details pane. Window size is session-local because OMV does not
write an ImGui ini file.

License and attribution details for the adapted shader sources are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Install Layout

```text
Data/NVSE/plugins/omv.dll
Data/NVSE/plugins/omv/omv.toml
Data/NVSE/plugins/omv/shaders/*.hlsl|*.pso|*.cso|*.toml
```

Config and logs:

```text
Data/NVSE/plugins/omv/omv.toml
<FalloutNV>/omv-latest.log
```

## Shader Layout

Loose user/developer shaders live in:

```text
Data/NVSE/plugins/omv/shaders
```

Source-tree shader layout:

```text
omv/shaders/runtime/     Loose shaders packaged to Data/NVSE/plugins/omv/shaders
omv/shaders/embedded/    HLSL compiled into omv.dll
```

Rust source layout:

```text
omv/src/runtime.rs       Frame orchestration and menu runtime
omv/src/hooks.rs         D3D9 and window hook installation
omv/src/backend/         Fallout NV renderer data access
omv/src/effects/         Engine-owned effect implementations
omv/src/shaders.rs       Loose shader loading and HLSL compilation
```

## Native PBR and Sky

OMV's native PBR and Sky shaders were ported from New Vegas Reloaded, then
significantly improved for OMV's standalone renderer context. NVR supplied the
original shader techniques and visual foundation; OMV owns its own resources,
draw selection, configuration and compatibility behavior.

The ports place especially strong focus on performance:

- shader source is compiled and cached outside the draw hot path;
- replacement resources are prepared before they become visible;
- draw selection uses explicit shader records instead of broad per-frame
  guessing;
- state changes are kept narrow and unsupported draws stay on the original
  game path;
- expensive contract telemetry is disabled during normal gameplay;
- PBR, Sky and the screen-space stack are tuned to work together without the
  complete NVR runtime.

The packaged configuration currently enables Native PBR and Sky. New Vegas
Reloaded remains the source reference, not a runtime dependency or supported
co-installation target.

The log explains whether each renderer feature and dependency initialized
successfully.

## Build

Only the 32-bit FNV target is supported:

```bash
cargo build --release --target i686-pc-windows-gnu -p omv
```

Compile every active shader and generated quality/engine variant through the
runtime D3D compiler path:

```bash
cargo test --target i686-pc-windows-gnu -p omv
```

Cargo runs the Windows test executable through Wine. Shader tests bypass the
runtime bytecode caches, so every test run validates the current HLSL source.

Full workspace install from the repository root:

```bash
./build_fnv.sh
```

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
- Embedded ambient occlusion, contact AO, bloom/HDR, sunshafts, and depth of
  field.
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

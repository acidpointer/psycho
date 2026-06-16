# Oh My Vegas!

Oh My Vegas! is a Fallout: New Vegas graphics plugin focused on controlled
Direct3D 9 post processing, engine-owned screen-space effects, and native shader
work that is gated by proven renderer contracts.

The short project name is **OMV**. The DLL, config directory, log, and source
crate all use `omv`.

## Requirements

OMV requires these NVSE graphics dependencies:

- **xNVSE**: required. OMV is an xNVSE plugin.
- **Fallout Shader Loader**: required for the shader-loader contract used by
  the modern terrain stack. Vanilla Plus Terrain expects plugin version `131` or
  newer.
- **Vanilla Plus Terrain**: required for the close-terrain and terrain-fade
  shader contract OMV is designed to build on.
- **LOD Flicker Fix**: required by the modern VPT terrain stack and detected by
  OMV.

**New Vegas Reloaded is not a dependency or a supported compatibility target.**
NVR remains useful source/reference material for shader contracts, but OMV does
not guarantee safe co-installation with `NewVegasReloaded.dll`.

Runtime requirements:

- Fallout: New Vegas or TTW on Direct3D 9.
- Shader Model 3.0 support.
- One D3DCompiler DLL visible to the game process:
  `d3dcompiler_47.dll`, `46`, `43`, `42`, or `41`.

## Features

- In-game OMV graphics menu, toggled with `Insert` by default.
- Loose screen-space shader loading from `Data/NVSE/plugins/omv/shaders`.
- Embedded ambient occlusion, contact AO, bloom/HDR, and sunshafts.
- Native PBR work for renderer paths whose shader contract is known.
- Dependency logging for VPT, Fallout Shader Loader, and LOD Flicker Fix.

OMV expects to own its installed graphics hooks. Do not install it beside another
native graphics overhaul unless that combination has been tested.

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

## Native PBR Status

Native PBR is contract-gated.

- Object PBR is limited to proven PPLighting object shader families.
- LandLOD uses the VPT terrain register contract and is disabled when that
  contract is unavailable.
- Close terrain PBR must use the VPT/FSL/LODFF contract.
- SI hair, parallax/POM, skin, and terrain point-light passes are separate
  shader contracts and stay vanilla until proven.
- New Vegas Reloaded coexistence is not supported.

The log should always explain whether a feature installed, was disabled by
config, or was blocked by a missing dependency.

## Build

Only the 32-bit FNV target is supported:

```bash
cargo build --release --target i686-pc-windows-gnu -p omv
```

Full workspace install from the repository root:

```bash
./build_fnv.sh
```

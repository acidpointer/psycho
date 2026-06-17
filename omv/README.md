# Oh My Vegas!

Oh My Vegas! is a Fallout: New Vegas graphics plugin focused on controlled
Direct3D 9 post processing, engine-owned screen-space effects, and native shader
work that is gated by proven renderer contracts.

The short project name is **OMV**. The DLL, config directory, log, and source
crate all use `omv`.

## Requirements

OMV requires:

- **xNVSE**: required. OMV is an xNVSE plugin.
- One D3DCompiler DLL visible to the game process:
  `d3dcompiler_47.dll`, `46`, `43`, `42`, or `41`.

OMV detects these terrain-stack plugins:

- **Fallout Shader Loader**: required by the modern terrain stack. Vanilla Plus
  Terrain expects plugin version `131` or newer.
- **Vanilla Plus Terrain**: required for experimental LandLOD and close-terrain
  PBR.
- **LOD Flicker Fix**: required by the modern VPT terrain stack.

Terrain PBR is experimental and disabled by default. LandLOD and close-terrain
PBR also stay disabled when this terrain stack is missing.

**New Vegas Reloaded is not a dependency or a supported compatibility target.**
NVR remains useful source/reference material for shader contracts, but OMV does
not guarantee safe co-installation with `NewVegasReloaded.dll`.

Runtime requirements:

- Fallout: New Vegas or TTW on Direct3D 9.
- Shader Model 3.0 support.

## Features

- In-game OMV graphics menu, toggled with `Insert` by default.
- Loose screen-space shader loading from `Data/NVSE/plugins/omv/shaders`.
- Embedded ambient occlusion, contact AO, bloom/HDR, and sunshafts.
- Native PBR work for object renderer paths whose shader contract is known.
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
- Replacement becomes visible only after all active shader
  contracts are compiled, created, and ready together.
- LandLOD and close terrain PBR are experimental, disabled by default, and
  require the VPT/FSL/LODFF terrain stack when explicitly enabled.
- EnvMap/reflection, skin, terrain fade, projected terrain, parallax/POM, and
  unproven helper terrain rows stay vanilla until proven.
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

# FNV depth resolve routes

## Purpose and user-visible behavior

OMV depth-aware effects need shader-readable world and first-person depth.
Fallout New Vegas renders those views into multisampled D3D9 depth surfaces,
so OMV resolves each selected surface into an `INTZ` texture before an effect
samples it.

The backend now chooses one capability-based route per D3D9 device generation:

1. RESZ when the device exposes the D3D9 RESZ format;
2. NVIDIA NvAPI D3D9 depth copy when RESZ is unavailable and NvAPI can
   initialize;
3. a durable unavailable state when neither route exists.

The workbench reports the selected route or the reason depth is unavailable.
Unsupported depth fails closed: effects that require depth are rejected before
their resources or phase color copy are created. Color-only effects and native
game rendering remain usable.

## Evidence and scope

The supplied read-only reference
`.research/fnv-depth-resolve-main/DepthResolve/main.cpp` directly establishes
the route order and native NvAPI resource lifecycle:

- test RESZ support first;
- use `NvAPI_D3D9_StretchRectEx` only when RESZ is absent;
- register the source depth surface and destination texture;
- retry exactly once when NvAPI returns `NVAPI_UNREGISTERED_RESOURCE`;
- unregister a replaced source and the destination at release.

The tester log
`.reports/omv-latest--performance-bad.log` directly records repeated D3D error
`0x8876086A` from the former RESZ-only path for both world and first-person
depth. It does not identify the tester's GPU or prove that NvAPI will be
available there.

No new FalloutNV.exe address or engine layout was introduced for this change.
OMV retains its previously documented render-target ownership, camera
projection, hook order, and world/first-person capture points. The only new
contract is the device capability route used after OMV has obtained the
existing source surface.

## Architecture and ownership

`omv/src/backend/fnv.rs` owns `FnvDepthResolve`, its current device identity,
the route, two `INTZ` targets, resolved projection metadata, and the RESZ state
block. Route probing is lazy at the first valid device boundary and occurs
once per device generation.

The RESZ path retains the full-state safety contract: capture the state block
and explicitly tracked states, bind the source depth surface, issue the marker
draw, trigger RESZ through `D3DRS_POINTSIZE`, and restore point size, the state
block, and the original depth surface.

The NvAPI path late-loads `nvapi.dll` and obtains functions through
`nvapi_QueryInterface`; OMV neither links nor depends on another depth-resolve
plugin. The function IDs and ABI match the supplied NVIDIA headers/reference:

- `NvAPI_Initialize`: `0x0150E828`;
- `NvAPI_D3D9_RegisterResource`: `0xA064BDFC`;
- `NvAPI_D3D9_UnregisterResource`: `0xBB2B17AA`;
- `NvAPI_D3D9_StretchRectEx`: `0x22DE03AA`.

An `INTZ` target is registered when created. The current source surface is
registered when its pointer changes and the previous source is unregistered.
If the copy returns `NVAPI_UNREGISTERED_RESOURCE` (`-170`), OMV makes
best-effort registrations for both resources and retries the copy once. The
retry result is authoritative. Other NvAPI failures do not loop.

`libpsycho/src/os/windows/directx9.rs` exposes the owned texture's raw
`IDirect3DTexture9` pointer for this registration boundary. All Win32 dynamic
loading remains behind `libpsycho` wrappers.

## Reset, failure, and concurrency

A D3D device identity change releases both targets, unregisters NvAPI
resources, discards the RESZ state block, and returns route selection to
unprobed. Target size/format changes unregister and replace only the affected
target. Release is idempotent.

An unavailable route is cached for the device generation and logged once. OMV
does not repeat capability probing or NvAPI loading every frame. The render
callback performs no blocking file I/O, shader compilation, or retry loop.
Existing nonblocking runtime locks remain unchanged.

Modern DXVK normally exposes RESZ. If RESZ is not exposed and native NvAPI is
also unavailable, the menu advises checking the DXVK version/setup. OMV does
not terminate the game, force a particular DXVK build, or assume that the
presence of a `d3d9.dll` proves a working resolve route.

## Performance and memory

The route probe is one-time per device generation. A successful resolve uses
one destination texture per world/first-person slot. RESZ uses its existing
marker and state restore; NvAPI performs one native copy plus registration
only when resource identity changes, except for the single `-170` recovery
retry. An unavailable route reaches the effect applicability preflight, so
rejected depth-only phases do not allocate a color copy or initialize effect
resources.

## Validation and runtime acceptance

Pure regression tests prove route priority and that only `-170` selects the
registration retry. Runtime source-order tests prove rejected AO, sunshafts,
and depth-of-field work exits before resource creation/copy and that a phase
with only rejected effects allocates no color-copy target.

The supported commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

On 2026-07-27, all 309 OMV tests passed through Wine and the optimized
`i686-pc-windows-gnu` OMV release build completed successfully.

A Proton/DXVK playtest remains required for:

- a RESZ-capable setup, with the menu reporting `RESZ`;
- an NVIDIA setup without RESZ, with the menu reporting `NvAPI`;
- an unsupported setup, with one clear warning and stable color-only effects;
- device reset or resolution change, proving targets are recreated and no
  stale registration is used;
- world and first-person motion, proving depth alignment and absence of state
  leakage.

The code and supplied reference prove ownership and route selection. Only a
runtime playtest can prove a particular Proton/DXVK/NVIDIA stack exposes the
expected capability and produces correct sampled depth.

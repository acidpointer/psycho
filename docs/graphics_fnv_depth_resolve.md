# FNV depth resolve routes

## Purpose and user-visible behavior

OMV depth-aware effects need shader-readable world and first-person depth.
Fallout New Vegas renders those views into multisampled D3D9 depth surfaces,
so OMV resolves each selected surface into an `INTZ` texture before an effect
samples it.

The backend chooses and validates one capability-based route per D3D9 device
generation:

1. RESZ when the device exposes the D3D9 RESZ format;
2. NVIDIA NvAPI D3D9 depth copy when RESZ is unavailable, or when an advertised
   RESZ route operationally rejects the transaction with
   `D3DERR_NOTAVAILABLE`, and NvAPI can initialize;
3. a durable unavailable state when neither route exists.

The workbench reports the selected route or the reason depth is unavailable.
Unsupported depth fails closed: effects that require depth are rejected before
their resources or phase color copy are created. Color-only effects and native
game rendering remain usable.

## Evidence and scope

The primary working reference is NVR:

- `.research/TESReloaded10-master/src/core/RenderManager.cpp`;
- `.research/TESReloaded10-master/src/core/RenderManager.h`;
- `.research/TESReloaded10-master/src/core/TextureManager.cpp`;
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Render.cpp`.

It directly establishes the route, resource, hook, and bounded-state contract:

- test RESZ support first;
- use `NvAPI_D3D9_StretchRectEx` only when RESZ is absent;
- create and retain world and view-model `INTZ` destinations;
- save only FVF, declaration, texture 0, vertex/pixel shaders, stream 0,
  Z-enable, Z-write, and color-write around RESZ, then reset the point-size
  trigger;
- when the native NVIDIA source is itself `INTZ`, obtain its
  `IDirect3DTexture9` container and register/copy that resource rather than the
  level surface;
- otherwise register/copy the standalone source surface.

The secondary
`.research/fnv-depth-resolve-main/DepthResolve/main.cpp` reference establishes
the one-retry behavior for `NVAPI_UNREGISTERED_RESOURCE` and explicit
unregistration at resource replacement/release.

NVR does not select depth behavior from a concrete GPU model or vendor ID. Its
`DXVK` flag is detected and logged during initialization but is not consulted
by `ResolveDepthBuffer`. The working decision is capability-only: exposed RESZ
first, otherwise successfully initialized native NvAPI. OMV preserves that
decision.

The tester log
`.reports/omv-latest--performance-bad.log` directly records repeated D3D error
`0x8876086A` from the former RESZ-only path for both world and first-person
depth. The route probe had succeeded, but every frame still attempted up to
three all-state-block-backed RESZ transactions that could not produce sampled
depth. The log does not identify which D3D call inside the transaction returned
the error, nor does it identify the tester's GPU.

External source provides secondary compatibility context:

- [DXVK's RESZ implementation](https://github.com/doitsujin/dxvk/blob/master/src/d3d9/d3d9_device.cpp)
  dispatches the `D3DRS_POINTSIZE` marker only when the reported D3D9 vendor is
  AMD.
- [DXVK 2.7.1](https://github.com/doitsujin/dxvk/releases/tag/v2.7.1)
  added a Fallout New Vegas vendor override specifically because the NVR
  NVIDIA path calls an unimplemented D3D9 NvAPI function. On NVIDIA hardware,
  that compatibility override deliberately makes the game use the supported
  RESZ path.
- The current
  [DXVK-NVAPI query table](https://github.com/jp7677/dxvk-nvapi/blob/master/src/nvapi_interface.cpp)
  implements `NvAPI_Initialize`, but not
  `NvAPI_D3D9_RegisterResource`, `NvAPI_D3D9_UnregisterResource`, or
  `NvAPI_D3D9_StretchRectEx`.
- [NVIDIA's native API contract](https://docs.nvidia.com/nvapi/group__dx.html)
  documents those D3D9 functions as Windows 10-and-later APIs and requires
  source and destination registration before `StretchRectEx`.

Therefore NvAPI is a native-Windows NVIDIA fallback, not the Proton route.
Loading `nvapi.dll` through DXVK-NVAPI does not imply that D3D9 depth copy is
available. A current DXVK setup is expected to report `RESZ` in OMV even on
physical NVIDIA hardware.

No new FalloutNV.exe address or engine layout was introduced for this change.
OMV retains its previously documented render-target ownership, camera
projection, hook order, and world/first-person capture points. The only new
contract is the device capability route used after OMV has obtained the
existing source surface.

## Architecture and ownership

`omv/src/backend/fnv.rs` owns `FnvDepthResolve`, its current device identity,
the route, two `INTZ` targets, and resolved projection metadata. Route probing
is lazy at the first valid device boundary and occurs once per device
generation.

`libpsycho/src/os/windows/directx9.rs::ReszState9` owns the bounded bindings and
render states proven by NVR. COM bindings are retained through restoration, so
changing texture, shader, declaration, or stream bindings cannot destroy the
saved object. OMV also preserves the incoming point size instead of assuming
NVR's zero reset is always the prior value. The RESZ path captures that
snapshot, retains the original depth attachment, binds the selected source
depth surface, issues the marker draw, restores Z/write states, triggers RESZ
through `D3DRS_POINTSIZE`, then restores point size, bindings, and the original
depth attachment. Every restore is attempted even when an earlier draw/trigger
operation fails.

OMV previously created, captured, and applied a `D3DSBT_ALL` state block for
every RESZ capture in addition to explicit render-state queries. NVR does not
do that. The all-state transaction was unnecessary for the states OMV changes,
added a broad driver state walk to a path reached up to three times per frame,
and introduced another operation that could return the reported
`D3DERR_NOTAVAILABLE`. It has been removed only from RESZ; screen-effect and
world-pipeline transactions retain their independent state blocks.

Capability probing alone is not authoritative. If this complete transaction
returns `D3DERR_NOTAVAILABLE`, OMV releases its RESZ resources, then tries to
initialize native NvAPI. A successful transition recreates and registers the
current target and retries the current capture once through NvAPI. If NvAPI is
unavailable, OMV caches `Unavailable` for the device generation. It never
repeats the rejected RESZ transaction on later captures. Other D3D errors do
not change the route because they can represent a transient device or
state-contract failure rather than absent capability.

The NvAPI path late-loads `nvapi.dll` and obtains functions through
`nvapi_QueryInterface`; OMV neither links nor depends on another depth-resolve
plugin. The function IDs and ABI match the supplied NVIDIA headers/reference:

- `NvAPI_Initialize`: `0x0150E828`;
- `NvAPI_D3D9_RegisterResource`: `0xA064BDFC`;
- `NvAPI_D3D9_UnregisterResource`: `0xBB2B17AA`;
- `NvAPI_D3D9_StretchRectEx`: `0x22DE03AA`.

An `INTZ` target is registered when created. When the current source pointer
changes, OMV retains the source surface. If its format is `INTZ`, OMV first
queries its owning texture and prefers that texture for registration and copy,
matching NVR. A standalone or non-INTZ source uses the retained surface. The
old source resource is unregistered before replacement. If the copy returns
`NVAPI_UNREGISTERED_RESOURCE` (`-170`), OMV makes best-effort registrations for
both resources and retries the copy once. The retry result is authoritative.
Other NvAPI failures do not loop.

All COM retention/container lookup and Win32 dynamic loading remains behind
`libpsycho` wrappers.

## Reset, failure, and concurrency

A D3D device identity change releases both targets and the retained NvAPI
source, unregisters NvAPI resources, and returns route selection to unprobed.
Target size/format changes unregister and replace only the affected target.
Release is idempotent.

An unavailable route is cached for the device generation and logged once. OMV
does not repeat capability probing or NvAPI loading every frame. The render
callback performs no blocking file I/O, shader compilation, or retry loop.
Existing nonblocking runtime locks remain unchanged.

DXVK 2.7.1 contains the Fallout New Vegas vendor override required for RESZ on
NVIDIA hardware. DXVK master also contains the upstream fix for the separate
depth-as-texture regression tracked as
[DXVK #5665](https://github.com/doitsujin/dxvk/issues/5665), but that fix is
newer than the latest 2.7.1 release as of 2026-07-28. An older, overridden, or
otherwise mismatched DXVK configuration can still leave neither RESZ nor D3D9
NvAPI available. In that case the menu advises checking the DXVK
version/setup. OMV does not terminate the game, rewrite DXVK configuration, or
assume that the presence of `d3d9.dll` or `nvapi.dll` proves a working resolve
route.

## Performance and memory

The route probe is one-time per device generation. Operational RESZ rejection
adds at most one native-NvAPI initialization attempt and one current-capture
retry. Later captures either use that working route or return from the cached
unavailable state without the RESZ marker draw or target recreation. A
successful resolve uses one destination texture per world/first-person slot.
RESZ performs NVR's bounded binding/state snapshot instead of a
`D3DSBT_ALL` capture/apply. This removes one all-state capture, one all-state
apply, redundant cull/alpha queries and writes, and the reusable all-state
resource from every active device. NvAPI performs one native copy plus
registration only when resource identity changes, except for the single `-170`
recovery retry. An unavailable route reaches the effect applicability
preflight, so rejected depth-only phases do not allocate a color copy or
initialize effect resources.

## Validation and runtime acceptance

Pure and source-contract regressions prove route priority, that RESZ uses the
bounded snapshot without `D3DSBT_ALL`, that native NvAPI prefers an INTZ
texture container while retaining the surface fallback, that only an active
RESZ route returning the exact `D3DERR_NOTAVAILABLE` code selects operational
fallback, and that only `-170` selects the NvAPI registration retry. Runtime
source-order tests prove rejected AO, sunshafts, and depth-of-field work exits
before resource creation/copy and that a phase with only rejected effects
allocates no color-copy target.

The supported commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

On 2026-07-28, all 342 OMV tests passed through Wine and the optimized
`i686-pc-windows-gnu` OMV build completed successfully.

A Proton/DXVK playtest remains required for:

- a RESZ-capable setup, with the menu reporting `RESZ`;
- native Windows on NVIDIA without RESZ, with the menu reporting `NvAPI`;
- Proton/DXVK on NVIDIA, with the menu reporting `RESZ`;
- an advertised-but-rejected RESZ setup, proving there is one transition
  warning and no repeated RESZ transaction;
- an unsupported setup, with one clear warning and stable color-only effects;
- device reset or resolution change, proving targets are recreated and no
  stale registration is used;
- world and first-person motion, proving depth alignment and absence of state
  leakage;
- a fixed scene A/B on the reported NVIDIA system, proving frame time rather
  than inferring FPS from static call removal.

The code and supplied reference prove ownership and route selection. Only a
runtime playtest can prove a particular Proton/DXVK/NVIDIA stack exposes the
expected capability and produces correct sampled depth.

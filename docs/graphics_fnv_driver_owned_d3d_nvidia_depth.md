# FNV engine-owned D3D lifecycle and NVIDIA depth scheduling

## Purpose and user-visible behavior

This change addresses the unresolved NVIDIA performance failure without
disabling PBR, atmosphere, temporal AA, first-person depth, or any other OMV
effect. It changes ownership and scheduling below the effect layer:

- OMV no longer rewrites the live `IDirect3DDevice9` vtable for Present,
  Reset, SetRenderState, DrawPrimitive, or DrawIndexedPrimitive;
- presentation, reset, and native shader-draw work use Fallout New Vegas
  renderer entry points instead;
- NVIDIA source registration and its texture alias persist for the complete
  D3D device generation;
- immediately consumed depth stages use the NVIDIA texture alias and issue no
  OMV `StretchRectEx` command;
- the coherent world snapshot remains a real copy because the engine later
  overwrites the same physical depth surface with first-person depth;
- when Depth Resolve 1.31 is loaded, OMV borrows its already-produced world
  texture instead of adding duplicate world copies. The OMV provider still
  adds independent first-person coverage, so its feature contract is not
  reduced.

The configured provider remains user-visible:

| Provider | World depth | First-person depth | Physical scheduling |
|---|---|---|---|
| `none` | none | none | OMV issues no depth command. An installed third-party producer remains independent. |
| `fallout_new_vegas` without Depth Resolve | OMV | OMV | NvAPI aliases pre-alpha and terminal first-person depth and copies coherent world depth once. RESZ remains the non-NVIDIA fallback. |
| `fallout_new_vegas` with Depth Resolve | borrowed Depth Resolve texture | OMV | OMV adds no world copy. It adds first-person depth through an NvAPI alias, the persistent NvAPI copy fallback, or one RESZ copy. |
| `depth_resolve` | borrowed Depth Resolve texture | absent in Depth Resolve 1.31 | OMV issues no depth copy. World-only AO retains its established pre-first-person composition path. |

## Why the previous fixes could not solve NVIDIA

### Proven runtime facts

The supplied critical log
`.reports/omv-latest--critical-1fps.log` records 96 active render epochs and
288 OMV RESZ depth operations: exactly three per epoch. The stages are
`PreAlphaWorld`, `CoherentWorld`, and `FirstPerson`. The source surface is
stable (`0x623C91F0` in that run) even though its semantic contents change.
The same log records 192 external attempts, exactly two per epoch.

The one-FPS failure occurs in exteriors and the same machine reports only
40-60 FPS in interiors. A later NVIDIA playtest reported no improvement after
the shader-state correction. Those observations prove that shader correctness
work was not a performance fix. They do not, by themselves, prove which
driver-internal synchronization point consumed the time.

### The missed Depth Resolve NVIDIA branch

`.research/fnv-depth-resolve-main/DepthResolve/main.cpp` is decisive:

- `FinishAccumulating_Standard_PostResolveDepth` calls `ResolveDepth` before
  alpha/water and again after water;
- its RESZ branch emits `D3DRS_POINTSIZE = 0x7FA05000`;
- its NVIDIA branch calls `NvAPI_D3D9_StretchRectEx` directly and emits no RESZ
  marker;
- it exports effect registration, but no pause or producer-control API.

The removed OMV SetRenderState hook could suppress only the marker branch. It
could never see or suppress the two native NvAPI copies. Selecting OMV while
Depth Resolve used NvAPI therefore risked five full-resolution operations per
frame: two external world copies plus OMV pre-alpha, coherent-world, and
first-person copies. Switching the provider label could not remove work that
the loaded third-party DLL continued to submit.

### Driver-owned vtable mutation

Before this change, `omv/src/hooks.rs` replaced five entries in the vtable of
Fallout's live `IDirect3DDevice9`. In particular, every native DrawPrimitive
and DrawIndexedPrimitive call traversed OMV even when the useful replacement
boundary was an engine shader draw. Present, Reset, the optional RESZ marker,
and both primitive families shared that driver-owned table with overlays,
compatibility layers, and the vendor runtime.

Both available NVR generations avoid this ownership model. The older source
creates an owned D3D proxy at device creation; the newer source uses engine
render hooks and leaves its ordinary D3D draw forwarding passive. Neither
patches selected entries in the already-published real device vtable. This is
a correctness difference independent of PBR shader equations.

The NVIDIA-only severity remains a reasoned inference: NVIDIA may serialize or
price one of these ownership/synchronization patterns more severely than AMD.
The code and logs prove OMV's excessive boundaries and the invisible external
NvAPI copies; only a native NVIDIA playtest or GPU trace can prove the final
driver mechanism and measured gain.

## Engine lifecycle contract

The supported executable is `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, image base `0x00400000`.

### Presentation

`NiDX9Renderer::DisplayScene @ 0x00E75000` is renderer vtable slot `+0x184`.
Direct radare2 disassembly proves:

- ECX is saved as the renderer receiver;
- there are no stack arguments and the function returns with plain `ret`;
- it drains the display queue at renderer `+0x900/+0x908` and invokes each
  queued object's display virtual at `+0x50`;
- every exit writes `AL = 1`.

OMV performs its former pre-Present services before the original call, records
completion after it, closes the world-pipeline epoch, and advances the render
epoch. The durable vtable pointer evidence is
`analysis/ghidra/output/perf/graphics_fnv_taa_projection_only_upload_contract_followup.txt`.

### Device recreation

`NiDX9Renderer::Recreate @ 0x00E73EB0` owns the complete reset attempt and
notification order. The caller at `0x004DC360` leaves two width/height values
on the stack after the preceding renderer lookup, moves its return value into
ECX, and calls Recreate. Direct disassembly proves every successful/failure
return is `ret 8`. Return values are 0 for failure, 1 for recovery parameters,
and 2 for the requested parameters.

OMV releases device resources before entering this function and returns the
native failure value 0 when its nonblocking resource owner is busy. It resets
PBR/sky CPU state before the original call and queries the renderer's current
device after a successful recreation. Evidence:
`analysis/ghidra/output/crash/crash_20260715_phase10_exit_blocking_boundary_followup.txt`.

### Native shader draw

The common shader method at `0x00E812F0` is published by PPLighting, sky,
terrain/vegetation, and other shader vtables at slot `+0x6C`. It is a
`__thiscall` function with four explicit stack arguments and `ret 0x10`.
It performs the renderer stream/index/draw work and returns the fourth
argument. OMV prepares PBR and sky immediately before the original method and
closes both scopes immediately afterward.

The authoritative function/vtable evidence is:

- `analysis/ghidra/output/perf/graphics_fnv_pbr_shader_virtual_interface_followup_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_pbr_continuity_draw_resource_contract_closure.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_pbr_selector_setup_vtable_deep_audit.txt`.

All three lifecycle/draw hooks are prepared and enabled synchronously from
xNVSE DeferredInit. They stay resident. Native sky's engine constants hook is
also resident after its one DeferredInit installation. Feature toggles publish
cheap atomic gates; they do not rewrite executable code or a COM vtable from a
render callback. WndProc interposition remains a separate Win32 menu-input
concern.

## NVIDIA depth resource contract

The supplied NVIDIA headers document
`NvAPI_D3D9_AliasSurfaceAsTexture` with query-interface ID `0xE5CEAE41`.
The exact ID also appears in
`.research/fnv-depth-resolve-main/external/nvapi/nvapi_interface.h`. The API:

- requires an NvAPI-registered surface;
- returns an owned `IDirect3DTexture9` alias that can be bound by SetTexture;
- requires the alias to be unbound before rendering to the surface again;
- resolves an MSAA surface on use with the default flag;
- offers `USE_SUPER` for direct multisample access but explicitly describes it
  as much slower.

OMV registers the surface itself, not an INTZ texture container, because that
is the alias API's exact contract. Registration occurs only when the source
surface identity changes. The alias is created once, retained as an owned COM
reference, and reused until source replacement or device reset. The public
`Texture9::adopt_raw` wrapper consumes exactly the reference returned through
the NvAPI out pointer without first retaining that raw texture pointer; its
separate base-interface reference remains normally balanced by the wrapper.

### Why only two stages may alias

The log proves that world and first-person rendering reuse the same physical
surface. Semantic timing therefore controls whether a live alias is correct:

1. `PreAlphaWorld` is sampled immediately by OMV atmosphere before native
   alpha continues. The atmosphere transaction detaches the depth attachment,
   binds the alias, and restores its full D3D state block before returning.
   No OMV snapshot must survive later writes.
2. `CoherentWorld` must remain world depth while first-person rendering clears
   and overwrites the source surface. It therefore requires one private INTZ
   destination and one `NvAPI_D3D9_StretchRectEx` copy.
3. `FirstPerson` is captured after the last first-person depth write and is
   consumed by later image-space transactions before the next frame writes the
   surface. It can use the persistent alias.

Aliasing coherent world depth would silently turn the stored world texture
into first-person depth and break AO, TAA, motion blur, atmosphere, and custom
shader reconstruction. The remaining copy is a correctness requirement, not
an unoptimized duplicate.

On MSAA, NVIDIA may still perform an internal resolve when the alias is used.
The optimization removes OMV's explicit copy command and destination for the
two alias stages; it does not claim zero GPU work inside the proprietary
driver. OMV intentionally does not select `USE_SUPER` because NVIDIA documents
that mode as much slower.

### Route selection and recovery

OMV probes the complete NvAPI capability first. A valid copied route requires
Initialize, RegisterResource, UnregisterResource, and StretchRectEx;
AliasSurfaceAsTexture upgrades that route with two stages that issue no
explicit OMV copy command. If the copied route is unavailable, OMV falls back
to the live device's RESZ capability. This capability-based order makes native
NVIDIA prefer NvAPI even if its driver also advertises RESZ, while AMD and
current Proton/DXVK remain on RESZ when D3D9 NvAPI is not implemented.

The source and coherent destination are registered once per identity. A
`NVAPI_UNREGISTERED_RESOURCE` result permits one bounded re-registration and
one retry. Other failures do not loop. An alias-creation failure is cached for
the exact source surface and uses the persistent registered-copy route until
the source identity changes; setup is not retried every frame. Telemetry
counts actual register calls, alias creations, one-time alias fallbacks,
StretchRectEx calls, and StretchRectEx retries rather than logical capture
requests.

## Depth Resolve coexistence

Depth Resolve remains the allocation/reset owner of its shared INTZ texture.
OMV detects its stable public effect-registration exports, calls the patched
`ImageSpaceManager::GetDepthTexture @ 0x00B54090`, validates the complete
`NiTexture -> NiDX9TextureData -> IDirect3DTexture9` chain, retains the COM
texture, and verifies INTZ format and dimensions.

At OMV's pre-alpha boundary, Depth Resolve's pre-water copy has completed. At
the post-world boundary, its post-water copy has completed. Both
`fallout_new_vegas` and `depth_resolve` can therefore borrow the current world
texture without another GPU command. The former still resolves or aliases
first-person depth; the latter retains its explicit world-only behavior.

OMV cannot pause Depth Resolve and no longer pretends SetRenderState can
suppress its NVIDIA branch. No Depth Resolve code, callsite, data, or device
vtable is patched. This is capability-based and version-agnostic at the public
provider boundary.

## Reset, failure, concurrency, and cost

Render callbacks remain `try_lock`-only. There is no file I/O, compilation,
blocking wait, allocation, or repeated capability query in the depth hot path.
Alias creation and destination allocation occur only on first use or identity
change.

Recreate releases captures, private targets, alias ownership, and source
registration before the engine's reset notifications run. Shared Depth
Resolve textures are retained but never unregistered by OMV. A new device
generation probes routes and resources lazily again.

Expected OMV commands per applicable frame are:

| Environment | Pre-alpha | Coherent world | First-person |
|---|---:|---:|---:|
| native NVIDIA, no Depth Resolve | alias use | 1 StretchRectEx | alias use |
| native NVIDIA, Depth Resolve loaded, OMV provider | borrowed | borrowed | alias use |
| RESZ fallback, no Depth Resolve | 1 RESZ | 1 RESZ | 1 RESZ |
| RESZ fallback, Depth Resolve loaded, OMV provider | borrowed | borrowed | 1 RESZ |
| Depth Resolve provider | borrowed | borrowed | unavailable by provider contract |

Depth Resolve itself still performs its two designed world copies. The table
counts OMV commands only.

## Validation and acceptance

The 2026-08-04 regression suite passed all 442 OMV tests under Wine:

```bash
cargo test --target i686-pc-windows-gnu -p omv
```

All 27 affected `libpsycho` unit tests also pass. Its separate doctest phase
still reports the unrelated existing overflowing literal in
`libpsycho/src/logger/impl.rs`; this change does not modify that file. The
supported optimized OMV release build completes successfully.

Regression contracts prove:

- OMV graphics hooks contain no `VmtHook` or D3D device-vtable constants;
- DisplayScene orders OMV pre-presentation work, native work, then completion;
- the engine shader draw closes PBR after the native draw;
- the OMV provider remains active with external NvAPI world production and
  retains first-person coverage;
- NvAPI prefers the alias route over advertised RESZ;
- only pre-alpha and first-person stages alias;
- coherent world remains the single copied NVIDIA snapshot;
- alias setup registers the exact source surface;
- only status `-170` permits a bounded registration retry;
- alias rejection is cached for the current surface instead of retried per
  frame;
- provider switching never requests driver-vtable interposition;
- native-sky runtime toggles keep its engine hook resident.

Compilation and source contracts cannot prove FPS, proprietary driver
synchronization, or image correctness. Required runtime acceptance is:

- native Windows NVIDIA, full PBR and the complete effect set enabled;
- exterior and interior frame-time measurements, not only Present count;
- workbench counters showing alias creation once per stable source, register
  calls stable after warmup, one coherent StretchRectEx per applicable frame,
  and zero StretchRectEx retries in steady state;
- correct pre-alpha atmosphere, world TAA/AO/motion blur, and first-person
  exclusion with camera and weapon motion;
- device reset and resolution change without stale aliases or registration;
- Depth Resolve loaded with OMV provider, proving external world snapshots rise
  while OMV world physical-copy counters remain unchanged;
- Proton/DXVK, proving the unavailable D3D9 alias capability cleanly selects
  RESZ and preserves the working Linux behavior.

The 2026-08-04 local Proton/Wine 11 playtest satisfies the last acceptance
item and exercises the new engine-owned hooks. The deployed
`FalloutNV/omv-latest.log` identifies the dirty test build, records
`d3d_device_vtable=not-installed`, `draw_hooks=engine-owned`, and keeps every
pipeline failure/busy/retry counter at zero. The exterior run advanced from
4,800 to 13,200 DisplayScene boundaries in 75.529 seconds (about 111.2 per
second) at 3440x1440, including a final sustained native-PBR-enabled interval.
Depth Resolve was loaded: OMV borrowed exactly two external world
publications per frame, issued zero pre-alpha/coherent world copies, and
issued exactly one first-person RESZ copy per frame. Its companion log reports
`DXVK status: 1`, `RESZ status: 1`, and `NVAPI status: 0`; all OMV NvAPI
counters consequently remained zero.

This playtest proves the rewritten ownership and RESZ coexistence path retain
the known healthy Proton behavior. It does not exercise native Windows D3D9
NvAPI, even if Proton selected a physical NVIDIA adapter. Native Windows
NVIDIA exterior/interior performance, persistent alias counters, reset, and
image acceptance therefore remain unverified.

# ENB reference depth transport

## Conclusion and scope

The supplied ENB 0.451 wrapper uses an owned INTZ depth texture as the game's
temporary depth attachment, then samples it into an R32F render target. The
traced transport does not invoke RESZ or NvAPI. Its graphics path forces
single-sample device presentation, render targets and depth surfaces.

This establishes a concrete alternative to replacing Gamebryo depth-resource
objects: substitute the D3D attachment during the required rendering interval.
It does not establish OMV's safe insertion interval, complete geometry/stencil
coverage, or initial MSAA transition. The subsequent FNV audit proves a
zero-clear world-target rebind, so restoring the displaced depth after each
temporary scope is insufficient. Persistent identity and retained-resource
MSAA rollback remain FNV contracts to complete in
the [portable transport plan](graphics_fnv_portable_depth_transport.md).

This is a focused reverse engineering of the depth pipeline, not a complete
audit of ENB's memory manager, host process, renderer or security. No claim
about harmfulness, abandonment or newest upstream release follows from it.
The supplied readme identifies 0.451 and requires HDR with hardware AA off.

## Evidence identity and recovery

Reference: `.research/ENB WrapperVersion/d3d9.dll`, PE32 x86, preferred base
`0x10000000`. Exact identity, recovery recipe and instruction evidence are in
the [radare2 audit](../analysis/ghidra/output/perf/graphics_fnv_enb_depth_radare2_audit.txt).
All ENB addresses below belong to that reference, not FalloutNV.exe. Do not
reuse them as OMV hook addresses.

The DLL is packed. The inspected executable image was recovered by emulating
only its verified decompression/filter and relocation instruction ranges in
Unicorn 2.1.4. Import resolution and the original entry point were not executed.
Synthetic PE section/import metadata enabled radare2 navigation while keeping
original code/data RVAs. Derived images and decoded effect text stayed in
`/tmp`; original reference files were not modified or loaded into Wine.

Radare2 MCP disassembly is the primary evidence. Its inferred stack-variable
names, prototypes and decompiler arguments are unreliable here; conclusions
use instruction operands, stack accounting and documented D3D9 COM slots.
Supplementary objdump output preserves literal stack offsets for MSAA fields.

## Device and resource ownership

`Direct3DCreate9` at `0x10008A80` calls the selected real provider through
`0x101BA17C` and returns an ENB IDirect3D9 wrapper. Its CreateDevice method at
`0x100085C0` forwards to the real provider. Constructor `0x100082F0` replaces
the returned device pointer with ENB's wrapper and stores the real device at
wrapper `+0x08`. Device wrapper vtable: `0x1009D04C`.

This is one real device with an interception layer. ENB does not manufacture a
second device and share depth across devices, nor does its depth route need
to replace native Gamebryo renderer-data objects.

Resource setup `0x10024760` creates:

| Resource | Creation evidence | Ownership |
|---|---|---|
| INTZ texture | `CreateTexture` at `0x100248D8`: scene dimensions, one level, DEPTHSTENCIL usage, DEFAULT pool, format `0x5A544E49` | Texture global `0x101C3980`; level-zero surface `0x101C3984` |
| Depth snapshot | `CreateTexture` at `0x10024B50`: same dimensions, one level, RENDERTARGET usage, DEFAULT pool, format 114 (R32F) | Texture `0x101C3AD8`; surface `0x101C3ADC` |
| Temporarily displaced depth | Real `GetDepthStencilSurface` at `0x1000CF08` | Saved COM reference at device wrapper `+0x18` |

The resource setup obtains the render-target dimensions. These are ordinary
in-process COM resources; the texture creation's shared-handle argument is
null. The [CreateTexture contract](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-createtexture)
has no multisample parameter. R32F and the HDR target format below are
identified by the [D3DFORMAT enumeration](https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dformat).

## Attachment and capture sequence

1. **Recognize the target.** Wrapped `SetRenderTarget`, `0x10009E70`, examines
   the incoming surface description. Scene-sized format 113
   (A16B16G16R16F) sets the HDR-target flag at `0x101C34B0`.
2. **Replace depth before an eligible indexed draw.** Wrapped
   `DrawIndexedPrimitive`, `0x1000CE00`, checks that flag, attachment status
   and the owned surface. It saves the current depth surface, binds INTZ
   at `0x1000CF28`, and, on successful binding, clears depth to 1 at
   `0x1000CF5E`. Clear flags are ZBUFFER only; this insertion does not copy
   existing depth or initialize stencil. Subsequent forwarded geometry writes
   directly into INTZ. The normal draw tail reaches helper `0x1000CC80`, which
   calls the real device's DrawIndexedPrimitive slot.
3. **Preserve depth before later rendering destroys it.** Capture function
   `0x10019B20` is called from eligible SetRenderTarget, Clear and indexed-draw
   paths. A capture-done flag at `0x101C3528` suppresses repeats. The indexed
   path also tests identifier `0x24B778AA`; its semantic game-pass identity is
   not established by this audit. These are ENB pipeline heuristics, not proof
   of OMV's pre-alpha, coherent-world or first-person boundaries.
4. **Sample into independent storage.** Capture saves RT/depth state, unbinds
   depth at `0x10019DEC`, binds the R32F surface at `0x10019E97`, selects effect
   technique `BlitX1` at `0x10019F1D`, binds the INTZ texture to sampler zero
   at `0x10019F72`, and draws a two-triangle fan at `0x10019FB3`.
5. **Restore.** The capture routine restores render targets and the saved
   depth attachment (`0x1001A15B`). Leaving the classified HDR target restores
   the displaced game surface, releases the saved reference and clears ENB's
   active-attachment flag (`0x1000A003` through `0x1000A017`). The explicit
   SetDepthStencilSurface wrapper also restores/releases the displaced
   surface before forwarding the requested attachment. Its flag handling is
   not identical to SetRenderTarget; do not copy this as a proven general
   ownership state machine.

The snapshot source is passed directly from global `0x101C3980`. Its R32F
result reaches effects, for example `AOtexOrigDepth` at `0x10011225`.
Present wrapper `0x100090B0` invokes frame helper `0x10024130`; that helper
clears capture-done and depth-used flags at `0x100244B3` and `0x100244E5`.

The embedded effect input is recoverable directly from verified instructions:
`0x1002BA65` reads the bytes at `0x1016F3B8`, rotates each byte by four bits,
and produces the buffer passed to D3DXCreateEffect at `0x1002BB31`. BlitX1's
pixel shader samples sampler zero, sets alpha to one and outputs the sampled
value. It does not linearize or reconstruct depth. R32F retains its red
component. This establishes the transport arithmetic; it does not prove GPU
pixel output, sampler/texel alignment or compatibility with every backend.

## MSAA and reset

Global `0x101C35F8` is the parsed `UseENBoostWithoutGraphics` setting, as
shown by its configuration read at `0x10020D7D`. When it is zero, ENB clears
sample type and quality in these API paths:

| Boundary | Evidence |
|---|---|
| CreateDevice | Copies the 56-byte presentation structure at `0x10008690`; clears copied offsets +0x10/+0x14 at `0x1000883A`/`0x1000883E` |
| Reset | Copies presentation at `0x10008EF2`; clears +0x10/+0x14 at `0x10008F1F`/`0x10008F23` |
| CreateRenderTarget | Clears sample-type/quality arguments at `0x100098EE`/`0x100098F2` |
| CreateDepthStencilSurface | Clears the same arguments at `0x10009A4E`/`0x10009A52` |

The [presentation layout](https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dpresent-parameters)
identifies these fields as MultiSampleType and MultiSampleQuality. This is
actual allocation policy, not the MULTISAMPLEANTIALIAS render-state toggle.
It does not prove that ENB updates all of FNV's internal MSAA bookkeeping;
the supplied readme independently requires users to disable hardware AA.

Wrapped Reset `0x10008ED0` runs resource teardown through `0x10022C30` before
calling real Reset at `0x1000907B`. Cleanup `0x10027520` releases the owned
INTZ surface and texture at `0x100275F2` and `0x10027609`, nulling their globals.
It also releases snapshot resources. Successful real Reset invokes
`0x10022C70`, which calls resource setup again. Initial device construction
uses `0x10022BF0` to allocate the same resources.

That wrapper observes Reset calls passing through its device interface,
regardless of which engine caller initiates them. OMV's existing single
native call-site hook does not provide equivalent coverage; use the shared
native reset notifications already established in the portable plan.
ENB's global flags and partial allocation handling do not constitute a
proven multi-device, concurrent or failure-atomic design.

## Consequences for OMV

- Keep the owned single-sample INTZ plus R32F snapshot architecture. ENB
  provides direct binary evidence for it, without a vendor resolve or
  backend-specific interop path.
- Evaluate **temporary attachment substitution first**, before requiring
  replacement of native depth-object metadata. It can avoid asking FNV's
  format converter to describe INTZ, provided the required interval never
  depends on the displaced attachment's pixels and every rebind/cache boundary
  is handled. Those conditions need FNV evidence; ENB alone does not prove them.
- Use OMV's semantic engine boundaries. Do not import ENB's HDR-only target
  classifier, shader identifiers, global flags or depth-only initialization
  as substitutes for complete world/first-person/stencil coverage.
- Keep initial single-sample conversion and reset coverage as separate work.
  ENB intercepts creation from the start. Its approach does not establish a
  safe post-DeferredInit retrofit for OMV, or prove that migrating to Syringe
  is necessary. An earlier loader permits earlier interception; it does not
  itself implement the ownership, COM, startup or rendering contracts.
- INTZ remains a queried driver-format extension. Removing RESZ/NvAPI and
  DXVK-specific interfaces removes those dependencies, not the requirement
  that the active D3D9 implementation support the requested resources.

No production code changed. No ENB/FNV gameplay, GPU image, native Windows,
NVIDIA laptop or DXVK-version matrix was executed. This audit closes ENB's
depth-transport mechanism; it does not qualify a finished OMV backend.

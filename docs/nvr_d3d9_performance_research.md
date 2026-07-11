# NVR D3D9 Performance Research

## Status

This document preserves the July 11, 2026 New Vegas Reloaded (NVR) performance
investigation. The temporary D3D9 observer and every supporting configuration,
hook, integration, and command-reporting change were removed after the
investigation. No NVR-specific runtime code remains in `psycho-engine-fixes` or
`libpsycho` as a result of this work.

The important conclusion is architectural:

- The largest observed workloads are real shadow rendering and full-resolution
  post-processing traffic. The observer did not measure GPU duration.
- DXVK already filters redundant D3D9 state internally.
- A large, behavior-preserving optimization requires ownership of NVR's effect
  and shadow resource graph.
- An opaque, cross-version D3D9 interceptor cannot safely remove the expensive
  draws, resolves, copies, or passes.
- The correct implementation boundary is an NVR source change or an explicitly
  version-specific semantic integration, not a generic Psycho hook.

This report is performance-specific. The larger engine, shader, effect, and
resource contract remains documented in `docs/nvr_reference_contract.md`.

## Scope And Compatibility Requirement

The original goal was to improve NVR performance from `psycho-engine-fixes`
without depending on an NVR version, internal address, C++ layout, shader record,
or preset schema.

The allowed compatibility surface was intentionally limited to:

- detection of the loaded module name `NewVegasReloaded.dll`;
- the standard `IDirect3DDevice9` COM ABI;
- the FNV renderer's existing `IDirect3DDevice9` pointer;
- xNVSE's frame-present event;
- read-only D3D9 resource descriptions during sampled frames.

The investigation did not patch NVR internals, inspect NVR memory, replace an NVR
shader, change a draw, suppress a copy, or modify a resource. The observer was a
temporary measurement tool, not an optimization.

This distinction matters. NVR's visible effects are not a shader-only overlay.
The plugin owns engine hooks, render stages, depth resolves, shadow render passes,
intermediate textures, effect ordering, constants, and resource lifetimes. A D3D9
call alone usually does not carry enough semantic information to decide that the
call is unnecessary.

## Evidence Sources

### Runtime logs

The two relevant playtests were recorded in:

```text
/data/storage0/Games/FalloutNV_TTW/FalloutNV/psycho-engine-fixes-latest.log
```

The file is a rolling symlink, so the line numbers below describe the captured
playtest at the time of analysis rather than a permanent repository artifact.

First useful counter run:

- start: `2026-07-11T17:18:44.299Z`;
- NVR detection: line 994;
- observer attachment: line 1018;
- sampled frames: lines 1049-1276.

Render-target attribution run:

- start: `2026-07-11T17:41:37.228Z`;
- NVR detection: line 994;
- observer attachment: line 1022;
- sampled frames: lines 1056-1160.

### NVR reference source

The source-level analysis used:

```text
.research/TESReloaded10-master
```

This is a reference checkout, not a stable ABI and not proof that every released
NVR build has identical code. Findings tied to this checkout must not be turned
into version-independent runtime assumptions.

Important source files:

- `src/core/EffectRecord.cpp`
- `src/core/ShaderManager.cpp`
- `src/core/ShaderRecord.cpp`
- `src/core/TextureManager.cpp`
- `src/core/RenderManager.cpp`
- `src/core/ShadowManager.cpp`
- `src/core/RenderPass.cpp`
- `src/effects/ShadowsExterior.cpp`
- `src/effects/ShadowsExterior.h`
- `src/effects/Bloom.cpp`
- `src/effects/SMAA.cpp`
- `src/hlsl/NewVegas/Effects/*.hlsl`
- `src/hlsl/NewVegas/Shaders/Shadows/*.hlsl`
- `resource/NewVegasReloaded.dll.defaults.toml`

### FNV and local graphics research

Existing relevant material includes:

- `docs/nvr_reference_contract.md`
- `docs/graphics_fnv_pbr_errata.md`
- `analysis/ghidra/output/perf/graphics_fnv_nvr_shader_replacement_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pplighting_renderer_8b8_render_state_constructor_audit.txt`
- `analysis/ghidra/output/perf/display_d3d_reset_present_audit.txt`
- `analysis/ghidra/output/crash/va_space_d3d9_budget.txt`

Ghidra was not needed for the NVR shadow and effect implementation because the
reference source directly exposes those paths. Existing Ghidra output was used to
confirm the FNV device and render-state contracts where relevant.

### D3D9 and DXVK references

The state-cache analysis used DXVK master commit
`c8c49cc156f5044f9046ae5a8396a3a3aec2ed00`, dated July 11, 2026.

Relevant DXVK source:

- `src/d3d9/d3d9_device.cpp`, `SetRenderState` around lines 2296-2317;
- `SetSamplerState` around lines 2842-2852;
- sampler shadow-state comparison around lines 4535-4554;
- vertex shader comparison around lines 3533-3543;
- pixel shader comparison around lines 3891-3901;
- shader constant comparison around lines 8034-8092;
- `SetRenderTarget` around lines 1640-1707;
- `StretchRect` around lines 1206-1466;
- `src/d3d9/d3d9_state.h`, constant shadow state around lines 606-703;
- `src/d3d9/d3d9_stateblock.h`, state-block application around lines 188-347.

Microsoft D3D9 references used during the analysis:

- `IDirect3DDevice9::StretchRect`;
- `IDirect3DDevice9::SetRenderTarget`;
- `IDirect3DDevice9::BeginStateBlock`;
- `IDirect3DStateBlock9::Apply`;
- `IDirect3DDevice9::Reset`;
- D3D9 state-block save and restore behavior.

## Temporary Observer Design

The removed observer was opt-in. When disabled it installed no hooks. When
enabled it:

- waited for `NewVegasReloaded.dll`;
- located the FNV D3D9 device;
- patched standard D3D9 vtable slots;
- forwarded every observed call unchanged;
- sampled one frame every 600 presented frames;
- logged one aggregate line per sampled frame;
- later logged render-target and copy dimensions for the sampled frame.

The first version observed:

- `Reset`;
- `SetRenderState`;
- `SetSamplerState`;
- `SetTextureStageState`;
- `BeginStateBlock`;
- `EndStateBlock`;
- `StretchRect`;
- `DrawPrimitive`;
- `DrawIndexedPrimitive`;
- `DrawPrimitiveUP`.

The second version added:

- primitive totals from draw arguments;
- `SetRenderTarget` counts;
- `SetTexture` counts and null-unbind counts;
- render-target width, height, and format buckets;
- draw and primitive totals by render-target bucket;
- successful `StretchRect` source and destination dimensions and formats;
- surface-description failure and bucket-overflow reporting.

The second observer called `IDirect3DSurface9::GetDesc` only in a sampled frame,
after a successful render-target bind or copy. This perturbed the diagnostic
frame's CPU timing but did not change rendering and did not run in the other 599
frames. Therefore the counters and resource descriptions are useful, while the
sampled frame itself must not be treated as an uninstrumented benchmark. Buckets
were keyed by width, height, and format, not COM pointer identity, so one bucket
can contain several distinct surfaces with the same description.

### Observer defects found during the first run

The initial observer performed device-pointer validation after every frame. The
validation path used `VirtualQuery` and generated debug-memory log entries. This
made the first playtest unsuitable as a performance benchmark.

That design was corrected before collecting the useful samples:

- pointer and vtable validation occurred only during attachment;
- the attached frame path did not repeat memory validation;
- sample summaries were logged automatically;
- cumulative counters remained available for diagnostics.

The code was subsequently removed in full, including the temporary chain-safe
vtable-slot utility created for the experiment.

## First Counter Run

### Menu and loading behavior

Samples 1-8 contained menu or loading work:

```text
sample 1: draws=0/31/0,  copies=0, states=75/4/0
sample 2: draws=0/30/0,  copies=0, states=73/4/0
sample 3: draws=0/30/0,  copies=0, states=73/4/0
sample 4: draws=0/31/0,  copies=0, states=75/4/0
sample 5: draws=0/30/0,  copies=0, states=73/4/0
sample 6: draws=0/30/0,  copies=0, states=73/4/0
sample 7: draws=0/58/0,  copies=0, states=151/8/0
sample 8: draws=0/41/0,  copies=0, states=101/12/0
```

The slash-separated draw fields were:

```text
DrawPrimitive / DrawIndexedPrimitive / DrawPrimitiveUP
```

The slash-separated state fields were:

```text
SetRenderState / SetSamplerState / SetTextureStageState
```

### Gameplay behavior before additional effect activation

Samples 9-22 established a stable gameplay region:

```text
sample 9:  draws=45/494/4,  copies=47, resolves=4, states=707/2213/0
sample 10: draws=45/1378/4, copies=47, resolves=4, states=1234/3146/0
sample 11: draws=45/1640/4, copies=47, resolves=4, states=1362/3324/0
sample 12: draws=45/1799/4, copies=47, resolves=4, states=1537/3498/0
sample 13: draws=45/1881/4, copies=47, resolves=4, states=1545/3371/0
sample 14: draws=45/1294/4, copies=47, resolves=4, states=1166/3053/0
sample 15: draws=45/1244/4, copies=47, resolves=4, states=1200/2996/0
sample 16: draws=45/2010/4, copies=47, resolves=4, states=2005/4022/0
sample 17: draws=45/2326/4, copies=47, resolves=4, states=2419/4418/0
sample 18: draws=45/1890/4, copies=47, resolves=4, states=1631/3521/0
sample 19: draws=45/1870/4, copies=47, resolves=4, states=1582/3490/0
sample 20: draws=45/1870/4, copies=47, resolves=4, states=1583/3504/0
sample 21: draws=45/1864/4, copies=47, resolves=4, states=1606/3513/0
sample 22: draws=45/1871/4, copies=47, resolves=4, states=1582/3473/0
```

The representative median was approximately:

- 45 non-indexed draws;
- 1,870 indexed draws;
- 4 `DrawPrimitiveUP` calls;
- 47 `StretchRect` calls;
- 4 RESZ point-size triggers;
- 1,580 render-state calls;
- 3,500 sampler-state calls.

### Gameplay after additional NVR features were enabled

Samples 23-27 showed the transition reported by the user:

```text
sample 23: draws=54/3082/7, copies=59, resolves=4, states=1698/3791/0
sample 24: draws=58/5447/8, copies=64, resolves=4, states=1780/3902/0
sample 25: draws=59/3692/7, copies=66, resolves=4, states=2274/4892/0
sample 26: draws=59/3129/7, copies=66, resolves=4, states=1450/4198/0
sample 27: draws=59/6380/8, copies=66, resolves=4, states=1947/4774/0
```

Relative to the stable 47-copy region, the copy increments were exactly:

- `+12`;
- `+17`;
- `+19`.

The indexed-draw increase and longer 600-frame sample intervals initially made
shadow geometry the leading hypothesis. The copy increments separately matched
the structure of newly active multipass effects.

Aggregate counters could not identify the exact effects because many combinations
produce the same pass total. That limitation motivated the render-target and copy
dimension pass.

## Render-Target Attribution Run

### Format identifiers

The important D3D9 format values were:

| Value | D3D9 format | Payload |
|---:|---|---:|
| 21 | `D3DFMT_A8R8G8B8` | 4 bytes/pixel |
| 22 | `D3DFMT_X8R8G8B8` | 4 bytes/pixel |
| 34 | `D3DFMT_G16R16` | 4 bytes/pixel |
| 113 | `D3DFMT_A16B16G16R16F` | 8 bytes/pixel |
| 115 | `D3DFMT_G32R32F` | 8 bytes/pixel |

### Attributed gameplay samples

The four useful attributed samples were:

| Sample | Indexed draws | Indexed primitives | Copies | Texture binds/nulls |
|---:|---:|---:|---:|---:|
| 4 | 2,525 | 4,536,771 | 66 | 1,582 / 109 |
| 5 | 2,152 | 3,276,030 | 66 | 2,029 / 127 |
| 6 | 2,268 | 3,480,069 | 66 | 2,177 / 153 |
| 7 | 3,515 | 5,712,162 | 66 | 2,359 / 142 |

All four had:

- 59 `DrawPrimitive` calls;
- 7 or 8 `DrawPrimitiveUP` calls;
- 66 attempted `StretchRect` calls;
- 4 RESZ triggers;
- 44 render-target calls;
- zero surface-description failures;
- zero copy-bucket overflow.

Two render-target dimensions dominated indexed work.

#### 4096x4096, format 113

| Sample | DrawPrimitive | Indexed draws | Indexed primitives | Binds |
|---:|---:|---:|---:|---:|
| 4 | 2 | 1,566 | 2,781,779 | 2 |
| 5 | 2 | 292 | 507,190 | 2 |
| 6 | 2 | 423 | 605,177 | 2 |
| 7 | 2 | 1,815 | 3,143,747 | 2 |

This description bucket had the strongest variable indexed workload. It does not
identify one COM surface.

#### 3440x1440, format 113

| Sample | DrawPrimitive | Indexed draws | Indexed primitives | Binds |
|---:|---:|---:|---:|---:|
| 4 | 21 | 853 | 1,749,986 | 5 |
| 5 | 21 | 1,762 | 2,764,816 | 5 |
| 6 | 21 | 1,741 | 2,870,558 | 5 |
| 7 | 21 | 1,604 | 2,564,397 | 5 |

This bucket contained the full-resolution FP16 scene/effect work.

#### Other consistent targets

The frame also included:

- `1024x1024`, format 21: 8 indexed draws and 3,718 primitives;
- `3440x1440`, format 22: roughly 80-90 indexed draws;
- `3440x1440`, format 115: one bind, no indexed draws;
- `3440x1440`, format 34: six non-indexed draws;
- Bloom-style dimensions from `1720x720` down to `13x5`, format 113;
- a separate `6x2`, format-113 target with one indexed draw;
- a `1x1`, format 113 luminance target.

Two target descriptions exceeded the temporary 16-bucket table, but the overflow
affected only two target transitions. The unknown bucket contained two
non-indexed draws and no indexed draws, so it did not affect the shadow or scene
conclusions.

### Successful copy dimensions

Every attributed gameplay sample reported the same successful copies:

```text
1024x1024 f21  -> 1024x1024 f21  = 3
4096x4096 f113 -> 4096x4096 f113 = 1
3440x1440 f113 -> 3440x1440 f113 = 27
3440x1440 f22  -> 3440x1440 f113 = 18
```

This totals 49 successful calls. The aggregate counter recorded 66 attempts.
There were no `GetDesc` failures and no copy-bucket overflow, leaving 17 calls
that returned a failing HRESULT before they could enter the successful-copy
profile.

The observer did not record the failing HRESULT or pointer equality directly.
The exact source-level 17-call match described below is therefore a very strong
inference rather than direct runtime proof of `D3DERR_INVALIDCALL`.

## Exterior Shadow Atlas

### Runtime identity

The `4096x4096`, format-113 description bucket strongly matches NVR's exterior
sun-shadow atlas resource family in the reference source. That family contains at
least the distinct MSAA render surface and sampleable atlas surface.

The reference implementation explains the observed dimensions, format, two
non-indexed calls, indexed-call cluster, and same-description copy through:

- a 2x2 atlas of four cascades;
- 2048x2048 per cascade;
- EVSM4, 16-bit floating-point channels;
- a separate 4x MSAA render surface;
- one full-atlas MSAA resolve;
- two full-atlas prefilter draws;
- indexed geometry replay into refreshed cascades.

Relevant source:

- format table: `src/effects/ShadowsExterior.h:21-28`;
- format selection: `src/effects/ShadowsExterior.cpp:200`;
- atlas dimensions: `src/effects/ShadowsExterior.cpp:363-368`;
- texture creation: `src/effects/ShadowsExterior.cpp:368`;
- 4x MSAA surfaces: `src/effects/ShadowsExterior.cpp:372-375`;
- atlas bind: `src/core/ShadowManager.cpp:691-696`;
- cascade loop: `src/core/ShadowManager.cpp:698-720`;
- MSAA resolve: `src/core/ShadowManager.cpp:722-724`;
- prefilter call: `src/core/ShadowManager.cpp:726`;
- blur implementation: `src/core/ShadowManager.cpp:885-917`.

### Cascade layout

The atlas quadrants are:

| Cascade | Index | Quadrant | UV offset |
|---|---:|---|---|
| Near | 0 | top-left | `(0.0, 0.0)` |
| Middle | 1 | top-right | `(0.5, 0.0)` |
| Far | 2 | bottom-left | `(0.0, 0.5)` |
| LOD | 3 | bottom-right | `(0.5, 0.5)` |

Viewport construction is in `ShadowsExterior.cpp:377-381` and `462-466`.
Sampling and offsets are in `SunShadows.fx.hlsl:76-84` and `112-117`.

### Geometry workload

For each refreshed cascade NVR:

1. calculates the cascade light matrix;
2. traverses exterior cells and LOD roots;
3. filters and classifies geometry;
4. clears the cascade viewport;
5. renders normal, alpha, skinned, SpeedTree, and terrain-LOD queues.

The loaded-cell traversal is repeated per cascade:

- `src/core/ShadowManager.cpp:248-263`;
- `src/core/ShadowManager.cpp:275-295`.

Render queues are executed at `ShadowManager.cpp:217-224`. Geometry returns to
engine draw routines in `RenderPass.cpp:49-94` and skinned partitions at
`RenderPass.cpp:254-300`.

This strongly explains the observed range from 292 to 1,815 submitted indexed
draw calls and from 0.5 million to 3.14 million nominal primitives in the D3D9
arguments for one sampled frame. The observer did not record draw HRESULTs, GPU
timestamps, rasterized primitives, or pass duration.

### Update cadence

With `LimitFrequency = true`:

- near updates every frame;
- middle updates every frame;
- far updates every frame;
- LOD updates once every four frames.

Source: `ShadowManager.cpp:698-715`.

On skipped LOD frames, NVR translates the cached light matrix by camera movement
instead of rebuilding the LOD map. Near, middle, and far have no equivalent dirty
tracking. They redraw even when camera, sun, and scene state do not materially
change.

### EVSM4 channel contract

Format 113 is not an accidentally oversized single-channel depth target. EVSM4
uses all four channels:

```text
R = positive exponential first moment
G = negative exponential first moment
B = positive exponential second moment
A = negative exponential second moment
```

Producer: `ShadowMap.pso.hlsl:66-72`.

Consumer: `Effects/Includes/Shadows.hlsl:116-127`, using `.xz` and `.yw` as the
two moment pairs.

Therefore changing the resource to a one- or two-channel format would break the
EVSM4 shader contract. A generic D3D hook cannot safely reduce this resource's
format.

### Approximate allocation

For a 4096x4096 EVSM4 FP16 atlas:

```text
sampleable atlas: 4096 * 4096 * 8     = 128 MiB
4x MSAA color:    4096 * 4096 * 8 * 4 = 512 MiB
4x D24S8 depth:   4096 * 4096 * 4 * 4 = 256 MiB
total:                                      896 MiB
```

This excludes backend alignment and any accidental mip allocation.

With MSAA disabled, the approximate color/depth allocation becomes:

```text
single-sample color: 128 MiB
single-sample depth:  64 MiB
total:               192 MiB
```

The difference is approximately 704 MiB. This is a configuration-quality tradeoff,
not a behavior-preserving optimization.

### MSAA resolve

The one observed `4096x4096 f113 -> f113` copy strongly matches this reference
resolve:

```cpp
Device->StretchRect(
    Shadows->ShadowAtlasSurfaceMSAA,
    NULL,
    Shadows->ShadowAtlasSurface,
    NULL,
    D3DTEXF_NONE);
```

Source: `ShadowManager.cpp:722-724`.

In the reference path, the resolve is required to make the MSAA render surface
available through the sampleable atlas texture. Skipping that source operation
would leave stale shadow data.

### Prefilter cost and feedback defect

`BlurShadowAtlas` renders two fullscreen atlas passes, horizontal and vertical.
This strongly explains the two observed non-indexed draws on the 4096 target.

At 4096x4096, two submitted full-atlas draws nominally cover 33.55 million output
pixels. The observer did not record their HRESULTs. The reference shader uses
approximately five bilinear samples per axis for the near cascade and three for
other cascades, amounting to roughly 117 million nominal bilinear sample
instructions before cache effects. These are source-derived workload estimates,
not measured GPU execution counts or timing.

The reference implementation binds the atlas texture as a sampler and its own
level-zero surface as render target:

- source texture: `ShadowManager.cpp:890`;
- target surface: `ShadowManager.cpp:891`;
- target bind and source bind: `ShadowManager.cpp:903-905`.

Sampling and rendering to the same texture subresource is undefined in D3D9. No
temporary ping-pong texture exists. The two-pass separable blur therefore has no
portable visual contract in this source checkout.

A correct source implementation needs:

1. horizontal atlas -> temporary texture;
2. vertical temporary texture -> atlas.

This is primarily a correctness fix. It adds another 128 MiB temporary resource
at the measured resolution unless a smaller or aliased lifetime is designed.

An opaque hook cannot safely invent this ping-pong resource because the current
undefined feedback result is not a stable behavior to preserve across drivers or
DXVK versions.

### Shadow source defects observed in the reference checkout

The following settings are declared and consumed, but their assignments are
commented out in the examined source:

- `Mipmaps`;
- `Anisotropy`.

Relevant locations:

- commented setting reads: `ShadowsExterior.cpp:77-85`;
- texture creation uses `Mipmaps`: `ShadowsExterior.cpp:368` and `453`;
- runtime generation checks `Mipmaps`: `ShadowManager.cpp:728-729`.

The intended defaults are false/zero in
`resource/NewVegasReloaded.dll.defaults.toml:670-671`, but the reference C++ field
initialization is not deterministic enough to rely on that without auditing the
complete object-allocation path.

The source should explicitly initialize settings, COM pointers, counters, and
resource flags. This is a correctness and resource-lifetime prerequisite.

### Exterior shadow configuration controls

The effective resource signature matches this reference configuration:

- EVSM4 mode;
- 16-bit channels;
- 2048 cascade resolution;
- prefilter enabled;
- MSAA enabled;
- limit-frequency enabled.

Relevant defaults are in
`resource/NewVegasReloaded.dll.defaults.toml:664-674`.

Custom cascade resolution mapping in the reference source is:

```text
0 -> 1024
1 -> 1536
2 -> 2048
```

Source: `ShadowsExterior.cpp:73`.

Caster populations are controlled separately for near, middle, far, and LOD
cascades in the defaults TOML around lines 578-640.

## Point-Light And Other Shadow Paths

The first aggregate run made point-light cube shadows a plausible explanation
for thousands of indexed draws. The attributed run ruled that out as the primary
indexed API workload in the measured scene.

NVR can render up to 12 point-light cubemaps. Each light renders six faces:

- face loop: `ShadowManager.cpp:412-439`;
- geometry selection: `ShadowManager.cpp:442-499`;
- target, clear, and render: `ShadowManager.cpp:502-512`;
- outer light loop: `ShadowManager.cpp:764-789`.

That path remains a potentially severe workload in other scenes, especially
interiors. It was not the source of the measured 4096x4096 indexed-draw spike.

The reference point-light path has a more specific fingerprint than the square
target shape alone:

- point-light cubemaps are `D3DFMT_R32F`, format 114;
- their face size comes from `ShadowCubeMapSize`;
- the reference default is `512x512`.

Sources:

- cubemap creation: `ShadowsExterior.cpp:402-412`;
- setting load: `ShadowsExterior.cpp:310`;
- default size: `resource/NewVegasReloaded.dll.defaults.toml:700`.

The attributed runtime data did not contain an indexed format-114 target. The
observed `1024x1024`, format-21 target therefore does not match this reference
point-shadow path. The millions of variable shadow primitives instead appeared
on the 4096 format-113 target that strongly matches the exterior cascade atlas.

Other possible geometry replay paths include:

- optional flashlight shadow maps: `ShadowManager.cpp:791-804`;
- ortho maps for wet/snow effects: `ShadowManager.cpp:732-760`;
- engine water reflections wrapped by `NewVegas/Hooks/Render.cpp:96-112`.

These paths require their own runtime fingerprints before attribution.

## Post-Processing Copy Chain

### Global buffers

NVR creates two full-resolution FP16 staging textures:

```text
TESR_SourceBuffer
TESR_RenderedBuffer
```

Source: `src/core/TextureManager.cpp:11-18`.

Both use `D3DFMT_A16B16G16R16F` and render-target usage through
`TextureManager.cpp:36-52`.

### Generic effect algorithm

`EffectRecord::Render` performs:

1. one optional render-target -> `SourceBuffer` copy;
2. `SetCT` and effect begin;
3. one fullscreen draw per effect pass;
4. one render-target -> `RenderedSurface` copy after every pass.

Source:

- initial copy: `src/core/EffectRecord.cpp:351-360`;
- pass loop and output copy: `EffectRecord.cpp:361-374`.

For an ordinary enabled effect that passes `ShouldRender()`, has a non-null source
buffer and rendered surface, and executes `P` passes:

```text
DrawPrimitive calls = P
StretchRect calls = 1 + P
```

ShaderManager also initializes both source and rendered staging surfaces at the
start of pre-tonemap and post-tonemap chains:

- pre-tonemap copies: `src/core/ShaderManager.cpp:719-723`;
- post-tonemap copies: `ShaderManager.cpp:775-780`.

### Meaning of the measured full-resolution copies

At 3440x1440:

```text
pixel count = 4,953,600
format 22 payload = 19,814,400 bytes
format 113 payload = 39,628,800 bytes
```

The measured successful copies were:

```text
18 * X8R8G8B8 -> A16B16G16R16F
27 * A16B16G16R16F -> A16B16G16R16F
```

Destination writes alone are approximately:

```text
45 * 39.63 MB = 1.78 GB/frame
```

Approximate logical read plus write traffic is:

```text
18 * (19.81 MB read + 39.63 MB write)
27 * (39.63 MB read + 39.63 MB write)
= approximately 3.21 GB/frame decimal
= approximately 2.99 GiB/frame
```

At 60 FPS this is approximately 193 GB/s of logical transfer traffic before
counting:

- 59 fullscreen draws;
- shadow rasterization;
- shadow prefiltering;
- texture sampling inside each effect;
- depth and color attachment traffic;
- backend-specific layout transitions;
- compression, caching, or copy implementation details.

This is not a hardware-memory-controller measurement. It is a resource-payload
estimate that establishes the scale of the work.

### Likely pre-tonemap/post-tonemap split

The format-113 source group is consistent with pre-tonemap HDR processing. The
format-22 source group is consistent with post-tonemap output being copied into
NVR's FP16 staging textures.

Relevant stage selection:

- pre-tonemap game surface: `src/NewVegas/Hooks/Render.cpp:182-204`;
- post-tonemap output surface: `Render.cpp:207-214`.

The format split is strongly consistent with this flow, but aggregate dimensions
alone do not identify every individual effect.

## Seventeen Failed StretchRect Attempts

### Runtime evidence

Each attributed gameplay frame recorded:

- 66 total `StretchRect` attempts;
- 49 successful calls with valid source/destination descriptions;
- zero description failures;
- zero copy-profile overflow.

The 17-call gap is exactly explained by the reference source's
`RenderEffectToRT` behavior.

### Source defect

`ShaderManager::RenderEffectToRT` passes the same surface as all three arguments:

```cpp
Effect->Render(
    Device,
    RenderTarget,
    RenderTarget,
    0,
    clearRenderTarget,
    RenderTarget);
```

Source: `src/core/ShaderManager.cpp:682-689`.

`EffectRecord::Render` then attempts:

- one `StretchRect(RenderTarget, RenderTarget)` before the passes;
- one `StretchRect(RenderTarget, RenderTarget)` after every pass.

D3D9 does not support stretching or copying from a surface to itself. The expected
result is `D3DERR_INVALIDCALL`. NVR ignores the HRESULT at every high-level call
site. The surrounding C++ exception handler does not catch HRESULT failures.

### Exact 17-call match

For the measured exterior frame:

| Offscreen effect | Passes | Self-copy attempts |
|---|---:|---:|
| CombineDepth | 1 | 2 |
| Normals | 3 | 4 |
| PointShadows | 1 | 2 |
| PointShadows2 | 1 | 2 |
| SunShadows | 4 | 5 |
| AvgLuma | 1 | 2 |
| Total | 11 | 17 |

Source references:

- CombineDepth invocation: `ShaderManager.cpp:707-709`;
- CombineDepth pass: `CombineDepth.fx.hlsl:59-65`;
- Normals target: `src/effects/Normals.cpp:8`;
- Normals passes: `Normals.fx.hlsl:175-191`;
- point-shadow invocation: `ShaderManager.cpp:711-715`;
- PointShadows pass: `PointShadows.fx.hlsl:94-98`;
- PointShadows2 pass: `PointShadows2.fx.hlsl:65-69`;
- SunShadows invocation: `ShaderManager.cpp:716`;
- SunShadows passes: `SunShadows.fx.hlsl:243-263`;
- AvgLuma invocation: `ShaderManager.cpp:739-743`;
- AvgLuma target: `src/effects/AvgLuma.cpp:4`;
- AvgLuma pass: `AvgLuma.fx.hlsl:118-124`.

PointShadows2 requires more than six configured light points. AvgLuma is requested
by Exposure or DoF. These conditions match the measured pass total.

The observer did not log pointer equality or the failing HRESULT. The mapping is
too exact to be plausibly accidental, but a future source fix should still verify
the HRESULT directly in its target runtime.

### Why removing only the failed calls is not a meaningful fix

An opaque interceptor could theoretically check pointer equality and return
`D3DERR_INVALIDCALL` without forwarding the call. This would preserve the usual
D3D9 result while avoiding 17 DXVK validation paths.

That optimization was rejected because:

- the calls return failure rather than submitting the intended copy operation;
- no CPU timing proved that bypassing 17 validation paths would produce a useful
  saving;
- another hook could intentionally observe or transform the call;
- a different backend could return a different failure code;
- skipping downstream hooks weakens cross-plugin compatibility;
- it would preserve the broken feedback behavior rather than repair it.

### Broken intermediate ownership behind the failures

The self-copy failures expose deeper source problems.

#### Normals

Later Normals passes sample `TESR_NormalsBuffer` while rendering to the same
surface. A correct implementation needs two normal textures:

```text
pass 1: write A
pass 2: sample A, write B
pass 3: sample B, write A/final
```

Relevant HLSL: `Normals.fx.hlsl:152-191`.

#### PointShadows2 and SunShadows

These effects sample `TESR_PointShadowBuffer` while rendering to its surface.
They need alternating point-shadow surfaces or an explicit compositing target.

References:

- `PointShadows2.fx.hlsl:8-9,50`;
- `SunShadows.fx.hlsl:23-24,169,229,243-263`.

#### AvgLuma

AvgLuma samples the previous `TESR_AvgLumaBuffer` and writes the same 1x1 target.
Correct temporal adaptation needs two 1x1 history textures swapped per frame.

Reference: `AvgLuma.fx.hlsl:8-9,71,93,109-115`.

## Fullscreen Draw Decomposition

The measured 59 `DrawPrimitive` calls can be explained by the reference source:

```text
11 special offscreen-effect draws
15 Bloom draws for 8 levels
 2 shadow-atlas prefilter draws
31 ordinary effect draws
--
59 total
```

The 11 special draws are:

- CombineDepth: 1;
- Normals: 3;
- PointShadows: 1;
- PointShadows2: 1;
- SunShadows: 4;
- AvgLuma: 1.

Bloom with `N` levels performs `N` downsample and `N - 1` upsample draws. At the
default eight levels this is 15 draws. Source:

- settings: `resource/NewVegasReloaded.dll.defaults.toml:158-179`;
- implementation: `src/effects/Bloom.cpp:97-144`.

The remaining 31 ordinary draws are consistent with the active pre-tonemap and
post-tonemap effect passes, but aggregate counts cannot uniquely identify their
names.

## Effect-Specific Reduced-Resolution Opportunities

These are source-level opportunities. They cannot be applied safely by an opaque
D3D9 hook.

### Bloom

Bloom already allocates progressive smaller targets and performs a real
downsample/upsample chain. It is structurally better than the generic full-size
effect pipeline.

However, the upsample shader can sample a destination level while writing to that
same level. A correct implementation should use a temporary target or additive
blending that does not sample the current destination.

### GodRays

GodRays uses `scale = 0.5` and clips work to a portion of a full-size target, but
the target and every generic copy remain full resolution.

A real optimization requires dedicated half-resolution ping-pong textures for
the intermediate passes and one full-resolution composite.

Reference: `GodRays.fx.hlsl:29,60-64,79-84,103-106`.

### SnowAccumulation

Snow coverage multiplies UV by four and rejects work outside `[0,1]`, limiting its
heavy coverage calculation to one quarter of each axis, or 1/16 of the target
area. The pass and generic effect pipeline still operate on and copy the complete
full-size surface.

A proper implementation could use a correspondingly reduced coverage/blur
texture and one full-resolution composite, with dimensions chosen from the actual
sampling and blur contract.

Reference: `SnowAccumulation.fx.hlsl:138-170`.

### AmbientOcclusion

The HLSL contains a disabled `halfres` branch, but it clips within a full-size
surface rather than allocating a smaller render target. Enabling the macro alone
would not remove full-resolution allocation or copy bandwidth.

A real half-resolution implementation needs:

- half-resolution AO ping-pong targets;
- depth/normal-aware upsampling;
- adjusted texel and projection constants;
- a final full-resolution composite.

Reference: `AmbientOcclusion.fx.hlsl:3-5,68-77,204-243`.

### DepthOfField

DoF packs image and masks into quadrants of a full-size buffer. It still performs
six full-resolution generic output copies.

Separate reduced-resolution near/far blur buffers would lower traffic, but the
packing, sampling, and compositing ABI must change together.

Reference: `DepthOfField.fx.hlsl:115-180,212-249`.

## Redundant And Avoidable Successful Copies

The reference source exposes several source-level opportunities.

### Duplicate phase-initial SourceBuffer copy

ShaderManager copies the phase target into `SourceBuffer`, then the first active
ordinary effect copies the unchanged target into `SourceBuffer` again before
calling `SetCT`.

Because disabled or rejected effects return before copying, the first effect that
actually renders refreshes the source buffer. The phase-initial SourceBuffer copy
therefore appears redundant in this flow.

Relevant source:

- phase copies: `ShaderManager.cpp:719-723,775-780`;
- per-effect copy after render gate: `EffectRecord.cpp:351-360`.

The initial `RenderedBuffer` copy is not automatically redundant because the
first effect may consume it.

### Effects that do not consume SourceBuffer

The generic pipeline passes a non-null `SourceBuffer` to every ordinary effect,
even when the effect has no `TESR_SourceBuffer` sampler.

The effect reflection code should record `NeedsSourceBuffer` and copy only for
effects that declare it. Candidates that generally consume only rendered output
include Coloring, Exposure, Sharpening, MotionBlur, Cinema, BloodLens, WaterLens,
LowHF, and ImageAdjust. Each target effect must be confirmed against its active
techniques and version.

### Unconsumed final RenderedBuffer copy

Every generic effect copies its final pass to `RenderedBuffer`, even if no later
active effect consumes it before the final output is presented or captured.

A source-aware scheduler can omit the final copy only after resolving the actual
active effect list and buffer consumers for that frame.

### Equal-size copies use linear filtering

Generic effect copies use `D3DTEXF_LINEAR` even when source and destination sizes
match. `D3DTEXF_NONE` is the natural exact-size copy choice and avoids a filtering
capability requirement.

Source: `EffectRecord.cpp:359,372`.

The measured equal-size copies succeeded under DXVK, so filtering was not the
cause of the 17 failures.

## RESZ Depth Resolves

Every gameplay sample observed exactly four magic RESZ triggers.

NVR's RESZ path:

1. saves shaders, streams, texture, declaration/FVF, and render states;
2. binds the destination depth texture;
3. disables depth and color writes;
4. draws a point;
5. triggers the resolve with
   `D3DRS_POINTSIZE = 0x7FA05000`;
6. restores state.

Source: `src/core/RenderManager.cpp:301-350`.

NVR requests depth around world and first-person rendering in
`src/NewVegas/Hooks/Render.cpp:70-94`.

The runtime environment may include another depth-resolve component, so the four
aggregate triggers must not all be attributed to NVR without call-site evidence.

Critical rule: `D3DRS_POINTSIZE` is not an ordinary idempotent state setter. The
magic value performs an operation. Any generic state cache that suppresses it
would break depth-dependent effects. The reference source also uses unusual
point-size values during render setup, so forwarding all point-size assignments
is the conservative rule.

## State Calls And DXVK

The measured 3,000-5,000 sampler-state calls initially looked like a major CPU
optimization opportunity.

NVR source explains the volume. `EffectRecord::SetCT` applies sampler states 1-11
for every effect sampler without checking the current value:

- `src/core/EffectRecord.cpp:280-299`.

Replacement shader records do compare cached sampler values:

- `src/core/ShaderRecord.cpp:431-455`.

Despite the source-level redundancy, the available evidence does not justify an
external D3D9 cache under the measured Proton/DXVK environment.

The inspected DXVK master commit already performs equality checks for:

- render states;
- sampler states;
- vertex and pixel shader pointers;
- float and integer shader constants;
- render-target pointers and backend framebuffer work.

For unchanged setters, the remaining cost is mostly:

- an in-process COM call;
- validation;
- an optional device lock;
- recording-state checks;
- a shadow-state lookup and comparison.

No Wine-server or kernel transition occurs for a normal DXVK setter in this
implementation. The investigation did not identify the exact installed DXVK
binary or prove that it matched the inspected commit, and it did not measure CPU
time spent in these setters.

### Why an external state cache is dangerous

An external proxy must handle all of the following correctly:

- `BeginStateBlock` recording must retain a setter even when it equals live state;
- `IDirect3DStateBlock9::Apply` can mutate state without traversing device vtable
  hooks;
- `Reset` invalidates cached state, including some failure paths;
- `QueryInterface` aliases can bypass one hooked object;
- other plugins can install later hooks or call a saved lower-level function;
- multithreaded devices require ordering compatible with the device lock;
- suppressing a call suppresses downstream hooks and their intentional behavior;
- returning `D3D_OK` from a cache can change validation HRESULTs;
- setting render target 0 has required viewport side effects even if the target
  pointer is unchanged.

The source-level fix is to avoid redundant work inside NVR's own effect and render
state manager, where state-block and renderer ownership are known. A broad Psycho
cache would add compatibility risk for an unmeasured front-end saving and would
not reduce the observed draw, primitive-argument, or copy workload.

## Native Shader Replacements Versus Added Passes

NVR's PBR, POM, Terrain, Sky, and similar shader collections replace shader
handles used by existing game passes. Their selection path is in
`src/core/ShaderManager.cpp:424-437` and `ShaderRecord.cpp:480-554`.

These replacements can make each existing draw much more expensive, but they do
not inherently replay scene geometry.

Therefore:

- an FPS drop after enabling native PBR/POM/Terrain can be shader ALU, texture,
  register, or bandwidth cost without an increased draw count;
- a simultaneous increase of thousands of indexed draws indicates a shadow,
  reflection, or other geometry replay path, or a changed scene;
- extra `StretchRect` calls indicate enabled fullscreen/offscreen effect passes,
  not merely a native replacement shader.

The attributed run showed its largest variable indexed workload on the target
that strongly matches the exterior shadow atlas.

## Source-Level Optimization Plan

The following plan assumes ownership of the NVR source and explicit visual
regression testing. It is not suitable for an opaque interceptor.

### Priority 0: establish correct resource behavior

1. Initialize every setting, pointer, counter, and resource flag deterministically.
2. Give Normals a real two-surface ping-pong chain.
3. Give PointShadows/SunShadows alternating accumulation surfaces.
4. Give AvgLuma two 1x1 history textures.
5. Fix Bloom upsample destination feedback.
6. Fix shadow-atlas prefilter feedback with a temporary atlas.
7. Check and log every resource-creation and copy HRESULT.
8. Add capability checks and fallback for MSAA formats and resolves.

Correctness comes first because undefined feedback makes before/after image
equivalence impossible to define reliably.

### Priority 1: remove behavior-preserving CPU work

1. Upload cascade-invariant and pass-invariant shadow constants once per
   cascade/pass rather than through complete shader constant tables per geometry
   draw.
2. Separate object-varying constants such as world transform, alpha texture, and
   skinning bones from invariant shadow constants.
3. Gather exterior shadow candidates once, then classify/cull the candidate set
   for each cascade instead of traversing the loaded-cell graph four times.
4. Cache stable form/property classification with invalidation for load, unload,
   movement, animation, material, and visibility changes.
5. For EVSM custom clear, clear depth only before the full-viewport custom color
   clear rather than performing a white color clear that is immediately
   overwritten.
6. Avoid unconditional full constant-table and sampler-table walks when neither
   the shader record nor values changed.

These changes can preserve draw output if their cache keys and invalidation rules
are proven.

### Priority 2: remove avoidable effect copies

1. Reflect and store whether each effect actually consumes `TESR_SourceBuffer`.
2. Remove the duplicate phase-initial SourceBuffer copy.
3. Copy SourceBuffer only for effects that consume it.
4. Build the active effect list and omit final RenderedBuffer copies with no
   later consumer.
5. Use explicit ping-pong render targets for ordinary multipass effects rather
   than rendering to one target and copying after every pass.
6. Use `D3DTEXF_NONE` for equal-size exact copies unless conversion semantics
   require another path.
7. Track resource generations so a copy can be skipped only when the required
   destination generation already exists.

This requires a real effect graph. Pointer or dimension equality alone is not a
safe proof of redundancy.

### Priority 3: reduce pixel workload

1. Use true half-resolution intermediates for AO, GodRays, and broad blur stages.
2. Use quarter-resolution or smaller intermediates for snow coverage where the
   shader already computes only a reduced region.
3. Replace DoF quadrant packing with dedicated reduced-resolution blur buffers.
4. Preserve depth/normal-aware upsampling and edge behavior.
5. Compute cascade selection before sampling SunShadows and sample only the
   selected cascade plus a blend neighbor, if compiled shader inspection proves
   the compiler does not already remove unconditional samples.

These changes preserve feature intent but can change image quality. They require
side-by-side testing, not only FPS comparison.

### Priority 4: improve shadow update scheduling

1. Add dirty tracking for near, middle, and far cascades.
2. Separate camera translation from scene/sun invalidation.
3. Stagger lower-priority cascade updates when their projection can be corrected
   safely between refreshes.
4. Dirty point-light cube faces from light/object movement rather than rendering
   every active face every frame.
5. Preserve matrix compensation and avoid stale casters after cell transitions.

This can be a high-value optimization but is not behaviorally trivial. Shadow
latency and temporal artifacts must be measured.

## Quality-Tradeoff Controls

These controls reduce real work but intentionally change image quality.

### Disable shadow MSAA

Expected effect:

- removes the 4x color surface;
- removes the 4x depth surface;
- removes the full 4096 resolve;
- saves approximately 704 MiB at the measured atlas size;
- changes rasterized shadow-edge quality.

### Disable shadow prefilter

Expected effect:

- removes two 4096x4096 fullscreen draws;
- removes their atlas texture sampling and writes;
- changes shadow softness and moment filtering.

### Reduce cascade resolution

Changing each cascade from 2048 to 1536 changes the atlas from 4096 to 3072.
Pixel area becomes:

```text
3072^2 / 4096^2 = 56.25%
```

This reduces atlas raster, resolve, blur, and allocation costs but lowers shadow
detail.

### Reduce caster population

Increasing per-cascade `MinRadius`, reducing shadow distance, or disabling
expensive form classes directly lowers indexed draws. Actors, alpha foliage,
small statics, and distant LOD are likely high-cost classes.

### Change shadow mode

VSM uses a two-channel format and can halve color payload relative to EVSM4 FP16,
but has different light-bleeding and filtering behavior.

The reference checkout's EVSM2 path appears internally inconsistent: its producer
writes positive and negative first moments while its consumer treats channels as
a mean/second-moment pair. EVSM2 should not be recommended as a performance mode
until that contract is corrected and tested.

## Rejected Opaque Optimizations

### Skip indexed draws

Rejected because a draw may differ in geometry, buffers, constants, skinning,
alpha material, cascade, cube face, or visibility. D3D arguments do not prove a
draw is redundant.

### Rate-limit render-target dimensions

Rejected because a 4096 target identity does not expose camera/light matrices,
cascade ownership, dirty state, or the translation compensation required by NVR.

### Skip the shadow resolve

Rejected because the sampleable atlas would remain stale after rendering to the
MSAA surface.

### Replace the EVSM4 format

Rejected because all four channels are consumed as two EVSM moment pairs.

### Skip successful full-resolution copies

Rejected because source/destination dimensions do not reveal whether a later
shader consumes SourceBuffer, RenderedBuffer, temporal history, or another named
resource generation.

### Alias SourceBuffer and RenderedBuffer

Rejected because effects often need an immutable pre-effect image and a mutable
previous-pass image at the same time.

### Suppress redundant state externally

Rejected because the inspected DXVK implementation already filters unchanged
state before backend work, while an external cache cannot safely track state
blocks, reset, aliases, threads, and other hooks. The installed DXVK build was not
identified and no setter CPU timing was collected.

### Inject reduced-resolution targets

Rejected because shaders, UV packing, constants, viewports, sampler bindings, and
compositing logic all assume the original resource graph.

### Recognize NVR shader bytecode

Rejected under the cross-version requirement. Bytecode recognition and semantic
replacement would be an NVR-version-specific integration, not an opaque D3D9
optimization.

## Runtime Stability Observations

The observer attached successfully in both useful runs. No vtable displacement,
compatibility fallback, reset issue, or surface-description failure was observed.

One hang warning occurred during each broader test period while `loading=true`.
The reports showed stale main-loop heartbeat around loading/focus transitions and
were followed by normal rendering or fullscreen repair. There was no evidence
linking those warnings to the D3D9 observer.

The memory watchdog remained below its pressure thresholds during the attributed
run. This does not negate the large shadow resource estimate; D3D/DXVK allocation,
VRAM residency, host-visible mirrors, and the 32-bit process VAS are different
accounting domains.

## Final Decision

The temporary observer answered the research question:

- the largest variable indexed workload was on the 4096x4096 format-113 target
  that strongly matches the EVSM4 exterior shadow atlas;
- the 4096x4096 description bucket received up to 1,815 submitted indexed calls
  containing 3.14 million nominal primitives in one sampled frame;
- the matching reference shadow contract allocates approximately 896 MiB for its
  4x MSAA color, depth, and sampleable atlas resources at that effective size and
  format;
- the process-wide observer recorded 45 successful full-resolution copies per
  frame whose formats, dimensions, and counts strongly match the reference NVR
  post-processing chain;
- those copies represent approximately 3.21 GB/frame of logical read/write
  payload at 3440x1440;
- 17 additional calls almost certainly came from invalid same-surface copies in
  the reference `RenderEffectToRT` path;
- sampler-state call volume was real at the API boundary, while the inspected
  DXVK source deduplicates unchanged values before backend work;
- the major wins require NVR effect/shadow source ownership.

Because the project requirement was compatibility with arbitrary old, current,
and future NVR versions, no runtime optimization met the safety bar. All
NVR-specific code and configuration changes were removed. This document is the
retained deliverable.

If the compatibility requirement is later relaxed, the recommended path is an
NVR source fork or upstream contribution following the source-level plan above.
Do not revive the generic D3D9 observer as a permanent runtime feature unless a
new question requires measurements that existing logs and this report cannot
answer.

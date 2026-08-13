# Fallout New Vegas NVR Shadow Engine Contract

## Status and purpose

This document is the durable, implementation-grade shadow contract derived from
the two NVR source snapshots under `.research/`, current OMV source, the current
repository `FalloutNV.exe`, and the authoritative static-analysis artifacts under
`analysis/ghidra/output/`.

It has three purposes:

1. preserve the complete engine and D3D9 contract needed if OMV later implements
   replacement directional, point, or spotlight shadows;
2. correct an important comparison error in the NVIDIA one-FPS investigation:
   modern NVR does not wrap the native shadow transaction that OMV currently
   wraps. It replaces the native transaction prefix and invokes only its tail.
3. define and record OMV's 2026-08-12 test-driven replacement implementation,
   including its quality, lifecycle, performance, and acceptance contracts.

The historical and executable sections remain research evidence; no source
under `.research/` is patched or built. The "OMV implementation" section below
is the durable implementation record. It distinguishes static proof from the
runtime behavior that still requires a Proton playtest.

The executable inspected on 2026-08-09 is:

```text
path:       fnv_reverse/FalloutNV.exe
format:     PE32 x86
image base: 0x00400000
SHA-256:    42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c
```

All absolute addresses in this document are valid only for that executable.

## Evidence rules

- **Executable proof** means direct radare2 inspection of the identified binary
  or an existing authoritative `.txt` artifact under `analysis/ghidra/output/`.
- **Source proof** means behavior directly visible in the supplied NVR or OMV
  source tree.
- **Runtime observation** means a supplied log or the recorded healthy NVR
  observer run. It proves what happened in that run, not why a driver behaved
  that way.
- **Inference** means a conclusion consistent with those facts but not yet
  timed on the affected NVIDIA system.

The two NVR trees are source snapshots, not shipped binaries. Source facts are
not automatically executable facts. This distinction matters because the
legacy snapshot contains one shadow-tail address that contradicts the current
executable.

## Terminology

The native world-shadow operation is split here into two executable regions:

- **native prefix**: `0x00871290..0x008719F7`, which owns native local-light
  candidate handling and shadow production;
- **native tail**: the separate function at `0x00871A50`, called by the prefix
  at `0x008719F8` and also by a main-render caller at `0x008702F7`.

"Legacy NVR" means the `TES-Reloaded-master` snapshot, identified by its source
as New Vegas Reloaded 3.3.0. "Modern NVR" means `TESReloaded10-master`,
identified as New Vegas Reloaded 4.4.1.

"Native shadows" means the game's `ShadowSceneLight` selection and rendering
transaction. "NVR shadows" means the replacement directional/cube/spot map
producer and its image-space consumers. They are not the same resource graph.

## Native Fallout New Vegas shadow boundary

### Dispatcher and direct call sites

Executable xrefs prove three direct calls to `0x00871290`:

| Branch function | Call instruction | Receiver load | Immediate continuation |
|---|---:|---|---|
| `0x008707C0` | `0x00870851` | `ECX = [EBP-0x28]` | world/render continuation beginning `0x00870856` |
| `0x00870A00` | `0x00870A74` | `ECX = [EBP-0x20]` | world/render continuation beginning `0x00870A79` |
| `0x00870BD0` | `0x00870C3C` | `ECX = [EBP-0x78]` | world/render continuation beginning `0x00870C41` |

The parent dispatcher is `0x008706B0`. Its flag-dependent control flow selects
one of those mutually exclusive variants. The three call sites are therefore
alternative render modes, not three unconditional calls in one dispatcher
invocation.

The exact proven selection logic is:

```text
mode = 0x00870770()
if arg3 != 0 and 0x00702680(0x3F5, 0) == 0:
    call 0x008707C0(arg2, mode)
else if mode != 0:
    call 0x00870A00(arg2, arg4)
else:
    call 0x00870BD0(arg2, arg4)
```

The semantic names of `arg3`, `arg4`, and helper result `mode` are not proven
by the current symbols, so this document does not guess them. It is proven that
legacy NVR's `0x00870C39` patch applies only to the final `mode == 0` branch,
while modern NVR and OMV cover all three outcomes.

The dispatcher itself has these proven call sites:

| Caller | Call site | Context established by caller research |
|---|---:|---|
| `0x0086FF70` | `0x00870244` | main pre-render/render path |
| `0x0086FF70` | `0x008702A9` | second main-render path |
| `0x00871DC0` | `0x008721A4` | special main/render path |
| `0x00878F60` | `0x00879174` | screenshot rendering |

Consequences:

- `0x00871290` is common across all three dispatcher variants.
- It is not proven to execute exactly once per present.
- A hook there may see main rendering, special rendering, and screenshot
  rendering.
- Any per-present publication attached there needs an epoch/context rule; a
  raw call count cannot safely be interpreted as a frame count.

Current OMV keys this publication with the core `render_epoch`, which advances
at `DisplayScene`, but its world-light hook has no "already captured this
epoch/context" guard. Every qualifying invocation starts/reuses staging,
performs capture, and can replace atmosphere and terrain publications with the
same epoch number. Multiple main/special/screenshot calls before one
`DisplayScene` therefore repeat all validation/scan work and can overwrite
which camera/light set represents that epoch.

### Native prefix and tail

The function at `0x00871290` is 1,905 bytes and returns at `0x00871A00`. At its
end:

```text
0x008719F2  mov ecx, [ebp-0x88]
0x008719F8  call 0x00871A50
0x008719FD  mov esp, ebp
0x008719FF  pop ebp
0x00871A00  ret
```

`0x00871A50` is a separate 571-byte function. It has two direct callers:

- `0x00871290 @ 0x008719F8`;
- `0x0086FF70 @ 0x008702F7`.

The tail stores entry `ECX` into a local at `0x00871A75`. Current decompilation
and complete function disassembly find no later read of that local. The parent
prefix likewise saves its incoming `ECX` at `0x00871299` and reloads it only for
the tail call at `0x008719F2`. Modern NVR invokes the tail through a `CdeclCall`
and ignores the original `this` pointer. These facts explain why a missing
receiver can be tolerated by this exact binary; they are not a general ABI
guarantee for another executable.

The strict replacement invariant for this binary is:

- wrapping `0x00871290` means the native prefix and tail both still execute;
- replacing `0x00871290` means the replacement must execute `0x00871A50`
  exactly once if it intends to preserve the native post-shadow behavior;
- calling both the original `0x00871290` and `0x00871A50` explicitly would
  execute the tail twice and is incorrect.

### Native prefix ownership

Authoritative static artifacts establish that the native prefix owns a
scene-wide local-light/shadow candidate transaction. It reads the native scene
light manager, selects native `ShadowSceneLight` candidates, and invokes native
shadow helpers including `0x00B5B880` and `0x00B9F780`. The zero-shadow branch
clears candidate resources/slots; the nonzero path prepares and renders selected
native shadows before reaching the common tail.

The manager fields used by both native research and current OMV are:

| Offset | Meaning |
|---:|---|
| `+0xB4` | scene-light list pointer |
| `+0xBC` | scene-light count |
| `+0xC0` | selected/native candidate storage |

The completed native `ShadowSceneLight` fields relevant to OMV's optional
atmosphere shadow capture are:

| Offset | Meaning |
|---:|---|
| `+0x10`, `+0x50`, `+0x90` | completed shadow matrices |
| `+0xD0` | transition value |
| `+0xD4` | fade value |
| `+0xF4` | positional flag |
| `+0xF5` | ambient flag |
| `+0xF8` | native light pointer |
| `+0x10C` | rendered shadow texture pointer |
| `+0x110` | active/completed flag |

Those offsets describe native engine objects. Modern NVR's replacement cube
maps and constants do not populate this native resource graph.

### Native local-shadow queue, package, and writer ABI

The native prefix is not one synchronous draw function. Its selected-light
path crosses the engine's queued render contract:

1. `0x00B9DFC0` prepares a local `ShadowSceneLight` render and submits each
   selected job through queued-render helper `0x00BA3390` at `0x00B9E6CB`.
2. `0x00B5B880` temporarily writes shader package `0x20` to the current
   thread's renderer TLS field at `+0x2B4`, processes selected shadow lights,
   and restores the previous package before returning. Package `0x20` is thus
   scoped state for native shadow production, not a global OMV PBR package.
3. Its call at `0x00B5B9DC` pushes the selected slot, then the render
   accumulator, loads the `ShadowSceneLight*` into `ECX`, and calls
   `0x00B9F780`. The proven ABI is therefore thiscall-like:
   `finish_shadow(this_light, accumulator, slot)`.
4. `0x00B9F780` first waits on the queued-render semaphore through
   `0x00BA3130`, selects native render mode 7 through `0x00B6B8D0`, completes
   the offscreen render into the light's pooled texture, copies the completed
   matrices/scalars into the light object, and applies image-space effect
   `0x11` in place to that texture.
5. The resulting texture at `ShadowSceneLight +0x10C` is a refcounted rendered
   texture of engine type `0x2B`, lazily acquired from the pool and released on
   invalidation/destruction. Its normal size is 1024 by 1024. The default path
   uses `D3DFMT_R32F`; the ATI compatibility package changes it to
   `D3DFMT_A8R8G8B8`.

Installed shader packages close the native writer ABI. Selector 7 pairs
PPLighting vertex group-C indices 92-95 (`SLS2092.vso..SLS2095.vso`) with
pixel group-B indices 90-91 (`SLS2090.pso` and the alpha-textured
`SLS2091.pso`). Both pixel variants write the same scalar depth to red:

```text
D = length(-t0) * (1 - c16.w / dot(-t0, normalize(c16.xyz))) / c14.x
```

The alpha variant also preserves sampled alpha. The ATI format is therefore a
lower-precision red-channel scalar path, not packed multi-channel depth. These
shader identities describe native local shadows only; both NVR replacement
producers bypass this native prefix on the variants they hook.

There is a separate native projected-shadow/receiver path at `0x00B9D020`.
Existing analysis shows pass IDs `0x58` and `0x5C`, traversal of a geometry
list, and PPLighting/ShadowLight interface dispatch through `0x00B7A870`.
Those facts do not prove that `0x00B9D020` produces the offscreen map. It must
not be merged with the selector-7 writer contract without an additional caller
bridge.

The global `BSShader::SetShaders @ 0x00BE1F90` binds whichever wrapper pair the
current pass exposes, and the ShadowLight virtual interface shares resource
method `0x00E812F0` with other shader classes. Static evidence has not yet
closed every indirect edge from queued selector-7 submission through those two
OMV detours. Future diagnostics must therefore count hook entry by native
package/pass rather than assuming either zero or one call per shadow light.

### Caller repair is part of the practical contract

Each dispatcher branch continues into world rendering immediately after the
shadow call. The later branch setup re-establishes render targets, viewport,
shaders, streams, and render states needed by the world render. Both NVR
generations rely on that later work to repair state they do not completely
restore.

This is a practical compatibility fact, not a safe isolated-plugin contract.
A future OMV implementation must either:

- prove and document the exact dirty-state postcondition accepted by every
  caller variant and keep the engine render-state cache coherent; or
- restore every state it changes before returning.

The second option is safer unless measurements prove it too expensive and the
first option has complete executable coverage.

## Legacy NVR 3.3.0 contract

### Hook placement and coverage

Legacy NVR defines:

```text
kRenderShadowMapHook   = 0x00870C39
kRenderShadowMapReturn = 0x00870C41
```

At this executable those eight bytes are:

```text
0x00870C39  mov ecx, [ebp-0x78]
0x00870C3C  call 0x00871290
0x00870C41  ... continuation
```

Its naked detour performs `pushad`, loads `TheShadowManager` into `ECX`, calls
`ShadowManager::RenderShadowMaps`, restores registers with `popad`, and jumps
to `0x00870C41`.

Therefore the source snapshot:

- replaces both the receiver load and native call;
- preserves general-purpose registers around its C++ replacement;
- affects only dispatcher branch `0x00870BD0`;
- does not intercept the calls at `0x00870851` or `0x00870A74`.

This is materially different from modern NVR and current OMV. It is also an
important compatibility limitation: source-level legacy shadow replacement is
not common to every render mode in the current executable.

Legacy installs two supporting shadow hooks:

- `0x0050DD06` derives `NiPointLight::CastShadows` and carried-light state from
  the reference/light form and first-/third-person equipment policy;
- `0x0066A115` names `BSTreeNode` child 1 `"Leaves"`, providing an identity used
  by the SpeedTree shadow path.

These are part of legacy's producer contract, not generic engine behavior.

### Legacy native-tail contradiction

The first line of legacy `ShadowManager::RenderShadowMaps` is:

```cpp
Global->RenderShadowMaps(); // Window reflections seem to be rendered here
```

In `TESReloaded/Framework/Game.h`, that wrapper calls literal address
`0x004073D0`.

Direct executable inspection proves that `0x004073D0` is not a valid function
entry in the identified `FalloutNV.exe`. It decodes in the middle of another
instruction stream as nonsensical instructions beginning with:

```text
0x004073D0  add byte [ecx + 0x558bfc4d], cl
0x004073D6  aam 0x83
0x004073D8  mov edx, 0x88
```

No executable xrefs to `0x004073D0` were found. Other legacy hook addresses in
this subsystem do match the current executable.

The only defensible conclusion is that this one source literal is stale,
wrong, or not representative of the known healthy shipped legacy binary. It
must not be silently reinterpreted as `0x00871A50`, and it must not be copied
into OMV. The healthy-runtime premise applies to NVR releases, not to the
byte-for-byte correctness of every line in this source snapshot.

This contradiction leaves the legacy source unable to prove exactly how its
shipped binary preserved the native tail/window-reflection behavior. Modern
NVR supplies the clear contract for the current executable: replace the common
entry and explicitly call `0x00871A50`.

### Startup and ownership

Legacy renderer initialization is engine-led:

1. native renderer initialization completes;
2. `TrackInitializeRenderer` stores the engine renderer in
   `TheRenderManager`;
3. `RenderManager::Initialize` acquires the device/render-state objects;
4. global managers, including `ShadowManager`, initialize;
5. shader effects are created.

The shadow manager is heap allocated as a singleton and described as never
disposed. Its D3D resources are created after the engine device exists.

No complete lost-device/reset release-and-recreate flow was found. The shadow
resources use `D3DPOOL_DEFAULT`; Direct3D 9 requires default-pool resources to
be released before a successful reset. The snapshot therefore has incomplete
reset ownership even though ordinary runtime is reported healthy.

### Resource topology

Legacy directional shadows are four independent `R32F` textures rather than an
atlas:

| Index | Name | Default size | Default radius | Normal draw state |
|---:|---|---:|---:|---|
| 0 | near | 4096 | 4096 | rendered every replacement invocation |
| 1 | far | 1024 | 8192 | rendered every replacement invocation |
| 2 | ortho | 256 | 2048 | surface cleared/bound; geometry only when enabled |
| 3 | skin | 4096 | 512 | rendered every replacement invocation |

The default directional far plane is 8192. Each map owns one `D24S8` depth
surface and one full-size viewport.

Point-light resources are:

- 12 `R32F` cube textures;
- six retained face surfaces per cube;
- 72 separate `D24S8` depth surfaces, one per cube face;
- one cube viewport;
- cube size equal to the minimum of the interior and exterior-point settings,
  both defaulting to 512 in this snapshot.

All are default-pool resources. Creation HRESULTs are not checked before later
use, and there is no destructor that establishes balanced release ownership.

At the supplied defaults, directional color plus matching depth is nominally
264.5 MiB: 128 MiB each for near and skin, 8 MiB for far, and 0.5 MiB for
ortho. Twelve 512-face `R32F` cubes add 72 MiB and 72 independent 512-square
`D24S8` depth surfaces add another 72 MiB. Total nominal legacy shadow storage
is therefore about 408.5 MiB before alignment, metadata, shaders, and other
effect resources.

### Constructor defects that are not contract

The legacy constructor contains two source defects:

- local variables named `ShadowCubeLightCount` and
  `ShadowCubeCullLightCount` shadow the members, leaving the members
  uninitialized;
- `ShadowCubeMapLights[12] = { NULL };` writes one element past a 12-element
  array instead of initializing the array.

These are snapshot defects, not behaviors to preserve. Their existence is
another reason to extract architectural invariants rather than transliterate
the source.

### Top-level producer sequence

The source replacement does the following:

1. invokes the disputed `Global->RenderShadowMaps()` wrapper;
2. obtains the current depth-stencil surface;
3. updates and installs scene-camera data;
4. renders exterior directional and point shadows as applicable;
5. renders interior point shadows as applicable;
6. restores only the captured depth-stencil surface.

It does not capture or restore RT0, viewport, shaders, textures, sampler state,
vertex declaration/FVF, streams, indices, or the full set of render states it
mutates. It therefore returns with a dirty pipeline and depends on dispatcher
continuation to establish the world-render state.

`GetDepthStencilSurface` returns an owned COM reference on success. The shown
legacy path never releases it, producing one leaked reference per successful
replacement invocation. That leak is a source defect; it is not evidence that
COM getter ownership is harmless.

### Directional-map mathematics and cadence

For each directional map, legacy NVR:

- derives a camera-relative look-at position;
- selects the sun or moon direction and clamps its vertical component to at
  least 0.3;
- builds an orthographic view/projection using the configured radius and far
  plane;
- computes `ShadowCameraToLight = inverse(camera view-projection) *
  shadow view-projection`;
- installs the map surface, depth surface, and map viewport;
- clears the target/depth;
- traverses loaded cells and renders accepted geometry when the map is enabled.

Near, far, and skin maps are produced every invocation. The optional interval
logic smooths the light direction; it does not skip those map renders. The
ortho producer is called every invocation and binds/clears its map, but its
geometry draw is conditional on the setting.

The far map rejects objects fully inside the near frustum to avoid duplicating
near coverage. Map-specific minimum-radius defaults are 9 for near, 100 for
far/ortho, and 0 for skin in the producer logic.

Each active directional map opens and closes its own D3D9 scene pair. Multiple
non-nested pairs are legal, but Microsoft documents that more than one pair
between presents may incur a performance cost. This behavior is known to be
tolerated by the healthy legacy release; it is not a preferred future design.
The source does not check `BeginScene` success before drawing/calling
`EndScene`, so device-lost/failure behavior is incomplete.

### Directional traversal and form policy

The directional producer walks `SettingGridsToLoad^2` loaded exterior cells,
terrain children, and cell object lists. It applies:

- form-category settings;
- `kFormFlags_NotCastShadows`;
- an excluded-form-ID binary search;
- app-culled checks;
- world-bound radius thresholds;
- water-height rejection where applicable;
- exact vtable classifications for node, fade, FaceGen, SpeedTree,
  `NiTriShape`, and `NiTriStrips` objects.

Terrain children 2 through 5 are handled explicitly. The legacy path does not
apply modern NVR's refraction/decal shader-flag rejection.

### Legacy draw ABI

Legacy NVR draws accepted geometry directly rather than calling the native
shadow draw helpers. The source establishes these generation-side facts:

- packed geometry supplies vertex buffers, index buffer, primitive type,
  stride, base vertex, start index, and primitive count;
- the path binds every populated stream and the index buffer;
- it chooses either FVF or vertex declaration;
- regular and skinned partitions call `DrawIndexedPrimitive` directly;
- skinned matrices are uploaded as three float4 rows per selected bone;
- SpeedTree uploads billboard/wind/leaf constants beginning at vertex register
  63 and binds its texture at sampler 0;
- alpha-tested forms bind their diffuse texture for shadow alpha testing.

The source has a null-safety defect in the alpha path: `AlphaProperty` can be
dereferenced when alpha rendering is enabled without a complete null guard.

The legacy HLSL sources are absent from the supplied snapshot. Exact shader
equations, compiled register declarations, sampler registers, effect pass
counts, and comparison math therefore cannot be reconstructed from this tree
alone. Only the C++-visible names, constants, formats, and bindings are proven.

### Point-light selection

Legacy point selection builds a distance-keyed `std::map<int, NiPointLight*>`.
`AddSceneLight` resolves integer-key collisions by decrementing the key until a
free entry exists, so equidistant lights are retained rather than overwritten.
The per-invocation maps and per-light vectors can allocate on the render thread.
Their healthy-runtime history is negative evidence against an allocation-only
theory, not permission for a new hot-path allocator design.

The sorted lights are divided into bounded categories:

- shadow-casting lights, with storage for 12;
- shadow-culling lights, with storage for 24;
- general point lights, with storage for 2.

Selection uses configured radius bounds, player distance, magic-light policy,
and `CastShadows`. The active legacy `AddCastShadowFlag` hook derives
`CastShadows` from form flags and carried-light policy. This active producer of
the flag is important: it makes the later selection rule meaningful.

### Point-light caster discovery and caching

Exterior point lights scan loaded cells; the x loop stops at
`SettingGridsToLoad - 1` while the y loop covers the full configured range.
Interior lights scan the current cell. References and actors are accumulated
in separate distance-keyed maps.

The static-caster optimization computes a checksum by summing reference
world-bound centers. After an approximately 30-frame warm-up it can reuse a
static map until the checksum changes or a carried-light condition invalidates
it. This checksum:

- is collision-prone;
- ignores geometry shape and rotation;
- is not a robust content identity;
- is an optimization artifact, not a future ownership contract.

A behave-like-exterior interior can use a synthetic/fake interior light path.

### Point-map render ordering

Static references are rendered face-major:

1. select cube face and its dedicated depth surface;
2. clear it;
3. begin a D3D scene;
4. traverse/draw all static references for that face;
5. end the scene;
6. repeat for six faces.

Actors are rendered geometry-major. One scene pair is opened for the light,
then each actor geometry loops through six faces, rebinding the target, depth,
matrix, and constants before drawing into the previously produced static
contents.

Unused cube faces are explicitly cleared. State transitions between exterior
and interior modes can clear all remaining faces, producing up to 72 clear
operations.

### Legacy publication and consumer ABI

The constant table exposes at least:

- shadow world and shadow view-projection matrices;
- four camera-to-light matrices;
- cube-light position;
- 12 shadow-casting light positions;
- 24 culling-light entries;
- far planes, blend values, light direction, forward/deferred bias values;
- general shadow data, skin data, ortho data, and cube data.

The texture binder exposes near, far, skin, and ortho maps plus cube maps 0
through 11. The effect collection contains exterior directional/point,
dialog-point, and interior shadow effects.

Because the HLSL/effect sources are missing, the exact consumer sampler slots,
pass topology, and mathematical merge are an explicit evidence gap. A future
implementation must use modern NVR or an independently recovered shipped
legacy binary for those details; it must not invent them.

## Modern NVR 4.4.1 contract

### Hook placement and native preservation

Modern NVR installs:

```cpp
WriteRelJump(0x871290, RenderShadowMapHook);
```

Its hook is:

```cpp
void __fastcall RenderShadowMapHook(void* apThis) {
    TheShadowManager->RenderShadowMaps();
    CdeclCall(0x871A50);
}
```

This is a common-entry replacement, not a wrapper:

- every direct caller of `0x00871290` reaches the replacement;
- native bytes `0x00871290..0x008719F7` do not execute;
- the original receiver `apThis` is ignored;
- the native tail at `0x00871A50` executes once after NVR production.

This is the decisive shadow-flow difference from current OMV.

Modern `Hooks.cpp` applies the jump as an explicit patch after its Detours
transaction. It does not inspect an existing jump or compose a trampoline
chain. Another owner of `0x00871290` is therefore a direct compatibility
conflict unless both mods negotiate ownership.

The modern `AddCastShadowFlag` hook exists in source but its installation is
commented out. `GetNearbyLights` also comments out use of the setting because
the flag is described as broken by JIP; its effective code forces
`CastShadow = true` before later radius/count filtering.

The modern leaves hook remains active at `0x0066A112` and names tree child 1
`"Leaves"`. The changed patch start versus legacy reflects a different naked
stub, but the semantic purpose remains SpeedTree leaf identification.

Modern NVR also replaces the call at `0x009BB158` with
`MuzzleLightCullingFix`. It toggles the muzzle light's culled flag from muzzle
enabled state before calling native `0x009BB8A0`. Because `GetNearbyLights`
rejects culled lights, this supporting render hook prevents inactive muzzle
lights from persisting in point-light/shadow selection.

### Startup and publication order

The engine initializes its renderer first. The renderer hook then initializes
the NVR render manager and calls `InitializeManagers`. Relevant ordering is:

1. texture manager;
2. shader manager and effect registration;
3. for each effect: `UpdateSettings`, `RegisterConstants`, `RegisterTextures`,
   and `LoadEffect`, in that order;
4. `ShadowsExteriorEffect::RegisterTextures`, within that sequence, creates and
   registers its shadow resources;
5. shadow manager and its generation passes/shaders;
6. later per-frame shadow production and image-space consumption.

This means the effect owns settings, textures, and published consumer
constants, while `ShadowManager` owns traversal and generation passes. A future
implementation should retain similarly explicit ownership even if it uses
different types.

The manager is heap allocated and described as never disposed. No complete
device-lost/reset shadow-resource release/recreate path was found.

### Initialization hazards

The effect object itself has a more fundamental construction-order hazard than
the shader-load checks. `RegisterEffect<T>` performs `new T()` and immediately
calls `UpdateSettings`, `RegisterConstants`, `RegisterTextures`, then
`LoadEffect`. `ShadowsExteriorEffect` has a user-provided constructor which
initializes only its `EffectRecord` base. That base constructor initializes
`Name`, `Effect`, `Enabled`, and the two timing fields; it does not initialize
the derived settings, constants, COM pointers, arrays, or private
`texturesInitialized` flag. Because the selected default constructor is
user-provided, the empty parentheses in `new T()` do not establish zeroed
derived storage.

The first `UpdateSettings` therefore runs before any shadow texture exists and
has this exact source-level failure sequence:

1. `Enabled` is known false from `EffectRecord`, so the final disable test
   necessarily calls `clearShadowsBuffer`.
2. `clearShadowsBuffer` captures RT0, passes the indeterminate
   `Textures.ShadowPassSurface` to `SetRenderTarget`, clears the target, restores
   RT0, and releases the captured reference. No HRESULT is checked.
3. If the pointer happens to be null, `SetRenderTarget(0, NULL)` is invalid for
   RT0. Because failure is ignored, the following red clear can apply to the
   previously bound engine target. If the pointer is non-null garbage, the call
   crosses the COM boundary with an invalid interface pointer.
4. `UpdateSettingsFromQuality` compares new settings with indeterminate old
   format, resolution, and MSAA fields. The same first update reads the
   indeterminate `texturesInitialized` flag.
5. If that flag happens true, `RecreateTextures` can test, release, and replace
   indeterminate COM pointers before `RegisterTextures` has created anything.
6. Only the later `RegisterTextures` call creates the resources and finally
   writes `texturesInitialized = true`.

`Settings.ShadowMaps.Mipmaps` and `Anisotropy` add a second initialization gap:
their settings assignments are commented out. `Mipmaps` is nevertheless passed
to atlas `InitTexture`; `Anisotropy` is retained in the structure but no active
consumer was found in the audited path.

This is C++ undefined behavior in the supplied source snapshot. It cannot be
the intended engine contract, and it is not a persuasive explanation for a
stable one-FPS state after successful startup. A released NVR binary may have
been built from different source, may obtain zero-filled fresh heap storage in
the observed environment, or may merely tolerate the first invalid calls. The
healthy released behavior does not make this source ordering safe to copy. A
future implementation must fully initialize every setting, resource pointer,
flag, and constant before its first settings update, and must never clear or
recreate an unpublished target.

`ShadowManager::Initialize` creates five pass objects:

- general geometry;
- alpha geometry;
- skinned geometry;
- SpeedTree geometry;
- terrain LOD.

It loads directional, cube, blur, and clear generation shaders and sets
`ClearSamplers = false` on each. However, it dereferences the shader pointers to
set this flag before the later null test. The null test also omits the clear
pixel shader. Missing shader files can therefore fail before the intended
`ShadowShadersLoaded = false` fallback.

This is a source defect and not a valid failure contract.

### Directional atlas formats and quality presets

Four cascades—near, middle, far, and LOD—occupy quadrants of one 2-by-2 atlas.
The atlas is twice the configured cascade resolution in each dimension.

Supported moment modes/formats are:

| Mode | Low format | High format |
|---|---|---|
| VSM | `G16R16` | `G32R32F` |
| EVSM2 | `G16R16F` | `G32R32F` |
| EVSM4 | `A16B16G16R16F` | `A32B32G32R32F` |

Built-in exterior presets are:

| Quality | Mode/format | Distance | Cascade resolution | 4x MSAA |
|---:|---|---:|---:|---|
| 0 | VSM / `G16R16` | 3000 | 1024 | off |
| 1 | VSM / `G16R16` | 4000 | 1024 | on |
| 2 | EVSM2 / `G32R32F` | 4500 | 2048 | on |
| 3 | EVSM4 / `A16B16G16R16F` | 6000 | 2048 | on |

Quality is clamped to 0 through 4; 4 enters the custom branch. Custom cascade
resolution maps setting values to 1024, 1536, or 2048. Built-in presets enable
LOD frequency limiting and prefiltering.

The supplied New Vegas defaults request quality 4 with EVSM4, 16-bit components,
2048 cascade resolution, 6000 distance, 4x MSAA, prefiltering, no mipmaps,
lambda 0.9, and LOD frequency limiting. The source reads every item in that
list except mipmaps: its assignment is commented, so the declared default does
not establish the runtime field in this snapshot. Effective ortho defaults are
512 resolution, 3000 distance, and quarter-rate updates. Interior defaults select
12 point lights, 512 cube faces, 4000 draw distance, first-person player
shadows off, and third-person player shadows on. Exterior point shadows are off
for both day and night by default.

With MSAA enabled, NVR creates a 4x multisampled render surface and matching
`D24S8` depth surface, then resolves the entire atlas into the sampleable atlas
surface with `StretchRect`.

Moment clear values are mode-dependent:

- VSM: `(1, 1, 0, 1)`;
- EVSM2: positive and negative exponential moments;
- EVSM4: positive/negative moments and their squares.

EVSM cascades use a custom full-screen clear shader. The ortho map explicitly
disables that custom clear and stores linear `R32F` depth.

### Other modern shadow resources

Modern NVR creates:

- one separate `R32F` ortho texture/surface and `D24S8` depth surface;
- 12 `R32F` cube textures with all 72 face surfaces retained;
- one shared `D24S8` depth surface for all cube faces;
- one `R32F` 2D spotlight texture per `SpotLightsMax` entry;
- one full-resolution `G16R16` point-shadow accumulation texture/surface;
- one atlas-sized screen-quad vertex buffer for clear/blur work.

All relevant resources are `D3DPOOL_DEFAULT`. Most creation HRESULTs are not
checked by callers before publication/use. `TextureManager::InitTexture` can
log failure but does not establish a coherent all-or-nothing shadow-resource
state for the caller.

The measured healthy NVR configuration used a 4096-by-4096 EVSM4 atlas with 4x
MSAA. Existing research estimates approximately 896 MiB for the atlas color,
MSAA color, and matching depth resources alone. That observation proves large
resource pressure can be healthy in at least one run; it does not prove
residency is irrelevant to OMV on every driver.

At the supplied 512 cube size, 12 `R32F` cubes consume 72 MiB of nominal face
storage and the shared `D24S8` cube depth surface adds 1 MiB. The one spotlight
map adds 1 MiB. The `G16R16` point-shadow buffer adds four bytes per output
pixel (31.64 MiB at 3840-by-2160). These figures exclude allocation alignment,
driver metadata, retained interface objects, and other NVR effect buffers.

### Dynamic recreation limitations

`RecreateTextures(cascades, ortho, cubemaps)` handles cascade and ortho changes,
but the `cubemaps` parameter is unused.

Cascade recreation releases atlas surface, optional MSAA surface, texture,
depth surface, and vertex buffer, recreates them, and clears the cached
`SunShadows` atlas sampler binding.

Ortho recreation releases its surface and texture but does not release the old
ortho depth surface before overwriting the pointer. Each such recreation leaks
that default-pool surface.

The routine does not recreate:

- point cube textures/face surfaces;
- the shared cube depth surface;
- spotlight maps;
- the full-resolution point-shadow accumulation buffer.

Interior cube resolution changes therefore do not have a complete resource
transition. Mipmap and anisotropy assignments are commented out; their struct
fields are not visibly initialized by a constructor before use, creating an
additional source-level indeterminacy risk.

### Top-level invocation sequence

Modern `ShadowManager::RenderShadowMaps` performs:

1. return if global render effects are disabled;
2. allocate zeroed stack arrays for 12 native shadow-scene lights, tracked
   ordinary lights, and spotlights;
3. call `ShaderManager::GetNearbyLights`;
4. compute exterior/interior/ortho enablement;
5. return if no producer is required, shaders are unavailable, or the player
   has no parent cell;
6. capture D3D state and configure shadow-generation state;
7. update/setup scene camera and periodically flag player geometry;
8. call `BeginScene` once;
9. produce applicable directional cascades and ortho map;
10. produce applicable point cube maps;
11. produce an optional flashlight spotlight map;
12. restore the explicitly captured subset and release captured surfaces;
13. perform optional debug saves;
14. call `EndScene`;
15. advance `FrameCounter` modulo four.

`GetNearbyLights` occurs before the shadow-enabled early-out. Even a call that
does not render a replacement map can therefore scan/sort lights and publish
light constants.

The single NVR scene pair spans all maps. It must be entered when the engine is
not already inside a D3D scene pair. The current dispatcher placement satisfies
that in the known engine flow; moving this producer to a later image-space or
draw hook could make `BeginScene` nested and invalid.

The source does not branch on the `BeginScene` HRESULT and always reaches
`EndScene` on its successful producer path. Microsoft documents that `EndScene`
is invalid when the preceding `BeginScene` failed. A future implementation must
handle that failure and restore the captured state without issuing draws.

### Captured and restored state

Modern NVR captures:

- depth-stencil surface;
- RT0;
- viewport;
- `ZFUNC`;
- `STENCILENABLE`, `STENCILREF`, `STENCILFUNC`;
- `ALPHAREF`;
- `NORMALIZENORMALS`;
- `POINTSIZE`.

It mutates those and many additional states through `NiDX9RenderState`, then
restores the captured surfaces/viewport/scalars through raw device calls. It
does not restore at least:

- vertex/pixel shaders;
- FVF or vertex declaration;
- vertex streams and index buffer;
- textures and sampler states;
- `ZENABLE` and `ZWRITEENABLE`;
- cull mode;
- alpha blend/test enable and alpha function;
- depth bias and slope-scale depth bias.

There is a second subtle contract violation: mutation through
`NiDX9RenderState` updates the engine's cached state, while raw-device restore
does not necessarily update that cache. The device and engine cache can
therefore disagree on restored scalar values.

This incomplete restoration is source-proven and known to work in the intended
caller sequence because subsequent world setup repairs the state. It is not a
safe general plugin boundary.

### Cascade partition and stabilization

`GetCascadeDepths` uses a practical split between logarithmic and uniform
partitions with a configurable lambda. It starts from camera near plus 10,
clamps the configured shadow distance against the camera far range, and
publishes four contiguous split depths.

`GetCascadeViewProj`:

- transforms camera-frustum corners into world space;
- isolates the current split interval;
- computes a bounding sphere;
- compensates for field of view;
- builds a camera-relative light view;
- snaps the projection to shadow texels to reduce shimmer;
- uses a zero near plane and extent-derived far plane;
- records frustum planes, camera translation, center, and radius;
- dynamically adjusts minimum caster radius.

Sun/moon selection is combined with angular smoothing/quantization and a
time/moon-phase fade for the consumer constants.

### Cascade cadence

- Near, middle, and far cascades are rendered on every successful exterior
  producer invocation.
- LOD is rendered every fourth successful invocation when frequency limiting
  is enabled.
- On skipped LOD invocations, its camera-to-light matrix is translated by the
  camera delta to reduce visible jumps.
- Ortho is rendered every fourth successful invocation with a phase offset of
  two when its limiter is enabled.
- On skipped ortho invocations, its matrix is likewise translated by camera
  delta.
- `FrameCounter` advances only after the producer reaches its successful end;
  early-out calls do not advance cadence.

These are invocation-based rules, not present-based rules. If the hook executes
in a screenshot/special-render context, cadence can advance independently of
what the player perceives as one gameplay frame.

### Directional traversal and queues

Each active directional map traverses loaded exterior grid cells and optional
LOD roots. `GetRefNode` rejects null nodes, non-casting forms, unsupported form
types, and strong refraction. `CheckShaderFlags` rejects refraction,
fire-refraction, decal, and dynamic-decal shader properties.

Iterative child traversal applies:

- app-cull state;
- minimum world-bound radius;
- switch-node active child selection;
- frustum and multibound tests;
- fade-alpha threshold (`< 0.75` is rejected in the shown traversal);
- map-specific form policy.

Accepted geometry is queued by priority:

1. skinned;
2. SpeedTree;
3. LOD land;
4. alpha;
5. general.

The queues render in the distinct order general, terrain LOD, alpha, skinned,
then SpeedTree. Pass shaders are installed once per nonempty queue. Per-geometry
constant tables are then updated.

### Geometry submission ABI

For regular geometry, modern NVR delegates final submission to engine functions
instead of directly issuing every indexed draw:

- `NiTriStrips`: `0x00E74840`;
- `NiTriShape`: `0x00E745A0`.

It preserves and reapplies the geometry dirty flags around those calls.

Skinned geometry calculates matrices, optionally copies skin-to-world data,
uploads three float4 rows per bone beginning at vertex constant 9, and submits
through `0x00E6D310`.

SpeedTree uploads billboard, wind, rock/rustle, and leaf data in the c63-c130
range and binds sampler 0. Terrain LOD publishes its world/high-detail/LOD
parameters in c140-c145.

### Atlas clear, resolve, prefilter, and mip behavior

Each cascade selects its atlas quadrant viewport and clears only that region.
EVSM modes use a clear pixel shader and screen quad because fixed-function clear
cannot express the desired moment vector. When MSAA is active, all cascade
draws target the MSAA atlas and one full-atlas `StretchRect` resolves it.

Prefilter then binds `ShadowAtlasTexture` as the source while
`ShadowAtlasSurface`, level zero of the same texture, remains the render target
for two blur draws. The source snapshot therefore contains same-subresource
read/write feedback rather than ping-pong resources. That is a correctness and
driver-validation hazard and must not be copied, even though the tested NVR
runtime is healthy.

Optional autogenerated mip levels are generated after prefiltering. The source
comments say mipmaps are disabled for deferred shadow derivatives, but the
resource path still contains configurable/autogen support.

### Point-light discovery and ordering

`GetNearbyLights` iterates `SceneNode->lights` and rejects app-culled or nearly
black lights. It admits a light when it is in front of the camera or contains
the player and when distance plus radius is under a hardcoded 8000-unit draw
distance.

It sorts using `std::map<int, ShadowSceneLight*>` with key
`(int)(Distance * 10000)`. Unlike legacy `AddSceneLight`, it does not resolve
key collisions. Exact integer-key collisions overwrite an earlier entry.
The map and traversal/pass containers can allocate during shadow production;
modern source also constructs timing-label strings around cascade/cube work.
Those costs were tolerated by the healthy source configuration but are not
invariants to copy.

Constant arrays are cleared, then the sorted list is divided into:

- at most 12 shadow candidates, requiring radius greater than 10;
- at most 12 tracked nonshadow lights;
- bounded spotlights.

The cast-shadow decision is forced true in the shown code. The configured
`UseCastShadowFlag` is read but not applied because its intended expression is
commented out.

### Point cube producer

Point maps render when exterior day/night policy allows them or when interior
shadows are enabled. The loop count is the configured interior `LightPoints`,
clamped to 12.

For each selected `ShadowSceneLight`:

- the source native light supplies position and radius;
- six 90-degree cube cameras are constructed;
- every face binds its retained `R32F` face surface and the one shared cube
  depth surface;
- the face is cleared and accepted geometry is accumulated/rendered;
- the native `ShadowSceneLight::kGeometryList` is preferred when present;
- a full cell-reference fallback is used when that list is absent.

The traversal/accumulation work is repeated for all six faces. Player geometry
is periodically tagged so first- versus third-person visibility can be
filtered. Refraction/decal and near-transparent geometry are rejected.

The generation shader stores normalized radial distance in `R32F`.

### Spotlight producer

If the flashlight effect is enabled, a spotlight is active, and its settings
request shadows, NVR renders each valid bounded spotlight into its dedicated
`R32F` 2D map using the shared cube depth surface. It publishes the
spotlight camera-to-light matrix for the later effect.

### Generation shader ABI

The modern source includes the HLSL, so its generation ABI is directly proven.

Directional/ortho vertex constants:

| Registers | Meaning |
|---|---|
| c0-c3 | object world matrix |
| c4-c7 | shadow view-projection |
| c8 | data: geometry type, alpha/context, ortho marker |
| c9+ | up to 54 float4 skinned-bone rows |
| c63-c130 | SpeedTree billboard/wind/leaf data |
| c140-c143 | transposed terrain world matrix |
| c144 | terrain high-detail range |
| c145 | terrain LOD-land parameters |

The directional vertex shader emits clip depth and optional alpha UV and
clamps projected z to at least zero. The pixel shader samples diffuse alpha at
sampler 0, discards below 0.5, and writes VSM/EVSM moments. The ortho marker
selects linear `R32F` depth instead.

Cube generation uses c0-c3 world, c4-c7 cube view-projection, c8 data, c9+
bones, and c63 light position/radius. Its pixel shader samples alpha at sampler
0, discards below 0.2, and stores `length(light-to-fragment) / radius`.

Blur uses the atlas at sampler 0 and inverse-resolution/direction constants.
The clear shader consumes one clear-color constant.

These registers are a coherent producer ABI. They are not evidence that shader
math causes OMV's NVIDIA performance failure.

### Deferred consumer graph

Modern NVR consumes the produced resources before tonemapping:

1. combined world/first-person depth and normals are available;
2. `PointShadows` renders into the full-resolution `G16R16` point-shadow
   accumulation buffer and clears it;
3. `PointShadows2` runs without clearing when more than six configured point
   lights are enabled;
4. `SunShadows` runs for exterior scenes without clearing that accumulation;
5. exterior or interior final shadow effect combines the accumulated shadow
   term into the scene.

`SunShadows` binds:

- combined depth at s0;
- shadow atlas at s1;
- normals at s2;
- point-shadow buffer at s3;
- noise at s4.

It uses four camera-to-light matrices and atlas quadrant transforms, selects
cascades by their sphere centers/radii, blends boundaries, evaluates
VSM/EVSM, and combines its result with the point term.

`PointShadows` reads depth/normals, samples cube maps 0 through 5, incorporates
tracked nonshadow lights and spotlight contribution, and writes a monochrome
shadow/light term. `PointShadows2` reads the existing buffer and samples cube
maps 6 through 10.

This reveals a source quirk: 12 cube maps and 12 shadow-light constants can be
produced, but the deferred consumers sample cubes only 0 through 10. Light 11
falls through the nonshadowed/fallback contribution rather than receiving its
cube shadow in the shown consumer chain.

### Effect copy ownership

Modern `EffectRecord::Render` may copy the current render target to a shared
source buffer, renders each effect pass, and then `StretchRect`s the target to a
shared rendered buffer after every pass. The shadow consumers participate in
that general graph.

The healthy observer therefore includes substantial full-resolution copy and
effect state traffic. It does not establish that copy placement is free: it
establishes that raw count alone is not sufficient to explain OMV's one-FPS
failure.

## Side-by-side shadow contract

| Dimension | Native game | Legacy NVR source | Modern NVR source | Current OMV |
|---|---|---|---|---|
| Hook target | owns `0x871290` | replaces branch-C call at `0x870C39` | replaces common entry `0x871290` | wraps common entry `0x871290` |
| Entry ABI | thiscall-like receiver in `ECX` | naked stub preserves registers and supplies replacement manager in `ECX` | fastcall hook captures `apThis` from `ECX` | incorrectly declared zero-argument cdecl; receiver is not preserved |
| Coverage | all dispatcher variants | only `0x870BD0` variant | all variants | all variants |
| Native prefix | executes | skipped on hooked branch | skipped everywhere | executes through trampoline |
| Native tail | called by prefix | preservation source is contradictory | explicit `0x871A50` once | called inside original prefix |
| Construction/resource publication | engine-owned | constructor leaves unsafe member state | first settings/clear precedes resource creation with indeterminate derived state | explicit Rust owners, but local-light capture repeatedly rediscovers native resources |
| Replacement output | native local shadows | four R32F directional maps + 12 cubes | moment atlas + ortho + 12 cubes + spot maps | no replacement shadow producer |
| Local-light work | native selection | own selection and cube production | own nearby-light selection and cube production | optional completed-slot capture inside native prefix plus post-native scan/publication for atmosphere and PBR terrain |
| Begin/EndScene | native engine ownership | many nonnested pairs | one pair around all maps | no pair in local-light capture itself |
| State restoration | engine-defined | restores depth only | partial explicit restore | original restores native behavior; OMV capture does no shadow state |
| D3D cache coherence | native | raw/cache mixture | cache mutation + raw restore mismatch | depends on each OMV owner |
| Reset ownership | native | incomplete in snapshot | incomplete in snapshot | OMV resources have separate lifecycle owners |
| Healthy observer workload | not measured separately | not measured | replacement workload measured healthy | affected current path not fully attributed |

## Proven NVR invariants versus incidental defects

### Invariants worth preserving

- Initialize D3D-dependent shadow ownership only after the engine renderer and
  device exist.
- Install shadow ownership once, outside render-hot callbacks.
- Use an engine semantic boundary before world rendering, not a universal D3D
  draw or texture hook.
- If replacing `0x00871290`, cover all three direct callers and invoke the
  proven native tail exactly once.
- Publish producer textures, matrices, light arrays, and consumer constants as
  one coherent frame/epoch.
- Bound light counts and traversal.
- Keep shadow generation and screen-space consumption in known render stages.
- Preserve the caller's required world-render continuation.

### Defects and shortcuts that are not invariants

- legacy's branch-only hook coverage;
- legacy's invalid `0x004073D0` source literal;
- both snapshots' incomplete default-pool reset ownership;
- legacy's depth-surface COM leak and constructor out-of-bounds write;
- modern effect registration calling settings/clear/recreation code before
  initializing derived resource pointers and flags;
- unchecked resource-creation failures;
- modern null dereferences before shader validation;
- modern ortho-depth leak and unused cube-recreation parameter;
- modern same-subresource atlas blur;
- incomplete render-state restoration and engine-cache divergence;
- modern distance-key collision overwrite;
- forced cast-shadow behavior and the unused twelfth deferred cube.

Known healthy runtime makes these defects compatible with at least the shipped
NVR configurations. It does not make them good implementation contracts.

## Contract for a future OMV shadow implementation

This section records requirements, not a request to implement them now.

### Hook and ABI ownership

1. Select wrapper or replacement behavior explicitly. A replacement must not
   call the original prefix; a wrapper must not call the tail separately.
2. Prefer the common `0x00871290` entry only if OMV intends to own shadows in
   every dispatcher variant.
3. Preserve `0x00871A50` exactly once on this executable when replacing the
   prefix.
4. Declare a thiscall/fastcall-compatible detour and trampoline type that
   captures the incoming `ECX` receiver. Preserve/pass it even though this
   executable's tail does not read it; do not generalize modern NVR's ignored
   `apThis` to unknown executables.
5. Detect existing patches and fail closed or use an explicit capability/chain
   protocol. Modern NVR and current OMV cannot independently own the same first
   five bytes safely.
6. Count and classify normal, special, and screenshot invocations during
   validation.

### Threading and epoch ownership

- All device work and engine scene traversal remain on the render thread.
- Settings may be staged off-thread, but resource transition/publication occurs
  at a proven render boundary.
- One producer invocation publishes one immutable shadow epoch containing map
  identities, matrices, light identities, counts, and validity flags.
- Screenshot/special invocations must not silently advance a gameplay cadence
  or overwrite a gameplay epoch unless that behavior is intentional.
- Render callbacks must not take blocking locks, allocate routinely, perform
  file I/O, or validate stable engine pointers through `VirtualQuery`.

### Device and resource lifetime

- Initialize every settings field, COM pointer, validity flag, viewport, and
  publication slot before the first settings/update/clear call.
- Retain the engine device from renderer lifecycle ownership instead of
  rediscovering it through checked pointer chains per map or light.
- Explicitly release every successful D3D getter result.
- Check every creation result and publish resources only when the complete
  required set exists.
- Release all default-pool resources before reset and recreate them after a
  successful reset/resolution transition.
- Treat resolution, format, MSAA, cube size, spotlight count, and full-screen
  accumulation size as one transactional configuration transition.
- Invalidate all cached consumer samplers when a texture identity changes.
- Use ping-pong surfaces for separable blur; never sample the subresource being
  rendered to.

### Scene and light ownership

- Establish whether OMV is replacing native candidate selection or consuming
  native completed shadows. Do not mix those identities accidentally.
- If native `ShadowSceneLight::kGeometryList` is consumed, prove its producer
  epoch and lifetime for each dispatcher mode and retain a bounded fallback.
- Avoid collision-prone distance maps; use a stable total ordering that retains
  equal-distance lights.
- Define cast-shadow policy independently of optional third-party flag
  mutations.
- Define player first-/third-person caster policy explicitly.
- Keep form, shader-flag, refraction, alpha, multibound, fade, and LOD filtering
  observable/testable rather than inheriting NVR quirks implicitly.

### D3D9 state and scene ownership

- Prove the hook is outside an existing scene pair before calling `BeginScene`.
- Use one scene pair for the complete producer unless measurement proves a
  different legal structure is better.
- Capture and restore a documented complete state subset, including all
  attachments, viewport, shaders, declarations/FVF, streams, indices,
  textures/samplers, and render states actually changed.
- Keep `NiDX9RenderState` cache and raw device state coherent. Restore through
  cache-aware setters or explicitly repair/cache-invalidate both sides.
- Account for `SetRenderTarget` resetting the viewport to the new target's full
  dimensions; every sub-atlas pass must install its own viewport after target
  changes.
- Match render-target/depth format, dimensions, and multisample type.

### Producer/consumer ABI

- Version the constant and sampler ABI in code and documentation.
- Publish cascade transforms, centers/radii, map mode/format, fades, light
  positions/radii/colors, cube/spot indices, and counts atomically.
- Keep the number of produced cube maps equal to the number consumers can
  actually sample.
- Define clear values for every map representation.
- Ensure skipped-cascade matrix reprojection and cadence are keyed to the
  intended gameplay epoch, not merely hook call count.
- Place deferred consumers after their required depth/normals and before the
  final exterior/interior composite, with exact first-person semantics.

### Validation required before shipping

- no-OMV native visual baseline;
- pass-through common hook with no producer;
- exterior directional maps at every quality/format/MSAA combination;
- interior/exterior point lights at count limits and equal distances;
- flashlight spotlight shadows;
- actors, first person, SpeedTree, alpha geometry, terrain, LOD, refraction,
  decals, multibounds, water, and behave-like-exterior cells;
- normal render, special render, screenshot, menus, alt-tab, resolution change,
  reset, and device replacement;
- NVIDIA native Windows, AMD control, and Proton/DXVK;
- CPU and GPU timings attributed by producer stage rather than aggregate FPS;
- balanced COM references and stable VRAM/resource counts across recreation.

## OMV implementation (2026-08-12)

### Status, scope, and configuration ownership

The 2026-08-12 corrective pass addressed the first integration's observed
zero-impact behavior and missing controls. Static analysis, source comparison,
and user runtime logs identified nine concrete divergences: an MSAA
resolve directly into an atlas sub-rectangle, all-or-nothing exterior/interior
allocation, reliance on the point-light cast flag that modern NVR declares
broken under JIP, a `NiMaterialProperty::fAlpha` read from `fEmitMult` at
`+0x40` instead of alpha at `+0x3C`, a scalar `COLOR0` return in the cube pixel
shader, a common-entry classifier that treated a main-render wrapper as
exclusively offscreen, and a first-use path that returned after allocation
without producing any map, followed by a classifier that equated top-level
renderer ancestry with outer-world ownership and an exact-epoch publication
rule that discarded completed maps before a later valid scene-pre callback.
The implementation and tests reject all nine.

The scalar output was the observed all-branch activation blocker. The
2026-08-12 runtime log proves that DeferredInit, shadow configuration, and both
resident hook groups completed, then records `error X4529: COLOR0 must be a
four-component vector` for `shadow_cube.hlsl`. Shader publication is
intentionally transactional, so this one compiler rejection left
`prepared_bytecode()` empty and every common entry selected native fallback.
The cube target is `R32F` and consumers read red only; returning the same radial
depth as `float4(depth, depth, depth, 1)` satisfies the legacy compiler without
changing stored data, sampling, precision, or quality.

The next supplied runtime log closed that compiler blocker: all eleven programs
prepared successfully, exterior resources finished allocation, and no shader
or resource failure was recorded. A source-to-contract audit then found three
concrete first-transaction work amplifiers: all four 2048 cascades were rebuilt
in one invocation, object/land LOD roots were traversed in near and middle maps
where NVR disables them, and NVR's per-map projected-radius plus form-category
pruning was absent.

The corrective producer clears a dirty atlas to valid neutral EVSM4 far
moments and produces all four complete full-quality cascades before its first
publication. The engine common entry is a transaction boundary, not a frame
callback with a promised equivalent successor. Deferring resource use or the
remaining cascades to later entries could therefore leave the effect permanently
unpublished. Steady-state resolution, FP16 format, 4x sampling, filtering, and
staggered distant-cascade cadence are unchanged.
Near/middle keep NVR's one-pixel caster threshold; far/LOD use ten pixels,
converted to world radius from each stabilized cascade extent. LOD roots and
NVR's restricted form profile are admitted only in the matching far/LOD
routes. These changes remove work that modern NVR itself rejects rather than
reducing its steady-state image-quality profile.

One supplied runtime log used an exact deployed/release DLL match (12,711,514
bytes, SHA-256
`4823973c477df75056b5c1c866fe5515b92a8f13d3eac066fd5432ce983146fb`). It
proved DeferredInit, all eleven shader programs, and ordinary world color/depth
were active. Exterior and interior shadow resources became ready 12 ms apart;
a roughly 450 ms gap followed, while no D3D error, main map publication, or
scene-pre composition was logged and normal rendering continued. That evidence
led to the caller-chain correction below, but the user's following unchanged
image proved that correction was not sufficient.

An intermediate executable analysis correctly proved that immediate dispatcher
return `0x008721A9` belongs to shared wrapper `0x00871DC0`, but initially used
outer image-space ownership as the producer-admission rule. A wrapper nested
below the top-level renderer is not necessarily the outer player-visible world
transaction, but map production and image-space consumption have different
inputs and therefore require different ownership tests.
`0x0086ED86` is reached only after active-menu query `0x007023C0` returns
`0x3F4`, which NVR's headers identify as Sleep/Wait. Helper `0x0086F450` is
likewise guarded by rendered-menu state and explicit Message/Hacking menu IDs.
The nested wrapper at `0x0087000F` is a subtransaction inside `0x0086FF70`.
Unlike the direct Sleep/Wait and rendered-menu wrappers, its exact caller chain
continues through return `0x00870014`, then through `0x0086FF70` return
`0x0086EDED` into the main renderer. It does not own the later scene-pre
destination. OMV generation, however, reads the global world camera, current
player cell, TES roots, and global sun and writes only private OMV resources;
it does not read the wrapper camera or destination. The complete D3D state is
restored before native rendering resumes. This exact nested chain is therefore
a valid gameplay-map producer even though it is not the consumer owner.

Direct dispatcher returns `0x00870249` and `0x008702AE` remain valid when their
`0x0086FF70` owner returns to main root `0x0086EDED`. The classifier admits
those direct chains plus only the exact nested `0x00870014 -> 0x0086EDED`
wrapper chain. Direct wrappers returning to `0x0086ED8B` or `0x0086F4E8`,
dedicated screenshot calls, and unknown ancestry retain native ownership. The
corrected evidence is appended to
`analysis/radare2/output/graphics_fnv_shadow_main_context_call_chain.txt`.

The next supplied runtime log is an exact match to the deployed release DLL
(12,694,159 bytes, SHA-256
`dd5069e2383bbff6d21bfae3c02875bdaf66b590dccfcbcdacb259c1ff4da4c2`). It
records all eleven programs ready, thousands of active ordinary world frames,
and valid exterior color/depth inputs. Its only later shadow event is
`Exterior resources ready` at the final log line; it contains no map-production
or scene-pre-composition event. Source order makes this signature decisive:
after successful shared and exterior resource creation, `produce` set
`resources_warmed` and deliberately returned `FallbackNative` before
`produce_transaction`. The design assumed another equivalent main invocation
would arrive. The observed transaction supplied no such successor, so no map
could be published and the effect necessarily had zero visual impact.

Modern NVR does not split this ownership. `RenderShadowMapHook` calls
`ShadowManager::RenderShadowMaps` synchronously, and that function creates a
complete four-cascade result before returning to native tail `0x00871A50`.
OMV now follows the same transaction invariant: the first valid main entry
copies camera POD, creates any missing reusable resources, renders every dirty
cascade (all four for first publication), restores D3D state, and publishes or
falls back as one operation. The old implementation is retained as a negative
control by tests that fail if `resources_warmed` can defer generation or an
incomplete first cascade family can be published.

The following deployed build (12,688,190 bytes, SHA-256
`170bc3797ea1611f66609f58bfdb22e713cdf3a5ecd90de6ad283cea1668b80e`)
proved a later failure boundary. It logged all eleven shaders ready, exterior
resources ready, and `exterior maps produced for the main epoch`, but never
logged scene-pre composition. Two independent source-level publication defects
remained after generation:

1. `Special` and `Screenshot` calls entered the same producer, cleared the
   current publication, overwrote the shared atlas, and returned without a
   scene-pre publication. The executable proves that menu/offscreen wrapper
   calls can occur beneath the main renderer and do not own the outer
   image-space destination.
2. The consumer required exact equality with the producer's Present epoch.
   If a valid outer scene-pre callback arrived after one `DisplayScene`, it
   discarded the completed map family before attempting composition. NVR
   intentionally reuses completed maps across frames, and OMV's matrix rebasing
   already supports that bounded reuse.

The next exact-match runtime log contains 1,750 lines from deployed
12,693,615-byte DLL SHA-256
`da06176051530f6ecd54e2f355923ec2a3b5285f380f462fc53252a5bacd0c5c`.
It records DeferredInit, all eleven shadow shaders, and thousands of valid
world color/depth epochs, but its complete shadow record consists only of
route installation and shader preparation. There is no resource creation, map
production, composition, or D3D failure. This excludes shader, allocation, and
compositor math as the boundary for that build: the main-only admission test
rejected every observed common-entry invocation before `produce`.

The previous exact-match log had proved that the nested wrapper chain reaches
generation by recording a completed gameplay map. Rejecting that chain in the
following build removed all production. The next correction admitted only
`0x008721A9 -> 0x00870014 -> 0x0086EDED`; the user's unchanged image rejected
that correction too.

The exact rejected build was 12,693,344 bytes with SHA-256
`a25647dba545bcdef392b76249c5054bd9e35bc7da7657807fe74afda6852d0b`.
Its 1,227-line log again contains only route installation and successful
preparation of all eleven shaders while the ordinary world pipeline completes
thousands of frames. It has no shadow resource, production, composition, or
D3D-failure event. The deployed DLL exactly matches the locally built artifact.
This proves that ancestry remained the only boundary reached by the failed run.

The root error was treating producer admission and consumer-destination
ownership as the same contract. Modern NVR installs one jump at common entry
`0x00871290`; `RenderShadowMapHook` unconditionally calls
`ShadowManager::RenderShadowMaps` and then native tail `0x00871A50`. It does not
inspect the outer caller, wrapper return, menu, or screenshot ancestry. That is
safe for OMV generation too: the producer reads the global world camera,
current cell/TES roots, global sun, and scene-light manager and writes only
private OMV targets. It neither reads nor retains the caller's destination.
Only the later scene-pre composition needs the outer player-visible target.

OMV now follows that NVR ownership boundary exactly. Every invocation of the
validated common entry may create the first complete publication for its render
epoch. Later common-entry invocations in the same epoch reuse that immutable
publication and call only the native tail, so menu or screenshot calls cannot
erase or partially replace it. Caller ancestry remains relevant only to the
separate scalar-light POD publication used by atmosphere/PBR. A complete shadow
publication is consumable in its production epoch or the immediately following
epoch, including `u32` wrap; anything older expires.

The user's effective custom INI contains `bDrawShadows=0`. This is not an OMV
admission switch. Radare2 resolves `bDrawShadows:Display` at `0x01021A40`, its
initializer at `0x00F3FE80`, and setting object `0x011C74D4`; the object's only
executable xref is native-prefix helper `0x00871A10`. There is no outer
dispatcher xref. OMV and modern NVR both replace the common prefix before that
check. Modern NVR
also does not force `bDrawShadows`; it forces the native canopy/actor subfeature
settings off. OMV therefore does not rewrite user INI state. Native fallback
may legitimately draw nothing with this setting, but the validated OMV common
entry still generates and publishes the replacement.

OMV now owns one user-facing **Shadows** effect with schema-one working
configuration values for location admission, appearance, and bounded work:

```toml
[graphics.native_shadows]
enabled = true
exterior_enabled = true
interior_enabled = true
exterior_darkness = 0.75
exterior_distance = 6000.0
cascade_split_lambda = 0.90
contact_shadows = true
contact_distance = 180000.0
contact_ray_distance = 2000.0
interior_darkness = 0.65
interior_shadowed_lights = 12
interior_light_radius_multiplier = 1.50
interior_light_draw_distance = 8000.0
interior_receiver_bias = 0.018
```

`enabled` is the effect master. The other two values independently admit
exterior/behave-like-exterior cascades and interior point shadows. The
remaining values have finite or discrete bounds described below. The global
`graphics.screen_space_shaders` switch masks runtime admission without changing
the persisted values. Shadows are not preset-owned, no existing serialized
field changed position or type, `CONFIG_SCHEMA_VERSION` remains 1, and the
built-in preset payload/version is unchanged.

ImGui edits are live, not restart-only. `draw_native_shadows_config` mutates a
local coherent shadow snapshot rather than the pre-Deferred
`GraphicsMenuConfig`; the menu transaction detects that change and calls
`shadows::configure_runtime_options`. That function publishes all fourteen raw
persisted values through an even/odd atomic sequence counter, while render
admission applies the graphics-wide master without mutating those values.
Render hooks read one coherent snapshot without taking a lock. A direct
round-trip test covers every field and a second test proves that master gating
cannot overwrite the effect switch. After a Shadows-specific menu edit is
published, OMV emits one `[SHADOWS] Menu settings published` record containing
the effective master, both location gates, and every bounded quality/work
value. This log is change-driven from ImGui and adds no render-hook diagnostic
work. Current Look autosave reads the same coherent snapshot on its existing
worker, and external reload publishes the separately parsed table there only
after the complete reload transaction succeeds.

The next exact deployed/release match was the 12,696,244-byte DLL with SHA-256
`6aff1a9c599b3d4e9e07a8c064129a7dc298a9062a9841cb1f3ceecaf69fb1fb`.
Its supplied log proves the complete wiring path: DeferredInit opened all three
shadow gates, all eleven programs compiled, the four 2048 EVSM4 cascades were
allocated with 4x sampling, exterior maps were produced, and the exterior
publication was composed into scene color. It also records live disable/enable
changes and every edited scalar, including exterior darkness and cascade
lambda. The user nevertheless observed zero visual change and a 20-30 FPS
loss while Shadows was enabled. This excludes missing menu publication,
configuration admission, shader preparation, map-resource allocation, and a
missing scene-pre call as causes for that artifact. The large enable-only cost
also proves that the expensive producer/consumer graph was executing; it does
not prove that any fullscreen draw wrote a pixel.

Source comparison at that narrowed boundary exposed a D3D9 ownership defect.
`bind_fullscreen_state` disabled depth, culling, blending, scissor, and sRGB
writes, but inherited alpha test, stencil test, color-write masks,
multisample masks, and vendor alpha-to-coverage state from whichever Fallout
route reached the common producer or outer image-space consumer. D3D9 reports
`DrawPrimitiveUP` success even when those predicates reject every fragment.
The defect therefore permits exactly the observed signature: all cascade,
resolve, blur, contact, copy, and composition work consumes frame time while
the final scene remains byte-for-byte unaffected. Every other established OMV
fullscreen pipeline explicitly disables alpha/stencil rejection and restores
all color channels.

Shadow fullscreen and generation passes now establish alpha-test function and
reference, disable alpha and stencil rejection, enable all color channels and
MSAA samples, disable the detected NVIDIA/AMD alpha-to-coverage mode, and force
non-sRGB sampling for depth, moments, and intermediate buffers. The complete
transaction state block still restores the caller afterward. A regression
test was first demonstrated failing on the missing alpha-test state and now
locks the whole pixel-admission contract.

The same audit found a separate cache-coherency and performance defect. On a
cadence-skipped middle/far/LOD cascade, OMV retained the old atlas quadrant but
recomputed and published a current-camera projection and origin. That samples
old moments through an unrelated transform, causing displaced or neutral
visibility, and performs projection work that cannot update the texture. A
cached quadrant, projection, generation origin, and split are now refreshed
as one unit only when that cascade is rendered. Skipped cascades retain their
matching metadata and use the existing consumer-side camera rebasing. This
removes invalid work and preserves quality; it does not lower NVR's 2048
resolution, 4x sampling, EVSM4 precision, prefilter, or caster coverage.

The next deployed artifact exactly matched local `omv.dll` at 12,697,085
bytes and SHA-256
`6923b49d7cdd529902ec9cd087819bc5dbbfbe951bcc7d3a17cd09b7b305b6dc`.
Its supplied log records all eleven programs ready, four-cascade allocation,
map publication, scene-color composition, coherent world depth, and coherent
first-person depth. The user then confirmed that shadows were finally visible.
That observation closes the former output-admission blocker, but the same run
exposed six new acceptance failures: 30-40 FPS rather than the normal 120 or
more, incomplete third-person actors and small geometry, wall flicker, nearby
shadow changes when only distance changed, and world shadows composited over
first-person hands/weapons.

Source comparison reduced those symptoms to explicit contracts:

- `DirectionalVisibility` evaluated all four atlas lookups before selecting a
  cascade. At 3440 by 1440 this issued four expensive FP16 EVSM reads for every
  world pixel, although only one cascade (and a second only in a blend band) can
  contribute.
- The contact ray and both separable filters ran at full output resolution.
  Their deliberately soft, depth-filtered result does not require three native
  resolution work passes.
- Cascade refresh was invocation-count based, so its cost scaled up with an
  uncapped presentation rate; a distance edit also cleared the whole 4096
  atlas and dirtied every quadrant even when only the LOD interval changed.
- Ordinary shade-subtype filtering ran before the skinned pass, rejecting
  `HairShader` actor partitions. Alpha texture lookup was restricted to
  `kProp_PPLighting`, although NVR admits ordinary geometry by
  `BSShaderProperty::uiShaderIndex` (`ShadowLight`, `Parallax`, or
  `Lighting30`) and reads `ppTextures[0]` for every admitted lighting property.
  OMV also incorrectly disabled NVR's near/middle books and LOD misc forms.
- The EVSM minimum-variance calculation used receiver bias `0.00002`, while
  NVR uses `0.01`. The 500-times smaller floor exposed FP16 quantization as
  unstable self-shadowing. Contact-ray length was additionally randomized by
  screen coordinates, so camera motion moved the pattern over walls.
- The consumer ignored the already-proven `DepthFrame.first_person_texture`.
  Existing AO/HDR consumers establish that valid non-endpoint pixels in this
  separate current-epoch capture are the exact view-model mask.

The first performance implementation kept four 2048 EVSM4 cascades, FP16
moments, 4x MSAA when supported, the separable prefilter, and NVR caster
thresholds while bounding repeated work. The later runtime report documented
below rejected that cost/quality tradeoff: 4x nonlinear moment generation was
still the dominant avoidable bandwidth immediately before a mandatory spatial
prefilter.
The selected cascade now uses SM3 relative constant addressing and performs
one atlas lookup, plus one neighbor only inside the five-percent blend band.
Exterior contact ray/filter targets are half resolution in each dimension and
branch-lazy; the final native-resolution composition linearly upsamples the
already depth-filtered soft visibility. At 3440 by 1440 this reduces contact
ray/filter pixel executions from 14,860,800 to 3,715,200 per composed frame.
Interior point lighting retains independent full-resolution normal and
illumination targets.

Map cadence is now monotonic-time based rather than present-count based:
near/middle/far/LOD have maximum refresh periods of 16/33/50/66 ms. Late
presentations advance the deadline by whole periods instead of resetting its
phase, avoiding accumulated 48 Hz drift on a 144 Hz presentation loop. Dirty
projections bypass the cap synchronously, and the first publication still
produces all four maps in one engine transaction. The consumer continues to
rebase a cached map from its immutable generation origin between refreshes.

The initial distance correction kept every inner boundary on NVR's 6000-unit
profile. Runtime observation showed why that was invalid: at a played distance
of 15,957 units the actor-capable far cascade still ended around 1,800 units,
putting the remaining view into the LOD profile that excludes actors and most
small gameplay forms. The final policy anchors only the near boundary at the
6000-unit profile and lets middle/far expand using NVR's practical split. It
therefore preserves near shadow density while restoring gameplay-caster reach.
Per-cascade comparison refreshes only the changed outer quadrants.

Caster pass order now matches NVR: skinned, SpeedTree, lighting-validated
terrain/ordinary alpha, then ordinary lighting geometry. This retains
third-person hair/body partitions and all `ppTextures[0]` lighting cutouts.
The supplied NVR TOML, rather than its different C++ quality-constructor
defaults, is the runtime profile authority: books are disabled in all four
maps and misc forms are disabled only in LOD. Receiver variance uses the source
`0.01` bias and contact samples use fixed stratification. Finally, the
compositor binds coherent first-person depth at sampler 4 and returns original
scene color for valid view-model pixels before reading world depth or applying
any shadow factor.

#### Runtime rejection and second corrective pass

The user playtested an exact local/deployed DLL match, SHA-256
`def7098ccc46833f37b18c939c676afb977d1943926399160ec0419362237b1f`
(12,827,797 bytes). Shadows were visible, but contact shadows produced large
camera-dependent false shapes, actor and small-object coverage remained
incomplete, distant shadows were mostly absent, and frame rate remained about
30-40 FPS versus 120 FPS or more without Shadows. The supplied log also
contained a long comparison interval with contact shadows disabled and an
exterior distance near 15,957 units. That separates the distant-map and
producer-cost failures from the contact consumer.

Source and deterministic-reference analysis found five concrete causes:

1. Contact generation linearized both hardware depth clear endpoints as real
   far-plane positions. Rays could then compare against sky/disocclusion pixels
   and synthesize screen-locked occluders. Ray length was also normalized by
   the configurable contact cutoff; editing that cutoff moved every existing
   shadow even though NVR normalizes by the camera far range.
2. All three inner cascade boundaries were frozen at the 6000-unit profile.
   At the played distance, the far gameplay cascade ended around 1,800 units;
   the much larger remainder used the LOD profile, which intentionally rejects
   actors, activators, containers, furniture, misc, and all books.
3. Cached maps retained generation matrices but not the matching
   center/radius receiver spheres. The consumer selected by current view depth,
   so camera movement could select a retained quadrant that did not own that
   receiver. Modern NVR selects the first containing cascade sphere and blends
   through its outer ten percent.
4. Stencil-backed geometry was mapped directly to fixed D3D cull values.
   Fallout instead resolves `NiStencilProperty::DrawMode` through
   `NiDX9RenderState::m_auiCullModeMapping[4][2]` and its `LeftHanded` column.
   Ignoring that mapping can cull the wrong side of mirrored actor geometry.
5. Each updated map wrote 2048-square FP16 EVSM4 color and D24S8 depth at four
   samples, resolved a complete surface, and only then ran the mandatory
   separable moment prefilter. Every due cascade also rescanned all grid cells
   and reference lists independently.

The final code rejects depth values within `1/65536` of either endpoint for
both contact receivers and ray samples, normalizes ray scale by camera far,
and bounds contact work to the far gameplay-caster cascade. The configurable
cutoff can still reduce that range. The near split remains stable once the
configured distance reaches 6000 units, while middle/far follow NVR's
practical partition and LOD retains the remaining reach. Each map publishes
its camera-relative center/radius together with matrix, origin, and moments;
both matrix and sphere are rebased to the current camera before composition.

Generation remains 2048 `A16B16G16R16F` EVSM4 with the same FP16 exponents,
far clear, alpha thresholds, and distinct-source five-tap separable prefilter.
The intermediate moment texture and matching depth are now single-sample, so
spatial resolution and the final filter stay unchanged while four nonlinear
color/depth samples plus the resolve are removed. Loaded-cell reference roots
are collected once into a preallocated 32,768-entry transaction-local cache
and filtered by scalar form metadata for every due cascade. Cache overflow
clears it and falls back to the complete bounded per-cascade traversal; it
never reallocates or publishes incomplete coverage. The cache is cleared
before the native tail resumes and never owns engine pointers across epochs.

At 1920 by 1080 the exterior resource estimate falls from 415,094,784 bytes to
230,545,408 bytes, and the retained two-branch estimate falls from 516,524,032
to 331,974,656 bytes. These are residency and bandwidth bounds, not a runtime
FPS claim. Visual and performance acceptance for this second corrective
artifact still requires the user's Proton/DXVK playtest.

#### Runtime rejection and third corrective pass

The user then tested the exact local/deployed 12,815,268-byte DLL with SHA-256
`1eb97aa9b31817858aa3119e4bc8a8a7eea770b0b9d100962f8a7779a8ac7c8c`.
Exterior quality and speed were materially better, but the run still showed
camera-following contact shapes, broad distant-wall artifacts, displaced and
short actor shadows, and about 70-80 FPS instead of 120 FPS or more. Interiors
darkened the complete scene and did not react to point lights or the Pip-Boy
light.

The matching 5,984-line runtime log closes the interior symptom at the
producer boundary. It records successful creation of twelve 512 cube maps but
publishes `0 shadowed point lights`; the adjacent atmosphere capture sees six
manager lights, four usable, and zero completed native shadows. This is not a
missing manager or consumer invocation. Source comparison found that OMV
multiplied replacement-light color by `ShadowSceneLight +0xD0` transition
state. Modern NVR's `ShaderManager::GetNearbyLights` instead uses
`NiLight::Diff * NiLight::Dimmer` directly. The transition belongs to the
native prefix which NVR and OMV replace, so it cannot be required to make a
replacement light visible. OMV now follows that contract. Influence admission
also tests whether a sphere overlaps the configured draw range; requiring the
whole multiplied radius to fit made increasing the radius control reject large
room lights.

New radare2 inspection of `NiDX9Renderer::CalculateBoneMatrices @ 0x00E6FE30`
proves the actor-only coordinate mismatch. At `0x00E700DB`, `0x00E700E8`, and
`0x00E700F5`, the engine subtracts camera globals `0x011F474C`, `0x011F4750`,
and `0x011F4754` from the fourth component of the three output bone rows.
Modern NVR calls `RenderManager::SetupSceneCamera` before shadow generation,
which copies its selected world-camera translation into those globals. OMV
correctly made rigid transforms relative to its coherent captured camera but
did not synchronize the unrelated engine global before asking for bone
matrices. It now leaves engine state untouched and adds
`native_camera_origin - captured_camera_origin` to each copied bone-row
translation. The correction is applied before both directional and point-map
submission, and the deterministic reference test covers nonzero origins.

Contact rays now snap both receiver and ray-hit addresses to exact texel
centers in the full-resolution depth source. A two-neighbor receiver plane
rejects coplanar depth quantization as a caster and rejects receivers facing
away from the light. This specifically targets ground shapes which follow the
camera rather than real world occluders. The stronger validation permits one
center-plus-cardinal bilateral pass instead of two separable passes. At the
half-resolution work extent, the contact route falls from three draws to two
and from roughly 25 to 18 depth/contact reads per output pixel, while retaining
four ray tests and two-axis filtering.

Distant EVSM receivers now use NVR's cascade-specific light-bleed reductions
`0.1/0.2/0.6/0.8`. A bounded one-world-unit shift toward the sun prevents
broad coplanar walls from comparing against their own far-map moments. This is
the light-direction equivalent of receiver bias and avoids adding a separate
four-depth-fetch normal reconstruction to the hottest native-resolution pass.
Map resolution, FP16 EVSM4 moments, alpha coverage, and separable map
prefiltering are unchanged.

Interior composition no longer interprets missing local illumination as a
global darkness request. The accumulator already publishes visible light in
`x` and the same lights' unoccluded energy in `y`; the compositor removes only
`saturate(y - x) * darkness`. Pixels with no selected light, ambient-only
illumination, emissive surfaces, and fully visible point light retain a neutral
factor. An occluded point light alone darkens its affected receiver. This lets
ordinary room lights and a manager-exposed Pip-Boy light participate without
dimming the whole interior merely because Shadows is enabled.

Four independent cost corrections preserve spatial quality:

- cascade refresh limits are now 33/66/100/200 ms, about 30/15/10/5 Hz and
  roughly 60 rather than 125 complete 2048-map updates per second; current
  camera matrices still rebase retained maps every frame and dirty sun,
  frustum, and setting changes remain synchronous;
- the final compositor emits a scalar RGB shadow factor and uses checked D3D9
  `DESTCOLOR/ZERO` multiplication into the source. This removes the native-size
  scene copy, one full-resolution scene sample, and 7.9 MiB of retained memory
  at 1920 by 1080. Unsupported post-pixel-shader blending fails transactionally
  to the established native path;
- the contact route uses the two-pass bound above;
- point cubes render every new, replaced, radius-changed, or materially moved
  light synchronously. Stable maps refresh at a 100 ms per-slot cadence with
  at most one six-face light per invocation and staggered deadlines. Movement
  below eight world units retains both the old map and its paired light
  position; it never samples a retained cube through current unmatched
  metadata. Cell identity invalidates all slots, and cache mutation commits
  only after the complete D3D transaction succeeds.

The resulting 1920-by-1080 resource estimates are 222,251,008 bytes for the
exterior branch, 101,429,248 bytes for the interior branch, and 323,680,256
bytes after both lazy branches have been visited. These are static memory and
work bounds, not a runtime FPS claim. The corrected artifact still requires
the user's Proton/DXVK visual and performance playtest.

This third corrective artifact was subsequently rejected by playtest. Its
screen-depth contact route, late scene-pre composition, hybrid cascade
partition, native-prefix-dependent light fields, and full-resolution target
ownership are historical evidence only. The current contract below supersedes
those decisions.

The implemented scene-shadow scope is the modern NVR consumer graph that has an
OMV scene-color consumer: exterior directional/EVSM shadows, exterior
camera-stable EVSM contact refinement, and interior point-light cube shadows. Modern
NVR's ortho map is an input to its separate rain, snow, accumulation, and wet
world effects rather than its scene-shadow compositor, so OMV Shadows neither
allocates nor publishes that unrelated resource. NVR's custom flashlight owns
its synthetic spotlight; OMV has no corresponding flashlight producer, and
does not invent an engine spotlight owner. These are explicit adjacent-system
boundaries, not reduced cascade or point-shadow coverage.

Static implementation and supported-target validation can close the code and
ABI contracts. No statement in this section claims visual, startup, Proton, or
driver acceptance without a user load-to-gameplay playtest.

### Source and API ownership

`shaders.rs` owns an explicit nine-program catalog. Preparation remains a
single serialized post-Deferred worker publication, but success now logs the
program count, total bytecode DWORDs, and elapsed milliseconds. A short elapsed
time is therefore distinguishable from an incomplete catalog; tests compile
all nine production sources, enforce SM3 instruction budgets, reject
duplicate bytecode programs, and require four-component pixel `COLOR0`
signatures. The complete catalog was additionally executed against the exact
32-bit Microsoft `d3dcompiler_47.dll` from the user's game prefix, rather than
only Wine/VKD3D's more permissive built-in compiler.

| Owner | Responsibility |
|---|---|
| `omv/src/effects/shadows/contract.rs` | pointer-free settings, cadence, selection, caster, EVSM, compositor, transaction, and memory reference contracts |
| `omv/src/effects/shadows/engine.rs` | executable identity, hook/tail addresses, native layouts, draw entries, and register ABI |
| `omv/src/effects/shadows/native.rs` | bounded current-scene, cell/root, geometry-list, and stable point-light discovery |
| `omv/src/effects/shadows/math.rs` | allocation-free row-vector cascade, cube, frustum, and camera-relative transform math |
| `omv/src/effects/shadows/render.rs` | native geometry classification, traversal, register upload, and original-renderer submission |
| `omv/src/effects/shadows/pipeline.rs` | complete device-generation resources, producer transaction, immutable epoch publication, and pre-alpha consumer |
| `omv/src/effects/shadows/shaders.rs` | complete process-owned shader bytecode catalog prepared after `DeferredInit` |
| `omv/src/effects/shadows/mod.rs` | atomic runtime settings, route admission, common-entry decision, try-lock ownership, and reset boundary |
| `omv/src/fnv_local_lights.rs` | thiscall bridge at `0x00871290` and the exclusive prefix/replacement-tail choice |
| `omv/src/startup.rs` | isolated post-`DeferredInit` shadow config load, route publication, and hook ordering |
| `omv/src/fnv_render.rs` | opaque/pre-alpha composition boundary and shadows-before-atmosphere order |
| `omv/src/runtime.rs` | configuration updates, menu, and stable world/scene color-target ownership |
| `omv/src/hooks.rs` | reset ordering and bypass submission through original geometry trampolines |
| `libpsycho/src/os/windows/directx9.rs` | safe D3D9 cube, surface, state, raw-buffer, and scene wrappers |

The crate-visible public boundary is intentionally small. `NativeShadowsSettings`
is the immutable runtime setting value; `configure_runtime_options` is an
atomic post-Deferred menu/worker publication; `runtime_config` is the coherent
non-render snapshot used by UI and persistence; `install` owns deferred route
publication; `handle_common_entry` returns the only legal native continuation;
`apply_before_alpha` consumes the current or immediately preceding compatible
publication; and
`reset_runtime_state` releases every default-pool resource before native device
recreation. Each unsafe public entry documents the native lifetime required of
its pointers.

### Hook, epoch, and startup ordering

The existing receiver-preserving naked bridge remains the sole owner of the
common entry. For every invocation it selects exactly one path:

1. call the complete native prefix, which includes the native tail;
2. run the complete OMV producer, then call `0x00871A50` once; or
3. when the location is disabled or the same common epoch is already published,
   call only `0x00871A50`.

Unavailable bytecode, a busy producer, an invalid engine owner, a missing
camera/device, incomplete resource creation, or any D3D error selects the
native prefix. A replacement never calls both prefix and tail. Caller ancestry
does not gate shadow generation: this matches NVR's common-entry hook, and
generation uses no caller-specific camera or destination. Special and
screenshot invocations either create the same global-world publication or find
one already complete for the epoch; neither can invalidate it.

The naked bridge still captures the branch EBP and walks the proven branch,
dispatcher, wrapper, and owner frames for the adjacent scalar-light
publication. That POD has per-view semantics and remains restricted to exact
`0x0086FF70 -> 0x0086E650` ownership. The classification result is deliberately
not passed to `handle_common_entry`.

Missing shared or location-branch resources are allocated by the first valid
common-entry invocation. That same invocation must continue into full-quality
generation; resource readiness without a map is not a valid publication state
and no later producer call is assumed.

During `NVSEPlugin_Load`, OMV does not deserialize Shadows into
`GraphicsConfig`, copy it through `GraphicsMenuConfig`, `RuntimeSettings`, the
Current Look value graph, or `DeferredHookSettings`, and does not touch the
shadow settings atomics. At `DeferredInit`, a dedicated schema-one parser reads
only `[graphics.native_shadows]`, then startup validates process-static
globals, initializes the pipeline owner, starts serialized CPU shader
preparation, opens the passive route, and only then makes the already-proven
common hook resident. A render-side snapshot retries only a bounded number of
times and chooses the native fallback instead of blocking if a later menu
publication is in progress. Until the entire shader family is ready, enabled
locations continue through native shadows. An explicitly disabled
interior/exterior location needs no resource and takes the tail-only path
immediately after deferred route admission, so a toggle cannot transiently
re-enable native generation during preparation.

Pre-alpha composition runs immediately after opaque pre-depth geometry and
before atmosphere. Native alpha, fog, volumetric lighting, first-person
geometry, TAA, AO, motion blur, and image-space work therefore land above
shadows. Renderer recreation
first releases existing runtime resources, then the shadow resource family,
then PBR/sky resources, and enters the native recreate only when every owner is
quiescent.

### Exterior quality contract

The exterior and behave-like-exterior branch defaults to modern NVR's
custom/highest supplied settings:

- four practical-split cascades, default lambda `0.9`, covering 6000 world
  units by default;
- one 4096-by-4096 `A16B16G16R16F` EVSM4 atlas with four 2048 quadrants;
- a reusable single-sample 2048 `A16B16G16R16F` generation texture and matching
  `D24S8` depth target;
- exact FP16-safe EVSM exponents `5.54` and `5.0`, a finite far-moment clear,
  alpha cutout at `0.5`, and receiver-domain filtering that never rewrites a
  completed map;
- texel-stabilized cascade projections plus paired center/radius spheres, with
  consumer matrix and sphere rebasing for cached camera motion;
- one coherent 33 ms refresh limit for the complete four-map family; first
  publication and any material scene/sun/frustum/split invalidation rebuild all
  quadrants from one camera and sun epoch, while missed deadlines advance by
  whole periods so high presentation rates cannot multiply map work or drift;
- modern NVR's projected caster-size profiles: one shadow-map pixel for near
  and middle, ten pixels for far and LOD, with terrain exempt from aggregate
  node-radius rejection;
- no object/land LOD traversal in near or middle, and the supplied NVR default
  form-category switches for every loaded-cell reference;
- one preallocated transaction-local root scan shared by every due cascade,
  with allocation-free complete-traversal fallback on capacity overflow;
- projection comparison that ignores subpixel TAA lens shifts but accumulates
  real FOV/lens changes against the last material signature;
- NVR's one-degree yaw and quarter-degree pitch sun quantization, with a
  one-tenth blend for changes no larger than five degrees; the stabilized
  direction is shared by every cascade and the contact-shadow consumer so
  cadence cannot create cross-cascade light-direction seams;
- camera-stable contact refinement operates only in the near cascade and uses
  a continuous center-moment comparison, preserving lit/shadow endpoints while
  tightening uncertain transitions without a quantized hard threshold; it
  performs no camera-depth ray search, offset receiver lookup, blur pass, or
  screen-sized work allocation;
- exterior darkness `0.75`, matching the supplied NVR default.

The menu and schema-one working config expose darkness, distance, split lambda,
contact enablement, contact depth distance, and contact ray distance. Values
are finite-clamped before atomic publication. Split comparison identifies
whether any complete near/far interval changed; one changed interval
invalidates the blendable family so the atlas can never mix old and new
projection epochs. Extending the default distance recomputes NVR's complete
practical partition rather than retaining a private 6000-unit near anchor. A
published family retains the projection, center/radius sphere, split,
generation origin, and stabilized sun with which its moments were rendered.

The reusable single-sample moment texture preserves per-cascade spatial
resolution while avoiding NVR's 4096 4x-MSAA color/depth allocation and OMV's
former per-map resolve. A completed generation surface is copied exactly to
its atlas quadrant. Near and middle receivers use four fixed bilinear EVSM4
lookups; far and LOD receivers use one bilinear lookup because the same kernel
covers many world units there and deforms distant thin silhouettes. Atlas
sampling clamps each local UV to its own half-texel inset, so linear filtering
cannot bleed across quadrants. Directional receivers at or beyond the exact
outer split are fully lit even if a native sky mesh wrote non-clear depth.

### Interior quality contract

The interior branch defaults to twelve cube-shadowed lights. All twelve cubes
are sampled; lights outside the cube budget remain in the already-rendered
native scene and are neither redrawn nor globally attenuated:

- stable distance plus native-identity ordering retains equal-distance lights;
- a nearer thirteenth light displaces only the farthest cube owner; native
  crowded-room illumination remains untouched without an OMV fallback draw;
- every eligible light competes for a cube slot because modern NVR explicitly
  forces that decision true when JIP makes the engine flag unreliable;
- light admission reads `NiDynamicEffect::EffectType +0x9D`,
  `CanCarry +0x9F`, `NiLight::Dimmer +0xC4`, `Diff +0xD4`, and radius from
  `Spec.r +0xE0`; it does not depend on `ShadowSceneLight` prefix fields that
  OMV replaces. Lights must be live, point, visibly nonblack, in front of the
  camera or contain it, and overlap the configured draw range;
- influence radius uses the supplied NVR `1.5` multiplier;
- carried and Pip-Boy lights use NVR's fixed 256-unit cube radius;
- twelve 512-face `R32F` cube maps share one matching `D24S8` depth surface;
- all six D3D faces use the NVR coordinate flip and 90-degree view convention;
- conservative sphere-versus-face tests reject objects outside each 90-degree
  pyramid while retaining seam-touching bounds, reducing redundant draw calls
  without changing cube resolution or temporal quality;
- alpha cutout is `0.2`, and the normalized radial-depth receiver bias is
  NVR's `0.018`;
- the native per-light geometry list is borrowed only inside the common-entry
  lifetime; a bounded current-cell traversal is the documented fallback;
- point accumulation first rejects clear depth and receivers outside every
  selected light volume, then reconstructs a normal from the shorter 3D
  neighbor on each axis only for affected pixels; this preserves the
  rotated-camera discontinuity fix without a separate full-screen normal pass;
- two additive six-cube passes accumulate RGB direct-light energy proven
  occluded by radial depth. A full-resolution FP16 RGB target preserves colored
  lights, and reverse-subtract blending removes only that deficit from native
  scene color. A smooth zero-to-full source guard over 2-8 percent of the light
  radius preserves emissive source geometry where cube depth is undefined.
  Ambient, emissive, fully visible, and unselected native light energy remains
  unchanged.

The menu/config exposes interior darkness, cube-light count (one through
twelve), radius multiplier, draw distance, and receiver bias. Lowering the
count reduces six face renders per removed cube while overflow lights retain
unshadowed native illumination. The third-person player node is collected
explicitly through `PlayerCharacter::GetNode` ownership semantics in both the
cached and capacity-overflow traversal routes. First-person geometry is drawn
later by the engine, after pre-alpha composition, so shadows cannot be painted
over hands or weapons and no first-person depth mask is needed. SpeedTree is intentionally excluded only from the
point-cube route: NVR's cube register `c63` aliases its SpeedTree constant
block, so attempting that route consumes invalid data. Directional SpeedTree,
terrain LOD, skinned, ordinary, and alpha geometry all retain dedicated paths.

### Caster and submission invariants

Traversal rejects non-casting forms, app-culled nodes, fade below `0.75`,
refraction/fire-refraction, decal/dynamic-decal, invalid bounds, multibound
exclusion, and light/cascade-frustum exclusion. Missing diffuse ownership on an
alpha caster skips the caster instead of turning foliage or fences into an
opaque silhouette. Routine traversal uses a reusable bounded stack and fixed
point arrays; it performs no file I/O, blocking lock, `VirtualQuery`, shader
compilation, or per-object allocation.

Pass classification is ordered, not merely a set of predicates. Skinned
partitions are claimed before ordinary lighting-definition filtering so actor
hair and body partitions cannot be discarded by their shade subtype.
SpeedTree retains its leaf-alpha path. Terrain requires an admitted lighting
definition but bypasses the ordinary alpha pass. Remaining geometry is
admitted only when `BSShaderProperty::uiShaderIndex` at `+0x58` is NVR's
`ShadowLight` (1), `Parallax` (15), or `Lighting30` (29); every such lighting
property obtains its diffuse owner from `ppTextures[0]` at `+0xAC` when alpha
testing is required. The supplied NVR profiles enable books in near and middle,
enable misc forms in all four cascades, and exclude actors, activators,
containers, and furniture only from LOD.

Stencil culling reads the renderer's `renderState` at `+0x8B8`, draw-mode map
at render-state `+0xD4`, and handedness selector at `+0xF4`. Legal mapped D3D9
values are used directly; an unavailable or invalid renderer map falls back to
the prior conservative mapping. This preserves mirrored third-person geometry
without forcing all casters double-sided.

Ordinary and strip geometry are submitted through the original OMV trampolines
for `0x00E745A0` and `0x00E74840`, bypassing PBR/sky detours while the dedicated
shadow shaders are bound. Skinned partitions use `0x00E6D310`; bone constants
remain in `c9..c62`. SpeedTree blocks remain in `c63..c139`, and their two
scalar globals plus 16 wind rows are read as separate proven blocks rather than
as one invented contiguous span. Terrain LOD owns `c140..c145`.

A final radare2 audit of all three native submission functions proves that they
perform validation, buffer/declaration setup, and draw calls without binding a
vertex or pixel shader. The OMV generation programs therefore remain active
through the original trampoline calls. Modern NVR uses the same contract in
`RenderPass::RenderAccum`: it binds the shadow shader family once and then
calls `0x00E74840`, `0x00E745A0`, or `0x00E6D310` for the corresponding
geometry. This closes shader replacement during native submission as a cause
of neutral maps; the proof is recorded with the geometry predicate evidence in
`analysis/radare2/output/graphics_fnv_shadow_geometry_predicate_contract.txt`.

### Transaction, publication, and failure behavior

Producer work uses one successful `BeginScene`/`EndScene` pair. A failed
`BeginScene` is never followed by `EndScene`. Before writes, publication is
invalidated. OMV captures all active render targets and depth, plus a
`D3DSBT_ALL` state block covering viewport, shaders, declaration/FVF, streams,
indices, textures, samplers, and render states. Auxiliary MRTs are detached;
every target transition reinstalls its required viewport and compatible depth
surface. CPU scheduler/signature changes are staged locally and committed only
after `EndScene` and complete attachment/state restoration succeed.

Every fullscreen pass also owns its pixel-admission state: alpha and stencil
tests cannot reject the quad, the required color channels and all multisample bits
are writable, vendor alpha-to-coverage is disabled, and used samplers declare
non-sRGB reads. These states are part of output correctness, not merely
restoration hygiene, because successful D3D9 calls otherwise provide no
evidence that the render target changed.

The pre-alpha consumer is try-lock-only and accepts the current or immediately
preceding render epoch on the same device. It captures/restores the same state
boundary and multiplies a shader-produced factor into source RGB through
capability-checked fixed-function blending; it never samples the bound source
render target, and its RGB-only channel mask preserves source alpha. Any failure
removes the publication; the next common entry either retries OMV or safely
executes native shadows.
Resource creation is transactional per location branch and device generation.
Shared shader/state objects are small; the exterior atlas/moment/depth
family and interior cube/depth family are lazy `Option` owners. A branch
failure poisons only that branch for the current device generation, and native
fallback remains available. Once lazily created, both heavy families remain
resident across cell transitions. Reset drops every consumer, shader,
state-block, and branch COM owner before native recreation.

At 1920 by 1080 the conservative exterior estimate is 277,684,224 bytes,
including the 4096 atlas, reusable single-sample 2048 moment/depth pair, twelve
point cubes, and one lazy full-resolution RGB-deficit target, with no blur,
normal, or screen-space contact work target. The twelve-light interior estimate
is 93,134,848 bytes. NVR's 4096 4x-MSAA atlas
color/depth topology alone has a 896 MiB lower bound before cubes and
full-resolution resources. OMV therefore preserves map resolution while
avoiding NVR's giant multisampled atlas. After both branches have been
visited, their combined conservative 1920-by-1080 residency is 277,684,224
bytes. Interior point-light targets are allocated lazily and retained after
their first use. Keeping that bounded capacity avoids reallocating hundreds of
MiB and stalling the driver at every interior/exterior door transition. Face
culling and the configurable cube count reduce interior draw work without
changing cube quality.

### Test and acceptance evidence

Deterministic tests cover:

- executable identity, hook prologue/returns/tail, calling convention, bounded
  direct-world versus menu-wrapper/offscreen frame chains, native layouts, draw
  entries, and every shader register range;
- independent configuration admission and exact prefix-versus-tail counts;
- unconditional validated-common-entry replacement matching NVR, immutable
  same-epoch deduplication, and current/next-epoch publication lifetime
  including counter wrap and expiry;
- complete first-invocation cascade publication, exact one/one/ten/ten
  projected caster thresholds, per-cascade LOD admission, exact modern-NVR
  book/misc form profiles, skinned-before-lighting pass ownership, and the
  native-to-captured-camera bone-row translation rebase;
- exact NVR practical splits and expanding gameplay-caster reach,
  coherent-family split invalidation, texel stabilization, cached matrix/sphere
  rebasing, sphere-based receiver selection, cube axes, world-to-view sun
  conversion, and TAA-jitter projection tolerance;
- monotonic 33 ms coherent-family cascade scheduling, synchronous dirty
  refresh, complete first publication, atlas-paired sun publication, and
  deadline advancement without high-rate drift;
- equal-distance selection, radius/front/distance admission, point-sphere
  volume and conservative cube-face culling, caster rejection, forced-true
  modern-NVR light admission, native point/carry field ownership, configured
  cube budgets without fallback redraws, plus cube-cache first publication,
  immediate motion invalidation, presentation-cadence dynamic-caster refresh,
  paired retained metadata, and transaction-only commit;
- CPU EVSM4 and distinct exterior-visibility/interior-light-deficit compositor
  reference behavior, including neutral unlit, emissive, and fully visible
  interior pixels;
- branch-lazy quality/memory topology, retained transition capacity,
  absence of blur, screen-space contact, and full-screen normal targets, exact
  residency accounting, same-invocation allocation/generation, direct
  single-sample moment publication, complete state classes, and scene-pair
  balance;
- compilation of all seven SM3 shader variants with static instruction
  budgets and source contracts for complex geometry, alpha thresholds,
  derivative-free continuous EVSM contact refinement, clear/sky/out-of-range
  depth rejection, selected-cascade lookup count, NVR EVSM variance and per-cascade bleed
  reduction, pre-first-person ordering, direct
  multiplicative composition, all twelve cubes, exact far clear, atlas edge
  isolation, and legacy
  D3DCompiler-compatible four-component pixel outputs;
- strict schema-one defaults, finite bounds, save/round-trip behavior, all
  appearance/performance controls, no preset payload ownership, complete
  exclusion from every pre-Deferred config/menu/runtime/persistence/handoff
  value owner, isolated deferred parsing, deferred hook order, pre-alpha order,
  and reset order.

The required static gates are the focused shadow/config/startup tests, the full
`cargo test --target i686-pc-windows-gnu -p omv`, the explicit supported
release build, formatting, `git diff --check`, and final diff inspection.

The original 2026-08-12 implementation passed 32 focused shadow tests and 519
OMV tests. The earlier corrective passes added rejecting tests for the nine
integration defects, caller ownership, branch residency, user controls, shader catalog
identity, configurable cube budgets, face culling, complete first publication,
projected-size policy, form/LOD admission, common-entry producer ownership, and
bounded producer/consumer epoch handoff, complete menu-to-render publication,
change-driven menu diagnostics, explicit fullscreen/generation pixel
admission, and cached atlas/projection pairing. All 533 then-current OMV tests
passed.
The explicit supported release build produced a 12,696,715-byte `omv.dll` with
SHA-256
`5370f0aad3339982b7337d6f971bb7986a178bd84f10b4c0ed1ba41f6d955f61`;
`.idata` remains `0x33fc` and `.tls` remains `0x8`. The complete eleven-program
catalog also passed against the game's Microsoft `d3dcompiler_47.dll` (version
10.0.15063.674). These results prove static, compiler, and supported-build
behavior only.

The third corrective pass added the actor-origin, contact-plane, far-receiver,
interior-deficit, point-cache, cadence, and direct-composition regressions
described above. Its focused shadow suite passed 64 tests and the complete OMV
suite passed all 553 tests under `i686-pc-windows-gnu`; the explicit optimized
OMV build also passed. The resulting 12,827,921-byte `omv.dll` has SHA-256
`52ba14694aa1538a5db8b3be33634a63af1e068c1cec4fb50fe9e52ffbd0e209`.
The pre-Deferred PE footprint remains `.idata = 0x33fc` and `.tls = 0x8`.
Formatting and `git diff --check` also pass. These are static and build results;
the corrected image, frame rate, and Proton/DXVK behavior remain explicitly
unaccepted until the user's load-to-gameplay playtest. The next playtest did
reject it with the artifact, ordering, interior-light, actor, and performance
symptoms recorded above; its acceptance status is therefore failed.

#### Fourth corrective pass: opaque ordering and stable map-domain ownership

The rejected run's current log contains two decisive runtime facts. Interior
resources were ready for twelve cubes but selection repeatedly reported zero
shadowed point lights. At 3440 by 1440, the log also alternated every frame
between a post-world target in format `0x71` and the scene-post graph target in
format `0x16`. Source showed both phases overwriting one
`scene_post_color_copy` owner. This forced a full-resolution D3D texture
release/create cycle every frame and is a direct driver-stall mechanism, not a
shader-cost inference. First-person motion blur now shares the established
`world_color_copy`, whose lifetime and FP16 format match that boundary;
scene-post retains its independent LDR graph owner.

The visual ordering defect was also source-proven. The rejected compositor ran
from `apply_fnv_scene_pre_image_space`, after `hook_render_pre_depth_groups`
had already executed atmosphere/fog. Multiplying scene color there necessarily
darkened fog and volumetric lighting. The consumer now runs immediately after
the original pre-depth-group renderer returns and before
`fnv_world_pipeline::apply_before_alpha`. This is the opaque-world boundary
already owned by OMV. Native alpha, fog, volumetric lighting, the later
first-person pass, AO, motion blur, TAA, and image-space effects consequently
render above shadows. A missed early boundary fails closed and never falls
forward to scene-pre.

Modern NVR's `ShaderManager::GetNearbyLights` establishes the point-light
adapter contract: `ShadowSceneLight::sourceLight` identifies the native light,
then eligibility reads `NiDynamicEffect::EffectType` and `CanCarry`, plus
`NiLight::Dimmer`, `Diff`, and `Spec.r`. It does not require the native-prefix
point/ambient/active bytes at `ShadowSceneLight +0xF4/+0xF5/+0x110` or its
transition. OMV replaces that prefix, so requiring those fields explained the
zero-light publication. The adapter now uses the native fields at
`+0x9D/+0x9F/+0xC4/+0xD4/+0xE0`, the exact NVR nonblack threshold, and the
fixed 256-unit carried/Pip-Boy radius. This is source evidence from
`.research/TESReloaded10-master/src/core/ShaderManager.cpp:521-669` and
`src/NewVegas/nvse/GameNi.h:1021-1058`; it changes no executable address.

Actor ownership no longer assumes that `TESObjectCELL::objectList` contains the
player. The player singleton already validated by `current_scene` supplies its
third-person render node explicitly. The node is deduplicated in the shared
root cache and is also visited by the complete capacity-overflow route. Actors
remain enabled in near, middle, and far, and excluded only from LOD. Modern NVR
form defaults were rechecked directly: books are enabled in near/middle and
misc forms in every cascade. This corrects the former small-object omissions.
The previously proven `NiDX9Renderer::CalculateBoneMatrices @ 0x00E6FE30`
camera-origin correction remains paired with this now-complete actor route.

Camera-following contact artifacts came from the design, not a tunable ray
bias. The screen-depth ray and bilateral programs, their two half-resolution
targets, and their per-frame draws are removed from the production catalog.
Contact refinement now tightens only the selected cascade's stable EVSM
probability. It preserves exact lit/shadow endpoints, performs no additional
texture lookup, never searches camera-depth discontinuities, and cannot move a
receiver across an atlas boundary. The nine remaining shader programs compile
under SM3 budgets.

Cascade distribution now uses modern NVR's exact practical split equation for
every configured distance. The rejected private 6000-unit near anchor created
a hybrid partition and mismatched crop transitions when distance or lambda
changed. Cached matrix, sphere, split, and generation origin remain one
immutable publication. Refresh is 16/33/50/100 ms: the actor-critical near map
is 60 Hz, while middle/far/LOD are bounded near 30/20/10 Hz. This eliminates
the rejected 100/200 ms gameplay staleness without restoring four 2048 maps on
every uncapped frame.

Interior composition is now an actual cube-depth occlusion operation. Two
six-light passes calculate RGB direct-light energy only where a cube proves the
receiver occluded. The FP16 RGB result is reverse-subtracted from native scene
color. Unselected lights, ambient, emissive surfaces, visible light, and the
light source are not globally multiplied. NVR's near-light normal guard is
retained so reconstructed normals cannot turn a nearby point/Pip-Boy source
into a black disk.

No startup schema, preset payload, `LazyLock`, hook-admission order, TLS owner,
or pre-`DeferredInit` first-touch changed. New tests reject late composition,
first-person masking, missing player ownership, stale native-prefix light
fields, non-NVR split/form profiles, screen-space contact targets, incompatible
color-copy sharing, scalar point-light targets, and unbounded cascade cadence.
The focused shadow suite passes all 65 tests and the complete OMV suite passes
all 556 tests under `i686-pc-windows-gnu`. The explicit supported release build
also passes. The resulting 12,845,405-byte `omv.dll` has SHA-256
`5dd8daf815bec5eb77a825f3fa096f0fd99693cd9d73b980d553c90c25b9abc2`;
the pre-Deferred PE footprint remains `.idata = 0x33fc` and `.tls = 0x8`.
Formatting also passes. These results prove source contracts, shader
compilation, and the supported build only. Runtime image quality and FPS remain
unaccepted until a new Proton/DXVK playtest.

#### Fifth corrective pass: stable camera ownership, complete actors, and bounded filtering

The next runtime rejection showed that the fourth artifact was still not
acceptable. Exterior shapes changed with camera/player movement and height,
point sources did not cast exterior shadows, interior actor motion stepped,
contact refinement was not visibly functional, directional lighting disagreed
with atmosphere, and the 3440-by-1440 cost remained excessive. The following
contracts are the corrective boundary for that rejection.

The common native shadow entry executes after OMV temporal AA has temporarily
shifted the live camera frustum by its Halton offset. Reading the live camera at
that point made cascade fitting and texel snapping depend on the jitter phase.
The producer now nonblockingly reads the `TemporalProjectionOverride` output
camera retained for the same render epoch; when TAA is inactive or the owner is
busy it uses the established native camera fallback. The cached matrix, sphere,
split, and generation origin remain one publication, and the consumer rebases
that exact publication to the current camera. A numeric negative-control test
proves that the jittered frustum is rejected and the restored frustum is used.

Actor failure had an independent ABI cause. Direct inspection of the supported
FalloutNV.exe proves that `BSDismemberSkinInstance` extends the 0x34-byte
`NiSkinInstance` with a partition count at `+0x34`, the partition-array pointer
at `+0x38`, and `IsRenderable` at `+0x3C`. The decisive reads are
`0x00E7197B` (`[ecx+0x38]`) after the RTTI check in `0x00E718A0` and
`0x00B63F33` (`[ebx+0x3C]`) after the check in `0x00B63F10`; `0x00A6CAC0`
corroborates all three fields. OMV previously treated the partition count as a
pointer and the low byte of that pointer as the renderable flag. The corrected
route uses `+0x38/+0x3C`, while retaining the already proven
`NiDX9Renderer::CalculateBoneMatrices @ 0x00E6FE30` ABI. Raw evidence is in
`analysis/radare2/output/graphics_fnv_shadow_dismember_skin_layout.txt`.

Local-light cubes now belong to the single shadow effect in either location.
The exterior branch selects the same bounded nearest-light set as interiors, so
the Pip-Boy and outdoor practical lights can cast shadows concurrently with the
directional atlas. Composition remains two legal operations: directional
visibility multiplies opaque native color, then cube-proven RGB local-light
deficit is reverse-subtracted. Pixels outside a light radius exit before the
cube lookup. The schema-one `interior_shadowed_lights`, radius, distance, and
bias field names remain persisted unchanged, but ImGui exposes them in a shared
`LOCAL LIGHTS` section whenever either location toggle is enabled.

Point-map caching no longer uses a 100 ms timer carousel. New, replaced, or
materially moved lights refresh immediately; a 0.25-world-unit threshold keeps
carried lights paired with their cubes. Unchanged static light/map pairs remain
immutable. A current native geometry-list scan marks
only cubes containing skinned geometry for presentation-cadence regeneration.
If the native list is absent, the conservative dynamic result matches the
complete-cell fallback. This keeps actor silhouettes synchronized without
periodically spending six face traversals on unrelated static lamps.

Directional shadows publish the stabilized sun vector paired with the live
atlas. Sunshafts and volumetric lighting now consume that publication rather
than independently projecting the raw sky vector; a busy or absent publication
falls back to the native direction. AO owns no sun vector. The already accepted
opaque-boundary ordering remains unchanged: shadows compose before atmosphere,
fog, volumetric light, alpha, first person, AO, TAA, and image-space work.

The producer no longer executes two full 2048-by-2048 blur draws for every
refreshed cascade. Each completed generation surface is copied exactly into its
atlas quadrant. Four bilinear moment taps filter only visible receivers; inside
the configured contact distance, one additional center-moment comparison
provides independent, sharper map evidence. That fifth lookup uses the same
stabilized light projection and never reads or searches screen depth, so it
cannot create the rejected camera-following silhouettes. Compared with the
former two five-tap producer passes, each refreshed cascade removes two full-map
draws, approximately 41.9 million texture reads, and the 32 MiB blur scratch
texture. The complete catalog is eight SM3 programs, and compiled shader tests
retain explicit texture and instruction ceilings.

This pass changes no persisted field order or type, schema/version, built-in
preset payload, hook admission, `LazyLock`, TLS owner, worker order, or
pre-`DeferredInit` first touch. Tests reject the jittered camera, incomplete
dismember layout, timer-stepped static cubes, frozen skinned cubes, exterior
local-light omission, hidden exterior-only controls, raw-sun atmosphere,
screen-space contact targets, visually inert contact remapping, and full-map
producer filtering. Static tests and the supported build cannot prove image or
frame-time acceptance; the next Proton/DXVK playtest must still validate stable
movement/height/zoom, animated actors under static and carried lights, far-wall
shape, contact visibility, effect ordering, and measured FPS.

The focused shadow suite passes all 70 tests and the complete OMV suite passes
all 561 tests under explicit `i686-pc-windows-gnu`; doc tests also pass. The
explicit optimized OMV build produced a 12,805,556-byte `omv.dll` with SHA-256
`e2318377cad532c8ae3eeba37d085235ac132c38af2b492d283967f45055881b`.
The loader-visible PE sections remain `.idata = 0x33fc` and `.tls = 0x8`.
These results prove the source contracts, compiler ceilings, and supported
build only, not the pending runtime image or FPS acceptance.

#### Sixth corrective pass: coherent atlas epochs and bounded receiver work

The fifth artifact was runtime-rejected. At 3440 by 1440 the user observed
camera- and height-dependent exterior blinking, deformed and unstable far
shadows, occasional shadowing of the sky, contact-edge blinking/artifacts,
dark emitting lamps, and unacceptable exterior performance. Interior point
shadows were materially better, so this pass preserves their cube generation
and corrects the receiver and subtraction costs instead of replacing that
working ownership model.

Source inspection found five independent causes:

1. The atlas quadrants used independent 16/33/50/100 ms refresh epochs. The
   consumer then selected and blended maps made from different camera
   orientations and potentially different stabilized sun directions.
2. The producer published the newest stabilized sun on skipped invocations,
   even though the retained atlas still belonged to an older sun epoch.
3. The compositor rejected only clear depth endpoints. Native sky geometry can
   write a finite depth, and a cascade bounding sphere can contain a point
   beyond the exact configured view-depth range at only some camera angles.
4. Contact refinement used a hard `step` against one FP16 moment. Crossing one
   representable map value therefore changed a receiver discontinuously.
5. Every selected local-light frame first reconstructed normals over the whole
   backbuffer, requiring five depth reads and one FP16 write for pixels outside
   every light. The subsequent accumulation then read that extra target.

The four directional maps are now one all-or-none 33 ms transaction. Any due
refresh or one changed split regenerates every quadrant from one unjittered
camera and stabilized sun, and only that atlas-paired sun is published to
atmosphere. This retains the previous aggregate ceiling of 120 2048-map updates
per second while removing invalid cross-epoch cascade selection and blending.
It deliberately does not claim per-frame animation: 33 ms is the bounded
quality/performance contract awaiting runtime acceptance.

Directional composition now rejects finite receivers at or beyond the outer
split before sphere selection, closing the native-sky path. Near and middle
cascades retain four stable bilinear EVSM4 taps. Far and LOD cascades use one
bilinear EVSM4 lookup: at their world scale the previous four-tap footprint
blurred and deformed thin geometry, while most 3440-by-1440 exterior pixels paid
all four reads. Contact runs only in cascade zero and compares the center
positive moment through a relative smooth interval instead of a binary step.
It retains the same map projection and adds no screen-space target or ray.

Point accumulation now reconstructs its center position after one depth read,
rejects pixels outside all six lights in the current batch, and only then reads
four neighbors for the established edge-aware normal. This removes one
full-resolution pass, one texture read in the accumulation pass, and the FP16
normal target (16,588,800 bytes at 1920 by 1080; 39,628,800 bytes at 3440 by
1440). A smooth source guard makes the estimated occluded-light deficit zero
inside two percent of a light radius and reaches full strength at eight
percent, so the subtractive pass cannot blacken the emitter where cube depth is
undefined. The stage order remains shadows before atmosphere, fog, volumetric
lighting, alpha, and first person; the reported lamp darkness was therefore an
over-subtraction defect, not evidence that shadows executed after fog.

Negative controls cover finite-depth sky, exact outer-range rejection,
all-or-none cadence and late-frame phase recovery, continuous contact
visibility, near-only contact range, source preservation, removal of the
full-screen normal owner, atlas tap topology, and compiled SM3
instruction/texture budgets. The focused suite currently passes 73 tests. The
shader catalog is seven programs. These static results do not prove the
reported visual artifacts or frame rate fixed; the new artifact still requires
the same Proton/DXVK playtest and measured 3440-by-1440 comparison. The complete
OMV suite passes all 564 tests and doc tests under explicit
`i686-pc-windows-gnu`. The supported release build produced a 12,706,305-byte
`omv.dll` with SHA-256
`5484230796c49b23bfcb5c8dbcdb614fcdfb5dab99327f214e256975cf539aed`.
The loader-visible PE baseline remains `.idata = 0x33fc` and `.tls = 0x8`.
Formatting and `git diff --check` pass.

The performance/visual-correctness pass added tests that rejected every newly
reported failure before implementation: present-rate-scaled cascade work,
full-resolution contact work, eager four-cascade sampling, whole-atlas clears,
distance-driven near split changes, actor/pass misclassification, missing NVR
form coverage, unstable EVSM/contact receiver behavior, and missing
first-person composition exclusion. It also corrected the exact memory-plan
test after that test rejected the obsolete full-resolution exterior model. All
54 focused shadow tests and all 542 OMV tests now pass. The explicit supported
release build produced a 12,824,138-byte `omv.dll` with SHA-256
`af2066031bd8ef08444a3923478b43ef7f66fc7a6748c6220480cfd54216b281`;
`.idata` remains `0x33fc` and `.tls` remains `0x8`.

The second corrective pass added rejecting tests for raw-depth contact
endpoints, camera-far-independent contact rays, extended outer cascade reach,
sphere-owned receiver selection and blending, exact actor skin weighting,
renderer-handed culling, NVR form-profile defaults, bounded root collection,
and single-sample directional residency. All 60 focused shadow tests and all
549 OMV tests pass. The explicit supported release build produced a
12,811,596-byte `omv.dll` with SHA-256
`674ce8271caf43fd1822da7ff5f6ad18e46a4501a5cc840beba4e828f6dda33d`;
`.idata` remains `0x33fc` and `.tls` remains `0x8`. `cargo fmt -p omv` and
`git diff --check` also pass.

Runtime shadow visibility is proven for prior artifacts, including the fifth
artifact which the user described as materially better indoors, but every such
artifact was rejected for the defects recorded above. The sixth corrective
artifact has not been playtested and its visual and performance acceptance
therefore remain open. A later playtest
should first measure the same 3440-by-1440 exterior route, then cover ordinary
interior and behave-like-exterior cells; sunrise, night, time jumps, zoom, TAA,
first/third person; actors, small and alpha geometry, broad walls, SpeedTree,
terrain/LOD, distance edits, and multibounds; zero/one/twelve/equal-distance
point lights; special and screenshot rendering; menu toggles; alt-tab,
resolution change, and device recreation; and cold load-to-gameplay with
BaseObjectSwapper. Visual acceptance requires stable, correctly oriented
contact/cascade/cube shadows, complete third-person actors and small casters,
unchanged near coverage under far-distance edits, clean view-model ownership,
and no atlas seams, stale publication, wall flicker, light leaks, acne,
peter-panning, state corruption, or lower spatial quality than the supplied
NVR custom configuration. Performance acceptance requires recovered frame
rate plus per-stage CPU/GPU attribution and stable resource residency on
Proton/DXVK and the affected NVIDIA path.

#### Seventh corrective pass: executable static validation and current contract

The user rejected the sixth artifact and specifically rejected its validation
method. This section supersedes the sixth pass's current-implementation claims;
the older sections remain as a history of rejected artifacts and must not be
read as the active design. The seventh pass began by removing every
`include_str!`/source-presence assertion from the shadow behavior suite. HLSL
text checks remain only for the native/register ABI that cannot be recovered
from SM3 tokens. Image behavior, geometry, temporal reuse, phase order,
producer transactions, resource cost, and shader work are exercised through
numeric reference models or compiled bytecode.

The new negative controls rejected the pre-fix implementation before the
corresponding correction:

- a clear-depth sky pixel became black when directional-neutral white was
  reused as reverse-subtractive point output;
- an HDR lamp lost more than two units of radiance under scalar interior
  darkening;
- near motion refreshed all four maps, while a later retained-map rule allowed
  a one-degree sun change to displace a caster by about 17.87 texels;
- one skinned point caster regenerated all six cube faces;
- twelve camera-containing lights performed twelve full-screen point passes,
  then the first batching attempt still reconstructed depth six times;
- a center-only directional producer completely missed a projected thin
  caster which NVR's four coverage samples retained;
- the contact configuration's 180,000-unit range collapsed to the default
  near split (less than 300 units) and contact evidence was discarded outside
  the 6,000-unit atlas;
- source-text phase assertions were replaced by executing the same ordering
  helper used by the pre-alpha hook, with a negative image oracle proving that
  shadowing after fog attenuates additive scattering illegally.

Modern NVR source establishes the quality inputs used here. Custom quality is
2048 per cascade, FP16 EVSM4, four-sample coverage, practical splits with
lambda 0.9, and a 6,000-unit default range. Receiver sampling applies a
one-world-unit grazing normal offset. Its contact loop emits four actual
comparisons at cumulative base-step offsets 1, 3, 6, and 10, uses a thickness
of 20, and owns a distance independent of cascade partitioning. Near, middle,
and far admit actors; LOD does not. Point shadows use up to twelve 512 cube
maps. NVR's full-atlas MSAA, full-map prefilter, repeated point rendering,
screen-anchored noise, and incomplete state restore are costs or defects, not
quality invariants.

The current directional producer preserves four-sample silhouette coverage on
one reusable 2048 `A16B16G16R16F` surface plus matching four-sample depth. D3D9
resolves that surface to one single-sample 2048 texture before the changed
quadrant is copied into the persistent 4096 atlas. This retains NVR's thin
geometry coverage without allocating or clearing a complete multisampled 4096
atlas. Failure to create the exact four-sample color/depth pair fails the OMV
transaction to the established native path; it never silently lowers coverage
quality. Compiled consumer filtering is receiver-bounded and the resource plan
keeps the 1920-by-1080 combined lazy-branch peak below 512 MiB, versus the
documented 896 MiB lower bound for NVR's comparable full-atlas topology.

Near actor animation is isolated from static-scene work. The static near map
excludes actor roots and is retained in a separate 2048 FP16 EVSM4 backing
texture. On a frame containing a near player or NPC, only those roots are
submitted through the same four-sample producer. A two-read 2048 merge then
selects the complete EVSM distribution with the nearer positive first moment
and writes the combined result into atlas quadrant zero. Selecting an entire
distribution is essential: a component-wise minimum combines incompatible
positive and negative variance pairs. When the last actor leaves near
coverage, one exact copy restores the static quadrant. An incomplete root
cache takes the conservative old path and rebuilds the complete map; it never
omits an unclassified caster. This removes the dominant per-frame terrain and
building resubmission while preserving actor resolution, coverage sampling,
EVSM precision, and the existing consumer shader budget.

Each retained cascade publishes an immutable matrix, origin, coverage sphere,
split, and stabilized sun. Reuse is legal only while the cached sphere contains
the complete current receiver slice and sun rotation moves an extremal caster
by at most half a texel. Numeric motion tests cover horizontal translation,
height, camera rotation, and sun drift. FOV fitting includes NVR's
default-to-live tangent ratio. Animated actor bounds select the actor-only
near overlay and invalidate every intersecting middle/far map on the current
presentation; they never enter LOD. The dedicated third-person player route,
FNV D3DCOLOR blend-index order,
camera-origin bone rebase, and `BSDismemberSkinInstance +0x34/+0x38/+0x3C`
partition contract are all executable tests rather than source searches.

Composition is one source-owned operation. Clear endpoints and finite native
sky at the final 1.5 percent of camera depth return exact source color. On a
world receiver, directional visibility owns a multiplicative surface term and
point maps own only RGB direct-light deficit proven occluded. These identities
can no longer be confused by blend state. HDR energy transitions to complete
source preservation above 1.15 linear, and a near-source guard prevents a
light emitter from subtracting itself. An interior publication with no selected
cube performs no depth resolve, source copy, or gamma round trip.

Point consumer work is coverage-driven. Conservative analytic sphere scissors
reject off-screen lights. A shared `A16B16G16R16F` receiver target reconstructs
view depth and the discontinuity-safe normal once over merged light coverage;
the accumulation shader then fills all six remaining SM3 samplers with cube
maps. Twelve camera-containing lights therefore require one receiver pass and
two point passes. The deterministic static fetch model falls from 30
full-screen depth-fetch equivalents for the rejected two-light design to seven
depth/receiver equivalents, while separated lights retain their individual
small rectangles. The compiled receiver and six-light programs have explicit
instruction, texture-fetch, and derivative ceilings.

Contact shadows again use actual screen depth instead of the visually inert
map-center substitute. Fixed sampling removes NVR's screen-anchored blue-noise
motion; the exact cumulative NVR positions are uploaded from a tested Rust
contract. The raw half-resolution visibility is filtered by two depth-aware
five-tap passes. Endpoint rejection prevents far-plane occluders. Range is
clamped only by the camera far plane, not by a cascade split, and contact may
darken a receiver beyond the last map. A world-space blocker/plane oracle
checks localization and bounds the pixels changed by subpixel camera motion.

The compositor executes at the proven opaque pre-alpha boundary. The
production ordering helper executes surface shadows first and atmosphere
second; native alpha, first person, fog/volumetric scattering, AO, TAA, motion
blur, and later image-space work therefore remain above shadows. This pass
does not change schema one, built-in presets, hook admission, static/TLS
ownership, worker order, or any pre-`DeferredInit` first touch.

Static validation still cannot prove a Proton/DXVK image or frame rate. The
next runtime acceptance artifact must verify clear and finite-depth sky,
Pip-Boy outdoors, lamps and unlit interior surfaces, contact motion, actor
poses in all three gameplay cascades, alpha/small casters, broad far walls,
height/rotation/zoom/distance edits, first/third person, and measured
3440-by-1440 exterior/interior frame times. Until that playtest, visual and FPS
acceptance remain explicitly open.

The final focused static gate contains 78 passing shadow tests. It includes
numeric image, temporal, geometry, cache, transaction, and workload oracles;
compiled SM3 instruction/texture/derivative budgets for eleven distinct
programs; and source inspection only for unavoidable shader-register ABI and
the repository-mandated pre-`DeferredInit` source-order contract. The new
directional workload negative control failed before actor/static separation
because one animated near actor requested a complete 2048 four-sample static
map rebuild. The corrected model produces 120 actor overlays and zero static
map submissions across the equivalent 120-frame sequence. The complete
supported-target gate passes 569 OMV tests and doc tests with no failures, and
`cargo build --release --target i686-pc-windows-gnu -p omv` succeeds. These
gates produced a 12,843,543-byte `omv.dll` with SHA-256
`9a904586eb59efdadac34b07158e01fdab364660a3f003b90e6ce26065e9aa3d`.
These results prove compilation and the deterministic contracts, not a
rendered Proton/DXVK frame or an achieved frame rate.

That artifact was subsequently rejected by the known BaseObjectSwapper
pre-Deferred crash signature. The render implementation above remains intact.
The startup-only correction removes Shadows from every value constructed or
copied during `NVSEPlugin_Load` and gives the unchanged schema-one table a
dedicated `DeferredInit` parser. Static regression tests reject both the former
main-config deserialization and every former staged value owner. This restores
the documented phase boundary but cannot establish Proton compatibility; the
corrected artifact remains unaccepted until a cold BaseObjectSwapper-enabled
run reaches `[INIT] Deferred OMV graphics hooks initialized` and gameplay.
The corrected supported-target gate passes all 571 OMV tests, including 78
focused shadow tests, and produces a 12,822,605-byte `omv.dll` with SHA-256
`8c5b55dcac328ad5f5f6fc96a2e06f442f285dfd84b7af2e9050645bd4971c`.
Its import and TLS sets are unchanged from the crashing artifact; complete
footprint evidence is recorded in
`docs/graphics_fnv_atmosphere_startup_crash_errata.md`.

#### Eighth corrective pass: light ownership, current-view cascades, and stable contacts

The next runtime artifact reached gameplay but was rejected for mixed-light
artifacts, camera-moving far-wall rectangles, unstable contact shapes,
incomplete actor shadows, first-person view-model projections, and excessive
frame cost. This pass supersedes the seventh pass's active render description;
that older text remains only as the history of a rejected artifact. The
startup-only correction remains intact. No schema, persisted value, preset,
hook admission, TLS owner, static initializer, worker order, or
pre-`DeferredInit` first touch changes here.

Eight deterministic negative controls failed before production was changed.
They reproduced an exterior becoming darker when an occluded Pip-Boy light was
added, overlapping interior estimates subtracting beyond their owned local
energy, a cached coverage sphere selecting a different cascade on a moved
camera, contact visibility toggling without valid history, an unflagged
first-person child being admitted, a skinned partition being rejected solely
because `NiGeometryData::m_pkBuffData` was null, one full 2048-square actor
merge every animated frame, and compiled `D3DSIO_DSX`/`D3DSIO_DSY` operations
in the branched fullscreen compositor. An additional workload negative control
then proved that one near actor intersected all nested cascade frusta and
therefore rebuilt the middle and far static maps every frame. A final compiled
ABI negative control rejected the initial one-target mixed-light correction:
compressing an occluded RGB subset to scalar luminance made an occluded red
light incorrectly darken an overlapping unoccluded blue light.

Local-light accumulation now publishes two exact RGB identities from one
scissored draw into equal-format additive FP16 MRTs. One target is the selected
lights' total modeled direct contribution; the other is the subset proven
occluded by cube depth. No extra fullscreen pass is needed, and independently
colored lights cannot leak a scalar visibility into one another. The
compositor clamps both terms to source radiance and uses
`source * directional + local * (1 - directional) - local_deficit`.
Consequently the sun can attenuate only its surface term: switching on the
Pip-Boy can physically fill a sun shadow but cannot make that receiver darker.
Interiors use directional identity one and subtract only the cube-proven subset
of the same local estimate. HDR emitter preservation and the near-source guard
remain independent protections.

Cached map coverage and visible cascade selection are now separate contracts.
The cached, padded sphere is used only to decide whether a retained map still
contains the current receiver slice. At composition, all four unpadded receiver
spheres are recomputed from the actual consumer camera, including a one-epoch
producer/consumer handoff. They can therefore neither stick to an older world
center nor inherit the map guard radius. Cached matrices remain paired with
their generation origins and are translated into the consumer camera domain.
This closes the moving rectangular boundary on broad walls without resampling
old moments through a new transform.

Actor admission now matches NVR's actual submission ownership. A skinned
geometry does not require the unrelated main geometry buffer; each
`NiSkinPartition::Partition +0x28` supplies the buffer submitted to
`NiDX9Renderer::DrawSkinnedGeometry @ 0x00E6D310`. Static geometry still
requires its main buffer. First-person exclusion no longer assumes the engine
maintains NVR's private shade bit. Every directional and point-cube route also
walks bounded parent ancestry against
`PlayerCharacter::firstPersonNiNode +0x694`. Existing radare2 evidence proves
`PlayerCharacter::Get3D @ 0x00950BB0` returns this root for its true branch and
the ordinary `TESObjectREFR::Get3D @ 0x0043FCD0` third-person root otherwise;
see
`analysis/radare2/output/perf/graphics_fnv_motion_blur_player_coverage_contract.txt`.
Modern NVR source establishes that the first-person shade bit is mod-owned and
periodically written, so it is retained only as a fast additional rejection.

The actor-only near resolve is sampled independently at visible near receivers.
The obsolete static-near backing texture, 2048-by-2048 merge shader, full-map
merge draw, restore copy, and 32 MiB allocation are gone. Static atlas moments
and actor moments are each evaluated as complete EVSM distributions and their
darker visibility wins; channels from different distributions are never
combined. Animated bounds now follow the consumer's smallest-sphere ownership
rule and add only the adjacent map when the actor crosses the outer ten-percent
blend shell. A player in the near core therefore requests its private actor
overlay and zero nested outer static-map rebuilds. Distant actors still update
their selected gameplay map, and no actor enters the LOD profile. Four-sample
2048 generation, FP16 EVSM4 precision, third-person skinning, and conservative
root-cache overflow behavior are unchanged.

Contact shadows retain NVR's four cumulative ray positions but replace
screen-space toggling with an explicit three-stage half-resolution contract.
Raw G16R16F stores visibility and linear receiver depth. One depth-aware
five-sample cross filter replaces the former two separable passes. The third
draw reprojects the preceding completed map from the current camera into the
previous camera, rejects skipped epochs, cuts, off-screen samples, and every
depth-disagreeing history tap, then gives valid history a bounded 0.75 weight.
Manual four-tap depth-rejected history filtering stabilizes sub-texel camera
motion without interpolating foreground and wall depths. Final composition
again checks stored contact depth against the full-resolution receiver, which
prevents half-resolution evidence from drawing a line across a disocclusion.
Spatial, temporal, and final ownership all use the same two-unit/0.25-percent
depth tolerance; the rejected broad twenty-unit spatial threshold could bridge
a foreground edge even when temporal history was valid.
The pass count remains three quarter-resolution draws. Memory becomes three
G16R16F maps. Exact colored local-light ownership adds one full-resolution FP16
MRT, while removal of static-near moments still reduces the combined
1920-by-1080 lazy-branch estimate to 518,220,800 bytes.

The compositor no longer uses quad derivatives after depth/sky rejection.
Only an actual EVSM transition reads four neighboring depths, chooses the
depth-nearest difference on each screen axis, reconstructs the receiver normal,
and resamples with NVR's grazing offset. Uniformly lit or shadowed pixels avoid
those four reads. Compiled shader tests reject derivative opcodes, retain a
static instruction ceiling for D3DCompile's expanded mutually exclusive
cascade branches, and bound contact temporal history to exactly one current
plus four individually depth-rejected history samples.

Modern NVR evidence reused by this pass is
`.research/TESReloaded10-master/src/core/RenderPass.cpp:182-296`,
`.research/TESReloaded10-master/src/core/ShadowManager.cpp`, the New Vegas
shadow HLSL under `.research/TESReloaded10-master/src/hlsl/NewVegas/`, and the
custom-quality defaults at
`.research/TESReloaded10-master/resource/NewVegasReloaded.dll.defaults.toml:570-690`.
The executable identity remains SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

Validation on 2026-08-12 used the supported explicit
`i686-pc-windows-gnu` target. The focused shadow suite passed 86/86 tests, the
complete OMV suite passed 579/579 tests, and the release build succeeded. The
resulting `omv.dll` is 12,829,332 bytes with SHA-256
`2b8d099bb7ff4ccb6cb820c97fa8b88268e9dd2a582201c52ea903379a9ec0a6`.
`cargo fmt -p omv` and `git diff --check` also passed.

Static and build validation cannot prove a Proton/DXVK image or frame rate.
Runtime acceptance still requires the same exterior and interior scenes with
sun plus Pip-Boy, multiple differently colored local lights, broad distant
walls, camera translation/rotation/height/zoom, contact disocclusions, moving
third-person actors, first-person hands and weapons, small/alpha casters,
sunrise/time jumps, fog/volumetric/shaft ordering, and measured stage/frame
times. Cold BaseObjectSwapper-enabled load to gameplay remains a separate
mandatory startup acceptance gate.

#### Ninth corrective pass: screenshot-isolated contact depth and motion stability

This pass supersedes the eighth pass's active contact-depth, contact-pass, and
exterior mixed-light descriptions; that text remains rejection history.
The runtime evidence for this pass is the complete `shadow*` set supplied in
`.reports/`: `shadows_exterior_light_mix.png`,
`shadows_far_artifacts.png`, and `shadows_far_artifacts_detailed.png`. The
first image shows a local-light/sun interaction cutting a large jagged dark
region into an exterior facade. The two Tenpenny images show hard vertical and
horizontal rectangles on the tower at a displayed distance of 2130 m. The
additional runtime report states that ordinary forward movement with `W`,
especially combined with faster camera movement, makes exterior geometry and
contact shadows flicker. These are runtime observations; the screenshots do
not by themselves prove which producer wrote a pixel.

The active distance contracts isolate the likely tower route without relying
only on visual resemblance. Directional cascades stop at the configured 6000
game units, whereas the contact route continues to its 180,000-unit default.
Using FNV's conventional approximate scale of 70 game units per HUD metre, the
displayed 2130 m is about 149,100 units: outside the atlas and inside contact
coverage. That conversion is a reasoned inference, not new executable proof.
Static inspection independently found that the contact G16R16F target stored
raw linear depth. Binary16's largest finite value is 65,504, so every valid
contact receiver beyond that limit overflowed or saturated before filtering,
temporal reprojection, and final receiver matching. The corruption explains
stable screen partitions becoming camera-dependent rectangles instead of
coherent distant geometry.

Contact depth is now stored as `linear_depth / 250000`. The fixed denominator
is the schema-one contact slider's complete supported range, rather than the
current camera far plane, so a camera or FOV change cannot reinterpret history.
The spatial blur is no longer part of the active path. The generation scratch
feeds the camera-reprojected temporal resolve directly, and both temporal
rejection and final composition decode the key before applying the established
two-unit or 0.25-percent linear-depth tolerance. Three G16R16F allocations
remain: one generation scratch and two completed-history targets. The runtime
topology drops from three half-resolution fullscreen draws and fifteen
executed texture reads per output pixel to two draws and twelve reads.

The motion report exposed two additional NVR-contract deviations. First, a
half-resolution contact raster center commonly lies on a full-resolution depth
texel boundary. The old shader point-sampled one texel but reconstructed the
requested boundary coordinate, so receiver position changed as the camera
crossed sampling phases even when the depth value did not. Receiver and ray
samples now snap to the exact full-resolution texel center selected by the
point sampler. Temporal reprojection reconstructs each stored key at that same
full-resolution receiver ray rather than the half-resolution carrier UV.
Second, OMV scaled NVR's ray by view Z. NVR uses homogeneous
view distance; equal-distance receivers therefore received different ray
lengths as they moved from screen center to an ultrawide edge. OMV now uses
the radial length of the reconstructed view position.

Exact addressing does not alone distinguish a blocker from the receiver
surface. Contact generation now samples two receiver depths on the side
opposite the projected light ray. Device depth is affine over a rasterized
plane, so those samples define a raw-depth plane without a derivative or four
extra view-position reconstructions. A ray sample matching that plane is
self-occlusion and remains neutral; a depth-separated sample within NVR's
twenty-unit marched-ray thickness remains a valid blocker. Endpoint,
silhouette, border, and discontinuous-neighbor failures also return neutral.
This replaces the removed five-tap spatial pass: receiver validation adds two
generation reads while eliminating five filter reads and one draw. NVR's four
cumulative ray positions, temporal weight, half resolution, and contact range
are unchanged.

The exterior mixed-light compositor now treats the directional-only surface
as a lower bound. NVR-derived analytic point attenuation may overestimate the
local energy actually present in a native material. Such an estimate may fill
a sun shadow when visible or remove that fill when cube-occluded, but it may
not subtract through the sun-only result into ambient/emissive ownership. The
bound applies only when the exterior directional branch is active; interiors
retain exact RGB local-deficit subtraction. Directional and actor atlas reads
also reject projected Z outside `[0, 1]` instead of saturating it and sampling
a clamped map edge, closing another source of moving rectangular geometry.

Eight regression controls failed before these production changes. They cover
binary16 quantization and decode at 149,100 units across forward motion,
half-to-full-resolution point-sample centers at 3440 by 1440, radial ray scale
at equal world distance and after ordinary forward movement, planar-receiver
self-occlusion versus a detached blocker, complete directional clip-volume
admission, temporal reconstruction at the generation texel center, an
overestimated Pip-Boy cube cutting below the sun-only image, and the old
three-pass/fifteen-read contact workload. The tests use numeric depth
quantization, geometric samples, radiance bounds, compiled SM3 programs, and a
loop-aware workload model; no behavior is accepted because source text merely
exists. The previously established actor, first-person, sky, fog ordering,
cascade coverage, and point-light image oracles remain in the same suite.

The NVR facts reused here are the four cumulative contact positions, fixed
twenty-unit thickness, homogeneous-depth ray scale, 180,000-unit default, and
point-light equations in
`.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/SunShadows.fx.hlsl`,
`.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/Includes/Shadows.hlsl`,
and the custom-quality defaults. The executable identity and established hook,
phase, depth, camera, and actor contracts are unchanged. No configuration,
preset, schema, hook admission, TLS owner, lazy/static owner, worker phase, or
pre-`DeferredInit` publication changes in this pass; shadow bytecode preparation
remains after the deferred safety boundary.

Validation on 2026-08-13 used the explicit supported
`i686-pc-windows-gnu` target. All 94 focused shadow tests and all 587 OMV tests
pass, including doc tests, and the release build succeeds. The resulting
`omv.dll` is 12,840,339 bytes with SHA-256
`75d8e38ff69db79a2c728243c4f4c86cf9ca00e3e3f0eb41978bc0869f2477f5`.
`cargo fmt -p omv` and `git diff --check` also pass.

Static tests and a release build can prove the numeric, ABI, shader-model, and
workload contracts, but cannot prove the final Proton/DXVK image or measured
frame rate. Runtime acceptance still requires the three supplied scenes plus
forward/strafe movement, simultaneous fast camera rotation, ultrawide edges,
sun plus Pip-Boy, contact on broad ground and walls, cascade boundaries, and
measured stage/frame times. The BaseObjectSwapper-enabled cold load-to-gameplay
gate remains mandatory and separate from visual acceptance.

#### Tenth corrective pass: production-path movement contracts

The ninth artifact was runtime-rejected: forward movement still made shadows
appear or flicker, fast camera rotation changed shadow geometry, distant wall
rectangles and contact artifacts remained, and the claimed fixes were not
visible. Its temporal-contact and validation descriptions above are therefore
rejection history, not the active design.

This rejection was not a stale DLL or an unwired route. The deployed
`mods/omv/NVSE/plugins/omv.dll` and the matching target artifact both had
SHA-256 `fb8f626379d01dbd85a4723462156248a53de56d8bd1548b6cd1c08a741e9a6e`.
The supplied runtime log records successful shadow bytecode preparation,
directional and point resource publication, and pre-alpha composition. It also
records alternating off-centre TAA frusta at 3440 by 1440, with lens-centre
offsets around `+/-0.00045`. These are runtime facts about the rejected
artifact. They prove that work executed; they do not accept its image.

The central validation error was that several passing tests exercised reduced
Rust equations without proving that the compiled production shader and map
cache made the same decision. Six new negative controls were run against the
rejected implementation before their fixes:

- a depth-only temporal contact resolve retained `0.25` visibility on one side
  of a moved wall while the current ray required `1.0`;
- production cascade-sphere selection changed from cascade 1 to cascade 0
  under a log-sized TAA lens shift;
- half-resolution point upsampling attached an odd pixel's receiver depth to
  the adjacent even receiver;
- a quantized affine D24 wall exceeded the old fixed one-LSB plane tolerance
  and was classified as a detached contact occluder;
- an actor moving from outer cascade bit `0b0010` to `0b0100` dirtied only
  `0b0100`, leaving its old silhouette in the departed map; and
- after initial atlas publication, a changed exterior root set scheduled
  `[false, false, false, false]`, so newly streamed geometry could not enter a
  cached map until an unrelated camera or sun invalidation.

Those failures map directly to active production paths. Contact history is now
removed, not retuned. Receiver depth proves only which wall owns a sample; it
cannot prove that the ray hit the same occluder after camera or object motion.
Raw contact evidence therefore passes through one same-frame, depth-aware cross
filter. The deleted temporal shader, history matrices, camera state, ping-pong
index, and third G16R16F target cannot retain a camera-following shape or delay
a newly detected shadow. Two half-resolution draws remain. The loop-aware
workload contract counts at most fourteen texture samples across those stages,
and the exact 1920-by-1080 combined resource model is 516,147,200 bytes.

Every half-resolution contact receiver is reconstructed at the exact
full-resolution depth texel selected by point sampling. Final upsampling first
accepts the nearest sample only when its normalized 250,000-unit depth key owns
the full-resolution receiver; only a mismatch takes four axial, independently
depth-rejected taps. A distant planar receiver is evaluated in affine device
depth. Its rejection tolerance now grows by the worst-case accumulated D24
endpoint quantization over the sampled pixel displacement, preventing a broad
wall from becoming a false detached blocker. A real blocker must still satisfy
the unchanged NVR twenty-unit marched-depth test, so this stability correction
does not soften valid contact silhouettes.

Depth reconstruction retains the jittered lens that produced the depth
buffer. Cascade ownership does not: the atlas producer uses the restored output
camera, so consumer selection removes only the TAA lens-centre offset while
preserving frustum width, height, pose, and FOV. This closes the exact boundary
failure observed with the recorded Halton-sized shifts. Atlas and actor reads
also retain the ninth pass's complete light-volume Z rejection.

Directional cache ownership now includes scene and animated-caster history.
Outer actor work dirties the union of previous and current cascade footprints;
the near actor map remains a same-frame optional publication and needs no stale
clear when it is not sampled. The previous footprint advances only after the
complete D3D transaction succeeds. The complete collected root set also has an
allocation-free, order-independent identity containing pointer and form/land/
LOD profile metadata. An added, removed, or reprofiled root invalidates all
retained maps; cache overflow remains correctness-first and does the same.
This closes movement-triggered cell streaming without periodically redrawing a
stable exterior. The integer identity is never dereferenced outside the native
common-shadow epoch.

Point-light and sun energy remain distinct. The exterior result cannot fall
below its directional-only lower bound when the NVR-derived analytic local
estimate exceeds light energy actually present in the native surface. Exact
RGB local deficit remains active for interiors. Point-cube caches already
retain the union of previous and current animated face footprints, so a body
crossing a cube edge clears both its abandoned and arrived silhouettes.

The ordinary exterior frame with no selected local light now uses a compiled
compositor specialization. Its equation is algebraically identical to the
mixed shader at zero point contribution, including HDR-emitter preservation,
but compiled bytecode removes two full-resolution point-buffer reads and 39
static instructions in the current compiler result. Contact generation keeps
four NVR cumulative ray positions, FP16 EVSM4 maps keep 2048 resolution and
four coverage samples, and no quality control or form category was reduced.

Validation on 2026-08-13 used the explicit supported
`i686-pc-windows-gnu` target. The focused shadow suite passes 100/100 tests,
the complete OMV suite passes 593/593 tests plus doc tests, and the optimized
OMV build succeeds. The resulting 12,839,242-byte `omv.dll` has SHA-256
`faed039e36141c982197733682b6e18afaf68c7c72b44696f24d5ca766c93c07`.
Formatting and `git diff --check` also pass. These results establish the static
contracts and supported build only.

This pass changes no persisted configuration field, schema, preset, hook
admission, TLS owner, worker phase, or pre-deferred publication. It did change
the inline payload of the existing shadow `LazyLock`, however: the tenth-pass
runtime state reduced its loader-visible size from the last gameplay-reaching
shadow build's `0xA28` bytes to `0x9D0`. The next cold load failed at the exact
known BaseObjectSwapper `+0x4990` pre-Deferred signature before any shadow code
ran. The static-owner correction retains the complete tenth-pass pipeline
behind a `Box` allocated only by the established DeferredInit installer and
restores an explicit `0xA28` compatibility slot. A target-width compile-time
assertion plus a regression test prevent future pipeline fields from silently
changing that slot. This is a startup-footprint repair only; it does not alter
shadow quality, work scheduling, resources, shader bytecode, or admission.

Static and supported-target validation still cannot prove the corrected cold
load, final Proton/DXVK image, or frame rate. Startup acceptance first requires
the deferred marker and gameplay with BaseObjectSwapper installed. Visual
acceptance remains the supplied three scenes plus forward/strafe motion,
simultaneous fast yaw, distant planar walls, sun plus Pip-Boy, third-person
animated bodies, first-person hands, contact disocclusions, and measured
exterior/interior frame times.

The startup-corrected supported release artifact is 12,846,995 bytes with
SHA-256
`baa5aac1919d14a62357aeca5151057e2052385a9a640972969d6c55806afd3c`.
All 594 OMV tests pass, including 101 focused shadow tests, and PE inspection
confirms the required `0xA28` pipeline owner with unchanged imports, TLS,
import-address-table, and `.bss` footprints relative to the rejected build.

#### Eleventh corrective pass: provider-parity depth and fused exterior light work

The next runtime report established two independent defects. Shadows were
visible only with the OMV depth provider, and exterior shadows approximately
halved frame rate. The depth failure was a common-API contract violation, not
a shadow equation: shadows request `PreAlphaWorld`, but the external route
only returned a snapshot published after `RenderWorldSceneGraph`. Beginning a
new render epoch cleared that post-world snapshot before the pre-alpha request,
so `depth_resolve` deterministically rejected the shadow consumer.

Depth Resolve 1.31 physically owns two world copies inside its native
accumulator: pre-water and post-water. The common depth API now asks the
external provider to publish metadata at the requested world boundary. It
retains the provider's existing INTZ texture and records the exact source
surface, projection, depth convention, dimensions, stage, and epoch. It does
not execute RESZ, NvAPI, or an OMV fallback copy. Stage/slot mismatch and
first-person requests remain rejected because the external provider owns only
world depth. The executable provider-route regression requires both providers
to serve `PreAlphaWorld`, while also requiring the external route to remain a
borrowed boundary snapshot rather than an OMV physical resolve. Exact capture
tests continue to reject stage, source, epoch, and dimension aliasing.

The exterior local-light consumer had two avoidable bandwidth multipliers. It
first wrote an `A16B16G16R16F` full-resolution receiver-geometry target, read
that target in point accumulation, and split twelve overlapping lights across
two full-screen six-cube draws. Pixel shader model three exposes sixteen
samplers, so scene depth plus all twelve NVR point cubes fit concurrently. The
production shader now reconstructs the same five-sample, discontinuity-safe
receiver normal directly from scene depth and immediately evaluates exact RGB
total and occluded energy. This deletes the geometry target and its complete
write/read transition without changing a receiver, light, or cube equation.
Twelve camera-containing lights schedule one draw instead of two; separated
lights keep conservative individual scissors so batching never adds empty
screen work.

Uniform draw counts select compiled one-, six-, or twelve-light programs. The
common carried/Pip-Boy case therefore runs the 345-instruction one-light
program instead of retaining eleven unused light branches from the measured
1,524-instruction maximum program. The six-light specialization is 880
instructions. Bytecode tests require 6, 11, and 17 or fewer texture
instructions respectively, reject derivatives, and validate the sampler and
constant-register ABI. The full twelve-light program keeps all configured
coverage and performs one depth centre plus four neighbour reads and twelve
cube reads; no resolution, EVSM precision, point-map size, or light limit was
reduced.

The exact 1920-by-1080 resource model drops by 16,588,800 bytes: exterior and
combined peak become 499,558,400 bytes, and the interior branch becomes
126,312,448 bytes. A separate exterior producer defect scheduled the complete
2048-by-2048 four-sample actor overlay even when the third-person player root
was application-culled in first person. Dynamic invalidation and overlay
submission now use the same root-level app-cull predicate as the actual native
geometry traversal. Visible player/NPC actors retain the full overlay; only a
map which provably submits no geometry is skipped.

This pass changes no configuration, schema, preset, hook admission, TLS,
worker order, or pre-Deferred publication. The additional bytecode variants
are prepared by the established post-Deferred worker. `ShadowPipeline` remains
behind the startup-corrected boxed `0xA28` compatibility owner. Static tests
and the supported build can prove provider routing, shader compilation,
workload bounds, resources, and startup footprint; measured FPS and final
depth alignment still require the user's Proton/DXVK playtest.

Validation on 2026-08-13 used the explicit `i686-pc-windows-gnu` target. All
102 focused shadow tests and all 596 OMV tests pass, including doc tests, and
the supported release build succeeds. The resulting `omv.dll` is 12,818,327
bytes with SHA-256
`227dcb84d4835271807aa812e39e35c167bafb2af2515b71ae31bb8885ab9f7c`.
PE inspection retains `PIPELINE = 0xA28`, `.bss = 0x6b10`, `.idata = 0x340c`,
`.tls = 0x8`, TLS directory `0x18`, and IAT `0x6bc`; imported DLL identities
are unchanged from the startup-corrected baseline. Formatting and
`git diff --check` also pass.

#### Twelfth corrective pass: native skin-cache ownership and static/dynamic map separation

The eleventh artifact was runtime-rejected. Exterior Shadows cost about 70 FPS
on the reported RX 6800 XT system, movement still made retained shadows flicker
or appear with distance, and nearby third-person bodies could disappear while
their separately rendered weapon remained. The same body disappearance then
occurred for nearby NPCs in interiors, where a head or weapon could remain.
These are observations from the user's Proton/DXVK playtest. They reject the
previous runtime result and the earlier inference that restoring raw D3D state
made native renderer-cache interaction transparent.

Direct radare2 inspection of the identified executable closes the actor state
contract. `NiDX9Renderer::CalculateBoneMatrices @ 0x00E6FE30` is a thiscall
with the renderer in `ECX` and `NiSkinInstance*` as its first stack argument.
It reads and writes the skin calculation stamp at `+0x18` and calculation mode
at `+0x20`; `0x00E6FE54..0x00E6FE62` returns early when the current frame and
mode already match. The same function reaches the renderer's render-state
owner at `renderer +0x8B8`. Function `0x00E88AD0` writes the byte at render
state `+0x10F5`, which the supplied NVR headers identify as
`InternalNormalizeNormals`. Those headers also establish the relevant exact
`NiSkinInstance` layout: bones `+0x1C`, bone registers/mode `+0x20`, bone
capacity `+0x24`, bone matrices `+0x28`, and skin/world matrices `+0x2C`.
Modern NVR calls this helper as
`CalculateBoneMatrices(skin, world, false, 3, true)` before native
`DrawSkinnedGeometry @ 0x00E6D310`.

The previous OMV producer called that native helper for actor shadow maps but
restored only device state. A nearby actor entering a shadow route could
therefore stamp its skin as calculated for the current frame and change the
renderer-global normalisation byte. The later native body pass could take the
early return while those CPU-side values belonged to OMV's shadow submission.
Heads and weapons use separate objects/routes, which explains why they could
remain. Player and NPC bodies share this contract; no player-specific masking
or point-light equation is required to explain the two observations.

The safe intervention point is the existing serialized common-shadow
transaction. Before its first native geometry submission, OMV snapshots the
renderer byte and journals each unique skin's original `FrameID` and
`BoneRegisters` exactly once in preallocated storage. All cascades and cube
faces may then reuse the native calculated matrices. Before `EndScene` and
before the native tail can render a body, OMV restores the original frame and
renderer byte on both successful and failed producer paths. A matching
mode-three stamp is restored exactly. A different original mode is set to an
impossible sentinel instead: restoring a current-frame mode-four stamp beside
newly written mode-three matrices would make the native early-return cache lie.
The sentinel forces the next native helper call to recompute. OMV deliberately
does not restore the bone allocation pointer, capacity, or matrix storage: the
native helper may have freed or grown that engine-owned allocation, so
restoring old pointers would create a use-after-free. The restored frame plus
exact-or-invalidated mode either describes mode-three matrices coherently or
forces native recomputation.

Static workload tests exposed four independent movement amplifiers which the
earlier near-actor-only performance test did not model:

- any actor touching middle or far set static cascade bits `0b0110`, causing
  complete 2048-by-2048 four-sample terrain/building maps to be redrawn every
  presentation;
- animated actor roots participated in the static root-set identity, so actor
  streaming or root changes invalidated all retained static cascades;
- point cubes were assigned by nearest-sort position, so a small camera move
  which exchanged two unchanged lights regenerated both six-face cubes; and
- every animated point face traversed the native light's complete geometry
  list, resubmitting static walls and clutter along with one moving skin.

Directional maps now separate immutable world roots from animated actor roots
for all actor-capable cascades. Near, middle, and far actor-only EVSM4 maps keep
the same 2048 resolution and four coverage samples; near/middle are packed
side-by-side behind one compositor sampler and far uses a second sampler.
Their complete moments are compared with static moments and the nearer complete
distribution is evaluated once. This is not a component-wise moment minimum,
which would corrupt EVSM's negative squared moment. The static atlas is
invalidated only by its own scene, projection, sun, light-profile, and
immutable-root contracts.

Actor overlays also no longer run a full-screen EVSM far-clear shader for each
active cascade. That rejected route shaded up to three complete 2048-square
four-sample targets every presentation before drawing a body-sized footprint.
D3D hardware now clears actor color/depth to zero. A valid positive EVSM first
moment is at least `exp(-5.54)` and therefore strictly positive, so zero is an
unambiguous empty-actor sentinel. The compositor treats it as neutral and
evaluates the same EVSM4 distribution wherever actor geometry wrote moments.
This removes up to three full-map multisample draws without reducing actor map
resolution, coverage samples, update cadence, or silhouette precision.

Each selected point light now owns a stable physical cube slot across
distance-order permutations. Its published 512-face `R32F` cube has an
equal-quality immutable-static backing cube. A new, replaced, or materially
moved light rebuilds all six static faces. Actor animation restores only the
union of the actor's previous and current faces from that backing cube and
submits only skinned geometry to current faces. The dynamic cube shader writes
the nearer of actor radial depth and the sampled static radial depth; this
preserves a wall in front of an actor even though the reusable D3D depth surface
contains only the actor pass. An abandoned face receives only the static copy,
which removes the old silhouette without another static traversal.

The final five percent of local-light draw range now has a smooth bounded
retirement weight instead of changing shadow contribution from one to zero
across one world unit. The weight is paired with the same map/light publication
and multiplies both local total and cube-proven deficit, so it cannot darken or
brighten unrelated energy. This handles the configured discovery boundary;
the twelve-light selection limit and 512 cube quality remain unchanged.

The regression sequence was intentionally negative first. Before the fixes,
the production-coupled tests observed a static directional mask of `0b0110`
for actor-only outer changes, two full six-face cube invalidations after a
distance-order swap, a one-to-zero point weight at the admission edge, and
four static point faces resubmitted for one compact animated caster. The
transaction-state test also rejected the missing skin and renderer cache
categories. A memory-backed fake renderer/skin test then mutates the exact
`+0x18`, `+0x20`, and `+0x10F5` fields as the native helper does, submits the
same skin twice, and requires exact frame/renderer restoration plus coherent
mode invalidation after a mode-three overwrite of an original mode-four cache.
Separate tests require disjoint and complete static/dynamic caster admission,
old-face restoration without an actor draw, stable physical cube ownership,
actor exclusion from the static root signature, and zero static cascade work
for an otherwise stable animated scene.

The first corrected actor compositor also failed the existing compiled-shader
gates at 2,510 instructions and 37 texture instructions. No ceiling was raised.
Merging complete moments before one EVSM evaluation, packing near/middle actor
maps behind one sampler, and reusing the nearest contact sample returned the
production programs below the existing 2,040-instruction and 32-texture-
instruction limits. The complete 106-test shadow-focused suite and all 600 OMV
tests pass on the supported target; doc tests and the optimized OMV build also
succeed. The resulting 12,844,216-byte `omv.dll` has SHA-256
`c1e3a5534a1dfc405a7bd73d3ce02f5db2eab997dc2de8e6a7cc04d3fd5838a2`.
PE inspection retains `PIPELINE = 0xA28`, `.bss = 0x6b10`, `.idata = 0x340c`,
`.tls = 0x8`, TLS directory `0x18`, and IAT `0x6bc`; imported DLL identities
are unchanged from the startup-corrected baseline. Formatting and
`git diff --check` pass.

At 1920 by 1080 the current conservative resource model is 675,719,168 bytes
for an exterior or retained combined branch and 201,809,920 bytes for an
interior-only branch. The increase comes from twelve immutable 512-face point
cubes and three persistent actor-only EVSM4 maps. It buys removal of repeated
static geometry traversal and preserves NVR's map precision, spatial
resolution, coverage sampling, light count, and actor cadence. These are
residency/work-topology bounds, not measured FPS claims.

This pass changes no persisted configuration, schema, preset, hook admission,
TLS owner, worker order, lazy/static owner, or pre-Deferred publication.
`ShadowPipeline` remains behind the startup-corrected boxed `0xA28`
compatibility owner. Static validation cannot prove that the disappearing
bodies, movement flicker, distance transitions, or reported frame rate are now
accepted at runtime. The next Proton/DXVK playtest must cover nearby player and
NPC bodies in both locations, forward/strafe plus fast yaw, light-order
crossings, cube-face crossings, distant walls, sun plus carried lights, and
measured exterior/interior frame times.

#### Thirteenth corrective pass: view-independent caches, exact LOD morphing, and actor coverage

The screenshots captured on 2026-08-13 reject several assumptions in the
twelfth artifact:

- `.reports/shadows_actor_squares.png` and
  `.reports/shadows_actor_squares_2.png` show large axis-aligned dark polygons
  behind the third-person actor instead of an antialiased body silhouette;
- `.reports/shadows_tower_artifacts.png` shows a deformed, nearly black
  Tenpenny Tower/LOD projection;
- `.reports/shadows_interior_missing_far.png` and
  `.reports/shadows_interior_far_exist.png` hold nearly the same interior view
  while a large distant shadow set disappears or returns; and
- `.reports/shadows_interior_missing_close.png` and
  `.reports/shadows_interior_exist_close.png` reproduce the same discontinuity
  on nearby stairs and walls after a small camera-angle change.

The user deliberately increased shadow darkness to make the boundaries easy
to inspect. That changes contrast, not the ownership failure: whole caster
sets and large rectangles change rather than a filter kernel merely becoming
more visible. The same playtest reports about 70 FPS instead of the normal
120 FPS and pronounced camera-rotation stutter.

The modern NVR re-audit found two contracts which cannot be copied unchanged
into OMV's retained architecture. `ShadowManager::GetNearbyLights` uses a
camera-forward dot test (and marks its cube-face approximation as needing
frustum improvement), while `AccumChildren` and the direct point geometry
list reject `NiAVObject::APP_CULLED`. NVR rebuilds its selected maps every
frame, so those observations expire with that frame. OMV retained the result
for many views. A light or caster which happened to be behind the camera when
a map was created therefore remained missing, and crossing the forward plane
could exchange a complete room-light shadow set. This is a cache-lifetime
violation, not an incorrect point-cube projection.

OMV now admits finite point-light influence by radius/distance independently
of camera orientation. Receiver projection/scissoring still rejects a light
which covers no screen pixels. Retained directional and cube traversal ignores
only the frame-local `APP_CULLED` bit; form opt-out, material compatibility,
fade, minimum projected radius, multibound, light-volume, and shadow-frustum
tests remain intact. Static directional root signatures additionally include
absolute transform and world-bound state, and point-map signatures include an
order-independent fold of every non-skinned geometry identity, transform, and
bound.

Doors, movable clutter, streamed geometry, and changed root transforms can no
longer survive indefinitely in an immutable map. Skinned geometry remains in
the independent presentation-rate actor path.

The nearest-twelve point-light boundary had a second discontinuity. Two nearly
equal candidates could exchange the last physical cube after sub-unit camera
motion, forcing six new faces and changing a whole local shadow. A retained
identity now competes with a bounded ten-percent distance preference. This is
hysteresis, not permanent pinning: a materially nearer source still replaces
the old owner. Physical slot preservation then prevents harmless nearest-order
changes from copying or regenerating other cubes.

The far-LOD deformation was a direct shader transcription error. Modern NVR's
`TerrainLODPass` uploads `WorldTranspose` at c140-c143,
`HighDetailRange` at c144, and morph/drop data at c145. Its vertex shader first
computes
`lerp(input terrain height, original Z, morph)` and then subtracts the loaded
land drop. OMV computed that intermediate value but subtracted the drop from
the original vertex, discarding geomorphing. The dedicated OMV terrain path now
uses the exact NVR ordering. The addresses remain the source-proven FNV globals
`kLoadedRange = 0x011F95F4`, camera translation `0x011F474C`, and
`fLODLandDrop = 0x011AD808`; no new executable assumption was introduced.

The actor rectangles invalidate the twelfth pass's zero-sentinel inference.
Zero is distinguishable from an exact EVSM sample, but a multisample resolve or
bilinear footprint blends zero with valid four-moment data. Scaling all four
EVSM moments by coverage does not describe any depth distribution, so even a
one-percent silhouette sample can evaluate as a large false occluder. Actor
maps now store `(linear depth * coverage, coverage)` instead. Each of NVR's
four coverage samples writes `(depth, 1)` and the hardware clear writes
`(0, 0)`. Resolve and bilinear filtering are closed under this representation;
the consumer reconstructs mean actor depth and retains the uncovered sample
fraction behind it. Static world maps continue to use full FP16 EVSM4. The
preferred actor work/persistent targets use `G16R16F`, halving their
presentation-rate color bandwidth; devices without multisampled G16R16F fall
back transactionally to the quality-equivalent four-channel format without
reducing resolution or four-sample coverage. The far actor texture also serves
as the required same-size resolve scratch, avoiding a redundant texture and
copy.

Camera rotation previously converted every still-valid half-texel sun or
guard-band refinement into as many as four 2048-square four-sample map draws in
one presentation. Retained-map planning now separates mandatory validity from
quality refinement. A receiver which no longer fits is rebuilt immediately;
a still-contained map approaching its guard or exceeding the half-texel sun
threshold is scheduled early, at most one quality map per frame, with rotating
cascade priority. Quality work waits whenever mandatory validity work already
owns the frame. This keeps the hard coverage invariant while removing both the
four-map refinement burst and avoidable mixed-work spikes responsible for
severe yaw stutter.

Point receiver batching is now instruction-aware. The rejected rule compared
only union area with summed rectangle area; two adjacent disjoint lights could
therefore execute both light branches over every pixel even though batching
saved no fragments. Compiled one/six/twelve-light programs establish a
conservative model of 238 shared receiver instructions plus roughly 107 per
active light. Fixed-array spatial sorting and greedy grouping accept a batch
only when the modeled work does not exceed separate draws. Overlapping local
clusters still share depth/normal reconstruction, while empty space between
clusters is never bridged. No render-thread allocation was added.

The regression sequence was negative first. Before implementation, focused
tests observed all of the following failures:

- point-light admission changed solely when camera forward was negated;
- an application-culled caster was rejected from a retained map;
- a 0.2-unit change exchanged the twelfth point cube;
- one-percent filtered actor coverage was non-neutral and non-monotonic;
- the terrain reference returned original Z instead of geomorphed Z;
- two adjacent disjoint point rectangles increased modeled shader work from
  6,900,000 to 9,040,000 units;
- four still-valid quality refreshes were submitted together;
- sun drift was classified as mandatory despite complete receiver containment;
- a changed static point-caster signature reused all six old faces;
- a changed directional root bound produced the same static-root signature;
- an unchanged bound hid a static caster rotation from retained-map identity;
  and
- non-urgent quality work was appended to an already expensive mandatory-map
  frame.

The corrected suite requires temporal invariance across opposite camera
orientations, strict cache invalidation for changed static geometry, bounded
selection hysteresis, monotonic actor subpixel coverage, exact terrain morph
and loaded-drop ordering, no-worse point shader work, independent spatial
cluster batching, immediate mandatory cascade work, and at most one
still-valid quality refresh per presentation. These are behavioral math,
temporal state, resource, compiled-shader, and workload assertions; none treats
the presence of a Rust/HLSL string as proof of image correctness.

At 1920 by 1080 the preferred retained exterior/combined model is 692,496,384
bytes, including full NVR 2048 cascade resolution, four coverage samples,
twelve 512-square `R32F` point cubes plus their immutable backing cubes, and
the new two-channel actor family. The quality-equivalent actor-format fallback
is 809,936,896 bytes, still below the 939,524,096-byte comparable NVR atlas
lower bound. Interior-only residency remains 201,809,920 bytes. The preferred
actor producer writes exactly half the color bytes of the rejected EVSM4 actor
producer per active overlay. These are static bounds, not an FPS claim.

This pass changes no configuration, schema, preset, hook admission, TLS,
worker order, shader catalog shape, lazy/static owner, or pre-Deferred
publication. `ShadowPipeline` and all new runtime state remain behind the
startup-corrected boxed `0xA28` owner. Static validation cannot prove final
visual acceptance or measured Proton/DXVK frame time. Runtime acceptance must
repeat the seven named captures, slow and fast yaw, forward movement, actor and
NPC animation, interior light-limit crossings, distant LOD transitions, and
frame-time measurement on both the RX 6800 XT and a lower-end GPU.

Supported-target validation on 2026-08-13 passed 117 focused shadow tests and
all 611 OMV tests, including compiled shader, depth-provider, frame-order, and
startup-footprint contracts. The `i686-pc-windows-gnu` release build also
passed. Its 12,868,086-byte `omv.dll` has SHA-256
`d21f145e03fbd4e0b52632df9e695798ee641b971d76bae06d746537e8bdb524`.
`git diff --check` and `cargo fmt -p omv -- --check` passed. This evidence is
deliberately separate from the runtime acceptance still required above.

### Evidence classification for the implementation

**Proven by executable/static artifacts:** the common hook/tail topology,
receiver ABI, branch continuations, bounded main/wrapper/offscreen caller
chains, manager/native layouts used here, geometry submission entries, and
executable hash. The caller-chain evidence is recorded in
`analysis/radare2/output/graphics_fnv_shadow_main_context_call_chain.txt`. A
focused radare2 check also proves
that `NiGeometry::IsGeometry` at vtable slot 6 dispatches to `0x00E68810`
(`mov eax, ecx; ret`), so its non-null result aliases the input object rather
than a separate `NiGeometryData` owner; see
`analysis/radare2/output/graphics_fnv_shadow_geometry_predicate_contract.txt`.

**Proven by NVR source:** quality defaults, shader equations/registers,
selection limits, consumer topology, alpha thresholds, radius/distance/bias,
contact-shadow model, and the defects explicitly rejected above.

**Proven by OMV code/tests/build:** deterministic policy/math and image
oracles, compiled shader budgets, configuration shape, executable phase order,
D3D ownership/resource plans, and supported-target compilation.

**Runtime-rejected inference:** restoring a D3D state block alone does not make
native skin and renderer CPU caches transparent. The disappearing player/NPC
bodies disproved that inference; the exact additional owners and corrective
journal are documented in the twelfth pass.

**Reasoned but awaiting runtime observation:** that the static engine owners
remain live in every modded render context, that the new explicit native-state
journal covers every CPU-side value mutated by the borrowed helpers, exact
visual parity or improvement, driver performance/residency, and startup
compatibility with the accepted BaseObjectSwapper baseline.

## Implications for the current OMV NVIDIA one-FPS problem

### The earlier workload comparison used the wrong boundary

The healthy modern NVR observer measured NVR's replacement shadow workload.
Because modern NVR jumps over `0x00871290..0x008719F7`, that measurement did not
include the native prefix.

Current OMV hooks the same entry but calls its trampoline. Its active local-light
flow is:

1. discover the D3D device;
2. call the complete native prefix, which also invokes the native tail;
3. discover/revalidate the device again;
4. capture camera/light-manager state;
5. scan, rank, copy, and publish scene lights for atmosphere consumers.

Therefore “healthy NVR and OMV execute the same native shadow transaction” is
false. NVR replaces it; OMV surrounds it.

### Why this does not prove the native prefix is the cause

The vanilla game also executes the native prefix and is not reported to run at
one FPS. The prefix alone is therefore insufficient. Plausible interactions
are:

- OMV's post-prefix CPU/VM-query work lands immediately after native shadow
  command submission or driver validation;
- the hook runs more than once per present in normal/special/screenshot
  contexts;
- atmosphere native-shadow capture at `0x00B9F780` adds work inside the native
  prefix while local-light capture adds more at its outer boundary;
- other OMV transactions introduce resource/state dependencies that make the
  native prefix or the following getters block on NVIDIA;
- the world-light work combines with the independently proven overly broad
  `0x00E812F0` PBR resource hook and exterior terrain work.

Those are causal hypotheses. Only split timing on an affected machine can rank
them.

### Source-proven OMV hot work at this boundary

Current OMV declares the common-entry type and detour as zero-argument
`extern "cdecl"` functions. All three executable call sites load the native
receiver into `ECX`, so the exact native entry ABI is thiscall-like. OMV does
not capture that incoming register and performs substantial work before
invoking its cdecl-typed trampoline; `ECX` is caller-saved and is not guaranteed
to retain the original value.

On this executable the mismatch is masked because the native prefix uses its
saved receiver only to pass it to the tail, and the tail only stores it. Modern
NVR still declares its detour `__fastcall RenderShadowMapHook(void* apThis)`,
which captures incoming `ECX` correctly even though the shown hook does not use
`apThis`. Legacy NVR's naked detour explicitly preserves registers with
`pushad`/`popad` and deliberately supplies its own manager as `ECX` to its C++
replacement.

OMV's cdecl declaration is therefore a source-proven ABI defect and an
important hook-rework requirement. It is unlikely to be the isolated one-FPS
cause in this binary because the lost receiver has no observed semantic use,
but relying on that accident is not an acceptable engine contract.

When local-light capture is ready, `hook_world_light_epoch` calls
`d3d_device_ptr()` before and after the original transaction. Each lookup reads
two engine pointers through `validate_memory_range`; each validation performs a
`VirtualQuery`. Device discovery therefore costs four queries.

Because either atmosphere or terrain capture requests a camera, the successful
camera path performs three more validations: world-scene-graph pointer, camera
pointer, and one bulk camera range. `capture_scene_lights` validates the light
manager once. A successful active outer capture therefore has a source-proven
base cost of eight `VirtualQuery` calls before scanning up to 512 manager
entries. The list and light fields are deliberately read unchecked after that
single manager validation. Validating the manager allocation does not validate
the manager's list pointer, list nodes, or pointed light objects; safety relies
on an unstated same-render-thread lifetime/stability assumption across the
entire scan.

This path is coupled directly to the historical PBR trigger:
`store_terrain_options` calls `fnv_local_lights::configure_terrain` with the PBR
enabled flag. Terrain capture therefore keeps the outer scan active even when
volumetric atmosphere capture is off. A PBR on/off comparison changes both the
PBR draw path and this native-shadow-boundary scan, so it cannot isolate either
one without a more focused A/B.

The optional completed-shadow path is far more expensive than this base count.
For each retained native slot 0 through 3, `hook_render_local_shadow` performs:

- two queries in another `d3d_device_ptr()` lookup;
- five validations for the shadow record and its initial fields;
- 48 validations because three 4-by-4 matrices are read through a helper that
  validates every scalar separately, despite the earlier whole-record check;
- eight validations while resolving the rendered-texture, `NiTexture`,
  renderer-data, raw-COM-object, and vtable chain;
- one further whole-record validation when retaining the engine texture.

That is 64 `VirtualQuery` calls for one successfully retained shadow slot. Four
slots add 256 queries to one outer transaction. The texture resolution also
calls D3D9 `GetType`, `GetLevelDesc`, `GetDevice`, and `GetLevelCount` for every
slot; `GetDevice` creates an owned COM reference that is released when the
temporary wrapper drops.

When atmosphere later requests a binding, each retained shadow resolves the
texture chain again: eight more `VirtualQuery` calls and the same D3D9 texture
inspection calls. With four accepted slots and one later binding of each, the
documented path reaches 296 memory queries: eight outer, 256 capture, and 32
consumer revalidation, before counting any other OMV owner or an additional
shadow-entry context.

This redundant validation pattern is a source-proven hot-path defect, not a
mere theoretical lower bound. `VirtualQuery` itself is still CPU/OS work and
does not inherently explain NVIDIA specificity, but per-slot D3D getters and
the location inside/after native shadow submission make the path a much
stronger candidate for the catastrophic render-thread stall.

### Native shadow enrichment and modern NVR are mutually exclusive flows

OMV's optional atmosphere hook at native shadow helper `0x00B9F780` consumes
completed native `ShadowSceneLight` slots. Modern NVR's replacement prefix does
not execute that helper or populate those native completed textures.

Consequences:

- OMV native-shadow enrichment cannot be assumed to work under modern NVR;
- a future NVR-compatible OMV path needs an explicit capability/resource ABI,
  not native-slot inspection;
- performance A/Bs must state whether native prefix, modern NVR replacement, or
  neither produced the shadows.

### Native DepthMap shaders do not alias OMV terrain replacement

One plausible but rejected interaction was that OMV might replace the shaders
used while the native prefix renders its local-light shadow maps. The numerical
SLS ranges look suspicious until stage, table, and pass identity are kept
together:

- native selector 7 uses vertex group-C indices 92 through 95
  (`SLS2092.vso..SLS2095.vso`) and pixel group-B indices 90 and 91
  (`SLS2090.pso` and `SLS2091.pso`);
- OMV close terrain requires vertex group-C index 100 (`SLS2100.vso`), pixel
  group-B indices 92 through 147 (`SLS2092.pso..SLS2147.pso`), and pass IDs 503
  through 558 with `pass = pixel_index + 411`;
- OMV object templates end at vertex `SLS2049.vso` and pixel `SLS2056.pso`, and
  object admission also requires the recorded wrapper to occupy its exact
  PPLighting group-C/group-B table slot.

Consequently `SLS2092` in the native writer and `SLS2092` in close terrain are
different-stage wrappers in different pairs. Native selector 7 cannot satisfy
the close-terrain vertex, pixel, or pass tests, and it cannot enter the object
replacement family. OMV's global `BSShader::SetShaders` detour can still be
reached during native rendering, but source proves that an unclassified pair
falls through to the original binder without replacement.

This closes a potentially catastrophic shader-substitution hypothesis. It does
not make nested hook work free: every enabled `SetShaders` call first restores
any prior fallback, clears the pending-kind and sampler atomics, evaluates the
family gates, and then calls the original. Static evidence does not yet count
how often selector-7 rendering reaches that hook, so this remains a bounded
overhead/cadence question rather than a proven one-FPS cause. A runtime counter
should report `SetShaders` calls by package, pass, and admitted family, with
native selector-7 pairs expected to show zero PBR admissions.

### Hook ownership conflict

OMV's inline-hook enable verifies that target bytes still match the stolen
bytes. If modern NVR already owns `0x00871290`, OMV should reject enablement as
an ownership conflict rather than silently chain it. Modern NVR's blind
`WriteRelJump`, if installed later, can overwrite OMV's entry jump. OMV's
trampoline remains allocated but stops receiving calls.

This is a correctness/compatibility problem and a possible source of
configuration-dependent behavior. It is not a sufficient explanation for
OMV-only one FPS when NVR is absent.

### Refined root-cause ranking

The complete shadow contract changes the ranking as follows:

1. **Co-leading source-proven architecture defect:** OMV treats shared
   resource method `0x00E812F0` as a draw bracket even though executable proof
   shows buffer/resource preparation and no primitive submission. Exterior
   shader families multiply that work.
2. **New co-leading world-stage defect:** OMV wraps the full native shadow
   prefix and adds repeated device discovery, camera/light capture, and up to
   512 light entries at a boundary that can execute in multiple render contexts.
   Its completed-shadow path costs 64 `VirtualQuery` calls plus D3D texture
   inspection per accepted slot and revalidates again at consumption. Healthy
   modern NVR replaces this prefix and has none of this OMV capture path.
3. **Driver-facing transaction interaction:** broad state blocks, attachment
   getters/setters, COM ownership, effect copies, depth/world copies, and native
   shadow work may create a wait/serialization graph whose NVIDIA cost is much
   larger than the individual operations.
4. **Exterior close-terrain work:** sampler getters, 25 native pass-light
   entries, bounded property/manager scans, supplemental-light selection, and
   3-51 pixel-constant rows remain a strong scene-specific multiplier.
5. **Lifecycle/compatibility amplifiers:** protected per-frame package writes,
   hook order/conflicts, partial installation, and resource pressure remain
   credible but lower-ranked without correlation.

The native DepthMap/PBR substitution theory is below this ranking because the
exact stage/table/pass identities reject it. Modern NVR's uninitialized effect
construction is likewise a source-snapshot startup defect, not a steady-state
OMV hot path.

Depth resolution, RESZ selection, shader equations, raw copy count, live device
vtable mutation, and the trampoline jump itself remain rejected or materially
weakened as isolated causes.

### Required shadow-boundary diagnostics

The next diagnostic build must add coarse, allocation-free counters/timers for:

- entry count at `0x00871290` per present;
- dispatcher caller/variant classification for `0x00870851`, `0x00870A74`, and
  `0x00870C3C`;
- normal main-render, special-render, and screenshot context;
- OMV pre-original device lookup;
- original native `0x00871290` duration;
- OMV post-original device lookup;
- camera capture;
- light-manager validation;
- list length, entries scanned, accepted candidates, ranking work, and
  publication;
- nested `0x00B9F780` shadow-slot captures per outer invocation;
- exact validation counts per outer capture, per accepted shadow slot, and per
  later shadow binding;
- `GetType`, `GetLevelDesc`, `GetDevice`, `GetLevelCount`, and balanced device
  reference releases in shadow texture resolution;
- same-epoch repeated capture/publication count before each `DisplayScene` and
  which context supplied the epoch ultimately consumed;
- CPU duration in D3D getters/setters inside the native prefix where a coarse
  trace can attribute them;
- GPU duration of the native prefix separately from OMV screen effects.

Required A/Bs, in order:

1. no OMV DLL;
2. OMV loaded with optional visual hooks absent at startup;
3. `0x00871290` hook resident but pure trampoline pass-through;
4. trampoline plus local-light capture only;
5. atmosphere native-shadow capture only;
6. local-light and native-shadow capture together;
7. terrain/PBR only;
8. full configuration.

Run the same scene and camera on affected NVIDIA and an unaffected control.
Record frame-time distributions and the split CPU/GPU intervals. A long CPU
duration around a D3D call can be a driver wait; a GPU timestamp is needed to
distinguish submitted GPU work from CPU-side synchronization.

An experimental “call only `0x00871A50`” build would disable the native shadow
prefix and change visuals/engine behavior. It is not an appropriate first
diagnostic and must not be confused with a pass-through test.

## Proven facts, inferences, and remaining gaps

### Proven

- The current executable has three direct calls to common entry `0x00871290`.
- Their dispatcher is reachable from normal, special, and screenshot rendering.
- The native prefix calls separate tail `0x00871A50` exactly once.
- Legacy source replaces only one branch call; modern NVR replaces the common
  entry; current OMV wraps the common entry.
- Modern NVR explicitly calls the tail and skips the native prefix.
- Current OMV declares the thiscall-like common entry and its detour as
  zero-argument cdecl functions and does not preserve incoming `ECX`.
- Legacy's `0x004073D0` wrapper target is not a valid function entry in the
  identified executable.
- Both NVR source producers allocate default-pool resources and lack a complete
  reset contract.
- Legacy restores only depth and leaks its captured depth reference.
- Modern restores RT0/depth/viewport and seven scalar states but leaves a much
  wider dirty state and can desynchronize the engine cache.
- Modern NVR performs light selection before its rendering early-out.
- The modern source calls `UpdateSettings` before `RegisterTextures` on a
  derived object whose user-provided constructor leaves its resource pointers,
  settings, and `texturesInitialized` indeterminate; the known-false base
  `Enabled` field makes the first update call `clearShadowsBuffer`.
- Native selector 7's local-shadow writer uses group-C vertex indices 92-95 and
  group-B pixel indices 90-91. OMV close terrain instead requires group-C
  vertex index 100, group-B pixel indices 92-147, and passes 503-558, so it
  cannot replace the native DepthMap pair.
- Current OMV performs eight `VirtualQuery` calls in a successful active outer
  world-light capture before its scene-list scan.
- Each successfully retained native shadow slot performs 64 more memory queries
  plus D3D texture inspection; each later binding performs eight more queries
  plus the same texture inspection.
- Current OMV can scan up to 512 scene-light entries at that boundary.
- Modern NVR's healthy measured shadow work replaced rather than supplemented
  the native prefix.

### Reasoned inferences

- The OMV wrapper's placement immediately around native shadow work can amplify
  a driver wait even when each CPU operation is modest in isolation.
- Multiple render contexts can make per-call light capture more expensive or
  semantically unstable than a once-per-present design.
- The world-shadow boundary is a newly important co-candidate, but the existing
  `0x00E812F0` ownership defect and fragmented D3D transactions remain at least
  as important.
- NVR's incomplete state restoration works because of caller repair; copying
  that behavior into a differently placed OMV hook would be unsafe.

### Remaining evidence gaps

- the shipped legacy binary's true native-tail preservation behavior;
- whether the released modern NVR binary shares the construction order and
  uninitialized member state visible in this source snapshot;
- exact legacy generation/effect HLSL and sampler/pass ABI;
- GPU and CPU duration of the vanilla native prefix on affected NVIDIA;
- actual `0x00871290` calls per present and context in the failing setup;
- whether the long interval is native prefix, OMV pre/post capture, a nested
  native helper hook, or a later dependency;
- whether the one-FPS event correlates with resource residency/eviction;
- exact compatibility behavior with each installed NVR/Fallout Shader Loader
  version and load order.

## Primary evidence index

### Current executable and static artifacts

- direct radare2 inspection on 2026-08-12 of
  `NiDX9Renderer::CalculateBoneMatrices @ 0x00E6FE30`, including camera-origin
  subtraction at `0x00E700DB`, `0x00E700E8`, and `0x00E700F5`;
- direct radare2 inspection on 2026-08-13 of the same function's
  `NiSkinInstance +0x18/+0x20` early-return cache contract, renderer
  render-state access through `+0x8B8`, `InternalNormalizeNormals +0x10F5`
  writer `0x00E88AD0`, and native skinned submission
  `NiDX9Renderer::DrawSkinnedGeometry @ 0x00E6D310`;
- `analysis/ghidra/output/perf/graphics_fnv_pplighting_renderer_8b8_render_state_constructor_audit.txt`,
  corroborating renderer `+0x8B8` render-state ownership;
- `analysis/radare2/output/graphics_fnv_shadow_dismember_skin_layout.txt`,
  proving the `BSDismemberSkinInstance +0x34/+0x38/+0x3C` extension fields;
- direct radare2 inspection on 2026-08-09 of `0x008706B0`, the three branch
  calls, `0x00871290`, `0x00871A50`, `0x00B6B8D0`, `0x00B9F780`, their
  relevant xrefs/call sequences, and `0x004073D0`;
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_light_shadow_resource_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_pbr_shadow_selection_continuity_closure.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_light_value_copy_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_shadow_bind_lifetime_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_manager_epoch_contract_followup.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_shadow_texture_lifecycle_followup_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_volumetric_local_shadow_sampling_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_stage_boundary_order_deep_audit.txt`;
- `analysis/ghidra/output/memory/two_phase_hook_research.txt`.

### Legacy NVR source

- `.research/TES-Reloaded-master/TESReloaded/Core/ShadowManager.cpp:13-14,63-110,153-648,649-724,724-1016,1017-1304,1305-1566`;
- `.research/TES-Reloaded-master/TESReloaded/Core/ShadowManager.h:7-109`;
- `.research/TES-Reloaded-master/TESReloaded/Core/SettingManager.cpp:845-879,1170-1290`;
- `.research/TES-Reloaded-master/TESReloaded/Core/SettingManager.h:301-353`;
- `.research/TES-Reloaded-master/TESReloaded/Framework/Game.h:8754`;
- `.research/TES-Reloaded-master/TESReloaded/Core/ShaderManager.cpp`;
- `.research/TES-Reloaded-master/TESReloaded/Core/TextureManager.cpp`.

### Modern NVR source

- `.research/TESReloaded10-master/src/NewVegas/Hooks/Hooks.cpp:3-71`;
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Shadows.cpp:1-8`;
- `.research/TESReloaded10-master/src/core/ShadowManager.cpp:1-922`;
- `.research/TESReloaded10-master/src/core/ShadowManager.h:1-58`;
- `.research/TESReloaded10-master/src/core/RenderPass.cpp:77-93,245-310`;
- `.research/TESReloaded10-master/src/NewVegas/nvse/GameNi.cpp:311-313`;
- `.research/TESReloaded10-master/src/NewVegas/nvse/GameNi.h:1244-1260,2515-2532`;
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp:151-160,521-721`;
- `.research/TESReloaded10-master/src/effects/ShadowsExterior.cpp:1-690`;
- `.research/TESReloaded10-master/src/effects/ShadowsExterior.h:1-207`;
- `.research/TESReloaded10-master/src/effects/SunShadows.cpp`;
- `.research/TESReloaded10-master/src/effects/PointShadows.h`;
- `.research/TESReloaded10-master/src/effects/PointShadows2.h`;
- `.research/TESReloaded10-master/src/effects/ShadowsInteriors.cpp`;
- `.research/TESReloaded10-master/src/core/EffectRecord.cpp:4-17,351-374`;
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Shadows/`;
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Effects/` shadow files.

### Current OMV and existing research

- `omv/src/fnv_local_lights.rs:181-184,608-710,803-835,864-915,1209-1270`;
- `omv/src/effects/pbr/hooks.rs:43-75,567-704,729-833,1828-1985`;
- `omv/src/effects/pbr/shader_registry.rs:82-578,579-862,932-974`;
- `omv/src/effects/pbr.rs:854-860`;
- `omv/src/backend/fnv.rs:315-329,386-392,670-760`;
- `libpsycho/src/os/windows/memory.rs:48-78`;
- `libpsycho/src/os/windows/directx9.rs:1284-1312`;
- `libpsycho/src/os/windows/hook/inline/inlinehook.rs:20-225,475-582`;
- `docs/graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md`;
- `docs/nvr_d3d9_performance_research.md`;
- `docs/nvr_reference_contract.md`;
- `docs/graphics_fnv_volumetric_fog_lighting_plan.md:260-300`.

### Authoritative D3D9 contracts

- Microsoft [BeginScene](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-beginscene)
  and [EndScene](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-endscene)
  document pairing, invalid nesting, and the potential cost of multiple pairs.
- Microsoft [SetRenderTarget](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-setrendertarget)
  documents viewport reset and render-target/depth compatibility constraints.
- Microsoft [StretchRect](https://learn.microsoft.com/en-us/windows/win32/api/d3d9helper/nf-d3d9helper-idirect3ddevice9-stretchrect)
  documents multisample downsampling through a distinct same-size
  single-sample render target and the driver-dependent texture-surface path.
- Microsoft [CheckDeviceMultiSampleType](https://learn.microsoft.com/en-us/windows/win32/api/d3d9helper/nf-d3d9helper-idirect3d9-checkdevicemultisampletype)
  documents that render-target and depth formats must both support the chosen
  sample type. OMV proves the live pair by transactional creation and returns
  to the established native path if either 4x creation fails; it does not
  silently reduce generation coverage.
- Microsoft [GetDepthStencilSurface](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-getdepthstencilsurface)
  documents AddRef ownership and the required release.
- Microsoft [Lost Devices](https://learn.microsoft.com/en-us/windows/win32/direct3d9/lost-devices)
  documents that all `D3DPOOL_DEFAULT` resources must be released before
  `Reset` can succeed.

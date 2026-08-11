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

OMV now owns one user-facing **Shadows** effect with three schema-one working
configuration values:

```toml
[graphics.native_shadows]
enabled = true
exterior_enabled = true
interior_enabled = true
```

`enabled` is the effect master. The other two values independently admit
exterior/behave-like-exterior cascades and interior point shadows. The global
`graphics.screen_space_shaders` switch masks runtime admission without changing
the persisted values. Shadows are not preset-owned, no existing serialized
field changed position or type, `CONFIG_SCHEMA_VERSION` remains 1, and the
built-in preset payload/version is unchanged.

The implemented scene-shadow scope is the modern NVR consumer graph that has an
OMV scene-color consumer: exterior directional/EVSM shadows, exterior
screen-space contact shadows, and interior point-light cube shadows. Modern
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

| Owner | Responsibility |
|---|---|
| `omv/src/effects/shadows/contract.rs` | pointer-free settings, cadence, selection, caster, EVSM, compositor, transaction, and memory reference contracts |
| `omv/src/effects/shadows/engine.rs` | executable identity, hook/tail addresses, native layouts, draw entries, and register ABI |
| `omv/src/effects/shadows/native.rs` | bounded current-scene, cell/root, geometry-list, and stable point-light discovery |
| `omv/src/effects/shadows/math.rs` | allocation-free row-vector cascade, cube, frustum, and camera-relative transform math |
| `omv/src/effects/shadows/render.rs` | native geometry classification, traversal, register upload, and original-renderer submission |
| `omv/src/effects/shadows/pipeline.rs` | complete device-generation resources, producer transaction, immutable epoch publication, and scene-pre consumer |
| `omv/src/effects/shadows/shaders.rs` | complete process-owned shader bytecode catalog prepared after `DeferredInit` |
| `omv/src/effects/shadows/mod.rs` | atomic runtime settings, route admission, common-entry decision, try-lock ownership, and reset boundary |
| `omv/src/fnv_local_lights.rs` | thiscall bridge at `0x00871290` and the exclusive prefix/replacement-tail choice |
| `omv/src/startup.rs` | post-`DeferredInit` route and hook ordering |
| `omv/src/runtime.rs` | configuration updates, menu, and pre-screen-stack composition |
| `omv/src/hooks.rs` | reset ordering and bypass submission through original geometry trampolines |
| `libpsycho/src/os/windows/directx9.rs` | safe D3D9 cube, surface, state, raw-buffer, and scene wrappers |

The crate-visible public boundary is intentionally small. `NativeShadowsSettings`
is the immutable runtime setting value; `configure_runtime_options` is an
atomic-only pre-deferred operation; `install` owns deferred route publication;
`handle_common_entry` returns the only legal native continuation;
`apply_scene_pre` consumes a same-epoch publication; and
`reset_runtime_state` releases every default-pool resource before native device
recreation. Each unsafe public entry documents the native lifetime required of
its pointers.

### Hook, epoch, and startup ordering

The existing receiver-preserving naked bridge remains the sole owner of the
common entry. For every invocation it selects exactly one path:

1. call the complete native prefix, which includes the native tail;
2. run the complete OMV producer, then call `0x00871A50` once; or
3. when the location is disabled or the same main epoch is already published,
   call only `0x00871A50`.

Unknown callers, unavailable bytecode, a busy producer, an invalid engine
owner, a missing camera/device, incomplete resource creation, or any D3D error
selects the native prefix. A replacement never calls both prefix and tail.
Special and screenshot invocations rebuild their transient maps but do not
advance main gameplay cadence or publish scene-pre input; their completion
invalidates shared gameplay maps so the next main view fully recovers.

During `NVSEPlugin_Load`, OMV only copies shadow settings into one atomic byte.
It does not first-touch the pipeline `LazyLock`, validate an engine pointer,
compile a shadow shader, create a D3D resource, or open the route. At
`DeferredInit`, startup validates process-static globals, initializes the
pipeline owner, starts serialized CPU shader preparation, opens the passive
route, and only then makes the already-proven common hook resident. Until the
entire shader family is ready, enabled locations continue through native
shadows. An explicitly disabled interior/exterior location needs no resource
and takes the tail-only path immediately after deferred route admission, so a
toggle cannot transiently re-enable native generation during preparation.

Scene-pre composition runs before the ordinary screen-effect runtime lock and
stack, so later effects receive already-shadowed color. Renderer recreation
first releases existing runtime resources, then the shadow resource family,
then PBR/sky resources, and enters the native recreate only when every owner is
quiescent.

### Exterior quality contract

The exterior and behave-like-exterior branch fixes quality at modern NVR's
custom/highest supplied settings:

- four practical-split cascades, lambda `0.9`, covering 6000 world units;
- one 4096-by-4096 `A16B16G16R16F` EVSM4 atlas with four 2048 quadrants;
- a reusable 2048 `A16B16G16R16F` 4x-MSAA generation target and matching
  `D24S8` depth target;
- exact FP16-safe EVSM exponents `5.54` and `5.0`, a finite far-moment clear,
  alpha cutout at `0.5`, and a distinct-source five-tap separable prefilter;
- texel-stabilized cascade projections and consumer matrix rebasing for cached
  camera motion;
- near-map refresh every main frame, middle every two, far every three, and LOD
  every four stable main frames; any material scene, sun, or frustum change
  rebuilds all four;
- projection comparison that ignores subpixel TAA lens shifts but accumulates
  real FOV/lens changes against the last material signature;
- NVR's one-degree yaw and quarter-degree pitch sun quantization, with a
  one-tenth blend for changes no larger than five degrees; the stabilized
  direction is shared by every cascade and the contact-shadow consumer so
  cadence cannot create cross-cascade light-direction seams;
- four screen-space contact-depth comparisons over NVR's 2000-unit ray model,
  deterministic interleaved noise, intensity-two visibility, and two
  depth-aware full-resolution filter passes;
- exterior darkness `0.75`, matching the supplied NVR default.

The reusable MSAA workspace preserves per-cascade sample count and final atlas
resolution while avoiding NVR's 4096 4x-MSAA color/depth allocation. It also
prevents the same-subresource blur feedback present in the source snapshot.
Atlas sampling clamps each local UV to its own half-texel inset, so linear
filtering cannot bleed across quadrants.

### Interior quality contract

The interior branch produces twelve cube-shadowed lights and retains twelve
additional tracked lights without cube comparisons. All twelve cubes are
sampled, rather than repeating NVR's eleven-shadowed-plus-one-fallback defect:

- stable distance plus native-identity ordering retains equal-distance lights;
- a cube candidate displaced by a nearer thirteenth light competes for the
  tracked fallback set, preserving crowded-room illumination without adding a
  cube render; non-casting native lights enter that same stable bounded set;
- lights must be live, point, nonambient, visible/nonblack, in front of the
  camera or contain it, and satisfy `distance + radius < 8000`;
- influence radius uses the supplied NVR `1.5` multiplier;
- twelve 512-face `R32F` cube maps share one matching `D24S8` depth surface;
- all six D3D faces use the NVR coordinate flip and 90-degree view convention;
- alpha cutout is `0.2`, and the normalized radial-depth receiver bias is
  NVR's `0.018`;
- the native per-light geometry list is borrowed only inside the common-entry
  lifetime; a bounded current-cell traversal is the documented fallback;
- a full-resolution FP16 normal reconstruction chooses the shorter 3D neighbor
  on each axis, avoiding rotated-camera discontinuity errors;
- two additive six-cube passes plus at most two sampler-free fallback passes
  accumulate local-light energy, and the interior composite maps that energy
  from the supplied NVR darkness floor `1 - 0.65` to full light.

OMV observes the engine cast-shadow bit rather than repeating modern NVR's
forced-true bug. First-person player geometry remains excluded and third-person
geometry remains eligible. SpeedTree is intentionally excluded only from the
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

Ordinary and strip geometry are submitted through the original OMV trampolines
for `0x00E745A0` and `0x00E74840`, bypassing PBR/sky detours while the dedicated
shadow shaders are bound. Skinned partitions use `0x00E6D310`; bone constants
remain in `c9..c62`. SpeedTree blocks remain in `c63..c139`, and their two
scalar globals plus 16 wind rows are read as separate proven blocks rather than
as one invented contiguous span. Terrain LOD owns `c140..c145`.

### Transaction, publication, and failure behavior

Producer work uses one successful `BeginScene`/`EndScene` pair. A failed
`BeginScene` is never followed by `EndScene`. Before writes, publication is
invalidated. OMV captures all active render targets and depth, plus a
`D3DSBT_ALL` state block covering viewport, shaders, declaration/FVF, streams,
indices, textures, samplers, and render states. Auxiliary MRTs are detached;
every target transition reinstalls its required viewport and compatible depth
surface. CPU scheduler/signature changes are staged locally and committed only
after `EndScene` and complete attachment/state restoration succeed.

The scene-pre consumer is try-lock-only and accepts only the current render
epoch on the same device. It captures/restores the same state boundary, copies
scene color to a distinct texture before writing the source surface, and never
samples a bound render-target subresource. Any failure removes the publication;
the next common entry either retries OMV or safely executes native shadows.
Resource creation is all-or-nothing per device generation. Reset drops atlas,
workspace, blur, cube, depth, consumer, shader, and state-block COM owners as a
single family.

At 1920 by 1080 the conservative fixed-family estimate is 478,822,400 bytes
(about 456.6 MiB), including the atlas, shared MSAA color/depth, blur target,
twelve cubes, cube depth, point/contact target, normal/contact scratch, and
scene-color copy. NVR's 4096 4x-MSAA atlas color/depth topology alone has a
896 MiB lower bound before cubes and full-resolution resources. OMV therefore
preserves map/sample/filter quality while removing roughly half a GiB of peak
directional residency and most repeated distant traversal.

### Test and acceptance evidence

Deterministic tests cover:

- executable identity, hook prologue/returns/tail, calling convention, native
  layouts, draw entries, and every shader register range;
- independent configuration admission and exact prefix-versus-tail counts;
- main/special/screenshot cadence and invalidation;
- practical splits, texel stabilization, cached-matrix rebasing, cube axes,
  world-to-view sun conversion, and TAA-jitter projection tolerance;
- equal-distance selection, radius/front/distance admission, point-sphere
  culling, caster rejection, cube-overflow demotion into the twelve-light
  fallback set, and no forced cast flag;
- CPU EVSM4 and exterior/interior compositor reference behavior;
- quality/memory topology, distinct blur identities, complete state classes,
  and scene-pair balance;
- compilation of all eleven SM3 shader variants with static instruction
  budgets and source contracts for complex geometry, alpha thresholds,
  derivative-free normals/contact work, depth-aware filtering, all twelve
  cubes, exact far clear, and atlas edge isolation;
- strict schema-one config default/save/round-trip behavior, no preset payload
  ownership, pre-deferred atomic-only configuration, deferred hook order,
  scene-pre order, and reset order.

The required static gates are the focused shadow/config/startup tests, the full
`cargo test --target i686-pc-windows-gnu -p omv`, the explicit supported
release build, formatting, `git diff --check`, and final diff inspection.

On 2026-08-12, all 32 focused shadow tests passed, the complete OMV suite
passed 519 tests with no failures, and
`cargo build --release --target i686-pc-windows-gnu -p omv` completed without
warnings. Formatting and diff checks also passed. These results prove the
static and supported-build gates only.

Runtime acceptance remains intentionally unproven here. A later playtest should
cover ordinary exterior/interior and behave-like-exterior cells; sunrise,
night, time jumps, zoom, TAA, first/third person; actors, alpha foliage,
SpeedTree, terrain/LOD, multibounds; zero/one/twelve/equal-distance point
lights; special and screenshot rendering; menu toggles; alt-tab, resolution
change, and device recreation; and cold load-to-gameplay with
BaseObjectSwapper. Visual acceptance requires stable, correctly oriented
contact/cascade/cube shadows with no atlas seams, stale publication, light
leaks, acne, peter-panning, state corruption, or lower quality than the
supplied NVR custom configuration. Performance acceptance requires per-stage
CPU/GPU attribution and stable resource residency on Proton/DXVK and the
affected NVIDIA path.

### Evidence classification for the implementation

**Proven by executable/static artifacts:** the common hook/tail topology,
receiver ABI, branch continuations, manager/native layouts used here, geometry
submission entries, and executable hash.

**Proven by NVR source:** quality defaults, shader equations/registers,
selection limits, consumer topology, alpha thresholds, radius/distance/bias,
contact-shadow model, and the defects explicitly rejected above.

**Proven by OMV code/tests/build:** deterministic policy/math, shader
compilation/budgets, configuration shape, source order, D3D ownership topology,
and supported-target compilation.

**Reasoned but awaiting runtime observation:** that the static engine owners
remain live in every modded render context, that raw/native renderer cache
interaction is visually transparent after complete restore, exact visual
parity or improvement, driver performance/residency, and startup compatibility
with the accepted BaseObjectSwapper baseline.

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
- Microsoft [GetDepthStencilSurface](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-getdepthstencilsurface)
  documents AddRef ownership and the required release.
- Microsoft [Lost Devices](https://learn.microsoft.com/en-us/windows/win32/direct3d9/lost-devices)
  documents that all `D3DPOOL_DEFAULT` resources must be released before
  `Reset` can succeed.

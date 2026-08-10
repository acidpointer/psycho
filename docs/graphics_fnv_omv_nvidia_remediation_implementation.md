# OMV NVIDIA Render-Path Remediation Implementation

## Status

This document is the durable implementation contract for
`graphics_fnv_omv_nvidia_1fps_remediation_plan.md`. The source-proven defects
and high-frequency work described below are corrected in the associated OMV
change. The supported i686 test and release-build gates are recorded here when
they complete.

This is not yet a runtime claim that the NVIDIA one-FPS report is fixed. That
claim requires the controlled affected-machine matrix in the plan. Static
proof establishes where OMV now intervenes, which work was removed, and which
state/copy boundaries remain necessary; it cannot identify a proprietary
driver stall by itself.

The governing executable remains FalloutNV.exe 1.4.0.525, PE32 x86, preferred
base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Exact addresses, byte signatures, frame chains, and ABIs in this document
apply to that executable. A mismatched entry fails the dependent feature group
closed instead of being overwritten.

## Purpose and user-visible behavior

The implementation removes OMV work that was multiplied by exterior PBR and
native-shadow rendering while preserving shader equations, resolution, family
coverage, sampler requirements, depth coverage, native effect order, and
vanilla fallback. In particular:

- OMV no longer treats `NiD3DShader::SetupGeometry @ 0x00E812F0` as a draw;
- PBR and native sky admission run at actual renderer geometry submissions;
- `SetTexture` observation replaces production texture getters;
- device discovery is replaced by a lifecycle-published identity and
  generation;
- native-shadow capture uses the correct receiver ABI, one gameplay context,
  one scalar traversal per required epoch, bulk matrix copies, and retained
  texture ownership;
- close-terrain light reconstruction has a complete generation-keyed bounded
  cache;
- package ownership moves from a per-frame forced write to the native package
  transition;
- related hooks are prepared before publication, rolled back as groups, and
  remain resident behind passive runtime gates;
- equal-description color copies use exact unfiltered `StretchRect` semantics,
  while semantically different pre-alpha and post-world versions remain
  separate.

If a target, sampler, device generation, resource, or producer epoch is not
proven current, only the dependent replacement falls back to native behavior.
The implementation does not reduce supported rendering to obtain speed.

## Evidence classification

### Proven by the executable and repository code

- `0x00E745A0` and `0x00E74840` are the `NiDX9Renderer` TriShape and TriStrips
  renderer entries containing the eventual native primitive submissions.
- `0x00E812F0` performs shared geometry/resource setup and is not a primitive
  owner.
- `0x00871290` is a receiver-bearing thiscall with no stack arguments.
- its direct branch continuations are `0x00870856`, `0x00870A79`, and
  `0x00870C41`;
- the caller frame above those branches returns to the normal renderer at
  `0x00870249` or `0x008702AE`, special rendering at `0x008721A9`, or screenshot
  rendering at `0x00879179`;
- `0x00B9F780` is the completed native local-shadow helper and returns before
  OMV observes its slot;
- `0x00B4F710` is the six-argument cdecl `SetShaderPackage` transition;
- the shader package globals are mutable engine data, while the lifetime
  branch at `0x00B575AA` is executable code patched once at DeferredInit;
- the PBR object, LandLOD, TerrainFade, close-terrain, and selector-7 DepthMap
  table identities are disjoint under their complete table/pass contracts;
- OMV's pre-alpha atmosphere copy and screen runtime's post-world copy cross
  native alpha/world barriers and therefore are not the same semantic color
  version.

The code evidence is in the modules named below. Static engine evidence and
the two-NVR comparison remain indexed by:

- `graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md`;
- `graphics_fnv_nvr_shadows_engine_contract.md`;
- `nvr_reference_contract.md`;
- `nvr_d3d9_performance_research.md`;
- `graphics_fnv_driver_owned_d3d_nvidia_depth.md`.

### Reasoned inference

The most likely cause of the vendor cliff remains a combined CPU/driver-facing
cost: false draw ownership, native-shadow-adjacent pointer validation and COM
traffic, repeated sampler/state readback, repeated light reconstruction, and
fragmented state/copy dependencies. Correcting these defects removes the known
multipliers, but static source cannot prove which D3D call caused an NVIDIA
wait.

### Runtime evidence still required

No affected NVIDIA run, AMD control, reset/alt-tab sequence, or visual capture
has been performed for this implementation in the repository environment.
The acceptance matrix at the end of this document remains mandatory before a
release can state that the one-FPS defect is closed.

## Module ownership

| Module | Technical ownership |
|---|---|
| `startup.rs` | Staged configuration, initial device publication, DeferredInit ordering, and retryable top-level install gate |
| `hooks.rs` | DisplayScene, Recreate, TriShape, and TriStrips resident hook transaction; render epoch; draw scope |
| `fnv_render.rs` | Resident image-space, underwater, world, pre-alpha, and first-person scene-stage hook transaction |
| `backend/fnv.rs` | Balanced device owner, lock-free device identity/generation, semantic depth cache, and FNV camera contract |
| `graphics_diagnostics.rs` | Compile-time-gated fixed atomic counters and sampled QPC intervals |
| `effects/pbr/hooks.rs` | SetShaders selection, shared SetTexture observation, wrapper overrides, geometry admission, and fallback |
| `effects/pbr/engine_contracts.rs` | Eye/fog flags, transactional shader-package lifetime/transition, and engine wrapper/pass state |
| `effects/pbr/samplers.rs` | Fixed 16-stage known/null/identity mirror and semantic texture generation |
| `effects/pbr/terrain_lights.rs` | Native/property/manager light merge and generation-keyed fixed cache |
| `effects/pbr/device_resources.rs` | Replacement resources keyed by device identity and generation |
| `effects/sky.rs` | Sky constant selection and getter-free geometry admission using the shared texture mirror |
| `fnv_local_lights.rs` | Exact shadow ABI bridge, caller-context policy, scalar publication, completed-shadow retention, and reset drain |
| `render_state.rs` | Named state capture/apply attribution, attachment restoration, alias removal, and exact color copies |
| `fnv_world_pipeline.rs` | Pre-alpha/coherent-world atmosphere and TAA transactions |
| `runtime.rs` | Scene-pre, scene-post, and final image-space transactions and post-world color ownership |
| `libpsycho/.../directx9.rs` | Narrow reusable owned `Device9` COM reference and render-thread borrow |

The detailed module-level contracts are also stated in `//!` documentation at
the top of the new or materially changed hot-path owners. Public and
crate-visible APIs introduced by this change document lifetime, safety,
generation, and failure semantics at their definitions.

## Startup and hook publication

### Ordering

`NVSEPlugin_Load` still stages settings and may begin CPU-only embedded PBR
preparation. It does not inspect engine objects, create D3D resources, publish
the world pipeline, or install render hooks.

At xNVSE `DeferredInit`, `startup::install_deferred_hooks_once` performs this
order:

1. publish a balanced reference to the renderer's initial device;
2. select and initialize the depth provider;
3. make the first focused world-pipeline configuration publication;
4. prepare PBR and shared sampler observation;
5. prepare native sky;
6. install the core renderer lifecycle/geometry group;
7. install scalar light and optional completed-shadow capture;
8. install the resident scene-stage group.

The top-level gate is retryable after a failed attempt and publishes complete
only after every required step succeeds. A startup failure abandons the active
depth provider so already-resident callbacks cannot produce an uncoordinated
snapshot. The first-person motion-blur extension additionally keeps only its
new route admission closed until DeferredInit and closes that admission after
a failed attempt. Existing scene-input and process-owned preparation contracts
are unchanged.

### Exact entry manifests

| Entry | Address | ABI | Verified leading bytes | Role |
|---|---:|---|---|---|
| DisplayScene | `0x00E75000` | thiscall `(renderer) -> u8` | `55 8B E9 80 BD` | presentation service and epoch seal |
| Recreate | `0x00E73EB0` | thiscall `(renderer,u32,u32) -> u32` | `83 EC 38 56 57` | device-resource release/reset/republish |
| RenderTriShape | `0x00E745A0` | thiscall `(renderer,geometry)` | `83 EC 18 56 8B F1` | actual TriShape submission scope |
| RenderTriStrips | `0x00E74840` | thiscall `(renderer,geometry)` | `83 EC 20 55 8B E9` | actual TriStrips submission scope |
| ProcessImageSpaceShaders | `0x00B55AC0` | cdecl, three pointers | `8B 54 24 04 56` | native image-space order |
| SetWaterShaderUnderwater | `0x004E2120` | thiscall `(owner,u8)` | `55 8B EC 51 89` | underwater metadata |
| RenderWorldSceneGraph | `0x00873200` | thiscall, exact five-argument declaration in source | `55 8B EC 6A FF` | world transaction |
| RenderFirstPerson | `0x00875110` | thiscall, exact five-pointer declaration in source | `55 8B EC 6A FF` | first-person depth stage |
| RenderPreDepthGroups | `0x00B65AE0` | cdecl `(owner)` | `56 8B 74 24 08` | pre-alpha stage |
| common shadow transaction | `0x00871290` | thiscall `(receiver)` | `55 8B EC 81 EC 9C 00 00 00` | native prefix and scalar producer epoch |
| completed local shadow | `0x00B9F780` | thiscall `(light,accumulator,slot)` | `55 8B EC 83 E4 F0` | post-native resource retention |
| SetShaderPackage | `0x00B4F710` | cdecl `(i32,i32,u8,i32,char*,i32)` | `8B 4C 24 04 8B 54 24 08 56` | semantic package transition |

PBR `SetShaders`, shared `SetTexture`, optional shader creation, and sky update
hooks retain their existing exact prologue manifests. Arbitrary `E9` targets
are no longer followed. A container already prepared by OMV can be re-enabled;
an unrecognized external owner is a conflict and the dependent feature fails
closed. This deliberately avoids claiming ABI or lifetime compatibility from
the shape of one jump instruction.

Core and scene groups prepare every trampoline before enabling the first new
member. An enable failure rolls back members enabled by that attempt in reverse
order. Readiness is published only after all mandatory members are active.
Runtime settings no longer reconcile, attach, or detach depth-stage entries.

The package lifetime opcode and `SetShaderPackage` hook use one
`ModificationTransaction`. Failure of either restores the other before
gameplay. `service_frame` refreshes only the established eye-position data
contract; it does not patch code, enable hooks, call `VirtualProtect`, or force
the package globals every frame.

## D3D9 device lifecycle

The engine remains the device owner. OMV keeps one balanced `Device9` COM
reference behind the lifecycle mutex and publishes two atomic values. Changed
publication and Recreate clearing use `try_lock`; a busy owner rejects the
lifecycle transition instead of waiting in a renderer callback:

- the current non-owning `IDirect3DDevice9*` used by serialized callbacks;
- a nonzero generation incremented whenever publication is cleared or a new
  ownership interval is established.

Publishing the same device pointer in DisplayScene is one atomic comparison
and does not acquire a lock or a second reference. Draw, sky, PBR, light, and
depth paths never rediscover the device through the renderer singleton.

Recreate performs the following sequence:

1. acquire the existing nonblocking OMV resource owners;
2. restore/release PBR, sky, atmosphere, depth, and retained native shadows;
3. clear the fast pointer and drop OMV's balanced device reference;
4. call the native Recreate trampoline with the exact return ABI;
5. on native success, retain and publish the renderer's current device;
6. let default-pool effect resources recreate lazily for the new generation.

Resource stores and publications include the generation in addition to raw
pointer identity. This rejects pointer reuse across reset and same-object reset
intervals. PBR and native-sky shader creation poll compiler publications and
resource owners with `try_lock`; contention defers creation to a later
DisplayScene. Their Recreate release paths also use `try_lock`; contention
rejects the native reset attempt before any still-owned resource is
invalidated. Reset clears slots in place and does not allocate a replacement
resource table on the renderer callback.

## PBR and native-sky draw contract

### Selection and submission

`BSShader::SetShaders @ 0x00BE1F90` remains the engine's cache authority. OMV
temporarily exposes replacement handles through the exact engine wrapper
fields only while the predecessor runs. The predecessor updates
`NiDX9RenderState` and D3D; the wrapper fields are restored immediately, while
the selected native/replacement identities remain in a fixed process-static
atomic selection publication.

The TriShape/TriStrips renderer entry then receives the actual geometry after
native SetShaders and SetupGeometry. Immediately before the predecessor:

- PBR validates the selected family, exact sampler mask, geometry-dependent
  data, device/resource generations, and final constants;
- native sky validates its exact pending family and required observed stages;
- a rejected replacement binds its exact native pair for that geometry;
- an admitted replacement avoids shader getters and redundant raw flips.

After the renderer function returns, draw-local fallback state is restored.
Close terrain is re-armed per renderer geometry because one SetShaders setup
can cover more than one geometry. A renderer function may submit multiple
primitives for that geometry; the geometry, samplers, shader pair, and
constant block remain common to those primitives.

`0x00E812F0` has no production hook, before/after callback, or state machine.
Static tests reject reintroduction of the obsolete address as a draw owner.

### Native DepthMap fast path

Selector 7 uses group-C vertex rows 92..95 and group-B pixel rows 90..91.
Those exact rows are detected before object/terrain admission. OMV publishes
no pending replacement, calls native SetShaders, and performs no pointer-record
clear or D3D resource work. Static tests prove that close terrain row 100/92
and object rows are not accepted as native DepthMap.

### Shared texture-stage observation

`NiDX9RenderState::SetTexture @ 0x00E88A20` is a shared resident observer for
PBR and native sky, including when PBR starts disabled. It records only the
fixed first 16 stages as:

- unknown;
- known null;
- known non-null identity.

The global texture generation changes only on an unknown-to-known or identity
change, not on an equal repeated SetTexture call. The hot observer performs no
pointer validation, D3D getter, COM reference operation, lock, allocation, or
log. Detailed selector telemetry remains separately gated.

Unknown and null required stages both produce exact vanilla fallback. No
production PBR or sky admission calls `GetTexture`, `GetVertexShader`, or
`GetPixelShader`. Reset makes every stage unknown so a new device must be
repopulated by native SetTexture traffic before replacement resumes.

## Native shadow and scene-light contract

### Exact ABI bridge

The common entry takes its receiver in ECX and no stack arguments. The naked
x86 bridge records, in order, caller EBP, the direct return at `[ESP]`, and ECX,
then calls a cdecl Rust body. It removes exactly 12 bytes of bridge arguments
and returns with the native stack unchanged. The original trampoline is typed
as thiscall and receives the preserved receiver exactly once.

i686 type-level tests bind the common shadow, completed-shadow,
SetShaderPackage, DisplayScene, Recreate, TriShape, and TriStrips detours to
their declared function pointer types.

### Context and epoch policy

At the common entry, EBP belongs to the selected dispatcher branch. The saved
EBP points to the dispatcher frame; its saved return classifies ownership:

| Direct continuation | Variant | Dispatcher caller return | Context | Publication policy |
|---:|---|---:|---|---|
| `0x00870856` | A | `0x00870249` / `0x008702AE` | main | authoritative candidate |
| `0x00870A79` | B | `0x00870249` / `0x008702AE` | main | authoritative candidate |
| `0x00870C41` | C | `0x00870249` / `0x008702AE` | main | authoritative candidate |
| any known variant | A/B/C | `0x008721A9` | special | native pass-through only |
| any known variant | A/B/C | `0x00879179` | screenshot | native pass-through only |
| unknown | unknown | unknown | unknown | native pass-through only |

Only the first known main invocation for a render epoch and device generation
may publish. Repeated main invocations and every special/screenshot invocation
still execute the complete native prefix but cannot replace gameplay data.

### Scalar manager publication

Consumer demand is separated:

- atmosphere requests ranked scalar lights and optional shadow enrichment;
- close terrain requests scalar manager lights only;
- completed shadow slots are not retained for a terrain-only request.

The authoritative callback uses the exact same-thread manager/list lifetime as
the engine. It reads the manager once, traverses at most 512 nodes, copies
scalar values, and deterministically ranks into fixed arrays. It performs no
device discovery and no `VirtualQuery` for the manager, list nodes, light
records, or camera. A special fast camera API is unsafe by contract and is
callable only inside this proven main world-render lifetime.

Terrain publication is a fixed 64-light atomic POD seqlock. Odd versions mean
a producer is writing; equal even versions before and after the copy prove a
coherent snapshot. Geometry consumers never take the atmosphere resource
mailbox lock and never rescan the manager. A busy or stale generation returns
no manager supplement rather than waiting.

### Completed native shadows

The native helper runs first. For one accepted slot OMV then:

1. validates the complete `ShadowSceneLight` record once;
2. bulk-copies the three contiguous 4-by-4 matrices and rejects nonfinite data;
3. validates each pointer-bearing texture-chain object once;
4. reads the texture description once and verifies 1024x1024, default-pool,
   render-target, one-level R32F or A8R8G8B8 ownership;
5. obtains one balanced owned `Texture9` reference;
6. publishes the base-texture identity, format, matrices, native light
   identity, device identity, and device generation together.

The atmosphere consumer binds the already-retained base texture. It does not
walk the engine chain, validate it again, query the description again, or own
the intrusive `BSRenderedTexture` reference count. Epoch replacement and
Recreate drop the COM owner exactly once.

If another shadow provider replaces the common prefix, the exact entry-byte
preflight rejects OMV's native completed-slot enrichment. OMV does not inspect
slots whose native producer was bypassed.

## Close-terrain light cache

One fixed atomic cache entry stores the complete supplemental-light result.
The key contains:

- render epoch;
- device generation;
- texture-stage generation;
- scalar manager publication generation;
- geometry identity;
- lighting-property identity;
- selector identity;
- native render-pass identity;
- a fast native-light membership signature;
- the exact ordered native-light count and bounded identity set;
- native point-light count.

Pointer identity by itself is never treated as a generation. A cache miss runs
the complete native/property/manager merge and preserves the 24-light capacity,
identity deduplication, multibound test, light scale, LOD dimmer, HDR rule, and
native black-color rule. The 32-bit signature is only a fast rejection test;
exact identity comparison rejects a theoretical hash collision as a miss. A
concurrent odd publication is also only a miss; neither case can drop lights
or block the render callback.

The key stores at most 25 native identities; the payload contains 24
supplement identities plus the packed two-float4 shader rows and count. An
even/odd atomic publication prevents a Rust data race even if the serialized
engine contract is unexpectedly violated. Constants are uploaded at the final
renderer geometry boundary because native geometry setup may overwrite them
between engine batches; expensive reconstruction is generation cached
independently from this required upload.

## D3D state and attachment footprint

The current safe endpoint retains one complete `D3DSBT_ALL` owner per actual
semantic transaction. It does not replace a complete restore with a guessed
partial snapshot. All applicability and resource checks that can be performed
without D3D mutation occur before capture.

| Transaction | Entry/exit phase | Attachments | Raw state used by OMV | Restoration/cache rule |
|---|---|---|---|---|
| pre-alpha atmosphere | before native alpha groups / before returning to native | captures RT0..RT3 and depth; atmosphere intermediates may replace RT0 | shaders, textures/samplers, constants, declaration/FVF, streams/indices, render states, viewport/scissor | restore attachments first, then apply the one complete state block |
| coherent-world TAA | after native world, before first person | captures current world RT/depth and TAA output | full-screen shader pair, texture stages, constants, raster/depth/blend state, viewport | restore attachments first, then complete state block |
| post-world AO | after world, before first person | captures completed world target and current depth | AO pipeline shaders, targets, textures, constants, raster state | one runtime transaction; restore attachments before state |
| scene-pre | native image-space pre phase | captures up to four MRTs and depth | admitted phase chain, ping-pong color, shaders, samplers, constants, geometry/raster state | one phase transaction and first-error restore |
| scene-post | after native image-space barrier | same bounded attachment set | admitted post chain and ping-pong resources | one phase transaction and first-error restore |
| final image space | final OMV/native output phase | same bounded attachment set | final color, AA, loose effects, shader/sampler/raster state | one phase transaction and first-error restore |
| PBR/sky geometry | actual native renderer entry | does not replace attachments | wrapper-authoritative pair; raw shader set only for rejected-draw fallback; constants and observed textures | native SetShaders owns cache; fallback pair restored after geometry |

`RenderAttachments::restore` runs before `apply_state_block`; failure handling
keeps the first error while attempting every required restore. Target textures
are removed from every known sampler alias before becoming writable. Broad
capture/apply counts and CPU intervals are named centrally in
`render_state.rs`.

Replacing the single complete state owner for a phase remains conditional on
an affected-machine measurement proving that capture/apply is a material stall
and on a complete bounded-state proof. No unsafe partial-state optimization is
part of this change.

## Color and depth semantic versions

### Color

The existing phase graph already performs one initial color copy and bounded
ping-pong per admitted scene-pre, scene-post, or final phase. Rejected tails do
not allocate a phase copy, and the failure commit is not a steady-state
producer.

Two superficially similar world-color owners remain intentionally distinct:

- atmosphere owns pre-alpha world color at its proven pre-depth/pre-alpha
  boundary;
- screen runtime owns completed post-world color after native world/alpha work.

They differ in native contents and stage, so sharing them would remove required
alpha/world data. The implementation therefore does not create a new global
copy owner merely to merge incompatible versions. Exact equal-description
copies now use `D3DTEXF_NONE`, not point filtering, through one attributed
helper.

### Depth

The established depth producer cache remains keyed by provider, stage, source
surface, epoch, and dimensions. It continues to:

- borrow an externally published Depth Resolve world snapshot without an OMV
  physical world resolve;
- coalesce identical requests;
- preserve a coherent-world snapshot only when later native writes require
  persistence;
- create a distinct first-person-inclusive snapshot only for consumers that
  request it;
- preserve bounded native NvAPI alias/copy and RESZ routes;
- fail closed when the selected route is unavailable.

Every successful physical depth copy increments the cross-subsystem diagnostic
counter. This implementation does not lower depth resolution or remove the
first-person contract.

## Diagnostics and hot-path cost

The optional Cargo feature is `graphics-diagnostics`. Normal builds compile
the sampled counter/timing functions to inline no-ops. A diagnostic build must
also be armed by the diagnostics configuration; it samples one frame per 120
by default.

Fixed atomic counters distinguish shadow variants and main/special/screenshot
contexts, repeated publication, native slots/retention, SetShaders, SetTexture,
TriShape/TriStrips submissions, PBR/sky admission and fallback, physical
color/depth copies, state capture/apply, and package transitions. QPC spans
separate OMV shadow pre-work, native prefix, post-work, manager traversal,
texture retention, PBR/sky admission, real geometry submission, state
capture/apply, and color copies.

Callbacks never allocate, format, lock, or log for this diagnostic owner.
DisplayScene seals a fixed POD sample. A long D3D-adjacent CPU interval remains
evidence of a possible wait, not proof of GPU execution; affected-machine
testing must correlate it with coarse GPU/vendor capture evidence.

Steady production hot paths now have these intended costs:

| Path | Production cost added by OMV before feature work |
|---|---|
| unrelated SetTexture | bounded stage check and fixed atomic mirror update, then predecessor |
| equal repeated SetTexture | fixed atomic reads/store; no generation increment |
| native DepthMap SetShaders | exact table identity check, small pending invalidation, predecessor; no resource/D3D work |
| unrelated SetShaders with no prior PBR selection | one pending-kind atomic swap plus native classification/fallback |
| renderer geometry with no pending PBR/sky | atomic gates then predecessor |
| repeated same-device DisplayScene | one atomic pointer comparison |
| special/screenshot shadow entry | caller classification, native prefix, no producer scan/publication |
| repeated authoritative shadow epoch | epoch/generation check, native prefix, no second producer scan |

No routine draw/capture path introduces file I/O, shader compilation, TLS,
blocking synchronization, live vtable rewriting, or per-frame code protection
changes.

## Failure, compatibility, and invariants

- Native predecessors run exactly once whenever their hook is active.
- An unavailable original trampoline logs only through the existing bounded
  emergency path and never guesses a return convention.
- Hook readiness cannot be published for an incomplete mandatory group.
- Shared SetTexture observation may remain resident when PBR fails; it cannot
  select a PBR shader by itself and is required by independent native sky.
- Unknown texture state, stale device/resource generation, unknown shadow
  context, busy publication, or incomplete family resources keep the exact
  native draw.
- Another unrecognized entry owner is never overwritten or followed as an
  arbitrary near-jump predecessor.
- OMV does not patch a live D3D9 vtable and does not add BeginScene/EndScene at
  an engine-owned scene boundary.
- Native shadow bytes `0x00871290..0x008719F7` are not skipped. A future shadow
  producer must satisfy the separate complete NVR shadow contract before that
  rule can change.
- All retained COM references are released on publication replacement or
  Recreate. Borrowed raw pointers never become owners.
- Render callbacks use nonblocking mailboxes where resource drops require
  ownership; a busy owner defers work rather than waiting.
- `.research` remains comparison-only and no NVR source is built or patched.

## Tests and static acceptance

The implementation adds or extends tests for:

- exact x86 detour/trampoline function types;
- resident hook policy and reverse rollback ownership;
- rejection of the false SetupGeometry draw boundary and D3D vtable hooks;
- native DepthMap row exclusion;
- shared SetTexture ordering and getter-free sampler admission;
- all required terrain sampler masks and one-through-seven layer variants;
- device-generation rejection by PBR, sky, atmosphere, and terrain state;
- main/special/screenshot context classification;
- bulk 4-by-4 matrix copying and nonfinite rejection;
- scalar terrain publication coherence;
- close-terrain cache invalidation for every semantic key component;
- exact unfiltered color copies, alias unbinding, and attachment-before-state
  restoration;
- nonblocking PBR/native-sky compiler, creation, and Recreate resource paths;
- absence of runtime depth-hook reconciliation.

Required repository gates:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
cargo fmt --all
git diff --check
```

Validation completed on 2026-08-10. The supported i686 OMV suite passed all
453 tests with no failures, ignored tests, or compiler warnings. The supported
optimized i686 OMV build then completed successfully. `cargo fmt --all` and
`git diff --check` completed cleanly. These gates prove source integration and
the static contracts above; they do not replace the affected-machine runtime
acceptance matrix.

## Runtime acceptance still required

Use the exact controlled matrix in the remediation plan. At minimum preserve:

- same save, exterior camera, weather/time, resolution, AA, mod list, warm-up,
  driver, and configuration;
- OMV absent, resident pass-through, PBR family splits, shadow scalar-only,
  completed-shadow-only, full stack, and PBR-disabled controls;
- affected NVIDIA, AMD control, and supported Proton/DXVK runs;
- at least 300 warm gameplay frames per sample;
- median, p95, p99, worst non-transition frame, and consecutive frames over
  100 ms;
- diagnostic attribution for native shadow prefix versus OMV work, real
  geometry admission/submission, state capture/apply, and physical copies;
- visual coverage for object PBR, LandLOD, TerrainFade, close terrain 1..7
  layers and 0/6/12/24 lights, canopy, sky, atmosphere/local shadows, TAA/AO,
  first person, menus, screenshots, reset, and resolution change.

Do not call the source change a completed NVIDIA fix if the affected-machine
run is absent or still shows the multi-fold vendor cliff. If it remains, use
the named diagnostic intervals to isolate the longest remaining driver-facing
transaction before changing quality, coverage, or shader code.

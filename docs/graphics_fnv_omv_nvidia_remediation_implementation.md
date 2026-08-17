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

### 2026-08-17 Sky/PBR hot-path candidate

The current unaccepted candidate removes additional CPU work from the native
Sky and PBR paths without changing HLSL, intended family coverage, hook
ownership, or normal-build diagnostics:

- the PBR master gate is one published atomic read instead of a complete
  logical bytecode-catalog scan followed by the global resource gate; object
  and terrain families retain independent readiness and failure gates;
- renderer submissions with no pending PBR family return before the readiness
  gate, and required-sampler admission visits only stages present in the
  required mask;
- PPLighting wrapper-table lookup caches only a hit whose current table slot
  still contains the same wrapper. Absence is not cached because the package
  selector does not own wrapper-table mutation;
- object selection publishes the already-proven pixel template with the
  wrapper/handle transaction, so the synchronous geometry callback does not
  repeat shader-record and replacement-handle discovery;
- object classification consumes the selector supplied by the synchronous
  native callback only after proving the PPLighting wrapper pair. Invalid
  selector/list state is a distinct unavailable result and preserves vanilla;
- object and Sky classification use direct bounded reads only while their
  native predecessor owns the referenced selector/pass objects. Fixed ranges
  are checked at installation and detailed diagnostics retains checked global
  discovery;
- native Sky validates its fixed selector arrays and engine global slots once
  when preparing the live `UpdateConstants` slot, instead of issuing virtual
  memory queries for them at every sky draw;
- scene-light capture remains dormant until close-terrain bytecode, resources,
  hooks, and the functional terrain contract are all ready. Demand is updated
  only on configuration, contract, draw-boundary, resource, or reset changes;
- successful resource preparation becomes terminal for the current D3D
  generation, so warm presentation no longer scans the 162-slot catalog;
- pending object and Sky ownership includes the D3D device generation; reset
  or recreate cannot consume raw shader handles from an earlier generation;
- unchanged supplemental light payloads still avoid serialization and a D3D
  discard lock. New attribution distinguishes terrain-cache reuse, light-list
  scans, payload reuse/uploads, sampler queries/mutations, and actual native
  Sky shader transitions.

Native sampler research rejected a broader cache shortcut. FNV
`NiDX9RenderState::SetSamplerState @ 0x00E910A0` tracks only sampler state types
1, 2, 5, 6, and 7 through TypeMap `0x0126F92C`; it does not track
`D3DSAMP_SRGBTEXTURE`. ENB, NVR, or another owner may also write the device
directly. Supplemental s14 therefore continues to capture the three physical
D3D values and restore them after the draw. Replacing those queries requires a
complete mod-agnostic direct-write observation contract, not an engine-cache
assumption.

No Sky or PBR HLSL equation is changed by this candidate. Shader lowering is
measurement-gated: the affected NVIDIA trace must first show that GPU shader
work, rather than selector CPU work, D3D state transitions, or light-payload
traffic, owns the residual stall. Any later HLSL change requires a shipped
shader behavior test that rejects the measured defect.

Radare2 closure of the cache lifecycle rejected an earlier negative-cache
assumption. Both hooked callers at `0x004DB187` and `0x004DCB9D` invoke
`SetShaderPackage @ 0x00B4F710`, which updates package-selection globals but
does not mutate the five PPLighting wrapper tables. The table-clearing owners
at `0x00B79DE0` and `0x00B7A170` are separate lifecycle routines. A missing
wrapper therefore cannot be cached against a `SetShaderPackage` generation;
only a positive entry whose live slot is revalidated is retained.

### 2026-08-14 mod-agnostic ownership update

The current source supersedes the original entry-hook ownership described by
older paragraphs in this document. OMV no longer owns `DisplayScene`, the
shared scene callees, `SetShaders`, `SetTexture`, shader-creation functions,
`SkyShader::UpdateConstants`, `SetShaderPackage`, or the completed-shadow
callee entry. Current production ownership is:

- xNVSE `OnFramePresent` for final service/epoch completion;
- exact `E8 rel32` callers for Recreate, scene phases, package transitions,
  the three shadow variants, and completed-shadow observation;
- live engine-owned vtable slots for renderer geometry, render-state texture
  observation, PPLighting selection, and SkyShader constants;
- no `CreateVertexShader` or `CreatePixelShader` interception;
- a functional terrain shader/resource probe instead of provider filenames;
- independent capability publication and a diagnostic-only predecessor matrix.

Each route captures and invokes the target present when OMV installs. A
changed instruction or slot is not overwritten, a multi-member group publishes
nothing until all members commit, and a later owner is not overwritten during
rollback. The complete design, address inventory, dependency graph, and open
runtime gates are authoritative in
[`graphics_fnv_omv_dependency_compatibility_plan.md`](graphics_fnv_omv_dependency_compatibility_plan.md).

The later AMD/NVIDIA comparison and failed split-array compiler experiment led
to one additional shader-lowering correction. OMV now stores supplemental
close-terrain light records in a draw-scoped 32x2 RGBA32F texture instead of a
dynamically selected constant array. Its exact ABI, state transaction,
bytecode evidence, and remaining runtime gates are documented in
`graphics_fnv_omv_nvidia_close_terrain_shader_fix_implementation.md`. That
document supersedes this implementation's earlier supplemental constant-layout
description but preserves all hook, lifecycle, quality, and acceptance
boundaries here.

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
| `hooks.rs` | xNVSE presentation service, unique Recreate caller, live renderer geometry slots, render epoch, and draw scope |
| `fnv_render.rs` | Independent direct-caller groups for image-space, underwater, world, pre-alpha, and first-person stages |
| `backend/fnv.rs` | Balanced device owner, lock-free device identity/generation, semantic depth cache, and FNV camera contract |
| `graphics_diagnostics.rs` | Compile-time-gated fixed atomic counters and sampled QPC intervals |
| `effects/pbr/hooks.rs` | Live PPLighting-selection and render-state texture slots, first-use wrapper adoption, geometry admission, and fallback |
| `effects/pbr/engine_contracts.rs` | Eye/fog flags, two-caller transactional shader-package lifetime/transition, functional terrain probe, and engine wrapper/pass state |
| `effects/pbr/samplers.rs` | Fixed 16-stage known/null/identity mirror and semantic texture generation |
| `effects/pbr/terrain_lights.rs` | Native/property/manager light merge and generation-keyed fixed cache |
| `effects/pbr/device_resources.rs` | Replacement shaders and supplemental light-data texture keyed by device identity and generation |
| `effects/sky.rs` | Live SkyShader constants slot and getter-free geometry admission using the shared texture mirror |
| `fnv_local_lights.rs` | Three exact shadow-caller ABI bridges, scalar observation, exclusive native-replacement admission, completed-shadow caller, retention, and reset drain |
| `interop.rs` | Read-only capability/dependency snapshot, one DeferredInit matrix log, and diagnostic predecessor-owner formatting |
| `render_state.rs` | Named state capture/apply attribution, attachment restoration, alias removal, and exact color copies |
| `fnv_world_pipeline.rs` | Pre-alpha/coherent-world atmosphere and TAA transactions |
| `runtime.rs` | Scene-pre, scene-post, and final image-space transactions and post-world color ownership |
| `libpsycho/.../directx9.rs` | Narrow reusable D3D owners, including the dynamic RGBA32F discard-upload texture |

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

### Exact interception manifest

| Capability | Ownership cell(s) | ABI | Role |
|---|---|---|---|
| Presentation | xNVSE `OnFramePresent` | message payload points to unaligned `i32 loadingScreen` | final service and epoch seal |
| Recreate | caller `0x004DC41F` | thiscall `(renderer,u32,u32) -> u32` | release/reset/republish |
| Geometry | live renderer vtable `+0x1B4`, `+0x1B8` | thiscall `(renderer,geometry)` | TriShape/TriStrips submission scope |
| Image space | caller `0x00876136` | cdecl, three pointers | native image-space order |
| Water | callers `0x004E1D7C`, `0x004E1DB1`, `0x008728AE` | thiscall `(owner,u8)` | underwater metadata |
| World | callers `0x00870AE8`, `0x00870E18` | thiscall, exact five-argument declaration in source | world transaction |
| First person | callers `0x0087093D`, `0x00870B21`, `0x00870F74` | thiscall, exact five-pointer declaration in source | first-person depth stage |
| Pre-alpha | callers `0x00B6653D`, `0x00B665A6` | cdecl `(owner)` | opaque-world consumer stage |
| PBR selection | live selector-index-4 vtable `+0xF4` | thiscall `(selector,u32)` | PPLighting selection only |
| Texture mirror | live render-state vtable `+0xDC` | thiscall `(state,u32,texture)` | PBR/sky texture observation |
| Shader package | callers `0x004DB187`, `0x004DCB9D` | cdecl `(i32,i32,u8,i32,char*,i32)` | startup/reload transitions |
| Sky constants | live selector-index-10 vtable `+0x7C` | thiscall `(selector,property)` | sky classification/constants |
| Shadow transaction | callers `0x00870851`, `0x00870A74`, `0x00870C3C` | thiscall receiver in `ECX`, caller frame in `EBP` | variant-specific scalar observation/native replacement |
| Completed local shadow | caller `0x00B5B9DC` | thiscall `(light,accumulator,slot)` | post-native resource retention |

Every direct route requires an exact five-byte `E8 rel32` and captures its
current target; every pointer route compare-exchanges the current live slot.
Neither primitive follows arbitrary jumps or assumes a vanilla predecessor.
Changed ownership blocks only the dependent group. Multi-member groups
preflight all cells, roll back in reverse order, and publish readiness only
after commit. Runtime settings never attach, detach, or transfer these routes.

The package callers and lifetime opcode share one `ModificationTransaction`.
Failure restores everything before gameplay. `service_frame` refreshes only
the established eye-position data contract; it does not patch code, enable
hooks, call `VirtualProtect`, or force package globals every frame.

## D3D9 device lifecycle

The engine remains the device owner. OMV keeps one balanced `Device9` COM
reference behind the lifecycle mutex and publishes two atomic values. Changed
publication and Recreate clearing use `try_lock`; a busy owner rejects the
lifecycle transition instead of waiting in a renderer callback:

- the current non-owning `IDirect3DDevice9*` used by serialized callbacks;
- a nonzero generation incremented whenever publication is cleared or a new
  ownership interval is established.

`OnFramePresent` republishes the singleton device only if the lifecycle owner
has no published pointer; the normal frame performs no renderer/device query.
Draw, sky, PBR, light, and depth paths use the published identity rather than
rediscovering the device through the renderer singleton.

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
presentation callback. Their Recreate release paths also use `try_lock`; contention
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

The common shadow implementation takes its receiver in `ECX` and no stack
arguments. Three naked x86 callsite wrappers statically encode the main,
special, or screenshot variant, preserve caller `EBP` and `ECX`, and dispatch
to one cdecl Rust body. Each wrapper invokes the predecessor captured at its
own callsite exactly once. This removes return-address inference for the
variant while preserving caller-frame classification needed by the established
main/special/screenshot policy.

i686 type-level tests bind the three shadow callers, completed-shadow caller,
two package callers, Recreate caller, renderer slots, and all scene caller
wrappers to their declared function-pointer types.

### Context and epoch policy

At each direct caller, `EBP` belongs to the selected dispatcher branch. The
wrapper itself proves the variant; the saved frame return still classifies
main versus special/screenshot ownership:

| Caller | Variant | Dispatcher caller return | Context | Publication policy |
|---:|---|---:|---|---|
| `0x00870851` | A | `0x00870249` / `0x008702AE` | main | authoritative candidate |
| `0x00870A74` | B | `0x00870249` / `0x008702AE` | main | authoritative candidate |
| `0x00870C3C` | C | `0x00870249` / `0x008702AE` | main | authoritative candidate |
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

If another shadow provider replaces the common implementation, the three
caller observers still invoke their independently captured predecessors and
may publish scalar context. Exact entry-byte validation disables only OMV's
exclusive native replacement path. The completed-shadow caller remains an
independent cooperative observer; it retains output only when the post-call
resource contract validates, so absent or foreign output naturally falls
closed without suppressing scalar lights.

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

The Sky/PBR candidate adds these attribution groups:

| Group | Fields | Interpretation |
|---|---|---|
| PBR gate | `pbr_ready_query`, `pbr_ready_entry`, `pbr_pending_none` | The first two must remain equal because readiness is one published entry; pending-none shows geometry calls rejected before that work. |
| Table lookup | `table_positive`, `table_miss`, `table_entry` | Positive hits revalidate their live slot; `table_entry` reports remaining bounded linear-scan work. |
| Pointer validation | `object_memory_query`, `sky_memory_query` | Normal hot admission should report zero; nonzero work belongs to setup or explicitly detailed diagnostics. |
| Terrain lights | `terrain_cache_hit`, `terrain_cache_miss`, `terrain_native_entry`, `terrain_property_entry`, `terrain_manager_entry`, `supplemental_lights_*` | Separates unavoidable native membership reads from full property/manager reconstruction and shows actual supplemental occupancy. |
| Supplemental D3D | `supplemental_payload_hit`, `supplemental_upload`, `supplemental_discard`, `supplemental_sampler_get`, `supplemental_sampler_set` | Identifies changed texture payloads and the exact draw-scoped D3D sampler transaction. |
| Native Sky | `sky_raw_shader`, `sky_update_constants_us` | Counts raw replacement/restoration calls and CPU time in native Sky classification/publication. |

Additional sampled intervals are `pbr_selector_us`, `pbr_object_us`,
`pbr_terrain_lights_us`, `pbr_supplemental_upload_us`, and
`pbr_supplemental_sampler_us`. `OnFramePresent` emits one `[GRAPHICS PERF]`
record for a sealed sampled frame. Formatting and logging occur only after the
frame is sealed; callbacks retain fixed atomic/QPC work in an armed attribution
build and no diagnostic work in a normal build.

Callbacks never allocate, format, lock, or log for this diagnostic owner.
`OnFramePresent` seals a fixed POD sample. A long D3D-adjacent CPU interval remains
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
| ordinary `OnFramePresent` with a published device | no renderer/device discovery |
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

The 2026-08-11 supplemental-selector follow-up passed the complete 465-test
i686 OMV suite, the optimized i686 build, and all 33 PBR shader-registry tests
through the forced native x86 Microsoft `d3dcompiler_47.dll`. Its candidate
DLL SHA-256 is
`f274016f75f400025cad9f585744039d54091a0475d94ecebfdf568de5840eff`.
These results extend the static evidence above; the affected-machine matrix
remains open.

The 2026-08-14 mod-agnostic ownership update passed all 37 explicit-target
`libpsycho` tests, all 644 explicit-target OMV tests, the optimized OMV build,
and the complete supported FNV release build. Its `omv.dll` is 12,826,970
bytes with SHA-256
`fbde3b26ca7243a6734d5821f9cbaa151cba2bc8bd2986080c8e6e388e47dc69`.
The complete PE footprint and comparison boundary are recorded in the
interoperability plan. These static results do not replace BaseObjectSwapper
cold starts, visual/reset coverage, or the NVIDIA/AMD timing matrix.

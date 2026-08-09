# OMV NVIDIA One-FPS Remediation Plan

## Status and purpose

This document is the implementation plan derived from the completed OMV/NVR
hook, D3D9, PBR, copy-graph, and native-shadow research. It does not claim that
one proprietary NVIDIA driver call has already been identified as the sole
cause. The evidence instead establishes a cluster of source-proven OMV defects
and excessive work that is entered by the historically decisive PBR toggle and
is multiplied in exterior scenes.

The plan has four required outcomes:

1. remove the catastrophic NVIDIA-specific frame-time collapse without
   disabling or narrowing any OMV feature;
2. replace OMV's false engine contracts with executable-proven hook, ABI,
   lifecycle, and render-stage ownership;
3. remove render-hot pointer discovery, redundant D3D readback/COM traffic,
   repeated light reconstruction, broad transaction fragmentation, and
   duplicate semantic copies;
4. preserve exact PBR family coverage, sampler requirements, world and
   first-person depth, atmosphere ordering, TAA history, screen-effect order,
   reset behavior, and current shader quality.

The governing executable is FalloutNV.exe 1.4.0.525, PE32 x86, preferred base
`0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Every address and ABI in this plan applies only after that executable identity
or an independently proven compatible capability has been established.

No source implementation is authorized by this document itself. Each future
implementation slice must be reviewed and validated independently. Repository
commit creation still requires a separate explicit user request for each
commit.

## Evidence basis

The plan depends on the following durable research:

- `docs/graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md` is the complete
  current OMV versus both-NVR flow comparison and root-cause ranking;
- `docs/graphics_fnv_nvr_shadows_engine_contract.md` proves the native,
  legacy-NVR, modern-NVR, and current-OMV shadow entry, prefix, tail, caller,
  resource, and consumer contracts;
- `docs/nvr_reference_contract.md` records the broader NVR startup, shader,
  terrain, effect, depth, and state contracts;
- `docs/nvr_d3d9_performance_research.md` records the healthy NVR command and
  copy workload and the distinction between correctness work and optional
  quality reductions;
- `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` records the current
  engine-owned D3D9 lifecycle and NVIDIA depth scheduling contract;
- `docs/graphics_fnv_pbr_errata.md` and
  `docs/graphics_fnv_atmosphere_startup_crash_errata.md` remain mandatory for
  PBR and world-pipeline implementation.

The user-supplied and stored runtime evidence constrains every phase:

- both supplied NVR versions are healthy on NVIDIA and other vendors;
- shader code, depth resolution, RESZ changes, live device-vtable removal, and
  the 2026-08-04 depth scheduling changes did not cure the NVIDIA report;
- a historical same-scene toggle measured about 42 FPS with PBR disabled and
  about 5.5 FPS with PBR enabled while the world effect was not ready;
- the historical full stack measured about 4.9 FPS, while master-disabled with
  depth capture active measured about 78 FPS;
- an AMD RX 7700 control did not reproduce the vendor cliff;
- a healthy NVR sample completed 49 successful copies, including 45
  full-resolution copies and about 3.21 GB of logical read/write payload at
  3440x1440.

The last item rejects a raw-copy-count theory. It does not excuse OMV's known
duplicate world-color ownership or unnecessary depth copies. Copy placement,
dependency edges, surrounding state transitions, and semantic duplication are
the optimization targets.

## Root-cause position carried into implementation

### Proven defects and excessive work

The following facts are sufficiently established to require correction even
before their individual contribution to NVIDIA frame time is ranked:

1. OMV treats `0x00E812F0` as a draw bracket. The executable proves that it is
   a shared geometry/resource method that binds buffers and contains no
   `DrawPrimitive` or `DrawIndexedPrimitive` call. It is shared by at least
   PPLighting, TallGrass, SpeedTreeLeaf, and SpeedTreeBranch.
2. `BSShader::SetShaders @ 0x00BE1F90` is the actual engine shader-binding
   authority. One call can cover multiple geometries, so it is not by itself a
   universal per-geometry boundary.
3. OMV wraps native shadow entry `0x00871290`, executes the full native prefix,
   and adds work before, inside, and after it. Modern NVR replaces the prefix
   with a complete shadow producer and calls native tail `0x00871A50` exactly
   once, so the healthy NVR measurement did not include OMV's flow.
4. OMV declares the thiscall-like `0x00871290` target as zero-argument cdecl and
   does not preserve incoming `ECX`. The current executable masks the error
   because the receiver has no observed later semantic use, but the ABI is
   still wrong.
5. An active outer OMV local-light capture performs eight source-countable
   `VirtualQuery` calls before scanning up to 512 scene-light entries.
6. One retained native shadow slot performs 64 memory queries, including 48
   scalar matrix validations, plus D3D texture inspection. A later binding
   repeats eight queries and the texture inspection. Four captured and once
   bound slots account for 296 memory queries before other OMV work.
7. PBR enablement directly enables the terrain manager scan even if only the
   PBR consumer needs it. The shadow entry is reachable from normal, special,
   and screenshot paths, and current publication has no same-epoch/context
   deduplication.
8. Every evaluated PBR family rediscovers the D3D device through checked engine
   pointer reads. A new seven-layer close-terrain geometry can issue fourteen
   `GetTexture` calls with immediate COM releases.
9. A close-terrain cache miss can inspect 25 pass-light entries, walk up to 64
   property lights, consult a 64-light manager snapshot, select 24 supplemental
   lights, and construct 3 to 51 float4 constant rows. The constants are
   uploaded on every false resource-method evaluation.
10. OMV forces two shader-package globals through memory query and temporary
    page protection every serviced PBR frame. Modern NVR owns package 7 at the
    native `SetShaderPackage` transition.
11. OMV can open several independent `D3DSBT_ALL` plus attachment transactions
    in one frame. A four-MRT screen transaction performs five attachment
    getters and up to thirteen clear/restore setters in addition to state-block
    capture/apply and effect work.
12. OMV has independent atmosphere and screen-runtime world-color owners and
    can perform approximately seven full-resolution color copies in a fully
    admitted 4K FP16 frame. Identical semantic versions are not shared.
13. Mandatory hooks can be partially enabled, PBR chaining recognizes only a
    single near jump, and depth-stage hooks can still be physically reconciled
    after startup instead of remaining resident behind passive gates.

### Best current causal model

The best defensible model is an interaction, not a single isolated call:

```text
native shadow submission
  -> OMV pre/inside/post capture and memory/D3D discovery
  -> exterior PBR selection at SetShaders
  -> false resource-method "draw" ownership
  -> sampler getters, light reconstruction, constants, shader fallback flips
  -> fragmented state/attachment transactions and copy dependencies
  -> vendor-specific CPU wait, validation, synchronization, or residency cost
```

The exact final NVIDIA mechanism remains an inference until named CPU and GPU
intervals are captured on an affected machine. Implementation must therefore
retain attribution after every slice rather than landing one opaque rewrite
and declaring success from average FPS.

## Immutable constraints and non-goals

### Feature and quality constraints

- Do not change shader equations or bytecode as the performance fix.
- Do not reduce depth, color, TAA, atmosphere, PBR, or shadow resolution.
- Do not disable close terrain, LandLOD, TerrainFade, object PBR, native sky,
  atmosphere, TAA, AO, screen shaders, or first-person coverage.
- Do not weaken family/table/pass identity gates or exact required-sampler
  masks.
- Do not replace a missing required texture with a guessed fallback.
- Do not broaden close-terrain classification or infer terrain from shader
  source names, pair identity alone, or selector identity alone.
- Preserve the one-through-seven layer and `0/6/12/24` close-terrain variants,
  exact object table identities, LandLOD/TerrainFade separation, and canopy
  companion semantics.
- Preserve the established phase order for atmosphere, TAA, AO, native image
  space, DOF, motion blur, loose effects, and final output.

### Shadow constraint

OMV does not yet implement a replacement shadow producer. This remediation
must not skip native bytes `0x00871290..0x008719F7` or call `0x00871A50`
directly. Modern NVR can do that only because it replaces the skipped native
work with its own directional, point, and spotlight shadow producers. Until a
separately authorized OMV shadow implementation satisfies the complete shadow
contract, OMV must call the native prefix exactly once with the correct
receiver.

### Lifecycle and hot-path constraints

- Never patch the live `IDirect3DDevice9` vtable.
- First world-pipeline publication and engine-hook installation remain at
  xNVSE `DeferredInit`, after staged configuration publication.
- CPU-only embedded PBR prewarming may occur earlier, but it may not touch the
  engine, D3D, hooks, or the focused world-pipeline owner.
- Runtime switches become passive atomic/data gates. They must not attach or
  detach executable hooks during normal play.
- Render callbacks must not block, allocate routinely, perform file I/O,
  compile shaders, or write logs.
- Do not introduce Rust `thread_local!`, TLS callbacks, or another lazy
  render-cache owner. Use process-static zero-initialized POD/atomic state or
  existing render-thread owners.
- Every successful D3D getter reference must remain balanced, including
  failure and reset paths.
- Keep all engine scene traversal and D3D work on the serialized render
  thread. Settings may be staged elsewhere, but only a proven render boundary
  may publish or replace render-owned state.
- Do not add `BeginScene`/`EndScene` calls at a new hook unless executable and
  runtime evidence proves that the hook is outside the engine's active scene.
- Every target change must avoid render-target/sampler feedback and restore the
  complete state it changes while keeping `NiDX9RenderState` coherent.

## Target architecture

### One startup transaction, resident entries, passive features

`startup.rs` remains the sole high-level `DeferredInit` coordinator. It will
stage settings first, preflight hook capabilities, prepare every trampoline,
and enable dependent hook groups transactionally. A group becomes published
as ready only after every mandatory entry is active. If one mandatory entry
fails, entries enabled by that attempt are rolled back before gameplay can
enter the group.

The intended groups are:

| Group | Mandatory ownership | Optional ownership | Failure result |
|---|---|---|---|
| core lifecycle | `DisplayScene`, `Recreate` | presentation diagnostics | OMV graphics unavailable |
| scene stages | image-space order, underwater metadata, world, pre-alpha, first person | provider-specific observation | world/depth consumers unavailable as one group |
| PBR replacement | `SetShaders`, `SetTexture`, every executable-proven geometry/primitive boundary needed for exact coverage | vertex/pixel creation observation | native PBR unavailable; vanilla remains intact |
| native sky replacement | executable-proven sky selection/submission boundaries | creation observation | native sky replacement unavailable |
| scene lights | correct-ABI common shadow/world boundary or a separately proven equivalent producer boundary | completed native-shadow slot capture | shadowless scalar lights remain available only when their mandatory producer is coherent |
| package lifetime | native `SetShaderPackage` boundary plus the already-proven lifetime branch | none | affected PBR families remain unavailable |

Shader creation hooks remain optional because lazy adoption can recover
already-created wrappers. `SetTexture` is no longer optional for production
PBR: an unavailable tracker must fail the PBR hook group closed rather than
fall back to per-draw `GetTexture` readback.

Entry resolution will classify each target as vanilla, explicitly recognized
compatible predecessor, already owned by OMV, or conflict. It must not blindly
follow arbitrary jump chains. Unsupported bytes or ambiguous ownership fail
the dependent group closed with one startup log. The design must preserve a
validated predecessor when safe and must never overwrite an unknown owner.

### Lifecycle-published D3D device identity

The engine renderer remains the device owner. OMV will validate and retain a
balanced device identity at a lifecycle boundary, publish a non-owning fast
render-thread pointer plus device generation, and clear publication before
`NiDX9Renderer::Recreate` releases OMV resources. After successful recreation,
the new identity is validated and published before effects can use it.

Production draw and capture code will read the already-published pointer and
generation without `VirtualQuery`, COM getters, locks, or singleton pointer
chasing. Validation is repeated only when the renderer-published identity
changes or after recreation. If the current DirectX wrapper cannot express an
owned lifecycle reference and a trusted render-thread borrow safely, add that
narrow abstraction to `libpsycho`; do not duplicate raw AddRef/Release calls in
each OMV subsystem.

### Explicit render and producer epochs

The current presentation epoch is not enough to distinguish main gameplay,
special rendering, and screenshots. The target model publishes:

- device generation;
- presentation/render epoch;
- native shadow invocation context;
- semantic world-color/depth phase;
- source target identity and description;
- producer generation for scene lights, samplers, and effect resources.

One authoritative producer invocation publishes one immutable scene-light
epoch. A special or screenshot invocation cannot silently overwrite the main
gameplay epoch. Consumer admission requires matching epoch, context, device,
and resource generation. The exact authoritative invocation policy must be
selected from Phase 1 diagnostics and executable proof, not inferred from call
order.

### Engine-owned shader selection and proven geometry submission

`BSShader::SetShaders` remains the stable shader-selection/cache boundary.
Family selection must be stable through the primitive that consumes it.
Geometry-specific sampler and light admission must occur at an
executable-proven class boundary that is reached once for each relevant
geometry before its actual primitive submission.

The final implementation depends on the caller contract found in Phase 1:

- if a class-specific per-geometry setup occurs before its native
  `SetShaders`, choose the wrapper handles there and let native `SetShaders`
  update `NiDX9RenderState` and D3D once;
- if `SetShaders` legitimately covers several geometries, use the proven late
  per-geometry boundary and cache-aware native render-state setters for the
  exceptional native/replacement transition;
- use a narrow primitive hook only when its caller, class coverage, ABI,
  constant lifetime, and restoration point are all proven.

No version may retain `0x00E812F0` as a nominal universal draw hook. No raw
shader getter/setter bracket may be substituted merely because it is easy to
place around `DrawIndexedPrimitive`.

### Observed sampler state, not device readback

The `NiDX9RenderState::SetTexture @ 0x00E88A20` detour will maintain a bounded
shadow of texture-stage identity and a monotonically increasing generation.
The detour sees the requested pointer even when native cache equality later
suppresses the device setter, so it can represent the engine state without a
`GetTexture` call.

Each required stage has `unknown`, `null`, or known-identity state. Unknown or
null required stages cause exact vanilla fallback; they never cause a hot-path
device query or guessed texture. The tracker is invalidated at device
replacement and any proven engine operation that bypasses the observed setter.
OMV-owned screen transactions either update the tracker through the same
cache-aware path or restore/invalidate it explicitly before native world
rendering resumes.

### Coherent scalar light epochs and retained native shadow resources

The world manager is scanned at most once for the authoritative context in one
render epoch, and only while a ready consumer actually needs it. PBR object,
LandLOD, or TerrainFade readiness alone must not request close-terrain manager
capture. Close-terrain manager demand becomes active only when close-terrain
resources, executable contract, settings, and draw ownership are ready.

The scalar terrain epoch is a fixed-capacity, immutable publication. Geometry
consumers do not lock or rescan the manager. Atmosphere's local-light epoch may
retain a nonblocking mailbox for owned texture resources, but it consumes it
once per world transaction rather than once per light or geometry.

For completed native shadows:

- preserve the receiver and call native `0x00B9F780` once before observing its
  result;
- validate each bounded engine record and matrix region once, then copy all
  three matrices directly;
- resolve and validate the texture chain once at the producer boundary;
- retain one balanced D3D texture identity in the published epoch;
- never reconstruct the chain at consumer binding;
- invalidate the epoch on context change, device recreation, or producer
  overwrite.

If modern NVR owns the common shadow entry, native completed-slot enrichment is
unavailable because NVR does not execute the native helper. OMV must report the
capability loss and use only an explicitly supported resource ABI if one is
introduced later. It must not inspect stale native slots.

### Semantic render graph

Every produced texture or surface is identified by a semantic version rather
than by whichever subsystem allocated it. At minimum the graph distinguishes:

- pre-alpha world color;
- coherent world color after native world rendering and before first person;
- scene-pre input/output;
- scene-post input/output;
- final image-space input/output;
- coherent world depth;
- first-person-inclusive depth;
- TAA input, current resolve, and previous history.

The key includes device generation, render epoch, phase, source-target
identity, dimensions, format, and MSAA state. Two consumers share a physical
copy only when this complete semantic key matches. In particular, atmosphere
and screen-runtime world color must not be merged if one requires pre-alpha
contents and the other requires post-world-alpha contents.

Each semantic version has one producer. Consumers borrow the version and do
not recapture it. Each actual native phase owns at most one OMV attachment/state
transaction. Applicable effects are completely preflighted before the first
copy or draw. A safety commit remains available after an unexpected mid-chain
failure, but its steady-state count must be zero.

### State and attachment ownership

The first state rewrite consolidates compatible work under one transaction
while retaining a single complete state block where completeness is not yet
proven. It does not replace several safe all-state blocks with several guessed
partial snapshots.

For each consolidated transaction, document:

- exact entry and exit engine phase;
- source and destination attachments;
- every render, sampler, texture-stage, shader, declaration/FVF, stream,
  index, viewport, scissor, and constant state changed;
- which state is represented by `NiDX9RenderState` and how cache coherence is
  restored;
- all failure exits and the first-error rule;
- all sampler/target aliases that must be unbound before a write.

Only after that inventory and affected-machine timing may a single broad state
block be replaced with an explicit bounded snapshot. If the bounded set cannot
be proven complete, the accepted end state is one shared all-state owner for
that semantic transaction, not an unsafe partial restore.

## Implementation phases

Each phase ends with focused tests, an affected-machine measurement, a diff
inspection, and an updated evidence table. Do not combine phases before the
preceding attribution gate is satisfied; otherwise the project can recover FPS
without learning which defect caused it and can later regress unknowingly.

## Phase 0: diagnostic baseline and controlled A/B harness

### Changes

Add a compile-time-gated cross-subsystem diagnostic owner, expected in a small
new module such as `omv/src/graphics_diagnostics.rs`. Normal release builds
must compile out sampled timers and diagnostic A/B branches. Existing always
useful cumulative status counters may remain, but draw-level timing must not
execute unless the diagnostic feature is built and explicitly armed.

Use fixed-size atomics/POD storage and sampled `QueryPerformanceCounter`
intervals. Do not allocate, format strings, or log from a draw, shadow, scene,
or presentation callback. `DisplayScene` may atomically seal one frame sample;
diagnostic UI or an explicit non-hot export action may read completed samples.
GPU attribution uses coarse D3D timestamp queries or a vendor capture around
whole transactions, not a generic live-device vtable observer.

Record per presentation:

- `0x00871290` entries by direct caller `0x00870851`, `0x00870A74`, and
  `0x00870C3C`, plus normal/special/screenshot context;
- pure native-prefix time, OMV pre/post work, manager scan, publication, and
  repeated same-epoch attempts;
- `0x00B9F780` calls, accepted slots, exact validation counts, D3D texture
  inspection calls, and later bindings;
- `SetShaders`, `SetTexture`, and `0x00E812F0` visits classified by shader
  family/class;
- actual relevant primitive submissions once Phase 1 has proved their entries
  (the diagnostic substrate is added in Phase 0 and the address-specific
  counters are activated after that proof);
- PBR admissions/fallbacks and raw or cache-aware shader pair transitions by
  object, LandLOD, TerrainFade, and close terrain;
- device discoveries, memory queries, texture/shader/attachment getters,
  successful owned COM references, and releases;
- pass/property/manager light entries inspected, cache hits/misses, selected
  lights, constructed rows, and constant setter calls;
- shader-package changes and attempted writes;
- state capture/apply, attachment get/detach/restore, and target changes by
  named transaction;
- every color/depth copy by semantic producer, dimensions, format, MSAA, and
  source/destination identity;
- resource creation/release, device generation, target-description changes,
  and failed creation retry.

Sample CPU time separately for the blocks listed above, including state
capture versus apply, attachment capture versus restore, constant construction
versus `SetPixelShaderConstantF`, and each copy call. A long CPU interval around
a D3D call is a possible driver wait, not proof of GPU execution; correlate it
with a coarse GPU interval or vendor capture.

The controlled matrix must include the following deployment baselines and
startup-only diagnostic profiles. The first entry is an external baseline;
the remaining isolation choices are read before hook publication:

1. OMV DLL absent;
2. OMV present with no optional visual hook groups installed;
3. resident hook groups in direct pass-through mode;
4. common shadow hook as a correct-ABI pure trampoline;
5. outer scalar scene-light capture only;
6. completed native-shadow capture only;
7. both light paths;
8. PBR split into object, LandLOD, TerrainFade, and close terrain;
9. sky, atmosphere, TAA, screen stack, and full stack separately;
10. current versus later transaction/copy planners during their respective
    phases.

These switches are diagnostic isolation tools, not shipping fixes. They are
read once before hook publication and cannot cause live entry patching.

### Baseline protocol

Use the same save, camera, weather, time, resolution, AA, mod list, warm-up,
driver, and configuration for every run. Capture at least 300 warm gameplay
frames and preserve frame-time distributions, counters, and named timings.
Run on the affected NVIDIA environment, an AMD control, and the supported
Proton/DXVK path. Add native Windows/NVIDIA when it differs from the reporter's
environment or D3D9 translation path.

### Exit gate

- The historical PBR on/off cliff is reproduced or a current affected scene
  with equivalent catastrophic timing is captured.
- A no-OMV, no-optional-hook, resident-pass-through, and full-stack baseline
  exists.
- Diagnostic overhead is measured with sampling armed/disarmed and is not
  mistaken for the bug.
- The longest CPU/GPU intervals can be attributed to named owners even if the
  final NVIDIA mechanism remains unknown.

## Phase 1: close the remaining executable contracts

This is mandatory before choosing new hook addresses. Use the radare2 MCP as
the primary interface while available and update durable engine documentation
with binary identity, addresses, xrefs, ABI, lifetime, and caller chains.

### PBR and sky submission contract

Starting from `BSShader::SetShaders @ 0x00BE1F90`, the current draw dispatcher
around `0x00B994F0`, its observed `0x00B98E80` callee, every relevant shader
vtable, and `0x00E812F0`, prove for each supported family:

- selector/pass setup and whether it runs per pass, geometry, or batch;
- where current geometry/property/pass globals become valid and are cleared;
- all calls that can overwrite vertex/pixel constants after selection;
- the final PPLighting object, LandLOD, TerrainFade, close-terrain, and sky
  primitive call;
- whether one setup can issue several primitives or several geometries;
- exact thiscall/fastcall/cdecl receiver and stack ABI;
- the earliest complete sampler/light admission point;
- the last safe constant upload point;
- the point at which native/replacement identity may change again.

The output must explicitly reject or approve each candidate hook. A function
is not accepted merely because it is close to a DIP in one caller.

### Native shadow/light contract closure

Extend the existing shadow contract only where needed to prove:

- a low-overhead way to classify all three dispatcher variants and
  normal/special/screenshot context;
- the authoritative invocation for gameplay light publication;
- the manager list/header/node/light lifetime during the chosen scan;
- whether a post-prefix caller boundary can own scalar publication without
  surrounding the native D3D shadow transaction;
- whether completed native texture contents remain stable until the atmosphere
  consumer for every accepted context.

### Package and render-state contract closure

Prove the native `SetShaderPackage` address, ABI, callers, reload behavior, and
the writable lifetime of current/max package globals. Prove the
`NiDX9RenderState` shader/texture/cache setters and any invalidation method
needed by a late per-geometry transition. Inventory native attachment and
viewport state at each OMV world/image-space boundary before removing getters.

### Exit gate

- Every proposed production hook has a proven function, caller coverage, ABI,
  lifetime, and intervention point.
- The plan selects one documented replacement strategy for each PBR/sky
  family from the target-architecture decision above.
- No unresolved constant writer can occur between OMV upload and primitive.
- The scene-light context and same-epoch publication policy is explicit.
- Raw research stays in its established analysis location and the derived
  contract is indexed under `docs/`.

## Phase 2: transactional hook and device-lifecycle foundation

### Changes

In `omv/src/startup.rs`, `omv/src/hooks.rs`, `omv/src/fnv_render.rs`, and the
PBR/sky hook owners:

- introduce one preflight/prepare/enable/rollback coordinator for each
  dependent hook group;
- verify target identity and predecessor ownership before any group entry is
  enabled;
- publish readiness only after the group is complete;
- make every render entry resident after `DeferredInit`;
- replace physical depth-stage reconciliation with passive consumer gates;
- preserve optional shader-creation observation and lazy adoption;
- make conflict reporting one-time and capability-specific.

Correct `fnv_local_lights.rs` so the common shadow detour captures incoming
`ECX` through a fastcall-compatible thunk and calls a thiscall-compatible
trampoline with the exact receiver. Preserve the native prefix exactly once.

In `backend/fnv.rs` and `hooks.rs`, add lifecycle-owned device publication:

- validate/acquire once after renderer readiness;
- expose an allocation-free render-thread fast path;
- clear it before OMV resource release at `Recreate`;
- reacquire only after successful recreation;
- attach a generation to every device-keyed resource and publication.

Move package 7 ownership from `engine_contracts::service_frame` to the proven
native `SetShaderPackage` detour. Apply the lifetime opcode patch once during
the hook transaction. Write current/max only when the semantic package
transition requires it; do not call `VirtualQuery` or change page protection
per frame.

### Tests

- Pure hook-manifest tests cover success, mandatory-member failure, rollback,
  retry, already-owned entries, recognized predecessor, and unknown conflict.
- Source/target-specific tests prove that runtime settings cannot call hook
  enable/disable methods.
- An i686 type-level ABI test binds every detour/trampoline to its declared
  x86 function type.
- Device-generation tests cover install, same-device reuse, failed recreate,
  successful same-object reset, replacement device, and stale consumer
  rejection.
- Package tests cover initial package selection, engine reload, already-7
  state, unexpected bytes, and zero frame-service writes.

### Measurement and exit gate

- Physical hook transitions after `DeferredInit` are zero.
- A pass-through build is within the release baseline budget and has no partial
  readiness state.
- Production render paths perform zero checked device discovery calls.
- Package writes and page-protection calls are zero in steady frames.
- Reset/alt-tab/resolution changes do not expose stale device generations.

## Phase 3: rebuild native shadow-boundary light capture

### Outer scene-light flow

In `omv/src/fnv_local_lights.rs`:

- use the Phase 1 context classification and select one authoritative gameplay
  publication per render epoch;
- make all other contexts pass through or publish to explicitly separate
  context slots;
- remove pre/post device lookup and use the lifecycle-published device;
- separate scalar terrain demand from atmosphere shadow demand;
- request the manager scan only when a ready consumer needs the exact epoch;
- scan the bounded manager once, copy scalar values into fixed storage, and
  publish one immutable generation;
- reject impossible count/list/header state before traversal;
- use the proven same-render-thread list lifetime or native iterator contract
  rather than issuing `VirtualQuery` per entry;
- prevent same-epoch special/screenshot replacement of main gameplay data.

If Phase 1 proves a post-prefix semantic boundary that supplies the same
manager/camera lifetime, move scalar capture there so a terrain-only consumer
does not need pre-original state at `0x00871290`. If not, retain the correct-ABI
resident wrapper but keep its pre-original work to a few atomic gates before
calling native.

### Completed native-shadow flow

Replace scalar-by-scalar validation and repeated chain resolution with one
producer capture:

- validate the whole `ShadowSceneLight` record and each referenced native
  record once;
- bulk-copy the three 4-by-4 matrices;
- validate and inspect the D3D texture once;
- hold one balanced owned texture reference in the local-light epoch;
- copy format, dimensions, matrix, fade, and light identity into the same
  publication;
- bind the already-retained texture directly at consumption;
- release all retained resources on epoch replacement and before `Recreate`.

Do not perform completed-slot capture when only close-terrain scalar lights are
needed. Do not expose native shadow enrichment when another shadow replacement
owner bypasses the native helper.

### Tests

- Context/epoch tests cover all three direct callers, repeated main calls,
  special render, screenshot, device change, and presentation rollover.
- Capture-demand tests prove object-only PBR, unready close terrain, disabled
  atmosphere shadows, and disabled features do no manager/slot work.
- Bulk matrix tests preserve all 48 values and reject truncated/nonfinite
  records.
- Texture lifetime tests balance producer retention, publication replacement,
  failed consumer, reset, and device mismatch.
- Bounded list tests cover zero, maximum, corrupt count, null header, equal
  score, and deterministic ordering.

### Measurement and exit gate

- One authoritative manager scan occurs per required gameplay epoch.
- Same-epoch publication replacement is zero.
- Outer capture has zero `VirtualQuery` and zero D3D getters in steady state.
- One accepted completed shadow performs no scalar memory queries and at most
  one producer-side D3D texture inspection; consumer inspection is zero.
- The pure trampoline, scalar-only, shadow-only, and combined A/B timings show
  the exact recovered CPU/GPU time on NVIDIA and the AMD control.
- Native shadow visuals and vanilla behavior are unchanged because the prefix
  still executes exactly once.

## Phase 4: replace false PBR and sky draw ownership

### Hook replacement

In `omv/src/hooks.rs`, `omv/src/effects/pbr/hooks.rs`, and
`omv/src/effects/sky.rs`:

- remove `COMMON_SHADER_DRAW_ADDR = 0x00E812F0` and its before/after state
  machine from production;
- install only the Phase 1 proven class-specific boundaries;
- keep pass/family selection at the native `SetShaders` authority;
- make geometry-specific admission occur exactly once before the consuming
  primitive;
- keep replacement identity stable until that primitive completes;
- use cache-aware native setters or a proven wrapper-selection path so
  `NiDX9RenderState` and D3D agree;
- eliminate raw native/replacement restore cycles caused solely by the false
  resource-method scope;
- retain vanilla fallback for exact per-geometry sampler/material rejection.

Validate shader wrappers, handle slots, vtables, and replacement records at
creation/adoption or device-resource publication. The production `SetShaders`
and per-geometry paths consume those retained records under the proven
render-thread lifetime; they do not rediscover stable wrapper fields with
`VirtualQuery`.

The global `SetShaders` detour must have a minimal unrelated-pass path. Native
DepthMap selector 7, unsupported shader classes, and table/pass pairs outside
all OMV families call the predecessor without clearing a large pending state
record or performing device/resource work. Diagnostic counters must still
prove zero PBR admission for native DepthMap vertex C[92..95]/pixel B[90..91].

The new contract must cover object PBR, LandLOD, TerrainFade, every close
terrain row, canopy companions, and the supported sky families. It must not
interpose grass/SpeedTree resource setup unless those classes have a separately
supported replacement and a proven boundary.

### Sampler and shader state

Make `SetTexture` tracking mandatory and use its stage generation for
admission. Remove `missing_sampler_mask`, `missing_sampler_mask_from_bits`, and
all shader/texture getter fallbacks from production draw evaluation. Unknown or
missing required stages select vanilla without a D3D query.

The `SetTexture` tracker must likewise remain bounded: update only the fixed
stage identity/generation state needed by admitted families, then call the
predecessor. It must add no pointer validation, getter, lock, allocation, or
diagnostic work in a normal build, including when the native setter later
detects an equal cached texture.

Replace global pending atomics that represent an imaginary resource-method
scope with a small explicit render-thread selection record keyed by pass,
family, geometry generation, sampler generation, and replacement resource
generation. The storage must be process-static, zero initialized, and free of
TLS, locks, and allocation.

### Constants

Upload constants only at the Phase 1 proven final writer boundary. Combine
contiguous rows into the minimum correct number of D3D calls. Skip an unchanged
block only if executable proof shows that no native owner overwrites it between
draws; otherwise preserve one upload per real primitive rather than the
current one upload per false resource visit.

### Tests

- Family matrices exercise every accepted and rejected table/pass combination.
- Sampler tracker tests cover cached equal sets, null, recovery, unknown after
  reset, irrelevant stages, and all one-through-seven-layer masks.
- Selection tests cover one `SetShaders` followed by multiple geometries,
  multiple primitives for one geometry, native fallback followed by valid
  replacement, and family changes without stale state.
- State-cache tests assert that wrapper, `NiDX9RenderState`, and raw D3D
  identities agree before and after every admitted/fallback path.
- Static contract tests reject `0x00E812F0` as a draw address and reject
  production `GetTexture`, `GetVertexShader`, and `GetPixelShader` admission.
- Existing shader compilation, reference, register-budget, and family-coverage
  tests remain unchanged and passing.

### Measurement and exit gate

- `0x00E812F0` has zero OMV production visits.
- Production PBR/sky admission has zero device discovery, shader getters, and
  texture getters.
- Raw shader flips that are not required by a real rejected primitive are
  zero.
- Constant uploads equal proven consuming primitives, not shared resource
  visits.
- The PBR family split identifies how much of the NVIDIA cliff was removed by
  boundary/state correction without any visual coverage loss.

## Phase 5: eliminate repeated close-terrain reconstruction

### Changes

In `omv/src/effects/pbr/terrain_lights.rs`, `fnv_local_lights.rs`, and the new
draw owner:

- consume the already-published scalar manager epoch without a mutex or
  manager traversal per geometry;
- compute the native pass-light identity/signature once at the proven
  geometry setup point;
- cache the merged result by render epoch, device generation, geometry,
  lighting property, selector/pass/material generation, native-light
  signature, and manager-light generation;
- use a fixed-capacity direct-mapped or bounded associative process-static
  cache with deterministic replacement, atomic/POD publication, and no TLS or
  allocation;
- retain exact duplicate removal, multibound behavior, native capacity, light
  scale, LOD dimmer, fade, HDR, and black-color semantics;
- separate expensive membership/transform construction from the final
  contiguous constant upload;
- invalidate through explicit producer generations rather than every
  `SetShaders` call.

Cache size is selected from Phase 0 geometry working-set data and must have a
hard static bound. A miss always recomputes the correct result; it never drops
lights to meet a performance budget.

### Tests and exit gate

- Pure cache-key tests reject stale reuse across every key component.
- Collision, wraparound, reset, pointer reuse, manager change, and pass-light
  change tests preserve exact results.
- Golden CPU tests compare uncached and cached light selection/constant rows
  for zero through 24 supplemental lights.
- Manager traversal is one per required world epoch; property/pass traversal is
  one per cache miss; repeat primitives for an unchanged key perform neither.
- Constant row construction is one per key generation, while the final D3D
  upload follows only the proven overwrite rule from Phase 4.
- NVIDIA timing separates CPU reconstruction improvement from driver constant
  setter time.

## Phase 6: consolidate D3D9 state and attachment transactions

### Inventory first

Create a durable per-effect state-footprint table from current code. Include
render states, sampler states, textures, shaders, constants, declaration/FVF,
streams, indices, viewport, scissor, RT0..RT3, and depth. Mark each item as
engine-cache-owned, raw-device-owned, or attachment-owned.

### Transaction changes

In `omv/src/render_state.rs`, `omv/src/fnv_world_pipeline.rs`, and
`omv/src/runtime.rs`:

- introduce named transaction owners for pre-alpha world, coherent-world/TAA,
  scene-pre, scene-post, and final image-space stages;
- decide all applicability and resource readiness before attachment/state
  capture;
- capture each required attachment once per actual transaction and release it
  once;
- group compatible OMV draws under that transaction rather than nesting or
  reopening it;
- perform target detachment and alias unbinding once in dependency order;
- restore attachments before viewport/scissor and other raster state;
- keep the first error while completing every required restore;
- repair or invalidate `NiDX9RenderState` whenever a raw OMV transition could
  make its cache disagree with the restored device.

Initially retain one `D3DSBT_ALL` owner per consolidated transaction. Then use
Phase 0 timing and the state-footprint proof to decide whether replacing it
with one explicit bounded snapshot is necessary. The bounded version is
allowed only when failure-injection tests demonstrate complete restoration.

Do not consolidate across native alpha, first-person, DOF, or image-space work
whose contents form a semantic barrier. "One transaction" means one per actual
compatible phase, not one giant transaction across the frame.

### Tests and exit gate

- A fake/recording D3D device verifies exact ordering and balance for success
  and failure at every operation.
- Every transaction restores all four possible MRTs, optional depth, viewport,
  scissor, shaders, textures, streams, indices, and changed scalar state.
- Target/sampler alias tests cover both normal and fallback world-color slots.
- Engine-cache coherence tests cover native rendering immediately after each
  transaction.
- There is at most one state capture/apply and one attachment capture/restore
  per admitted semantic transaction, with no nested ownership.
- A broad state block remains only where it is the one documented complete
  owner or measured bounded replacement is proven safe.
- NVIDIA CPU/GPU timing demonstrates whether state capture, apply, attachment
  getter, target switch, or restore contained the vendor stall.

## Phase 7: build the semantic color/depth copy graph

### Color versions

Introduce one frame-resource/version owner, expected to be shared by
`fnv_world_pipeline.rs` and `runtime.rs`, rather than giving atmosphere and the
screen runtime unrelated world-copy slots. The owner plans all consumers before
copying and publishes one resource for each exact semantic key.

- Reuse one world-color copy for atmosphere and screen consumers only when
  epoch, stage, source target, description, format, MSAA, and required contents
  match.
- Preserve distinct pre-alpha and post-world versions when alpha coverage
  differs.
- Keep one initial copy and ping-pong pair for each admitted scene-pre,
  scene-post, or final phase.
- Preflight the whole pass list so an ordinary rejected tail does not require a
  fallback commit.
- Retain a correctness commit for unexpected failure after a successful draw,
  count it, and require zero steady-state use.
- Keep TAA input and resolved output copies when simultaneous read/write rules
  require them. Remove one only after a ping-pong/direct-output proof preserves
  history, alpha, MSAA, and target lifetime.
- Keep reduced AO history separate from full-resolution color versions.

Equal-size copies use the exact unfiltered D3D9 operation unless a resolve or
format conversion has a separately proven filter requirement.

### Depth versions

In `backend/fnv.rs`, `fnv_render.rs`, and the frame-resource owner:

- prefer a proven external Depth Resolve publication without another physical
  resolve;
- publish one coherent world-depth version for every consumer at that stage;
- alias pre-alpha or immediate consumers only while the source cannot be
  overwritten;
- create a physical snapshot only when contents must survive later native
  depth writes;
- produce one first-person-inclusive version only when a consumer requires it;
- coalesce duplicate requests for the same provider/stage/epoch/target;
- preserve the current bounded RESZ/NvAPI selection and fail closed when no
  valid provider exists.

This phase optimizes all remaining repeated depth copies, but success is judged
as an independent bandwidth/dependency improvement rather than retroactively
calling depth the sole root cause.

### Static budgets and tests

For one render epoch:

- at most one physical copy exists per semantic color/depth version;
- atmosphere/runtime duplicate copies are zero when their full keys match;
- phase-initial color copies are at most one per admitted native phase;
- steady fallback commits are zero;
- TAA performs no more than its proven input/output requirement;
- external borrowed depth performs zero redundant physical world resolves;
- the selected provider performs at most one coherent-world snapshot and one
  first-person snapshot when distinct persistent contents are required.

Planner tests cover matching and differing stage, target, dimensions, format,
MSAA, epoch, and device generation. Failure tests ensure an invalid publication
cannot be consumed and a write destination is never simultaneously sampled.

### Measurement and exit gate

- Counters match the static budgets in every controlled configuration.
- Logical bytes and GPU time are reported by semantic owner, not as one copy
  total.
- Atmosphere, first-person exclusion, TAA alpha/history, and screen sampler
  inputs are visually and numerically unchanged.
- No copy removal depends on lower quality, narrower feature coverage, or an
  unsafe resource alias.

## Phase 8: lifecycle, failure, compatibility, and cleanup

### Reset and resource ownership

Audit every default-pool texture, surface, state object, query, shader, and
retained native-shadow reference. On `Recreate`:

1. close active publications and reject new consumers;
2. release OMV default-pool and retained native resources;
3. clear device/sampler/light/copy/state generations;
4. call native `Recreate` with its exact ABI and return value;
5. publish the resulting device only after success;
6. recreate lazily at the next proven render boundary.

Creation failure is latched per device/config generation and cannot become a
per-frame retry loop. Resolution, format, MSAA, provider, and device changes
invalidate the complete dependent resource set transactionally.

### Compatibility

- Test vanilla, Fallout Shader Loader, both supplied NVR ownership patterns,
  overlays, and the supported Proton/DXVK route.
- If another owner controls a mandatory entry, either use a documented
  compatible predecessor/capability ABI or fail only the dependent feature
  group closed.
- Never silently overwrite an existing entry jump.
- Native-shadow enrichment reports unavailable under a replacement prefix;
  scalar lights require an independently proven producer boundary.
- Startup logs report executable identity, hook-group capability, selected
  device lifecycle, and unavailable features once. Render callbacks do not log
  repeated failures.

### Diagnostic cleanup

Keep low-cost correctness counters needed by the user-facing diagnostics.
Compile out sampled timers, A/B branches, per-draw counters, and GPU query
objects from normal release builds. Add static tests proving that production
hot paths do not call the diagnostic sampler.

### Exit gate

- Repeated load, new game, save load, menu, alt-tab, resolution change, reset,
  and device replacement do not leak resources or consume stale generations.
- No routine allocation, blocking lock, file I/O, compilation, logging,
  `VirtualQuery`, or page-protection change remains in draw/capture hot paths.
- No hook group can report ready while a mandatory member is absent.
- Production behavior remains capability-based and does not depend on building
  or patching either NVR source tree.
- Default-pool resource counts and estimated bytes stabilize after warm-up;
  no unchanged device/description generation recreates a full-size target.

## Planned source ownership

The exact file set can narrow after Phase 1, but responsibility should remain
as follows:

| File/area | Planned responsibility |
|---|---|
| `omv/src/startup.rs` | staged settings, hook-group preflight/transaction order, one-time readiness publication |
| `omv/src/hooks.rs` | DisplayScene/Recreate lifecycle, device generation, proven PBR/sky geometry boundaries; remove false `0x00E812F0` ownership |
| `omv/src/fnv_render.rs` | resident native scene-stage hooks and passive requirement gates; no live reconciliation |
| `omv/src/backend/fnv.rs` | lifecycle-published device fast path and semantic depth versions |
| `omv/src/fnv_local_lights.rs` | correct shadow ABI, context/epoch policy, one scalar scan, bulk native-shadow capture, retained texture publication |
| `omv/src/effects/pbr/hooks.rs` | native pass selection, mandatory sampler tracker, proven per-geometry admission, cache-coherent fallback |
| `omv/src/effects/pbr/engine_contracts.rs` | one-time package/lifetime ownership and proven engine/cache access only |
| `omv/src/effects/pbr/terrain_lights.rs` | generation-keyed fixed light cache and constant construction |
| `omv/src/effects/pbr/device_resources.rs` | device-generation-keyed replacement resources and latched creation failure |
| `omv/src/effects/sky.rs` | proven sky boundary and getter-free/cache-coherent admission |
| `omv/src/render_state.rs` | named transaction primitives, state footprint, restore/alias invariants |
| `omv/src/fnv_world_pipeline.rs` | pre-alpha/coherent-world consumers using shared semantic resources |
| `omv/src/runtime.rs` | scene-pre/post/final phase planner and shared color consumer ownership |
| `omv/src/effects/temporal_aa.rs` | explicit TAA input/output/history version contract |
| new cross-subsystem diagnostics module | compile-time-gated counters/timers and sealed frame samples |
| new frame-resource module if separation is needed | semantic color/depth version planning shared by world and screen owners |
| `libpsycho` DirectX wrapper, only if required | narrow owned lifecycle device reference/trusted render-thread borrow abstraction |

Do not move subsystem policy into `libpsycho`; only a reusable COM/lifecycle
primitive belongs there.

## Verification strategy

### Static and unit gates after each code phase

- `cargo test --target i686-pc-windows-gnu -p omv`
- `cargo build --release --target i686-pc-windows-gnu -p omv`
- relevant formatting/lint checks without unrelated rewrites;
- `git diff --check` and final diff inspection;
- existing PBR bytecode, family coverage, sampler-mask, register-budget,
  atmosphere, TAA, phase-order, depth-provider, and reset tests;
- new pure tests for hook grouping, epochs, sampler tracking, light caching,
  frame-resource planning, state restoration, and failure injection.

Source-architecture tests should reject these production patterns in the
affected owners:

- `0x00E812F0` described or installed as a draw hook;
- zero-argument cdecl for the common shadow entry;
- device discovery or `VirtualQuery` in draw/light-capture functions;
- `GetTexture`/shader getters in PBR/sky admission;
- per-frame package forcing or page-protection changes;
- runtime hook enable/disable reconciliation;
- nested state/attachment transactions;
- more than one producer for the same semantic frame-resource key;
- routine hot-path logging, allocation, blocking lock, or TLS owner.

### Visual acceptance matrix

Capture deterministic comparisons for:

- exterior and interior;
- object PBR, LandLOD, TerrainFade, close terrain one through seven layers,
  `0/6/12/24` lights, canopy companions, missing textures, and fades;
- mixed PPLighting, grass, SpeedTree leaf/branch, actors, skin, water,
  refraction, decals, multibounds, LOD, and first person;
- native sky through weather/time transitions;
- atmosphere before required alpha coverage with and without local shadows;
- TAA history/alpha, AO, motion blur, DOF, native image-space effects, loose
  shaders, and final output;
- menus, special render, screenshots, alt-tab, reset, and resolution change.

Use stable-camera non-temporal references where exact pixels are expected and
toleranced temporal sequences where history/jitter makes exact single-frame
comparison invalid. A performance gain with a missing family, changed sampler,
broken shadow, or reordered effect fails the phase.

### Performance release gates

The controlled affected NVIDIA scene must satisfy all of these after warm-up:

1. no sustained catastrophic interval: no ten consecutive gameplay frames
   exceed 100 ms outside loading, compilation, menu transition, or reset;
2. median PBR-enabled frame time is no more than 1.5 times the same-scene
   PBR-disabled median unless a separately approved visual workload explains
   and budgets the difference;
3. resident pass-through OMV changes no-OMV median by more than 3 percent or
   p95 by more than 5 percent;
4. the normalized PBR on/off vendor cliff is absent: NVIDIA must not retain a
   multi-fold slowdown that the AMD control does not show;
5. every static hot-path and copy budget in the preceding phases is met;
6. the named before/after timings identify which changes recovered time.

Also require no statistically meaningful regression in interiors,
master-disabled behavior, the AMD control, and Proton/DXVK. Report median,
p95, p99, worst non-transition frame, and consecutive-stall count; average FPS
alone is insufficient.

If the source-proven corrections meet their static gates but NVIDIA still
fails the runtime gates, do not weaken quality or declare partial success.
Return to the Phase 0 named timings, identify the remaining longest
driver-facing interval, add one bounded diagnostic A/B, and update this plan or
the research with the new evidence before another architectural change.

## Change sequence and dependency map

| Order | Deliverable | Depends on | May proceed without affected-machine result? |
|---:|---|---|---|
| 0 | diagnostic counters, timers, and startup A/B modes | current research | implementation can be prepared; attribution gate cannot close |
| 1 | actual PBR/sky primitive and context contracts | current executable and Phase 0 correlation | static proof can proceed |
| 2 | transactional resident hooks, correct ABI, device/package lifecycle | Phase 1 target/ABI proof | yes, with static/unit validation |
| 3 | deduplicated scalar/native-shadow capture | Phase 1 context/lifetime proof and Phase 2 device generation | code can proceed; causal claim cannot close |
| 4 | proven PBR/sky ownership and sampler tracker | Phase 1 boundary proof and Phase 2 hook group | no guessed substitute allowed |
| 5 | terrain light cache and final-writer constants | Phases 3 and 4 generations/boundary | yes |
| 6 | consolidated state/attachment ownership | Phase 0 timing and state inventory | safe all-state consolidation can proceed |
| 7 | semantic color/depth graph | Phase 6 transaction boundaries | exact-key deduplication can proceed |
| 8 | lifecycle/compatibility audit and diagnostic cleanup | all prior phases | no release until runtime matrix passes |

The highest-value causal checkpoints are after Phases 3, 4, 6, and 7. Preserve
their separate measurements. If Phase 4 alone removes the NVIDIA cliff, the
remaining phases still correct proven waste and lifecycle defects, but they
must be evaluated as independent optimizations rather than credited with the
root cause.

## Completion definition

The NVIDIA one-FPS remediation is complete only when:

- the real primitive/geometry, native-shadow context, package, device, and
  render-stage contracts are documented and implemented with exact x86 ABIs;
- `0x00E812F0` is no longer treated as a draw;
- the native shadow prefix still executes exactly once in OMV-only operation;
- shadow/light and PBR/sky hot paths contain no repeated pointer discovery,
  scalar matrix validation, device state readback, or redundant COM traffic;
- close-terrain reconstruction is generation-cached without reducing lights or
  shader variants;
- hooks are installed once in complete groups and settings are passive;
- state/attachment ownership is consolidated and cache coherent;
- color and depth have one producer per exact semantic version and meet the
  documented copy budgets;
- reset and compatibility paths release and republish every resource safely;
- all static, unit, build, visual, performance, vendor, and lifecycle gates
  pass;
- the affected NVIDIA measurement demonstrates that the catastrophic frame
  time is gone and attributes the recovery to named owners;
- all remaining uncertainty or environment-specific playtest requirements are
  recorded honestly in the durable graphics documentation.

# FNV depth providers and resolve routes

## Purpose and user-visible behavior

OMV depth-aware effects need shader-readable world and first-person depth.
Fallout New Vegas renders those views into multisampled D3D9 depth surfaces,
so OMV resolves each selected surface into an `INTZ` texture before an effect
samples it.

The machine-local `graphics.depth_provider` option selects exactly one
producer for OMV:

| Setting | Physical producer | OMV inputs |
|---|---|---|
| `none` | OMV issues no resolve. An independently installed Depth Resolve DLL remains outside OMV's control. | No world or first-person depth. |
| `fallout_new_vegas` | OMV. If Depth Resolve is installed, OMV writes its shared `INTZ` target and suppresses the inactive plugin's duplicate RESZ markers. | World and first-person depth. |
| `depth_resolve` | Depth Resolve. OMV borrows the plugin's already-resolved texture and issues no depth copy. | World depth only with Depth Resolve 1.31; first-person depth is explicitly absent. |

The provider can be switched in game. A switch releases snapshots, validates
the new provider, atomically changes producer identity at the Present-owned
configuration boundary, and invalidates temporal history. It never silently
runs an OMV fallback in addition to the selected producer. Depth-provider
selection describes the local GPU/driver/mod stack and is deliberately absent
from shareable visual presets. Preset capture and activation preserve it.

### World-only provider AO composition

Depth Resolve 1.31 has no first-person depth resource. Sampling its world
texture after weapons and hands have been rendered makes those foreground
pixels inherit the background depth, so post-composed AO appears as dark lines
through first-person geometry. Treating a missing first-person texture as an
empty mask is therefore not a valid composition fallback.

OMV keeps provider ownership exclusive and changes AO timing instead:

1. the external world snapshot is published after
   `Main::RenderWorldSceneGraph`;
2. pending TAA/atmosphere work and the optional world-color capture finish on
   the currently bound completed-world target;
3. AO is composited into that same active RT0 before the world hook returns;
4. the later first-person renderer draws hands and weapons over the
   occluded world;
5. the later scene-pre-image-space transaction always suppresses AO for the
   world-only provider while retaining every non-AO pass.

This is a true provider switch: no OMV world or first-person depth resolve is
reactivated. With the OMV provider, AO retains its established later
scene-pre-image-space boundary and uses the coherent first-person texture as
an exclusion mask. If the post-world external-provider transaction is busy or its
target is unavailable, AO is skipped and temporal history is invalidated for
that frame; OMV never falls back to applying world-only AO over first-person
color.

The provider-specific route changes no AO shader equation, sample count,
target format, temporal rule, or persistent allocation. It moves the same AO
draws and scene-color copy earlier in the frame. Existing external
scene-pre-image-space shaders remain at their configured boundary, so their
ordering is not silently changed with AO.

The intervention point is statically proven for the supported
`FalloutNV.exe` identity documented below. The main callers invoke
`Main::RenderWorldSceneGraph` at `0x00870AE8` or `0x00870E18`, then invoke
`Main::RenderFirstPerson` at `0x00870B21` or `0x00870F74`.
`Main::RenderFirstPerson @ 0x00875110` does not obtain the render-target group
from its stack argument `[EBP+0x14]` until `0x008758AD`, after calling
`BSRenderedTexture::StopOffscreen` at `0x0087589A`; it activates the argument
at `0x008758B5` and submits first-person geometry at `0x0087590A`.

The first world-only AO implementation pre-bound that stack argument at the
function-entry detour. Static evidence proves only that the argument will be a
native first-person target later; it does not prove identity with the
completed world color that is active before the call. The reported broken AO
under Depth Resolve is consistent with writing AO into that wrong ownership
phase. The corrected path instead retains the device's already validated RT0
after world rendering, performs no engine-object lookup or target switch, and
returns before the native first-person call. OMV changes no callsite or engine
object and retains no raw pointer after the serialized render callback.
Evidence:
`analysis/ghidra/output/perf/graphics_fnv_stage_boundary_order_deep_audit.txt`
and
`analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`.

Within the OMV provider, the backend chooses and validates one
capability-based copy route per D3D9 device generation:

1. RESZ when the device exposes the D3D9 RESZ format;
2. NVIDIA NvAPI D3D9 depth copy when RESZ is unavailable, or when an advertised
   RESZ route operationally rejects the transaction with
   `D3DERR_NOTAVAILABLE`, and NvAPI can initialize;
3. a durable unavailable state when neither route exists.

The workbench reports the selected provider, route, physical attachment state
of the native depth-stage and RESZ hooks, and cumulative resolve/snapshot
counters. The same state is emitted every 600 Presents in the
`[FNV WORLD] Reliability` record. That record also reports the independent
native material DP/DIP lifecycle as `draw_hooks=attached`,
`prepared-detached`, or `unavailable`; it must not be confused with depth
ownership. World transaction counters are deliberately separate: they
continue advancing when OMV consumes Depth Resolve's texture and therefore do
not prove which producer copied it.
Unsupported depth fails closed: effects that require depth are rejected before
their resources or phase color copy are created. Color-only effects and native
game rendering remain usable.

## Evidence and scope

### RTX 5060 disabled baseline

The focused runtime evidence is retained in
`.reports/omv-nvidia-depth-provider-2026-07-29.txt`. Two reliability samples
span 600 Presents in 8.984 seconds, or 66.79 FPS. Across that complete interval
`pre_alpha`, `primary`, and `applied` remain exactly 525. Therefore no OMV
world, atmosphere, or TAA transaction executed during the low-FPS baseline.
This directly rejects material shaders, TAA shader cost, and the simultaneous
effect set as causes of that disabled interval.

The matching Depth Resolve log records DXVK active, RESZ active, NvAPI
inactive, and a 3440x1440 `INTZ` target. The reference implementation in
`.research/fnv-depth-resolve-main/DepthResolve/main.cpp` proves that
`FinishAccumulating_Standard_PostResolveDepth` calls `ResolveDepth` once before
water and once after water. Its RESZ implementation issues a dummy point draw
and then the `D3DRS_POINTSIZE = 0x7FA05000` marker for each call. Version 1.31
exports only pre/post effect registration; it has no producer pause,
selection, or freshness API.

These facts establish a pre-shader workload that remains active when OMV
visuals are disabled: Depth Resolve still performs two full-resolution depth
resolves per applicable world frame. Before this change, enabling OMV could add
pre-alpha, coherent-world, and first-person resolves without coordinating with
that producer. Provider selection also did not physically remove OMV's
`SetRenderState` interposition or native scene-depth entries, so the old
provider A/B was not a zero-OMV-hook control.

The cross-GPU observation is that the RTX 5060 exhibits the approximately
67-FPS floor while the RX 6800 XT does not. The evidence excludes OMV shader
work from the disabled interval and proves that external RESZ production and
OMV hook residency were both pre-shader candidates. It does not distinguish
their costs and contains no GPU timestamps that identify the NVIDIA
driver/DXVK synchronization primitive consuming the remaining frame time.
The proven root-cause boundary is therefore before shader application, not a
specific resolve or hook. The physically detached control added here is the
required causal test.

### First live provider comparison

The 2026-07-29 13:50 UTC run proves that menu changes reached the active
provider state: the log records `omv -> depth_resolve`, `depth_resolve -> omv`,
and the final `omv -> depth_resolve` transition. It is not a disabled-effects
comparison. TAA, atmosphere, AO, DOF, bloom/color grade, motion blur, native
PBR, native sky, and the external depth-aware CAS pass all initialize.

The 600-Present reliability intervals remain between approximately 53.20 and
53.53 FPS on both sides of the final switch. Before it, the OMV provider logs
both a pre-alpha atmosphere resolve and a coherent-world resolve. After it,
Depth Resolve's reference contract performs its pre-water and post-water
resolves. Equal FPS is therefore consistent with exchanging two physical
world resolves for two physical world resolves while the complete visual
pipeline remains active; it does not reproduce the earlier 66.79-FPS
disabled-effects interval. That build also retained OMV interposition in both
provider modes, so it cannot reject hook overhead.

That build exposed marker counters only in the workbench, so its file log
cannot independently prove which RESZ markers were forwarded or suppressed.
Subsequent builds include provider, physical hook attachment, all marker
counts, and successful external snapshot publications in each reliability
record and provider-switch baseline.

### Existing route contract

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

The secondary Depth Resolve reference also establishes the one-retry behavior
for `NVAPI_UNREGISTERED_RESOURCE`, explicit unregistration at resource
replacement/release, its public-effect exports, the shared texture getter, and
the two world RESZ call sites.

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

The supported executable is `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, image base `0x00400000`. Existing authoritative output
`analysis/ghidra/output/perf/graphics_fnv_depth_texture_layout_audit.txt`
establishes `ImageSpaceManager::GetDepthTexture @ 0x00B54090`, a `NiTexture*`
return in EAX, `NiTexture::m_pkRendererData @ +0x24`, and
`NiDX9TextureData::m_pkD3DTexture @ +0x64`. Depth Resolve replaces that exact
entry with its no-argument static getter. OMV calls the patched entry only
after detecting `DepthResolve.dll` and its two public effect-registration
exports, validates every pointer range, queries and retains the D3D texture,
and requires a non-empty `INTZ` level zero with matching world dimensions.

## Architecture and ownership

`omv/src/backend/fnv/depth_resolve_provider.rs` owns optional-plugin
discovery, shared-texture validation, route freshness, and exclusive RESZ
marker classification. `omv/src/backend/mod.rs` owns the atomic active-provider
identity and the live handoff transaction. `omv/src/hooks.rs` owns the
`IDirect3DDevice9::SetRenderState` vtable hook. `omv/src/fnv_render.rs` owns
the pre-alpha service capture, post-world external publication boundaries,
and native depth-stage hook lifecycle. `omv/src/fnv_world_pipeline.rs`
invalidates temporal state when provider identity changes.

Depth Resolve remains the allocation and reset owner of its shared texture.
OMV retains a COM reference for each active snapshot or target; it does not
replace the plugin's `NiTexture`, patch the plugin, rewrite either of its
resolve call sites, or build third-party source. Vanilla Plus Particles and
other registered consumers continue to obtain the same texture through
`ImageSpaceManager::GetDepthTexture`.

The RESZ ownership hook recognizes only the exact pair
`D3DRS_POINTSIZE = 0x7FA05000`. It reads texture stage zero and suppresses the
call only when all of the following are true:

1. the selected provider is OMV;
2. the bound pointer is the exact validated shared Depth Resolve texture;
3. OMV has not armed the marker as its own current resolve.

An unknown target, unknown provider state, non-marker render state, or
OMV-armed marker always reaches the original D3D9 method. Suppression returns
`D3D_OK` so the inactive provider completes its ordinary state restoration.
The scope uses one process-wide atomic so the device-vtable detour can observe
OMV's bounded marker call without allocation or a lock. FNV's D3D9 render
calls are serialized on the render thread.

The vtable detour is physically attached only while OMV is the selected
producer. Selecting `depth_resolve` or `none` restores the original
`SetRenderState` entry at the Present-owned switch boundary. The disabled
provider therefore pays no OMV branch on ordinary render-state changes.

When `fallout_new_vegas` is selected and Depth Resolve is present, its shared
world texture becomes `FnvDepthResolve`'s world destination. OMV first refreshes
it at the established pre-alpha boundary. That service capture remains active
even when the visual master switch is off because external consumers can
sample depth during native alpha rendering. The plugin's pre-water and
post-water markers are then suppressed. With visuals disabled this replaces
two external copies with one OMV copy; enabled effects request only the
existing OMV phase captures, up to pre-alpha world, coherent post-world, and
first-person.

When `depth_resolve` is selected, OMV never calls either its RESZ or NvAPI copy
path. After the original world renderer returns, OMV retains the shared
texture and publishes a read-only world snapshot with the persistent world
camera and source depth convention. The RESZ detour is physically absent in
this mode, so RESZ and native NvAPI both use the fixed post-world
replacement-function boundary proven by the reference source as the external
freshness contract. Successful borrowed snapshots have a separate counter;
the frozen external-marker counter confirms that OMV is not observing the
external provider through its D3D9 hook.
Depth Resolve 1.31 publishes no separate first-person resource; OMV therefore
does not issue a hidden first-person supplement.

The world, first-person, pre-alpha, and underwater entry trampolines are
prepared once at DeferredInit. When published scene-input and world-pipeline
requirements are both empty and OMV is not maintaining its shared-depth
service, a Present-boundary transaction restores all four original native
entry sequences. This remains true when the global visual master is enabled
but every individual effect is disabled. Enabling a scene consumer or
switching back to the OMV shared service reattaches the existing trampolines
before the next world render. General OMV `Present`, material, and image-space
hooks are outside the depth-provider lifecycle and remain independent.

When startup selects OMV and Depth Resolve is present, both required scene
boundaries are installed and verified during DeferredInit before RESZ
interposition is enabled synchronously. DeferredInit is the quiescent startup
boundary, so no render frame can enter between those operations. This closes
the otherwise possible first-frame dual-producer window and avoids suppressing
the external producer if OMV cannot publish its replacement. If startup
selects another provider, the normal device-hook worker prepares the
`SetRenderState` hook object asynchronously without replacing the device
vtable entry. A later live switch to OMV is rejected until both the scene
service and the prepared RESZ hook report ready. At the Present boundary the
switch first attaches the scene trampolines and RESZ interposition, then
publishes OMV as active; the reverse switch restores the original RESZ vtable
entry before publishing the external provider.
If either required startup hook cannot be established, OMV publishes the
inactive provider before returning the startup error. Already-resident scene
callbacks therefore cannot add an uncoordinated resolve; the persisted
machine-local choice is retained for a repaired next launch.

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
`nvapi_QueryInterface`; standalone OMV neither links nor requires another
depth-resolve plugin. The function IDs and ABI match the supplied NVIDIA
headers/reference:

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

Provider switching uses `try_lock` only. If either resolver owns its bounded
render transaction, the switch is rejected and the old provider remains
active. Validation occurs before release and again after release so the
shared COM identity used by the marker hook belongs to the new generation.
The menu restores the old machine-local setting and reports the rejection
instead of persisting a provider that is not active. A successful switch
clears both providers' snapshots, publishes the new identity with release
ordering, republishes input requirements, and invalidates TAA history.

Depth Resolve exposes no way to pause its native NvAPI copy. Consequently OMV
exclusive mode is rejected when the plugin selected native NvAPI; claiming an
OMV switch in that state would leave two producers running. External mode is
valid because OMV emits no copy. OMV interposes the exact shared RESZ target
only while OMV owns production. External mode restores the original
`SetRenderState` vtable entry, so its publication freshness is established at
OMV's fixed post-world boundary and validated against the plugin's currently
published texture identity. Shared identity and marker state are cleared on
device reset. Stale or replaced depth is never labeled current.

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

The `SetRenderState` hook object is prepared only when a compatible Depth
Resolve module is present; standalone OMV retains the original D3D9 path.
Its vtable detour is physically attached only while OMV owns production.
External and inactive modes restore the original entry and therefore pay no
OMV per-`SetRenderState` branch or target query. While attached, ordinary
calls add one exact integer comparison and only the RESZ marker queries
texture stage zero. There are no render-thread allocations, blocking locks,
file operations, shader compilations, or per-marker log writes. Diagnostics
read fixed atomic counters.

With Depth Resolve present, expected physical world-copy counts are:

| Provider/state | External copies | OMV copies |
|---|---:|---:|
| `depth_resolve` applicable world frame | 2 | 0 |
| OMV, visuals disabled | 0 | 1 shared pre-alpha service copy |
| OMV, depth-aware visuals enabled | 0 | 1-2 world copies, plus first-person only when required |
| `none` | unchanged third-party behavior | 0 |

The important invariant is exclusive production, not a promise that every
configuration performs one copy. Depth Resolve 1.31 intentionally exposes
both pre-water and post-water world versions. OMV's enabled pipeline has
distinct pre-alpha, coherent post-world, and view-model consumers.

### Conservative atmosphere admission before depth

The v2.0.6 record `.reports/omv-latest--1fps.log` shows
`completed_no_draw` increasing by 560 while pre-alpha and primary world
transactions also increase by 560. In that implementation, atmosphere
resolved pre-alpha depth before evaluating its no-contribution gate, then
could enter the coherent transaction and still draw nothing.

OMV now builds a CPU-published atmosphere frame before either depth request.
Admission skips only a proven no-contribution case: no enabled integration
family, underwater, a known interior with no current local-light candidate, or
no resolved directional/fog/local contribution. Debug views always proceed.
Unknown camera transform, material classification, underwater publication, or
a busy local-light mailbox also proceeds. Local volumetric lighting remains an
independent family; it is not gated by directional volumetric lighting.

A pre-alpha rejection returns before depth resolve and color copy. The same
gate runs before the coherent world transaction; TAA still requests coherent
depth independently when its prepared device consumer exists. Atmosphere and
TAA device-object readiness is also established before the physical request;
background preparation therefore cannot produce a depth-only transaction. The
reliability record exposes
`pre_alpha ... admission_skip=<n>` and `coherent_admission_skip=<n>`, allowing
the no-draw count to be distinguished from a transaction avoided before any
physical copy.

### Exact-stage physical-copy reuse

Each OMV resolve request names one semantic stage:

- `PreAlphaWorld`;
- `CoherentWorld`;
- `FirstPerson`.

A successful capture is reusable only when device generation, depth slot,
render epoch, semantic stage, source-surface identity, width, and height still
match. In particular, a pre-alpha world capture can never satisfy a coherent
post-world request even if both use the same surface and epoch; alpha and water
coverage make them different resources semantically. Reset, target
replacement, epoch transition, or any identity mismatch forces the normal
physical route.

The reliability record reports cumulative physical route attempts as
`depth_copies=pre_alpha:<n>/coherent:<n>/first_person:<n>/cache_hits:<n>`.
An operational RESZ rejection followed by the one allowed NvAPI retry counts
both route attempts. An exact cache hit performs neither RESZ nor NvAPI work.
These counters separate actual provider-copy pressure from higher-level world
transaction attempts.

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

Provider regressions additionally prove:

- marker classification suppresses only the exact shared target under OMV;
- an OMV-armed marker and an external-provider marker are forwarded;
- only the exact point-size/value pair enters RESZ classification;
- RESZ interposition is physically requested only for the OMV provider;
- the detached external route establishes freshness at the post-world
  boundary without depending on OMV marker observation;
- external provider capability is world-only and cannot silently request an
  OMV first-person supplement;
- world-only AO uses current RT0 after world publication and before the native
  first-person draw; structural negative control rejects the former
  `RenderFirstPerson` texture pre-bind, while the composition model proves that
  post-first-person AO darkens a covered weapon pixel;
- the later scene-pre phase cannot execute world-only AO even on render paths
  that omit first-person geometry;
- disabled visuals still retain the machine-local shared-depth service;
- external mode with no published scene consumer reaches physical restoration
  of all four scene-depth hook entries even if the visual master remains on;
- atmosphere no-contribution admission runs before depth, while incomplete
  scene and local-light publications conservatively retain the transaction;
- exact depth reuse requires stage, source, epoch, slot, and dimensions, and
  the negative controls reject pre-alpha/coherent aliasing and stale identity;
- a provider change invalidates temporal ownership;
- visual preset application preserves `depth_provider`.

The supported commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

On 2026-07-29, the completed provider, lifecycle, performance, world-only AO,
pre-depth admission, and exact-stage cache update passed all 427 OMV tests
through Wine. The optimized `i686-pc-windows-gnu` OMV build completed
successfully. The follow-up correction that moved world-only AO from the
`RenderFirstPerson` argument to active post-world RT0 passed all 428 tests and
the release build. Its structural regressions reject both the obsolete
first-person-detour call and any rendered-texture-source bind inside the
post-world AO transaction, and require missed-frame history invalidation even
when another scene-pre pass draws.

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
- with `depth_resolve`, first-person hands and weapons remain free of AO while
  world AO remains visible behind them in first and third person; the log must
  emit `[AO] World-only-provider AO is drawing on the active post-world target`
  once after the first successful AO transaction;
- in the workbench, switch `OMV -> Depth Resolve -> OMV` without restarting;
  verify `RESZ hook` reports detached in external mode and attached in OMV
  mode. External and suppressed marker counters must remain frozen in external
  mode while `external snapshots` rises when a depth-aware visual consumes
  the post-world texture;
- confirm presets do not change the selected provider;
- on the reported RTX 5060, disable every OMV effect (the visual master may
  remain enabled), select `depth_resolve`, and verify both `depth hooks` and
  `RESZ hook` report detached. OMV marker counters must remain unchanged. This
  is the zero-OMV-depth-hook performance control;
- with the same save, camera, and resolution, switch to OMV. Both hook groups
  must report attached and OMV mode should show one OMV marker and two
  suppressed external markers per applicable world frame;
- compare frame time for the detached external control, external mode with a
  minimal depth-aware visual, and OMV production. A gain only in the first
  isolates scene-hook overhead; a gain in both external cases isolates OMV
  resolve/interposition overhead; no gain rejects the depth-provider path as
  the source of the NVIDIA frame-time floor.

The code and supplied reference prove ownership and route selection. Only a
runtime playtest can prove a particular Proton/DXVK/NVIDIA stack exposes the
expected capability, produces correct sampled depth, and removes the observed
NVIDIA frame-time floor.

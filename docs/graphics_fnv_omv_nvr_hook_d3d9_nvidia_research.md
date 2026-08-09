# OMV versus NVR: D3D9 hook flow and the NVIDIA one-FPS failure

## Status and scope

This is a source and runtime-evidence comparison, not an implementation plan or
an assertion that the exact NVIDIA driver failure has been found. It traces the
two NVR source snapshots under `.research/`, the current OMV implementation, and
the available OMV/NVR runtime records as of 2026-08-09.

No OMV code was changed for this research. The intended outcomes are:

- identify the D3D9 and engine-hook behavior common to both NVR generations;
- distinguish the normal NVR path from optional debugging infrastructure;
- trace current OMV startup, shader replacement, frame stages, state ownership,
  and copies end to end;
- identify differences that can plausibly become vendor-specific driver costs;
- separate proven inefficiencies from candidate causes of the catastrophic
  exterior frame time;
- define the evidence needed before a later hook or render-graph rewrite.

The user-supplied runtime facts governing this analysis are:

1. both supplied NVR generations run without the NVIDIA one-FPS problem;
2. OMV still exhibits the problem for NVIDIA users after the 2026-08-04 removal
   of live D3D9 device-vtable hooks and the NVIDIA depth scheduling rewrite;
3. changing depth resolution, RESZ handling, and shader code did not fix it;
4. the remaining repeated depth copies are still waste and must be reduced,
   but depth work is not accepted as the sole root cause.

The current post-2026-08-04 NVIDIA observation has no matching new log or GPU
capture in the repository. It therefore proves that the prior fixes were not
sufficient, but it cannot attribute the remaining time to a particular hook or
D3D call. Older logs remain useful structural evidence and are identified as
historical wherever they describe a pre-2026-08-04 build.

## Executive conclusion

The exact one-FPS mechanism remains unproven. The source comparison does,
however, materially narrow the problem.

The normal path of neither NVR source wraps or patches the live, already-created
`IDirect3DDevice9` vtable. Legacy NVR 3.3.0 can install an owned device proxy at
device creation, but only when `Develop.LogShaders` is enabled. Modern NVR 4.4.1
compiles its device hook out with `HookDevice 0`, and the line that would wrap
the returned device is commented out. The shared, known-healthy NVR model is
therefore engine-level detours plus ordinary calls through the engine-owned
device, not generic D3D9 interception.

Current OMV has already converged on the first half of that contract: it no
longer patches the D3D9 device vtable. The 2026-08-04 change was correct as a
lifecycle and compatibility fix, but the user-reported lack of improvement
falsifies the earlier hypothesis that live device-vtable ownership was the
catastrophic performance cause.

OMV still differs from both NVR generations in two more important ways:

1. **Replacement shader ownership is split across two boundaries.** OMV
   temporarily replaces engine wrapper handles during `BSShader::SetShaders`,
   restores the wrappers immediately, and later validates or changes raw D3D9
   shader state from a common draw detour. Native sky also selects and restores
   raw shaders around a draw. NVR completes replacement selection at the engine
   pass setup boundary and lets the engine render-state cache bind that stable
   wrapper identity. It does not need a second universal draw interception.
2. **Image work is fragmented into several independent D3D transactions.** OMV
   can capture/apply an all-state block, capture/clear/restore all render-target
   attachments, and cross a full-resolution copy or resolve boundary at
   pre-alpha atmosphere, coherent-world TAA, post-world AO, scene-pre,
   scene-post, and final image-space stages. NVR performs substantial work and
   even more copies, but clusters it at world/first-person and native
   `ProcessImageSpaceShaders` boundaries with simpler attachment ownership.

These produce the strongest remaining root-cause classes:

- raw shader-pair alternation and validation at OMV's per-draw boundary,
  particularly close-terrain fallback/re-arm behavior in exteriors;
- NVIDIA-expensive command-stream serialization caused by OMV's combination of
  `D3DSBT_ALL` capture/apply, attachment churn, and copies/resolves split across
  multiple engine stages;
- interaction between those two systems, rather than either hook dispatch or
  copy bandwidth in isolation.

The raw number of copies cannot explain one FPS by itself. A measured healthy
NVR run issued 47 to 66 `StretchRect` attempts and four RESZ triggers per
gameplay frame. In its fully attributed region, 49 copies succeeded, 45 were
full-resolution, and the logical read/write payload was about 3.21 GB per frame
at 3440x1440. OMV must still remove redundant copies, but the NVR evidence says
to investigate *placement, synchronization, resource state, and surrounding
hook ownership*, not merely the counter total.

Similarly, the inline-hook library itself is not a strong steady-state suspect.
OMV and Microsoft Detours both reduce to an entry jump plus a trampoline on the
covered x86 paths. `InlineHookContainer::original()` reads a `OnceLock`-published
function pointer and takes no render-path lock. The important differences are
which functions are intercepted, how often, what work their detours perform,
how chains are discovered, and whether executable bytes are changed after
startup.

## Evidence rules

This document uses three evidence labels:

- **Proven**: directly visible in current source, supplied source, an existing
  static-analysis artifact, or a recorded runtime counter.
- **Observed**: supplied playtest behavior or log timing. It proves the visible
  outcome but not an internal cause.
- **Inference**: a causal interpretation consistent with the evidence. It must
  be tested on the affected native Windows/NVIDIA system.

No proprietary NVIDIA driver implementation is available here. A statement
that a command *may* serialize or trigger expensive driver validation is an
inference unless a GPU trace or isolated timing proves it.

## Source and executable identity

### OMV

The inspected repository commit is:

```text
e4283928b12c90c67fe3ec38f727aea508fae7dd
2026-08-04T01:07:00+03:00 perf(omv): use engine-owned render hooks
```

The worktree contained unrelated user-owned changes in `libnvse/xnvse` and
`intelmoc/`; no OMV source file was dirty before this document was written.

Relevant inspected-file SHA-256 values are:

```text
df245ddd8db23e3ad81e6543594f6a505dfcd915622d0aec5af19dfec16cd053  omv/src/hooks.rs
a052a51ad662e6d159fbe49148b06bf0d158cb6a1bef1c0c5e0f47dfaf69bf1d  omv/src/fnv_render.rs
920d91dd828412ce16f48c194d7860132ac604e92fad57b7522b962b440a2160  omv/src/runtime.rs
```

The supported executable contract remains Fallout New Vegas PE32 x86, image
base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Existing address evidence is indexed from
`docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` and the analysis outputs it
references. No new binary address was needed for this repository/source
comparison, so no new static engine research was performed.

### Legacy NVR snapshot

`.research/TES-Reloaded-master` contains no `.git` metadata. Its exact upstream
commit cannot be recovered from the archive itself. Its New Vegas entry point
reports plugin version `3`, while its Windows resource reports `3.3.0.0`:

- `.research/TES-Reloaded-master/NewVegasReloaded/Main.cpp:18-20`;
- `.research/TES-Reloaded-master/NewVegasReloaded/NewVegasReloaded.rc:72-77`.

The inspected `Main.cpp` SHA-256 is:

```text
a0f67924cc35735f5d66349a49f8541672f58dde9a0fa0354d8daa3abae5a0fe
```

This document calls that snapshot **legacy NVR 3.3.0** without asserting an
unavailable commit identity.

### Modern NVR snapshot

`.research/TESReloaded10-master` also contains no `.git` metadata. Its New Vegas
entry point reports plugin version `441`, and its resource reports `4.4.1`:

- `.research/TESReloaded10-master/NewVegasReloaded/Main.cpp:75-77`;
- `.research/TESReloaded10-master/NewVegasReloaded/NewVegasReloaded.rc:71-76`.

The inspected `Main.cpp` SHA-256 is:

```text
f880866d938e7bbaf1dc00d526793dd0ffbe85e2e9897f2259432499e5ce11ef
```

This document calls that snapshot **modern NVR 4.4.1**.

## Runtime evidence already available

### Healthy NVR command volume

`docs/nvr_d3d9_performance_research.md` records a temporary process-wide D3D9
observer against a working NVR setup. In representative gameplay it measured:

- about 45 non-indexed draws;
- about 1,870 indexed draws;
- 47 `StretchRect` calls;
- four RESZ triggers;
- about 1,580 render-state calls;
- about 3,500 sampler-state calls.

After additional NVR features were enabled, it measured 59 non-indexed draws,
3,129 to 6,380 indexed draws, and 66 copy attempts. The attributed samples
consistently reported 49 successful copies:

```text
1024x1024 f21  -> 1024x1024 f21  = 3
4096x4096 f113 -> 4096x4096 f113 = 1
3440x1440 f113 -> 3440x1440 f113 = 27
3440x1440 f22  -> 3440x1440 f113 = 18
```

The remaining 17 attempts strongly match invalid same-surface calls in NVR's
source, although the observer did not record their HRESULT and that attribution
is an inference. The important fact for this investigation is that a healthy
NVR frame can contain large draw, state, and copy counts. Neither a hot engine
state hook nor high raw copy count is automatically catastrophic on NVIDIA.

### Historical OMV affected-machine evidence

`.reports/omv-nvidia-depth-provider-2026-07-29.txt` records approximately
66.79 DisplayScene boundaries per second on an RTX 5060 at 3440x1440 while the
recorded world counters remain unchanged. The tester reported that all OMV
effects were disabled. This is evidence of a separate disabled-baseline ceiling,
not proof of the active exterior one-FPS cause.

`.reports/omv-latest--1fps.log` is an older v2.0.6 run at 3840x2160. It shows
multi-second render-thread initialization and 1,551 completed-no-draw world
transactions. Current code has since moved compilation off the render thread,
added applicability preflight, and consolidated phase copies. That log explains
old defects but does not measure current `e4283928` behavior.

`.reports/omv-latest--critical-1fps.log` is a 2026-07-30 run at 2560x1440. Its
first full-feature reliability record contains 96 active epochs, 288 OMV RESZ
operations, and 288 phase-initial color copies: exactly three depth operations
and three phase copies per epoch. It also contains 70 fallback commits. The 96
epochs accumulated over roughly 19.5 seconds after visual activation, about
4.9 active epochs per second. This is catastrophic even below 4K and therefore
rejects a simple 4K-pixel-count explanation.

That historical log also proves native-PBR fallback was occurring:

```text
[PBR] LandLOD PBR kept vanilla: missing_sampler_mask=0x0010 required_sampler_mask=0x00D3
```

After PBR was disabled, the old device draw hooks became
`prepared-detached`. A later interval advanced 600 presentation boundaries in
about 30.9 seconds, roughly 19.4 per second, while much world work was rejected
as no-draw. The interval is heavily confounded by live configuration changes
and cannot quantify PBR alone. It does show that the catastrophic state was not
a uniform presentation cap.

Most importantly, all of these stored logs predate the current engine-owned
hook change. The user now reports that the failure persists after that change.
Accordingly:

- old logs can prove that excessive work and fallback existed;
- current source can prove which old ownership mechanisms were removed;
- only a new affected-machine trace can measure the remaining current path.

## Legacy NVR 3.3.0 flow

### Startup and hook installation

`NewVegasReloaded/Main.cpp:30-50` performs configuration and manager setup from
the NVSE load callback. It calls:

1. `PerformGameInitialization()`;
2. shader creation hooks;
3. render hooks and other subsystem hooks;
4. optional `CreateD3D9Hook()` only when `Develop.LogShaders` is enabled.

`TESReloaded/Framework/Game.cpp:170-198` attaches engine initialization and
object-construction detours in one Microsoft Detours transaction. Its
`TrackInitializeRenderer` calls the original renderer initializer first, then:

1. stores the returned renderer as `TheRenderManager`;
2. calls `RenderManager::Initialize()`;
3. initializes managers;
4. creates effects.

This establishes a simple invariant: D3D-dependent managers are initialized
after the engine has created and published the real renderer/device.

`TESReloaded/Core/RenderHook.cpp:680-741` installs the New Vegas rendering
detours in another one-time Detours transaction. The relevant entries are:

- main engine `Render`;
- `BeginScene`;
- `ProcessImageSpaceShaders`;
- `RenderWorldSceneGraph`;
- `RenderFirstPerson`;
- `SetupRenderingPass`;
- related water/interface hooks.

The normal path does not modify the live D3D9 vtable and does not detour every
D3D draw or every D3D texture bind.

### Optional device proxy is not the normal contract

`TESReloaded/Core/D3D9Hook.cpp:14-37` patches the engine's device-creation path
and replaces the returned interface with a `TESRDirect3DDevice9` proxy. The
proxy implements the complete `IDirect3DDevice9` interface and forwards calls
to the real device.

However, `NewVegasReloaded/Main.cpp:49` calls this hook only when
`Develop.LogShaders` is true. It is development logging infrastructure, not the
ordinary renderer architecture that established NVR's vendor compatibility.

This corrects an over-broad sentence in
`docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md`: legacy NVR *can* create an
owned proxy at device creation, but its known normal path does not require that
proxy. A future OMV rewrite must not copy the debug proxy merely because it is
present in the legacy tree.

### Replacement shader ownership

Legacy NVR loads replacements after renderer initialization. In
`TESReloaded/Core/ShaderManager.cpp:2219-2245`, successful replacement creation:

1. stores the engine shader handle in `ShaderHandleBackup`;
2. creates the replacement D3D shader directly into `ShaderHandle`;
3. leaves the engine wrapper pointing at that replacement.

At `TESReloaded/Core/RenderHook.cpp:133-158`, `TrackSetupRenderingPass` calls the
native engine setup first. Native setup sees the replacement handle already in
the wrapper and updates the engine render-state cache through its normal path.
The detour then uploads replacement constant tables for the current vertex and
pixel records.

There is no later universal draw hook. There is no temporary wrapper alias that
is removed before the draw. The wrapper, engine cache, and D3D device agree on
the selected replacement for the pass.

### World and first-person depth

At `TESReloaded/Core/RenderHook.cpp:163-182`, the New Vegas hooks perform:

1. native world rendering;
2. a world depth resolve when camera conditions require it;
3. native first-person rendering;
4. a depth resolve;
5. an explicit Z clear and engine setup call;
6. a second native first-person render.

This is expensive and was simplified in modern NVR, but it is important
negative evidence: even legacy NVR's unusual two-render first-person sequence
does not reproduce OMV's NVIDIA catastrophe.

`TESReloaded/Core/RenderManager.cpp:175-284` creates an INTZ texture, probes
RESZ, and otherwise initializes NvAPI. RESZ saves a bounded set of state, emits
a dummy point and the `D3DRS_POINTSIZE` marker, then restores the state. Native
NVIDIA registers the source and destination resource and uses
`NvAPI_D3D9_StretchRectEx`.

Legacy `ShaderRecord::SetCT` at `ShaderManager.cpp:536-551` can copy the rendered
buffer and resolve depth, but guards each with per-frame filled flags. Depth
capture is therefore shared among shader records within that frame.

### Image-space effects and copies

`RenderHook.cpp:559-590` wraps the native `ProcessImageSpaceShaders` call. It
runs either pre-HDR effects before the original or post-HDR effects after it at
the outer image-space target.

The legacy effect graph is deliberately copy-heavy:

- full-resolution source and rendered textures are created in
  `ShaderManager.cpp:782-785`;
- selected effects copy the current target to `SourceSurface` before drawing;
- `EffectRecord::Render` copies the render target to `RenderedSurface` after
  every effect pass (`ShaderManager.cpp:697-713`);
- the pre/post chains at `ShaderManager.cpp:2727-2851` contain many additional
  effect-specific copies.

The graph is not an optimization model for OMV. Its relevance is that the
healthy implementation performs those copies inside a small number of known
engine stages and does not combine them with a universal post-setup draw
ownership layer.

### State and reset behavior

Legacy effects issue raw D3D state calls and use D3DX effects. There is no
explicit OMV-style capture of all MRT slots plus depth and no visible reusable
`D3DSBT_ALL` owner around each image-space phase. D3DX effect execution is
allowed to save/restore effect-managed state because `Effect->Begin` is called
without a do-not-save flag; the source does not expose the driver's internal
implementation of that save.

No complete lost-device/reset ownership path was found for the legacy manager
resources. This is a weakness of the snapshot, not a behavior OMV should copy.

## Modern NVR 4.4.1 flow

### Startup and hook installation

`NewVegasReloaded/Main.cpp:89-107` logs configuration and calls `AttachHooks()`.
The optional device hook is compiled only inside `#if HookDevice`, while line 2
defines `HookDevice 0`.

`src/NewVegas/Hooks/Hooks.cpp:3-39` attaches the main engine hooks in one
Detours transaction. Relevant entries include:

- `InitializeRenderer`;
- vertex/pixel shader creation;
- shader package setup;
- main `Render`;
- `ProcessImageSpaceShaders`;
- world and first-person renderers;
- `SetShaders`;
- `NiDX9RenderState::SetSamplerState`;
- optional reflection and related game hooks.

After the transaction it applies a small set of explicit engine patches. Two
are directly relevant:

- `0x00B575AA` retains shader packages;
- `0x008751C0` disables the native clear before first-person rendering because
  NVR assumes explicit ownership of that clear.

`src/core/Hooks/GameCommon.cpp:3-12` calls the original renderer initializer,
stores the returned renderer, initializes it, and then initializes managers.
Like legacy NVR, D3D ownership begins at the engine renderer's creation boundary.

### Modern optional device hook is inactive

`src/core/Device/Hook.cpp:3-28` contains a device-creation patch, but the line
that would replace the returned interface with `TESRDirect3DDevice9` is
commented out. Combined with `HookDevice 0`, modern NVR's ordinary and compiled
path neither wraps nor patches the D3D device.

### Replacement shader ownership

Shader creation hooks in `src/NewVegas/Hooks/ShaderIO.cpp` extend the engine
wrapper, retain the original handle, attach a stable shader name, and associate
replacement records.

`src/NewVegas/Hooks/Render.cpp:20-52` owns the pass selection:

1. read the current engine pass and shader wrappers;
2. read current shader identities from `NiDX9RenderState`;
3. call `SetupShader` on the wrapper before native `SetShaders`;
4. call native `SetShaders` once.

`src/core/ShaderRecord.cpp:480-550` selects exterior, interior, default, or
backup handles by writing the wrapper's `ShaderHandle`. Constants and declared
textures are uploaded only when the selected handle differs from the engine
cache's current handle. Native `SetShaders` then observes that stable selected
handle and updates the engine cache/device normally.

This modern flow is the clearest NVR reference for OMV. It has a per-pass hook,
but no second per-draw shader ownership decision and no raw replacement restore
after the draw.

Modern NVR also hooks `SetSamplerState` (`Render.cpp:56-67`). The measured NVR
run saw roughly 3,500 sampler-state calls per representative frame and remained
healthy. Therefore merely describing a hook as "hot" is insufficient. The
question is whether it adds driver-facing work, unstable state, or a later
ownership boundary.

### World and first-person flow

`Render.cpp:71-94` performs:

1. native world rendering;
2. a world depth resolve, subject to Pip-Boy state;
3. for non-first-person world calls, clear Z and snapshot the cleared
   first-person depth target;
4. on first-person entry, clear Z;
5. render first person once;
6. resolve first-person depth.

This removes legacy NVR's duplicate first-person render. The static byte patch
that disables the engine's own clear is paired with the explicit clear in the
hook, so there is one owner.

### Modern depth behavior

`src/core/RenderManager.cpp:272-370` probes RESZ first and otherwise initializes
NvAPI. The RESZ state set is bounded to FVF, declaration, texture 0,
vertex/pixel shaders, stream 0, Z enable/write, and color write. NvAPI retains
the source depth surface, obtains and registers its texture container when the
surface is INTZ, and then copies to the requested destination.

`ShaderRecord::SetCT` at lines 423-430 can copy the rendered buffer or resolve
depth whenever a selected shader declares those inputs. Unlike legacy NVR, the
shown path has no single per-frame filled flag. This can add depth operations at
shader transitions and is further evidence that resolve count alone does not
explain OMV's vendor failure.

One source defect should not be copied: the RESZ path retrieves vertex
declaration, vertex shader, and pixel shader COM references but releases only
texture 0 and stream 0. The omitted releases appear to leak references per RESZ
call. Native NVIDIA uses the NvAPI branch after a failed RESZ probe, so this is
not a persuasive native-NVIDIA one-FPS explanation, but it is not a safe model
for OMV.

### Modern image-space graph

`Render.cpp:134-216` wraps the same native image-space boundary as legacy NVR.
On the outer call it can:

- configure artifact-sensitive render state through `NiDX9RenderState`;
- run pre-tonemap effects on the source surface;
- call native image-space processing;
- run remaining pre-tonemap and post effects on the final target.

`src/core/ShaderManager.cpp:692-813` prepares one frame vertex stream, binds
RT0, and begins each pre/post group with two copies: target to rendered buffer
and target to source buffer. `src/core/EffectRecord.cpp:351-374` can make another
source copy per effect and one rendered-buffer copy after each effect pass.

Again, the graph is copy-heavy but stage-local. It does not use a generic
device-vtable hook, a common engine draw hook, or an engine `SetTexture` hook to
manage replacement ownership.

## NVR invariants common to both healthy generations

The implementations differ in details, but the following common properties are
the strongest reference contract because they survive across both known-healthy
generations:

1. **Normal device ownership stays with the engine.** The real
   `IDirect3DDevice9` is called directly. A full proxy exists only as legacy
   development infrastructure, and modern device wrapping is inactive.
2. **Hooks are primarily installed once.** Render hooks are attached in
   Detours transactions during startup and remain resident. Runtime settings
   select work inside the hooks rather than repeatedly rewriting their entries.
3. **Renderer-dependent managers start after native renderer initialization.**
   Both generations hook the engine initializer, call it first, and initialize
   their D3D managers from the returned object.
4. **Native replacement selection belongs to the engine pass boundary.**
   Legacy NVR keeps the replacement in the wrapper before native setup. Modern
   NVR selects the wrapper handle immediately before native `SetShaders`. The
   engine render-state cache remains the binding authority.
5. **No universal post-setup draw interception is needed.** Neither normal NVR
   path detours every primitive or every common shader-backed draw to decide
   whether its replacement remains valid.
6. **Image-space effects are clustered around native image-space ownership.**
   NVR wraps `ProcessImageSpaceShaders` and performs its pre/post work there.
7. **Depth capture is tied to semantic engine stages.** World and first-person
   hooks select the contents; RESZ/NvAPI is only the transport.
8. **Heavy command volume is tolerated.** Working NVR can issue thousands of
   state calls/draws and dozens of full-resolution copies. Compatibility cannot
   be reduced to minimizing any single API counter.

Not every NVR behavior is desirable. Legacy duplicate first-person rendering,
copy-heavy effect graphs, incomplete reset handling, same-surface copy bugs, and
modern RESZ COM leaks are explicitly not recommendations.

## Current OMV flow

### Startup ownership

`omv/src/startup.rs:88-163` keeps `NVSEPlugin_Load` limited to configuration,
logging, and CPU-side worker preparation. It does not initialize the focused
world pipeline or install render hooks there.

At `DeferredInit`, `startup.rs:167-221` performs the graphics publication in
this order:

1. initialize the selected depth provider;
2. publish the initial world configuration;
3. configure/install native PBR and sky ownership;
4. install the core engine hooks;
5. install local-light hooks;
6. prepare scene hooks;
7. reconcile which depth-stage hooks are physically active.

This ordering is constrained by
`docs/graphics_fnv_atmosphere_startup_crash_errata.md`: the focused world
pipeline must not be initialized or first-published from `NVSEPlugin_Load`.
The constraint does not require OMV's current per-draw topology; it only limits
when world ownership can be published.

Unlike NVR, OMV does not hook `InitializeRenderer`. It reads the device from the
already-published engine renderer and validates device identity lazily at render
boundaries. This is workable after DeferredInit and has explicit recreate
handling, but it is a lifecycle difference.

### Current relevant hook inventory

With the complete visual configuration installed, OMV can own 15 relevant
engine inline detours:

| Owner | Entry | Approximate frequency | Purpose |
|---|---|---:|---|
| core | `NiDX9Renderer::DisplayScene @ 0x00E75000` | once per presented scene | presentation service and render epoch |
| core | `NiDX9Renderer::Recreate @ 0x00E73EB0` | reset/recreate only | release and rebuild device resources |
| core | common `NiDX9Shader` draw `@ 0x00E812F0` | every shader-backed draw | PBR/sky draw-time ownership |
| scene | `ProcessImageSpaceShaders @ 0x00B55AC0` | native image-space calls | scene-pre, scene-post, final phases |
| scene | `SetWaterShaderUnderwater @ 0x004E2120` | water classification changes | underwater publication |
| scene | `RenderWorldSceneGraph @ 0x00873200` | world scene calls | jitter, world depth/color, world pipeline |
| scene | `RenderFirstPerson @ 0x00875110` | first-person scene calls | retry and first-person depth |
| scene | `RenderPreDepthGroups @ 0x00B65AE0` | world pre-alpha stage | atmosphere before alpha coverage |
| PBR | `BSShader::CreateVertexShader @ 0x00BE0FE0` | shader creation | wrapper discovery |
| PBR | `BSShader::CreatePixelShader @ 0x00BE1750` | shader creation | wrapper discovery |
| PBR | `BSShader::SetShaders @ 0x00BE1F90` | engine pass setup | replacement selection |
| PBR | `NiDX9RenderState::SetTexture @ 0x00E88A20` | every engine texture bind while resident | sampler tracking and draw admission |
| lights | world light epoch `@ 0x00871290` | once per light epoch | scene light capture |
| lights | completed local shadow slot `@ 0x00B9F780` | rendered local shadow slots | native shadow publication |
| sky | `SkyShader::UpdateConstants @ 0x00B89D80` | sky setup | native sky frame/replacement selection |

This does not count WndProc/input integration because it is not part of D3D9
render ownership.

Not all entries are active in every configuration:

- the three core hooks and image-space hook are resident;
- four depth-stage hooks can be physically enabled/disabled when published
  requirements change;
- once PBR engine ownership is installed, its hooks remain resident and take
  passive branches when disabled;
- local-light hooks remain resident with fast disabled paths;
- the sky hook remains resident after installation.

The two most important hot entries are the common draw hook and `SetTexture`.
The NVR observer's 1,500-2,300 texture binds and roughly 2,000 or more draws per
representative frame are not direct OMV counts, but they establish the scale an
equivalent scene can present to those detours. Current OMV telemetry does not
count either entry, so exact affected-machine volume remains open.

### Hook mechanics and chaining

`libpsycho/src/os/windows/hook/inline/inlinehook.rs:475-582` prepares a
trampoline and publishes its callable pointer through `OnceLock` before enable.
The hot `original()` call does not acquire the container's `RwLock`. Enabled
x86 hooks use a five-byte relative jump and a trampoline, conceptually the same
steady call shape as a Detours entry hook.

The meaningful installation differences are:

- NVR groups related attachments into a Detours transaction and calls
  `DetourUpdateThread(GetCurrentThread())`;
- OMV prepares/enables its inline hooks individually and uses a rollback
  transaction for selected groups;
- OMV's hook library explicitly does not suspend other threads and requires a
  quiescent target while executable bytes are written;
- OMV can physically change four scene-hook entries later at a DisplayScene
  boundary, whereas NVR normally leaves render detours resident;
- PBR and sky recognize a vanilla prologue or one existing near `E9` jump and
  hook that immediate destination. They do not traverse an arbitrary redirect
  chain.

The historical critical log proves that another component had already
redirected both shader-creation entries; OMV logged one-hop chains to
`0x05B81B50` and `0x05B81B70`. That behavior is compatibility-sensitive.

These differences matter for correctness and mod chaining. They are not a
strong explanation of *steady* one-FPS behavior after successful installation:
entry bytes are not rewritten every ordinary frame, and the hot trampoline
lookup is lock-free. They become performance candidates only if requirements
oscillate, a chain invokes duplicate work, or a different detour order changes
driver-facing state. No current runtime evidence proves any of those cases.

### Presentation and reset

`omv/src/hooks.rs:210-229` runs selected services before native DisplayScene,
calls the original once, completes telemetry/world epochs afterward, and then
increments the render epoch. There is no `IDirect3DDevice9::Present` hook.

The final screen phase normally executes inside `ProcessImageSpaceShaders`, not
DisplayScene. The DisplayScene path draws final work only for the provider-none
fallback or menu/presentation services. This means DisplayScene placement is
unlikely to explain exterior-only one FPS unless a service is unexpectedly
admitted there.

`hooks.rs:236-261` owns device recreation: release OMV resources before the
native recreate, reset PBR/sky state, call the engine once, and report the new
presentation profile. This is more explicit and safer than the reset ownership
visible in the supplied NVR snapshots.

### PBR replacement flow

OMV starts similarly to modern NVR. Shader-creation hooks discover engine
wrappers. `BSShader::SetShaders` classifies the current native pass and chooses
a replacement pair.

The ownership then diverges at `omv/src/effects/pbr/hooks.rs:567-704`:

1. OMV temporarily writes replacement handles into the vertex and pixel
   wrappers;
2. it calls native `SetShaders`, so `NiDX9RenderState` caches/binds the
   replacement pair;
3. the temporary scope restores both wrapper fields to native handles;
4. OMV publishes a pending draw descriptor in atomics;
5. later, the common shader-draw hook calls `prepare_direct_draw()`;
6. that function validates wrapper identity, sampler availability, geometry,
   and constants;
7. if rejected, OMV binds the native shaders directly on the device;
8. selected paths later restore the engine-cache-owned replacement directly.

This deliberately creates a period where the engine cache owns the replacement
identity while the wrapper field again exposes the native identity. OMV's code
contains repair logic for that split state.

Close terrain is the most important hot case. At
`pbr/hooks.rs:1010-1057`, every new geometry can query a complete sampler mask,
capture supplemental lights, and upload terrain constants. At lines 1139-1202,
close-terrain admission is re-armed after every draw so later geometry in the
same `SetShaders` batch can be reconsidered. When one geometry falls back,
`bind_native_fallback` issues raw vertex/pixel shader binds; restoration can
issue the replacement pair again before another draw.

This design preserves coverage, but it has no counterpart in either NVR source.
It can turn alternating valid/invalid exterior terrain geometry into repeated
raw shader-pair transitions inside one engine batch. Those transitions are
driver-facing and therefore can plausibly have vendor-specific cost. Existing
telemetry reports logical replacement/fallback counts, but no stored current
NVIDIA record reports the number of actual raw `SetVertexShader` and
`SetPixelShader` transitions.

The `SetTexture` detour at `pbr/hooks.rs:1402-1455` records every engine texture
binding while replacement is configured and updates the pending required/missing
sampler masks. A passive PBR configuration bypasses this work before selector
reads and atomics. With PBR active, however, it adds an OMV boundary to every
engine texture binding. The detour is CPU work unless it changes later draw
admission; its strongest relevance is as an input to the raw fallback/rebind
cycle, not as a standalone NVIDIA-specific branch cost.

### Native sky replacement flow

The sky hook captures the native shader pair and publishes a pending sky draw.
At `omv/src/effects/sky.rs:449-470` the common draw hook tries to bind it. The
draw-time path:

- takes nonblocking settings/frame-state locks;
- verifies current raw vertex/pixel shader identities;
- queries required textures;
- uploads constants;
- binds raw replacement shaders;
- restores native shaders after the draw (`sky.rs:1165-1180`).

Sky draw count is small compared with terrain, so this is unlikely to create
one FPS alone. It reinforces the larger architectural difference: OMV owns
replacement shader transitions after engine pass setup, while NVR makes the
engine pass setup authoritative.

### Local-light flow

`omv/src/fnv_local_lights.rs:608-710` wraps the native world light epoch. After
the original call it can traverse up to 512 scene lights, rank 16 atmosphere
lights and 64 terrain lights, and publish nonblocking snapshots. The optional
shadow hook captures up to four native shadow slots.

This work is allocation-free and uses `try_lock`, but it is exterior-sensitive
CPU work. Pure CPU traversal does not naturally explain a vendor-only GPU
failure; it is a secondary candidate or amplifier. The historical log proves
terrain-light capture was enabled by PBR, but current affected-machine scan
counts and CPU time have not been recorded.

### Scene and image-space sequence

For a full world frame, current OMV can execute the following conceptual flow:

```text
RenderWorldSceneGraph entry
  arm pre-alpha target and apply TAA camera jitter
  native world render begins
    RenderPreDepthGroups returns
      optional pre-alpha depth publication
      optional atmosphere composition transaction
  native world render returns
  publish/capture coherent world depth
  optional TAA transaction
  optional independent runtime world-color copy
  optional post-world AO transaction for external depth

RenderFirstPerson entry
  retry pending world transaction if necessary
  native first-person render
  publish/capture first-person depth

outer ProcessImageSpaceShaders entry
  close world deadline
  optional scene-pre screen transaction
  native ProcessImageSpaceShaders
  optional scene-post screen transaction
  optional final screen transaction

DisplayScene entry
  bounded PBR/sky/menu/presentation services if needed
  native DisplayScene
  close epoch and advance
```

NVR has the same broad semantic points, but fewer independent transaction
owners: world/first-person capture and pre/post work wrapped around
`ProcessImageSpaceShaders`.

## OMV state and attachment ownership

### Screen transactions

`omv/src/runtime.rs:1454-1488`, `1568-1602`, and `1670-1692` show three possible
screen transaction sites: final/presentation, post-world AO, and native scene
phases. Each admitted site can:

1. capture RT0 through the device's supported MRT count plus depth;
2. capture a reusable `D3DSBT_ALL` state block;
3. detach depth and every auxiliary target;
4. execute OMV copies/draws;
5. detach attachments again, restore RT0 and all auxiliary targets, restore
   depth, and apply the all-state block.

`omv/src/render_state.rs:20-128` correctly documents why attachment restoration
must precede state-block apply: D3D9 state blocks do not own render targets, and
`SetRenderTarget` changes viewport/scissor state. The implementation is
defensive and preserves the first error.

That correctness does not make the transaction cheap. On a four-MRT device, a
single transaction can issue five attachment getters, multiple depth/MRT
detaches, nine attachment restoration calls, one all-state capture, and one
all-state apply before counting effect-specific state and draws. Several such
transactions can run in one frame.

Because the state block restores the exact captured entry state, it should
normally restore coherence with the engine cache rather than make it stale.
The main concern is command and validation volume, not an automatically stale
cache. PBR's temporary wrapper/device split is a separate ownership concern.

### World transactions

`omv/src/fnv_world_pipeline.rs:635-1005` uses another reusable all-state block
and a separate attachment snapshot for world effects:

- pre-alpha atmosphere can capture world color and run one state transaction;
- coherent-world TAA can run another state transaction;
- atmosphere and TAA do not normally compose twice in one epoch because the
  atmosphere completion flag prevents the primary path from repeating a
  successful pre-alpha draw.

NVR does not explicitly capture every MRT/depth attachment and apply an
all-state block around each equivalent group. It also uses D3DX effect state
management, so the correct conclusion is not that NVR has no state-save cost.
The direct difference is OMV's broad explicit transaction repeated across more
engine boundaries.

### Why `D3DSBT_ALL` remains a serious candidate

An all-state capture/apply is a driver-facing request over a much larger state
domain than the bounded RESZ snapshot. It can require the driver to enumerate,
retain, and reapply many states that OMV does not touch. OMV can execute it at
several points per frame and surround it with target/depth changes and
full-resolution dependencies.

This is a plausible vendor-specific synchronization point, but it is not yet
proven:

- no current affected-machine timing isolates `Capture` from `Apply`;
- NVR's D3DX effect system may internally save changed effect state;
- the older failed OMV RESZ path also used all-state blocks, but current depth
  no longer does;
- an ordinary state block should not by itself force one second of work on
  every implementation.

The candidate is therefore the repeated *combination* of broad state save,
attachment rebinding, copies/resolves, and fragmented placement, not the API
name alone.

## Copy graph comparison

### Current OMV explicit copies

Current source contains the following steady explicit copy sites:

| Owner | Copy | Size | Frequency when admitted |
|---|---|---:|---:|
| phase color graph | engine target to phase primary | full phase size | once per drawn scene-pre, scene-post, or final phase |
| phase fallback | graph texture back to engine | full phase size | only when a planned tail rejects after an earlier draw |
| runtime world input | world RT to `world_color_copy` | full world size | once when a later screen consumer needs pre-first-person world color |
| atmosphere | world RT to atmosphere `world_color` | full world size | once when atmosphere draws |
| TAA | world RT to current texture | full world size | once when TAA draws |
| TAA | resolved history to world RT | full world size | once when TAA draws |
| AO | occlusion target to AO history | reduced AO size | once when AO draws |
| native NVIDIA depth | source depth to coherent snapshot | full depth size | once; pre-alpha/first-person use aliases when available |
| RESZ depth fallback | source depth to stage target | full depth size | up to the semantically requested stages |

The phase graph at `runtime.rs:2580-2840` is already better than old OMV: it
performs one initial phase copy and ping-pongs logical writers instead of
copying before every effect. The current expected fallback-commit count is low;
the 70/96 historical ratio in the critical log was not healthy and must not be
treated as the current intended budget.

There are still two independent full-resolution world-color owners:

- `runtime.rs:1761-1795` for later screen-effect sampler input;
- `fnv_world_pipeline.rs:1189-1207` for atmosphere.

When both consumers need the same epoch/target contents, the separate resources
and copies are certain duplication unless their semantic capture points differ.
The source currently does not share them.

With atmosphere, TAA, world-color consumers, and all three screen phases
actually drawing, the normal explicit color-copy ceiling is approximately:

- three phase-initial copies;
- one runtime world-color copy;
- one atmosphere world-color copy;
- two TAA copies;
- zero expected fallback commits.

That is seven full-resolution color copies, plus reduced AO history and the
selected depth transport. Exact format, MSAA resolve behavior, and phase
admission depend on the engine target and configuration.

### Transfer magnitude

For an eight-byte FP16 color surface, one full-surface copy has the following
logical payload. "Traffic" counts one read plus one write and does not claim the
driver's physical compression/cache behavior.

| Resolution | One surface | Read plus write | Seven copies |
|---:|---:|---:|---:|
| 2560x1440 | 28.13 MiB | 56.25 MiB | 393.75 MiB |
| 3440x1440 | 37.79 MiB | 75.59 MiB | 529.10 MiB |
| 3840x2160 | 63.28 MiB | 126.56 MiB | 885.94 MiB |

A four-byte surface halves these values. An MSAA-to-non-MSAA `StretchRect` can
also be a resolve rather than a plain copy, so byte arithmetic alone is not a
GPU-time prediction.

These are significant costs and should be optimized. They still remain well
below the measured healthy NVR logical copy payload in the attributed
3440x1440 run. This is the decisive reason not to call copy count the one-FPS
root without placement/timing evidence.

### NVR copy placement

Both NVR generations:

- acquire depth at world/first-person or replacement-shader semantic points;
- establish one source/rendered pair around a pre/post image-space group;
- update the rendered buffer after effect passes;
- keep those operations inside a compact render-manager/effect-manager call
  stack.

OMV:

- has fewer effect-chain copies after phase-graph consolidation;
- but opens and closes independent state/attachment transactions at more engine
  points;
- can duplicate world color between atmosphere and the screen runtime;
- places TAA copies between its own full state capture and restore;
- may then start another screen transaction later in the same frame.

The NVR comparison therefore supports consolidation and resource sharing, but
does not support sacrificing resolution, format, effect coverage, or shader
quality.

## Side-by-side architecture matrix

| Concern | Legacy NVR 3.3.0 | Modern NVR 4.4.1 | Current OMV |
|---|---|---|---|
| Normal live device vtable | untouched | untouched | untouched since 2026-08-04 |
| Device proxy | optional `LogShaders` creation-time proxy | compiled out; wrapper line commented | none |
| Renderer acquisition | hook native initializer, initialize after original | same | read published renderer/device after DeferredInit; lazy identity checks |
| Hook installation | one-time Detours transactions | one-time Detours transaction plus static patches | individually prepared inline hooks; some physical runtime reconcile |
| Existing-hook chaining | Detours predecessor chaining | Detours predecessor chaining | vanilla or one near-jump destination for PBR/sky; fixed targets elsewhere |
| Shader selection | wrapper permanently contains replacement | wrapper selected before native `SetShaders` | wrapper overridden only during native `SetShaders` |
| Engine cache authority | native setup | native `SetShaders` | native `SetShaders`, followed by OMV draw-time validation/fallback |
| Universal draw detour | none | none | common shader draw hook |
| Texture-bind detour | none for FNV replacement | none; sampler-state detour exists | `NiDX9RenderState::SetTexture` for PBR tracking |
| Raw shader bind after pass setup | not for normal replacement selection | not for normal replacement selection | PBR fallback/restore and every admitted sky replacement |
| Image-stage owner | `ProcessImageSpaceShaders` wrapper | `ProcessImageSpaceShaders` wrapper | same wrapper plus separate world/pre-alpha/post-world/present owners |
| State restoration | direct/D3DX effect behavior | engine state plus direct/D3DX effects | explicit all-state plus attachment transactions |
| World color resources | shared source/rendered effect buffers | shared source/rendered effect buffers | phase pairs plus separate runtime-world and atmosphere-world copies |
| Depth transport | RESZ else NvAPI | RESZ else NvAPI | external borrow, NvAPI alias/copy, or bounded RESZ |
| Reset handling | no complete path found | no complete path found | explicit engine Recreate hook |

## Root-cause assessment

### Candidate 1: per-draw replacement ownership and raw shader alternation

**Priority: highest. Evidence strength: medium. Exact cause: unproven.**

Why it fits:

- it is absent from both healthy NVR generations;
- it adds driver-facing raw shader binds after the engine believes pass setup is
  complete;
- close-terrain admission is deliberately re-armed per draw/geometry;
- invalid/missing samplers can alternate native fallback and replacement within
  one engine batch;
- exterior terrain greatly increases the opportunity for this behavior;
- proprietary drivers can price shader/state transition patterns differently;
- the historical affected log directly records at least one missing-sampler
  terrain fallback.

Why it is not proven:

- current logs do not count actual raw shader transitions per frame;
- a common-draw visit that finds no pending work is only atomics/branches;
- the user reports a vendor correlation, but no synchronized AMD/NVIDIA trace
  shows different time inside this path;
- the 2026-07-30 log used older device draw hooks, so its timing cannot be
  assigned solely to current engine draw ownership.

Required proof:

- count current common-draw visits, pending evaluations, admitted draws,
  fallback draws, and actual raw native/replacement shader binds by family;
- measure CPU time for `prepare_direct_draw` and driver time around the raw
  binds on the affected system;
- later compare a startup-only build where replacement ownership remains stable
  at the engine pass boundary and no common draw hook is installed.

### Candidate 2: fragmented all-state/attachment/copy transactions

**Priority: highest. Evidence strength: medium. Exact cause: unproven.**

Why it fits:

- the broad transaction is repeated across more semantic boundaries than NVR;
- every transaction crosses many driver entry points before effect-specific
  work begins;
- copies/resolves inside the transaction introduce read-after-render
  dependencies that can flush or serialize queued work;
- state capture/apply and attachment rebuild behavior is driver-owned and can be
  vendor-sensitive;
- the catastrophic 2560x1440 report contained three phase copies per active
  epoch plus many fallback commits, so it was not merely a 4K bandwidth event.

Why it is not proven:

- no timing separates state block, attachment churn, copy, and draw;
- healthy NVR still performs substantial state management and more copies;
- current OMV has already removed all-state blocks from RESZ, so historical
  depth-transaction conclusions do not directly measure current world/screen
  transactions;
- ordinary driver implementations should handle several valid state blocks per
  frame, making a one-second penalty exceptional rather than expected.

Required proof:

- per-boundary counts and CPU timings for state capture, attachment capture,
  target preparation, state apply, and attachment restore;
- GPU timestamps or a vendor trace around each admitted world/screen
  transaction;
- a later bounded-state A/B that preserves every required state and attachment,
  not a blind removal that risks image correctness.

### Candidate 3: interaction between candidates 1 and 2

**Priority: highest as a combined failure mode. Evidence strength: low to
medium.**

OMV can leave the engine's render cache owning a replacement pair, perform
draw-time raw fallback/rebinds, then later capture and apply full D3D state at
world/image boundaries. Each subsystem is designed to repair its own state, but
their combined transition graph is much more complex than NVR's stable wrapper
plus stage-local effects.

A vendor driver may repeatedly validate or serialize shader/resource state that
would remain stable in NVR. This combined hypothesis best explains why neither
removing device-vtable hooks nor changing depth transport alone fixed the issue.
It remains an inference until transition counts correlate with the long frame.

### Candidate 4: duplicate and misplaced full-resolution copies

**Priority: mandatory optimization. Evidence strength for inefficiency: high.
Evidence strength as sole one-FPS root: low.**

Proven waste includes separate atmosphere/runtime world-color ownership when
their required contents coincide and any nonzero steady fallback-commit rate.
Seven full-resolution copies at 4K FP16 represent about 886 MiB of logical
read/write traffic per full frame, before depth and reduced histories.

The healthy NVR observer is the counterevidence against a copy-count-only root.
The actionable hypothesis is that a particular OMV copy is forcing a driver
serialization at a bad engine stage, not that seven is intrinsically worse than
49.

### Candidate 5: hook chaining and runtime executable mutation

**Priority: medium for correctness, lower for steady performance. Evidence
strength: low.**

OMV's one-hop `E9` resolver is narrower than Detours chaining, and the historical
log proves the shader-creation targets were already redirected. Hook order can
change which component observes or mutates wrappers first. Separately, four
scene hooks can be attached/detached after startup without suspending all
possible caller threads.

This can cause incompatibility, duplicate work, or a transition race. It does
not naturally explain a stable vendor-specific FPS floor when hook state is
constant. Future hook rework should still prefer one-time resident engine
detours and explicit predecessor ownership because that matches NVR and avoids
an unnecessary variable.

### Candidate 6: pure CPU hot-path work

**Priority: medium-low. Evidence strength: medium for cost, low for vendor
specificity.**

The common draw hook, texture tracking, terrain constant uploads, sampler
validation, and up-to-512-light scene traversal are real CPU work. They can be
exterior-sensitive and should be measured. The hook implementation avoids
per-call locks and the hottest PBR reads avoid `VirtualQuery`, which bounds some
of the concern.

Pure CPU overhead should affect AMD and NVIDIA similarly under a controlled
system. It becomes a stronger candidate only when it triggers additional D3D
calls or interacts with a vendor driver wait.

### Candidate 7: resource pressure and residency

**Priority: medium-low. Evidence strength: low.**

OMV retains multiple full-resolution exact-format phase textures, two world
color owners, TAA history/current resources, depth targets, and effect-specific
intermediates. At high resolution, FP16 and MSAA resources can be large. A GPU
with less usable VRAM could enter severe residency pressure that appears vendor
correlated.

Counterevidence is substantial: the critical report reproduced at 2560x1440,
and healthy NVR owns four full-resolution FP16 textures plus large shadow/effect
resources. No current affected log provides trustworthy resident/eviction data.
This remains a fallback hypothesis, not the leading explanation.

### Candidate 8: device initialization or reset ownership

**Priority: low for steady one FPS, high for lifecycle correctness.**

OMV initializes after DeferredInit and tracks device replacement lazily; NVR
hooks native renderer initialization. OMV's explicit Recreate path is otherwise
stronger. A stale resource from an unobserved reset could cause failures, but
current logs do not show reset loops, repeated resource creation, or persistent
D3D errors in the critical steady section.

## Hypotheses rejected or materially weakened

### Shader bytecode or shader equations

Rejected by the user-supplied isolation. This document intentionally does not
analyze shader math as the root cause. Shader replacement *ownership and bind
scheduling* remain in scope because they are hook/D3D behavior, not shader code.

### Depth resolution or RESZ alone

Rejected as the primary cause by repeated playtests and the current user report.
Current OMV also uses a bounded NVR-derived RESZ state snapshot and prefers
native NVIDIA aliasing/copy behavior where available. Depth copies still require
optimization, but changing their resolution or marker path did not solve the
failure.

### Live D3D9 device-vtable mutation

Rejected for current `e4283928`: no such hooks remain, and the NVIDIA problem
reportedly persists. The removal remains a valid compatibility improvement.

### Raw copy count

Rejected as a sufficient explanation by the healthy NVR observer. Copy count is
an optimization metric; driver time at a particular dependency boundary is the
causal metric still missing.

### Inline-hook dispatch alone

Materially weakened. The hot original pointer is lock-free and the enabled path
is a normal x86 entry jump/trampoline. NVR also tolerates thousands of calls
through a hot `SetSamplerState` detour. Hook topology and detour work remain in
scope.

### One obvious repeated native render

No OMV scene hook calls the original world or first-person renderer more than
once. Ironically, legacy NVR deliberately renders first person twice and is
still reported healthy. An accidental whole-scene duplicate is not visible in
current OMV source.

## Direction for a later hook rewrite

This section records research conclusions, not authorization to implement.

### Preserve the parts already aligned with NVR

- Keep the real D3D9 device and its vtable engine/driver-owned.
- Do not introduce the legacy `LogShaders` proxy as normal infrastructure.
- Keep reset handling at the proven engine `Recreate` boundary.
- Keep shader creation observation separate from per-frame replacement work.
- Keep render callbacks free of compilation, file I/O, blocking locks, and
  routine allocation.

### Converge replacement ownership toward NVR

The target architecture should make one engine pass/geometry boundary own the
complete decision:

1. choose a valid native or replacement pair;
2. ensure required textures/constants are ready;
3. expose the chosen stable handles to native `SetShaders`;
4. let `NiDX9RenderState` update its cache and device;
5. draw without a second universal shader-ownership decision;
6. change selection at the next proven engine boundary.

OMV's per-geometry terrain requirements mean this cannot be copied verbatim
from NVR. A later implementation must find an engine boundary late enough to
know geometry/samplers but early enough that native setup remains authoritative.
The research conclusion is to remove the split ownership, not to delete
validation or weaken fallback safety.

If a common draw hook remains necessary for a narrow family, it should not be
resident for all shader-backed draws without measurement, and it should not
perform raw pair alternation when a stable engine-owned selection is possible.

### Make hook installation one-time and resident where practical

NVR's stable pattern is one-time startup detours plus passive settings gates.
For OMV, a later design should:

- prepare/install the complete compatible engine-hook set at one quiescent
  lifecycle boundary consistent with the DeferredInit crash errata;
- keep render entries resident rather than physically reconciling them during
  normal live configuration changes;
- use explicit, validated predecessor chaining instead of assuming at most one
  near jump;
- group dependent installation with rollback and document thread-quiescence
  proof;
- make disabled paths direct and measurable.

This improves compatibility determinism. It is not claimed to fix FPS without
the hot-path evidence above.

### Consolidate D3D transactions

The later render graph should aim for the smallest number of engine-stage
transactions consistent with semantics:

- one coherent world transaction for consumers that require the same world
  contents;
- one shared world-color resource when atmosphere and later screen consumers
  need the same capture;
- one native image-space transaction per actual native phase, with all
  applicability decided before capture/copy;
- no fallback commit in steady state;
- a bounded explicitly owned state set if it can be proven complete, or one
  shared state owner instead of repeated `D3DSBT_ALL` capture/apply;
- no unnecessary MRT/depth detach/restore for a pass whose attachment contract
  is already proven.

This must preserve exact formats, depth semantics, first-person exclusion,
MSAA compatibility, TAA history, effect order, and failure restoration.

### Optimize depth independently

Depth should remain a separate workstream:

- reuse already-produced external world depth when its epoch/stage is proven;
- use aliases only for immediately consumed contents;
- copy only snapshots that must survive later depth writes;
- eliminate duplicate semantic captures requested by multiple consumers;
- retain first-person coverage and fail closed when no valid provider exists.

Those changes reduce real work but should no longer be presented as the expected
one-FPS cure without a new trace.

## Required diagnostic evidence before implementation decisions

The next diagnostic build should count and time existing owners without adding
a generic D3D9 vtable observer to release code.

### Per-frame hook counters

Record, behind an explicit diagnostic gate:

- common shader-draw detour visits;
- PBR pending evaluations by object, land LOD, terrain fade, and close terrain;
- replacement admissions and vanilla fallbacks by family;
- actual raw native and replacement vertex/pixel shader binds;
- `SetShaders` calls and `SetTexture` detour calls;
- sky pending/admitted/restored draws;
- local-light list length and scanned count;
- scene-hook attach/detach transitions, which should remain zero in steady state.

Logical fallback counts are not enough. The root candidate concerns actual
driver-facing pair transitions.

### Per-boundary D3D counters

Attribute to named owners rather than one aggregate:

- state-block captures and applies;
- attachment getters, detaches, and restores;
- `StretchRect`/`StretchRectEx` by source/destination dimensions, format, MSAA,
  and owner;
- world color copies separated into atmosphere, runtime input, TAA input, and
  TAA output;
- phase-initial and fallback commits separated by scene-pre, scene-post, and
  final;
- depth operations separated by pre-alpha, coherent world, and first person.

### Timing

CPU timing should sample named blocks with `QueryPerformanceCounter` and avoid
per-call formatting/logging. GPU attribution requires timestamps or a vendor
capture around coarse transactions, not around every draw in a normal build.
At minimum, isolate:

- native scene time outside OMV;
- PBR/sky draw preparation and raw bind time;
- pre-alpha atmosphere transaction;
- coherent-world TAA transaction;
- runtime world-color capture;
- each image-space phase transaction;
- DisplayScene services.

A long CPU duration around a D3D call may represent a driver wait; a GPU
timestamp distinguishes submitted GPU work from CPU-side synchronization.

### Controlled matrix

Use the same save, camera, resolution, AA, mod list, driver, and warm resource
state on the affected NVIDIA system and an unaffected control. Capture frame
times, not only average FPS.

The minimum future matrix is:

1. no OMV DLL;
2. OMV loaded with a startup configuration that installs no optional visual
   hooks;
3. resident hooks with direct pass-through only;
4. PBR only, split by object/land LOD/terrain fade/close terrain;
5. sky only;
6. screen stack only, with PBR/sky absent;
7. atmosphere only;
8. TAA only;
9. native image-space phases only;
10. full configuration.

Runtime master-off is not equivalent to no hooks: the common draw and passive
PBR/sky entries can remain resident. Both cases are needed.

Only after current counters identify a dominant path should later A/B builds
change architecture. The highest-value A/Bs are:

- current split PBR ownership versus stable engine-pass ownership with no
  common draw hook;
- current full state/attachment transaction versus a proven bounded/shared
  state owner;
- separate atmosphere/runtime world copies versus one epoch-owned copy;
- current multi-phase transactions versus consolidated image-space ownership.

## Acceptance criteria for a later fix

A later implementation is not complete merely because it builds or reduces a
counter. It must demonstrate on native Windows/NVIDIA:

- the catastrophic exterior frame time is gone across the supplied affected
  scenes;
- interior and disabled-baseline performance do not regress;
- AMD and Proton/DXVK remain healthy;
- native and replacement PBR/sky draws remain visually correct through mixed
  geometry, missing textures, fades, interiors/exteriors, and live settings;
- atmosphere remains before required alpha coverage;
- TAA, AO, motion blur, DOF, final output, and loose shaders retain exact order
  and inputs;
- world and first-person depth remain semantically correct;
- reset, resolution change, alt-tab, and device replacement release/recreate
  resources without stale aliases or wrappers;
- steady fallback commits and unexpected raw shader flips are zero or have a
  documented bounded reason;
- per-boundary timings show which removed work produced the gain.

## Proven facts, inferences, and open questions

### Proven by source or stored runtime evidence

- both supplied NVR normal paths use engine detours and an engine-owned D3D9
  device;
- legacy NVR's device proxy is optional development logging infrastructure;
- modern NVR's device hook is compiled out and would not wrap the device as
  written;
- both NVR generations select replacement shaders at engine pass setup and do
  not use a universal later draw hook;
- current OMV uses no D3D9 device-vtable hook;
- current OMV does use a common shader draw hook, a PBR `SetTexture` hook, and
  raw shader binds for PBR fallback/restore and sky replacement;
- current OMV can use several independent all-state/attachment transactions per
  frame;
- current OMV has two independent world-color copy owners;
- healthy NVR has been measured with much higher raw copy/state/draw volume than
  a simplistic OMV budget;
- the historical critical OMV log reproduced catastrophic timing at 2560x1440,
  contained three depth and three phase copies per active epoch, and recorded a
  terrain sampler fallback;
- the user reports no NVIDIA improvement after current device-vtable/depth
  changes.

### Reasoned inferences

- OMV's split pass/draw replacement ownership is the strongest hook-side root
  candidate;
- raw fallback/replacement alternation is more likely to become vendor-specific
  than the CPU jump/trampoline itself;
- repeated broad state/attachment transactions can amplify copy/resolve
  synchronization cost on a particular driver;
- the combined transition graph is a better explanation than depth, shader
  code, device-vtable ownership, or copy count alone;
- one-time resident hooks and stable engine-cache authority are safer future
  convergence targets.

### Open questions requiring the affected machine

- How many current common-draw and `SetTexture` detours run per bad frame?
- How many raw PBR/sky shader pair transitions actually reach the NVIDIA
  driver?
- Are close-terrain fallback and one-FPS frames correlated?
- Which state-block capture/apply or attachment restore blocks the CPU?
- Which copy or resolve has the long GPU dependency, if any?
- Are atmosphere and runtime world-color captures semantically shareable in the
  affected configuration?
- Does the one-FPS event coincide with VRAM residency loss or allocation churn?
- Does a true no-optional-hooks startup recover differently from runtime
  master-off?
- Does hook-chain order with Fallout Shader Loader or other graphics plugins
  change the bad path?

Until those questions are measured, a comprehensive rewrite should be guided by
the NVR invariants and the two leading root classes, but it must not claim a
specific proprietary-driver cause as proven.

## Primary evidence index

### Current OMV

- `omv/src/startup.rs:88-221` - Load versus DeferredInit ownership.
- `omv/src/hooks.rs:42-153,210-283` - core engine hooks and detours.
- `omv/src/fnv_render.rs:26-60,257-810` - scene hook inventory and frame flow.
- `omv/src/effects/pbr/hooks.rs:43-47,494-704,1010-1202,1292-1311,1402-1455`
  - PBR targets, chaining, split ownership, fallback, and texture tracking.
- `omv/src/effects/pbr/engine_contracts.rs:446-550` - wrapper handle reads and
  temporary override ownership.
- `omv/src/effects/sky.rs:449-470,912-974,1165-1205` - draw-time raw sky
  replacement and hook chaining.
- `omv/src/fnv_local_lights.rs:608-710,864-915,1168-1175` - light hook,
  bounded traversal, and capture limit.
- `omv/src/runtime.rs:1454-1801,2339-2379,2580-2840,4491-4615` - screen
  transactions, world copy, phase graph, and phase copies.
- `omv/src/fnv_world_pipeline.rs:635-1005,1182-1207` - pre-alpha, TAA,
  atmosphere state, and world color.
- `omv/src/effects/temporal_aa.rs:700-775` - two full-resolution TAA copies.
- `omv/src/render_state.rs:20-153` - attachment and state restoration contract.
- `omv/src/backend/fnv.rs:2092-2345` - current NvAPI/RESZ route and copies.
- `libpsycho/src/os/windows/hook/inline/inlinehook.rs:20-225,475-582` - inline
  hook enable/disable and lock-free original publication.

### Legacy NVR 3.3.0

- `.research/TES-Reloaded-master/NewVegasReloaded/Main.cpp:30-50` - startup and
  optional device hook gate.
- `.research/TES-Reloaded-master/TESReloaded/Framework/Game.cpp:170-198` -
  renderer initialization hook.
- `.research/TES-Reloaded-master/TESReloaded/Core/RenderHook.cpp:115-182,559-590,680-741`
  - pass, world, first-person, image-space, and hook flow.
- `.research/TES-Reloaded-master/TESReloaded/Core/ShaderManager.cpp:536-551,697-713,782-785,2219-2245,2727-2851`
  - replacement ownership, effect graph, and copies.
- `.research/TES-Reloaded-master/TESReloaded/Core/RenderManager.cpp:175-284` -
  renderer/depth initialization and RESZ/NvAPI transport.
- `.research/TES-Reloaded-master/TESReloaded/Core/D3D9Hook.cpp:14-37` - optional
  creation-time proxy.

### Modern NVR 4.4.1

- `.research/TESReloaded10-master/NewVegasReloaded/Main.cpp:75-107` - version,
  disabled device hook, and attach entry.
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Hooks.cpp:3-71` - one-time
  engine detours and static patches.
- `.research/TESReloaded10-master/src/core/Hooks/GameCommon.cpp:3-12` - renderer
  initialization order.
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Render.cpp:20-94,134-216`
  - SetShaders, world/first-person, and image-space flow.
- `.research/TESReloaded10-master/src/NewVegas/Hooks/ShaderIO.cpp:3-50` - shader
  wrapper observation.
- `.research/TESReloaded10-master/src/core/ShaderRecord.cpp:423-550` - replacement
  selection, constants, rendered buffer, and depth.
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp:692-813` and
  `.research/TESReloaded10-master/src/core/EffectRecord.cpp:351-374` - effect
  groups and copies.
- `.research/TESReloaded10-master/src/core/RenderManager.cpp:272-370` - depth
  provider and bounded RESZ state.
- `.research/TESReloaded10-master/src/core/Device/Hook.cpp:3-28` - inactive
  device hook.

### Runtime and prior research

- `.reports/omv-latest--1fps.log` - historical v2.0.6 4K run.
- `.reports/omv-latest--critical-1fps.log` - historical 2560x1440 catastrophic
  run and fallback/copy/depth counters.
- `.reports/omv-latest--performance-bad.log` - historical failed RESZ and
  preparation behavior.
- `.reports/omv-nvidia-depth-provider-2026-07-29.txt` - affected NVIDIA
  disabled-world baseline.
- `.reports/omv-depth-provider-live-switch-2026-07-29.txt` - historical live
  provider comparison.
- `docs/nvr_d3d9_performance_research.md` - measured healthy NVR D3D workload.
- `docs/graphics_fnv_omv_runtime_performance.md` - prior OMV optimization and
  historical report interpretation.
- `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md` - current device/depth
  implementation contract; its performance efficacy is superseded by the
  latest user observation recorded here.

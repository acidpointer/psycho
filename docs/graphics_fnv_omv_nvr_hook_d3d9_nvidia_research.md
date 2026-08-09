# OMV versus NVR: D3D9 hook flow and the NVIDIA one-FPS failure

## Status and scope

This is a source, executable, and runtime-evidence comparison, not an
implementation plan. It traces the two NVR source snapshots under `.research/`,
the current OMV implementation, the exact FalloutNV.exe hook targets, and the
available OMV/NVR runtime records as of 2026-08-09.

This revision includes a second-pass audit of every conclusion in the original
document. That audit found material omissions in the original ranking:

- `0x00E812F0` was described as a common draw method, but its proven body is a
  geometry/resource submission method. It binds streams and indices and does
  not itself call `DrawPrimitive` or `DrawIndexedPrimitive`;
- all PBR draw-family bind paths reacquire the device through a helper that
  performs two `VirtualQuery` calls, including the re-armed close-terrain path;
- close terrain can issue fourteen `GetTexture` calls, scan up to 64 property
  lights, consult a 64-light manager snapshot, and upload as many as 51 pixel
  constant rows for one evaluated geometry submission;
- OMV writes two shader-package globals through `VirtualQuery` and temporary
  page-protection changes every serviced PBR frame instead of owning the
  semantic package-change boundary;
- OMV's state transactions perform D3D getter calls that create owned COM
  references, a cost not visible in the prior healthy-NVR observer counters.

Those omissions materially change the leading root-cause assessment below.

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

The second-pass result is more specific than the original document: current OMV
contains a source-proven hot-path design defect at the center of the exterior
failure, plus two substantial amplifiers. The proprietary NVIDIA-internal step
that turns those defects into approximately one FPS is still not directly
measured, so it would be inaccurate to claim one isolated API call as the final
driver cause.

The normal path of neither NVR source patches the live, already-created
`IDirect3DDevice9` vtable. Legacy NVR 3.3.0 can install an owned creation-time
proxy only behind `Develop.LogShaders`; modern NVR 4.4.1 compiles its device hook
out and leaves its wrapper assignment commented. Current OMV also no longer
patches the live device vtable. The reported persistence of one FPS therefore
rejects live device-vtable mutation as the current catastrophic cause.

The strongest remaining defect is not merely "raw shader alternation." It is
that OMV built draw-scoped ownership around an address that is not proven to be
a draw scope:

1. `BSShader::SetShaders @ 0x00BE1F90` is the native shader-handle binding
   boundary. Both NVR generations complete replacement selection there or at
   the equivalent native pass setup and let `NiDX9RenderState` remain
   authoritative.
2. OMV publishes a pending pair there, but postpones sampler and constant work
   to `0x00E812F0`.
3. Static executable proof shows that `0x00E812F0` prepares geometry resources,
   calls vertex/index buffer helpers, binds streams, and binds indices. Its
   body contains no primitive draw call.
4. OMV nevertheless calls this the common shader "draw" hook, uploads
   draw-specific constants before the native resource method, and calls its
   finish logic when that method returns. A primitive submission is not
   statically bracketed by that before/after pair.
5. The same code address is published by at least PPLighting, TallGrass,
   SpeedTreeLeaf, and SpeedTreeBranch vtables. OMV therefore visits
   exterior-heavy resource submissions unrelated to a pending PBR or sky draw,
   while the address is not universal across all shader classes.

That boundary error matters independently of performance. A rejected
close-terrain evaluation can bind the native pair and then restore the
cache-owned replacement when `0x00E812F0` returns, before any separately owned
primitive submission. Likewise, constants uploaded before the original
resource method are not proven to be the last constant values before the draw.
The source comments that describe a DIP-bracketing scope are therefore stronger
than the executable evidence supports.

The first amplifier is hidden hot-path CPU and driver-interface work:

- `backend::d3d_device_ptr()` reads two engine pointers through
  `validate_memory_range`, hence two `VirtualQuery` calls per lookup;
- every PBR family bind path performs that lookup. A rejected path can perform
  it again to bind fallback, and close-terrain finish can perform it again to
  restore the replacement;
- a new close-terrain geometry can query up to fourteen texture stages through
  `IDirect3DDevice9::GetTexture`. Each successful query returns an owned COM
  reference which OMV immediately releases;
- admitted sky performs two device shader getters, one or two texture getters,
  raw replacement binds, another checked device lookup, and raw native restores;
- the engine's own `SetTexture @ 0x00E88A20` suppresses redundant device calls
  through its cache, but OMV's entry detour performs tracking before that native
  equality check. Device-vtable counters therefore undercount OMV detour visits.

The second amplifier is close-terrain work omitted from the original ranking.
For a geometry-cache miss, OMV can inspect 25 native pass-light entries, walk up
to 64 property lights, consult up to 64 already-published manager lights,
perform geometry/multibound calculations, and select up to 24 supplemental
lights. It then uploads two terrain rows, one count row, and two rows per
supplemental light: 3 to 51 pixel-constant rows in one call. The scan is cached
per geometry, but the constant block is deliberately uploaded on every
`0x00E812F0` evaluation. Neither healthy NVR source adds this geometry-level
admission and light-reconstruction path.

The broad world/image transaction graph remains a co-leading driver-facing
candidate. With four MRT slots, one ordinary screen transaction performs five
attachment getters, up to thirteen attachment clear/restore setters before
effect-specific target changes, one `D3DSBT_ALL::Capture`, and one
`D3DSBT_ALL::Apply`. The getters return owned COM references. OMV repeats this
ownership pattern at several semantic stages. NVR's D3DX effects also save and
restore effect-modified state, so "NVR has no state blocks" would be false; the
difference is OMV's repeated broad all-state plus explicit attachment ownership
at multiple engine boundaries.

The most likely root-cause cluster is consequently:

1. the incorrect and overly broad `0x00E812F0` ownership boundary;
2. per-evaluation Windows memory validation, D3D state readback, and COM
   reference churn at that boundary;
3. exterior-multiplied terrain light reconstruction and constant uploads;
4. interaction with fragmented all-state/attachment/copy transactions.

This cluster explains the scene and vendor shape better than depth, RESZ,
shader code, live vtable patching, or raw copy count alone. Exterior scenes
multiply the exact PPLighting/grass/SpeedTree and close-terrain work above.
Driver getters, shader/constant setters, state blocks, attachment changes, and
copy dependencies all enter the Windows D3D9/NVIDIA path, so vendor-specific
amplification is plausible. The exact NVIDIA wait or serialization remains an
inference until an affected-machine trace times these named owners.

Copy reduction is still mandatory, but copy count is not a sufficient root
cause. A measured healthy NVR run issued 47 to 66 `StretchRect` attempts and
four RESZ triggers per gameplay frame. In its fully attributed region, 49
copies succeeded, 45 were full-resolution, and their logical read/write payload
was about 3.21 GB per frame at 3440x1440. That evidence directs optimization
toward duplicate ownership, dependency placement, and surrounding state work.

The inline-hook jump/trampoline machinery itself remains a weak steady-state
suspect. `InlineHookContainer::original()` reads a `OnceLock`-published pointer
without taking the mutation lock. The decisive differences are the semantic
targets, detour coverage, detour work, chain order, and partial installation
behavior.

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

The inspected OMV source is the tree introduced by:

```text
e4283928b12c90c67fe3ec38f727aea508fae7dd
2026-08-04T01:07:00+03:00 perf(omv): use engine-owned render hooks
```

The first revision of this document was committed separately as
`71c8648e082c1191d6613c5f4c75ad6b5118317d`; that documentation-only commit did
not change the inspected OMV source. The worktree contained unrelated
user-owned changes in `libnvse/xnvse` and `intelmoc/`; no OMV source file was
dirty before either research pass.

Relevant inspected-file SHA-256 values are:

```text
df245ddd8db23e3ad81e6543594f6a505dfcd915622d0aec5af19dfec16cd053  omv/src/hooks.rs
a052a51ad662e6d159fbe49148b06bf0d158cb6a1bef1c0c5e0f47dfaf69bf1d  omv/src/fnv_render.rs
920d91dd828412ce16f48c194d7860132ac604e92fad57b7522b962b440a2160  omv/src/runtime.rs
```

The supported executable contract remains Fallout New Vegas PE32 x86, image
base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The second pass reopened this exact executable through the repository-required
radare2 interface and analyzed the focused targets. The relevant direct proof
is:

- `0x00BE1F90` reads the current pass at `0x0126F74C`, obtains the vertex
  wrapper handle from pass `+0x5C`, obtains the pixel wrapper handle from pass
  `+0x44`, and calls the render-state shader setters;
- `0x00E88A20` compares the requested texture against the cached stage pointer
  at render-state `+0x10A0 + stage * 4`, returns on equality, and calls the
  device `SetTexture` slot only on change;
- `0x00E812F0` is 297 bytes, calls `0x00E6D760`, `0x00E6D780`, and
  `0x00E71FE0`, then issues `SetStreamSource @ 0x00E813F4` and
  `SetIndices @ 0x00E8140E`. It contains no direct primitive draw call;
- `0x00E6D780` and `0x00E71FE0` are geometry buffer preparation/packing paths;
  their downstream `0x00E8F200` path contains
  `NiDX9IndexBufferManager::CreateIndexBuffer` and `PackBuffer` failure
  strings, not a primitive submission.

The radare2 result agrees with the durable static artifacts already stored at:

- `analysis/ghidra/output/perf/graphics_fnv_pbr_shader_handle_getter_setshaders_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_pbr_shader_virtual_interface_followup_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_pbr_continuity_draw_resource_contract_closure.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_atmosphere_alpha_coverage_composition_contract_audit.txt`.

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

The observer's negative evidence has important limits which the original
revision did not state strongly enough. It hooked selected
`IDirect3DDevice9` vtable methods: setters, draws, copies,
`BeginStateBlock`/`EndStateBlock`, reset, and related calls. It did **not**
observe:

- `GetTexture`, `GetRenderTarget`, `GetDepthStencilSurface`, `GetVertexShader`,
  or `GetPixelShader`;
- `IDirect3DStateBlock9::Capture` or `IDirect3DStateBlock9::Apply`, which are
  methods on a different COM interface;
- engine-level `SetTexture` requests which the native render-state cache
  rejected before reaching the device;
- `VirtualQuery`, `VirtualProtect`, or CPU work inside an engine detour.

The observer therefore proves that NVR tolerates high submitted command and
copy volume. It does not prove that OMV's state readbacks, COM-reference churn,
all-state `Capture`/`Apply`, or Windows memory-validation calls are cheap. The
observer's own first version is direct counterevidence: merely validating the
device pointer with `VirtualQuery` after each frame made that diagnostic run
unsuitable as a performance sample. Current OMV performs the same class of
validation at much hotter PBR boundaries.

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

The proxy is declared as `IDirect3DDevice9Ex`, but its New Vegas hook calls the
base `CreateDevice` method. Modern NVR's inactive version does the same, with
`CreateDeviceEx` present only as a commented alternative. OMV does not create
or replace the game device at all. Consequently, D3D9 versus D3D9Ex creation
mode is not a source-proven difference between healthy NVR and failing OMV; all
normal paths consume the engine-created device and its existing flags.

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
with flags `0`. Microsoft's D3DX contract says that default `Begin` captures
the pipeline state the technique can change and `End` restores it. NVR is
therefore not "state-block free"; its save/restore is scoped to effect
techniques and clustered inside NVR's image-space owners rather than wrapped in
OMV's separate all-state plus attachment transactions.

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

`src/NewVegas/Hooks/ShaderIO.cpp:52-59` also owns shader-package selection at
its semantic boundary. It calls native `SetShaderPackage` and then writes the
current/max package globals to package 7 once for that engine operation. It
does not revalidate and change page protection for those globals every frame.
Legacy NVR's analogous New Vegas hook is commented out and does no per-frame
package write. This makes OMV's frame-service package forcing a third, distinct
lifecycle difference rather than a shared NVR requirement.

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
6. **Replacement admission uses engine-owned identities.** Modern NVR reads
   current shaders through `NiDX9RenderState`, compares the selected handle,
   and uploads a record's constants only when that selected handle changes. It
   does not poll as many as fourteen device texture stages for every new terrain
   geometry or rediscover the D3D device through checked process-memory reads.
7. **Image-space effects are clustered around native image-space ownership.**
   NVR wraps `ProcessImageSpaceShaders` and performs its pre/post work there.
8. **Depth capture is tied to semantic engine stages.** World and first-person
   hooks select the contents; RESZ/NvAPI is only the transport.
9. **Stable package state is owned at setup.** Modern NVR forces package 7 after
   native `SetShaderPackage`; legacy NVR does not force it. Neither healthy
   source rewrites protected package globals on every rendered frame.
10. **Heavy submitted command volume is tolerated.** Working NVR can issue
    thousands of state calls/draws and dozens of full-resolution copies.
    Compatibility cannot be reduced to minimizing one setter or copy counter.
    This does not exonerate unobserved getters, COM-reference churn,
    `IDirect3DStateBlock9::Capture/Apply`, or Windows VM queries.

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
| core | shared shader geometry/resource method `@ 0x00E812F0` | PPLighting and other classes sharing this implementation | PBR/sky late admission, currently labelled as draw ownership |
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

The two most important hot entries are the shared `0x00E812F0` hook and
`SetTexture`. The NVR observer's roughly 2,000 or more draws per representative
frame establishes scene scale but is not a count of `0x00E812F0`. Likewise, its
device `SetTexture` counter is a lower bound for OMV's engine `SetTexture`
detour: the engine method can return on a cache hit without calling the device,
but OMV's tracking runs before that equality check. Current OMV telemetry does
not count production visits to either entry, so exact affected-machine volume
remains open.

### Exact executable semantics of the three shader hooks

The second-pass binary trace distinguishes three boundaries that the first
revision blurred together.

`BSShader::SetShaders @ 0x00BE1F90` is 82 bytes and is a genuine shader bind
boundary. It reads `0x0126F74C`, obtains the vertex wrapper from pass `+0x5C`,
calls its handle getter, and sends the result through the render-state vertex
shader setter. It repeats the sequence for the optional pixel wrapper at pass
`+0x44`. The engine cache and its device setter are therefore authoritative at
this exact point. The same address appears in 81 shader-class vtable data
references in the durable handle audit; it is the broad engine boundary used by
modern NVR.

`NiDX9RenderState::SetTexture @ 0x00E88A20` is a cache-aware setter. Its first
instructions compare the requested pointer with the per-stage cached pointer at
`this + 0x10A0 + stage * 4`; equality returns immediately. Only a change updates
the cache and invokes the device `SetTexture` slot. OMV hooks the function
entry, records the requested pointer, then calls native. It therefore converts
even a native cache hit into OMV atomic/tracking work.

`0x00E812F0` has different semantics. Its four parameters feed geometry and
buffer-building paths. It can create or obtain geometry buffer state, loops
over stream records and calls `SetStreamSource`, then calls `SetIndices` and
returns a resource/cookie pointer. Direct and focused downstream inspection
finds buffer packing and index-buffer creation, but no primitive draw in the
scope OMV wraps.

Durable vtable evidence proves this implementation at slot 27 (`+0x6C`) for:

- PPLighting selector vtable `0x010AF2F8`;
- TallGrassShader vtable `0x010B8980`;
- SpeedTreeLeafShader vtable `0x010B9190`;
- SpeedTreeBranchShader vtable `0x010BC070`.

This list is a proven minimum, not a claim that only four classes share the
code. Conversely, the executable contains other slot-27 implementations, so
`0x00E812F0` is not universal. The accurate description is "shared
geometry/resource submission implementation," not "every shader-backed draw."

### Hook mechanics and chaining

`libpsycho/src/os/windows/hook/inline/inlinehook.rs:475-582` prepares a
trampoline and publishes its callable pointer through `OnceLock` before enable.
The hot `original()` call does not acquire the container's `RwLock`. Enabled
x86 hooks use a five-byte relative jump and a trampoline, conceptually the same
steady call shape as a Detours entry hook.

The meaningful installation differences are:

- NVR groups related attachments into a Detours transaction and calls
  `DetourUpdateThread(GetCurrentThread())`;
- OMV prepares/enables its inline hooks individually. The scene-depth
  reconciliation has explicit best-effort rollback, and the two shader-creation
  hooks roll back their first member when the second fails, but the three core
  hooks do not form one rollback transaction;
- `install_engine_hooks()` can therefore leave DisplayScene or Recreate enabled
  if enabling a later core hook fails. The readiness flag stays false, but the
  executable mutation is partial;
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

One source comment should not be used as evidence: `Device9Ref::from_raw_void`
does not validate a COM vtable or call `QueryInterface`. It only rejects a null
pointer and constructs a borrowed interface reference. The core renderer helper
and several logs call the result "validated," but source inspection proves only
non-null conversion. This is primarily a safety/documentation gap. Performance
validation happens earlier in the separate `backend::d3d_device_ptr()` helper,
where it costs `VirtualQuery` calls without proving the pointed object is an
`IDirect3DDevice9`.

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

The ownership then diverges at `omv/src/effects/pbr/hooks.rs:567-724`:

1. OMV temporarily writes replacement handles into the vertex and pixel
   wrappers;
2. it calls native `SetShaders`, so `NiDX9RenderState` caches/binds the
   replacement pair;
3. the temporary scope restores both wrapper fields to native handles;
4. OMV publishes a pending draw descriptor in atomics;
5. later, the shared `0x00E812F0` geometry/resource hook calls
   `prepare_direct_draw()`;
6. that function validates wrapper identity, sampler availability, geometry,
   and constants;
7. if rejected, OMV binds the native shaders directly on the device;
8. selected paths restore the engine-cache-owned replacement when the resource
   method returns or at the frame boundary.

This deliberately creates a period where the engine cache owns the replacement
identity while the wrapper field again exposes the native identity. OMV's code
contains repair logic for that split state. More importantly, the repair scope
assumes that `0x00E812F0` returns after a primitive draw. The executable only
proves that it returns after geometry buffer preparation and stream/index
binding. Thus the names `prepare_direct_draw`, `finish_direct_draw`, and
`direct_draw_requires_finish` encode an unproven timing contract.

For admitted object, LandLOD, TerrainFade, and CloseTerrain work,
`prepare_direct_draw` calls a family binder. Every family binder obtains the
device through `crate::backend::d3d_device_ptr()`. That helper:

1. validates and reads the global renderer pointer;
2. validates and reads `renderer + 0x288`;
3. returns the non-null device pointer.

Both validations call `validate_memory_range`, and that function calls
`VirtualQuery`. An ordinary evaluated family path therefore performs at least
two `VirtualQuery` calls before its D3D work. A rejection after device
acquisition calls `bind_native_fallback`, which obtains the device again. A
close-terrain finish that restores the replacement can obtain it a third time.
Depending on the rejection point, one resource-method visit can therefore
produce two, four, or six VM-query calls. Neither NVR source does checked
process-memory discovery at its replacement boundary; both retain the renderer
and device established during initialization.

Close terrain is the largest multiplier. Its 56 supported pass/pixel rows map
to one through seven material textures. The required sampler mask contains
stages `0..texture_count` and `7..7+texture_count`, so a seven-layer row requires
fourteen stages. When the geometry pointer changes, or when the `SetTexture`
hook is unavailable, `missing_sampler_mask_from_bits` calls `GetTexture` once
for every required stage. Microsoft's D3D9 contract states that a successful
`GetTexture` increases the returned texture's internal reference count. The
Rust Windows interface owns that returned reference; `texture_raw` extracts the
identity and immediately drops it. A fully populated seven-layer geometry
therefore causes fourteen `GetTexture`/AddRef/Release cycles solely to prove
presence.

The geometry-change condition is reset by every accepted close-terrain
`SetShaders` and the pending evaluation is re-armed whenever `0x00E812F0`
returns. Calling this "once per DIP" is not proven: it is once per observed
resource-method evaluation and can be once per new geometry in the intended
path.

The same geometry-cache miss invokes `terrain_lights::capture_current_for_draw`.
On a miss it can:

- read as many as 25 identities from the native render-pass light array;
- build the geometry transform and optional multibound shape;
- call the engine's first/next property-light iterator up to 64 times;
- test candidates and, when membership is still incomplete, inspect the
  published manager snapshot containing up to 64 terrain lights;
- deduplicate and transform as many as 24 supplemental point lights.

The light scan is cached for repeated resource-method visits with the same
geometry address and invalidated by `SetShaders` and frame cleanup. Constant
upload is not cached. Every close-terrain evaluation constructs two terrain
rows plus a count row and two rows per selected light, then makes one
`SetPixelShaderConstantF` call. The range is three rows with no supplemental
light through 51 rows with 24 lights. This is additional work beyond the
native pass constants and beyond NVR's handle-change-driven `ShaderRecord::SetCT`.

This design has no counterpart in either NVR source. It can combine CPU-bound
engine traversal with OS memory queries, D3D getters, COM reference traffic,
large constant setters, and raw shader fallback/restoration in the same dense
exterior path. Existing telemetry reports logical replacement/fallback counts,
but no stored current NVIDIA record measures any of those individual costs.

The `SetTexture` detour at `pbr/hooks.rs:1402-1455` records every engine request
while replacement is configured and updates the pending required/missing
sampler masks. In ordinary diagnostics-off mode, each valid stage still causes
a release store to the tracked texture slot plus detailed-mode checks and
pending-mask loads. It does this before native reaches its equality return at
`0x00E88A20`. A passive PBR configuration bypasses this work, but an active
configuration can see more detour visits than actual driver `SetTexture` calls.

The common resource hook's disabled path also needs a precise distinction. If
the global OMV master is off, `runtime::effects_enabled()` forwards directly.
If the master is on but PBR is configured off or not yet ready,
`pbr::prepare_direct_draw` calls `release_device_resources()` on every shared
method visit. With no pending pair that function still writes the fallback
flag, kind, evaluated flag, and six pending-pair atomics. It is not a single
passive branch. This is a plausible contributor to a disabled-baseline ceiling,
although it remains too vendor-neutral to explain one FPS by itself.

### Native sky replacement flow

The sky hook captures the native shader pair and publishes a pending sky
operation. At `omv/src/effects/sky.rs:449-470` the shared resource hook tries to
bind it. The late path:

- takes nonblocking settings/frame-state locks;
- reacquires the device through two checked pointer reads;
- calls device `GetVertexShader` and `GetPixelShader` through
  `current_*_shader_raw` to verify native identities;
- calls `GetTexture` for one or two required stages;
- uploads constants;
- binds raw replacement shaders;
- reacquires the device through two more checked pointer reads;
- restores native shaders when `0x00E812F0` returns (`sky.rs:1165-1180`).

Sky draw count is small compared with terrain, so this is unlikely to create
one FPS alone. It reinforces both defects: OMV owns replacement transitions
after engine pass setup and calls its restore point a completed draw even
though the wrapped body does not submit a proven primitive.

### Per-frame shader-package mutation

PBR activation patches the shader-package destruction branch once, which
matches modern NVR's stable lifetime patch. OMV then adds a different recurring
operation. `engine_contracts::service_frame()` calls
`force_nvr_shader_package()` on every serviced configured PBR frame. It writes
the current and maximum package globals separately through `write_u32`.

Each `write_u32` performs one `VirtualQuery` through `readable_range` and then
uses `with_writable_memory`, which changes the page to `PAGE_READWRITE` and
restores the previous protection with two `VirtualProtect` calls. The pair of
four-byte writes therefore costs two `VirtualQuery` and four `VirtualProtect`
calls per serviced PBR frame even when both globals already equal 7.

Modern NVR instead writes both globals after native `SetShaderPackage`, and
legacy NVR does not force them. The OMV path is proven needless steady-state OS
work and a lifecycle ownership mismatch. It is unlikely to create exterior-only
one FPS alone, but it belongs in the hook rework and in disabled/baseline
measurement.

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

That correctness does not make the transaction cheap. Let `N` be the normalized
MRT slot count, from one through four. An ordinary admitted screen transaction
has this attachment-only baseline:

- capture: `N` `GetRenderTarget` calls plus one
  `GetDepthStencilSurface` call;
- prepare target change: one depth detach plus `N - 1` auxiliary RT clears;
- restore: one depth detach, `N - 1` auxiliary clears, one RT0 bind,
  `N - 1` auxiliary restores/clears, and one depth restore.

That is `N + 1` getters and `3N + 1` attachment setters before the new RT0 bind
inside the effect and before effect-specific changes. At `N = 4`, the baseline
is five getters and thirteen setters, followed by one all-state capture and one
all-state apply. A final/menu transaction which does not change target can skip
the prepare step, but still captures and restores attachments.

The getters are not simple borrowed pointer reads. Microsoft's D3D9 contract
states that `GetRenderTarget` and `GetDepthStencilSurface` increase the returned
surface's internal reference count. OMV holds those owned references for the
transaction and releases them afterward. This is correct COM ownership, but it
adds device getter, AddRef, and Release traffic. Several such transactions can
run in one frame.

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

The world snapshot receives RT0 from the proven world target instead of calling
`GetRenderTarget(0)`, but unconditionally calls the three auxiliary RT getters
and the depth getter. Its fixed restore is nine attachment setters. Thus each
world atmosphere/TAA transaction still adds four device getters, up to four
owned COM references, nine restore calls, one all-state capture, and one
all-state apply before the effect's target operations.

### Why `D3DSBT_ALL` remains a serious candidate

An all-state capture/apply is a driver-facing request over a much larger state
domain than the bounded RESZ snapshot. It can require the driver to enumerate,
retain, and reapply many states that OMV does not touch. OMV can execute it at
several points per frame and surround it with target/depth changes and
full-resolution dependencies.

Microsoft's documented `D3DSBT_ALL` state includes shaders and constants,
textures, vertex streams, index buffer, viewport, scissor, transforms, clipping
planes, material, and the full pixel/vertex state groups. Render targets and
depth are absent from that documented list, which is why OMV's separate
attachment owner is necessary. NVR's `Effect->Begin(..., 0)` also uses state
blocks, but the D3DX contract captures the state the active technique can
change. The two mechanisms therefore cannot be equated by counting only
`BeginStateBlock` calls.

The healthy-NVR observer did not hook `IDirect3DStateBlock9::Capture` or
`Apply`, nor any attachment getter. Its high setter/copy counts cannot reject
this candidate. A current comparison needs named timings for the interface
methods OMV actually calls.

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

### Resource creation and lifetime audit

The second pass found no steady per-draw render-target or shader creation loop.
This materially weakens allocation churn as the primary cause.

Screen-runtime phase resources are lazy and description-keyed:

- each of scene-pre, scene-post, and final can retain one color copy and one
  scratch copy;
- the runtime can retain a separate world-color copy;
- `ensure_phase_color_copy` and `ensure_world_color_copy` create only when the
  slot is absent or width, height, or format changes;
- the runtime `D3DSBT_ALL` object is created once and reused until visual/device
  resource release.

The focused world pipeline separately retains one atmosphere world-color copy
and one reusable state block. TAA retains one current target, two FP16 color
histories, and two R16F depth-key histories. Those five targets are recreated
only when the target description changes. Other effects retain their own
bounded intermediates and release them on master-off, reset, or device change.

Native PBR and sky shader objects are also warm-up resources. Their service
paths create at most four ready shader objects per frame, retain successes, and
latch individual failures. Creation is outside `SetShaders` and
`0x00E812F0`. No source path continuously retries a successfully created shader
on a stable device.

The retained resource set can still produce residency pressure, especially at
high resolution and FP16, and duplicate world-color/phase ownership remains
waste. A residency or allocation-loop explanation now requires evidence of one
of these conditions:

- repeated device identity changes;
- target width/height/format oscillation;
- reset/recreate churn;
- a creation failure path that is not actually latched;
- OS/driver eviction despite stable OMV ownership.

None is present in the stored critical interval. Resource pressure remains an
open fallback candidate; steady resource *creation* is not visible as the
current root.

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
| D3D9/Ex choice | consume engine device; debug proxy is typed Ex but calls base `CreateDevice` | inactive hook calls base `CreateDevice`; `CreateDeviceEx` commented | consume engine device; does not choose creation API/flags |
| Renderer acquisition | hook native initializer, initialize after original | same | read published renderer/device after DeferredInit; lazy identity checks |
| Hook installation | one-time Detours transactions | one-time Detours transaction plus static patches | individually prepared inline hooks; some physical runtime reconcile; core group can partially enable on failure |
| Existing-hook chaining | Detours predecessor chaining | Detours predecessor chaining | vanilla or one near-jump destination for PBR/sky; fixed targets elsewhere |
| Shader selection | wrapper permanently contains replacement | wrapper selected before native `SetShaders` | wrapper overridden only during native `SetShaders` |
| Engine cache authority | native setup | native `SetShaders` | native `SetShaders`, followed by OMV late resource-time validation/fallback |
| Late replacement detour | none | none | shared `0x00E812F0` geometry/resource method, incorrectly treated as a DIP scope |
| Proven late-hook class coverage | none needed | none needed | at least PPLighting, TallGrass, SpeedTreeLeaf, SpeedTreeBranch; not universal |
| Texture-bind detour | none for FNV replacement | none; sampler-state detour exists | `NiDX9RenderState::SetTexture` for PBR tracking |
| Redundant engine texture requests | native cache returns before device call | same native cache | OMV tracking runs before native equality return |
| Device acquisition in replacement path | retained renderer/device | retained renderer/device | two `VirtualQuery` calls per `d3d_device_ptr()` lookup |
| Close-terrain late admission | no equivalent | no equivalent | up to 14 `GetTexture`; 25 pass lights; 64 property lights; 64 manager lights; 3-51 constant rows |
| Raw shader bind after pass setup | not for normal replacement selection | not for normal replacement selection | PBR fallback/restore and every admitted sky replacement |
| Shader-package forcing | no active New Vegas force hook | two plain writes after native `SetShaderPackage` | two `VirtualQuery` plus four `VirtualProtect` calls per serviced PBR frame |
| Image-stage owner | `ProcessImageSpaceShaders` wrapper | `ProcessImageSpaceShaders` wrapper | same wrapper plus separate world/pre-alpha/post-world/present owners |
| State restoration | direct/D3DX effect-managed save/restore | engine state plus D3DX effect-managed save/restore | explicit repeated all-state plus attachment transactions |
| Attachment readback | direct current-group ownership at focused stages | same | 4-5 device getters and owned COM references per world/screen transaction |
| World color resources | shared source/rendered effect buffers | shared source/rendered effect buffers | phase pairs plus separate runtime-world and atmosphere-world copies |
| Depth transport | RESZ else NvAPI | RESZ else NvAPI | external borrow, NvAPI alias/copy, or bounded RESZ |
| Reset handling | no complete path found | no complete path found | explicit engine Recreate hook |

## Root-cause assessment

### Candidate 1: wrong semantic boundary at `0x00E812F0`

**Priority: highest. Evidence strength for the defect: high. Evidence strength
as the complete NVIDIA cause: medium.**

Why it fits:

- executable code contradicts OMV's "immediately surrounds the native draw"
  contract: the wrapped body binds geometry resources, streams, and indices but
  contains no primitive submission;
- close-terrain fallback restoration and sky native restoration run when that
  resource method returns, not at a proven post-draw instruction;
- draw-specific constants are uploaded before native resource preparation and
  are not proven to be the last values before submission;
- the address is shared by exterior-heavy PPLighting, grass, and SpeedTree
  classes, multiplying detour visits in the exact bad scene type;
- the address is not universal, so its state machine can both over-interpose
  unrelated classes and fail to represent every draw;
- neither healthy NVR source needs this second boundary.

What is already proven is sufficient to require a later redesign even if it is
not the sole FPS cause. What remains unproven is how often the method executes
per affected frame and which actual primitive call follows each invocation.

Required proof:

- count `0x00E812F0` visits by shader class and correlate them with actual
  primitive submissions;
- statically close the caller chain from each relevant slot-27 call to the
  eventual DIP before selecting any replacement boundary;
- in a later authorized A/B, keep selection and constants at a proven engine
  boundary and remove the false draw-scope state machine without reducing PBR
  coverage.

### Candidate 2: per-evaluation VM queries and D3D getter/COM churn

**Priority: highest. Evidence strength for work: high. Evidence strength for
vendor amplification: medium.**

Why it fits:

- all PBR family binders call a device lookup containing two `VirtualQuery`
  calls; fallback/restore can repeat the lookup in one visit;
- a seven-layer close-terrain geometry adds fourteen `GetTexture` calls and
  immediate AddRef/Release pairs;
- sky adds device shader getters, texture getters, two checked lookups, and raw
  bind/restore calls;
- screen/world transactions add four or five attachment getters with owned
  COM references;
- all of this work is absent from the NVR replacement boundary and invisible
  to the prior healthy-NVR observer;
- the bad path is exterior-multiplied and crosses the native Windows D3D9
  runtime/driver interface, where vendor cost can differ.

Why it is not the complete proof:

- `VirtualQuery` itself is CPU/OS work and should not intrinsically depend on
  GPU vendor;
- D3D9 getters are valid and do not have a documented mandatory GPU flush;
- no affected-machine sample separates time in the VM queries, COM getters,
  AddRef/Release, setters, or a driver wait they may expose.

The former "hottest PBR reads avoid VirtualQuery" conclusion was false and is
withdrawn.

### Candidate 3: close-terrain light reconstruction and constant cadence

**Priority: highest for exterior CPU/driver-call amplification. Evidence
strength for work: high. Exact one-FPS attribution: unproven.**

The per-geometry cache miss can combine 25 native light identities, 64 engine
iterator steps, a 64-entry manager snapshot, geometry transforms,
multibound tests, deduplication, and up to 24 light encodings. The upload is 3
to 51 float4 rows and occurs on every evaluated `0x00E812F0` visit, even when
the light scan hits its geometry cache.

This is distinct from the once-per-world-light-epoch scan of up to 512 scene
lights. Both run in an exterior PBR configuration. NVR updates its replacement
constant table when the selected shader handle differs from cached state; it
does not reconstruct missing terrain-light membership for every geometry.

Pure arithmetic should not be NVIDIA-specific, but the final constant setter is
driver-facing and can compound a render-thread CPU bottleneck or a driver wait.
The affected-machine trace must time scan and upload separately.

### Candidate 4: fragmented all-state/attachment/copy transactions

**Priority: highest as a driver-facing co-cause. Evidence strength: medium.**

Why it fits:

- the broad transaction repeats across more semantic boundaries than NVR;
- a four-MRT screen transaction adds five getters, thirteen attachment
  setters, all-state Capture/Apply, and effect target work;
- a world transaction adds four getters, nine restore setters, and all-state
  Capture/Apply;
- getters and state-block interface calls were blind spots in the healthy-NVR
  observer;
- copies/resolves inside those scopes add explicit read-after-render
  dependencies;
- state handling and dependency resolution are driver-facing and can be
  vendor-sensitive.

Why it is not proven:

- NVR's D3DX effects also save and restore effect-modified state;
- no timing separates state block, getters, attachment changes, copy, and draw;
- valid state blocks should not normally cost a second, so the candidate is
  the repeated broad transaction and its interaction, not the API name alone.

Required proof is named CPU/GPU timing of attachment capture, state capture,
target preparation, copies/draws, attachment restore, and state apply at every
admitted boundary.

### Candidate 5: interaction of candidates 1 through 4

**Priority: highest as the likely complete failure mode. Evidence strength:
medium as a source model, low for the proprietary-driver mechanism.**

OMV can make the engine cache own a replacement while wrappers expose native
handles, enter the false draw boundary, query VM and D3D state, reconstruct
terrain lights, upload constants, alternate native/replacement pairs on
fallback, and later capture/apply the full device state around multiple image
transactions. NVR keeps replacement selection stable at native pass setup and
clusters image work at fewer semantic owners.

The combination best explains why removing device-vtable hooks and changing
depth transport did not fix the issue. A specific claim that NVIDIA flushes or
recompiles at one of these calls remains inference until a Windows/NVIDIA trace
shows the long interval.

### Candidate 6: duplicate and misplaced full-resolution copies

**Priority: mandatory optimization. Evidence strength for inefficiency: high.
Evidence strength as sole one-FPS root: low.**

Proven waste includes separate atmosphere/runtime world-color ownership when
their required contents coincide and any nonzero steady fallback-commit rate.
Seven full-resolution copies at 4K FP16 represent about 886 MiB of logical
read/write traffic per full frame, before depth and reduced histories.

The healthy NVR observer rejects a copy-count-only theory. The actionable
hypothesis is that an OMV copy creates a dependency at a harmful fragmented
boundary, not that seven copies are intrinsically worse than NVR's measured 49
successful copies.

### Candidate 7: per-frame protected package writes and passive bookkeeping

**Priority: medium for baseline CPU cost, low as the sole exterior/vendor
cause. Evidence strength: high.**

Two `VirtualQuery` plus four `VirtualProtect` calls per serviced PBR frame are
unnecessary after package 7 is stable. When the OMV master remains on but PBR
is off/not ready, every shared resource-method visit can also clear nine PBR
atomics. These are concrete hot-path inefficiencies and differ from NVR.

Their frequency does not naturally explain an exterior-only NVIDIA collapse,
but they can lower the disabled/interior baseline and consume render-thread
budget before driver work. They must be removed or measured independently in a
later authorized change.

### Candidate 8: hook chaining, partial installation, and runtime mutation

**Priority: medium for correctness, lower for steady performance. Evidence
strength: low for one FPS.**

OMV's one-hop PBR/sky redirect policy differs from Detours predecessor
chaining, existing shader hooks are proven in the historical log, and the core
hook group can partially enable if a later member fails. Four scene hooks can
also change physical ownership after startup under a quiescence assumption.

This can cause duplicate work, missed predecessors, or partial lifecycle state.
It does not naturally explain a stable vendor-specific floor after a fully
successful install. One-time resident, transactionally installed hooks remain
the correct convergence target for compatibility.

### Candidate 9: resource pressure and residency

**Priority: medium-low. Evidence strength: low.**

OMV retains multiple full-resolution phase textures, duplicate world-color
owners, five TAA targets, depth targets, and effect intermediates. This can be
large at FP16/high resolution. Counterevidence is the 2560x1440 reproduction,
healthy NVR's large resource set, and the lack of a steady creation loop in
current OMV. Residency remains open only with eviction/device/description
oscillation evidence.

### Candidate 10: device initialization or reset ownership

**Priority: low for steady one FPS, high for lifecycle correctness.**

OMV initializes after DeferredInit and discovers the published device lazily;
NVR hooks renderer initialization. OMV's explicit Recreate ownership is
otherwise stronger. Current logs show no reset loop, device identity churn,
repeated target creation, or persistent D3D errors in the steady critical
interval.

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

### D3D9 versus D3D9Ex device creation

Rejected as a source-proven differentiator. Both NVR snapshots consume the
engine-published device in their normal paths. The optional legacy proxy is
typed around D3D9Ex interfaces but calls base `CreateDevice`, while modern
NVR's inactive hook also calls base `CreateDevice` and leaves its
`CreateDeviceEx` path commented. OMV does not create the engine device at all.
The supplied sources therefore do not establish a healthy-NVR D3D9Ex creation
mode that OMV is missing.

### Steady resource-allocation churn

Materially weakened by the lifetime audit. Current screen, world, TAA, depth,
and shader resources are description- or device-keyed and retained after warm
up. The source does not show an ordinary per-frame recreation loop. Resource
residency remains open, but an allocation-churn theory now requires runtime
evidence of device changes, target-description oscillation, reset loops,
unlatched failure retries, or driver eviction.

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

The target architecture must stop treating `0x00E812F0` as a draw bracket. The
proven common owner is `BSShader::SetShaders`; the exact geometry-aware owner is
not yet statically closed. A later design should separate those facts:

1. choose the native or replacement pair at a proven selector/pass boundary;
2. make the wrapper and `NiDX9RenderState` cache agree on that identity;
3. gather geometry-specific sampler/light inputs at a proven class-specific
   setup boundary, not by assuming slot 27 encloses a draw;
4. upload constants at a point proven to precede the actual primitive without
   an intervening owner that can overwrite them;
5. let native render state perform the final cached device bind wherever
   possible;
6. keep the selected pair stable through the actual primitive, then change it
   at the next proven selector/pass boundary.

OMV's per-geometry terrain requirements mean this cannot be copied verbatim
from NVR. The caller chain from each relevant shader class to the actual
`DrawPrimitive`/`DrawIndexedPrimitive` call must be closed before choosing the
geometry/constants hook. The research conclusion is to remove split ownership,
not to guess a new address, delete validation, or weaken fail-closed fallback.

If a late primitive hook remains necessary for one narrow family, its caller,
class coverage, constant lifetime, and post-draw restoration point must all be
proven. It must not be installed as a nominal universal draw hook merely
because several shader vtables share the same resource method.

### Remove discovery and readback from render-hot admission

NVR retains the renderer/device established after native renderer
initialization. A later OMV design should likewise publish a device identity at
a lifecycle boundary and invalidate it at `Recreate`, instead of rediscovering
it through checked process-memory reads for each family evaluation. Safety
validation belongs at publication/replacement, not at every draw candidate.

Sampler admission should use state already observed at the engine setter or a
bounded class-owned material contract. It should not issue fourteen device
`GetTexture` calls merely to recover state that the engine cache and OMV's own
setter hook have already seen. Any fallback query must be exceptional,
measured, and outside the common geometry path.

The same rule applies to shader getters and attachment state: capture an owned
snapshot once per actual transaction, avoid repeated raw bind/restore cycles,
and do not use a getter as routine validation when a stable engine identity is
available. This recommendation removes Windows VM queries and COM reference
traffic; it does not assume that a D3D getter is intrinsically invalid.

### Move stable package ownership out of the frame loop

Package 7 is stable configuration state, not per-frame render state. A later
rewrite should own it at the native `SetShaderPackage` transition, as modern
NVR does, or prove a different lifecycle callback that covers load/reload.
Render servicing must not perform page queries and two protection transitions
for values that already equal the desired package.

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

- shared `0x00E812F0` resource-method visits, classified by shader vtable and
  explicitly not labelled as primitive draws;
- actual engine primitive submissions correlated to the nearest relevant
  selector/resource calls;
- PBR pending evaluations by object, land LOD, terrain fade, and close terrain;
- replacement admissions and vanilla fallbacks by family;
- actual raw native and replacement vertex/pixel shader binds;
- `SetShaders` calls and `SetTexture` detour calls;
- native `SetTexture` cache hits versus device setter calls;
- device-pointer lookups and their resulting `VirtualQuery` count;
- texture/shader getters, successful owned references, and immediate releases;
- close-terrain geometry-cache misses, 25-slot pass-light entries consumed,
  property-iterator steps, manager-light candidates, selected supplemental
  lights, and uploaded constant rows;
- sky pending/admitted/restored draws;
- local-light list length and scanned count;
- shader-package writes and observed package-value changes;
- scene-hook attach/detach transitions, which should remain zero in steady state.

Logical fallback counts are not enough. The root candidate concerns actual
driver-facing pair transitions.

### Per-boundary D3D counters

Attribute to named owners rather than one aggregate:

- state-block captures and applies;
- attachment getters, successful owned references, releases, detaches, and
  restores;
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
- `0x00E812F0` detour overhead separately from its original resource method;
- device discovery/`VirtualQuery`, texture/shader getters, and COM releases;
- close-terrain light scan and constant-buffer construction separately from
  `SetPixelShaderConstantF` driver-call time;
- PBR/sky admission and raw bind/restore time;
- shader-package page-query/protection time;
- state-block `Capture` and `Apply` as separate intervals;
- attachment getter, prepare, and restore intervals;
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

Runtime master-off is not equivalent to no hooks: the shared resource-method
and passive PBR/sky entries can remain resident. Both cases are needed.

Only after current counters identify a dominant path should later A/B builds
change architecture. The highest-value A/Bs are:

- current split PBR ownership versus stable engine-pass ownership with no
  false `0x00E812F0` draw-scope state machine;
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
- no replacement owner claims a primitive scope unless the executable caller
  chain proves that scope for every class using it;
- no ordinary replacement evaluation discovers the device through
  `VirtualQuery` or reconstructs cached sampler state through device getters;
- stable shader-package state is not rewritten through page-protection changes
  every frame;
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
- `BSShader::SetShaders @ 0x00BE1F90` reads the selected wrapper handles and
  calls the render-state shader setters;
- `NiDX9RenderState::SetTexture @ 0x00E88A20` returns on a cached pointer match
  before calling the device, while OMV's detour bookkeeping precedes that
  native comparison;
- `0x00E812F0` prepares geometry buffers, binds vertex streams and the index
  buffer, and contains no primitive-submission call;
- the same `0x00E812F0` implementation is used by at least PPLighting,
  TallGrass, SpeedTreeLeaf, and SpeedTreeBranch slot-27 vtables, while other
  shader classes use different slot-27 implementations;
- current OMV uses no D3D9 device-vtable hook;
- current OMV detours that shared geometry/resource method, a PBR `SetTexture`
  entry, and raw shader binds for PBR fallback/restore and sky replacement;
- every evaluated PBR family binder discovers the device through two checked
  reads and therefore at least two `VirtualQuery` calls; fallback/restore can
  repeat the lookup;
- a seven-layer close-terrain sampler check can make fourteen `GetTexture`
  calls, and each successful D3D9 query returns a reference that is immediately
  released after identity extraction;
- a close-terrain geometry-cache miss can inspect 25 pass-light identities,
  walk up to 64 property lights, consult up to 64 manager lights, and select up
  to 24 supplemental lights;
- every evaluated close-terrain resource visit uploads 3 to 51 float4 constant
  rows, whether or not its light-membership cache hit;
- OMV forces two shader-package globals every serviced configured PBR frame,
  costing two `VirtualQuery` and four `VirtualProtect` calls even when the
  values are already 7;
- a four-MRT screen transaction performs five attachment getters and thirteen
  clear/restore setters, while a world transaction performs four getters and
  nine restore setters, in addition to all-state capture/apply and effect work;
- current OMV can use several independent all-state/attachment transactions per
  frame;
- current OMV has two independent world-color copy owners;
- current source retains description/device-keyed screen, world, TAA, depth,
  and shader resources; it does not show a normal steady allocation loop;
- healthy NVR has been measured with much higher raw copy/state/draw volume than
  a simplistic OMV budget;
- the historical critical OMV log reproduced catastrophic timing at 2560x1440,
  contained three depth and three phase copies per active epoch, and recorded a
  terrain sampler fallback;
- the user reports no NVIDIA improvement after current device-vtable/depth
  changes.

### Reasoned inferences

- OMV's split pass/resource replacement ownership around a falsely assumed
  draw bracket is the strongest source-proven design defect and hook-side root
  candidate;
- exterior multiplication of that hook, close-terrain admission, sampler
  queries, and light constants is a stronger scene-shape explanation than the
  original raw shader-flip hypothesis alone;
- raw fallback/replacement alternation is more likely to become vendor-specific
  than the CPU jump/trampoline itself;
- Windows VM queries and D3D getter/AddRef/Release traffic can amplify the
  render-thread path, but their vendor-specific cost is not established;
- repeated broad state/attachment transactions can amplify copy/resolve
  synchronization cost on a particular driver;
- the combined transition graph is a better explanation than depth, shader
  code, device-vtable ownership, or copy count alone;
- one-time resident hooks and stable engine-cache authority are safer future
  convergence targets.

### Open questions requiring the affected machine

- How many `0x00E812F0` and engine `SetTexture` detours run per bad frame, and
  which shader classes own the resource visits?
- Which primitive submission actually consumes each PBR/sky selection and
  constant upload?
- How much CPU time is spent separately in device discovery, `VirtualQuery`,
  D3D getters, AddRef/Release, light scanning, constant construction, and
  constant upload?
- How many raw PBR/sky shader pair transitions actually reach the NVIDIA
  driver?
- Are close-terrain fallback and one-FPS frames correlated?
- Which state-block capture/apply or attachment restore blocks the CPU?
- Which copy or resolve has the long GPU dependency, if any?
- Are atmosphere and runtime world-color captures semantically shareable in the
  affected configuration?
- Does the one-FPS event coincide with VRAM residency loss, device/description
  churn, or driver eviction despite stable resource ownership?
- Does a true no-optional-hooks startup recover differently from runtime
  master-off?
- Does hook-chain order with Fallout Shader Loader or other graphics plugins
  change the bad path?

Until those questions are measured, a comprehensive rewrite should be guided by
the NVR invariants and the leading root cluster, but it must not claim a
specific proprietary-driver cause as proven.

## Primary evidence index

### Current OMV

- `omv/src/startup.rs:88-221` - Load versus DeferredInit ownership.
- `omv/src/hooks.rs:42-153,210-283` - core engine hooks and detours.
- `omv/src/fnv_render.rs:26-60,257-810` - scene hook inventory and frame flow.
- `omv/src/effects/pbr/hooks.rs:43-47,494-704,1010-1202,1292-1311,1402-1455`
  - PBR targets, chaining, split ownership, fallback, and texture tracking.
- `omv/src/effects/pbr/engine_contracts.rs:186-187,446-550,623-625,785-797`
  - per-frame package forcing, wrapper handle reads, temporary override
  ownership, and protected writes.
- `omv/src/effects/pbr/terrain_lights.rs:28-65,234-423,529-552` - close-terrain
  light limits, geometry cache, native/property/manager membership, and
  supplemental selection.
- `omv/src/effects/pbr/constants.rs` and
  `omv/src/effects/pbr/hooks.rs:1010-1115,1284-1289` - close-terrain constant
  upload and required-stage device queries.
- `omv/src/effects/pbr/device_resources.rs:75-104` and
  `omv/src/effects/pbr/samplers.rs:268-437` - retained device resources and
  sampler state ownership.
- `omv/src/effects/sky.rs:449-470,912-974,1165-1205` - late raw sky
  replacement and hook chaining.
- `omv/src/fnv_local_lights.rs:608-710,864-915,1168-1175` - light hook,
  bounded traversal, and capture limit.
- `omv/src/runtime.rs:1454-1801,2339-2379,2580-2840,4491-4615` - screen
  transactions, world copy, phase graph, and phase copies.
- `omv/src/fnv_world_pipeline.rs:635-1005,1182-1207` - pre-alpha, TAA,
  atmosphere state, and world color.
- `omv/src/effects/temporal_aa.rs:700-775` - two full-resolution TAA copies.
- `omv/src/render_state.rs:20-153` - attachment and state restoration contract.
- `omv/src/backend/fnv.rs:315-329,670-684,2092-2345` - checked device
  discovery and current NvAPI/RESZ route and copies.
- `libpsycho/src/os/windows/memory.rs:48-78` - `VirtualQuery`-backed memory
  validation.
- `libpsycho/src/os/windows/directx9.rs:288-318,759-765,975-993` - borrowed
  device wrapper and raw texture/shader getters.
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
- `.research/TESReloaded10-master/src/NewVegas/Hooks/ShaderIO.cpp:3-61` - shader
  wrapper observation and package-change ownership.
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

### Static executable evidence

- `analysis/ghidra/output/perf/graphics_fnv_pbr_shader_handle_getter_setshaders_contract_audit.txt`
  - `BSShader::SetShaders` handle-getter and render-state contract.
- `analysis/ghidra/output/perf/graphics_fnv_pbr_shader_virtual_interface_followup_audit.txt`
  - shader virtual-interface and vtable relationships.
- `analysis/ghidra/output/perf/graphics_fnv_pbr_continuity_draw_resource_contract_closure.txt`
  - geometry/resource setup and downstream buffer-manager contract.
- `analysis/ghidra/output/perf/graphics_fnv_pbr_selector_setup_raw_slot_followup_audit.txt`
  and
  `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_selector_family_classification_audit.txt`
  - selector families and class-specific slot ownership.
- `analysis/ghidra/output/perf/graphics_fnv_atmosphere_alpha_coverage_composition_contract_audit.txt`
  - pre-alpha composition boundary.
- Direct radare2 inspection of the repository's current
  `fnv_reverse/FalloutNV.exe` on 2026-08-09 confirmed the bodies at
  `0x00BE1F90`, `0x00E88A20`, and `0x00E812F0`. The executable was PE32 x86,
  image base `0x00400000`, SHA-256
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

### Authoritative D3D9 contracts

- Microsoft [IDirect3DDevice9::GetTexture](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-gettexture),
  [GetRenderTarget](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-getrendertarget),
  and
  [GetDepthStencilSurface](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-getdepthstencilsurface)
  - successful getters increase the returned interface's internal reference
  count and require balanced release ownership.
- Microsoft [Saving All Device States with a StateBlock](https://learn.microsoft.com/en-us/windows/win32/direct3d9/saving-all-device-states-with-a-stateblock)
  and [State Blocks Save and Restore State](https://learn.microsoft.com/en-us/windows/win32/direct3d9/state-blocks-save-and-restore-state)
  - the documented `D3DSBT_ALL` state domain and capture/apply semantics.
- Microsoft [ID3DXEffect::Begin](https://learn.microsoft.com/en-us/windows/win32/direct3d9/id3dxeffect--begin)
  - default D3DX effect state save/restore behavior used to qualify the NVR
  comparison.

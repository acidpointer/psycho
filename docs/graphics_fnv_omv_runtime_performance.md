# OMV render-hook performance contract

## Purpose and user-visible behavior

OMV keeps only its mandatory Present, Reset, menu, and independently required
depth-provider infrastructure resident so the in-game master switch can be
changed without restarting Fallout New Vegas. Optional native draw hooks and
the sky engine hook are prepared once and physically detached when their
consumers are disabled. PBR engine hooks remain resident under the mandatory
stale-wrapper safety contract, but bypass before selector/sampler work. The
disabled state is a live zero-visual-work state: the menu remains reachable,
native rendering continues, and visual D3D resources are released.

This contract addresses reports ranging from roughly half the expected frame
rate to single-digit frame rates. Static code inspection proved a
machine-sensitive render-thread I/O defect and several unnecessary disabled
hook paths. It does not prove that every reported slow machine has the same
cause, and static validation cannot establish an FPS improvement.

## Proven defect

Before this change, `ScreenShaderRuntime::scan_shaders_if_due` ran from
`apply_present_frame` and `apply_scene_phase`, both render callbacks. At the
default 200 ms interval it synchronously called:

- `luts::scan_luts`, which enumerates the LUT directory and reads file metadata,
  and reads changed LUT files;
- `shaders::scan_screen_shaders`, which enumerates the external shader
  directory, reads file metadata, reads changed bytecode, and may compile
  changed HLSL.

The scan happened before the phase's enabled-shader check. Present also entered
this path while `graphics.screen_space_shaders` was false. Therefore filesystem
latency, Wine/Proton path translation, antivirus, mod-manager overlays, a slow
disk, a very large asset directory, or concurrent I/O could stall the render
thread directly. The code establishes that unbounded external latency was on
the frame boundary; the relative contribution of each host condition is a
reasoned inference.

The disabled hook paths also performed work that was not needed for live
pass-through:

- every D3D draw entered both PBR and sky draw preparation;
- disabled PBR `SetShaders` cleared tracking state and attempted direct-state
  restoration before calling the predecessor;
- every Present serviced PBR, sky, screen effects, and world-pipeline cleanup;
- the disabled local-light hook tried to lock and clear three publications on
  every world-light traversal;
- scene-boundary hooks continued OMV depth, target, and phase checks.

These paths are proven by the pre-change source. They can amplify CPU overhead,
but their individual FPS cost has not been measured.

## RTX 5060 isolation results from 2026-07-29

The tester's controlled in-game comparisons refine the earlier pre-shader
hypothesis:

- with all OMV effects disabled, performance remains about 67 FPS;
- changing OMV depth production to external Depth Resolve gains only about
  1-2 FPS;
- windowed mode gains about 2-3 FPS over the tested fullscreen path;
- DOF alone costs about 4-5 FPS;
- TAA alone costs about 3-4 FPS;
- all remaining filters together account for roughly the smaller remainder
  between the disabled and fully enabled states.

These are runtime observations on the affected NVIDIA machine, not static
proof and not a universal GPU cost model. They establish two distinct
problems. DOF and TAA have real GPU costs worth optimizing immediately, but
their shaders cannot explain the approximately 67-FPS disabled ceiling.
Provider work is also not the dominant disabled ceiling because the true live
provider switch changed performance only slightly.

The remaining disabled-path candidate was OMV hook/resource residency. The
previous master-off implementation still routed every DP/DIP through OMV and
left PBR `SetTexture` sampler tracking plus the sky-constant hook active. Even
a fast branch at each draw is not the same experiment as restoring the
original entry, especially under a driver/DXVK stack whose NVIDIA behavior
differs from the RX 6800 XT reference machine.

The current implementation creates the hook objects once but treats enabled
state as physical ownership:

1. enabling a native PBR/sky consumer attaches both DP and DIP at the
   Present-owned quiescent boundary;
2. sky then attaches its prepared engine hook, while PBR's resident hooks leave
   their passive early-bypass state;
3. disabling reverses that order, restores replacement state, detaches the sky
   hook, makes PBR detours passive, and finally restores both original device
   draw entries;
4. pair transitions roll back on the second-entry failure, so DP and DIP can
   never cover different primitive families;
5. the reliability record reports `draw_hooks=attached`,
   `prepared-detached`, or `unavailable`.

Master-off also releases all OMV visual shaders, intermediate targets, temporal
histories, and state blocks while retaining ImGui and the machine-local depth
provider. It deliberately does not call `EvictManagedResources`, which would
affect resources owned by the game and other plugins. Re-enable recreates
device resources lazily and reuses process-owned shader bytecode.

This physical control is the necessary next root-cause test. Static source
proves the original entries are restored; only the affected machine can show
whether the 67-FPS ceiling moves.

OMV now also logs the primary swap-chain parameters at device-hook install and
after each successful Reset: windowed/fullscreen mode, backbuffer dimensions
and format, buffer count, MSAA type/quality, swap effect, fullscreen refresh,
presentation interval, and the driver's approximate available texture memory.
This makes the observed 2-3 FPS windowed advantage reproducible without
guessing which presentation contract the game actually created. These are
diagnostics at lifecycle boundaries, not per-frame queries.

## Tester-log findings from 2026-07-26

`.reports/omv-latest--performance-bad.log` provides two additional direct
observations:

- PBR reported 162 queued shaders even though most entries were cache hits.
  Ten missing close-terrain variants visible before the log ended then
  compiled individually for about 8.6-11.7 seconds each while the game was
  already running. Per-entry cache/resource messages also produced hundreds
  of info-level log records.
- Every world and first-person depth resolve returned D3D error `0x8876086A`.
  Depth-dependent work was nevertheless reached and its resources and phase
  copies were initialized.

The failed route remained selected and attempted up to three full
state-block-backed RESZ transactions per rendered frame. The log cannot
identify whether the failure came from the all-state block, a binding, the
marker draw, or the RESZ trigger. It also cannot by itself attribute the
tester's sustained frame rate to one pass. It does prove an incomplete PBR
cache, a long and poorly distinguished preparation period, and a device on
which the old RESZ-only transaction did not work.

### NVR-derived depth hot path

The working NVR source does not capture/apply `D3DSBT_ALL` for RESZ. It retains
only FVF, declaration, texture 0, vertex/pixel shaders, stream 0, Z-enable,
Z-write, and color-write, then resets the point-size trigger. OMV previously
performed that bounded work plus an all-state capture/apply on every resolve.
At the active world, coherent-world, and first-person capture points, that
broad transaction could occur up to three times per frame.

OMV now owns the same bounded state set through
`libpsycho::os::windows::directx9::ReszState9`. Owned COM references keep every
saved binding alive until restoration, and OMV preserves the incoming point
size rather than assuming it was zero. The error path still attempts every
state and depth-attachment restore. Only the RESZ helper lost its all-state
block; independent screen/world draw transactions still retain theirs.

NVR also treats an `INTZ` source surface as a texture level on native NVIDIA:
it obtains the `IDirect3DTexture9` container, registers that texture, and uses
it as the NvAPI copy source. OMV previously registered and copied the surface
unconditionally. OMV now retains and prefers the texture container with a
standalone-surface fallback, matching NVR on native NVIDIA.

These are direct source-contract fixes. Static evidence proves the removed
calls and corrected resource identity, but only the reported NVIDIA system can
measure the resulting frame time.

### Operational depth-route circuit breaker

OMV now treats `D3DERR_NOTAVAILABLE` from an advertised RESZ transaction as an
operational capability rejection. It tries native NvAPI once for the current
device generation and retries the current capture only if initialization
succeeds. Otherwise it caches depth as unavailable. This removes the repeated
marker draw, full-state capture/restore, and target churn from the incompatible
path. Other D3D failures retain RESZ so transient errors cannot permanently
reduce effect coverage. Device replacement/reset clears the cached decision
and probes again. This is secondary failure containment; the bounded NVR state
transaction and native source-container ownership are the compatibility and
performance fix. Full evidence is maintained in
`docs/graphics_fnv_depth_resolve.md`.

## Architecture and ownership

`omv/src/asset_scanner.rs` owns live external shader and LUT discovery. Runtime
configuration starts one named `omv-asset-scan` worker. The worker:

1. parks completely while the live master switch is off;
2. scans at the configured interval while it is on;
3. retains the last valid external shader and LUT catalogs;
4. publishes changed catalogs through a capacity-one channel;
5. retains only the latest unsent snapshot if the render thread has not
   consumed the prior publication.

`ScreenShaderRuntime::poll_asset_scanner` uses non-blocking `try_recv`. It does
no filesystem work. A received generation is committed in one render tick:
unsaved menu values are preserved, changed shader bytecode invalidates compiled
passes, changed LUT data invalidates the bloom/final-color resource owner, LUT
choices are rebuilt, and embedded and external source lists are merged.

Initial `runtime::configure` still constructs embedded effect sources
synchronously from in-memory configuration. If the worker cannot start, OMV's
embedded effects and menu remain usable; external shader discovery, external
LUT discovery, and their live reload are unavailable and one warning is
logged. A scan failure retains the last valid catalog and warning output is
bounded.

The scanner starts during OMV runtime configuration. This does not publish or
initialize the focused FNV world pipeline. Its first publication remains in
`DeferredInit`, as required by
`docs/graphics_fnv_atmosphere_startup_crash_errata.md`.

### Native PBR local preparation

OMV releases contain PBR HLSL source and never contain generated `.cso` or
`.pso` bytecode or a populated cache directory. The release packager rejects
an archive that violates that rule.

After `NVSEPlugin_Load` has staged an enabled native-PBR settings snapshot, the
named `omv-pbr-prepare` worker may begin one CPU-only preparation transaction.
Starting there overlaps cache work with data loading, but does not configure or
activate PBR. Engine inspection, hook installation, world publication, D3D
resource creation, and replacement remain behind DeferredInit and Present.

The transaction:

1. constructs exact compiler-input groups from source bytes, shader target,
   compiler flags, and PBR contract revision;
2. inventories the canonical content-addressed cache entry for each group;
3. accepts only entries whose envelope, source/contract hash, bytecode size,
   checksum, shader stage, and terminal token validate;
4. compiles only missing or invalid unique inputs;
5. publishes one immutable bytecode allocation to every engine-visible logical
   alias in the group; and
6. retains the complete verified logical catalog in process memory.

The current 162 logical PBR templates contain 132 exact compiler inputs. The 57
close-terrain entries are one vertex input and 28 base/canopy pixel pairs, so
they require only 29 cache reads or compiler calls. The alias is internal to
preparation: each SLS identity keeps its own ready/failed state and current D3D
resource slot. A group failure marks every logical alias failed, preserving the
existing whole-catalog and close-terrain-family atomic activation gates.

Compiler workers share a bounded queue. The automatic count is half the
available logical CPUs, rounded up, clamped to `1..=8`, and capped by the unique
miss count. This gives one worker on a two-thread system, two on four threads,
four on eight, and eight on sixteen or more. The game therefore retains CPU
headroom while Wine compiler implementations that permit parallel work can use
it. A controlled sweep through the game's exact native `d3dcompiler_47.dll`
compiled the same eight unique close-terrain inputs successfully at every
tested count. Its wall times were 13.73, 13.65, 13.69, and 13.60 seconds for
one, two, four, and eight workers respectively. That compiler effectively
serializes this workload, so source deduplication and startup overlap are the
proven native wins; higher worker count is not claimed as a native speedup.

The canonical cache hash still includes source, shader target, compiler flags,
cache format revision, representative logical identity, and PBR contract
revision. A changed input therefore invalidates only its affected group. Cache
publication writes a complete envelope to a unique temporary file, closes it,
renames it atomically, reopens it, and verifies it before reporting success.
The cache is reconstructible and self-validating, so it deliberately does not
force a physical `sync_all` for every shader. A process or power interruption
may lose the newest cache entry; it cannot make unchecked bytecode ready, and
the next inventory removes or rebuilds invalid data. Stale variants are
reclaimed by the bounded 64 MiB/48 MiB cache-maintenance policy instead of a
directory scan after every compiler result.

Aggregate logs distinguish logical and unique cache counts and report total,
inventory, compile-phase, summed compiler-work, and summed cache-work
milliseconds. Summed work counters may exceed wall time when a compiler truly
runs calls concurrently. Detailed per-input messages remain debug-level.

The previous transaction performed these operations independently for every
logical template:

1. inventory all expected content-addressed cache entries;
2. accept only entries whose envelope, source/contract hash, bytecode size,
   and checksum validate;
3. compile only missing or invalid entries, using two workers;
4. write a temporary file, flush it, rename it atomically, reopen it, and
   verify the committed entry;
5. retain the complete verified bytecode catalog in process memory.

Those steps explain the measured cold-cache cost: prior 162-entry sessions took
201.105 and 276.489 seconds, while the 2026-08-03 56-entry close-terrain rebuild
took 45.864 seconds. Removing 28 redundant close-terrain compiler calls is a
deterministic 50-percent reduction for that affected family. Final wall time in
the game still requires the normal cold-cache playtest because compiler and
storage behavior vary by Wine prefix and machine.

Device-owned shader handles are created from the process-owned bytecode at a
budget of four per Present. Device loss discards only D3D handles. A reset
recreates them from memory without rereading or recompiling the cache. Disabling
native PBR cancels outstanding preparation generations; already verified
in-memory entries remain reusable. Detailed per-entry cache, compile, and
resource messages are debug-level, while aggregate completion and failures
remain visible.

No render callback performs shader compilation or cache I/O. Present retains a
fallback start in case native PBR was enabled after startup and creates the
bounded number of required D3D resources because D3D9 device ownership is
render-thread-bound. Draw replacement remains atomic at the whole prepared
catalog boundary, including the mandatory close-terrain family boundary.

### Effect applicability preflight

Each depth-dependent embedded effect now exposes a side-effect-free
applicability predicate. Ambient occlusion rejects a frame when neither AO
family is selected or required depth is absent. Sunshafts rejects absent depth
or an unavailable sun contract. Depth of field rejects absent depth and
preserves its vanilla-DoF resume state when skipped.

`ScreenShaderRuntime` evaluates those predicates before effect creation and
before any `StretchRect`. It also evaluates all enabled sources in a phase
before creating/capturing its D3D state block or allocating/updating the phase
color-copy target. A phase containing only rejected effects therefore performs
neither operation. Depth of field also waits for its background shader
preparation before declaring its phase applicable. This changes no shader
equation, pass quality, or supported coverage; an applicable effect uses the
same render path as before.

### The v2.0.6 1-FPS report

`.reports/omv-latest--1fps.log` is a v2.0.6 runtime record at 3840x2160. It is
not evidence from the implementation documented below, but it exposes three
old structural defects:

- first use of atmosphere, AO, final color, and motion blur coincides with
  multi-second initialization gaps; old effect constructors compiled or read
  cached HLSL from the render callback;
- `completed_no_draw` rises from 0 to 560 while both `pre_alpha` and `primary`
  rise by the same 560 transactions; the old world path resolved depth and
  entered the coherent transaction before discovering that atmosphere had no
  visible contribution;
- the screen stack gave each embedded effect its own full-resolution
  copy-before-draw transaction. Final Output then copied its composed
  full-resolution result again before chromatic aberration, and the external
  depth-aware CAS pass began from another phase copy.

The same record contains exact ten-second 600-Present intervals when world
work is absent, but slower intervals while the no-draw world transactions are
accumulating. This is correlation rather than a GPU timestamp attribution.
The source and counters nevertheless prove that expensive work occurred before
the old no-draw decision.

No effect, effect family, default, user parameter, shader equation, sample
count, or CAS pass is disabled by the remediation. It changes scheduling,
resource ownership, and redundant transfer work only.

### Process-owned screen-effect preparation

AO, atmosphere, spatial AA, TAA, sunshafts, Final Output, DOF, and motion blur
now own immutable process bytecode catalogs. Enabling a configured family
starts an idempotent worker request. A process-wide background-only gate permits
one screen-effect compiler/cache transaction at a time, preventing several
effect workers from saturating the same machine while PBR retains its separate
preparation contract. The request path remains part of the established
`NVSEPlugin_Load` startup contract; first-person motion blur adds no new worker
owner there.

Render callbacks poll readiness and create only D3D9 device objects from
resident bytecode. They never acquire the compiler gate, invoke the HLSL
compiler, or read/write the shader cache. Device reset discards device objects
but retains process bytecode. A failed catalog leaves that effect safely
unavailable and logs the bounded preparation failure; it does not switch to a
different quality tier. Phase applicability and the world pipeline verify that
the selected consumer is ready before full-resolution color allocation or
physical depth resolve, so queued preparation does not create a copy-only
frame.

### Phase-local color graph and immutable execution plan

Every native image-space phase now has one color graph:

1. copy the engine target to a persistent primary texture once;
2. execute intermediate logical writers by alternating primary and scratch
   targets;
3. direct the final planned writer to the engine target;
4. if dynamic admission rejects a planned tail after an earlier writer drew,
   commit the current graph texture once.

AO and Final Output each expose multiple menu sources but remain one logical
writer. External `pass_count` values remain distinct ordered writers. Final
Output writes composition directly into its persistent exact-format
full-resolution target when chromatic aberration follows, so that second pass
samples the target directly; there is no internal full-resolution copy.

Configuration, asset, and preset changes build immutable phase plans from the
compiled source set. Each plan retains allocation-free shared source snapshots,
the exact compiled-pass positions, AO-present and AO-absent schedules, logical
writer totals, and source-pass totals. A render callback therefore walks only
its phase and does not clone source names, option vectors, or other owned
configuration data per effect.

The reliability line reports cumulative
`color_copies=phase_initial:<n>/fallback_commit:<n>`. The normal cost is one
initial full-resolution copy for each phase that actually draws, independent
of the number of enabled effects in that phase. Fallback commits should be
rare and correlate with dynamic applicability rejection.

### DOF and TAA GPU work

The RTX 5060 isolation made DOF and TAA immediate work rather than deferred
research. The quality contract remains strict: no lower resolution, history
precision, gather tap count, blur radius, or effect coverage was accepted.

DOF now:

- uploads frame/projection constants once per effect transaction and changes
  only target-size constants between passes;
- binds and clears only its proven sampler ABI, s0-s4, rather than s0-s9;
- uses a three-vertex full-screen triangle for every pass;
- compiles round and soft gather shapes separately, removing the runtime shape
  branch and unused exponential work from round gathers;
- compiles near/far soft filters separately, removing a per-tap layer branch;
- expresses the high-quality near upsample's exact `[1 2 1]^2 / 16` kernel as
  four phase-correct bilinear samples instead of nine explicit samples.

The pass graph, half/full target dimensions, gather tap counts, FP16 formats,
focus equations, CoC equations, and alpha composition remain unchanged.
Detailed ownership and visual acceptance are in
`docs/graphics_fnv_depth_of_field.md`.

TAA now queries `NumSimultaneousRTs` and
`D3DPMISCCAPS_MRTINDEPENDENTBITDEPTHS`. When both prove the contract, one
shader writes FP16 resolved color to COLOR0 and the R16F logarithmic depth key
to COLOR1. This removes the second full-resolution depth-key draw and its
duplicate depth sample. Devices without the exact capability retain the
original two-pass path. Both paths use a three-vertex full-screen triangle,
preserve engine alpha, maintain the existing temporal rejection equations, and
remain inside the complete world attachment/state transaction.

## Disabled live-pass-through contract

The master switch is published as one atomic flag. Prepared hooks remain
reusable, but optional hot entries are physically restored; no restart is
required.

- DP and DIP detours are attached as an atomic pair only when enabled native
  PBR or sky requires a draw boundary. Their internal master check remains a
  defensive transition guard, not the normal disabled path.
- Present keeps native Present, render-epoch ownership, failure/timing
  accounting when requested, and the menu boundary. PBR, sky, and screen-effect
  services are skipped when the master is off, the menu is closed, and ImGui
  has already initialized.
- FNV image-space, world-scene, and first-person hooks call their predecessors
  directly when disabled.
- PBR `SetShaders` and `SetTexture` bypass before hot replacement work, and the
  sky constant hook is detached. PBR shader-creation hooks retain only their
  one-time wrapper observation so an initially disabled configuration can be
  enabled live. PBR hooks stay resident because the proven engine contract
  forbids a runtime teardown that could restore stale wrapper ownership.
- Local-light and retained world-light publications are cleared once after
  capture is disabled. A busy `try_lock` leaves the one-shot cleanup pending;
  render callbacks never block.

Inline and vtable bytes are changed only at DeferredInit or Present, the
serialized render-thread boundaries where no covered native call can be in
flight. On PBR re-enable, the cleared sampler cache warms from subsequent
engine texture bindings; an incomplete layout fails closed to the vanilla
shader.

Switching the master back on first republishes subsystem configuration. The
scanner is unparked, embedded effects are already available, and native PBR
activation continues at its existing Present boundary. Hook addresses,
predecessor chaining, scene phase ordering, shader equations, and resource
formats are unchanged.

## Performance and memory bounds

Render callbacks perform no directory enumeration, metadata query, shader file
read, LUT file read, or external HLSL compilation. Catalog polling is a
non-blocking channel receive and returns immediately when empty. Allocation and
source-list rebuilding occur only when a changed catalog generation is
committed, not every frame.

Each active phase retains one additional scratch texture matching that phase's
exact dimensions and format. At 3840x2160 this is 33,177,600 bytes for a
four-byte target or 66,355,200 bytes for an eight-byte FP16 target. Final
Output retains one additional exact-format full-resolution target only when a
composition pass feeds chromatic aberration. These are persistent device
resources, replaced only on device/description changes; the steady-state path
does not allocate them. The memory trade removes one full-resolution transfer
per additional phase writer and Final Output's former internal transfer.

The worker owns one external source catalog and one LUT catalog. The channel
holds at most one snapshot and the worker holds at most one newer pending
snapshot. LUT pixel storage is shared with `Arc`; external shader snapshots
clone their bounded bytecode and option data. This trades bounded background
memory for removal of unbounded filesystem latency from the render thread.

When the master switch is off, the scanner is parked and issues no periodic
filesystem requests. OMV visual resources are absent, native draw and sky
entries point to their predecessors, and resident PBR detours take only their
early configured-state bypass. Other disabled visual overhead is limited to
the mandatory Present/menu boundary plus independently selected depth-provider
service.

## Validation and acceptance

Static regression coverage establishes:

- `runtime.rs` cannot directly call the LUT or external shader scan functions;
- the background scanner publishes through a capacity-one channel;
- LUT and shader discoveries are committed together before rebuilding source
  choices;
- a disabled master bypasses D3D draw work and FNV scene-boundary work while
  retaining the menu boundary;
- disabled PBR `SetShaders` calls native behavior before tracking work;
- scan intervals remain bounded to 50-5000 ms.
- rejected AO, sunshafts, and depth-of-field frames exit before effect
  resource creation and backbuffer copy;
- a phase whose enabled effects are all rejected allocates no color-copy
  target;
- a drawn phase performs one initial color copy, alternates intermediate
  targets without feedback, preserves reference ordering through dynamic
  rejection, and performs at most one fallback commit;
- immutable phase plans collapse AO and Final Output to one logical writer,
  preserve external pass counts, and avoid whole-source scans and owned source
  clones in the draw loop;
- every production screen-effect compiler/cache transaction is reachable only
  from a background preparation worker;
- atmosphere admission rejects proven no-contribution frames before pre-alpha
  or coherent depth resolve while unknown scene/local-light state proceeds;
- Final Output contains no internal full-resolution copy when chromatic
  aberration follows composition;
- the native-PBR render boundary contains neither local HLSL compilation nor
  shader-cache commit calls;
- release packaging cannot include generated shader bytecode or cache files;
- device reset preserves the process-owned PBR bytecode catalog, while
  disabling PBR cancels unfinished preparation;
- exact PBR compiler-input grouping covers every logical template once and
  holds the reviewed 162-to-132 unique-input budget;
- close-terrain grouping holds its reviewed 57-to-29 budget and shares one
  immutable bytecode allocation across every base/canopy alias pair;
- adaptive compiler workers reserve half the reported logical CPUs, never
  exceed eight, and never exceed the number of unique misses;
- cache publication retains atomic rename and strict readback verification
  without a per-shader durable disk flush; and
- early PBR preparation follows the deferred-settings handoff and cannot
  publish world state or install graphics ownership from `NVSEPlugin_Load`.

Required validation is:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
git diff --check
```

On 2026-07-26, the Windows/Wine OMV suite passed all 302 tests and the optimized
`i686-pc-windows-gnu` OMV release target built successfully.

The 2026-07-27 PBR preparation, depth-route, and applicability update passed
all 309 OMV tests and the optimized `i686-pc-windows-gnu` OMV release build.

The 2026-07-29 disabled-path lifecycle, DOF, and TAA update passed all 417 OMV
tests, including shader-variant compilation and the CPU reference proof for the
four-sample near reconstruction. The optimized `i686-pc-windows-gnu` OMV
release target also built successfully.

The subsequent world-only-provider AO phase correction passed all 419 OMV
tests and the same optimized release build. Its regression proves that
post-first-person world AO darkens a covered weapon pixel and that the
provider-aware ordering preserves the first-person color.

The structural scheduling update passed all 427 OMV tests. This includes the
pre-depth admission negative controls, exact-stage depth-cache identity,
phase-graph ordering through dynamic rejection, Final Output transfer/memory
budget, background shader-variant compilation, and the existing DOF/TAA image
and bytecode budgets.

The 2026-08-03 PBR preparation performance update passed all 450 OMV tests
under Wine and built the optimized `i686-pc-windows-gnu` OMV release target.
The suite includes every registered PBR variant, exact grouping and alias-state
proofs, cache publication recovery, startup source-order ownership, adaptive
worker bounds, and eight concurrent unique compiler inputs. A separate sweep
through the game's native `d3dcompiler_47.dll` passed at one, two, four, and
eight workers with the timings recorded above.

The Depth Resolve AO playtest follow-up corrected the world-only composition
target without changing shader parameters or adding a depth copy. AO now draws
on active RT0 immediately after world rendering instead of pre-binding the
`BSRenderedTexture*` argument at `RenderFirstPerson` entry. The structural
negative controls reject the old target path and require missed-frame AO
history invalidation before unrelated scene-pre work; all 428 OMV tests and
the optimized release build pass.

Ordinary gameplay remains the runtime acceptance gate. Test at least one
previously affected Wine/Proton setup with the master both off and on. With the
master off, FPS and frame-time distribution should be statistically
indistinguishable from the same setup without OMV, apart from hook dispatch
noise. With the master on, remaining cost must correlate with enabled effect
passes rather than 200 ms filesystem stalls. No FPS result is claimed until
that playtest evidence exists.

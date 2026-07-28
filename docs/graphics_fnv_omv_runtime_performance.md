# OMV render-hook performance contract

## Purpose and user-visible behavior

OMV keeps its graphics hooks resident so the in-game master switch can be
changed without restarting Fallout New Vegas. The disabled state is a live
pass-through state: the menu remains reachable, native rendering continues,
and OMV effect work stops at the earliest safe hook boundary.

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

After native PBR activation, the named `omv-pbr-prepare` worker performs one
explicit preparation transaction:

1. inventory all expected content-addressed cache entries;
2. accept only entries whose envelope, source/contract hash, bytecode size,
   and checksum validate;
3. compile only missing or invalid entries, using two workers;
4. write a temporary file, flush it, rename it atomically, reopen it, and
   verify the committed entry;
5. retain the complete verified bytecode catalog in process memory.

The hash includes source, shader target, compiler flags, cache format revision,
logical shader identity, and PBR contract revision. A changed input therefore
invalidates only its affected logical entry. Invalid entries are removed and
rebuilt. Compilation or strict cache persistence failure leaves native PBR
passive and visible as a failed preparation; it is never silently treated as
ready.

Device-owned shader handles are created from the process-owned bytecode at a
budget of four per Present. Device loss discards only D3D handles. A reset
recreates them from memory without rereading or recompiling the cache. Disabling
native PBR cancels outstanding preparation generations; already verified
in-memory entries remain reusable. Detailed per-entry cache, compile, and
resource messages are debug-level, while aggregate completion and failures
remain visible.

No render callback performs shader compilation or cache I/O. The Present
service may start the worker and may create the bounded number of required D3D
resources because D3D9 device ownership is render-thread-bound. Draw
replacement is atomic at the whole prepared catalog boundary, including the
mandatory close-terrain family boundary.

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

## Disabled live-pass-through contract

The master switch is published as one atomic flag. Hooks remain installed; no
restart is required.

- D3D draw detours perform one atomic master check and call the predecessor
  directly when disabled.
- Present keeps native Present, render-epoch ownership, failure/timing
  accounting when requested, and the menu boundary. PBR, sky, and screen-effect
  services are skipped when the master is off, the menu is closed, and ImGui
  has already initialized.
- FNV image-space, world-scene, and first-person hooks call their predecessors
  directly when disabled.
- PBR `SetShaders` and sky constant hooks call native behavior before their
  enabled checks and do no replacement tracking while disabled.
- Local-light and retained world-light publications are cleared once after
  capture is disabled. A busy `try_lock` leaves the one-shot cleanup pending;
  render callbacks never block.

PBR's `SetTexture` hook intentionally continues recording the 16 texture slots.
This is one atomic slot store per valid engine texture binding and preserves
the current material state for safe live re-enable. It performs no allocation,
logging, file I/O, or D3D query in the normal disabled path. Dynamically
rewriting inline-hook entry bytes is not used because executable patching is
not safe while render threads may execute the target.

Switching the master back on first republishes subsystem configuration. The
scanner is unparked, embedded effects are already available, and native PBR
activation continues at its existing Present boundary. Hook addresses,
predecessor chaining, scene phase ordering, shader equations, pass counts, and
resource formats are unchanged.

## Performance and memory bounds

Render callbacks perform no directory enumeration, metadata query, shader file
read, LUT file read, or external HLSL compilation. Catalog polling is a
non-blocking channel receive and returns immediately when empty. Allocation and
source-list rebuilding occur only when a changed catalog generation is
committed, not every frame.

The worker owns one external source catalog and one LUT catalog. The channel
holds at most one snapshot and the worker holds at most one newer pending
snapshot. LUT pixel storage is shared with `Arc`; external shader snapshots
clone their bounded bytecode and option data. This trades bounded background
memory for removal of unbounded filesystem latency from the render thread.

When the master switch is off, the scanner is parked and issues no periodic
filesystem requests. Disabled render overhead is limited to predecessor
chaining and the atomic state checks or tracking explicitly listed above.

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
- the native-PBR render boundary contains neither local HLSL compilation nor
  shader-cache commit calls;
- release packaging cannot include generated shader bytecode or cache files;
- device reset preserves the process-owned PBR bytecode catalog, while
  disabling PBR cancels unfinished preparation.

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

Ordinary gameplay remains the runtime acceptance gate. Test at least one
previously affected Wine/Proton setup with the master both off and on. With the
master off, FPS and frame-time distribution should be statistically
indistinguishable from the same setup without OMV, apart from hook dispatch
noise. With the master on, remaining cost must correlate with enabled effect
passes rather than 200 ms filesystem stalls. No FPS result is claimed until
that playtest evidence exists.

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

Required validation is:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
git diff --check
```

On 2026-07-26, the Windows/Wine OMV suite passed all 302 tests and the optimized
`i686-pc-windows-gnu` OMV release target built successfully.

Ordinary gameplay remains the runtime acceptance gate. Test at least one
previously affected Wine/Proton setup with the master both off and on. With the
master off, FPS and frame-time distribution should be statistically
indistinguishable from the same setup without OMV, apart from hook dispatch
noise. With the master on, remaining cost must correlate with enabled effect
passes rather than 200 ms filesystem stalls. No FPS result is claimed until
that playtest evidence exists.

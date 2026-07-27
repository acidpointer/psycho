# OMV ImGui diagnostics ownership

## Purpose and user-visible behavior

OMV's graphics workbench exposes frame pacing, native-PBR draw details, local
volumetric-light counters, and a fog calibration estimate. These are optional
developer diagnostics collected and displayed in a dedicated `Diagnostics`
tab. Their producers run only while that tab is visible and the workbench's
ImGui context is ready. Opening the ordinary `Configuration` tab does not start
optional collection. Leaving `Diagnostics` or closing the workbench stops
collection, not merely UI formatting and rendering.

Entering `Diagnostics` starts a new diagnostic session. Frame pacing and
successful local-light counters are cleared so the displayed values describe
that visit. Detailed PBR transition collection additionally requires
`graphics.native_pbr.debug_log_draws = true`. That setting no longer keeps its
draw telemetry active after the tab is left.

## Ownership and gate

`omv/src/runtime.rs` owns an atomic diagnostics state containing both the active
bit and a session generation. The gate becomes active only when menu
visibility, ImGui readiness, and the selected Diagnostics tab are all
established. Selecting Configuration, closing the menu, or releasing D3D9
device resources deactivates it. Reactivation advances the generation, so the
frame-pacing owner clears its history and stale timestamp even though the
inactive fast path never acquires the runtime lock.

The optional producers are:

- `runtime.rs`: the 2,048-sample frame-pacing ring, one-second one-pole,
  ten-second metric window, configurable visible publication, 64-episode spike
  memory, session extremes, and periodicity analysis;
- `effects/pbr/diagnostics.rs` and `effects/pbr/samplers.rs`: detailed draw,
  transition, rejection, and sampler telemetry;
- `fnv_local_lights.rs`: traversal, successful capture/format, rendered-light,
  scene-light, and shadowed-light counters;
- `fnv_world_pipeline.rs`: the Diagnostics-only fog distance estimate.

`ScreenShaderRuntime::draw_menu` takes the frame-pacing snapshot only when
Diagnostics was already active for the frame. The first frame after selecting
the tab therefore establishes collection and may show the empty state; the
following frame publishes the live session. No optional producer allocates,
logs, performs file I/O, or blocks a render callback.

## Workbench layout and shader-preparation visibility

The workbench has two top-level tabs with deliberately separate jobs:

- `Configuration` is the default. A compact persistence toolbar sits above a
  two-pane workspace. The left pane contains General, engine features,
  built-in effects, and mod shaders; the right pane is an independently
  scrollable editor. General owns the master switch, menu key, depth choice,
  hot-reload interval, and bulk effect controls.
- `Diagnostics` is one full-height scrollable dashboard. It owns frame pacing,
  render-stack failures, depth-route details, native-sky and PBR resource
  state, PBR transition details, local-light counters, and the live fog
  estimate.

No graph is created in Configuration and there is no vertical overview region
above the effect editor. Graph history can therefore grow only inside the
Diagnostics tab and cannot alter the configuration workspace. This is the
1920x1080 acceptance contract. The feature list uses a bounded adaptive width,
while the editor receives the remaining window width.

Configuration panels present user choices first. ON/OFF list badges describe
the session intent rather than claiming a pipeline is live. Normal
active-state, source-type, render-stage, and embedded config-path lines were
removed from effect editing; errors, preparation warnings, compatibility
warnings, and explicit retry actions remain beside the affected control.
Technical counters and live estimates appear only in Diagnostics. Every
focused, hovered, selected, and dimmed tab state uses the same green palette as
the workbench controls; no default blue ImGui tab color remains. The compact
header always shows ImGui's rolling real-time FPS estimate, including while
Configuration is selected, without activating the optional diagnostics gate.

Native PBR preparation is production state rather than optional diagnostic
collection. While the workbench is closed, `runtime.rs` may render a small
noninteractive preparation window after ImGui is ready. It reports cache
inventory, local compilation, Direct3D resource creation, progress, and
failure. The window does not request DirectInput capture and does not alter
the `PreLoadGame` input-release contract. Native PBR replacements remain
passive until the complete prepared-bytecode and device-resource catalogs are
ready. The PBR configuration panel keeps only actionable preparation state and
an explicit retry action after a failure. Cache/resource counts and transition
telemetry are in Diagnostics.

## Production and error boundaries

The gate must not suppress state required to render correctly. Shader/resource
readiness, captured shader identity used for replacement, local-light capture
and publication, atmosphere visibility, and depth-of-field frame delta remain
production-owned. The depth-of-field delta therefore uses a small
`PresentFrameTiming` separate from the menu's frame-pacing history.

Failures remain observable with the menu closed. Compile/resource failures and
existing bounded error logs are unchanged. Local-light rejected/overflowed
captures and nonblocking lock/reset misses also remain cumulative because they
represent failed work rather than successful diagnostic sampling. Closing the
menu cannot hide or reset those errors. Runtime-owner rejections and failed
Presents are relaxed process-lifetime atomics displayed under frame pacing.
They are not periodically logged from the render callback.

## Performance and memory

With Diagnostics inactive, optional producers reduce to their subsystem gate
check. This includes ordinary Configuration use, not only a closed menu.
When depth-of-field timing is also inactive, the pre-Present frame-pacing gate
returns before timestamp capture and finish-present exits before runtime
acquisition. Optional
producers perform no success-counter increments, per-frame counter swaps,
frame-history timestamp query, ring write, snapshot preparation, or ImGui work.
PBR's configured-off fast path still performs its existing single relaxed
diagnostic-enable read. Local-light hooks load their gate once per capture
stage and reuse the result for all optional counters in that stage.

The frame-pacing ring is a fixed 2,048 `f32` array. Raw capture remains one
bounded write plus scalar smoothing and spike-state updates per valid frame.
Snapshot percentiles and robust jitter use a fixed 4,096-bin histogram instead
of sorting. Percentiles that land in the final histogram bin select the exact
raw overflow-tail value instead of clipping. Publication follows
`diagnostics.frame_pacing_update_interval_ms`; zero means every frame and timed
values are clamped to 50-2,000 ms. Diagnostic session reset uses fixed atomics
and arrays and happens only on the user-driven Diagnostics-tab transition,
never per draw.

The timestamp captured immediately before original D3D9 Present, its result,
and the render epoch protect measurement continuity. Failed Presents and
nonconsecutive callback epochs are counted and rejected. The next successful
callback becomes a new timestamp origin, so a missed nonblocking callback
cannot be reported as one artificial long frame. Adjacent sub-100 ms intervals
are pair-averaged before 100 ms bucketing so a repeating short/long submission
phase cannot become a connected sawtooth. Accepted intervals at or above
100 ms remain one peak. Raw percentiles, jitter, MAD, budget metrics, and
thresholded zero-baseline impulses remain unmodified.

The visible ImGui menu cannot be literally free because it submits UI geometry.
The diagnostic performance contract is narrower and testable: inactive
collection reaches no timestamp or runtime lock when production timing is not
needed; active capture performs no allocation, sort, log, file I/O, D3D work,
blocking lock, or transcendental math; and all history, histogram, event, and
chart bounds are static.

## Validation and runtime acceptance

Unit tests prove that an inactive frame-pacing gate records no samples,
entering Diagnostics starts a fresh session, timed and instant publication both
work, the cadence and noise-filtered impulse charts retain slow and fast
spikes without drawing steady timer quantization as a sawtooth, periodic events
are classified,
sustained rate shifts coalesce into one episode, the metric window is bounded to ten
seconds, histogram overflow is exact, failed/skipped Presents cannot create
synthetic long intervals, the Present path contains no telemetry logging, all
collector work is statically bounded, production frame delta remains
independent, optional local-light counters ignore inactive-session events, and
detailed PBR diagnostics require both configuration and an active diagnostic
session. UI regressions additionally prove that Configuration and Diagnostics
are separate tabs, that no graph overview exists in the configuration
workspace, that PBR and local-light telemetry do not appear in effect editors,
and that the optional producer gate follows the Diagnostics tab only.

The supported validation commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Validation on 2026-07-23 passed all 296 OMV tests and the complete supported
release build. The local release `omv.dll` SHA-256 is
`bf12fc28bf98a0716c22585025502bb08b83752fc1566157b675bca173c950c9`.

The 2026-07-27 layout/preparation update passed all 309 OMV tests and the
optimized `i686-pc-windows-gnu` OMV release build. The later tabbed-workbench
update, including the persistent header FPS readout, passed all 312 OMV tests
and the same supported optimized release build.

A normal Proton/DXVK playtest should compare a stable scene with the workbench
closed, Configuration open, and Diagnostics open; confirm counters and graphs
begin updating only after selecting Diagnostics; confirm effect controls stay
reachable at 1920x1080; and confirm compile/resource failures still reach the
OMV log while cumulative Present/owner rejections appear in the panel after
selecting Diagnostics.
Static tests cannot establish the final runtime frame-time difference or visual
polish under the shipped font and Proton/DXVK input stack.

# OMV ImGui diagnostics ownership

## Purpose and user-visible behavior

OMV's graphics workbench exposes frame pacing, native-PBR draw details, local
volumetric-light counters, and a fog calibration estimate. These are optional
developer diagnostics collected and displayed in a dedicated `Diagnostics`
tab. Frame intervals are the deliberate exception: a minimal nonblocking QPC
ring runs continuously so opening the tab immediately shows recent pacing.
Aggregate frame analysis and every detailed subsystem producer run only while
Diagnostics is visible and the workbench's ImGui context is ready. Opening
Customize or Presets does not start that detailed work.

Entering `Diagnostics` starts a new detailed-diagnostics session. Successful
local-light counters describe that visit, while frame pacing drains the newest
retained continuous history. Detailed PBR transition collection additionally requires
`graphics.native_pbr.debug_log_draws = true`. That setting no longer keeps its
draw telemetry active after the tab is left.

## Ownership and gate

`omv/src/runtime.rs` owns an atomic diagnostics state containing both the active
bit and a session generation. The gate becomes active only when menu
visibility, ImGui readiness, and the selected Diagnostics tab are all
established. Selecting Customize or Presets, closing the menu, or
releasing D3D9 device resources deactivates it. Reactivation advances the
generation for detailed session counters. The independent continuous Present
ring is not cleared by this transition.

The continuously retained frame-pacing owner is:

- `runtime.rs`: a 2,048-sample atomic Present ring. When Diagnostics is
  visible, the workbench drains it into a one-second one-pole, ten-second
  metric window, fixed 4 Hz aggregate publication, 64-episode spike memory,
  session extremes, and periodicity analysis.

The detailed optional producers are:

- `effects/pbr/diagnostics.rs` and `effects/pbr/samplers.rs`: detailed draw,
  transition, rejection, and sampler telemetry;
- `fnv_local_lights.rs`: traversal, successful capture/format, rendered-light,
  scene-light, and shadowed-light counters;
- `fnv_world_pipeline.rs`: the Diagnostics-only fog distance estimate.

`ScreenShaderRuntime::draw_menu` drains and analyzes frame pacing only when
Diagnostics was already active for the frame. The first frame after selecting
the tab establishes detailed collection; the following frame displays the
retained graph and live summary. No optional producer allocates, logs,
performs file I/O, or blocks a render callback.

## Workbench layout and shader-preparation visibility

The workbench has three top-level tabs with deliberately separate jobs:

- `Presets` is a searchable library for trying installed looks. Technical
  provenance is opt-in, while updating or creating a shareable preset lives
  in the separate Manage Presets view.
- `Customize` is the default editor. Its two-pane workspace places General,
  engine features, built-in effects, and mod shaders on the left and an
  independently scrollable editor on the right. General owns the master
  switch, menu key, depth choice, hot-reload interval, and bulk effect
  controls.
- `Diagnostics` is one full-height scrollable dashboard. It owns frame pacing,
  render-stack failures, depth-route details, native-sky and PBR resource
  state, PBR transition details, local-light counters, and the live fog
  estimate.

No graph is created in Customize and there is no vertical overview region
above the effect editor. Graph history can therefore grow only inside the
Diagnostics tab and cannot alter the configuration workspace. This is the
1920x1080 acceptance contract. The feature list uses a bounded adaptive width,
while the editor receives the remaining window width.

Customize panels present user choices first. ON/OFF list badges describe
the session intent rather than claiming a pipeline is live. Engine features,
built-in effects, finishing families, and mod shaders all use the same
`[STATUS] Name` label contract with exactly one separator space. Normal
active-state, source-type, render-stage, and embedded config-path lines were
removed from effect editing; errors, preparation warnings, compatibility
warnings, and explicit retry actions remain beside the affected control.
Technical counters and live estimates appear only in Diagnostics. Every
focused, hovered, selected, and dimmed tab state uses the same green palette as
the workbench controls; no default blue ImGui tab color remains. The compact
header always shows ImGui's rolling real-time FPS estimate, including while
Customize is selected, without activating the optional diagnostics gate.

The normal header is a compact gradient identity strip containing only the OMV
graphics title and live FPS. It never displays a preset name or persistence
buttons. Current Look changes autosave in the background and never expand the
header. A separate card appears only when `omv.toml` or an external shader
sidecar changed outside the game, because automatic saving is then paused.
That advanced card offers **Reload Files from Disk** and **Keep In-Game Look**
as an explicit conflict decision. Both fixed cards disable ImGui scrollbars
and mouse-wheel scrolling and use ImGui draw-list geometry only.

The historical `Color Grade and Film` editor is presented as eight separate
Customize entries: Final Output, Color Grading, LUT, Debanding, Film
Grain, Vignette, Halation, and Chromatic Aberration. Each entry owns only its
enable switch and relevant controls. This is a UI ownership split, not a
render-pipeline split: `Final Color Pipeline` remains one fused embedded source
and one established final-color pass, so the navigation adds no texture
copies, GPU passes, shader compilation, config fields, or preset-schema
changes.

Frame diagnostics below the custom graph use gradient metric cards for
Current, Average, 1% Low, frame-time distribution, jitter, stable variation,
and 60/30 FPS target delivery. Dense abbreviated status strings were replaced
with labeled values and short explanations. The user-selectable publication
cadence was removed; summaries refresh at a fixed 4 Hz and the raw graph still
advances every visible frame.

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

With Diagnostics inactive, detailed producers reduce to their subsystem gate
check. This includes ordinary Customize and Presets use, not only a closed
menu. They perform no success-counter increments, per-frame counter swaps,
snapshot preparation, or ImGui work. PBR's configured-off fast path retains
its existing single relaxed diagnostic-enable read. Local-light hooks load
their gate once per capture stage and reuse the result for all optional
counters in that stage.

Continuous pacing capture still performs one QPC read before Present and one
bounded atomic publication after a valid Present. It never acquires the OMV
runtime owner, allocates, sorts, formats, logs, touches a D3D resource, or
waits. Writer overlap is rejected. The frequency is initialized outside the
render path.

The frame-pacing ring retains 2,048 atomic `f32` bit patterns. While
Diagnostics is visible, draining the ring performs scalar smoothing and spike
updates. Snapshot percentiles and robust jitter use a fixed 4,096-bin
histogram instead of sorting. Percentiles that land in the final histogram bin
select the exact raw overflow-tail value instead of clipping. Aggregate
publication is fixed at 250 ms. The deprecated
`diagnostics.frame_pacing_update_interval_ms` key remains loadable and
saveable for working-config compatibility but has no runtime effect.

The timestamp captured immediately before original D3D9 Present, its result,
and the render epoch protect measurement continuity. Failed Presents and
nonconsecutive callback epochs are counted and rejected. The next successful
callback becomes a new timestamp origin, so a missed nonblocking callback
cannot be reported as one artificial long frame. Accepted intervals remain
raw. Percentiles, jitter, MAD, budget metrics, and the 240-frame graph all
consume the same unmodified interval sequence.

The visible ImGui menu cannot be literally free because it submits UI geometry.
The diagnostic performance contract is narrower and testable: continuous
capture is fixed, nonblocking, allocation-free, and runtime-owner independent;
detailed collection is tab-gated; and every history, histogram, event, chart,
card, and draw-list bound is static.

## Validation and runtime acceptance

Unit tests prove continuous raw capture without a menu-active gate, the fixed
4 Hz aggregate cadence, slow/fast spike retention, periodic-event
classification, sustained-rate-shift coalescing, the ten-second metric window,
exact histogram overflow, and rejection of failed/skipped Presents without a
synthetic long interval. Source-contract tests reject allocation, sorting,
logging, runtime locking, D3D work, and `Instant` use in the continuous hot
path. Detailed PBR and local-light diagnostics remain gated by an active
Diagnostics session. UI regressions prove the three-tab workbench split,
absence of live graphs in Customize, independent effect-editor ownership, and
the persistent header FPS readout.

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

The 2026-07-28 finishing-navigation, command-deck, and metric-card update
passed all 5 `psycho-imgui` tests, all 368 OMV tests, and the supported
optimized OMV release build.

The later contextual-header and separated preset-management UX update passed
all 6 `psycho-imgui` tests, all 386 OMV tests, and the supported optimized
`i686-pc-windows-gnu` OMV release build.

A normal Proton/DXVK playtest should compare a stable scene with the workbench
closed, Customize open, and Diagnostics open; confirm the graph immediately
shows retained history while detailed counters begin only after selecting
Diagnostics; inspect card legibility and the command-deck actions at minimum
and maximum window sizes; confirm all eight finishing editors stay reachable;
and confirm compile/resource failures still reach the OMV log while cumulative
Present/owner rejections appear in the panel after selecting Diagnostics.
Static tests cannot establish the final runtime frame-time difference or visual
polish under the shipped font and Proton/DXVK input stack.

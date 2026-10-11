# OMV ImGui diagnostics ownership

## Purpose and user-visible behavior

OMV's `Diagnostics` tab is a read-only performance dashboard. Its normal
content is the GPU/environment summary, frame-pacing chart, ten gradient
metric cards, and a compact pacing-event summary. An Issues section appears
only for failures affecting enabled features; it directs users to the affected
Customize panel and existing recovery controls.

Technical capability inventories, hook predecessor identities, feature
active/disabled reports, depth-copy counters, PBR draw/resource details,
local-light telemetry, fog calibration, and measurement-lock reports are not
end-user content. The page contains no configuration controls.

A minimal nonblocking QPC ring captures frame intervals continuously so
opening the tab immediately shows recent pacing. Aggregate analysis runs only
while Diagnostics is visible and ImGui is ready. Explicit PBR debug logging
still requires `graphics.native_pbr.debug_log_draws = true` and a visible
Diagnostics session; its configuration remains loadable and saveable, but the
checkbox and draw details are absent from the dashboard.

## Ownership and gate

`omv/src/runtime.rs` owns an atomic diagnostics state containing both the active
bit and a session generation. The gate becomes active only when menu
visibility, ImGui readiness, and the selected Diagnostics tab are all
established. Selecting Customize or Presets, closing the menu, or
releasing D3D9 device resources deactivates it. Reactivation advances the
generation for explicit PBR debug collection. The independent continuous
Present ring is not cleared by this transition.

The continuously retained frame-pacing owner is:

- `runtime.rs`: a 2,048-sample atomic Present ring. When Diagnostics is
  visible, the workbench drains it into a one-second one-pole, ten-second
  metric window, fixed 4 Hz aggregate publication, 64-episode spike memory,
  session extremes, and periodicity analysis.

Detailed PBR draw, transition, rejection, and sampler collection remains owned
by `effects/pbr/diagnostics.rs` and `effects/pbr/samplers.rs` and is activated
only by the explicit debug setting. The dashboard keeps
`fnv_local_lights.rs` and `fnv_world_pipeline.rs` diagnostic gates inactive
because it no longer displays successful-light counters or fog calibration.
Their rendering, capture/publication, and failure accounting remain independent
of those optional gates.

`runtime.rs` also owns two lazy, machine-local identity views. The active GPU
profile is bound to Fallout's live D3D9 device and cached for that device. The
environment view comes from libpsycho's process-wide cached `SystemProfile`.
The first system-profile read remains behind the visible Diagnostics child;
after publication it is a lock-free static read. Neither identity is
configuration, neither is written to `omv.toml`, and neither is eligible for
preset serialization.

DXVK is never required by this diagnostics owner. Native D3D9 uses the live
device's owning adapter identity directly. DXVK physical-device lookup is an
optional refinement; if its interop or Vulkan-property query fails, the card
keeps the D3D9 device profile but displays `Physical GPU unavailable`; the
card labels its source as `D3D9 compatibility fallback`. It does not present
the potentially spoofed adapter name as the physical GPU. That failure
cannot escape into plugin load, DeferredInit, effect admission, or
rendering policy.

`ScreenShaderRuntime::draw_menu` drains and analyzes frame pacing only when
Diagnostics was already active for the frame. The first frame after selecting
the tab establishes the analysis gate; the following frame displays the
retained graph and live summary. Normal dashboard collection adds no file I/O,
logging, or blocking work to a render callback. Explicit PBR debug logging
retains its existing bounded logging behavior.

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
  renderer/environment summary cards, pacing events, and actionable failures.

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
Technical counters and calibration estimates are absent from the workbench.
Every focused, hovered, selected, and dimmed tab state uses the same green
palette as the workbench controls; no default blue ImGui tab color remains. The compact
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

The dashboard begins with two **System at a Glance** gradient cards. GPU shows
the verified physical renderer and API, or an honest unavailable state.
Environment shows Proton, Wine, or native Windows, with the runtime version and
host system when available. PCI IDs, UUIDs, capability flags, Steam IDs, and
raw identity-query errors are not displayed. System cards stack below 640
pixels of available width and wrap their main values.

**Frame Pacing** follows immediately, retaining the raw graph, adaptive scale,
60/30 FPS budget lines, hover behavior, and threshold colors. Its ten metric
cards cover Current, Average, 1% Low, Typical, Slow Frames, Worst Frame,
Jitter, Variation, and 60/30 FPS Target Delivery. Three-card groups reflow to
two columns below 600 pixels and one below 400 pixels; two-card groups stack
below 400 pixels. All cards disable their own scrollbars and wheel scrolling.
Only the containing dashboard scrolls.

The 1% Low display remains the reciprocal of the 99th-percentile frame time;
it is not an average of the slowest one percent. Hover help supplies this
statistical definition and the definitions of jitter and variation. Summaries
still publish at a fixed 4 Hz while raw graph samples advance every visible
frame. Pacing Events retains counts, event magnitude/age, and repeating-event
intervals, without calibration or classifier-confidence prose.

**Issues** consumes existing production error states. It is absent when no
enabled feature has an error and when the master switch is off. Shader/settings
errors, selected-depth failure, PBR preparation/blocking/contract failures, and
native-sky failure point to their Customize controls. Normal warming, configured
disablement, and per-draw fallbacks do not become warning inventories. Identity
query failures stay within their summary cards and do not imply rendering failed.

Native PBR preparation is production state rather than optional diagnostic
collection. While the workbench is closed, `runtime.rs` may render a small
noninteractive preparation window after ImGui is ready. It reports cache
inventory, local compilation, Direct3D resource creation, progress, and
failure. The window does not request DirectInput capture and does not alter
the `PreLoadGame` input-release contract. Native PBR replacements remain
passive until the complete prepared-bytecode and device-resource catalogs are
ready. The PBR configuration panel keeps only actionable preparation state and
an explicit retry action after a failure. The dashboard does not duplicate
resource inventories or expose the transition-debug switch.

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
Presents remain relaxed process-lifetime atomics. They are not displayed in
the user dashboard or periodically logged from the render callback.

## Performance and memory

With PBR debug collection unrequested, its detailed producer reduces to its
subsystem gate check. Its configured-off fast path retains the existing single
relaxed diagnostic-enable read. Local-light diagnostic gates remain off even
while the dashboard is visible; hooks load their gate once per capture stage
and reuse the result for all optional counters. Successful-work increments and
fog-calibration publication are not requested by the cleaned dashboard.

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
explicit PBR debug collection is tab-gated; and every history, histogram,
event, chart, card, and draw-list bound is static.

The first visible Diagnostics frame may perform libpsycho's bounded CPUID,
Win32 memory, and Wine-export queries while initializing its process-wide
`SystemProfile`, plus the existing device-bound GPU query. Results and failures
are cached. Ordinary gameplay, Presets, Customize, and later Diagnostics
frames perform no repeated environment or driver capability acquisition.

## Validation

Existing behavioral tests cover continuous capture, aggregate publication,
distribution and budget metrics, raw graph ordering, spike retention and
periodicity, and continuity rejection. Existing identity-formatting checks
retain the physical-versus-compatibility distinction and the Proton, Wine, and
native-Windows summaries. Obsolete source-text checks requiring the removed
technical panels and explanatory paragraphs are not acceptance gates.

UI text and layout cleanup uses the normal affected tests, supported release
build, formatting, and diff review. Pixel or screenshot comparisons are not a
required gate. Game-only appearance, integration, and startup behavior are not
established by these offline checks and are not agent gates.

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

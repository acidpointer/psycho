# OMV frame-pacing diagnostics

## Status and purpose

OMV's Diagnostics tab includes a live frame-time graph for rapid effect tuning
and regression triage. It shows throughput, uneven delivery, and isolated
hitches without requiring an external overlay.

The component reports measurement, not attribution. It cannot by itself
identify whether a bad frame came from CPU work, GPU work, presentation, the
game, OMV, DXVK, the display driver, or another plugin.

## User-visible contract

Frame intervals are captured continuously, including while the workbench is
closed. Opening Diagnostics immediately shows the newest retained history
instead of starting from an empty graph. OMV retains at most 2,048 successful,
consecutive Present intervals. Aggregate metrics use the newest suffix
covering at most ten seconds of accepted interval time.

The graph is a raw 240-frame timeline. Every point is one accepted Present
interval in chronological order; OMV does not average, bucket, or otherwise
reshape the plotted values. This makes a single hitch and its immediate
recovery visible and gives the graph the direct response expected from a
real-time frame-time overlay.

The graph advances every ImGui frame. Aggregate publication uses one fixed
250 ms cadence (4 Hz): fast enough to follow a tuning change, slow enough for
the scalar values to remain readable. There is no update-frequency control in
the workbench.

`diagnostics.frame_pacing_update_interval_ms` remains accepted, sanitized, and
written only as a deprecated working-config compatibility key. Runtime
diagnostics ignore it. Removing or repurposing the field would make old
working configurations needlessly incompatible, while leaving it out of the
UI removes the user-facing complexity.

The panel presents these values as labeled gradient cards rather than dense
developer strings:

- live FPS from a one-second time-based one-pole;
- arithmetic-average FPS over the metric window;
- 1% low FPS, defined here as `1000 / P99 frame time`;
- P50, P95, and P99 frame times at 0.125 ms histogram resolution;
- the worst unmodified frame time;
- pacing jitter as P95 of the absolute delta between successive raw intervals;
- median absolute deviation (MAD) around P50;
- percentages meeting the 60 FPS (`16.667 ms`) and 30 FPS (`33.333 ms`)
  budgets;
- off-scale samples, timing gaps, and nonblocking runtime-owner misses.

The two target cards explain their frame-time budgets directly. Jitter and MAD
are labeled as frame-to-frame jitter and stable variation, with short
descriptions of what they measure. Pacing episodes use normal sentences and
separate Latest/Largest fields. Measurement-health text appears only when
intervals or optional runtime samples were skipped and explicitly explains
that nonblocking skips avoid game stalls.

P95 absolute delta detects persistent uneven delivery without allowing one
isolated loading hitch to dominate the jitter scalar. P99, worst, budget
percentages, and off-scale counts still use raw intervals. The histogram covers
`0..511.875 ms` directly. If a percentile lands in its overflow bin, OMV
selects the exact raw tail value rather than clipping it.

The Y scale uses stable budget-aware tiers:

| P99 frame time | Graph maximum |
|---|---:|
| up to 28 ms | 35 ms |
| up to 42 ms | 50 ms |
| up to 65 ms | 75 ms |
| above 65 ms | 100 ms |

The 60 and 30 FPS guides always fit. A value above the current tier remains
exact in the metrics and receives an overflow marker at the top of the graph.
The tiered scale avoids constant small rescaling while retaining useful detail
for both 60 FPS and 30 FPS workloads.

Graph segments, their translucent fill, and the current-frame marker use frame
budget color:

- green: at or below the 60 FPS budget;
- amber: above the 60 FPS budget and at or below the 30 FPS budget;
- red: above the 30 FPS budget.

The background gradient, subtle grid, guide labels, line glow, fill, current
point, overflow markers, and frame-relative hover tooltip are emitted as Dear
ImGui draw-list geometry. They do not add a game render pass.

## Spike analysis

Raw samples are also fed to a bounded adaptive spike detector when the
Diagnostics UI consumes them. It warms up for 30 accepted intervals and then
follows a baseline with a two-second response. A frame becomes an excursion
when its baseline distance reaches:

```text
max(2 ms, 25% of baseline, 6 * adaptive noise)
```

Positive excursions are `SLOW`; negative excursions are `FAST`. Consecutive
same-direction outliers coalesce into one episode, so a sustained shift from
60 to 30 FPS is not reported once per frame. The newest 64 episodes are
retained for periodicity analysis, along with cumulative counts and
session-wide slow/fast extremes.

Periodicity is evaluated independently by direction. It considers the newest
17 timestamps, uses the median interval as a candidate period, rejects
intervals outside `max(25 ms, 15% of period)`, and requires at least three
inliers plus 75% coverage. The UI reports direction, mean period,
standard-deviation spread, repeats, and confidence.

Because aggregate and spike processing is intentionally absent from the closed
render path, events older than the retained 2,048-frame continuous ring are not
reconstructed when Diagnostics is opened. This is the bounded-history
tradeoff, not silent unbounded collection.

## Ownership and render ordering

`omv/src/hooks.rs` calls `runtime::present_frame_started_at` immediately before
the original D3D9 `Present`. The original return value, captured counter, and
current render epoch then reach `runtime::finish_present_frame`.

The measurement is CPU-observed Present-submission cadence. Capturing after
`Present` would mix cadence with differences between adjacent Present wait
times and can manufacture a sawtooth. It is not a GPU timestamp, scan-out
timestamp, or timing-source attribution.

`omv/src/runtime.rs` owns:

- the continuous high-resolution-counter origin and atomic sample ring;
- continuity and failed-Present rejection;
- the workbench-owned `FramePacing` history and adaptive analysis;
- aggregate snapshots and panel composition.

An interval is published only when both endpoints are successful and their
render epochs are consecutive. A failed Present, missing callback, invalid or
regressing counter, or overlapping writer invalidates or rejects the interval.
The next valid callback establishes a new origin; OMV never converts an
unknown number of callbacks into one false long frame.

The atomic ring publishes a sample value before publishing its sequence with
release ordering. The UI acquires the sequence and copies only the retained
suffix newer than its cursor. If the workbench has been closed longer than the
ring capacity, it starts from the oldest still-retained sample.

Depth of field has separate `PresentFrameTiming` ownership because it needs a
production delta while enabled. Its `Instant` timestamp remains gated by the
depth-of-field requirement and does not populate diagnostic history.

The live FPS one-pole has a one-second time constant and bounds its input to
100 ms so a suspended process does not leave the live readout stale for many
seconds. The bound affects only smoothing; historical metrics retain the full
accepted interval.

`psycho-imgui/src/bridge.cpp` owns the reusable telemetry renderer. OMV passes
a zero sample interval to select frame-relative axis and hover labels. The
existing impulse style remains reusable by other callers but is not used by
the frame-pacing panel.

## Performance and memory contract

The always-on path is deliberately smaller than the old open-menu collector.
For each Present it performs:

1. one `QueryPerformanceCounter` call before native Present (its frequency is
   queried once during OMV configuration, outside the render path);
2. one nonblocking atomic writer claim after Present;
3. fixed scalar validation and, when an interval is valid, one atomic `f32`
   bit-pattern write plus sequence publication.

It performs no runtime-owner acquisition, allocation, smoothing, spike
analysis, histogram work, sort, formatting, logging, file I/O, D3D resource
operation, or draw submission. Writer overlap is rejected rather than waited
on. Failed or discontinuous callbacks only update fixed counters and origins.

Opening Diagnostics drains at most 2,048 samples. Live smoothing and bounded
spike analysis happen during that drain. Aggregate publication uses fixed stack
storage and a 4,096-bin `u16` histogram, and scans at most the retained
ten-second suffix. Selection is used only for a requested percentile in the
histogram overflow tail. The graph copies at most 240 raw values on each
visible frame. Persistent `FramePacing` storage remains below 16 KiB.

No telemetry can be literally free: continuous history necessarily costs one
counter query and a small fixed atomic transaction per Present. The static
contract proves that the path is bounded, nonblocking, allocation-free, and
independent of OMV's runtime mutex. It cannot prove a zero timing delta on
every CPU, Wine/Proton version, or driver. Ordinary runtime comparison remains
the final acceptance gate.

Detailed PBR, world-pipeline, and effect counters remain gated by
`menu_diagnostics_active` and run only while the Diagnostics tab is visible.
Continuous frame intervals do not broaden those costs.

## Failure behavior

- The first successful callback establishes an origin and emits no sample.
- Failed Presents and render-epoch gaps reject the incomplete interval and
  prevent cross-gap aggregation.
- Invalid counter values or frequency reject the interval.
- A simultaneous writer never blocks; it increments the timing-gap counter.
- If more than 2,048 samples arrive before the UI drains them, only the newest
  2,048 are available.
- Empty or one-sample histories show a collecting message and finite zero
  metrics.
- Values above the graph scale are clipped only visually and marked; raw
  aggregates retain them.

## Automated validation

Focused tests prove:

- exact QPC interval conversion and rejection of failed, skipped, regressing,
  and non-consecutive endpoints;
- synthetic 10/20/5 ms intervals reconstruct exact raw history, average,
  percentiles, worst, and jitter;
- continuous capture has no menu-active gate;
- the capture source contains no allocation, sort, logging, runtime lock, D3D
  work, or `Instant` call;
- capture precedes the depth-of-field early return and runtime-owner attempt;
- chronological 2,048-sample ring behavior and ten-second metric window;
- a raw 240-frame chart preserves order, adjacent jitter, short slow/fast
  excursions, and a single long hitch;
- stable scale tiers always retain both frame-budget guides;
- distribution, overflow-tail, smoothing, spike episode, periodicity, and
  invalid-input behavior;
- fixed storage bounds;
- fixed 250 ms aggregate publication independent of the deprecated config key;
- the telemetry renderer uses custom gradient, budget-colored segments, glow,
  current marker, and frame-relative hover instead of `ImGui::PlotLines`;
- diagnostics and workbench summary cards use draw-list backgrounds only and
  add no game render pass or D3D resource.

Supported validation:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-imgui
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Validation on 2026-07-28 passed all 5 `psycho-imgui` tests, all 368 OMV tests,
and the optimized `i686-pc-windows-gnu` OMV release build.

## Runtime acceptance

Before release:

1. launch at stable 30, 60, and uncapped rates, leave the workbench closed for
   several seconds, then confirm Diagnostics opens with recent history;
2. confirm the raw graph advances every visible frame while scalar cards
   refresh automatically at 4 Hz and no frequency selector remains;
3. verify the 60/30 guides, tier transitions, glow/fill, current marker,
   overflow markers, and hover tooltips remain legible at supported UI scales;
4. induce isolated and repeating hitches and confirm the exact raw peak,
   immediate recovery, direction, and periodic summary;
5. verify Alt-Tab, loading, failed Present, device reset, resolution change,
   and menu close/reopen do not create an aggregate false hitch;
6. compare a stable scene with this build against a build with continuous
   capture compiled out and confirm no material median/P99 regression;
7. separately compare Diagnostics closed and open; any open-menu cost includes
   ImGui geometry and aggregate publication and must remain acceptable.

The automated gates cannot prove final legibility or performance neutrality
under the user's NVIDIA driver and Proton/DXVK stack; those remain ordinary
playtest observations.

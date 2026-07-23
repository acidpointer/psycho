# OMV frame-pacing diagnostics

## Status and purpose

OMV's graphics workbench includes a compact frame-pacing diagnostic at the top
of the menu. It is intended for rapid effect tuning and regression triage: the
operator can see whether a visual change altered throughput, produced uneven
delivery, or introduced isolated hitches without leaving the game or inferring
timing quality from an FPS scalar.

The component reports measurement, not attribution. It cannot by itself tell
whether a bad frame came from CPU work, GPU work, presentation, the game, OMV,
DXVK, or another plugin.

## User-visible contract

The collector retains up to 2,048 completed present intervals while the
workbench is open. Published metrics use the newest suffix covering at most ten
seconds of accepted interval time; rejected holes are excluded and reported
separately. Raw capture remains per frame. The `UPDATE` selector controls only
visible publication:

- `Every frame // instant` publishes after every valid interval;
- 50, 100, 250, 500, 1,000, and 2,000 ms timed presets trade response speed for
  a steadier readout;
- a non-preset value loaded from TOML is shown as a custom cadence.

`diagnostics.frame_pacing_update_interval_ms` owns the persisted value. `0`
means instant mode; nonzero values are clamped to `50..=2000`. The default
remains 500 ms and legacy configurations receive that default.

The panel reports:

- live FPS from a one-second time-based one-pole;
- arithmetic-average FPS and frame time over the visible window;
- 1% low FPS, defined here as `1000 / P99 frame time`;
- P50, P95, and P99 frame times at 0.125 ms histogram resolution;
- the worst unmodified frame time in the window;
- pacing jitter as P95 of the absolute delta between successive raw frame
  times;
- median absolute deviation (MAD) around P50 as the stable-window noise floor;
- the percentage of samples meeting the 60 FPS (`16.667 ms`) and 30 FPS
  (`33.333 ms`) budgets.

P95 absolute delta measures persistent uneven delivery without allowing one
isolated loading hitch to dominate the jitter readout. P99, worst, budget-hit,
and off-scale metrics still use every raw interval, so the robust jitter value
does not hide a stall. The histogram covers `0..511.875 ms` directly. If a
requested percentile lands in its final overflow bin, OMV selects the exact
raw tail value instead of silently clipping the result to 511.875 ms.

The primary graph uses a real time axis with one point per 100 ms bucket.
Before bucketing, OMV averages adjacent accepted Present intervals below
100 ms. This cancels the common short/long submission pair without changing
its two-frame arithmetic mean. Pair values are then averaged inside each
100 ms bucket, and a bucket with no completed pair holds the last older
observed cadence. Intervals of 100 ms or more bypass pair normalization and
remain a single peak in their bucket.

This separation is intentional. The connected primary plot is a cadence trend,
while P50/P95/P99, worst, jitter, MAD, budget hits, off-scale counts, and the
impulse plot continue to use the accepted raw CPU Present intervals. The panel
labels both contracts. The previous whole-frame bucket assignment let the
phase-dependent number of short and long intervals alternate between buckets;
a perfectly repeating `1/32 ms` submission pattern consequently produced
`11.3/19.6 ms` teeth instead of its stable `16.5 ms` pair cadence.

A second compact graph shows meaningful excursions among the newest 100 raw
frames as signed deviation from the adaptive baseline. Positive/up means a
slower frame; negative/down means a faster frame. Values below the same
`max(2 ms, 25% of baseline, 6 * adaptive noise)` threshold used by the spike
detector are plotted at zero. Nonzero samples are drawn as independent
zero-baseline impulses rather than a connected line. This prevents normal
timer/VSync quantization and the triangles between isolated events from
becoming a permanent sawtooth while retaining the unfiltered P95 delta in the
`JITTER` scalar. A slow frame and its immediate fast rebound remain visible
even when both occur inside one 100 ms time bucket. The fixed
`-50..50 ms` scale and overflow markers make direction and magnitude
comparable between observations.

The Y range is fixed at `0..50 ms`; it no longer rescales when P99 changes.
This keeps the 60 and 30 FPS guides stationary and makes separate observations
visually comparable. Raw intervals above 50 ms remain exact in P99/worst and
are counted in the text summary.

Color communicates budget position only:

- green: at or below the 60 FPS frame budget;
- amber: above the 60 FPS budget and at or below the 30 FPS budget;
- red: above the 30 FPS budget.

It does not label a stable 30 FPS workload as an engine failure. The two budget
hit percentages remain available so the operator can apply the target relevant
to the current test.

`DATA QUALITY` reports intervals rejected during the current workbench
session. The panel also exposes process-lifetime nonblocking owner rejections
and failed Presents. A nonzero rejection count means OMV deliberately left a
hole rather than converting an unknown number of callbacks into one false long
frame. It does not mean that neighboring accepted measurements are fabricated.

## Spike analysis

The spike detector is session-owned and independent from the visible update
cadence. It warms up for 30 valid intervals, then follows an adaptive baseline
with a two-second response. A frame becomes an excursion only when its distance
from the baseline reaches all relevant noise protection through this threshold:

```text
max(2 ms, 25% of baseline, 6 * adaptive noise)
```

Positive excursions are labeled `SLOW`; negative excursions are labeled
`FAST`. Consecutive same-direction outliers are coalesced into one episode, so
a sustained switch from 60 to 30 FPS is not reported as one spike per frame.
The most extreme frame and severity within the episode are retained.
`NOTICE`, `MAJOR`, and `SEVERE` combine absolute and baseline-relative
magnitude; they describe the excursion, not its CPU/GPU cause.

The session keeps the newest 64 episodes for cadence analysis, cumulative
slow/fast counts, the latest episode, and separate session-wide largest slow
and fast episodes. Session extremes therefore survive rollover of the cadence
ring. Closing and reopening the workbench deliberately starts a new session.

Periodicity is evaluated independently for slow and fast episodes. It considers
the newest 17 timestamps in a direction, uses the median interval as the
candidate period, rejects intervals outside `max(25 ms, 15% of period)`, and
requires at least three inlier intervals plus 75% coverage. The panel reports
direction, mean inlier period, standard-deviation spread, repeat count, and a
coverage/regularity confidence. Fewer events or an irregular series is
reported explicitly as no repeatable cadence.

## Ownership and render ordering

`omv/src/hooks.rs` captures the gated timestamp immediately before calling the
original D3D9 `Present`. Its return value, timestamp, and current render epoch
then reach `omv/src/runtime.rs`. The metric is CPU-observed Present-submission
cadence. Capturing after `Present` was incorrect: completion deltas equal
submission cadence plus the difference between adjacent Present wait times, so
alternating wait duration manufactures a sawtooth in an otherwise stable
stream. This is not a GPU timestamp, scan-out timestamp, or attribution of
where the submitted frame later waits.

`ScreenShaderRuntime::finish_present_frame` forms an interval only when both
endpoints are successful and their render epochs are consecutive. A failed
Present, a nonblocking runtime-owner miss, or a regressing synthetic clock
invalidates the origin; the next accepted callback establishes a new origin
without adding an aggregate multi-frame interval. The same continuity rule
protects the production `PresentFrameTiming` used by depth of field.

`omv/src/runtime.rs` owns capture, fixed history, summary statistics, and panel
composition. Capture occurs only while the ImGui context is ready and the
workbench is open. The first callback after opening only establishes the time
origin. A generation stored with the atomic diagnostics gate makes every
close/reopen transition a new session even though the closed fast path does
not acquire the runtime owner. Invalid synthetic values are rejected; real
finite, consecutive intervals are retained in full.

`FramePacing` separates capture from presentation. Every valid interval performs
one fixed-ring write, one rational one-pole live update, and bounded adaptive
spike state work. Timed modes publish after their configured amount of captured
time; instant mode publishes every frame. The snapshot copies only the newest
ten-second suffix, builds fixed histograms for distributions, and produces at
most 100 points in each chart. ImGui frames between timed publications reuse
the prior snapshot unchanged.

Depth of field still needs a production frame delta while its pipeline is
enabled. That timing has separate `PresentFrameTiming` ownership and does not
populate the diagnostic ring or its aggregates.

The live FPS one-pole has a one-second time constant and bounds its input to
`100 ms` so an Alt-Tab, loading pause, or suspended process does not leave the
live readout stale for many seconds. Unlike the old fixed `0.08` per-frame
weight, its response does not become faster merely because the frame rate is
higher. The rational coefficient avoids a per-frame transcendental operation.
The bound does not alter historical samples or the depth-of-field delta.

The menu is built during OMV's existing present phase, after any final
image-space pass and before the captured D3D9 state is restored. The graph is
Dear ImGui geometry only. It creates no OMV render target, shader, sampler,
history texture, D3D pass, or engine hook, and does not change effect ordering.

`psycho-imgui/src/bridge.cpp` owns the reusable telemetry drawing primitive.
OMV supplies a positive `0.1` second interval for the cadence timeline and zero
for the filtered impulse graph, selecting time-relative and frame-relative
hover behavior respectively. The chart ABI exposes an explicit
`impulse_from_zero` style so isolated events are not connected.

## Performance, memory, and failure behavior

When the workbench is closed and depth-of-field does not need production frame
delta, the pre-Present capture returns after atomic gate reads and before
`Instant::now`; the finish callback returns before runtime acquisition. The frame-pacing collector
therefore performs no timestamp query, lock attempt, ring write, smoothing,
spike work, snapshot work, allocation, I/O, logging, or D3D work. If
depth-of-field is enabled, its separate production timer still runs by design
and never populates diagnostics.

While the workbench is open, capture writes one `f32`, advances fixed scalar
state, and may write one fixed spike episode. It allocates nothing, performs no
sort, logging, I/O, D3D work, or lock, and uses no transcendental math.
Publication uses a 4,096-bin `u16` histogram instead of sorting the raw and
delta arrays. All scratch storage is fixed stack memory. This keeps even
instant publication bounded to linear scans over at most 2,048 samples and
4,096 bins. Selection is used only when a requested percentile falls in the
histogram's overflow tail. Timed publication performs the same work only at
the chosen cadence. Persistent collector storage remains under 16 KiB,
including raw history, spike memory, and published charts.

The Present hook never performs telemetry logging. Earlier code serviced
cumulative lock-contention logging every 600 render epochs; after the first
miss that repeated synchronous log work forever at a fixed cadence. The hook
now only increments a relaxed atomic on an actual rejection. The workbench
reads and displays those cumulative counters while it is already rendering.

The open ImGui workbench itself necessarily submits UI geometry and therefore
cannot be literally zero-cost. The contract is that optional counters add no
unbounded, blocking, allocating, or periodically sorting work and that closing
the workbench removes their capture cost before runtime acquisition. Runtime
FPS neutrality still requires an ordinary Proton/DXVK comparison; static tests
cannot prove a zero timing delta.

With fewer than two intervals the panel displays its available scalar values
and a collecting-state message. Empty histories produce finite zero metrics.
NaN, infinity, and negative samples cannot enter the timeline. Device loss and
reset stop collection until the ImGui device objects recover; failed Presents
are rejected and the next rendered workbench session starts a fresh CPU
history.

## Automated validation

The focused tests in `omv/src/runtime.rs` prove:

- chronological fixed-capacity ring behavior after wraparound and a bounded
  ten-second metric suffix;
- no frame-pacing samples while the workbench diagnostic gate is closed and a
  generation-forced fresh history after it reopens without requiring a closed
  runtime callback;
- failed Presents and skipped finish callbacks are rejected instead of being
  merged into false long frames, for both diagnostics and production DoF
  timing;
- a synthetic successful Present-submission timeline reconstructs its exact
  10/20/5 ms raw intervals and their average, percentiles, worst, and jitter;
- production depth-of-field frame delta remains independent from the diagnostic
  ring;
- average, percentile, 1% low, worst, jitter, and budget-hit calculations;
- percentiles above the fixed histogram range retain their exact raw values;
- visible metrics honor a custom timed boundary and instant mode publishes each
  frame;
- alternating 10/20 ms raw frames become a stable bucketed trend while P95
  delta jitter remains 10 ms;
- stable 16/17 ms timer quantization produces no signed-chart sawtooth, while
  short slow and fast excursions remain visible;
- stable alternating `1/32 ms` and `10/20 ms` submission pairs produce exactly
  flat `16.5 ms` and `15 ms` primary trends while raw jitter stays exact;
- a single 250 ms hitch remains exact in raw worst/off-scale metrics and
  appears in exactly one cadence bucket;
- the hook captures its timestamp before the native Present call and consumes
  it only after the call returns;
- periodic slow spikes produce the expected period while irregular events are
  rejected as outliers;
- a sustained frame-rate transition is one episode rather than one event per
  frame;
- session extremes survive the bounded cadence-ring policy;
- the capture path contains no allocation, sort, logging, lock, or timestamp
  query and the closed top-level gate precedes runtime acquisition;
- the Present hook contains no periodic logging/telemetry service;
- history, chart, histogram, and spike-memory bounds remain fixed;
- invalid samples cannot poison any visible aggregate.

The supported gates are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Validation on 2026-07-23 passed all 296 OMV tests and the complete supported
release build. The local release `omv.dll` SHA-256 is
`bf12fc28bf98a0716c22585025502bb08b83752fc1566157b675bca173c950c9`.

Compilation and deterministic metric tests cannot prove final legibility,
hover ergonomics, font scaling, or real timing behavior under Proton/DXVK.

## Runtime acceptance

Before release, open the workbench at stable 30, 60, and uncapped frame rates
and confirm:

1. every update preset holds and publishes at the labeled cadence, while
   `Every frame // instant` visibly responds on the next frame;
2. 60/30 FPS guides are distinct, labels do not overlap, and ordinary data is
   legible against the fixed scale;
3. the cadence chart remains stable, while the impulse chart points up for slow
   / down for fast with correct hover values and no steady-cadence sawtooth;
4. repeated induced hitches report a stable period while isolated hitches keep
   their direction, severity, latest age, and session extreme;
5. Alt-Tab, loading screens, device reset, resolution change, and menu close /
   reopen do not corrupt history or input handling;
6. stable-scene captures at each timed cadence and in instant mode do not show
   a detector-generated recurring frame-time cadence;
7. compare the workbench closed/open at a stable scene and confirm no material
   median or P99 regression beyond the unavoidable ImGui overlay itself.

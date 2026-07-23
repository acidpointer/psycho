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
seconds. Raw capture remains per frame; visible text and chart data publish at
a fixed 500 ms cadence so values remain readable.

The panel reports:

- live FPS from a one-second time-based exponential moving average;
- arithmetic-average FPS and frame time over the visible window;
- 1% low FPS, defined here as `1000 / P99 frame time`;
- nearest-rank P50, P95, and P99 frame times;
- the worst unmodified frame time in the window;
- pacing jitter as P95 of the absolute delta between successive raw frame
  times;
- the percentage of samples meeting the 60 FPS (`16.667 ms`) and 30 FPS
  (`33.333 ms`) budgets.

P95 absolute delta measures persistent uneven delivery without allowing one
isolated loading hitch to dominate the jitter readout. P99, worst, budget-hit,
and off-scale metrics still use every raw interval, so the robust jitter value
does not hide a stall.

The graph uses a real time axis with one point per 100 ms bucket. Each point is
the time-weighted mean of the raw intervals overlapping that bucket.
Alternating short/long frames therefore produce an interpretable pacing trend
instead of a dense sawtooth. A long frame contributes across every bucket it
occupies rather than disappearing during aggregation.

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

## Ownership and render ordering

`omv/src/runtime.rs` owns capture, fixed history, summary statistics, and panel
composition. `ScreenShaderRuntime::finish_present_frame` records the interval
between successive successful finish-present callbacks only while the ImGui
context is ready and the workbench is open. The first callback after opening
only establishes the time origin. Closing the workbench stops capture;
reopening starts a fresh history. Invalid synthetic values are rejected; real
finite intervals are retained in full.

`FramePacing` separates capture from presentation. `record_sample` performs the
ring write and time-based EMA update on every valid interval. It publishes a
new fixed snapshot only after 500 ms of captured time. The snapshot copies only
the newest ten-second suffix, computes raw distributions and P95 delta jitter,
then produces at most 100 chart buckets. ImGui frames between publications
reuse the prior snapshot unchanged.

Depth of field still needs a production frame delta while its pipeline is
enabled. That timing has separate `PresentFrameTiming` ownership and does not
populate the diagnostic ring or its aggregates.

The live FPS EMA has a one-second time constant and bounds its input to `100 ms`
so an Alt-Tab, loading pause, or suspended process does not leave the live
readout stale for many seconds. Unlike the old fixed `0.08` per-frame weight,
its response does not become faster merely because the frame rate is higher.
The bound does not alter historical samples or the depth-of-field delta.

The menu is built during OMV's existing present phase, after any final
image-space pass and before the captured D3D9 state is restored. The graph is
Dear ImGui geometry only. It creates no OMV render target, shader, sampler,
history texture, D3D pass, or engine hook, and does not change effect ordering.

`psycho-imgui/src/bridge.cpp` owns the reusable telemetry drawing primitive.
OMV supplies a positive `0.1` second sample interval, selecting its existing
time-axis and time-relative hover behavior.

## Performance, memory, and failure behavior

While the workbench is open, capture writes one `f32` into a 2,048-entry ring
and updates one EMA per completed frame. With the workbench closed, the
frame-pacing collector performs no diagnostic timestamp query, ring write, EMA
update, or aggregate work. It performs no allocation, I/O, logging, D3D work,
or blocking operation. OMV's existing top-level runtime acquisition remains
`try_lock`-only; if that owner is busy, the finish callback still skips rather
than waits.

The detailed snapshot is produced at most twice per second while the workbench
is open. It copies the ring into fixed stack arrays, sorts bounded raw and
delta arrays, and performs bounded linear reductions. There is no heap
allocation. Persistent raw history costs 8 KiB; the published chart costs 400
bytes. Rendering produces at most 100 line segments and fills through the
existing ImGui frame.

With fewer than two intervals the panel displays its available scalar values
and a collecting-state message. Empty histories produce finite zero metrics.
NaN, infinity, and negative samples cannot enter the timeline. Device loss and
reset stop collection until the ImGui device objects recover; the next rendered
workbench session starts a fresh CPU history.

## Automated validation

The focused tests in `omv/src/runtime.rs` prove:

- chronological fixed-capacity ring behavior after wraparound and a bounded
  ten-second metric suffix;
- no frame-pacing samples while the workbench diagnostic gate is closed and a
  fresh history after it reopens;
- production depth-of-field frame delta remains independent from the diagnostic
  ring;
- average, percentile, 1% low, worst, jitter, and budget-hit calculations;
- visible metrics remain unchanged before the 500 ms publication boundary;
- alternating 10/20 ms raw frames become a stable bucketed trend while P95
  delta jitter remains 10 ms;
- a single 250 ms hitch remains exact in raw worst/off-scale metrics without
  poisoning robust jitter;
- invalid samples cannot poison any visible aggregate.

The supported gates are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Validation on 2026-07-23 passed all 267 OMV tests and the supported release
build. The resulting `omv.dll` SHA-256 was
`f3becd75325060d0973e81138e94835e4845c8a9668e39ce511e630b21707944`.

Compilation and deterministic metric tests cannot prove final legibility,
hover ergonomics, font scaling, or real timing behavior under Proton/DXVK.

## Runtime acceptance

Before release, open the workbench at stable 30, 60, and uncapped frame rates
and confirm:

1. the live, average, percentile, worst, jitter, and budget values update twice
   per second and remain readable at the minimum and preferred menu sizes;
2. 60/30 FPS guides are distinct, labels do not overlap, and ordinary data is
   legible against the fixed scale;
3. hover selects the intended 100 ms bucket at both ends and the center;
4. an induced hitch produces an exact worst value and raw off-scale count, then
   ages out after ten seconds;
5. Alt-Tab, loading screens, device reset, resolution change, and menu close /
   reopen do not corrupt history or input handling;
6. the workbench itself does not introduce a recurring frame-time cadence.

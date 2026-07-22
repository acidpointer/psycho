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

The panel presents the latest 180 completed present intervals in chronological
order and reports:

- live FPS from OMV's existing exponential moving average;
- arithmetic-average FPS and frame time over the visible window;
- 1% low FPS, defined here as `1000 / P99 frame time`;
- nearest-rank P50, P95, and P99 frame times;
- the worst unmodified frame time in the window;
- pacing jitter as the root mean square of each successive frame-time delta;
- the percentage of samples meeting the 60 FPS (`16.667 ms`) and 30 FPS
  (`33.333 ms`) budgets.

The graph uses frames, not estimated wall time, on its horizontal axis. Hovering
a point shows its exact frame-relative age and measured milliseconds. Dashed
budget guides and restrained warning/critical bands make budget misses visible
without requiring the reader to interpret the Y position from memory.

The Y range is `1.25 * P99`, clamped to a minimum of `41.667 ms` and a maximum
of `100 ms`. This keeps ordinary 60/30 FPS pacing legible when one exceptional
hitch occurs. Values are never truncated in storage or statistics: off-scale
samples are counted in the text summary, retain their exact hover value, and
receive red edge markers on the graph. The worst-time metric therefore remains
honest even when the graph uses a tighter diagnostic scale.

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
between successive successful finish-present callbacks. The first callback
only establishes the time origin. Invalid synthetic values are rejected; real
finite intervals are retained in full.

The live FPS EMA bounds its input to `100 ms` so an Alt-Tab, loading pause, or
suspended process does not leave the live readout stale for many seconds. This
does not alter the historical sample, percentiles, worst value, jitter, budget
rates, graph marker, or depth-of-field frame-delta clamp.

The menu is built during OMV's existing present phase, after any final
image-space pass and before the captured D3D9 state is restored. The graph is
Dear ImGui geometry only. It creates no OMV render target, shader, sampler,
history texture, D3D pass, or engine hook, and does not change effect ordering.

`psycho-imgui/src/bridge.cpp` owns the reusable telemetry drawing primitive.
A non-positive `sample_interval_seconds` selects its frame-index axis; the
positive time-axis behavior used by the Psycho dashboard remains unchanged.
The bridge also marks values outside either Y bound while preserving their real
value for hover inspection.

## Performance, memory, and failure behavior

Capture writes one `f32` into a 180-entry ring and updates one EMA per completed
frame. It performs no allocation, I/O, logging, D3D work, or blocking operation.
OMV's existing top-level runtime acquisition remains `try_lock`-only; if that
owner is busy, the finish callback still skips rather than waits.

The detailed snapshot is produced only while the workbench is open. It copies
the ring into a fixed stack array, sorts a second fixed 180-value array for
percentiles, and performs bounded linear reductions. The prior per-open-frame
`Vec` allocation was removed. Persistent history costs 720 bytes; the snapshot
uses two bounded arrays and scalar metrics. Rendering produces at most 180 line
segments, fills, and overflow markers through the existing ImGui frame.

With fewer than two intervals the panel displays its available scalar values
and a collecting-state message. Empty histories produce finite zero metrics.
NaN, infinity, and negative samples cannot enter the timeline. Device loss and
reset retain the CPU history and use the existing ImGui device-object recovery
path.

## Automated validation

The focused tests in `omv/src/runtime.rs` prove:

- chronological fixed-capacity ring behavior after wraparound;
- average, percentile, 1% low, worst, jitter, and budget-hit calculations;
- a single 250 ms hitch remains exact while the adaptive graph preserves the
  normal 10 ms signal and reports one off-scale sample;
- invalid samples cannot poison any visible aggregate.

The supported gates are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Compilation and deterministic metric tests cannot prove final legibility,
hover ergonomics, font scaling, or real timing behavior under Proton/DXVK.

## Runtime acceptance

Before release, open the workbench at stable 30, 60, and uncapped frame rates
and confirm:

1. the live, average, percentile, worst, jitter, and budget values remain
   readable at the minimum and preferred menu sizes;
2. 60/30 FPS guides are distinct, labels do not overlap, and ordinary data is
   not hidden by the filled graph;
3. hover selects the intended frame at both ends and the center of the graph;
4. an induced hitch produces an exact worst value, an off-scale count and red
   edge marker when applicable, then ages out after 180 newer frames;
5. Alt-Tab, loading screens, device reset, resolution change, and menu close /
   reopen do not corrupt history or input handling;
6. the workbench itself does not introduce a recurring frame-time cadence.

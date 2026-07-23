# OMV ImGui diagnostics ownership

## Purpose and user-visible behavior

OMV's graphics workbench exposes frame pacing, native-PBR draw details, local
volumetric-light counters, and a fog calibration estimate. These are optional
developer diagnostics. Their producers run only while the workbench is open
and its ImGui context is ready. Closing the workbench stops optional collection,
not merely UI formatting and rendering.

Opening the workbench starts a new diagnostic session. Frame pacing and
successful local-light counters are cleared so the displayed values describe
the current session. Detailed PBR collection additionally requires
`graphics.native_pbr.debug_log_draws = true`. That setting no longer keeps its
draw telemetry active after the workbench closes.

## Ownership and gate

`omv/src/runtime.rs` owns an atomic diagnostics state containing both the active
bit and a session generation. The gate becomes active only when both menu
visibility and ImGui readiness are established. Closing the menu or releasing
D3D9 device resources deactivates it. Reactivation advances the generation, so
the frame-pacing owner clears its history and stale timestamp even though the
closed fast path never acquires the runtime lock.

The optional producers are:

- `runtime.rs`: the 2,048-sample frame-pacing ring, one-second one-pole,
  ten-second metric window, configurable visible publication, 64-episode spike
  memory, session extremes, and periodicity analysis;
- `effects/pbr/diagnostics.rs` and `effects/pbr/samplers.rs`: detailed draw,
  transition, rejection, and sampler telemetry;
- `fnv_local_lights.rs`: traversal, successful capture/format, rendered-light,
  scene-light, and shadowed-light counters;
- `fnv_world_pipeline.rs`: the menu-only fog distance estimate.

The menu reads and formats snapshots only in `ScreenShaderRuntime::draw_menu`.
No optional producer allocates, logs, performs file I/O, or blocks a render
callback.

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

With the menu closed, optional producers reduce to their subsystem gate check.
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
and arrays and happens only on the user-driven open transition, never per draw.

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
The diagnostic performance contract is narrower and testable: closed
collection reaches no timestamp or runtime lock when production timing is not
needed; active capture performs no allocation, sort, log, file I/O, D3D work,
blocking lock, or transcendental math; and all history, histogram, event, and
chart bounds are static.

## Validation and runtime acceptance

Unit tests prove that a closed frame-pacing gate records no samples, reopening
starts a fresh session, timed and instant publication both work, the cadence
and noise-filtered impulse charts retain slow and fast spikes without drawing
steady timer quantization as a sawtooth, periodic events are classified,
sustained rate shifts coalesce into one episode, the metric window is bounded to ten
seconds, histogram overflow is exact, failed/skipped Presents cannot create
synthetic long intervals, the Present path contains no telemetry logging, all
collector work is statically bounded, production frame delta remains
independent, optional local-light counters ignore closed-menu events, and
detailed PBR diagnostics require both configuration and an open menu.

The supported validation commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Validation on 2026-07-23 passed all 296 OMV tests and the complete supported
release build. The local release `omv.dll` SHA-256 is
`bf12fc28bf98a0716c22585025502bb08b83752fc1566157b675bca173c950c9`.

A normal Proton/DXVK playtest should compare a stable scene with the workbench
closed and open, confirm diagnostics begin updating only after opening, and
confirm compile/resource failures still reach the OMV log while cumulative
Present/owner rejections appear in the panel after opening. Static tests cannot
establish the final runtime frame-time difference.

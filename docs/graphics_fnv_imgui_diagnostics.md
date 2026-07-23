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

`omv/src/runtime.rs` owns `MENU_DIAGNOSTICS_ACTIVE`. The gate becomes active
only when both menu visibility and ImGui readiness are established. Closing the
menu or releasing D3D9 device resources deactivates it. The recovered ImGui
frame reactivates the gate if the menu is still open.

The optional producers are:

- `runtime.rs`: the 180-sample frame-pacing ring and EMA;
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
menu cannot hide or reset those errors.

## Performance and memory

With the menu closed, optional producers reduce to their subsystem gate check;
they perform no success-counter increments, per-frame counter swaps,
frame-history timestamp query, ring write, percentile preparation, or ImGui
work. PBR's configured-off fast path still performs its existing single relaxed
diagnostic-enable read. Local-light hooks load their gate once per capture stage
and reuse the result for all optional counters in that stage.

The frame-pacing ring remains a fixed 180 `f32` array. Diagnostic session reset
uses existing fixed atomics and arrays and happens only on the user-driven open
transition, never per draw.

## Validation and runtime acceptance

Unit tests prove that a closed frame-pacing gate records no samples, reopening
starts a fresh session, production frame delta remains independent, optional
local-light counters ignore closed-menu events, and detailed PBR diagnostics
require both configuration and an open menu.

The supported validation commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

A normal Proton/DXVK playtest should compare a stable scene with the workbench
closed and open, confirm diagnostics begin updating only after opening, and
confirm compile/resource/capture failures still reach the OMV log while it is
closed. Static tests cannot establish the final runtime frame-time difference.

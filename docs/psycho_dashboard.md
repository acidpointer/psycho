# Psycho Engine Fixes control deck

## Status and purpose

The companion xNVSE plugin owns an in-game Dear ImGui dashboard for Psycho
Engine Fixes. Press `F10`, or run `PsychoInfo`/`psyinfo`, to open it. The old
multi-line console report remains available only through the core's legacy ABI;
the helper command now opens the dashboard because the game console truncates
and wraps the report too aggressively to be a useful support tool.

The control deck has five pages:

- **Overview** presents memory health, active allocator mode, safety activity,
  and the process values most useful for support.
- **Memory dashboard** separates total virtual-address-space (VAS) availability
  from the largest contiguous opening, shows allocator tiers, and presents two
  purpose-built pressure timelines over the last 120 samples. The VAS timeline
  includes explicit watch and critical pressure bands; the commit timeline uses
  a padded scale because it has no honest universal failure threshold.
- **Runtime Fixes** identifies active patch families and exposes cumulative
  save, task, native IO, SpeedTree materialization/Compute, and LOD counters.
- **Configuration** edits the complete supported Psycho TOML surface. Saving is
  explicitly labelled **Save for next launch**; it never changes live core
  state.
- **Log browser** tails the current Psycho log with independent ERROR, WARN,
  INFO, DEBUG, and TRACE filters plus optional auto-follow. Timestamp and module
  prefixes are hidden by default, with compact context available on demand.

The green-black presentation, status cards, restrained warning colors, and
charts are deliberate, but decoration does not replace meaning. Every chart
answers a time-series question. Scalar counters remain scalar.

## Ownership and startup contract

`psycho-engine-fixes-helper` owns the dashboard, xNVSE command, Win32 input
bridge, DirectInput suppression, and D3D9 overlay lifecycle. The early-loaded
`psycho-engine-fixes` DLL owns all engine fixes, allocator state, and diagnostic
counters. `psycho-imgui` owns the reusable Dear ImGui Win32/DX9 bridge.

The helper never calls `LoadLibrary` for the core and never initializes it. It
uses `GetModuleHandle("psycho_engine_fixes.dll")` and exact named exports only
after xNVSE `DeferredInit`. If Syringe did not load and activate the core at its
pre-CRT barrier, the helper remains passive and the command reports that the
dashboard is unavailable.

The established `NVSEPlugin_Load` sequence is unchanged:

1. publish xNVSE's console pointer;
2. register the message listener;
3. request the helper opcode base;
4. register `PsychoInfo` when that base is available;
5. retain the `PluginContext` backing required by xNVSE.

No ImGui context, D3D hook, input hook, file sampler, or worker starts from
`NVSEPlugin_Load`. `DeferredInit` only validates the optional core ABI and
starts the sampler. The ImGui context and D3D9 Reset hook are created lazily on
the first open request.

## Render and input contract

The supported executable is Fallout: New Vegas 1.4.0.525 PE32, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
For that executable:

- `NiDX9Renderer::singleton` is at `0x011C73B4`;
- the live `IDirect3DDevice9*` is at renderer offset `+0x288`;
- the renderer child `HWND` is at `0x011C6FBC`;
- xNVSE dispatches `OnFramePresent` immediately before the final display call
  at `0x00B6B730`, from normal-frame callsite `0x0087055E` and loading-screen
  callsite `0x007147C4`.

The dashboard renders only from `OnFramePresent`. It snapshots and restores
D3D9 state through the shared ImGui backend. Its Reset VMT hook chains the
current predecessor, invalidates ImGui device objects before Reset, and
recreates them only after a successful Reset. The hook is process-lifetime; it
is never removed while another hook might still chain through it.

The helper installs a Win32 WndProc chain after the renderer window exists.
`F10` toggles the dashboard and `Esc` closes it. While open, it forwards Win32
messages to ImGui and suppresses the game's DirectInput keyboard/mouse results.
Mouse-wheel data is forwarded to ImGui before the game-facing data is cleared.
The DirectInput VMT hooks also chain the predecessor found at installation and
remain installed for process lifetime. Closing the dashboard immediately
restores unsuppressed game input.

These choices are compatible with other well-behaved process-lifetime WndProc,
Reset, and DirectInput hook chains regardless of installation order. They
cannot guarantee compatibility with a plugin that overwrites a hook without
chaining, restores an obsolete predecessor, unloads while still referenced, or
mutates the same vtable concurrently. Such a plugin is outside a composable
hook contract; the runtime matrix below is still required before claiming
compatibility with a specific large modlist.

Evidence:

- `libnvse/xnvse/nvse/nvse/Hooks_Gameplay.cpp`, `DisplayFrameHook` and the two
  `WriteRelCall` sites;
- `analysis/ghidra/output/perf/display_current_fix_contract_audit.txt`;
- `analysis/ghidra/output/perf/display_d3d_reset_present_audit.txt`;
- `docs/omv-plan.md`, established FNV renderer/device ownership.

## Core/helper diagnostics ABI

`PsychoEngineFixes_QueryDashboard` is export ordinal 5. ABI version 1 is a
472-byte `repr(C)` caller-owned structure made only of fixed-width integers.
Both DLLs have a compile-time size assertion. The request begins with
`struct_size` and `abi_version`; the core reads only that mandatory prefix,
rejects an undersized or mismatched request, fills a local snapshot, and then
publishes the complete result in one write. No Rust allocation, string, enum,
reference, or ownership crosses the DLL boundary.

The snapshot groups are:

- readiness, pre-CRT, VAS-valid, and block-sample-valid flags;
- allocator mode and active engine-fix families;
- RSS, process commit, peak values, and page faults;
- total free/committed/reserved VAS, largest free opening, and free-region count;
- pool, metadata, block, direct-VA, and scrap-heap live/capacity values;
- allocator fallback/failure counts;
- save-integrity and queued-task lifetime counters;
- native IO and LOD streaming counters;
- eight SpeedTree materialization/Compute activity, contention, waiter, and
  maximum-wait counters, published in the version-1 growth tail.

All engine counters are cumulative and read-only. Dashboard sampling does not
drain the hitch profiler's interval counters. Missing optional samples are
marked invalid instead of being presented as zero.

## Sampling, memory meaning, and cost

The helper worker is demand-driven. While the dashboard is closed it waits on
a condition variable and performs no core query, VAS request, or log access.
Opening the dashboard wakes it immediately; while open it samples core
telemetry every 1.5 seconds. Switching to the Log browser also wakes it and
enables log refreshes, while switching away stops log access. The closed
`OnFramePresent` path reduces to readiness/open atomics after the process-
lifetime WndProc bridge has been installed.

The worker remains outside render callbacks and allocator hot paths. The
render callback uses `try_read`; if the worker is publishing, the dashboard
keeps the prior frame rather than waiting. Closing the dashboard wakes a timed
worker wait so it becomes idle promptly instead of completing the remaining
1.5-second interval repeatedly.

Full VAS enumeration is cached in the core. Every successful engine VAS walk
publishes one timestamped summary. Dashboard queries reuse a summary for up to
10 seconds and perform an on-demand walk when the cache expires. The mode-2
gheap watchdog also publishes its 60-second support sample into the same cache;
modes 0 and 1 retain identical dashboard coverage through the on-demand path.
A concurrent refresh returns the prior summary rather than starting another
walk.

The Runtime Fixes page reads LOD counts from the atomics already published by
the ledger. It does not acquire or scan the LOD ledger. The complete diagnostic
report still calculates oldest-pending age by scanning that ledger when the
report is explicitly requested.

Block-heap telemetry uses `try_lock`. A busy allocator causes a missing block
sample, visibly labelled in Memory dashboard, instead of adding periodic
contention to the variable-size allocator. Other allocator values are
maintained counters or lock-free snapshots.

The log reader opens the file only while the Log browser is selected. It keeps
an offset plus an incomplete-line buffer and parses only newly appended,
complete lines. Initial load, truncation, rollover, or a gap larger than 160
KiB resets the view to the newest 160 KiB. The UI keeps at most 320 lines and
caps an individual line at 8,192 Unicode scalar values. The log view keeps long
messages on one line and provides a horizontal scrollbar rather than wrapping
them into hard-to-scan blocks.

While the dashboard is open, history storage is fixed at 120 `f32` values per
chart (about three minutes at the 1.5-second sampling cadence). The ImGui
context and its resources exist only after the dashboard has first been
opened; no dashboard draw work occurs while it is closed. One
`GetAvailableTextureMem` query runs every 60 open frames. That value is labelled
a **driver texture estimate**, not real VRAM usage: D3D9 drivers commonly report
a budget-like estimate and texture content may also consume system memory and
32-bit VAS.

### Periodic-performance regression

The reported runtime symptom was a location-dependent fall from roughly
100--110 FPS to 60--70 FPS with a periodic frame-pacing pattern. Repository
code proved that the first dashboard version ran an unconditional 1.5-second
worker cycle even while closed; each cycle queried process accounting, walked
the process VAS, locked and scanned the LOD pending-reference ledger, and
reopened and reparsed the bounded log tail. The fixed contract removes that
closed-dashboard cycle and bounds each remaining open-dashboard cost as
described above. It does not disable a page, counter, chart, filter, or
configuration control.

A deployment-confirmed playtest with the fixed core and helper still reproduced
the FPS loss. That rejects the dashboard worker as a complete explanation. In
that run the dashboard worker was idle, but hitch profiling was disabled; the
log therefore could not attribute bad frames among the existing radio, engine,
render, watchdog, and scrap-reclamation paths. The opt-in hitch report now
includes `memWd` and `scrapGc` background spans so the next same-location
capture can distinguish periodic background correlation from sustained
main-thread work. This instrumentation does not change dashboard availability
or normal-play sampling behavior.

Memory health intentionally emphasizes contiguous VAS:

- **Critical:** largest opening below 128 MiB;
- **Watch:** largest opening below 384 MiB, or total free VAS below 512 MiB;
- **Stable:** neither threshold is crossed;
- **Unknown:** the `VirtualQuery` walk was unavailable.

These are support-oriented pressure bands, not a promise that a given texture
allocation will succeed or that a modlist is crash-free. Allocation size,
alignment, driver behavior, asset lifetime, and other mappings remain relevant.

### gheap three-way acceptance

- **OOM recovery:** the dashboard improves visibility into process commit,
  actual VAS shape, tier use, fallbacks, and failures. It performs no cleanup,
  retry, quarantine, or allocator mutation, so existing OOM recovery ordering
  and IO barriers are unchanged.
- **UAF protection:** sampling does not free, reuse, compact, or accelerate
  reclamation. Zombie readability and safe-reuse timing are unchanged.
- **Performance:** no dashboard work enters allocation/free hot paths. Full VAS
  walks publish a cold-path cache entry after sampling; the open dashboard
  reuses that entry and refreshes it no more often than every 10 seconds. Block
  telemetry remains a best-effort `try_lock` every 1.5 open seconds;
  contention produces an invalid sample rather than blocking either side. A
  closed dashboard performs neither operation.

## Configuration safety

The editor reads `syringe/psycho_engine_fixes.toml`, with the core's supported
legacy paths as discovery fallbacks. `toml_edit` preserves comments, ordering,
formatting context, and unknown mod-owned keys while updating known options.
Invalid TOML is shown as an error and is never overwritten. Before saving, the
editor compares the current file contents with the version it loaded; an
external edit causes a rejection and requires **Reload from Disk**.

Save writes a sibling temporary file, flushes its contents, and promotes it
with `MoveFileExA(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. A failed
promotion removes the temporary file and leaves the previous config in place.
The dashboard draft is sanitized to the core's supported allocator and LOD
multiplier ranges before serialization.

Saving changes disk state only. The core already published its runtime config
during early startup, so a full process exit and relaunch is always required.
The UI repeats this rule in the page heading, explanatory text, dirty-state
indicator, button label, and success notice.

## Failure behavior and compatibility boundary

- Missing core module/export: no dashboard worker or graphics/input hook starts.
- Temporary core sample miss: the last good sample remains visible; after three
  misses it changes to offline rather than displaying stale data indefinitely.
- Busy publication lock: rendering keeps the previous frame and never waits.
- Missing or unreadable log: the telemetry pages remain available and the log
  page shows the read error.
- Invalid or externally changed config: saving is rejected without overwriting
  user data.
- Missing renderer device/window: no graphics or input hook is installed that
  frame; xNVSE continues normally.
- ImGui or Reset-hook failure: the helper logs the failure and does not alter
  core engine-fix behavior.

The helper is optional. Removing it removes only the UI, command, and xNVSE
event forwarding; core activation and safety do not depend on it. Conversely,
installing the helper without an early-loaded core yields no partial engine-fix
startup.

## Validation and runtime acceptance

Automated coverage includes:

- strict dashboard ABI version/size requests in both DLLs;
- closed dashboard state producing no sampling request;
- complete-line incremental log-tail parsing across reads;
- contiguous-VAS health classification;
- structured log parsing, compact context extraction, and five-level filtering;
- config dirty-state tracking;
- exact legacy-key fallback ordering and integer multiplier parsing;
- leading, inline, and unknown-key comment/data preservation.

The supported checks are:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes-helper
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo build --release --target i686-pc-windows-gnu \
  -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Static code and build checks cannot prove presentation, device-loss behavior,
or interaction with every third-party hook. Before a release compatibility
claim, playtest at least:

1. `F10`, `Esc`, window close, and `PsychoInfo`, with the console closed after
   issuing the command;
2. mouse movement, clicks, scroll, text navigation, and restoration of game
   controls after close;
3. native fullscreen, windowed mode, Alt-Tab, minimize/restore, loading screens,
   resolution changes, and repeated D3D9 Reset;
4. helper with and without OMV, plus common overlay, input, and graphics hook
   combinations from the target large modlist;
5. valid, missing, invalid, read-only, and externally modified configuration;
6. allocator modes 0, 1, and 2, including a texture-heavy traversal that drives
   VAS fragmentation and confirms the dashboard remains responsive;
7. log rollover/growth, all five severity filters, context toggle, long-line
   horizontal scrolling, and behavior when the log is missing;
8. at the same reported regression location, compare at least 60 seconds with
   the dashboard closed, open on Overview, and open on Log browser; confirm the
   closed frame-time chart no longer has a 1.5-second periodic disturbance and
   that every page continues updating when selected.

The implementation establishes a bounded and composable design. “Works on any
modlist” remains an acceptance target, not a proven universal fact, until this
runtime matrix and representative extreme setups have been exercised.

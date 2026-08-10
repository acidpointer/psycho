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
- **Runtime Fixes** identifies active patch families, including dynamic actor
  retirement and encounter-zone form containment, and exposes cumulative
  save/form/task exceptions, rare native IO fallbacks, current LOD ownership,
  and the bounded native-IO scheduling policy.
- **Configuration** edits the complete supported Psycho TOML surface. Saving is
  explicitly labelled **Save for next launch**; it never changes live core
  state.
- **Log browser** tails the current Psycho log with independent ERROR, WARN,
  INFO, DEBUG, and TRACE filters plus optional auto-follow. Timestamp and module
  prefixes are hidden by default, with compact context available on demand.

The green-black presentation, status cards, restrained warning colors, and
charts are deliberate, but decoration does not replace meaning. Every chart
answers a time-series question. Scalar counters remain scalar.

## Contextual help contract

The dashboard must be usable by a player who has not read the TOML comments or
engine research. Overview, Memory, Runtime Fixes, and Configuration explicitly
invite the player to hover settings and technical labels. Hovering waits for
Dear ImGui's normal tooltip delay, then opens a wrapped, width-limited
plain-language explanation. The delay prevents popups from flashing while the
pointer merely crosses the dashboard.

Every one of the 26 `[engine_fixes]` controls has focused hover documentation
that answers three gamer-facing questions: what broken situation it handles,
what the enabled fix does, and whether normal valid behavior is preserved. The
21 engine-safety controls share one ordered help catalog; borderless windowed,
cursor confinement, and system-key passthrough have their own window/input
help; and the installation-path repair gate and Fallout 3 text field explain
their restart-only registry contract. The same explanation is reused where a
fix appears on the Runtime Fixes page, so saved configuration and installed
runtime state do not describe one feature in conflicting language.

All other supported configuration controls also explain their practical
effect and tradeoff, including allocator modes, the experimental PDD purge,
native IO, LOD, multipliers, performance options, and diagnostics. Memory and
runtime telemetry defines its specialized terms in place. In particular:

- **process commit** is memory Windows has promised to back with RAM or the
  page file, not current physical-RAM use;
- **RSS** is the portion currently resident in physical RAM;
- **VAS** is New Vegas' finite 32-bit virtual address space;
- **largest VAS opening** is the largest single free range and therefore the
  useful constraint for one large texture or model mapping;
- **reserved** address space is set aside without backing storage, while
  **committed** space has backing promised;
- cell pools, pool metadata, block heap, direct VA, and scrap heap explain
  which allocation sizes/lifetimes they serve;
- fallbacks, failures, contentions, tombstones, LOD, and microsecond timings
  explain whether the value is normal activity or support evidence.

Tooltip prose stays concise, ASCII, and gamer-facing. It does not expose raw
addresses, reverse-engineering terminology, or unsupported guarantees.

## Ownership and startup contract

`psycho-engine-fixes-helper` owns the dashboard, xNVSE command, Win32 input
bridge, DirectInput suppression, and D3D9 overlay lifecycle. The early-loaded
`psycho-engine-fixes` DLL owns all engine fixes, allocator state, and diagnostic
counters. `psycho-imgui` owns the reusable Dear ImGui Win32/DX9 bridge.

`psycho-imgui` exposes one generic hover-help operation. Its bridge treats a
label/value row as one Dear ImGui item, uses the normal delayed-hover flags,
and draws wrapped text inside a tooltip. The helper owns all product wording;
the reusable renderer has no Psycho-specific glossary.

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

### Core-only import isolation

The helper is a statically linked consumer of `libpsycho`, but it must not
inherit Win32 imports for features owned only by the early core DLL. An import
is observable startup work even when no Rust call site is reachable: the
Windows loader resolves the helper's complete PE import table before xNVSE can
finish plugin startup.

The first install-path registry implementation violated that boundary by
placing `RegCloseKey`, `RegCreateKeyExW`, `RegOpenKeyExW`,
`RegQueryValueExW`, and `RegSetValueExW` wrappers in the broad `libpsycho`
WinAPI code-generation surface. PE inspection proved that the deployed helper
imported all five even though helper source never calls registry repair. Three
consecutive Proton launches then failed before DeferredInit in BaseObjectSwapper
`ConditionalInput::IsValid +0x88`. The faulting visitor dereferenced an
indeterminate `ConditionalInput::currentWorldspace` value; the `std::variant`
was the dispatch path, not a proven corrupt object. The
crashing helper SHA-256 was
`66e27e3a01b563404341b2c5b4da522d4d90337e02ff0486b30ade00724aa6f0`.

The correction keeps the complete registry feature but isolates its bounded
Win32 wrappers in `libpsycho/src/os/windows/registry.rs`. Those FFI-bearing
functions are inline so only the core consumer instantiates their import
references. The helper's test image is parsed as PE and must contain none of
the five registry imports. Release inspection applies the same assertion to
the shipped helper and verifies that the core still imports all five. The
helper load callback, command, listener, dashboard, configuration editor,
input bridge, and eight-byte TLS section are unchanged in ownership.

The crash traces, phase logs, import table, and failing-then-passing regression
test prove the unintended helper dependency and its removal. They do not prove
the lower-level interaction with BaseObjectSwapper's independent invalid state;
that trigger attribution still requires a corrected load-to-gameplay playtest.
Focused evidence is retained in
`.reports/baseobjectswapper-helper-registry-import-2026-08-10.txt`. The exact
external defect, attribution limits, and mandatory mod-agnostic response are
documented in `docs/nvse_startup_phase_safety.md`.

### xNVSE listener-handle recovery

The helper's two open paths share one lifecycle dependency. `DeferredInit`
validates the core ABI and marks the dashboard ready; `OnFramePresent` finds
the game windows and installs the F10/WndProc bridge. Both messages arrive
through the listener registered in step 2. If that registration is absent,
F10 is never installed and `PsychoInfo` can only report that the dashboard is
unavailable. The command itself may still be present because command
registration occurs later in the same apparently successful load callback.

The vendored xNVSE 6.4.4 source at submodule commit
`694cdde6cbfa5e75afa661df587c73e8f0f6f441` proves a load-order-dependent
registration defect in `libnvse/xnvse/nvse/nvse/PluginManager.cpp`:

- `PluginManager::InstallPlugins` advances its second-pass `index` for every
  query-successful, compatible plugin before calling that plugin's `Load`, but
  appends to `m_plugins` only when `Load` succeeds;
- `GetPluginHandle` returns that gapful `index`;
- `GetNumPlugins` counts only successful plugins plus the plugin currently
  loading; and
- `RegisterListener` rejects a listener handle greater than `GetNumPlugins`.

The original `libnvse` messaging wrapper, introduced in commit `eac8542`,
discarded the `RegisterListener` Boolean. It retained the callback and returned
success even after xNVSE rejected it. This made the helper look loaded while it
received no lifecycle messages. The dashboard added in commit `5a92838` made
that pre-existing wrapper defect visible through both F10 and the command.

The repaired wrapper always honors xNVSE's return value. Registration for the
built-in `NVSE` sender first tries the reported handle. If xNVSE rejects it,
the wrapper tries lower handles until the first success and stores that
corrected handle for later messaging and callback APIs. This is safe without
knowing any installed plugin names or load order: with `N` earlier successful
plugins and `F` earlier `Load` failures, xNVSE reports `N + F + 1`, while the
current plugin's eventual and maximum accepted handle is `N + 1`. Descending
probes therefore reach `N + 1` before any existing plugin handle (`1..=N`) and
stop there. Any number of earlier failed plugins has the same result.

Fallback is deliberately restricted to the built-in `NVSE` sender, which is
guaranteed to exist. A failed registration for a third-party sender can mean
that sender is absent or not loaded yet; probing another handle in that case
would be unsound. Complete rejection now fails the helper load instead of
publishing a dead callback. The recovery does not load or initialize the core,
inspect third-party DLLs, reserve mod-specific names, install hooks, or perform
work after plugin load.

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
- the stable top-level input/foreground `HWND` is at `0x011C6FC0`;
- xNVSE dispatches `OnFramePresent` immediately before the final display call
  at `0x00B6B730`, from normal-frame callsite `0x0087055E` and loading-screen
  callsite `0x007147C4`.

At renderer construction, native fullscreen aliases `0x011C6FBC` to the
top-level HWND. Windowed mode instead creates a separate
`WS_CHILD | WS_VISIBLE` render target under that top-level window. The helper
therefore retains both roles: D3D presentation, ImGui display size, and cursor
coordinates use the renderer target, while WndProc chaining, foreground
ownership, F10, Esc, keyboard, and text input use the top-level HWND.
`psycho_imgui::Dx9Context::new_with_foreground_window` publishes that split
without changing single-window clients.

The dashboard renders only from `OnFramePresent`. It snapshots and restores
D3D9 state through the shared ImGui backend. Its Reset VMT hook chains the
current predecessor, invalidates ImGui device objects before Reset, and
recreates them only after a successful Reset. The hook is process-lifetime; it
is never removed while another hook might still chain through it.

The helper installs a Win32 WndProc chain on the top-level input owner after
both windows exist. `F10` toggles the dashboard and `Esc` closes it. While open,
it forwards Win32 messages to ImGui and suppresses the game's DirectInput
keyboard/mouse results. Mouse position and buttons are polled only while the
top-level window owns the foreground, then converted from screen space into
renderer-client coordinates. Mouse-wheel data is forwarded to ImGui before the
game-facing data is cleared. The DirectInput VMT hooks also chain the
predecessor found at installation and remain installed for process lifetime.
Closing the dashboard immediately restores unsuppressed game input.

The former single-HWND policy worked accidentally in native fullscreen. In
windowed and windowed-derived borderless modes, it subclassed the child rather
than the keyboard owner and required that child to equal `GetForegroundWindow`.
That could prevent F10 from opening the dashboard or leave an opened dashboard
without mouse input. Keeping the roles separate removes both failure modes
without changing display-fix or D3D-reset ownership.

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
- `analysis/ghidra/output/perf/display_exclusive_startup_owner_followup.txt`,
  renderer/top-level aliasing and windowed child creation;
- `analysis/ghidra/output/perf/display_current_fix_contract_audit.txt`;
- `analysis/ghidra/output/perf/display_d3d_reset_present_audit.txt`;
- `docs/omv-plan.md`, established FNV renderer/device ownership.

## Core/helper diagnostics ABI

`PsychoEngineFixes_QueryDashboard` is export ordinal 5. ABI version 4 is a
576-byte `repr(C)` caller-owned structure made only of fixed-width integers.
Both DLLs have a compile-time size assertion. The request begins with
`struct_size` and `abi_version`; the core reads only that mandatory prefix,
rejects an undersized or mismatched request, fills a local snapshot, and then
publishes the complete result in one write. No Rust allocation, string, enum,
reference, or ownership crosses the DLL boundary.

The snapshot groups are:

- readiness, pre-CRT, process-sample-valid, VAS-valid, and
  block-sample-valid flags;
- allocator mode and active engine-fix families;
- RSS, process commit, peak values, and page faults;
- total free/committed/reserved VAS, largest free opening, and free-region count;
- pool, metadata, block, direct-VA, and scrap-heap live/capacity values;
- allocator fallback/failure counts;
- save-integrity and queued-task lifetime counters;
- encounter-zone changed-form/runtime rejections and exact source repairs;
- false-predicate cell render-list cleanups and active-provider ownership
  losses;
- active native IO fallbacks and LOD ownership counters, plus reserved routine
  IO/LOD activity fields that remain zero for ABI compatibility;
- eight reserved SpeedTree materialization/Compute activity, contention,
  waiter, and maximum-wait fields. They remain zero in ABI version 4 after
  release hot-path sampling was removed;
- process/VAS sample timestamps plus fast-query and explicit-VAS-refresh
  counts and last/maximum durations.

`PsychoEngineFixes_RequestDashboardRefresh` is export ordinal 6. It accepts a
fixed refresh kind and runs on the helper's sampling worker. Version 4 requires
both exports, preventing a new helper from silently applying old periodic
sampling behavior to an older core.

Version 4 preserves the complete 560-byte version-3 prefix and appends two
`u64` cell-render-retirement counters. Both sides still require the exact
advertised version and complete storage, so mismatched helper/core DLLs fail
unavailable instead of interpreting a shorter structure.

Active engine counters are cumulative and read-only. The Runtime Fixes page no
longer presents the reserved routine LOD, cell, or SpeedTree fields as activity
measurements. Dashboard sampling does not drain the hitch profiler's interval
counters. Missing optional samples are marked invalid instead of being
presented as zero.

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
publishes one timestamped summary. The normal 1.5-second dashboard query only
uses `try_read` on that cache: it never starts a `VirtualQuery` walk and never
waits behind one. The mode-2 watchdog publishes its existing 60-second support
sample. The Overview and Memory pages expose an explicit **Refresh VAS map**
action; ordinal 6 performs that walk on the sampling worker and the UI keeps
the previous value, visibly aged, until the refresh completes.

In mode 2, process RSS/commit/fault values come from the watchdog's existing
five-second process-accounting result through an atomic publication sequence.
The dashboard does not make a duplicate process query. Modes 0 and 1 retain
their existing process sampling until their allocator telemetry is audited
separately; this change does not alter scrap-heap or mimalloc behavior.

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
opened; no dashboard draw work occurs while it is closed.
`GetAvailableTextureMem` runs only when Overview opens on a device, after a
successful device reset/change, or when the user presses **Refresh driver
estimate**. It has no frame-count interval and never runs on another page. The
value is labelled a **driver texture estimate**, timestamped, and accompanied
by last/maximum query duration; it is not presented as real VRAM usage.

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
render, watchdog, and reclamation paths. The current fix additionally parks the
logger while idle, removes automatic VAS and driver-estimate queries, reuses the
watchdog process sample in mode 2, and makes block diagnostics `try_lock`-only.
The Runtime page publishes the cost of the remaining fast snapshot and
requested expensive operations. Runtime playtesting is still required; source
and automated checks cannot prove the final frame-time chart.

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
  reads it without waiting and refreshes it only after an explicit request.
  Block telemetry remains a best-effort `try_lock` every 1.5 open seconds;
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

The **Repair Fallout install paths** checkbox owns
`[engine_fixes].install_path_registry_repair` and defaults on. The adjacent
**Fallout 3 path** text field owns `[engine_fixes].fallout3_install_path`. It
accepts a Windows-visible absolute path or a path relative to the directory
containing `FalloutNV.exe`; an empty value skips only Fallout 3. The helper
preserves this text in the restart-only TOML draft and never reads, writes, or
validates either game's registry or filesystem state. The early-loaded core is
the sole repair owner. The complete path, registry, startup, and launcher
contract is `docs/install_path_registry_repair.md`.

The **Borderless windowed** checkbox owns
`[engine_fixes].display_borderless_windowed`. It defaults on and applies only
when FalloutPrefs.ini selects `bFull Screen=0`; native fullscreen always takes
precedence. The helper writes the restart-only preference but never changes a
live HWND, style, position, focus state, or D3D9 resource.

The **Lock cursor to game window** and **Allow system and media keys**
checkboxes own `[engine_fixes].window_cursor_lock` and
`[engine_fixes].input_system_key_passthrough`. Both default on, require a
restart, and apply in native fullscreen, framed windowed, and borderless
windowed modes. Native fullscreen and borderless use their rendered client;
framed mode includes its caption and resize border. The core's window-thread
audit repairs an overlay that widens or clears an active clip. The helper only
edits next-launch values; cursor/WndProc ownership, timer reconciliation, and
the DirectInput cooperative-level patch remain exclusively in the early-loaded
core. Their complete behavior and compatibility contract is
`docs/window_input_policy.md`.

The **Dynamic actor container guard** checkbox owns
`[engine_fixes].actor_container_retirement_guard`. It defaults on and changes
only next-launch core activation. The Runtime Fixes page separately reads bit
8 from the core's `active_features` field, so the UI distinguishes a saved
preference from a hook that actually installed. The helper does not install,
load, or initialize the guard. This additive feature bit does not change the
position it held in the version-2 prefix or the ownership contract.

The **Model postprocess serialization** checkbox owns
`[engine_fixes].model_postprocess_serialization_fix`. It defaults on and
changes only next-launch core activation. Runtime Fixes reads additive bit 9
from `active_features`; no existing structure field or helper ownership rule
changes. The helper only displays and edits the contract and never installs or
initializes the core guard.

The **Encounter-zone form guard** checkbox owns
`[engine_fixes].encounter_zone_invalid_form_guard`. It defaults on and changes
only next-launch core activation. Runtime Fixes reads additive bit 10 to prove
the shared resolver hook installed, then displays counters introduced in
version 3 for changed-form rejections, runtime rejections, and exact source
repairs. The helper never resolves or mutates a game form and never initializes
the core.

The **Cell render retirement repair** checkbox owns
`[engine_fixes].cell_render_reference_retirement_fix`. It defaults on and
changes only next-launch core activation. Runtime Fixes reads additive bit 11
and version-4 counters for false-predicate cleanups and post-install provider
ownership loss. The active bit is derived from current provider bytes rather
than startup success alone. The helper does not inspect a cell or reference; it
only mirrors the core's fixed-width snapshot.

## Failure behavior and compatibility boundary

- Missing core module/export: no dashboard worker or graphics/input hook starts.
- Temporary core sample miss: the last good sample remains visible; after three
  misses it changes to offline rather than displaying stale data indefinitely.
- Busy publication lock: rendering keeps the previous frame and never waits.
- Missing or unreadable log: the telemetry pages remain available and the log
  page shows the read error.
- Invalid or externally changed config: saving is rejected without overwriting
  user data.
- Missing device, renderer window, or top-level input window: no graphics or
  input hook is installed that frame; xNVSE continues normally.
- ImGui or Reset-hook failure: the helper logs the failure and does not alter
  core engine-fix behavior.

The helper is optional. Removing it removes only the UI, command, and xNVSE
event forwarding; core activation and safety do not depend on it. Conversely,
installing the helper without an early-loaded core yields no partial engine-fix
startup.

## Validation and runtime acceptance

Automated coverage includes:

- immediate acceptance of a valid xNVSE listener handle;
- exhaustive recovery for 32 current-plugin positions crossed with 32 counts
  of earlier query-successful/`Load`-failed plugins, while proving no existing
  plugin handle is probed;
- end-to-end wrapper retention of the recovered handle for later APIs;
- no handle fallback for third-party senders, plus bounded complete rejection;
- strict dashboard ABI version/size requests in both DLLs;
- closed dashboard state producing no sampling request;
- VAS refresh represented as a one-shot sampling request;
- driver estimate sampling requiring both Overview and an explicit pending
  request, with no frame-counter path;
- aliased fullscreen and distinct windowed render/input handle retention;
- complete-line incremental log-tail parsing across reads;
- contiguous-VAS health classification;
- structured log parsing, compact context extraction, and five-level filtering;
- the complete 21-entry engine-fix help catalog, including unique labels,
  concise length bounds, and ASCII font safety;
- config dirty-state tracking;
- actor-container, encounter-zone, and cell-render-retirement default/disable
  parsing and comment-preserving serialization;
- exact legacy-key fallback ordering and integer multiplier parsing;
- leading, inline, and unknown-key comment/data preservation.

The supported checks are:

```bash
cargo test --target i686-pc-windows-gnu -p libnvse --lib
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes-helper
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib
cargo build --release --target i686-pc-windows-gnu \
  -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Validation recorded on 2026-08-03:

- `cargo test --target i686-pc-windows-gnu -p libnvse --lib`: 5 listener
  recovery tests passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p
  psycho-engine-fixes-helper`: 14 passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib`: 153
  passed, 0 failed;
- the affected release build for `psycho-engine-fixes` and
  `psycho-engine-fixes-helper` passed;
- the helper/core ABI tests prove a 576-byte layout and the complete 560-byte
  version-3 prefix on both sides;
- deployed ABI-v3 helper and core hashes matched the release artifacts, xNVSE
  loaded the helper, and the final captured-cell guard passed the affected live
  load; the logs do not independently prove visual presentation of every new
  dashboard row;
- native-fullscreen and windowed input behavior still requires the runtime
  matrix below.

The broader `libnvse` doctest target is not a supported gate: 41 existing
documentation fragments are incomplete snippets and do not compile as
standalone programs. The listener library, helper library, and affected release
DLL all compile independently of that pre-existing documentation debt.

Static code and build checks cannot prove presentation, device-loss behavior,
or interaction with every third-party hook. Before a release compatibility
claim, playtest at least:

1. place one and then several alphabetically earlier test plugins that pass
   `Query` but fail `Load`; verify xNVSE still loads the helper, then exercise
   `F10`, `Esc`, window close, and `PsychoInfo`, with the console closed after
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
   frame-time chart has no cadence tied to 60 frames, 1.5 seconds, 5 seconds,
   10.5 seconds, or 60 seconds, and that every page continues updating when
   selected; record the Dashboard overhead values before and after manual VAS
   and driver refreshes.

The implementation establishes a bounded and composable design. “Works on any
modlist” remains an acceptance target, not a proven universal fact, until this
runtime matrix and representative extreme setups have been exercised.

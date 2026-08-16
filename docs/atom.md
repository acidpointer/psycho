# Atom gameplay overhaul

Status: Atom Input playtest build; all other gameplay modules remain planned.

## Purpose and scope

Atom is Psycho's gameplay-oriented xNVSE mod for an urban-survival, hardcore
Fallout: New Vegas experience. Its ownership includes combat, NPC AI, loot and
weapon balance, camera behavior, input controls, and vanilla gameplay mechanic
fixes.

Atom is ESP-less. The shipped mod contains no ESM, ESP, or ESL and reserves no
load-order slot. Future gameplay systems must classify forms dynamically from
runtime type, data, capabilities, and relationships so mod-added items,
weapons, actors, and other records participate without per-plugin patches. A
record identity check is allowed only for a separately documented mechanic
which inherently targets that exact record; it is not Atom's generic
compatibility strategy.

The first gameplay milestone implements an engine-semantic input wrapper. It
does not replace DirectInput or XInput, and it does not claim that every source
of perceived input latency has been removed. The research and design contracts
are in `docs/fnv_actor_input_contract.md` and
`docs/atom_input_wrapper_design.md`.

## User-visible behavior

Atom appears in MCM Extender with `Overview`, `Mouse`, `Controller`,
`Diagnostics`, and `Modules` pages. Every visible label, help value, choice,
and status uses one to three words so it remains inside the MCM viewport. Atom
Input remains disabled by default because this expanded artifact still needs
the required in-game startup and behavior acceptance.

When enabled, the current input milestone:

- retains FNV and xNVSE as the authoritative device owners;
- captures one coherent keyboard, mouse, and controller snapshot after the
  normal xNVSE-aware native sample;
- applies a stateless direct transform at final player heading X/Y calls;
- publishes radial controller sticks and hysteretic triggers after a neutral
  live-toggle handoff, while bypassing FNV's second camera deadzone/curve;
- resolves all 28 FNV actions from simultaneous keyboard, mouse, and controller
  bindings with explicit gameplay, menu, and focus state;
- captures ordered keyboard events through xNVSE, preserves subframe taps for
  bound gameplay controls, and mirrors those events to later native consumers;
- leaves menu side effects, console/text entry, Pip-Boy pointer behavior,
  wheel, fly camera, movie, and focus-flow device ownership native;
- optionally records bounded sample-to-camera-consumer and
  sample-to-`OnFramePresent` histograms.

`Native` returns the chained final heading float bit-for-bit. `Direct` scales
that native final heading. `Fallout 4 Direct` rebuilds it from relative counts
with the supplied Fallout 4 installation's nominal
`0.0300 * 0.021 = 0.00063` radians-per-count product. None of the profiles adds
smoothing, acceleration, temporal history, or frame-time multiplication. The
Fallout 4 unit/context equivalence remains an explicit inference awaiting A/B
playtest, hence the preset is not named `Exact Fallout 4`.

The normal input sample has not been moved later. Static research proved that
`0x0086F390` couples the sample to controller and 28-control maintenance, while
moving that entire helper would cross unproven menu/UI/world consumers. Atom
does not ship a speculative late-sample toggle or register Raw Input.

## Source ownership

| Path | Ownership |
|---|---|
| `atom/src/lib.rs` | xNVSE query/load exports, load-owned service capture, and lifecycle message routing. |
| `atom/src/runtime.rs` | Deferred logger, config paths/reload, MCM event subscription, and input admission. |
| `atom/src/input/config.rs` | Serde/serini section model, validation, bounds, and atomic live config. |
| `atom/src/input/frame.rs` | Native value types, derived edges, controller processing, and coherent frame publication. |
| `atom/src/input/actions.rs` | 28-action binding resolution, mixed devices, focus epochs, contexts, and coherent publication. |
| `atom/src/input/buffered.rs` | Ordered DirectInput keyboard capture, native mirror, peek/overflow behavior, and health counters. |
| `atom/src/input/hooks.rs` | Fingerprints and transactional callsite, entry, and pointer-slot chaining. |
| `atom/src/input/native.rs` | Audited FNV offsets, globals, layouts, and native reads. |
| `atom/src/input/mouse.rs` | Stateless player-camera mouse transform. |
| `atom/src/input/controller.rs` | Radial stick shaping and trigger hysteresis. |
| `atom/src/input/telemetry.rs` | Optional QPC markers and saturating fixed histograms. |
| `atom/mcm/Atom.json` | The shipped MCM Extender UI and persistence contract. |

Gameplay hooks belong in Atom, not `psycho-engine-fixes-helper`, OMV, Syringe,
or an ESP. Atom reuses `libpsycho` for the logger, WinAPI wrappers, validated
memory reads, ownership-aware callsite hooks, and rollback transactions.

## xNVSE lifecycle and startup boundary

`NVSEPlugin_Query` publishes plugin version 2 and admits only the normal
FalloutNV.exe 1.4.0.525 runtime. It rejects the editor, no-gore executable, and
other packed runtime versions before any fixed address can be reached.

`NVSEPlugin_Load` constructs the xNVSE callback owner and captures the runtime
directory plus the event-manager wrapper while xNVSE identifies Atom as the
currently loading plugin. The registered lifecycle closure owns those services
and the callback thunk for the process lifetime. Load does not read
configuration, initialize Psycho's logger, query QPC, inspect native memory, or
install a hook.

This ownership split is mandatory. `NVSEInterface::from_raw` obtains the plugin
handle as part of construction, and xNVSE permits `GetPluginHandle` only from a
plugin's Query or Load handler. Deferred callbacks consume the wrappers acquired
during Load and never reconstruct an `NVSEInterface`.

At `DeferredInit`, Atom performs this ordered transaction:

1. initialize `libpsycho::logger::Logger` as `atom-latest.log`;
2. resolve `Data/config/Atom/Atom.ini` from xNVSE's runtime directory;
3. deserialize and validate the current MCM configuration;
4. initialize QPC-domain telemetry bounds outside the hook path;
5. validate the fixed data globals and immutable caller contexts;
6. capture every callsite, entry, and keyboard-slot predecessor;
7. enable the complete input bridge in one rollback-capable transaction;
8. subscribe to MCM Extender's `MCMExtUpdate` event for menu-close reloads.

If native validation or transactional installation fails, the transaction
leaves the callsites under their prior owners and Atom Input remains
unavailable. If only `MCMExtUpdate` subscription fails, the input bridge stays
active and the log states that settings will apply after restart. Atom never
identifies, inspects, patches, disables, or reorders another mod by name.

This milestone adds code, imports, atomics, `OnceLock`/`LazyLock` storage, Serde/serini,
and Psycho logger code to Atom's final DLL. Those are loader-visible footprint
changes even though their operational first use is deferred. Static checks and
a release build therefore cannot establish startup safety. The required
Proton/BaseObjectSwapper load-to-gameplay acceptance remains mandatory under
`docs/nvse_startup_phase_safety.md`.

### 2026-08-16 DeferredInit crash and correction

The first runtime playtest failed before native input validation or hook
installation. `atom-latest.log` ended immediately after `[INIT] Atom
DeferredInit started`. `nvse.log` then recorded xNVSE's assertion from
`PluginManager.cpp:498`: a plugin called `NVSEInterface::GetPluginHandle`
outside its Query/Load handlers. CrashLogger reported the halt through three
Atom frames from xNVSE's main-loop `DeferredInit` dispatch.

Code inspection proved the direct cause: Atom retained only the raw xNVSE
pointer during Load and called `NVSEInterface::from_raw` from `DeferredInit`.
That constructor unconditionally obtains the plugin handle before querying the
messaging interface. The failing build was the reviewed DLL with SHA-256
`faea3d86f6bf80bc77ca6e87dc527f935214d6eceb7bff19de9b7707f2508d7e`.

The correction follows OMV's process-lifetime callback ownership: Atom creates
one `PluginContext` during Load, obtains the runtime directory and event-manager
wrapper there, and moves those values into the registered lifecycle closure.
`DeferredInit` now receives borrowed, previously acquired services. It performs
no plugin-handle acquisition and still defers config reads, logger startup,
native validation, and hook installation. The corrected `c489be...` artifact
subsequently reached gameplay and is the accepted startup comparison described
under Runtime evidence. The expanded input bridge is a newer material delta and
requires its own playtest.

## Native hook contract

The fixed executable is FalloutNV.exe 1.4.0.525, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

| Purpose | Boundary | Native target | ABI |
|---|---:|---:|---|
| Normal input sample | `0x0086F39E` | `0x00A23010` | x86 `thiscall(input_owner) -> void` |
| Player-camera mouse X | `0x00945995` | `0x00A239E0` | x86 `thiscall(input_owner, axis) -> i32` |
| Player-camera mouse Y | `0x009459A8` | `0x00A239E0` | x86 `thiscall(input_owner, axis) -> i32` |
| Final heading X | `0x00945F90` | `0x00931D30` | x86 `thiscall(player, f32) -> void` |
| Final heading Y | `0x00945FD8` | `0x00931E50` | x86 `thiscall(player, f32) -> void` |
| Camera deadzones | four calls `0x009455EC`-`0x00945707` | `0x00EC7D40` | x86 `cdecl(i32) -> i32` |
| Camera exponents | `0x00945839`, `0x0094587C` | `0x0043D4D0` | x86 `thiscall(setting) -> *i32` |
| Camera minimum | `0x009458A4` | `0x00403E20` | x86 `thiscall(setting) -> *f32` |
| Bound actions | entry `0x00A24660` | captured trampoline | x86 `thiscall(owner, control, state) -> i32` |
| Keyboard data | live vtable slot `+0x28` | captured capability | x86 COM `GetDeviceData` |

Atom fingerprints immutable caller/entry instructions but does
not require its displacement to still name the vanilla target. The target
present at DeferredInit becomes Atom's typed predecessor, which preserves
capability-based chaining. The keyboard slot is resolved from the live input
owner and chained without identifying its module owner. All writes occur at
DeferredInit, when targets are quiescent, because x86 executable writes are not
atomic.

The sample detour calls its predecessor first, then copies:

- keyboard current `input_owner + 0x18F8`, 256 bytes;
- keyboard previous `input_owner + 0x19F8`, 256 bytes;
- current `DIMOUSESTATE2` at `+0x1B24`, 20 bytes;
- previous `DIMOUSESTATE2` at `+0x1B38`, 20 bytes;
- current/previous 16-byte XInput state at `0x011F35A8`/`0x011F35B8`;
- 28 keyboard, mouse, and active XInput bindings at `+0x1B94`, `+0x1BB0`,
  and `+0x1BE8`;
- controller mode, foreground ownership, and native `MenuMode`.

Mouse getter detours retain the chained relative counts. The later heading
detours receive FNV's final float: disabled/`Native` returns it unchanged,
`Direct` scales it, and `Fallout 4 Direct` derives a fractional heading from
the retained count. The Y transform owns final inversion while accounting for
the vanilla `bInvertYValues` value at `0x011E0A60`. Wheel call `0x009459BB`
remains native.

Controller enable/disable waits for a physically neutral sample. When active,
Atom writes only FNV's current XInput slot after the engine has already copied
the preceding processed state to `previous`. Buttons and packet identity are
unchanged. Dynamic deadzone/setting call hooks turn the later player-camera
transfer into identity; inactive paths call their exact predecessors.

The keyboard event mirror retains the newest 32 complete 20-byte events. It
drains only while Atom Input is enabled, calls xNVSE's current wrapper first,
and answers later native normal/peek requests in order. The bound-action entry
adapter opens only after the current normal helper returns and closes at
`OnFramePresent`, preventing stale events from being replayed during FNV's
internal control-maintenance loop. Native nonzero results win and menu control
14 always passes through because its provider owns a side effect.

Raw disassembly evidence and the established field contract live in
`analysis/radare2/output/perf/fnv_actor_input_contract.txt`.

## MCM Extender and configuration ownership

The installed menu is `Data/MCM/Atom.json`. Its DLL requirement uses Atom
plugin version 2, so a stray menu cannot advertise a plugin which did not load.
MCM persists values to `Data/config/Atom/Atom.ini`.

MCM Extender is the sole writer. Atom uses `serini` 0.3 and Serde nested structs
to deserialize recognized sections, converts MCM's numeric `0/1` booleans, and
then applies documented bounds. Atom never serializes the INI. Unknown sections
and keys are ignored by Serde and remain preserved because Atom performs no
writeback. Missing files or fields use safe defaults. A malformed recognized
value, non-finite float, invalid boolean, or unknown mouse profile rejects the
entire candidate; live reload keeps the previous coherent configuration.

| Setting | Default | Accepted/bounded value |
|---|---:|---|
| `Input:bEnabled` | `0` | `0` or `1` |
| `Mouse:iProfile` | `2` | Native `0`, Direct `1`, Fallout 4 Direct `2` |
| `Mouse:fSensitivity` | `1.00` | `0.05` to `8.00` |
| `Mouse:fHorizontalScale` | `1.00` | `0.10` to `4.00` |
| `Mouse:fVerticalScale` | `1.00` | `0.10` to `4.00` |
| `Mouse:bInvertX/Y` | `0` | `0` or `1` |
| `Controller:fLeftDeadzone` | `0.15` | `0.00` to `0.95` |
| `Controller:fRightDeadzone` | `0.12` | `0.00` to `0.95` |
| `Controller:fResponseExponent` | `1.00` | `0.25` to `4.00` |
| `Controller:fAntiDeadzone` | `0.00` | `0.00` to `0.75` |
| `Controller:fOutputSaturation` | `1.00` | `0.25` to `1.00` |
| `Controller:fRightHorizontalScale` | `1.00` | `0.10` to `4.00` |
| `Controller:fRightVerticalScale` | `1.00` | `0.10` to `4.00` |
| `Controller:bInvertRightX/Y` | `0` | `0` or `1` |
| `Controller:fTriggerPress` | `0.12` | `0.01` to `1.00` |
| `Controller:fTriggerRelease` | `0.08` | `0.00` to at least `0.01` below press |
| `Diagnostics:bTelemetry` | `0` | `0` or `1` |
| `Diagnostics:bWriteSummary` | `0` | edge-triggered `0`/`1` request |

Native defaults and all 20 MCM defaults are behaviorally compared by the
shipped-artifact test. Settings apply when MCM closes. To request another
telemetry summary, close MCM once with the request off, then close it with the
request on.

MCM Extender saves every cached INI before dispatching `MCMExtUpdate` with one
array argument. xNVSE's native-handler API accepts only an event name already
known to the event manager, while script listeners normally create this event
implicitly. Atom therefore attempts to define `MCMExtUpdate` with one `Array`
parameter and `ALLOW_SCRIPT_DISPATCH`, treats a registration collision as the
expected already-defined case, and then admits its native handler. The handler
reads `Atom.ini` once, validates the complete candidate, and atomically
publishes changed settings. It does not poll pause state or touch the file each
frame.

Atom depends on the user's installed MCM Extender stack and does not
redistribute or modify it, The Mod Configuration Menu, xNVSE, JIP LN NVSE,
JohnnyGuitar NVSE, ShowOff xNVSE, or User Interface Organizer assets.

## Coherent state, performance, and memory

The live configuration, device frame, action frame, and latest keyboard batch
use sequence-validated arrays of 32-bit atomics. Every payload access is atomic,
so publication does not rely on an `UnsafeCell` data race. MCM writes are rare
and main-thread owned.

One device frame stores 41 words; one action frame stores 59; one keyboard
batch stores 163. Capture performs bounded keyboard comparisons, 28 binding
resolutions, radial controller arithmetic, and fixed publication. The only
mutex protects the 32-event native keyboard mirror and is always acquired with
`try_lock`; contention forwards to the predecessor and increments a saturating
counter. There is no hook-path allocation, file I/O, blocking lock, logging,
second relative-mouse read, or mouse history.

Telemetry is off by default. When enabled, each admitted marker performs one
wrapped QPC call and 32-bit atomic updates. Bucket thresholds and the two-second
discontinuity limit are converted to QPC ticks at configuration time, so the
hot path performs no division. Counts saturate at `u32::MAX`. A requested
summary is emitted at `INFO` through Psycho's asynchronous logger after MCM
closes; Atom creates no separate report or telemetry file.

## Logging and failure visibility

Atom uses `libpsycho::logger::Logger` and writes the rotating
`atom-latest.log`. Messages use stable tags:

- `[INIT]` for normal lifecycle completion or a capability-wide failure;
- `[CONFIG]` for read-only load, live reload, and restart-only fallback;
- `[INPUT]` for hook admission and predecessor detail;
- `[INPUT_TELEMETRY]` for availability and requested summaries.

Normal milestones and requested summaries are `INFO`, validated predecessor
addresses are `DEBUG`, recoverable fallback is `WARN`, and a failed requested
capability is `ERROR`. Atom does not use `println!`, `eprintln!`, or direct
diagnostic file writes.

## Installation and release layout

`build_fnv.sh` builds Atom explicitly for `i686-pc-windows-gnu` and installs:

```text
<MO2 mods>/Atom/
|-- MCM/Atom.json
`-- NVSE/plugins/atom.dll
```

The GitHub release workflow produces `atom-nvse-<tag>.zip`:

```text
Data/
|-- MCM/Atom.json
`-- NVSE/plugins/atom.dll
```

The archive allowlist rejects an ESP, generated INI, report file, script, or
accidental development asset.

## Validation and runtime acceptance

The focused behavioral suite covers:

- real MCM-shaped serini deserialization, missing defaults, unknown data,
  invalid numeric booleans/profiles, non-finite rejection, and bounds;
- native mouse passthrough, direct odd symmetry, independent axes, repeated
  history-free output, and exact vanilla-Y inversion compensation;
- radial controller monotonicity, direction preservation, output bounds, and
  noisy trigger hysteresis;
- coherent keyboard/mouse/controller snapshot publication and derived edges;
- mixed 28-action resolution, merged device edges, meaningful-device policy,
  focus epochs, held-key suppression, and menu context transitions;
- ordered press/release tap preservation, non-consuming peek replay, and
  32-event overflow bounding;
- final float Fallout 4 scale and sub-native-threshold radial stick actions;
- the shipped MCM JSON, DLL version gate, persistence path, unique 20-key
  schema, slider bounds, equality of MCM/native defaults, and the one-to-three
  word viewport limit for every visible text value.

Required static gates are:

```bash
cargo test --target i686-pc-windows-gnu -p atom
cargo build --release --target i686-pc-windows-gnu -p atom
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv -p atom
cargo fmt -p atom -- --check
git diff --check
```

Runtime acceptance remains mandatory:

1. Confirm `atom-latest.log` reaches `[INIT] Atom initialized successfully`
   and records the active input bridge.
2. Open Atom in MCM and visually inspect all five pages, help text, sliders,
   dropdown, and toggles.
3. Close MCM after changing settings and confirm one `[CONFIG]` reload/applied
   sequence without restart.
4. Verify Native behavior is unchanged; then A/B Direct and
   Fallout 4 Direct across hip, aim, scope, first/third person, menus, Pip-Boy,
   VATS, console, fly camera, focus loss, and overlays.
5. Enable telemetry, play representative indoor/outdoor combat, request a
   summary, and inspect the two bounded histograms plus buffered-keyboard
   health counters in `atom-latest.log`.
6. With BaseObjectSwapper in the representative modlist, complete at least
   three cold Proton starts into gameplay without its documented startup fault.
7. Confirm no mouse loss, duplication, stair-step, periodic hitch, camera/aim
   disagreement, or new CrashLogger fault at high mouse polling rates.
8. Exercise both sticks, both triggers, and controller buttons around their
   thresholds. Toggle Atom Input while controls are held and confirm activation
   and deactivation wait for neutral without a jump or false edge.
9. Exercise xNVSE tap, hold, and disable injection plus quick keyboard taps.
   Confirm gameplay sees every edge while console, menus, text entry, and other
   `GetDeviceData` consumers neither lose nor duplicate events.

Until these steps are recorded, Atom is statically validated but is not claimed
startup-safe, visually accepted, or proven to match Fallout 4's feel.

### Current build evidence

On 2026-08-16, for the current expanded input bridge:

- all 19 focused behavioral/artifact tests passed under Wine staging 11.15 for
  `i686-pc-windows-gnu` (2 plugin-boundary, 1 live-buffer-mirror, 14 public
  input-behavior, and 2 shipped-MCM tests);
- Atom-only Clippy passed with `--all-targets --no-deps -- -D warnings`;
- the Atom release build and the complete supported five-package release build
  passed for `i686-pc-windows-gnu`;
- Atom formatting and `git diff --check` passed.

The complete Clippy dependency run is not an Atom gate and remains blocked by
pre-existing `libpsycho` warnings in `hardware/cpu.rs` and
`os/windows/registry.rs`; Atom's own targets are warning-free.

The current release `atom.dll` is 6,435,204 bytes with SHA-256
`8847a27d4adcff4854834c0685d4f65f322028da81d9b411ddc82562901231a8`.
PE inspection establishes:

- PE32 i386, large-address-aware, ASLR and NX compatible;
- exactly `NVSEPlugin_Load` and `NVSEPlugin_Query` exported;
- 316 imported symbols in 29 descriptors representing 22 distinct DLL names,
  exactly matching the accepted comparison artifact;
- `.text`, `.data`, `.rdata`, `.eh_fram`, `.bss`, `.edata`, `.idata`, `.tls`,
  and `.reloc` sections;
- an unchanged `0x2AB8` import directory and eight-byte `.tls` section.

The current DLL is 112,862 bytes larger than the accepted `c489be...` artifact.
Its import count, import-directory size, section roles, and TLS data size are
unchanged, but executable/data layout and deferred static ownership changed.
That remains a material startup-footprint delta which only the required
Proton/BaseObjectSwapper playtest can accept.

### Runtime evidence

The 2026-08-16 first launch reproduced the xNVSE lifecycle assertion documented
above; it did not reach input hook installation. The corrected partial-input
artifact at SHA-256
`c489be721719b8709d30790e5ef5fb732203961dfdd461b05dd57b0bc372bfb3`
then completed the user's load-to-gameplay playtest. Its retained
`atom-latest.log` reaches `[INIT] Atom initialized successfully`, proves live
`MCMExtUpdate` registration, records Native/Direct/Fallout 4 Direct switches,
and contains 22,761 camera-consumer plus 38,738 present intervals without an
invalid interval.

That evidence accepts `c489be...` only. The current `8847a2...` DLL adds direct
controller output, the 28-action layer, and the buffered keyboard bridge; it
has not been installed or runtime-tested. Its load-to-gameplay, MCM visual,
controller, short-tap, compatibility, and input A/B acceptance remain pending.

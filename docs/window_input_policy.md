# Window cursor and system-key policy

## Purpose and user-visible behavior

Psycho enables two restart-only `[engine_fixes]` policies by default:

- `window_cursor_lock = true` confines the system cursor to the rendered game
  client while Fallout is foreground and not minimized. The rectangle follows
  window movement, size/DPI changes, and monitor-topology changes. It releases
  on focus loss, deactivation, minimization, and window destruction.
- `input_system_key_passthrough = true` preserves normal DirectInput keyboard
  delivery to Fallout while allowing Windows/Super, PrintScreen, and media
  commands to reach the operating system.

Both policies apply independently of the display geometry settings and support
every engine window mode:

| Fallout mode | Cursor target | System-key policy |
|---|---|---|
| `bFull Screen=1` native fullscreen | Renderer/top-level HWND (the globals alias) | Shared foreground DirectInput |
| `bFull Screen=0`, framed windowed | Renderer child client inside the top-level frame | Shared foreground DirectInput |
| `bFull Screen=0`, borderless windowed | Renderer child client inside the popup parent | Shared foreground DirectInput |

Disabling `display_alt_tab` or `display_borderless_windowed` does not disable
either input policy. Each new option can also be disabled independently for a
compatibility comparison.

PrintScreen has two consumers after passthrough: Windows may capture it and
Fallout may still run its configured BMP screenshot feature. Psycho does not
disable or replace either consumer.

## Source and configuration ownership

- `psycho-engine-fixes/src/mods/engine_fixes/window_input.rs` owns cursor
  lifecycle, the WndProc chain, both DirectInput code patches, and diagnostics.
- `psycho-engine-fixes/src/mods/engine_fixes/display.rs` owns the already-audited
  top-level `CreateWindowExA` IAT boundary. It passes only the validated
  bootstrap creation result to `window_input`.
- `libpsycho/src/os/windows/winapi.rs` owns safe wrappers for `ClipCursor`,
  `GetClipCursor`, `GetClientRect`, `ClientToScreen`, and
  `GetForegroundWindow`. Engine modules do not call WinAPI directly.
- `psycho-engine-fixes/src/config.rs` and
  `psycho-engine-fixes/config/psycho_engine_fixes.toml` own defaults and runtime
  configuration.
- `psycho-engine-fixes-helper/src/dashboard_config.rs` and `dashboard.rs` edit
  the restart-only values. The helper never installs either engine behavior and
  never loads or initializes the core.

The core config is published before display installation in the Syringe
activation sequence. Cursor policy is published and the DirectInput patch is
installed before the display creation shim is installed. All state then has
process lifetime; the dashboard saves changes only for the next launch.

## Proven executable contract

The supported executable is Fallout: New Vegas 1.4.0.525 PE32 x86, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

### Window identity and lifetime

The visible top-level bootstrap window is created by the indirect
`CreateWindowExA` call at `0x0086AF42`, returning to `0x0086AF48`. The complete
caller fingerprint and twelve-argument stdcall bridge are established by the
display contract. Its returned HWND becomes the stable input/foreground window
at global `0x011C6FC0`.

The renderer target is stored at `0x011C6FBC`. Native fullscreen stores the
same HWND in both globals. Windowed rendering creates a separate
`WS_CHILD | WS_VISIBLE` target beneath the top-level window. Consequently the
top-level is the correct WndProc/focus owner in every mode, while the renderer
child client is the exact cursor rectangle in windowed modes.

Fallout's procedure at `0x0086A0A0` owns native focus and `ShowCursor` behavior,
then forwards unhandled messages to `DefWindowProcA`. Psycho does not replace
that logic. It subclasses the validated returned top-level HWND and chains the
captured procedure before reacting to focus or geometry messages.

Evidence:

- `analysis/ghidra/output/perf/display_message_input_contract_audit.txt`
- `analysis/ghidra/output/perf/display_current_fix_contract_audit.txt`
- `analysis/ghidra/output/perf/display_exclusive_startup_owner_followup.txt`
- `docs/display_fixes_reimplementation_plan.md`
- `docs/psycho_dashboard.md`

### DirectInput keyboard setup

The keyboard setup function at `0x00A22660` selects one of two
`IDirectInputDevice8::SetCooperativeLevel` calls through vtable offset `+0x34`:

| Site | Native immediate | Native meaning | Replacement |
|---|---:|---|---:|
| `0x00A22782` | `0x16` | `NONEXCLUSIVE | FOREGROUND | NOWINKEY` | `0x06` |
| `0x00A227A1` | `0x15` | `EXCLUSIVE | FOREGROUND | NOWINKEY` | `0x06` |

`0x06` is `DISCL_NONEXCLUSIVE | DISCL_FOREGROUND`. The game continues to read
keyboard state through DirectInput, while neither `DISCL_NOWINKEY` nor an
exclusive keyboard hook blocks normal system handling.

Psycho verifies the branch selector from `0x00A2277A`, both
`GetActiveWindow` IAT calls, both device loads, both vtable dispatches, and both
native-or-replacement immediates before applying a rollback-capable two-site
transaction. The patch is size preserving and changes no ABI, stack layout,
branch, device pointer, HWND argument, or call target.

The focused primary-tool evidence, including the keyboard GUID, complete
instruction/byte span, flag decoding, and display-mode independence, is
`analysis/radare2/output/perf/window_input_policy_contract.txt`.

The vendored xNVSE DirectInput wrapper forwards cooperative-level flags to its
captured device at
`libnvse/xnvse/nvse/nvse/Hooks_DirectInput8Create.cpp:111`; it does not restore
the native flags. The helper's captured Win32-message set excludes
`WM_APPCOMMAND`, so media commands continue down the existing WndProc chain.

Microsoft's cooperative-level contract is documented by
[`IDirectInputDevice8::SetCooperativeLevel`](https://learn.microsoft.com/windows/win32/api/dinput/nf-dinput-idirectinputdevice8-setcooperativelevel).
Wine's keyboard implementation returns the exclusive cooperative flag from its
low-level hook, which is why removing both exclusivity and `NOWINKEY` matters
under Proton as well as native Windows:
[`dlls/dinput/keyboard.c`](https://gitlab.winehq.org/wine/wine/-/blob/master/dlls/dinput/keyboard.c).

## Cursor architecture and invariants

The creation shim attaches at most one top-level HWND. Repeated observation of
the same HWND is idempotent. A second distinct live HWND is rejected because a
single global predecessor cannot safely represent two simultaneous WndProc
subclasses. `WM_NCDESTROY` releases confinement and clears that process-lifetime
association before a later recreated window may attach.

The chained WndProc performs these post-predecessor actions:

- refresh on activation/focus, movement, non-minimized resize,
  `WM_WINDOWPOSCHANGED`, and `WM_DPICHANGED`;
- release then refresh on `WM_DISPLAYCHANGE`, so a stale virtual-desktop clip
  cannot survive monitor add/remove;
- release on deactivation, focus loss, minimization, and `WM_NCDESTROY`.

A refresh requires the attached top-level HWND to equal `GetForegroundWindow`
and not be iconic. It selects the live renderer HWND when valid, otherwise the
top-level client during early startup. `GetClientRect` supplies half-open
client coordinates; translating both corners with `ClientToScreen` correctly
supports secondary monitors with negative coordinates. Empty or invalid
rectangles are never passed to `ClipCursor`.

`ClipCursor` is one desktop-wide shared resource. Psycho remembers its last
successful rectangle. During release it first queries `GetClipCursor`; if the
rectangle differs, a later owner has replaced Psycho and is left untouched. If
the query itself fails, Psycho still attempts release because avoiding a cursor
trapped after deactivation is safer than treating an unreadable rectangle as
proof of another owner. Microsoft explicitly requires an application to free
the cursor before relinquishing control:
[`ClipCursor`](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-clipcursor).

No `SetCursorPos`, mouse polling, focus-state write, D3D hook, or window-style
change belongs to this feature. In particular, an invisible game cursor cannot
interact with windows on another monitor because the underlying system cursor
remains clipped rather than repeatedly warped.

## Failure and compatibility behavior

- If the bootstrap caller fingerprint conflicts, cursor subclassing remains
  off; Psycho never guesses another HWND.
- A conflict in the fullscreen predicate or integer-setting accessor disables
  only display geometry work. Cursor attachment needs neither engine function
  and remains available through the independently valid creation boundary.
- Earlier `CreateWindowExA` IAT owners are captured and chained. Psycho attaches
  to their returned HWND without rewriting their style or geometry decision.
- Later well-behaved WndProc owners can capture and chain Psycho. Psycho always
  chains its own predecessor first.
- A later cursor-clip owner is never cleared during Psycho's release.
- Invalid HWNDs, client rectangles, subclass errors, and `ClipCursor` failures
  are counted and fail without cursor warping or fabricated geometry.
- Either keyboard-site or surrounding-fingerprint conflict prevents both code
  writes. An unexpected second-write failure rolls back the first while Psycho
  still owns it.
- Existing equivalent `0x06` patches are accepted without claiming rollback
  ownership, making installation compatible with another component that made
  the same size-preserving change.
- Cursor and keyboard failures are isolated from one another and from unrelated
  engine fixes.

## Threading, performance, and memory

Installation runs once during early core activation. Keyboard preflight and
patching execute before engine input initialization. The cursor subclass is
installed synchronously on the game's window-creation thread.

Normal WndProc work uses atomics and stack-only rectangles. It takes no locks,
performs no heap allocation or file I/O, and emits no routine transition logs;
exceptional failures may format a throttled support log. Geometry messages
perform at most one foreground/iconic check, one child HWND load, two
client-coordinate translations, and one `ClipCursor` call when the rectangle
actually changed. There is no worker, timer, polling loop, or per-frame work.

Persistent memory is limited to atomic policy, ownership, rectangle, and
counter fields. The only code changes are two one-byte immediate replacements
inside existing two-byte `push imm8` instructions.

## Diagnostics

`PsychoInfo` and hang reports expose:

- cursor policy configured, WndProc attached, and clip currently active;
- attachment, apply, release, failure, and newer-owner displacement counts;
- system-key policy configured and both patches installed.

The first three cursor failures and later power-of-two occurrences are logged.
Normal focus, move, and resize activity is silent.

## Verification and runtime acceptance

Repository validation requires:

- core and helper tests on `i686-pc-windows-gnu`;
- the affected release build on `i686-pc-windows-gnu`;
- configuration tests proving both policies default on and disable
  independently;
- pure message-policy tests for active, inactive, minimized, destroy, geometry,
  topology-change, and negative-monitor rectangles;
- formatting, `git diff --check`, and final diff inspection.

Proton/Wine playtest acceptance remains separate from static/build proof. Test
all three rows of the mode table with cursor visibility both native and hidden,
two monitors on both sides of the primary, Alt-Tab, Win/Super, PrintScreen,
volume/playback keys, minimization, window movement/resizing, DPI changes, and
monitor disconnect/reconnect. Repeat with ReShade/ImGui menus open and with a
well-behaved earlier/later WndProc owner. Confirm the cursor cannot affect
another monitor while active and is never trapped after deactivation.

Repository validation on 2026-08-10:

- the combined supported-target test run compiled both affected crates and
  passed 157 core unit tests plus 14 helper unit tests, including all new
  configuration, message-policy, and negative-monitor cases;
- the command then encountered three existing rustdoc failures because assembly
  examples in `havok.rs` and `navmesh.rs` are not fenced as non-Rust. Those
  unrelated doc tests were not weakened or edited;
- a focused rerun of the three dashboard-config tests passed after one transient
  Wine `wineserver: bind: Operation not permitted` launch failure;
- the final four-test window-input suite, including exact fingerprint-span
  coverage, passed after the same transient Wine launch condition on its first
  attempt;
- `cargo clippy --target i686-pc-windows-gnu -p psycho-engine-fixes
  -p psycho-engine-fixes-helper --all-targets` passed with only existing
  warnings outside this feature;
- the affected release build for both crates passed on
  `i686-pc-windows-gnu`;
- release disassembly identifies `cursor_window_proc@16` and its terminal
  `ret 0x10`, confirming the four-argument Win32 stdcall ABI;
- in-game Proton/Wine validation across the mode/overlay matrix is still
  pending.

## Evidence classification

Proven static facts are the executable identity, addresses, instruction bytes,
DirectInput flags, HWND global roles, creation caller, WndProc owner, and xNVSE
forwarding behavior cited above. The intervention points and failure policy are
implementation decisions derived from those facts and the documented Win32
shared-resource contract. Correct behavior under every Proton version, desktop
environment, overlay stack, DPI layout, and physical multi-monitor topology is
not a static fact; it remains the runtime acceptance matrix above.

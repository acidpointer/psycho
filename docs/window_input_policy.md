# Window cursor and system-key policy

## Purpose and user-visible behavior

Psycho enables two restart-only `[engine_fixes]` policies by default:

- `window_cursor_lock = true` confines the system cursor to the usable game
  boundary while Fallout is foreground and not minimized. The rectangle follows
  window movement, size/DPI changes, and monitor-topology changes. It releases
  on focus loss, deactivation, minimization, and window destruction, and a
  window-thread audit repairs an overlay that widens or clears it.
- `input_system_key_passthrough = true` preserves normal DirectInput keyboard
  delivery to Fallout while allowing Windows/Super, PrintScreen, and media
  commands to reach the operating system.

Both policies apply independently of the display geometry settings and support
every engine window mode:

| Fallout mode | Cursor target | System-key policy |
|---|---|---|
| `bFull Screen=1` native fullscreen | Top-level client (renderer and top-level globals alias) | Shared foreground DirectInput |
| `bFull Screen=0`, framed windowed | Top-level outer rectangle, including caption and resize border | Shared foreground DirectInput |
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
- `libpsycho/src/os/windows/winapi.rs` owns wrappers for `ClipCursor`,
  `GetClipCursor`, client/outer rectangles, child validation, WndProc chaining,
  and thread message-queue timers. Engine modules do not call WinAPI directly.
- `psycho-engine-fixes/src/config.rs` and
  `psycho-engine-fixes/config/psycho_engine_fixes.toml` own defaults and runtime
  configuration.
- `psycho-engine-fixes-helper/src/dashboard_config.rs` and `dashboard.rs` edit
  the restart-only values. The helper never installs either engine behavior and
  never loads or initializes the core.

The core config is published before display installation in the Syringe
activation sequence. Cursor policy is published and the DirectInput patch is
installed before the display creation shim is installed. The WndProc and timer
have window lifetime; policy, patch, and diagnostic state have process lifetime.
The dashboard saves changes only for the next launch.

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
captured procedure before reacting to focus or geometry messages. A validated
predecessor is published before `SetWindowLongA` exposes Psycho's procedure;
the defensive zero-predecessor path calls `DefWindowProcA` instead of swallowing
a message.

The audited `0x0086AF48` return remains the primary attachment path. If a later
IAT owner calls Psycho from a different return address with the exact unchanged
twelve-field bootstrap request, Psycho chains that owner's request unchanged and
attaches only to its returned HWND. It does not take geometry authority. If the
later owner changed the request, `DeferredInit` performs a one-shot recovery
from the already-proven `0x011C6FC0` global. This recovery uses an established
engine contract rather than treating an arbitrary `CreateWindowExA` result as
the game window.

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
subclasses. A dead prior HWND is safe to retire even if an outer WndProc consumed
its `WM_NCDESTROY`; a later recreated window may then attach. The subclass
installs a 16 ms callback timer with `SetTimer(NULL, 0, ...)` on the same window
thread. A system-generated id avoids collisions with HWND timer ids, and no
worker thread or cross-thread window mutation is introduced.

The chained WndProc performs these post-predecessor actions:

- refresh on activation/focus, movement, non-minimized resize,
  `WM_WINDOWPOSCHANGED`, and `WM_DPICHANGED`;
- release then refresh on `WM_DISPLAYCHANGE`, so a stale virtual-desktop clip
  cannot survive monitor add/remove;
- release on deactivation, focus loss, minimization, and `WM_NCDESTROY`;
- suspend clipping during `WM_ENTERSIZEMOVE`, when Win32 owns mouse capture, so
  a framed window can cross monitor edges; resume after `WM_EXITSIZEMOVE` or
  `WM_CANCELMODE`.

A refresh requires the attached top-level HWND to equal `GetForegroundWindow`
and not be iconic or inside the modal move/resize loop. A renderer HWND is used
only if it aliases the top-level HWND or `IsChild` proves that it descends from
it; this prevents a destroyed/recycled handle from targeting another process's
window. The style and relationship select the target without relying on a
potentially stale display-mode flag:

- aliased native fullscreen uses the top-level client;
- a child under an undecorated parent uses the renderer client;
- a child under a captioned or thick-frame parent uses the top-level outer
  rectangle, preserving access to the caption and resize borders;
- a missing or unrelated renderer falls back to the audited top-level client,
  or its outer rectangle when framed.

`GetClientRect` supplies half-open client coordinates; translating both corners
with `ClientToScreen` correctly supports monitors with negative coordinates.
`GetWindowRect` supplies the framed outer boundary. Empty rectangles are never
passed to `ClipCursor`.

`ClipCursor` is one desktop-wide shared resource. Psycho separately remembers
the requested boundary and the effective rectangle returned by `GetClipCursor`
immediately after success. This matters because Windows or Wine can intersect
an off-screen request with the virtual desktop. An unchanged requested/effective
pair requires no write. In client-target modes, a newer rectangle wholly
contained inside the requested boundary is safe and retained; an unrestricted
or wider rectangle is repaired. Framed mode instead restores the exact outer
rectangle so a child-client clip cannot make its caption or resize border
unreachable. Any geometry change reapplies the new boundary even if the old clip
is a subset, so a moved or enlarged window cannot remain trapped in stale
dimensions.

Release is unconditional once Psycho has established active confinement. A
rectangle mismatch can mean that an overlay forgot its own deactivation path;
skipping release would leave the user trapped after Alt-Tab. Microsoft requires
an application to free the cursor before relinquishing control:
[`ClipCursor`](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-clipcursor).
If replacement fails while an older Psycho clip remains active, Psycho attempts
an immediate fail-safe release. A failed release retains active state so later
WndProc or timer callbacks retry it. After `WM_NCDESTROY`, the timer remains
only until that pending release succeeds.

No `SetCursorPos`, raw-mouse polling, focus-state write, D3D hook, or window-style
change belongs to this feature. The audit observes only the shared clip state;
it never synthesizes input. An invisible game cursor therefore cannot interact
with another monitor while the active clip remains in force.

## Failure and compatibility behavior

- If the bootstrap caller fingerprint conflicts, cursor subclassing remains
  off; Psycho never guesses another HWND.
- A conflict in the fullscreen predicate or integer-setting accessor disables
  only display geometry work. Cursor attachment needs neither engine function
  and remains available through the independently valid creation boundary.
- Earlier `CreateWindowExA` IAT owners are captured and chained. Psycho attaches
  to their returned HWND without rewriting their style or geometry decision.
- Later `CreateWindowExA` IAT owners are supported when the exact bootstrap
  request survives; a changed request uses one deferred lookup of the proven
  top-level global. Neither recovery path changes the later owner's geometry.
- Later well-behaved WndProc owners can capture and chain Psycho. Psycho always
  chains its own predecessor first. Timer reconciliation remains active if an
  outer owner consumes a focus or overlay message.
- A stricter later cursor clip is preserved while Fallout remains active in
  client-target modes. Framed mode restores its outer boundary to protect window
  controls. Every active clip is released on deactivation because desktop escape
  safety takes priority over retaining an in-process overlay's stale global clip.
- Invalid or unrelated HWNDs, rectangles, subclass errors, timer errors, and
  `ClipCursor` failures are counted and fail without cursor warping or fabricated
  geometry. If timer creation fails, WndProc-driven confinement still operates.
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
installed synchronously on the game's window-creation thread. Its callback timer
runs only when that same thread dispatches messages; no worker, sleep, lock, or
cross-thread HWND access is added.

WndProc and timer work uses atomics and stack-only rectangles. It takes no locks,
performs no heap allocation or file I/O, and emits no routine transition logs;
exceptional failures may format a throttled support log. Each active timer tick
performs bounded foreground, HWND/style, rectangle, and current-clip queries.
`ClipCursor` is called only after geometry changes or when the live rectangle
permits escape. At 16 ms this is at most about 62 lightweight audits per second,
independent of render rate; Win32 may coalesce ticks under load.

Persistent memory is limited to atomic policy, ownership, rectangle, and
counter fields plus one Win32 timer registration while a window is attached.
The keyboard code changes remain two one-byte immediate replacements inside
existing two-byte `push imm8` instructions.

## Diagnostics

`PsychoInfo` and hang reports expose:

- cursor policy configured, WndProc attached, and clip currently active;
- selected target role and timer installation;
- direct/recovery attachments, applies, releases, and failures;
- timer audits, repairs, Wine/Win32 normalizations, safe stricter clips,
  fail-safe releases, and rejected renderer HWNDs;
- system-key policy configured and both patches installed.

The first three cursor failures or distinct renderer rejections and later
power-of-two occurrences are logged. Normal focus, move, and resize activity is
silent.

## Current Proton runtime evidence

The 2026-08-10 playtest log at
`psycho-engine-fixes/psycho-engine-fixes-latest.log` records Proton/Wine 11.0
(CachyOS), both default-on policies installing, complete display callsite
coverage, and direct attachment to top-level HWND `0x000C00E2` with the proven
Fallout WndProc `0x0086A0A0`. It then records native fullscreen at
`(0,0 3440x1440)`, an audited focus-loss transition, `DeferredInit`, and a
successful fullscreen focus-regain correction. No `[WINDOW_INPUT]` failure was
emitted. The user's playtest observation was that cursor and key behavior were
correct under Proton.

The matching `omv-latest.log` records OMV installing an outer WndProc and ImGui
after Psycho attached and before the later focus-regain event. That is runtime
evidence that the original chained WndProc path survived one later overlay
owner in native fullscreen. It does not exercise framed-window target selection,
multi-monitor negative coordinates, a deliberate overlay `ClipCursor(NULL)`, or
the new timer and recovery paths, so those remain explicit playtest items.

`psycho-engine-fixes/CrashLogger.log` contains only an incomplete
`EXCEPTION_ACCESS_VIOLATION` header without an address, register context, module,
or stack. The main and OMV logs continue well beyond startup. The file cannot be
attributed to this feature and is retained only as an unresolved runtime anomaly,
not treated as proof of either success or failure.

## Verification and runtime acceptance

Repository validation requires:

- core and helper tests on `i686-pc-windows-gnu`;
- the affected release build on `i686-pc-windows-gnu`;
- configuration tests proving both policies default on and disable
  independently;
- pure message-policy tests for active, inactive, minimized, destroy, geometry,
  topology-change, modal move/resize, and negative-monitor rectangles;
- pure target-selection tests for aliased, child, missing, and unrelated HWNDs
  in framed and undecorated modes;
- reconciliation tests for stable Wine normalization, wider external clips,
  stricter overlay clips, and geometry changes;
- later-IAT-owner request classification tests;
- formatting, `git diff --check`, and final diff inspection.

Proton/Wine playtest acceptance remains separate from static/build proof. Test
all three rows of the mode table with cursor visibility both native and hidden,
two monitors on both sides of the primary, Alt-Tab, Win/Super, PrintScreen,
volume/playback keys, minimization, window movement/resizing, DPI changes, and
monitor disconnect/reconnect. Repeat with ReShade/ImGui menus open and with a
well-behaved earlier/later WndProc owner. Deliberately call `ClipCursor(NULL)`
while the game remains foreground and verify the timer repairs it. Confirm a
framed caption and every resize edge remain usable, the cursor cannot affect
another monitor while active, and it is never trapped after deactivation.

Repository validation on 2026-08-10:

- the supported-target library suites passed 162 core tests and 14 helper
  tests, including the default-on configuration, all cursor decision tests,
  later-IAT-owner classification, and the DirectInput fingerprint span;
- `cargo clippy --target i686-pc-windows-gnu -p psycho-engine-fixes
  -p psycho-engine-fixes-helper --all-targets` passed with only existing
  warnings outside this feature;
- the affected release build for both crates passed on
  `i686-pc-windows-gnu`;
- release imports include `ClipCursor`, `GetClipCursor`, `IsChild`,
  `DefWindowProcA`, `SetTimer`, and `KillTimer` from user32;
- release symbols and disassembly identify both `cursor_window_proc@16` and
  `cursor_timer_proc@16` with terminal `ret 0x10`, confirming both four-argument
  Win32 stdcall callback ABIs;
- formatting and `git diff --check` passed;
- the baseline native-fullscreen Proton observation above passed, while a new
  in-game run across the complete mode/overlay matrix remains pending.

## Evidence classification

Proven static facts are the executable identity, addresses, instruction bytes,
DirectInput flags, HWND global roles, creation caller, WndProc owner, and xNVSE
forwarding behavior cited above. The intervention points and failure policy are
implementation decisions derived from those facts and the documented Win32
shared-resource contract. Correct behavior under every Proton version, desktop
environment, overlay stack, DPI layout, and physical multi-monitor topology is
not a static fact; it remains the runtime acceptance matrix above.

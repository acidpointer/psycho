# Display and window-mode implementation contract

## Scope

The display fix uses synchronous, mod-independent wrappers around
FalloutNV.exe's `CreateWindowExA` and `SetWindowPos` imports. It recognizes the
bootstrap creation and six placement callers by return address and full
instruction fingerprint. Unrecognized calls preserve all arguments and chain
the captured predecessor.

Psycho does not replace focus management, poll windows, write engine focus
state, or perform D3D9 reset/resource work. The helper plugin and xNVSE events
are not required for display behavior. The optional cursor policy reuses the
audited top-level creation result but owns its separate WndProc lifecycle in
`window_input.rs`; see `docs/window_input_policy.md`.

`bFull Screen` in FalloutPrefs.ini is the authoritative mode selector:

- `bFull Screen=1` always selects native fullscreen. It receives bootstrap and
  transition correction, and `display_borderless_windowed` is ignored;
- `bFull Screen=0` selects the child-window renderer path. Its top-level parent
  is created at the final loaded size and position. With the shipped
  `display_borderless_windowed=true`, the parent uses `WS_POPUP | WS_VISIBLE`;
  setting the option to false preserves the engine's framed style;
- when both loaded `iLocation X` and `iLocation Y` values are zero, Psycho
  centers the final outer rectangle on the monitor nearest `(0,0)`;
- a later renderer placement preserves the live parent origin, so an
  interactive move survives renderer recreation. Nonzero configured
  coordinates seed the bootstrap position and remain authoritative until the
  user moves the live window;
- an undecorated live window whose outer rectangle exactly covers its monitor
  is treated as borderless fullscreen for transition correction only;
- child resizes and unrecognized callers pass through unchanged.

The core DLL owns this policy. The helper exposes the restart-only setting in
the dashboard but never applies a window style itself. An earlier external
`CreateWindowExA` or `SetWindowPos` IAT owner remains authoritative for the
corresponding windowed boundary; Psycho reports the owner and chains the
original request instead of competing with it.

Source and configuration ownership:

- `psycho-engine-fixes/src/mods/engine_fixes/display.rs` owns executable
  validation, IAT chaining, mode selection, geometry, diagnostics, and the
  validated top-level HWND handoff to the window-input module;
- `psycho-engine-fixes/src/mods/engine_fixes/window_input.rs` owns cursor
  confinement after that handoff and never changes display geometry;
- `psycho-engine-fixes/src/config.rs` and
  `psycho-engine-fixes/config/psycho_engine_fixes.toml` own the restart-only
  `engine_fixes.display_alt_tab` and
  `engine_fixes.display_borderless_windowed` preferences;
- `psycho-engine-fixes-helper/src/dashboard_config.rs` exposes those
  preferences without changing the already-published runtime policy;
- FalloutPrefs.ini owns `bFull Screen`, render size, and optional location.

## Proven engine callers

| Role | Call | Return | Policy |
|---|---:|---:|---|
| Visible bootstrap creation | `0x0086AF42` | `0x0086AF48` | Fullscreen: popup at loaded render size. Windowed: final outer size and configured or centered origin, with optional popup style |
| Windowed parent placement | `0x004DA951` | `0x004DA957` | Preserve the live top-level origin while applying the renderer's final size |
| Device reset | `0x004DC4CE` | `0x004DC4D4` | Preserve size/flags and align the client origin to its monitor |
| WM_SIZE child resize | `0x004D7861` | `0x004D7867` | Exact pass-through |
| Focus regain | `0x0086B4BF` | `0x0086B4C5` | Restore if iconic, normalize malformed geometry, and chain |
| Focus loss | `0x0086B628` | `0x0086B62E` | Validate the malformed contract, then suppress the activating move |
| Renderer lifecycle | `0x00872715` | `0x0087271B` | Normalize malformed geometry and chain |

FalloutPrefs.ini is loaded before the bootstrap call, including `bFull Screen`
and the requested render dimensions and location. Vanilla creates the
top-level window with `WS_VISIBLE` at `(0,0)` and a 320x240 client request. The
exclusive branch later reuses that HWND and skips the windowed placement call
entirely. The windowed branch creates a `WS_CHILD | WS_VISIBLE` render target,
computes the parent outer size from its live style, and calls `SetWindowPos`
with `iLocation X/Y`.

Psycho corrects the fingerprinted bootstrap before visibility. Fullscreen keeps
the engine origin and changes only width, height, and popup style. Windowed
reads all four settings through the already-audited integer accessor, computes
the outer extent with `AdjustWindowRectEx`, and selects its final origin. Class,
title, instance, parent, menu, extended style, and creation parameter remain
unchanged.

The later windowed placement uses the live parent rectangle rather than
blindly replaying the setting origin. This decision is intentional: the first
call retains the bootstrap seed, while a reset after the user has moved the
window retains the user-selected location. If no live rectangle is available,
the engine request chains unchanged; an unset `(0,0)` origin is centered when
monitor discovery succeeds.

The focus/lifecycle defect is:

```text
y  = adjusted.bottom
cy = adjusted.top - adjusted.bottom
```

For a sane recognized request, normalization is exact:

```text
top    = y + cy
height = -cy
```

The normalized engine coordinates are made relative to the window's current
monitor. If monitor discovery fails, the normalized coordinates are retained.

## Installation and compatibility

The fix installs immediately after logging, before allocator and other engine
hooks. It verifies the bootstrap and all six placement callers independently,
then fingerprints the fullscreen predicate and integer-setting accessor. A
conflict at one boundary does not disable the others.

Installation independently replaces the aligned IAT pointers at `0x00FDF2B8`
and `0x00FDF2A4` under temporary page protection. Each current executable
target is published first and chained as its predecessor. This composes with
earlier IAT hooks; later well-behaved hooks can capture and chain Psycho.
Direct-call or unknown caller rewrites are reported and left untouched.

The x86 entry bridge reads the original return address from `[esp]`, forwards it
in fastcall `ecx`, and jumps to the Rust body without altering the stack. The
`CreateWindowExA` retains 48-byte stdcall cleanup and `SetWindowPos` retains
28-byte cleanup.

If installation occurs after renderer creation, a guarded catch-up reads the
live top-level/child HWND globals. In exclusive fullscreen only, it preserves
the live size and queues a non-activating asynchronous position-only move to
align the client with its current monitor.

## Failure behavior

- Unknown callers always chain unchanged.
- A recognized caller whose full fingerprint is not owned by Psycho chains
  unchanged when it can still reach the IAT.
- Runtime arguments that violate the caller contract chain unchanged.
- A fullscreen-predicate conflict disables only bootstrap/reset correction and
  catch-up; the fingerprinted malformed callers remain protected.
- A setting-accessor conflict disables bootstrap geometry changes; the
  independent placement boundaries retain their own audit results. Cursor
  attachment remains available because it does not call that accessor.
- Monitor lookup failure preserves the engine origin rather than inventing a
  coordinate.
- Borderless-windowed never changes a `bFull Screen=1` request.
- An existing external IAT predecessor retains windowed style or placement
  ownership for its corresponding boundary.
- An IAT ownership race never overwrites the new owner.
- A failed pointer-protection restoration attempts rollback only while Psycho
  still owns the slot.
- Display geometry adds no code-site patch, focus-state hook, timer mutation,
  or D3D9 reset owner. The separately configured cursor policy subclasses the
  already-validated top-level HWND only to maintain `ClipCursor` lifecycle.

## Diagnostics

`PsychoInfo` and hang reports expose:

- both predecessor addresses and vanilla/external ownership;
- the configured borderless-windowed policy;
- independent state for bootstrap creation and all six placement callers;
- bootstrap observations, total/windowed corrections, failures, and reset
  corrections;
- windowed parent observations and corrected origins;
- child pass-through, loss suppression, regain/lifecycle normalization counts;
- catch-up attempts, successes, and failures;
- monitor selection/fallback and iconic restore counts;
- contract mismatches, predecessor failures, and the last Win32 result/error.

Frequent transition logs are limited to the first three and power-of-two
occurrences.

## Threading and cost

Installation runs in the early core startup sequence before allocator hooks.
The bootstrap correction executes synchronously on the engine's window-creation
thread. Fullscreen reads two size settings. Windowed mode reads size and
location, calls `AdjustWindowRectEx`, and performs at most one monitor query.
Windowed renderer placement performs one live rectangle query and, only for an
unresolved zero origin, one monitor query.

There is no worker, timer, polling loop, persistent allocation, or per-frame
display work. Each shim uses atomic policy/diagnostic state and stack-only
geometry. Child resize and unknown calls add only caller classification plus
predecessor chaining. Cursor WndProc costs and invariants are specified
separately in `docs/window_input_policy.md`.

## Verification

- Build the supported i686 release target.
- Run formatting, diff checks, and clippy for touched crates.
- Inspect both generated bridges for the initial `[esp]` read and their Rust
  bodies for stdcall `ret 48`/`ret 28` cleanup.
- Confirm all seven fingerprint lengths end exactly after their six-byte
  indirect call.
- Confirm no display behavior depends on helper events.
- Unit-test zero-origin centering on a negative-coordinate monitor.
- Unit-test borderless-windowed popup style and final geometry.
- Unit-test preservation of a manually moved live parent origin.
- Confirm `bFull Screen=1` is evaluated before borderless-windowed.
- Confirm framed windowed mode remains available when
  `display_borderless_windowed=false`.
- Confirm external window owners retain style/size control at boundaries they
  already own while recognized engine transitions receive only their
  documented corrections.
- Confirm the engine remains the sole focus and D3D9 recovery owner.

Runtime coverage should include primary/secondary monitors (including negative
coordinates), common DPI scales, native D3D9/DXVK, exclusive modes below and at
desktop resolution, framed and borderless windowed modes, configured and unset
locations, interactive moves followed by renderer reset, repeated
Alt-Tab/minimize restore, loading screens, helper present/absent, allocator
modes 0/1/2, and earlier/later/direct display hooks.

Repository validation on 2026-07-29:

- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
  -p psycho-engine-fixes-helper`: 117 core and 14 helper tests passed;
- `cargo build --release --target i686-pc-windows-gnu
  -p psycho-engine-fixes -p psycho-engine-fixes-helper`: passed;
- release disassembly shows `set_window_pos_entry` begins with
  `mov ecx,[esp]` and reaches `ret 0x1c`, while
  `create_window_ex_a_entry` begins with `mov ecx,[esp]` and reaches
  `ret 0x30`;
- in-game Wine/Proton acceptance remains pending.

## Evidence and confidence

Proven static facts:

- the bootstrap request is visible, 320x240, and hard-coded to `(0,0)`;
- FalloutPrefs.ini is loaded before that request;
- the windowed renderer reads `iLocation X` from `0x011C75D4` and
  `iLocation Y` from `0x011C7654`, creates a child render HWND, and places the
  top-level parent once per renderer construction;
- the exclusive branch aliases the render and parent HWNDs and skips windowed
  placement;
- the malformed focus and lifecycle placements are guarded by the fullscreen
  predicate;
- FNV's WndProc forwards non-client hit testing and ordinary system commands to
  `DefWindowProcA`.

Reasoned root-cause inference:

- when a profile leaves both location values at their zero defaults, the
  one-shot windowed placement preserves the bootstrap corner;
- exposing the hard-coded bootstrap before the final renderer placement makes
  Wine/Proton window-manager state dependent on a later focus transition;
- creating the final top-level contract before visibility and preserving its
  live origin removes both sources of placement churn without taking focus or
  D3D9 ownership.

Runtime observation:

- the reported failure is a framed window at `(0,0)` that becomes movable only
  after Alt-Tab. The code and tests establish the intervention contract, but
  the corrected framed and borderless behavior still requires an in-game
  Wine/Proton playtest before it is claimed as runtime-proven.

## Research authority

- `analysis/ghidra/output/perf/display_current_fix_contract_audit.txt`
- `analysis/ghidra/output/perf/display_focus_timer_target_followup.txt`
- `analysis/ghidra/output/perf/display_startup_position_followup.txt`
- `analysis/ghidra/output/perf/display_exclusive_startup_owner_followup.txt`

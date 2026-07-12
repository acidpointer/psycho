# Display fix implementation contract

## Scope

The display fix uses synchronous, mod-independent wrappers around
FalloutNV.exe's `CreateWindowExA` and `SetWindowPos` imports. It recognizes the
bootstrap creation and six placement callers by return address and full
instruction fingerprint. Unrecognized calls preserve all arguments and chain
the captured predecessor.

Psycho does not replace focus management, poll windows, write engine focus
state, or perform D3D9 reset/resource work. The helper plugin and xNVSE events
are not required for display behavior.

## Proven engine callers

| Role | Call | Return | Policy |
|---|---:|---:|---|
| Visible bootstrap creation | `0x0086AF42` | `0x0086AF48` | In exclusive fullscreen, preserve the engine origin and create as `WS_POPUP | WS_VISIBLE` at the loaded render size |
| Windowed parent placement | `0x004DA951` | `0x004DA957` | Exact pass-through |
| Device reset | `0x004DC4CE` | `0x004DC4D4` | Preserve size/flags and align the client origin to its monitor |
| WM_SIZE child resize | `0x004D7861` | `0x004D7867` | Exact pass-through |
| Focus regain | `0x0086B4BF` | `0x0086B4C5` | Restore if iconic, normalize malformed geometry, and chain |
| Focus loss | `0x0086B628` | `0x0086B62E` | Validate the malformed contract, then suppress the activating move |
| Renderer lifecycle | `0x00872715` | `0x0087271B` | Normalize malformed geometry and chain |

FalloutPrefs.ini is loaded before the bootstrap call, including `bFull Screen`
and the requested render dimensions. Vanilla creates the top-level window as a
visible 320x240 popup at `(0,0)`. The exclusive branch later reuses that HWND
and skips the windowed placement call entirely. Psycho changes only the
fingerprinted exclusive bootstrap width, height, and style. The original
`WS_VISIBLE`-only style describes an overlapped top-level window; once created
at fullscreen size it must be made an explicit popup to prevent a frame. The
engine-owned origin, class, instance, parent, and creation parameters are
preserved.

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
- An IAT ownership race never overwrites the new owner.
- A failed pointer-protection restoration attempts rollback only while Psycho
  still owns the slot.
- No code-site patch, focus hook, timer mutation, or D3D9 reset owner is added.

## Diagnostics

`PsychoInfo` and hang reports expose:

- both predecessor addresses and vanilla/external ownership;
- independent state for bootstrap creation and all six placement callers;
- bootstrap observations/corrections/failures and reset corrections;
- child pass-through, loss suppression, regain/lifecycle normalization counts;
- catch-up attempts, successes, and failures;
- monitor selection/fallback and iconic restore counts;
- contract mismatches, predecessor failures, and the last Win32 result/error.

Frequent transition logs are limited to the first three and power-of-two
occurrences.

## Verification

- Build the supported i686 release target.
- Run formatting, diff checks, and clippy for touched crates.
- Inspect both generated bridges for the initial `[esp]` read and their Rust
  bodies for stdcall `ret 48`/`ret 28` cleanup.
- Confirm all seven fingerprint lengths end exactly after their six-byte
  indirect call.
- Confirm no display behavior depends on helper events.
- Confirm windowed/borderless and unrecognized calls are exact pass-through.
- Confirm the engine remains the sole focus and D3D9 recovery owner.

Runtime coverage should include primary/secondary monitors (including negative
coordinates), common DPI scales, native D3D9/DXVK, exclusive modes below and at
desktop resolution, repeated Alt-Tab/minimize restore, loading screens, helper
present/absent, allocator modes 0/1/2, and earlier/later/direct display hooks.

## Research authority

- `analysis/ghidra/output/perf/display_current_fix_contract_audit.txt`
- `analysis/ghidra/output/perf/display_focus_timer_target_followup.txt`
- `analysis/ghidra/output/perf/display_startup_position_followup.txt`
- `analysis/ghidra/output/perf/display_exclusive_startup_owner_followup.txt`

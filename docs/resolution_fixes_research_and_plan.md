# Resolution fixes: native contract and implementation plan

Status: implemented; local checks and supported release build passed; game runtime not run.
Last updated: 2026-10-20.

## Purpose and scope

Provide one Psycho engine feature with two coordinated corrections:

- Render Pip-Boy, terminals, and RaceMenu using the configured render width;
  preserve their native aspect calculation; correct tile scaling and Pip-Boy
  tab targeting together.
- Enlarge the native fade-to-black quad by removing its width and height halving.

Public control: restart-only `engine_fixes.resolution_fixes = true`,
with dashboard label `Resolution fixes`. The core owns both parts, independently
of allocator mode, OMV, and helper availability. One switch covers the entire
feature.

The implementation changes six executable sites while retaining native
rendering and D3D9 resource ownership. Existing display/window/input policies
and externally owned menu/scope FOV adjustments retain their existing behavior.

## Evidence and confidence

Reverified executable: discovered `fnv_reverse/FalloutNV.exe`, supported
1.4.0.525, PE32 x86, preferred image base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

Raw radare2 disassembly, bytes, cross-references, dispatch table, commands,
and executable identity:

- [Screen sites](../analysis/radare2/output/fnv_resolution_screen_sites_20261020.txt).
- [Fader and tile callers](../analysis/radare2/output/fnv_resolution_fader_and_ui_contract_20261020.txt).
- [Exact unchanged instruction contexts](../analysis/radare2/output/fnv_resolution_context_signatures_20261020.txt).

MCP was available for initial inspection; its analysis request did not return
and was cancelled. Targeted CLI queries with `bin.relocs.apply=true` supplied
the retained follow-up evidence. Arbitrary disassembly range starts sometimes
land inside instructions; claims below use verified instruction boundaries.

The original executable instructions are proven. Actual resource dimensions,
images, mouse behavior, GPU cost, and startup compatibility have not been
tested. The owner explicitly authorized implementation as a new feature
without an existing-defect reproduction. Environment discovery found an
executable but no configured game installation or runtime log set.

## Native screen contract

The shared dimension selector starts at `0x00B6C2C0`. It dispatches through
`0x00B6D048` on the second stack argument and returns with `ret 0x20`.
Its first stack argument supplies the renderer used by the changed branches;
the next two supply width and height output pointers. Byte replacements retain
this native call boundary and its eight stack arguments.

Dispatch entries `0x2D` and `0x31` reach `0x00B6CD24`; entry `0x30` reaches
`0x00B6CEBB`. The screen correction covers both branches. Individual
screen-to-type assignments still require observation at the real UI boundary.

Both original branches store width 1280 (`0x500`). Each then queries the
renderer through virtual `+0xC8`, obtains dimensions through group virtuals
`+0x90` and `+0x8C`, computes proportional height, converts it with x87
truncation, and restores the previous x87 control word. The screen branch
keeps flags `4`; RaceMenu keeps flags `0x40`.

Each replacement loads `[0x011F9430]` into EAX and stores it through
the original width output pointer, then preserves the renderer virtual call.
The remaining aspect/height calculation and native allocation path continue
unchanged. The executable writer at `0x004DB08F` copies it from the setting
accessed at `0x011C73DC`. It is a native settings snapshot, not a new Psycho
per-frame settings read.

This follows configured width, including widths below 1280. It is not a fixed
1080p/4K preset or a supersampling multiplier. Actual dimensions still depend
on the native aspect source and allocation outcome.

The other two screen changes coordinate scaling and targeting:

- `0x00A03C60` originally resolves the tile's menu through `0x00A03C90` and
  returns its byte at `+0x1C` in AL. Replacing its entry with
  `xor al,al; ret; nop` makes this predicate false. The original entry has no
  stack arguments to clean. The three direct callers found after `aar`, at
  `0x00A063E2`, `0x00A065DF`, and `0x00A07B3B`, all consume AL and select
  between native screen dimensions and alternate menu-space dimensions.
  The correction affects this shared predicate and its callers.
  Indirect/external caller coverage remains unqualified.
- `0x00712BA1` changes `je +0x78` to `jmp +0x78`, retaining destination
  `0x00712C1B`. This bypasses the following scaling of four targeting-rectangle
  coordinates. Its owner is the InterfaceManager path starting at
  `0x007126C0`, with a direct caller at `0x0070CEF1`. The earlier independent
  conditional at `0x00712B8C` remains intact. Correct Pip-Boy tab targeting is
  a behavioral requirement; actual click alignment needs runtime observation.

## Native fader contract

Both fade sites belong to the FaderManager function at `0x007006C0`, identified
by its embedded `FaderManager.cpp` source string. Direct callers found after
`aar` are `0x007130EB` and `0x00713356`.

The native path calls `0x004DC1F0` for width and `0x004DC200` for height. Those
accessors return `[0x0118947C]` and `[0x01189480]`. Each dimension is converted
to floating point and multiplied by the double `0.5` at `0x01011588` before
constructing the four quad positions.

The correction replaces each six-byte `fmul` with six single-byte
NOPs. The stored coordinate magnitudes become W and H rather than W/2 and H/2;
the following sign changes and vertex construction remain native. Both axes
therefore double in this geometry space. This is an enlarged native fade quad,
not an aspect-ratio detection algorithm. The correction applies at every
aspect ratio and does not hook fade timing or replace the global 0.5 constant.

The requested behavior is removal of the black-rectangle artifact; binary
inspection proves the targeted geometry arithmetic. Complete coverage after
projection, unaffected fade timing/composition, and reset behavior require the
actual game path. No static claim of image correctness follows from the larger
coordinates.

## Exact six-site patch set

Use the exact byte results and write footprints below. Duplicate identical
installation converges without introducing competing detours.

| Purpose | Address | Original bytes | Installed result |
|---|---|---|---|
| Tile-scale predicate | `0x00A03C60` | `55 8B EC 83` | `32 C0 C3 90` |
| Pip-Boy/terminal width block | `0x00B6CD2C` | `C7 45 00 00 05 00 00 8B 17 8B 82 C8 00 00 00 8B CF FF D0` | `A1 30 94 1F 01 90 89 45 00 8B 17 8B CF FF 92 C8 00 00 00` |
| RaceMenu width block | `0x00B6CEC3` | Same original 19 bytes above | Same replacement 19 bytes above |
| Targeting branch opcode | `0x00712BA1` | `74` (instruction `74 78`) | `EB` (instruction `EB 78`) |
| Fader width multiply | `0x00700AB2` | `DC 0D 88 15 01 01` | `90 90 90 90 90 90` |
| Fader height multiply | `0x00700ACC` | `DC 0D 88 15 01 01` | `90 90 90 90 90 90` |

The predicate's four-byte footprint overwrites the start of a six-byte original
prologue. Its replacement returns before the unchanged suffix can execute.
Validate complete surrounding original instructions and the complete accepted
replacement context; do not treat four prefix bytes as sufficient authority.
Similarly validate both targeting-branch bytes, its destination, and its
surrounding contract even though only its opcode changes. The two 19-byte
blocks and both six-byte multiplies end on original instruction boundaries.

## Compatibility strategy

The feature uses cooperative, exact-result code patches installed at the
existing core pre-CRT barrier. Identical external corrections can coexist
without a later override. This property does not certify compatibility with
unknown external implementations or untested runtime configurations.

At each site, classify the full relevant context:

1. Original supported code: eligible for an owned Psycho write.
2. Exact requested result already present: satisfied externally; perform no
   write and acquire no rollback ownership.
3. Anything else, including an unproven detour: conflict requiring evidence.
   Preserve it and report the precise boundary. Do not infer compatibility
   from a jump opcode, a DLL name, or apparent similarity.

Existing `OwnedCodePatch::verify/apply` already accepts the exact replacement;
`apply` returns `None` without a write for that case. Existing
`ModificationTransaction` restores only its recorded writes, in reverse order,
and checks ownership. Reuse both. Wider instruction-context checks must also
accept the matching original or exact feature result as appropriate.

Preflight all six sites before any write. A mix of original and exact already
corrected sites is valid. Apply only missing writes in one transaction and
publish success only when all six contracts hold. An unknown site blocks the
complete resolution-feature installation; leave pre-existing external patches intact and
report the feature as incomplete/conflicted, not fixed or fully vanilla.
Rollback is best effort and must report a restoration failure explicitly.

Known load-order cases to qualify:

| External behavior | Feature behavior |
|---|---|
| Exact requested result installed earlier | Leave it in place; supply only missing corrections |
| Identical external writes occur after Psycho | Identical stores preserve the requested result; no trampoline is damaged |
| External menu/scope FOV adjustments | Preserve their independently owned values |
| Only part of the identical set exists | Fill missing original sites under the common transaction |
| Unknown same-site code or modified surrounding contract | Preserve owner; report conflict; investigate a proven alternative boundary |
| Another owner changes code after installation | Report observed loss when verified; no automatic reapplication |

Do not move installation later merely to win load order. Multi-byte writes are
not execution-atomic, and `ModificationTransaction` does not suspend threads.
A late rewrite needs a proven quiescent point and complete displaced-code,
ABI, lifetime, and ownership contracts. Overwriting an unknown earlier hook
can discard unrelated behavior even when the visible resolution issue improves.

If runtime evidence reveals a real conflicting implementation, first research
a narrower chainable engine boundary that preserves its valid-input behavior.
A downstream dimension multiplier could double-apply the fader correction;
a whole selector detour would intersect more target types. Neither is approved
as a generic fallback by this research. An unresolved conflict remains an
implementation blocker for that configuration, not a claim of compatibility.

Configuration off means Psycho performs no writes. It cannot undo behavior
independently supplied by another mod. No mod detection, third-party code
patching, frame polling, background repatching, or load-order requirement is
part of this design.

## Implementation and ownership

- `psycho-engine-fixes/src/mods/engine_fixes/resolution_fixes.rs` owns six
  `OwnedCodePatch` descriptors, unchanged instruction-context signatures,
  common preflight, one `ModificationTransaction`, and published status.
  Preflight rejects unknown code before any write. A final verification
  requires all six corrected results before committing the transaction.
- `mods/engine_fixes/mod.rs` installs the feature at its existing pre-CRT
  engine-fix boundary, after allocator initialization. Core admission and the
  feature both require Syringe's established pre-CRT barrier. Installation
  errors are logged and contained to this feature; other engine fixes proceed.
- The module verifies unchanged owner entries, surrounding instructions, the
  predicate's remaining function body, and the targeting displacement. These
  signatures exclude all six writable footprints so independently supplied
  identical corrections pass the same preflight.
- Core `config.rs` appends the boolean to its immutable config/default/raw
  mapping. `config/psycho_engine_fixes.toml` places it under Display and input.
  Existing config fields, migrations, and shared ABI layouts are preserved.
- Helper `dashboard_config.rs` appends the restart-only field and persists it
  through the existing comment-preserving editor. `dashboard.rs` exposes it
  in Window and input. The helper cannot activate or disable live patches.
- Installation emits one `[RESOLUTION]` summary with newly installed and
  already corrected site counts. Unknown signatures and write failures report
  their boundary and consequence. The existing textual report exposes
  disabled, active, unavailable, or changed-after-installation status.
- Existing `DeferredInit` forwarding optionally verifies the six results and
  their contexts once. A mismatch publishes changed status and logs a warning;
  no live instructions are rewritten. The feature works without the helper.

The startup delta is limited to the new config boolean, fixed patch/signature
storage, three zero-initialized atomic status values, and the installation and
optional observation calls. No worker, TLS, import, dependency, new startup
phase, resource owner, or cross-DLL ABI field is introduced. Local import/TLS
comparison supports footprint review but cannot establish startup safety in
the real game. The owning startup requirements remain in
[startup safety](nvse_startup_phase_safety.md).

## Configuration text

TOML comments retain imperative wording:

```toml
# Improve Pip-Boy, terminal, and character creation screen resolution, and fix
# incomplete fades to black on ultrawide displays.
resolution_fixes = true
```

Helper label: `Resolution fixes`. Its tooltip follows the existing short,
third-person, player-facing style:

> Improves Pip-Boy, terminal, and character creation screen resolution, and fixes
> incomplete fades to black on ultrawide displays.

Restart behavior uses the helper's existing Save for next launch workflow.
Neither surface exposes implementation details.

## Cost and failure behavior

There is no new per-frame hook, per-draw allocation, lock, file read, shader
compile, or log. Installation uses the existing patch machinery once.
Screen targets contain more pixels when configured width exceeds 1280, so
native allocation and rendering can cost more. The fader uses the same vertex
count with larger coordinates. Measure actual resource memory and GPU cost in
the real workload; do not claim an FPS result from pixel arithmetic.

Preserve native resource failure handling and reset/recreation ownership. Do
not add an unproven resolution cap, multiplier, resource fallback, or global
dimension override. Signature/protection failures must not leave an
unreported partial Psycho patch set. No live disable/restore is planned.

## Behavioral acceptance and implementation gates

The behavior test is the shipped native UI/render path in the real game.
The owner authorized new-feature implementation without a real-game baseline.
When runtime validation is performed, preserve captures and observations using
the same settings, assets, menus, display mode, and save workload, and compare
the candidate against the explicit expected dimensions, image coverage, and
input behavior. Source assertions, synthetic rectangles, copied formulas,
compilation, and logs do not qualify
image correctness or input alignment.

Required observations:

- Pip-Boy tabs, terminal text/hacking input, and RaceMenu actually use the
  intended dimensions and remain readable, correctly proportioned, unclipped,
  and interactive. Observe actual native/D3D resource descriptions as well as
  images. Exercise mouse edges and tab targets; resource size alone is not
  sufficient.
- Fade-to-black covers the intended view without the ultrawide rectangle
  artifact and preserves fade timing, alpha, and surrounding UI composition.
  Use the actual loading/transition path that exhibits the defect, including
  other reachable fade paths in the affected native owner.
- Cover representative 4:3, 16:9, 21:9, and 32:9 modes, plus configured width
  below/equal/above 1280. Include exclusive and windowed paths, normal
  open/close, loading, Alt-Tab, and native renderer reset/recreation. Verify
  dimensions, coverage, and input again after each lifecycle transition.
- Execute Psycho alone and with overlapping external resolution corrections,
  preserving independently owned FOV choices. Cover each reachable
  earlier/later installation order, partial identical patch sets, config off,
  and helper present/absent. Inspect final six-site state
  after plugin initialization and exercise the affected behavior.
- When an actual conflicting configuration exists, observe preserved external
  behavior and accurate conflict reporting. Do not invent a synthetic hook or
  substitute a mock for this gate.
- Meet startup load-to-gameplay acceptance with the representative modlist and
  native D3D9/DXVK environments in scope; compare actual memory/render cost
  against the same workload. Preserve baseline settings and comparison images.

During candidate qualification, run focused applicable checks, then the
affected core/helper suites and one supported release build. The user deploys
that reviewed candidate for the final runtime comparison; acceptance requires
both the checks and the actual behavior:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes -p psycho-engine-fixes-helper
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv -p atom
cargo fmt -p psycho-engine-fixes -p psycho-engine-fixes-helper -- --check
git diff --check
```

These checks support the behavioral gate; they do not replace it. Add no
source-text, manifest, mirrored-formula, or coverage-only tests. A reversible
documentation plan needs document/link checks and diff review only.
Deployment, packaging, and installation remain user-only; commits require
separate explicit approval.

## Remaining runtime qualification

- A configured/authorized game environment and reproducible acceptance
  workload with matching assets, including the actual ultrawide transition.
- Load-to-gameplay startup acceptance for the new config/static footprint.
- Complete classification of relevant selector callers, any indirect/external
  predicate callers, and the two fader callers' lifecycle/thread ownership.
  Current direct cross-references are recorded; they do not prove runtime caller
  coverage or recreation behavior.
- Real coexistence results for the installed modlist. Byte equality can
  establish an already satisfied site, but cannot establish that unknown
  implementations preserve the complete surrounding contract.

Implementation follows the owner's explicit new-feature exception. Local tests
and a supported release build do not establish game image, input, startup,
reset, coexistence, or performance acceptance. Those observations remain not run.

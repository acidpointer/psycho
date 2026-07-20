# Agent operating guide

Use this file for repository-wide rules. Before editing a subtree, also read its nearest `AGENTS.md`. Keep work evidence-driven, scoped, and economical.

## Priorities

In order:

1. Correctness and user safety.
2. Preserve requested behavior and existing user changes.
3. Prove the result with the smallest sufficient validation.
4. Minimize implementation time, runtime cost, and agent context.

Do not trade correctness for speed. Do not add process, diagnostics, or abstraction without a concrete need.

## Default workflow

1. Restate the outcome internally; identify files, invariants, and explicit constraints.
2. Inspect only relevant code, tests, docs, and `git status`. Use `rg`/`rg --files`; batch independent reads.
3. Resolve material unknowns from code or authoritative research. Make reversible assumptions; ask only when a choice is blocking, destructive, or changes scope.
4. For a bug, first add or identify a regression test that can reject the defect. For a feature, define observable acceptance criteria.
5. Make the smallest coherent change. Avoid opportunistic refactors and unrelated formatting.
6. Validate in layers: focused check, affected suite, then one release build when required.
7. Inspect the final diff for accidental changes. Report the outcome, evidence, and any remaining playtest need concisely.

Stop when the requested outcome is proven. Do not continue speculative cleanup or research.

## Context and communication economy

- Do not scan the whole repository when targeted search can answer the question.
- Read detailed plans, errata, generated output, or third-party sources only when the task touches them.
- Use a written plan only for multi-stage, high-risk, or unclear work. Keep it outcome-based and update it at milestones, not after every command.
- Do not repeat unchanged context in progress updates or final reports. Communicate at meaningful milestones.
- Do not rerun an unchanged expensive test or build. Run narrow checks while iterating and the required broad check once at the end.
- Prefer existing helpers, patterns, fixtures, and test infrastructure over new frameworks.
- Preserve a dirty worktree. User changes are not cleanup targets.

## Definition of done

A change is done only when:

- the requested behavior is implemented without narrowing scope;
- a regression or acceptance test covers the important behavior when practical;
- applicable focused tests and the affected suite pass;
- the supported release target builds when code or build inputs changed;
- `git diff --check` passes and the diff contains no unintended edits;
- unsupported claims and unverified runtime behavior are identified honestly.

Documentation-only changes require document checks and diff inspection, not a Rust rebuild. Compilation alone is never proof of runtime or image correctness.

## Build and test

The only supported target is 32-bit `i686-pc-windows-gnu` for FNV/xNVSE. Always write the target explicitly even though `.cargo/config.toml` currently selects it. Requires `i686-w64-mingw32-gcc`, the Rust target, and initialized submodules.

```bash
git submodule update --init --recursive
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
```

OMV validation:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Cargo runs Windows tests through Wine. For non-OMV work, run available tests for affected crates, then the affected release build. Use formatting or linting when relevant; neither replaces tests or building.

Submodules:

- `libmimalloc/c_src/mimalloc`: upstream mimalloc C source.
- `libnvse/xnvse`: xNVSE headers used by bindgen.

`libnvse/build.rs` removes `[[nodiscard]]` from the xNVSE header during builds. Do not commit submodule changes unless intentional.

## Architecture boundaries

| Area | Ownership |
|---|---|
| `psycho-engine-fixes` | Early-loaded core DLL; engine patches and shared state. |
| `psycho-engine-fixes-helper` | Thin xNVSE service/command forwarder. Must never load or initialize the core DLL. |
| `syringe` | Generic, mod-agnostic, `no_std` `dinput8.dll` proxy. Must stay independent of `libpsycho`. |
| `syringe-api` | Small callback ABI for early-loaded DLLs. |
| `omv` | xNVSE graphics plugin; owns its D3D9 stages, resources, shaders, and graphics tests. |
| `libpsycho` | Shared WinAPI, hooking, and logging abstractions. |
| `libnvse` | xNVSE bindings. |
| `libmimalloc` | CRT-only mimalloc build. |
| `libf4se` | Deprecated; do not extend without explicit request. |

Startup order: Syringe's pre-CRT barrier runs outside loader lock after xNVSE preload callbacks, loads the real `dinput8.dll` and `syringe/*.dll`, then calls all `Syringe_ModInit` callbacks followed by all `Syringe_ModActivate` callbacks. Core startup belongs there, not in `DllMain` or TLS. The non-blocking worker is compatibility fallback only. The core refuses activation if the pre-CRT barrier was not reached.

Engine behavior fixes belong in `psycho-engine-fixes`, not the helper. The helper may register xNVSE services and lazily forward through exact exports only when the core is already loaded.

Do not call WinAPI directly outside allocator hot paths. Use `libpsycho::os::windows::winapi`; add a safe wrapper when missing. Direct calls are allowed only where wrapper overhead is material per allocation.

## Subsystem gates

### OMV graphics

Before any OMV graphics implementation or material shader change, read and follow `omv/AGENTS.md`.

- Native PBR: also read `docs/graphics_fnv_pbr_errata.md`; do not repeat its prohibited patterns.
- Atmosphere startup/ownership: also read `docs/graphics_fnv_atmosphere_startup_crash_errata.md`. Never initialize or first-publish the focused world pipeline from `NVSEPlugin_Load`; publish staged config from `DeferredInit` before render hooks. Startup/config locks may block; render callbacks remain `try_lock`-only.

### gheap

Before changing `psycho-engine-fixes/src/mods/heap_replacer/gheap/`, read its local `AGENTS.md`. Its OOM recovery, zombie/UAF protection, and allocator hot-path performance constraints are all mandatory.

## Engine research

Use research only to close a material knowledge gap.

- `.research/` contains optional third-party source for comparison. Treat it as read-only. Never patch or build another mod as the fix; implement fixes in this repository and keep compatibility capability-based and version-agnostic.
- For native game behavior, current `.txt` output in `analysis/ghidra/output/` is authoritative. Ignore outdated `.md` prose under `analysis/` unless the user explicitly requests it.
- Before a crash or engine-contract patch, prove the failing function, caller ownership, layout, lifetime, and safe intervention point. If existing output cannot do so, prepare a focused script in `analysis/ghidra/scripts/` instead of guessing.
- Do not run Ghidra, `analyzeHeadless`, or `ghidraRun`. Ask the user to run the prepared script, then analyze its output.
- Before editing a Ghidra script, read `analysis/ghidra/scripts/SCRIPT_RULES.md` completely. Every rule is mandatory, including tabs-only indentation, no top-level loops or tuple unpacking, standard helpers, correct output directory, and `decomp.dispose()`.
- The user runs through Proton/Wine. Prefer static research, logs, crash reports, minidumps, and targeted telemetry; do not depend on native Windows debuggers.

Do not invoke Ghidra research for a straightforward repository-local change whose contract is already proven.

## Code and review standards

- Use simple, direct designs and clear names. Comments explain why, not what.
- Preserve local style; Rust uses edition 2024. Comments and docstrings must be ASCII.
- Prefer editing existing files and reusing existing abstractions.
- Never hide uncertainty. Distinguish code evidence, static proof, inference, and playtest results.
- Do not present disabling a feature, reducing supported coverage, or weakening a test as a fix.
- Avoid routine allocations, blocking locks, file I/O, shader compilation, and diagnostics in hot paths.

## Repository aids

- Runtime config: `psycho-engine-fixes/config/psycho_engine_fixes.toml`, deployed to `FalloutNV/syringe/psycho_engine_fixes.toml`. `memory.allocator`: `0` off, `1` scrap heap, `2` gheap plus scrap heap.
- Fresh symlinked logs under `psycho-engine-fixes/`: `psycho-engine-fixes-latest.log`, `CrashLogger.log`. Store supplied problem logs in `.reports/`.
- `build_fnv.sh`: build and install the complete FNV set, including OMV; edit `TARGET_DIR` first.
- `psycho-engine-fixes/build.sh`: compatibility wrapper for `../build_fnv.sh`.
- `psycho-engine-fixes/release.sh`: build and package releases in `.release/`.
- `psycho-engine-fixes/ln_logs.sh`: create game-log symlinks.

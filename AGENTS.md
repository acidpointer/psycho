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
4. Define the exact observable behavior that will accept the bug fix or feature. Do not add a source-code test unless it directly validates shipped HLSL shader behavior.
5. Make the smallest coherent change. Avoid opportunistic refactors and unrelated formatting.
6. Validate in layers: focused check, affected suite, then one release build when required.
7. Inspect the final diff for accidental changes. Report the outcome, evidence, and any remaining playtest need concisely.

Stop when the requested outcome is proven. Do not continue speculative cleanup or research.

## Agent efficiency

- Keep this root file limited to repository-wide policy. Nested `AGENTS.md`
  files contain only subtree-specific deltas and must not repeat inherited
  rules. Keep the root plus any nested instruction chain below 28 KiB so the
  most specific rules remain below Codex's default 32 KiB discovery limit.
- Add durable instructions only for repository facts, hard constraints, or a
  repeated demonstrated failure. Put long task-specific workflows in their
  owning document or focused skill and keep only the trigger here. Remove
  obsolete, redundant, and superseded guidance instead of appending exceptions.
- Start from the current diff and the smallest relevant code path. Use `rg` or
  `rg --files` to locate symbols/files, then read exact ranges. Do not scan the
  repository or dump long files when a targeted query can answer the question.
- Resolve unknowns in this order: relevant code and logs, durable `docs/`,
  existing analysis, then authoritative external research. Stop once the
  material unknown is closed; do not collect redundant corroboration.
- Batch independent searches and reads in one tool round trip when outputs stay
  reviewable. Use direct calls when one result changes the next decision or an
  approval, citation, or native artifact must be preserved. Reduce large
  mechanical result sets before returning them to the reasoning context.
- Read detailed plans, errata, generated output, or third-party sources only
  when a concrete task condition routes to them.
- Use a written plan only for multi-stage, high-risk, or unclear work. Keep it outcome-based and update it at milestones, not after every command.
- Do not repeat unchanged context in progress updates or final reports. Communicate at meaningful milestones.
- Do not rerun an unchanged expensive test or build. Run narrow checks while iterating and the required broad check once at the end.
- Prefer existing helpers, patterns, fixtures, and test infrastructure over new frameworks.
- Preserve a dirty worktree. User changes are not cleanup targets.
- Stop when the requested outcome and its acceptance gate are satisfied. Do not
  continue speculative cleanup, research, documentation, or validation.

## Definition of done

A change is done only when:

- the requested behavior is implemented without narrowing scope;
- the release gate below passes;
- applicable focused tests and the affected suite pass;
- the supported release target builds when code or build inputs changed;
- `git diff --check` passes and the diff contains no unintended edits;
- unsupported claims and unverified runtime behavior are identified honestly.

The release gate requires a behavioral test that precisely validates the
requested result. If such a test is technically impossible, it instead
requires complete, independently checkable correctness evidence and the user's
explicit strict approval. Models, unit tests, logs, builds, static contracts,
and plausible architecture do not substitute for behavior. Until the gate
passes, label the work an unaccepted candidate; do not release, package,
commit, call it complete, or present it as ready.

Documentation-only changes need document checks and diff inspection, not a
Rust build. Compilation never proves runtime or image correctness.

## Test creation prohibition

Do not add or rewrite tests for Rust, C/C++, native hooks, gameplay,
configuration, manifests, source/order text, binaries, or documentation.
Existing non-HLSL tests may only be run. New tests are allowed solely for
shipped `.hlsl` behavior: compilation, bytecode budgets, deterministic
reference images, or shader-output properties. Each must demonstrably reject a
real defect or protect a concrete shader contract; never add coverage,
implementation-mirroring, mocked-result, or process-only tests.

## Commit creation

Read `docs/commit-rules.md` completely immediately before any commit. Never
create or rewrite a commit unless the current user explicitly requests and
strictly approves that exact commit. Implementation, fix, finish, prepare,
package, release, stage, push, PR, and plan requests do not authorize commits.
This covers commit/amend, merge, fixup/squash, cherry-pick, rebase, and any
commit-creating API. One approval authorizes neither another commit nor an
amend. Otherwise stop after validation and report uncommitted changes.

## Build and test

The only supported target is 32-bit `i686-pc-windows-gnu` for FNV/xNVSE. Always write the target explicitly even though `.cargo/config.toml` currently selects it. Requires `i686-w64-mingw32-gcc`, the Rust target, and initialized submodules.

```bash
git submodule update --init --recursive
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv -p atom
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
| `atom` | ESP-less xNVSE gameplay overhaul; owns dynamic gameplay systems and its MCM Extender configuration. |
| `libpsycho` | Shared WinAPI, hooking, and logging abstractions. |
| `libnvse` | xNVSE bindings. |
| `libmimalloc` | CRT-only mimalloc build. |
| `libf4se` | Deprecated; do not extend without explicit request. |

Startup order: Syringe's pre-CRT barrier runs outside loader lock after xNVSE preload callbacks, loads the real `dinput8.dll` and `syringe/*.dll`, then calls all `Syringe_ModInit` callbacks followed by all `Syringe_ModActivate` callbacks. Core startup belongs there, not in `DllMain` or TLS. The non-blocking worker is compatibility fallback only. The core refuses activation if the pre-CRT barrier was not reached.

Engine behavior fixes belong in `psycho-engine-fixes`, not the helper. The helper may register xNVSE services and lazily forward through exact exports only when the core is already loaded.

Do not call WinAPI directly outside allocator hot paths. Use `libpsycho::os::windows::winapi`; add a safe wrapper when missing. Direct calls are allowed only where wrapper overhead is material per allocation.

## Subsystem gates

### Pre-DeferredInit startup compatibility

Before changing any final DLL's imports, TLS, static ownership, configuration
layout, startup callbacks, worker order, shared-library code generation, or
anything else reachable or loader-visible before xNVSE `DeferredInit`, read
`docs/nvse_startup_phase_safety.md` completely. Its BaseObjectSwapper crash
evidence and mod-agnostic response protocol are mandatory repository-wide, not
only for OMV.

Treat the last load-to-gameplay-playtested artifact as the startup baseline and
inspect the complete pre-Deferred footprint only when a concrete startup or
ABI risk makes that comparison necessary. A function
does not need to execute to change that footprint: PE imports, TLS callbacks,
static sections, CRT work, dependency features, configuration value layout,
and code moved between final DLLs all count. Static tests and a release build
cannot replace the required Proton load-to-gameplay playtest.

The observed third-party fault is never permission to detect, inspect, patch,
hook, reorder, disable, or add a compatibility path for another mod. Do not
redesign `libnvse`, `libpsycho`, or the core/helper boundary as a response.
Preserve requested features and restore only the new Psycho-side delta from
the accepted startup footprint.

### OMV graphics

Before OMV graphics or material work, read `omv/AGENTS.md`. Native PBR also
routes to `docs/graphics_fnv_pbr_errata.md`; startup, configuration, and hook
lifecycle work routes to `docs/graphics_fnv_atmosphere_startup_crash_errata.md`.
The nested file owns all OMV-specific implementation and acceptance rules.

### gheap

Before changing `psycho-engine-fixes/src/mods/heap_replacer/gheap/`, read its local `AGENTS.md`. Its OOM recovery, zombie/UAF protection, and allocator hot-path performance constraints are all mandatory.

### Native IO and SpeedTree

Before changing IOManager worker topology, per-thread task maps, BSFile recovery, exterior-cell loading, SpeedTree ownership/Compute, or static vertex-buffer safety, read `docs/parallel_io_engine_contract.md`. Reuse its proven ownership and concurrency contracts, and reconfirm its executable identity before reusing an address.

## Engine research

Use research only to close a material knowledge gap.

- Treat `.research/` as read-only comparison material; never patch/build another
  mod as the fix. Keep compatibility capability-based and version-agnostic.
- Search `docs/` and existing analysis before new native research. Reuse proven
  contracts for the same executable and reverify address-sensitive facts.
- Preserve authoritative `.txt` output in `analysis/ghidra/output/`; do not
  regenerate it or rely on outdated analysis Markdown unless requested.
- Use the radare2 MCP as the mandatory primary interface when callable, against
  `fnv_reverse/FalloutNV.exe`, and analyze only enough to close the contract.
- Ghidra is fallback-only when the MCP cannot be invoked. Use existing output
  first; otherwise prepare a focused script, never run Ghidra, and ask the user
  to return its output. Before scripting, read
  `analysis/ghidra/scripts/SCRIPT_RULES.md` completely.
- Before a crash or engine-contract patch, prove the failing function, caller ownership, layout, lifetime, concurrency, ABI, and safe intervention point. Distinguish direct binary or crash evidence from inference.
- The user runs through Proton/Wine. Prefer static research, logs, crash reports, minidumps, and targeted telemetry; do not depend on native Windows debuggers.

Do not invoke static engine research for a straightforward repository-local change whose contract is already proven.

## Feature documentation

Document only reusable architecture, engine contracts, configuration ownership,
or operational knowledge. Extend the owning `docs/` file; never write process
documentation for its own sake. Record purpose, behavior, ownership,
lifecycle/order, invariants, failure and performance costs, compatibility,
acceptance, and unresolved approval. Reverse-engineered documents additionally
record executable identity, addresses/call chain, layouts, lifetime/threading,
ABI, intervention point, evidence paths, and clearly separate proof,
inference, and observation. Link raw analysis instead of duplicating dumps.

Do not put DLL hashes, binary sizes, section/import/TLS inventories, routine
test counts, command transcripts, transient candidate chronology, or other
build trivia in developer documentation. Do not hash, inspect, or compare DLL
contents by default. Binary identity or layout work is allowed only when a
specific, evidence-backed problem actually depends on artifact identity,
startup footprint, ABI, imports, TLS, or section layout, or when the user
explicitly requests it. Report only the minimum result needed for that problem.

## Code and review standards

- Write production-deployable code: correct, safe, maintainable, performant,
  and complete. Preserve local style; Rust uses edition 2024. Comments and
  documentation must be ASCII.
- Prefer safe, idiomatic Rust. Keep `unsafe` code in the smallest auditable
  boundary; document its safety contract and prove pointer validity, ABI,
  alignment, lifetime, aliasing, initialization, and thread assumptions that
  apply. Never use `unsafe` to bypass a sound ownership design.
- Handle failure explicitly and preserve valid state. Do not panic or unwind
  across FFI; validate external data, engine state, arithmetic, and conversions;
  use RAII and ownership-aware rollback for partial work. An unchecked
  operation, `unwrap`, or `expect` in production needs a locally proven
  invariant and a comment explaining why recovery is impossible or incorrect.
- Give each module one cohesive responsibility and explicit dependency
  direction. Separate policy from mechanism, engine/FFI access from safe
  domain logic, and hot paths from setup and diagnostics. Reuse an existing
  abstraction when it fits; introduce one only for a concrete invariant or
  demonstrated reuse, not hypothetical flexibility.
- Every production module requires clear module-level technical documentation
  covering purpose, ownership, key invariants, lifecycle, failure behavior,
  and performance constraints as applicable. Every public API requires a
  precise docstring covering behavior and, where relevant, inputs, outputs,
  errors, side effects, safety, threading, lifetime, and panic conditions.
- Comment every complex or non-obvious decision, especially ownership,
  synchronization, fallback, numerical, ABI, and performance tradeoffs.
  Explain why the design is necessary; do not narrate obvious statements.
- Keep functions and types focused, names explicit, invariants local, and
  failure paths deterministic. Avoid duplicated policy, hidden global state,
  broad mutable ownership, speculative frameworks, and unrelated refactors.
- Treat architecture, safety, and performance as design inputs before coding.
  For cross-module or engine-facing changes, identify ownership, lifecycle,
  concurrency, failure containment, and hot-path cost before implementation.
- Do not write new source-code tests except practical tests that directly
  validate shipped `.hlsl` shaders. Never test implementation source text,
  textual call order, symbol-name presence, manifest contents, mocked native
  behavior, or a model that cannot reproduce the reported defect.
- Rust DLLs must use `libpsycho::logger::Logger` and the `log` facade for diagnostics. Do not use `println!`, `eprintln!`, or subsystem-owned file writes for logs, reports, or telemetry; route requested summaries through the established logger. Initialize logging only at the subsystem's documented safe lifecycle boundary.
- Write logs for a human reader and include a stable subsystem tag. Use `debug` for technical detail such as validated addresses, `info` for normal lifecycle/configuration milestones and user-requested summaries, `warn` for recoverable degradation with the resulting fallback, and `error` when a requested capability cannot remain available or correctness is lost. State the consequence, not only the low-level failure.
- Keep every visible MCM Extender text value laconic: one to three words, including titles, descriptions, help text, status text, and choices. Review shipped menus directly; do not add a non-HLSL artifact test.
- MCM Extender-backed settings must apply from `MCMExtUpdate` after its INI save. Native listeners must define the published event parameter contract before handler admission and tolerate an already-defined event; do not poll pause state or parse configuration every frame.
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

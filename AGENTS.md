# Agent operating guide

Use this file for repository-wide rules. Before editing a subtree, also read its nearest `AGENTS.md`. Keep work evidence-driven, scoped, and economical.

## Agent skill

Task routing, playbooks, environment discovery, and the documentation index live
in `.agents/skills/psycho/`. Load `psycho` (`$psycho` in Codex, `/psycho` in
Claude Code, `@psycho` in OpenCode), or read its `SKILL.md` directly.
`CLAUDE.md` imports this file, and `.claude/skills/psycho` links the skill.
`AGENTS.md` remains authoritative.

## Priorities

In order:

1. Correctness and user safety.
2. Preserve requested behavior and existing user changes.
3. Prove the result with the smallest sufficient validation.
4. Minimize implementation time, runtime cost, and agent context.

Do not trade correctness for speed. Do not add process, diagnostics, or abstraction without a concrete need.

## Default workflow

1. State the outcome, files, invariants, and constraints.
2. Inspect only relevant code, tests, docs, and `git status`; use `rg`, batch reads.
3. Resolve every material unknown from direct evidence. Never assume; if
   inspection cannot prove it, stop and ask for the evidence or decision.
4. Define the behavioral acceptance test. For troubleshooting, run it against the
   unchanged behavior and record the failure before research or edits.
5. Research the proven failing path; make the smallest coherent change. Avoid
   opportunistic refactors and unrelated formatting.
6. Run the same test and validate in layers: focused check, affected suite, one
   release build when required.
7. Inspect the final diff and report outcome, evidence, and remaining gate.

Stop when the outcome is proven. Do not continue speculative cleanup or research.

## Agent efficiency

- Keep this root file to repository-wide policy. Nested `AGENTS.md` files contain
  only subtree deltas. Keep the root plus nested chain below 28 KiB.
- Add durable instructions only for repository facts, hard constraints, or a
  repeated demonstrated failure. Put long workflows in the owning document or
  the `psycho` skill. Remove superseded guidance.
- Start from the current diff and smallest code path. Use `rg`/`rg --files`, then
  read exact ranges. Never dump long files. For source search, skip `target/`,
  `node_modules/`, `.reports/`, `.research/`, and `fnv_reverse/`.
- Resolve unknowns in order: relevant code and logs, `docs/`, existing analysis,
  then authoritative external research. Stop when the material unknown is closed.
- Batch independent searches and reads; use direct calls when a result changes
  the next decision or an artifact must be preserved. Reduce large result sets.
- Read plans, errata, generated output, or third-party source only when a task
  condition routes to them.
- Use a written plan only for multi-stage, high-risk, or unclear work. Keep it
  outcome-based and update at milestones.
- Do not repeat unchanged context. Do not rerun an unchanged expensive test or
  build. Prefer existing helpers, fixtures, and test infrastructure.
- Preserve a dirty worktree. Stop when the outcome and acceptance gate are
  satisfied; do not continue speculative cleanup, research, or validation.

## Definition of done

A change is done only when the requested behavior is implemented without
narrowing scope; the release gate, focused tests, and affected suite pass; the
supported 32-bit release build succeeds when code or build inputs changed;
`git diff --check` passes; the diff has no unintended edits; and unverified
runtime behavior is reported honestly.

Except for the OMV exception, the behavioral gate has no static-evidence
exception. If the exact behavior cannot be tested, implementation is blocked.
Do not release, package, commit, or call it ready before the gate passes.
Documentation-only changes need document checks and diff review, not a Rust
build. Compilation never proves runtime or image correctness.

## No guessing and behavioral-test gate

Guessing is forbidden in every task. Never derive a cause, path, contract,
value, oracle, expected result, or implementation from assumption, resemblance,
analogy, likelihood, a stand-in, a synthetic proxy, or unverified inference.
Every material decision needs an explicit requirement or direct evidence from
actual behavior, executed code/data, an authoritative source, or a verified
binary. Unknown means stop: inspect it or request the evidence.

A behavioral test executes the actual shipped path and observes the requested
result at its real boundary. Models, mocks, source assertions, reimplemented
references, synthetic lookalikes, compilation, logs, builds, bytecode, and
static contracts do not substitute. Visual tests use the affected assets,
materials, passes, state, order, and composition. Performance tests use the
same workload and settings against an explicit metric. Startup, gameplay,
native-hook, and engine behavior runs through the real runtime.

Define expectations and the test before implementation; completion requires
every expected behavior. For troubleshooting, run it against the unchanged
defect and preserve the failure before research. Fix only the proven path; the
same test must pass after. No reproduction or authorized environment means
stop, with no production edit. Test-only instrumentation may expose the
boundary but must not alter behavior.

Add or rewrite tests only when behavioral, or as essential support beside an
established behavioral test. Never add coverage-only, mirrored, mocked,
source/order, symbol/manifest, or process tests.

### Explicit OMV no-game-runtime exception

For `omv` only, a local game run is not an implementation, qualification,
handoff, release, packaging, or commit gate. The owner alone decides whether and
when to playtest. Do not request, require, schedule, or wait for it. This
overrides the real-runtime, fail-first, same-test, and no-production-edit
requirements for OMV work.

Before editing, establish an offline behavioral test wherever the shipped
behavior can execute outside the game. Exercise the actual production Rust or
compiled HLSL path with evidence-backed inputs and fail it on the unchanged
defect before production edits. Do not substitute a mock, mirrored formula,
reconstructed shader, source assertion, compilation, or static contract for
behavior that can execute offline. When game-only composition or integration
cannot execute, use the owner's report as the behavioral requirement and prove
every decision from direct source, binary, and engine evidence. No guessing.

Qualify with applicable offline regressions, all production shader variants and
budgets, the affected crate suite, supported 32-bit release build, formatting,
`git diff --check`, and final diff review. Compare deterministic work budgets
and executable benchmarks where available; never convert them into an FPS
claim. Report offline qualification and identify game-only image, integration,
and performance behavior as not run.

### Explicit reporter-only Psycho engine-fix exception

For `psycho-engine-fixes` only, an explicit user authorization may permit an
unreleased defensive candidate for a supplied real-runtime report when neither
the reporter's workload nor a local reproduction is available. Read
`docs/psycho_engine_fix_exception.md` completely before using it. It overrides
only the fail-first, same-test, and no-production-edit rules for that incident;
all other rules remain.

## Commit creation

Read `docs/commit-rules.md` completely immediately before any commit. Never
create or rewrite a commit unless the current user explicitly requests and
strictly approves that exact commit. Implementation, fix, finish, prepare,
package, release, stage, push, PR, and plan requests do not authorize commits.
This covers commit/amend, merge, fixup/squash, cherry-pick, rebase, and any
commit-creating API. One approval authorizes neither another commit nor an
amend. Otherwise stop after validation and report uncommitted changes.

## Build and test

The only supported target is 32-bit `i686-pc-windows-gnu`; always pass it
explicitly. It requires `i686-w64-mingw32-gcc`, the Rust target, and initialized
submodules.

```bash
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv -p atom
cargo test --target i686-pc-windows-gnu -p <crate>
```

Cargo runs Windows tests through Wine. Use the narrowest test filter while
iterating, then the affected suite and release build once. See
`.agents/skills/psycho/references/validation.md` for filters, ignored
benchmarks, GPU/Wine, formatting, and packaging.

Submodules: `libmimalloc/c_src/mimalloc` (upstream mimalloc C source) and
`libnvse/xnvse` (xNVSE headers used by bindgen). `libnvse/build.rs` removes
`[[nodiscard]]` during builds. Do not commit submodule changes unless intended.

## Architecture boundaries

Crate ownership and startup order are in
`.agents/skills/psycho/references/repo-map.md`. The key boundaries:

- `syringe` is generic, `no_std`, and independent of `libpsycho`.
- `psycho-engine-fixes` owns engine behavior and shared state.
- `psycho-engine-fixes-helper` never loads or initializes the core.
- `omv` and `atom` own their graphics and gameplay systems.
- `libf4se` is deprecated; do not extend it.

Core startup belongs in Syringe's pre-CRT barrier, not `DllMain` or TLS; the
core refuses activation without that barrier. The helper may register xNVSE
services and lazily forward exact exports only when the core is already loaded.

Do not call WinAPI directly outside allocator hot paths. Use
`libpsycho::os::windows::winapi`; add a safe wrapper when missing. Direct calls
are allowed only where wrapper overhead is material per allocation.

## Subsystem gates

- **Startup**: before changing loader-visible imports, TLS, statics, config
  layout, workers, callbacks, or shared-library codegen, read
  `docs/nvse_startup_phase_safety.md` completely. It is repository-wide. Outside
  the OMV exception, a Proton load-to-gameplay playtest is required. Never
  detect, patch, hook, reorder, or add a compatibility path for another mod.
- **OMV graphics**: read `omv/AGENTS.md`. PBR also reads
  `docs/graphics_fnv_pbr_errata.md`; startup/config/hooks also read
  `docs/graphics_fnv_atmosphere_startup_crash_errata.md`.
- **gheap**: read `psycho-engine-fixes/src/mods/heap_replacer/gheap/AGENTS.md`.
- **Native IO/SpeedTree**: read `docs/parallel_io_engine_contract.md` and
  reconfirm executable identity before reusing an address.

## Engine research

Use research only to close a material knowledge gap.

- If `.research/` exists, treat it as read-only comparison material; never patch
  or build another mod. Keep compatibility capability-based and version-agnostic.
- Search `docs/` and existing analysis first. Reuse proven contracts for the same
  executable; reverify address-sensitive facts.
- Preserve authoritative `.txt` output in `analysis/radare2/output/` or
  `analysis/ghidra/output/`; do not regenerate it or rely on outdated Markdown.
- radare2 is the primary interface. Use r2mcp when the host exposes it; otherwise
  use the r2 CLI (`pdg` for decompilation, `pdf` for exact disassembly, `aar`
  before `axt`). Target the configured or discovered supported executable;
  `fnv_reverse/FalloutNV.exe` is only a convenience default.
- Ghidra is fallback-only. Use existing output first; otherwise prepare a
  focused script, never run Ghidra, and ask the user to return its output. Read
  `analysis/ghidra/scripts/SCRIPT_RULES.md` completely before scripting.
- Before a crash or engine-contract patch, prove the failing function, caller
  ownership, layout, lifetime, concurrency, ABI, and safe intervention point.
  Inference is not patch authority; unresolved facts stay unknown.
- Prefer static research, logs, crash reports, minidumps, and targeted telemetry.
  Do not depend on native Windows debuggers.

Do not invoke static engine research for a local change whose contract is proven.

## Feature documentation

Document reusable architecture, engine contracts, configuration ownership, or
operational knowledge. Extend the owning `docs/` file; do not create process
documentation for its own sake. Record purpose, behavior, ownership,
lifecycle/order, invariants, failure and performance costs, compatibility,
acceptance, and unresolved approval. Reverse-engineered documents also record
executable identity, addresses/call chain, layouts, lifetime/threading, ABI,
intervention point, evidence paths, and separate proof from observation and
unknowns. Link raw analysis instead of duplicating dumps.

Do not put DLL hashes, binary sizes, section/import/TLS inventories, routine test
counts, command transcripts, transient candidate chronology, or build trivia in
developer documentation. Do not hash or inspect DLLs by default. Binary identity
or layout work is allowed only when a specific problem depends on artifact
identity, startup footprint, ABI, imports, TLS, or section layout, or the user
asks. Report only the minimum result needed.

## Code and review standards

- Production-deployable code: correct, safe, maintainable, performant, complete.
  Preserve local style; Rust edition 2024; comments and docs ASCII.
- Prefer safe Rust. Keep `unsafe` in the smallest boundary and prove pointer
  validity, ABI, alignment, lifetime, aliasing, initialization, and threading.
- Handle failure explicitly; no panic or unwind across FFI. Validate external
  data, arithmetic, and conversions. Use RAII and rollback for partial work.
  Production `unwrap`/`expect` needs a proven invariant and a comment.
- One responsibility per module; explicit dependency direction; policy separate
  from mechanism; hot paths separate from setup and diagnostics.
- Document each module (purpose, ownership, invariants, lifecycle, failure,
  performance) and each public API. Comment non-obvious ownership,
  synchronization, ABI, numerical, and performance decisions.
- Tests follow the behavioral gate. Never test source text, call order, symbol
  presence, manifests, mocks, or a model that cannot reproduce the defect.
- Rust DLLs use `Logger` and `log`; no `println!`/`eprintln!` or subsystem file
  writes. Initialize logging only at the safe lifecycle boundary. Use stable
  subsystem tags and state the consequence.
- MCM Extender text is one to three words; review shipped menus directly.
  Settings apply from `MCMExtUpdate` after its INI save; native listeners define
  the event parameter contract and tolerate an already-defined event. Do not poll
  pause or parse config every frame.
- Never hide uncertainty. Do not present disabling a feature, reducing coverage,
  or weakening a test as a fix. Avoid routine hot-path allocation, blocking
  locks, file I/O, shader compilation, and diagnostics.
- See: `.agents/skills/psycho/references/contracts.md`.

## Repository aids

- Runtime config: `psycho-engine-fixes/config/psycho_engine_fixes.toml`,
  deployed to `syringe/psycho_engine_fixes.toml` under the game root.
  `memory.allocator`: `0` off, `1` scrap heap, `2` gheap plus scrap heap.
- Logs: `psycho-engine-fixes-latest.log`, `CrashLogger.log`, `omv-latest.log`,
  `atom-latest.log`. Paths vary. Use `psycho_env.py` or `PSYCHO_*`; never assume
  a developer path.
- Supplied logs: `PSYCHO_REPORTS_DIR` or `.reports/` when present.
- `.research/` and `fnv_reverse/` are optional, gitignored inputs.
- **User-only deployment:** `build_fnv.sh`, `build.sh`, `release.sh`,
  packaging, and installation are run only by the user. Agents must never run
  them or deploy artifacts. Agents build and test locally only.
- `ln_logs.sh` creates optional log symlinks; agents must not run it.

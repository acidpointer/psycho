---
name: psycho
description: Use for work in the Psycho Fallout New Vegas repository - engine fixes, OMV graphics, Atom gameplay, libpsycho hooks/WinAPI, crash triage, radare2/Ghidra reverse engineering, config/MCM/dashboard changes, tests, local builds, and docs. Use when locating the game, logs, reports, or analysis evidence, or when deciding which contract document and validation gate apply.
compatibility: Requires git. Build work requires cargo, the i686-pc-windows-gnu Rust target, i686-w64-mingw32-gcc, and Wine. Reverse engineering prefers radare2; r2mcp is optional and never required.
metadata:
  version: "1"
---

# Psycho repository workflow

`AGENTS.md` is authoritative. This skill is the routing and procedure layer. It
does not replace repository policy, contract documents, or the behavioral gate.

Repository paths below are relative to the repository root.

## Invocation

- Codex: `$psycho`
- Claude Code: `/psycho`
- OpenCode and other Agent Skills hosts: automatic, or `@psycho`
- Host without skill support: read this file directly.

## Start every non-trivial task

1. Run `git status --short` and `git diff --stat`. Preserve dirty work. Do not
   commit unless the user explicitly approves that exact commit.
2. If a game, log, report, binary, radare2, or analysis path is needed, run
   `python3 .agents/skills/psycho/scripts/psycho_env.py --json`. Never hardcode
   a developer-specific path.
3. Classify the task with the routing table below. If two rows apply, read both
   owning documents.
4. Read only the owning `docs/` file, the target module's `//!` header, and the
   exact functions. Use `rg` to find them; do not dump large files.
5. State the behavioral acceptance test or observable before editing. For an
   executable defect, run the unchanged path and record the failure first.
6. Make the smallest coherent change. Do not refactor unrelated code.
7. Validate in layers: focused check, affected suite, formatting, release build
   when required, `git diff --check`, final diff review.
8. Update the owning document and report what was not run.

## Routing

| Task | Read first | Edit |
|---|---|---|
| Core startup/lifecycle | `docs/nvse_startup_phase_safety.md`; `psycho-engine-fixes/src/{entry,startup,events}.rs` | entry, startup, events |
| New engine fix/hook | owning `docs/crash_*.md` or contract; `mods/engine_fixes/{mod,statics,types,patching}.rs` | new module, install, config, dashboard |
| Performance hook | `docs/fnv_location_performance_static_audit.md`; `mods/perf` | module, signatures, tests |
| Allocator/gheap | `psycho-engine-fixes/src/mods/heap_replacer/gheap/AGENTS.md`; `docs/gheap_large_modlist_compatibility.md` | `heap_replacer/*` |
| IO/LOD | `docs/parallel_io_engine_contract.md`; `docs/lod_streaming_handoff_engine_fix_plan.md` | `engine_fixes/{io,lod}` |
| Save | `docs/save_integrity.md` | `save_integrity.rs` |
| zlib | `docs/zlib_stream_ownership.md` | `mods/zlib` |
| Config/dashboard | `docs/psycho_dashboard.md`; `config.rs`; helper `dashboard_config.rs` | core config, TOML, helper, ABI mirror |
| OMV startup | `docs/nvse_startup_phase_safety.md`; `docs/graphics_fnv_atmosphere_startup_crash_errata.md`; `omv/src/startup.rs` | startup, nvse_plugin, runtime, hooks |
| OMV effect | owning `docs/graphics_fnv_*.md`; `omv/src/effects/<name>.rs`; shaders | effect, shader, tests, config |
| OMV PBR | `docs/graphics_fnv_pbr_errata.md`; `docs/graphics_fnv_pbr_contract_map.md` | `effects/pbr/*` |
| OMV depth | `docs/graphics_fnv_depth_resolve.md`; `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md`; `docs/graphics_fnv_portable_depth_transport.md` | `backend/fnv/*` |
| Atom | `docs/atom.md` plus the owning contract; `atom/src` | subsystem and MCM |
| libpsycho | module docs under `libpsycho/src` | `libpsycho/*` |
| Release | `.github/scripts/package_release.sh`; release workflow | User-only; agents do not run deployment |

The full documentation index is `docs/README.md`. The curated authority map is
[`references/docs-map.md`](references/docs-map.md).

## Optional inputs

`.reports/`, `.research/`, `fnv_reverse/`, the game directory, the supported
executable, and every log path are optional in a clone. Use
`.psycho.local.toml` or `PSYCHO_*` environment variables. Precedence is
environment, local config, bounded discovery, then ask the user.

If a path is missing, ask for it. Do not infer a game directory, log path, or
binary identity. A discovered executable with an unexpected hash is not the
documented supported binary.

See [`references/environment.md`](references/environment.md).

## Reverse engineering

Radare2 is the primary interface. Use r2mcp tools when the host exposes them;
otherwise use the r2 CLI. Existing evidence under `docs/` and
`analysis/radare2/output/` is read before new research.

```bash
python3 .agents/skills/psycho/scripts/r2q.py info
python3 .agents/skills/psycho/scripts/r2q.py func 0x00567D20 --decomp
python3 .agents/skills/psycho/scripts/r2q.py callers 0x00567D20
python3 .agents/skills/psycho/scripts/r2q.py bytes 0x00567D20 16
python3 .agents/skills/psycho/scripts/r2q.py string AddOcclusionPlane
python3 .agents/skills/psycho/scripts/r2q.py rtti 0x0102CBBC
```

r2mcp is optional. When it is available, set its decompiler to `pdg`; its
default `pdc` backend is experimental and unreliable. Decompiler output is a
hypothesis. Disassembly, exact bytes, caller coverage, and runtime signature
checks are the authority.

See [`references/reverse-engineering.md`](references/reverse-engineering.md).

## Non-negotiables

- Unknown means stop and inspect or ask. Never fill a gap with inference.
- Behavioral tests execute the shipped path. Models, mocks, source-text checks,
  and compilation are not behavioral evidence.
- Preserve the frozen pre-`DeferredInit` footprint. Read the startup contract
  before changing loader-visible work.
- Hot paths get no routine allocation, file I/O, shader compilation, blocking
  locks, or per-draw logging.
- Use `libpsycho` WinAPI wrappers and keep `unsafe` boundaries small and
  documented.
- Valid inputs chain existing providers unchanged. Reject only proven-invalid
  input.
- Deployment is user-only. Never run `build_fnv.sh`, `build.sh`, `release.sh`,
  packaging, installation, or log-link helpers.
- Never commit, amend, release, or package without explicit approval.

## Validation ladder

```bash
cargo test --target i686-pc-windows-gnu -p <crate>
cargo build --release --target i686-pc-windows-gnu -p <crate>
cargo fmt -p <crate> -- --check
git diff --check
```

Use the narrowest test filter while iterating. Run the affected crate suite and
the supported release build once at the end when code or build inputs changed.
Documentation-only changes need a link/status check and diff inspection, not a
Rust build.

See [`references/validation.md`](references/validation.md).

## Report

Report the outcome, files changed, behavioral evidence, commands run, remaining
unknown or runtime-only behavior, and whether changes are uncommitted. Do not
claim runtime, image, performance, or startup acceptance that was not executed.

## References

Load only what the task needs:

- [`references/repo-map.md`](references/repo-map.md) - crate/file ownership,
  startup order, key APIs, and search hygiene.
- [`references/docs-map.md`](references/docs-map.md) - authority chains and
  when to read each area.
- [`references/playbooks.md`](references/playbooks.md) - feature and fix
  recipes by subsystem.
- [`references/validation.md`](references/validation.md) - commands, test
  selection, GPU/Wine, local builds, and reporting.
- [`references/troubleshooting.md`](references/troubleshooting.md) - log
  triage, symptom routing, and common failure modes.
- [`references/reverse-engineering.md`](references/reverse-engineering.md) -
  radare2 CLI/MCP workflow, evidence, and address hygiene.
- [`references/environment.md`](references/environment.md) - local paths,
  optional directories, logs, and discovery.
- [`references/contracts.md`](references/contracts.md) - hooks, config, MCM,
  dashboard ABI, D3D9 state, shaders, logging, and doc templates.
- [`templates/`](templates/) - contract, crash post-mortem, and research
  templates.
- [`scripts/`](scripts/) - environment discovery, radare2 queries, and checks.

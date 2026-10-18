# Playbooks

Each playbook is a checklist, not a substitute for the owning contract or the
behavioral gate.

## New core engine fix or hook

Read the incident/contract first. Do not start from a hook address.

1. Prove the failing native path and the safe intervention point. Record
   callers, layout, lifetime, ABI, concurrency, and valid-input behavior.
2. Add the module under `psycho-engine-fixes/src/mods/engine_fixes/`.
   - Module `//!` header: purpose, ownership, lifecycle, failure behavior,
     hot-path cost, owning document.
   - Native signatures in `types.rs`.
   - Hook containers and addresses in `statics.rs`.
   - Fingerprint/patch helpers in `patching.rs` or the module.
3. Use `ModificationTransaction` for a related set of hooks and patches.
   Prepare every fallible step before enabling a transaction owner.
4. Chain the predecessor/provider already installed at the boundary. Reject
   only proven-invalid input. Valid inputs must preserve native behavior.
5. Add the config switch in `config.rs`, the raw/migration parser, defaults,
   validation, and the commented TOML.
6. Add the install call in `mods/engine_fixes/mod.rs` and startup only when the
   phase is correct.
7. Add a dashboard feature bit and counters when the helper should expose the
   state. Mirror the ABI exactly.
8. Add focused behavioral tests for the production helper/decision path.
9. Run the affected crate suite, release build, formatting, and diff check.
10. Update the owning document with evidence, status, and unresolved facts.

## Performance hook

1. Read `docs/fnv_location_performance_static_audit.md` and the owning section.
2. Prove the exact native loop or consumer and its ownership. Do not broaden a
   patch beyond the verified body.
3. Add the module under `mods/perf/` with exact signatures in
   `lighting_signatures/` or `scene_signatures/` when required.
4. Keep integer/FPU state, native order, and fallback behavior unchanged.
5. Establish a deterministic work-budget or executable offline test.
6. Run the focused tests and the crate suite.
7. Report the measured work change, not an FPS claim.

## OMV effect change

1. Read the owning `docs/graphics_fnv_*.md` and `omv/AGENTS.md`.
2. Prove the native phase, resource, target, sampler, and state ownership.
3. Implement the effect in `omv/src/effects/<name>.rs`.
   - Preparation is process-owned and off the render callback.
   - Render callbacks create only device objects from published bytecode.
   - Restore every touched D3D state through the owning transaction.
4. Compile every production entry point, macro family, quality tier, depth
   mode, and feature combination.
5. Add or extend the offline D3D9 image/reference test for the affected path.
6. Enforce compiled instruction, texture-op, sampler, flow-control, and
   prohibited-opcode budgets per variant.
7. Add config, preset, diagnostics, and menu wiring only where the contract
   requires it.
8. Run the OMV suite and release build. Report image/gameplay behavior as not
   run under the OMV exception.

## OMV shader change

1. Identify the exact production shader entry and variant family.
2. Compile all variants before judging the change.
3. Check shader-model, instruction, texture, sampler, flow-control, and
   prohibited-opcode budgets.
4. Use a deterministic offline image oracle with the affected inputs and
   composition. Compilation alone is not image proof.
5. Handle reversed/standard depth, clear/sky endpoints, invalid samples,
   quantization, near/far limits, half-pixel mapping, and texel centers
   explicitly.
6. Do not use derivatives after divergent control flow or clipping without
   seam-free proof.
7. Preserve accepted equations, filters, temporal behavior, and composition
   unless the change proves equal or better quality.
8. Keep disabled variants free of hidden work.

## New Atom feature

1. Read `docs/atom.md` and the owning feature contract.
2. MCM Extender remains the only INI writer. Atom reads the file into an
   immutable snapshot and applies from `MCMExtUpdate` after the save.
3. Add the setting to `atom/mcm/Atom.json` and the subsystem parser. Keep the
   native default and JSON default equal; keep persisted keys unique.
4. Keep every visible MCM string to one to three words.
5. Install native hooks at the documented deferred boundary. Valid inputs must
   pass through or chain the current owner unchanged.
6. Publish a coherent snapshot; do not mix settings within one frame or event.
7. Add public behavioral tests under `atom/tests/` or the subsystem module.
8. Run Atom tests, release build, formatting, and diff check.
9. Update `docs/atom.md` and the feature contract.

## Config, MCM, or dashboard setting

Touch all applicable layers:

1. Core `psycho-engine-fixes/src/config.rs`: default, raw field, migration,
   validation, and public getter.
2. `psycho-engine-fixes/config/psycho_engine_fixes.toml`: commented user-facing
   entry.
3. `psycho-engine-fixes-helper/src/dashboard_config.rs`: read/write mapping.
4. Dashboard UI and help text: state the practical effect and tradeoff.
5. Feature installer and diagnostics: consume the published value, do not
   re-parse the file.
6. Tests: defaults, migration, invalid values, dashboard round-trip.
7. Owning document: schema ownership and restart/live behavior.

MCM Extender settings additionally require `atom/mcm/Atom.json`, the subsystem
parser, default equality, unique keys, and the one-to-three-word text rule.

## Helper/core ABI change

1. Change the core `command_api.rs` structure or command ID.
2. Bump `DASHBOARD_ABI_VERSION` when the published layout changes.
3. Preserve the published prefix; append new fields at the end.
4. Mirror the exact layout and constants in
   `psycho-engine-fixes-helper/src/engine_fixes.rs`.
5. Reject mismatched size or version as unavailable.
6. Keep all crossing fields fixed-width scalars. No Rust allocation, pointer,
   enum, or `String` crosses the DLL boundary.
7. Test the mirror and size/version rejection.
8. Update `docs/psycho_dashboard.md`.

## Crash containment

1. Read the complete crash report and the relevant contract.
2. Prove the faulting consumer, invalid input contract, caller coverage, ABI,
   and a fail-closed result callers already tolerate.
3. Contain at the narrowest shared boundary. Do not identify or patch another
   mod.
4. Preserve valid inputs and the installed provider chain unchanged.
5. Add the focused regression for the production decision path.
6. Add counters/dashboard state only when they help support diagnostics.
7. Update the incident document with evidence and unresolved attribution.
8. Run the affected suite and release build.

## Research-only investigation

1. State the exact question and the decision it will unblock.
2. Search existing docs and analysis first.
3. Record binary identity and exact evidence paths.
4. Use radare2 or existing Ghidra output; do not write production code.
5. Separate proven facts, observations, and unresolved unknowns.
6. Mark the document as research/feasibility, not implementation.
7. Stop when the question is answered. Do not collect redundant corroboration.

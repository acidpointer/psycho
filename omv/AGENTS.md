# OMV graphics rules

These rules apply to all files under `omv/`. They extend the repository root rules. For graphics work, quality and performance are independent release gates: both must pass.

The root commit-creation prohibition applies here without exception.
`docs/commit-rules.md` remains mandatory, and no OMV change may be committed or
amended without the user's explicit request and strict approval for that
commit.

The ambient-occlusion suite in `src/effects/ambient_occlusion.rs` is the minimum pattern for shader compilation, bytecode inspection, deterministic reference rendering, regression power, and static work budgets. Reuse its infrastructure; never weaken or bypass it to land a change.

## BaseObjectSwapper-sensitive startup contract

Read `docs/nvse_startup_phase_safety.md` and
`docs/graphics_fnv_atmosphere_startup_crash_errata.md` completely before
changing startup, configuration, presets, process-owned preparation, hooks,
global storage, TLS, or any state first accessed before `DeferredInit`. The
first document owns the exact external crash mechanism, attribution boundary,
mod-agnostic response, and repository-wide review protocol. The erratum owns
OMV's incident history and local source-order contract. The latest
load-to-gameplay-playtested baseline must be identified from them before
editing; commit `9975b2e` is the baseline established by the 2026-08-10
motion-blur correction. A later documented and playtested baseline supersedes
it.

Treat everything reachable from `NVSEPlugin_Load`, including background work
it starts, as one compatibility-sensitive footprint. Before implementation,
diff that footprint against the playtested baseline and list every change in:

- config structs nested in `PsychoGraphicsConfig`, `GraphicsMenuConfig`,
  `RuntimeSettings`, or deferred settings, including Rust size/layout changes;
- `CONFIG_SCHEMA_VERSION`, shipped TOML shape, frozen preset manifests,
  migrations, built-in preset version/payload, parsing, validation, and save
  behavior;
- `LazyLock`/`OnceLock` first access, mutex creation or acquisition, TLS and TLS
  destructors, static constructors/destructors, thread creation, worker start
  order, filesystem scans, DLL loads, and allocation-heavy work;
- atomics or mailboxes that publish engine ownership, scene requirements, route
  readiness, hook admission, or configuration generations;
- the order of staging, provider selection, first world publication, and hook
  installation.

The current invariants are mandatory:

- `NVSEPlugin_Load` may parse/copy configuration and perform only the exact
  process-owned preparation already present in the playtested baseline. A new
  operation is not safe merely because it is CPU-only, off-thread, atomic, or
  does not call D3D.
- The focused world owner must remain untouched until `DeferredInit`.
  `apply_initial_depth_activation` is the config-to-hook handoff; first world
  publication follows there, before the resident hooks become reachable.
- A new engine-facing callback route or hook admission is initialized false,
  is not published by `ScreenShaderRuntime::configure`, opens only at the
  deferred handoff, and is cleared if deferred installation fails.
- Existing scene-requirement publication and process-owned shader/effect
  preparation retain their accepted phase and order unless the user explicitly
  requests a separately researched startup redesign.
- OMV config and presets remain schema 1. Deprecated fields remain in their
  original serialized position and round-trip unchanged. Motion blur's
  `first_person_strength` is the canonical pattern: keep it in Rust, shipped
  TOML, saves, and presets; omit it from active menu metadata, render settings,
  temporal identity, constants, and HLSL.
- Do not add `thread_local!`, a TLS destructor, or a new pre-deferred
  `LazyLock`/`OnceLock` first touch for render state. Prefer zero-initialized
  POD/atomics whose operational access begins after the deferred handoff.
- Never disable, remove, or postpone a requested effect or an established
  worker as a startup-crash fix. Preserve the work and surgically remove the
  new load-time owner, layout, migration, or publication that differs from the
  playtested baseline.

For a crash before `[INIT] Deferred OMV graphics hooks initialized`, the render
implementation is outside the executed call graph. Do not investigate shader
math, D3D state, render phase, depth resolution, RESZ, or GPU-vendor policy
until every new pre-deferred delta has been eliminated or proven. Treat
BaseObjectSwapper as the observed UB-sensitive fault site, not as permission to
patch it, blame it alone, or claim OMV directly corrupted its memory.

Every change to this footprint must add or retain source-order tests that reject
early world publication/hook admission, config and preset shape/version locks,
and round-trip tests for compatibility-only fields. Run the focused tests, full
OMV suite, and supported release build. Static success is insufficient: do not
declare, ship, or document the change as startup-safe until the user confirms a
normal load-to-gameplay playtest with BaseObjectSwapper installed. Update the
startup erratum with that runtime result and the new accepted baseline.

## Effect contract

Before implementation, define the applicable contract in code and tests:

- exact render phase and ordering relative to native rendering and other OMV effects;
- color, depth, normal, velocity, mask, and history inputs and outputs;
- format, dimensions, MSAA, color space, depth convention/precision, valid range, sampler filtering/addressing, and clear/invalid values;
- shader model, entry point, macros, samplers, constants, and CPU/GPU ABI;
- viewport, scissor, fullscreen topology, D3D9 half-pixel rule, and cross-resolution coordinate mapping;
- allocation, resize, device loss/reset, first frame, camera cut, config change, and history epoch;
- ownership and safe fallback when dependencies, capabilities, resources, or variants are absent;
- disabled/zero-strength behavior, which should skip resource work and draws when safe.

If a required engine fact is unknown, first search `docs/` and existing analysis for a solved contract, then use the radare2 MCP against the current executable. Ghidra may be used only under the root fallback rule when the radare2 MCP is unavailable. A plausible frame is not proof of the contract. Every implemented effect or graphics integration change must also create or update its detailed feature document under `docs/`, including the native phase, resource, ownership, ABI, quality, and performance contracts it depends on.

Third-party graphics source under `.research/` is reference-only. OMV fixes must be OMV-side, capability-based, mod-agnostic, and safe if future dependency versions change or already correct the behavior.

## D3D9 ownership

Set every state the pass depends on; never inherit it accidentally. Cover applicable shaders, declaration/FVF, streams, indices, viewport, scissor, RT0, unused MRTs, depth-stencil, depth/stencil tests and writes, culling, blending, alpha test/coverage, color writes, multisample mask, sRGB write/decode, and every used sampler's texture/filter/address state.

Prevent render-target feedback. Unbind or restore resources and state according to the owning pipeline contract. Test exact state invariants when direct D3D rendering tests are impractical.

## Shader rules

- Compile every production entry point, macro family, quality tier, depth mode, and feature combination. Base-source compilation is insufficient.
- Inspect each compiled production variant. Enforce shader-model, instruction, texture-op, sampler, flow-control, and prohibited-opcode budgets.
- Compilation proves syntax and ABI only, never image correctness.
- Do not reconstruct depth positions or normals with `ddx`/`ddy` after divergent control flow, early return, or clipping. Derivatives across a two-triangle fullscreen pass require explicit seam-free proof; prefer neighboring samples or a proven normal buffer.
- For point-sampled resources, reconstruct from the actual sampled texel center, not the requested UV. Respect D3D9 half-pixel and resolution mapping.
- Handle standard/reversed depth, clear/sky endpoints, invalid samples, source quantization, and near/far limits explicitly.
- Screen-space noise, hash, rotation, jitter, reprojection, and rejection math must remain stable during subpixel camera translation and rotation.
- Reject NaN/Inf at the source. Do not use clamping or epsilon to conceal an unknown resource or coordinate bug.
- Keep variants specialized so disabled families do no hidden work and a local fix does not perturb accepted variants.
- Preserve accepted equations, sample distributions, filters, temporal behavior, and composition unless an intentional change proves equal or better quality.

## Static quality validation

Every new effect and material behavior change needs a deterministic CPU reference renderer or equivalently strong offline image test modeling the relevant production sampling, reconstruction, filtering, temporal, and composition math. String checks may protect ABI details but cannot be the only quality test.

Cover every applicable row:

| Area | Required cases |
|---|---|
| Baseline | Disabled/zero effect, constant input, flat geometry, excluded/background pixels. |
| Geometry | Smooth gradients, shallow/steep/grazing planes, thin features, local occluders, real discontinuities. |
| Screen | Borders, corners, odd/even sizes, both fullscreen triangles, shared diagonal, full/partial-resolution mapping. |
| Depth | Near/mid/far, standard/reversed, sky/clear, invalid values, D16/D24-like quantization when accepted. |
| Motion | Subpixel translation and rotation across texel and triangle boundaries. |
| Temporal | First frame, valid/rejected/stale history, cut, resize, reset, config and epoch changes. |
| Integration | Every family/tier alone and interacting combinations; applicable sky, fog, water, first-person, UI, and masks. |

Assertions must prove outputs are finite and bounded; flat/excluded regions remain clean; real signal is local and correctly signed; filters preserve intended edges; and motion/history remain stable. Explicitly reject fullscreen fill, diagonal splits/seams, bands, wall lines, isolated points, speckles, crawling, flicker, popping, and ghosting.

For each reported bug, keep a regression test that reproduces its artifact class. Show that the test fails against the buggy implementation or a minimal negative control. A test never demonstrated to reject the defect is not evidence.

For user-accepted effects, preserve representative golden buffers and/or structural metrics. Prefer robust properties and tight tolerances over fragile exact float equality.

## Static performance validation

Each meaningful production variant needs tested upper bounds for:

- passes, draws, render-target switches, and pass resolution;
- executed samples/texture fetches and sample distribution;
- compiled arithmetic, flow, and texture instructions;
- samplers, constants, interpolators, and register pressure when available;
- persistent/history/temporary GPU memory;
- per-frame CPU work, allocations, locks, state churn, and lookups.

Budget compiled bytecode, not HLSL line count. Budget Fast, Contact, Combined, and quality variants independently. Do not loosen a ceiling merely to pass: document the quality/correctness need, compare simpler options, and prove the result still meets its performance contract.

Render callbacks must not compile shaders, perform file I/O, allocate routinely, log per draw/pixel, or block. Precompute constants, cache variants, reuse resources, and use `try_lock`. Exit unavailable-input and zero-strength paths before expensive setup.

Static counts prove bounded work, not FPS. Do not claim runtime gains without runtime evidence, and do not make the user perform diagnostic gameplay. A normal playtest is final acceptance after static gates pass.

## Change sequence

1. Read applicable errata and current tests; identify accepted behavior and budgets.
2. Add a failing regression/negative control or define objective feature invariants.
3. Prove missing engine, resource, phase, and lifetime facts.
4. Make the smallest complete engine-and-shader change; avoid unrelated visual changes.
5. Run focused variant compilation, bytecode, reference-image, state, temporal, and budget tests.
6. Run `cargo test --target i686-pc-windows-gnu -p omv`, then `cargo build --release --target i686-pc-windows-gnu -p omv` once.
7. Inspect the diff and report separately what static validation proves and what only ordinary playtesting can confirm.

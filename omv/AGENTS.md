# OMV graphics rules

OMV inherits all root rules; these are subtree deltas. Graphics quality and
performance are separate release gates.

The root OMV no-game-runtime exception applies to every section below. Agents
must use offline executable behavioral tests and direct static evidence, not a
game run. Gameplay validation belongs exclusively to the repository owner and
is never an agent gate. OMV still permits no guessing: a synthetic scene or
reconstructed shader cannot evidence a reported path without direct proof that
it is exact.

For permitted HLSL tests, the `src/effects/ambient_occlusion.rs` suite is the
minimum pattern for compilation, bytecode, deterministic rendering, regression
power, and work budgets. Never weaken or bypass it.

## BaseObjectSwapper-sensitive startup contract

Read `docs/nvse_startup_phase_safety.md` and
`docs/graphics_fnv_atmosphere_startup_crash_errata.md` completely before
changing startup, configuration, presets, process-owned preparation, hooks,
global storage, TLS, or pre-`DeferredInit` state. Those documents own the full
mechanism, history, review protocol, and accepted baseline; do not repeat their
detail here. Identify the latest load-to-gameplay-playtested baseline before
editing.

Treat everything reachable from `NVSEPlugin_Load`, including spawned work, as
one frozen compatibility footprint. When a concrete startup risk requires a
baseline comparison, cover config/schema/presets and layouts; lazy/static/TLS
ownership; locks, constructors, threads, workers, scans, DLL loads and heavy
allocation; publication atomics/mailboxes; and staging/provider/publication/
hook order.

The current invariants are mandatory:

- `NVSEPlugin_Load` retains only baseline config copying and process-owned
  preparation. CPU-only, off-thread, atomic, or non-D3D work is not inherently
  startup-safe.
- The focused world owner remains untouched until `DeferredInit`.
  `apply_initial_depth_activation` hands config to hooks and publishes world
  state before resident hooks become reachable.
- New engine callbacks/admission start false, are never published by
  `ScreenShaderRuntime::configure`, open only at the deferred handoff, and
  clear on installation failure. Preserve all accepted preparation/order.
- Config/presets remain schema 1; deprecated fields retain serialized position
  and round-trip. Keep motion blur `first_person_strength` serialized but
  absent from active menus, rendering, temporal identity, constants, and HLSL.
- Add no pre-deferred TLS/destructor or render-state lazy first touch. Prefer
  zero-initialized POD/atomics first used after handoff. Never disable or delay
  requested effects/workers as a startup fix; remove only the unsafe new delta.

Before `[INIT] Deferred OMV graphics hooks initialized`, render code has not
executed: investigate only the load-time delta, never shader/D3D/depth/vendor
policy. BaseObjectSwapper is an observed fault site, not a patch target or
proof of attribution.

Run applicable existing checks, the OMV suite, and the release build. Static
success cannot establish startup safety. Report startup behavior as not run
unless the owner voluntarily provides a gameplay result; do not require or
request a BaseObjectSwapper load-to-gameplay test. Record only durable accepted
conclusions, never hashes or routine artifact inventories.

## Effect contract

Before implementation, prove the applicable production contract and establish
the exact behavioral acceptance test. Repository-local automated graphics
tests may cover shipped HLSL behavior:

- native/effect phase, ordering, ownership, and unavailable-input fallback;
- resource I/O, formats, dimensions, MSAA, color/depth meaning, ranges,
  sampling, and invalid values;
- shader variant/ABI plus viewport, scissor, topology, half-pixel, and
  cross-resolution mapping;
- allocation/reset/history lifecycle and disabled-path cost.

Resolve unknown engine facts through the root research route. An unproven frame
is not an implementation target. Update the owning durable feature document with material native
phase, resource, ownership, ABI, quality, and performance contracts.

Third-party graphics source under `.research/` is reference-only. OMV fixes
remain OMV-side, capability-based, mod-agnostic, and safe across dependency
versions.

## D3D9 ownership

Set every state the pass depends on; never inherit it accidentally. Cover applicable shaders, declaration/FVF, streams, indices, viewport, scissor, RT0, unused MRTs, depth-stencil, depth/stencil tests and writes, culling, blending, alpha test/coverage, color writes, multisample mask, sRGB write/decode, and every used sampler's texture/filter/address state.

Prevent render-target feedback. Unbind or restore resources and state according
to the owning pipeline contract. Prove exact state invariants from the real
boundary or complete engine evidence; do not add a mocked Rust/native test.

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

Every HLSL effect or material change needs a deterministic reference
oracle and an offline image test executing the relevant shipped shader path,
sampling, reconstruction, filtering, temporal behavior, and composition math.
It is behavioral only when direct evidence proves those inputs and stages are
the reported production path. String or source-text checks are prohibited.

Cover boundary cases relevant to the proven report: disabled/flat/background,
gradients/grazing/thin/occluders, borders/resolution/depth, motion/history, and
interacting passes. Reject nonfinite output, lost edges, fills, seams, flicker,
pops, and ghosts.

For each reported HLSL bug, run a practical offline regression through the
proven production shader path with the affected inputs and oracle, and show
that the unchanged buggy shader fails it before editing. Reproducing only an
artifact class or a minimal negative control is insufficient. For native
integration, hook, camera, configuration, or effect-ownership behavior that
cannot execute outside the game, derive the requirement from the owner's
report and prove every implementation decision from direct source, binary, and
engine evidence. Do not create a substitute mocked test.

For user-accepted HLSL effects, preserve representative golden buffers and/or
structural metrics. Prefer robust properties and tight tolerances over fragile
exact float equality. Do not create golden or structural tests for non-HLSL
production code.

## HLSL static performance validation

Each meaningful HLSL variant needs practical shader-tested bounds for passes,
draws, target switches/resolution, samples, compiled instructions, samplers,
constants/interpolators/registers, GPU memory, and associated per-frame CPU
work, allocations, locks, state churn, and lookups.

Budget compiled bytecode, not HLSL line count. Budget Fast, Contact, Combined, and quality variants independently. Do not loosen a ceiling merely to pass: document the quality/correctness need, compare simpler options, and prove the result still meets its performance contract.

Render callbacks must not compile shaders, perform file I/O, allocate routinely, log per draw/pixel, or block. Precompute constants, cache variants, reuse resources, and use `try_lock`. Exit unavailable-input and zero-strength paths before expensive setup.

Static counts prove bounded work, not FPS. Establish a fail-first deterministic
work-budget or executable benchmark for each affected cost that can be tested
offline. A game-only performance report from the owner defines the remaining
requirement but is not an agent gate. Claim only the measured offline cost
change; do not claim an FPS or gameplay-performance gain without owner-supplied
runtime evidence.

## Change sequence

1. Read applicable errata and current evidence; identify accepted behavior and budgets.
2. Define the owner's reported game-only requirement and run each applicable offline behavioral test against the unchanged code; require a fail-first result wherever the shipped path can execute offline.
3. Prove the failing shader/engine, resource, phase, and lifetime path from direct evidence without proxies or assumptions.
4. Make the smallest complete engine-and-shader change; avoid unrelated visual changes.
5. Run the identical offline behavioral test. Then run HLSL variant compilation, bytecode, image, temporal, and budget support checks as applicable; never create a substitute mocked test.
6. Run `cargo test --target i686-pc-windows-gnu -p omv`, then `cargo build --release --target i686-pc-windows-gnu -p omv` once.
7. Inspect the diff, report offline qualification, and state which game-only behavior was not run. Gameplay validation occurs only if the owner independently chooses it.

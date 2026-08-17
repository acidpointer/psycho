# OMV graphics rules

These are only the OMV-specific deltas to the repository root rules; all root
acceptance, testing, commit, research, documentation, code-quality, safety, and
performance rules remain inherited. For graphics work, visual quality and
performance are independent release gates.

For permitted HLSL validation, the ambient-occlusion suite in
`src/effects/ambient_occlusion.rs` is the minimum pattern for shader
compilation, bytecode inspection, deterministic reference rendering,
regression power, and static work budgets. Reuse its shader-test
infrastructure; never weaken or bypass it to land a change.

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
success cannot establish startup safety; require the user's normal
BaseObjectSwapper load-to-gameplay approval. Record only durable accepted
conclusions, never hashes or routine artifact inventories.

## Effect contract

Before implementation, define the applicable production contract and its
behavioral acceptance evidence. New automated tests may cover only shipped
HLSL behavior:

- native/effect phase, ordering, ownership, and unavailable-input fallback;
- all resource inputs/outputs, formats, dimensions, MSAA, color/depth meaning,
  ranges, sampling, and invalid values;
- shader variant/ABI plus viewport, scissor, topology, half-pixel, and
  cross-resolution mapping;
- allocation/reset/history lifecycle and disabled-path cost.

Resolve unknown engine facts through the root research route. A plausible frame
is not proof. Update the owning durable feature document with material native
phase, resource, ownership, ABI, quality, and performance contracts.

Third-party graphics source under `.research/` is reference-only. OMV fixes must be OMV-side, capability-based, mod-agnostic, and safe if future dependency versions change or already correct the behavior.

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

Every new HLSL effect or material shader change needs a deterministic CPU
reference renderer or equivalently strong offline image test modeling the
relevant production sampling, reconstruction, filtering, temporal, and
composition math. Such a test is permitted only because it directly targets
shipped HLSL behavior. String or source-text checks are prohibited.

Cover applicable disabled/constant/flat/background cases; gradients, grazing
planes, thin features, occluders and discontinuities; borders, odd/even sizes,
fullscreen seams and resolution mapping; near/far, standard/reversed,
clear/invalid and accepted quantization; subpixel motion; first/stale/cut/reset
history; and interacting families with sky, fog, water, first person, UI, and
masks. Prove finite bounded output, clean excluded regions, local correctly
signed signal, preserved edges, and stable motion/history. Reject fills,
seams, bands, lines, points, speckles, crawl, flicker, pop, and ghosting.

For each reported HLSL bug, keep a practical shader regression that reproduces
its artifact class and show that it fails against the buggy shader or a minimal
negative control. For native integration, hook, camera, configuration, or
effect-ownership bugs, do not add a source-code test; require exact behavioral
reproduction or complete correctness evidence plus strict user approval.

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

Static counts prove bounded work, not FPS. Do not claim runtime gains without runtime evidence, and do not make the user perform diagnostic gameplay. A normal playtest is final acceptance after static gates pass.

## Change sequence

1. Read applicable errata and current evidence; identify accepted behavior and budgets.
2. Define objective behavioral acceptance. Add a failing regression or negative control only for shipped HLSL behavior.
3. Prove missing engine, resource, phase, and lifetime facts.
4. Make the smallest complete engine-and-shader change; avoid unrelated visual changes.
5. For HLSL changes, run focused variant compilation, bytecode, reference-image, temporal, and budget tests. For non-HLSL changes, do not create substitute mocked tests.
6. Run `cargo test --target i686-pc-windows-gnu -p omv`, then `cargo build --release --target i686-pc-windows-gnu -p omv` once.
7. Inspect the diff and keep the result explicitly unreleased until the exact behavioral gate passes or the user strictly approves complete evidence.

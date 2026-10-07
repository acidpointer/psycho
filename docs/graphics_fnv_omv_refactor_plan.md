# OMV code quality refactor plan

Date: 2026-09-28
Revision 2. Supersedes the mechanical file-split plan of the same date.

## Outcome

Migrate OMV from its current shape - one god-struct runtime, one hand-wired
orchestrator, and a test suite that is largely source-text theater - to a
layered ownership model where effects are registered against one lifecycle
contract, the menu is schema-driven, and every accepted ordering invariant is
either executed offline or documented as an engine contract. Shipped behavior,
configuration schema, D3D state ownership, hook order, and the frozen
pre-`DeferredInit` startup footprint do not change.

This stage is complete only when every work package passes its gate, the OMV
suite and the supported 32-bit release build pass, and the final diff contains
only the explicitly approved reorganization.

## The discovery that reorders the plan

The dominant defect is not file size. It is the test architecture:

- About 90 test sites in 25 files embed their own module with
  `include_str!("*.rs")` and then `split_once` on function signatures to
  carve function bodies out of source text (210 `split_once` occurrences).
  They assert textual call order inside function bodies, for example
  `temporal < readiness < color_target < attachments < color_copy < draw` in
  runtime.rs's `first_person_motion_blur_preflights_before_every_gpu_transaction`.
- `omv/AGENTS.md` and the root repository rules prohibit this test category
  outright: string or source-text checks are not behavioral tests.
- `docs/graphics_fnv_portable_depth_transport.md` records that this exact
  pattern was already removed once (source-text reset-order tests) as part of
  accepted work, so removal is an established precedent, not a new policy.
- Consequence: the suite structurally freezes the code. Any real refactor -
  moving a function, renaming it, splitting a file - breaks dozens of these
  assertions mechanically, so the previous plan's "tests must pass identically,
  never touch tests" gate was unsatisfiable. Refactoring was effectively
  blocked by tests that verify nothing behavioral.

Therefore no production restructuring can honestly precede test-debt
disposition. Package 0 is that disposition. Everything else is sequenced
behind it.

## Constraints that apply to every package

- Behavioral gate: the offline `cargo test --target i686-pc-windows-gnu -p
  omv` suite, with its real Wine D3D devices, rendered oracles, and budget
  checks, is the acceptance test. The `ambient_occlusion.rs` suite is the
  minimum pattern for any new HLSL-path test.
- Startup footprint freeze: `runtime::configure` and
  `apply_initial_depth_activation` are reachable from `NVSEPlugin_Load`.
  Within-crate restructuring is allowed only while statics, locks, worker
  threads and spawn points, and initialization order stay identical. No new
  `static`, `LazyLock`, `OnceLock`, mutex, or thread spawn appears in moved
  code. `docs/nvse_startup_phase_safety.md` is read before the runtime work.
- Single-runtime invariant: exactly one
  `static RUNTIME: LazyLock<Mutex<ScreenShaderRuntime>>`. Extracted sub-structs
  stay fields of the same outer struct; the lock and its `Default` semantics
  are unchanged.
- Configuration schema 1 round-trips byte-for-byte. Deprecated-field positions
  and serialized identity are frozen.
- HLSL text, compiled variant identity, option register ABI (`c3+`, `c6`/`c8`
  reserved), MCM/menu visible text, and composition order are frozen unless a
  package explicitly proves an intentional, equal-or-better change.
- Commits require a separate explicit owner request. The dirty worktree entries
  (`intelmoc/`, `libnvse/xnvse` submodule) are preserved untouched.
- Gameplay image quality, startup load-to-gameplay, and driver behavior remain
  owner-run gates under the OMV no-game-runtime exception.

## Target architecture

The production code's real problem is ownership, not lines. The accepted
module-static pattern and the offline test harnesses are good; what is wrong
is that one struct knows every subsystem and one orchestrator hand-wires every
effect. The target ownership map:

- **L1 Engine boundary** (exists, mostly sound): `fnv_render.rs`,
  `fnv_world_pipeline.rs`, `hooks.rs`, `interop.rs` - thin adapters converting
  engine callbacks into typed calls. No effect logic lives here.
- **L2 Frame contract**: `SceneInputRequirements` plus frame inputs become the
  single documented engine-to-effect data channel. Effects declare what they
  need; nobody re-derives engine facts per effect.
- **L3 Effect catalog**: one lifecycle contract and one const registry.
  Eight effects already implement the same lifecycle de facto
  (`service_preparation`, `preparation_ready`, `service_present_frame`,
  device-object creation from published bytecode, release on device loss).
  Runtime iterates the registry instead of hand-coding per-effect blocks; the
  `*_creation_failed` flags and per-effect fields collapse into per-effect
  lifecycle state owned by the contract.
- **L4 Presentation scheduler**: the existing `PhaseExecutionPlan` and
  `PhaseColorGraph` become the only ordering authority. Effects register
  phase and input requirements; the scheduler owns targets, copies, and
  composition order.
- **L5 Schema-driven UI**: one declarative per-effect schema (option name,
  kind, bounds, page, register lane) is the single source for both
  `ScreenShaderSource` option metadata and menu page rendering. This retires
  the ~15 copy-paste `*_source(config)` builders in `shaders.rs` and the
  hand-drawn ~290-line `draw_gpu_details`/`draw_shader_details` menu bodies.
- **L6 Diagnostics and pacing**: frame pacing, spike telemetry, and the
  diagnostics dashboards live in isolated read-only modules with defined
  snapshot APIs, not inside the runtime struct.

Deliberately rejected: a dependency-injection or plugin framework, dynamic
registry mutation, and any big-bang rewrite. They add machinery without a
behavioral gate and are prohibited by repository policy. The registry is a
const table; the trait's dynamic dispatch is per-frame per-effect, not
per-draw.

## Work packages

Ordered. Each package is independently shippable and stops at its own gate.
If a package cannot pass its gate, stop and report.

### Package 0: source-text test disposition (blocking, needs owner decisions)

Inventory every `include_str!("*.rs")` own-source site. For each, classify:

1. **Redundant** - the invariant is already covered by an existing offline
   behavioral suite (D3D raster tests, owned depth, adaptive display,
   reference oracles). Remove the text test.
2. **Replaceable offline** - the asserted ordering is a real D3D or state
   transaction that can execute offline against the existing test device
   harness. Write the behavioral test first, prove the old invariant holds,
   then remove the text test.
3. **Startup-contract guard** - textually asserts the frozen pre-`Deferred`
   footprint (for example "no Shadows in the pre-Deferred value graph",
   `DeferredInit` install order). Where the guarded path is CPU-only and can
   run in a test process, convert to an executable startup test; otherwise
   move the invariant to `docs/nvse_startup_phase_safety.md` as a reviewed
   contract item and remove the text test. The owner approves this class
   explicitly, because the startup gate remains the owner's playtest and
   these proxies are the only automated enforcement that exists today.
4. **Dead** - asserts a string that no longer corresponds to a live invariant.
   Remove with the missing invariant named in the report.

Deliverables: a disposition table in this document or a companion doc, owner
approval for classes 3 and 4 deletions, and `rg -c 'include_str!\("[a-z_]+\.rs"'`
approaching zero with every survivor justified in the table.

Gate: suite passes; test-count delta equals approved removals; no behavioral
suite was weakened; every invariant that lost automated enforcement is listed
with its new enforcement location (executable test or contract doc).

Current exception: on 2026-10-07 the owner directed removal of two
baseline-failing sunshaft behavioral tests. Their contracts have no passing
replacement, so this package gate remains open for those behaviors even
though the current offline suite passes. See the companion disposition ledger.

### Package 1: split `src/runtime.rs` into `runtime/`

Unblocked by package 0. `src/runtime.rs` stays a thin facade re-exporting the
existing `pub(crate)` entry points so external call sites are unchanged.

- `runtime/state.rs` - `ScreenShaderRuntime`, `Default`, and the one `RUNTIME`
  static.
- `runtime/pacing.rs` - present timing, frame pacing, spike summary,
  snapshot APIs.
- `runtime/phase_plan.rs` - scene input requirements, pass/phase planning,
  applied-phase tracking, backbuffer copies, color graph, and the external
  performance test module reference.
- `runtime/menu.rs` - ImGui menu state, key constants, menu draw functions.
- `runtime/motion_blur_retry.rs` - first-person retry token and deadline
  entry points.
- Present-time orchestration remains in the facade.

Rules: sub-struct extraction only where all consumers are within the would-be
module; a field touched across boundaries stays a direct field in this
package. No behavior edit.

Gate: suite passes with recorded counts; the only crate static in
`runtime/` is `RUNTIME`; no new lock/thread/`LazyLock` in the diff.

### Package 2: effect lifecycle contract and registry

Formalize the de facto lifecycle as one internal contract: settings gate,
CPU preparation service, bytecode readiness, device acquisition from
published bytecode, phase admission, present-time service, and device-loss
release. Introduce a const registry in the runtime listing each effect's
contract functions, and migrate effects one at a time, each in its own
gated step, replacing the runtime's hand-coded per-effect blocks and
`*_creation_failed` flags.

Rules: call order per frame is unchanged (this is proven per effect by the
package 0 behavioral replacements where they exist, and by code review plus
the existing suites otherwise). No effect's enable gate, phase admission, or
fallback changes.

Gate: per-effect step passes the full suite; after the last effect,
`ScreenShaderRuntime` no longer stores per-effect lifecycle flags outside the
contract state; runtime.rs's per-effect special cases are down to effects
that genuinely need bespoke ordering (documented per effect).

### Package 3: schema-driven UI and options

One declarative schema per effect drives both shader-option metadata and menu
pages. Register-lane rules (`c6`/`c8` reserved) are encoded once in the schema
construction. `shaders.rs`'s copy-paste builder family collapses onto the
table; `runtime/menu.rs` renders config pages from the schema.

Rules: generated `ScreenShaderSource` option metadata must be identical
(existing round-trip and config-sync tests are the proof; a difference is a
defect in the schema, never loosened tests). Menu layout may not change
visually; MCM/menu text stays laconic and unchanged. Cross-field sync logic
(for example fast-AO config sync) keeps its functions.

Gate: suite passes with recorded counts; no change under
`shaders/embedded/`; diff inspection shows menu draw code reduced to
schema-driven rendering plus genuinely bespoke panels.

### Package 4: split `atmosphere.rs` along its three-effect seams

`effects/atmosphere/` directory: facade keeping `AtmosphereEffect`'s public
surface, plus settings/gates, pure CPU math, bytecode families, and D3D draw
modules. No shader text, gate-order, or debug-view serialization change.

Gate: suite passes, including atmosphere debug-view and shader-compile tests
unchanged.

### Package 5: deduplicate `shadows/pipeline.rs` resource families

Highest-risk package; touches D3D ownership code. Extract the repeated
per-resource-family `create`/`ensure_branch`/grow patterns into one generic
family helper; split `draw_maps` and `draw_consumer` into stage functions
with unchanged call order and unchanged per-pass state sets.

Gate: suite passes including shadow producer/consumer, journal-restore, and
budget tests unchanged; state identity is proven by those tests plus diff
review. If identity cannot be proven, stop and report; do not soften a state
difference.

### Package 6 (optional, lowest priority): mechanical cleanup

- `config.rs` per-feature child modules behind the `config::` facade, schema
  frozen.
- `presets.rs` split of file service from version migration; raise comment
  density where non-obvious.
- `graphics_diagnostics.rs`: each of the 8 `#[allow(dead_code)]` items is
  either wired to its declared consumer or removed with the missing consumer
  named.

Gate: suite passes; deletions listed per item.

### Explicitly out of scope

- `fnv_local_lights.rs`: needs an unsafe-boundary audit driven by real crash
  or contract evidence, not a file split. Deferred.
- `effects/pbr/*`: already well-decomposed; no action.
- Any HLSL, config schema, hook, or D3D behavior change.

## Validation sequence per package

1. Record the full suite result and test count before the change.
2. Implement.
3. Rerun the identical suite; require the recorded count (plus approved new
   behavioral tests in package 0) and zero failures.
4. `git diff --check`; inspect the diff for accidental edits.
5. After the last package: one
   `cargo build --release --target i686-pc-windows-gnu -p omv`, then one final
   full suite run.

## Reporting

Per package: files moved, symbols re-exported, test counts before and after,
disposition outcomes, doc reference updates, and the standing statement of
what was not run (gameplay image quality, startup load-to-gameplay, driver
behavior). No correctness claims beyond offline-qualified results.

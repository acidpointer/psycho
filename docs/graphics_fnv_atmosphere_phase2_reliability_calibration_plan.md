# FNV atmosphere Phase 2 reliability and calibration plan

Startup erratum: the first world-pipeline config publication must remain in
`DeferredInit`, not `NVSEPlugin_Load`. See
`graphics_fnv_atmosphere_startup_crash_errata.md` before changing ownership or
startup wiring.

Date: 2026-07-18

## Implementation status

Implemented on 2026-07-18; runtime playtest acceptance remains open.

Static root-cause closure on 2026-07-18 supersedes the earlier lock/camera
hypotheses for the persistent angle-dependent fog blink. The failure was in
OMV's reduced-resolution atmosphere representation:

- each 2x2 or 4x4 depth cell stored both its nearest and farthest distances;
- integration generated only one atmosphere value at the nearest distance;
- composition compared every full-resolution pixel only with that nearest
  distance and rejected the tap when the pixel belonged to the far layer;
- therefore a mixed fence/foliage/sky cell had no usable sky atmosphere. A
  subpixel camera or TAA shift that changed the reduction-cell membership
  toggled the same sky pixel between untouched source and fog composition.

This is deterministic and was encoded by the former
`bilateral_key_rejects_background_inside_a_mixed_depth_interval` test: a cell
with near=100 and far/sky=10,000 explicitly assigned the sky a zero weight.
VRR only made the invalid on/off transition more visible. AO does not share
this reduced single-layer compositor, which explains why its debug view did
not reproduce the failure.

The corrected contract keeps two reduced atmosphere targets, integrates both
nearest and farthest distances, and matches each full-resolution pixel to its
position inside that depth interval. Mixed foreground/sky cells retain valid
fog for both layers. Do not restore nearest-only integration or bilateral
rejection against `abs(fullDistance - nearest)`.

- Present now owns an unconditional atomic render epoch.
- World TAA, source-color capture, atmosphere resources, and per-epoch target
  ownership moved to `fnv_world_pipeline.rs`.
- World/depth/config owners use `try_lock()` only. Requirement queries are
  atomic, config publication retains the last complete generation on busy, and
  underwater epoch/value publication is lock-free.
- A primary owner/depth miss publishes an epoch plus exact-target token. One
  retry is permitted at `RenderFirstPerson` entry before the original draw;
  outer image-space entry and Present close the deadline without drawing late.
- Duplicate and auxiliary callbacks no longer consume ownership by raw callback
  count. Success is keyed by epoch and exact main-world surface.
- Reset acquires the general runtime, world pipeline, and depth owners through
  nested `try_lock()` scopes. A busy owner returns the D3D device-lost result
  before the original Reset and before any partial release.
- Periodic `[FNV WORLD] Reliability` and general runtime contention summaries
  expose primary/depth misses, retry recovery, target lineage, missed deadlines,
  and transaction failures.
- The shipped/template height density is now `0.000002`; exact zero/logarithmic
  density tuning, a fog-only calibrated reset, effective distance bound, and an
  estimated horizontal-transmission readout are in the resizable menu.
- Deterministic tests cover complete mailbox publication under contention,
  exact retry epoch/target eligibility, atomic underwater epoch matching,
  world requirements, and Halton bounds. Existing atmosphere/TAA shader and
  alpha-preservation tests still compile for the supported target.

This status does not declare Phase 2 accepted. The 10,000-Present fence run,
visual calibration matrix, and device-reset playtest in work package 10 are
still required. Directional volumetric lighting remains Phase 3.

## Outcome

Close the remaining whole-frame atmosphere blink without ever blocking an
engine or D3D callback, then calibrate the shipped fog profile so clear sunny
weather receives subtle supplemental depth instead of a gray overcast wash.

The execution fix is complete only when a failed `try_lock` is an explicit,
recoverable state transition. It must not silently suppress a prerequisite,
consume the atmosphere callback for that Present, retain a stale epoch, or
turn a recoverable primary miss into an ordinary-image frame.

Fog calibration is a separate change. It must not hide a scheduling failure by
making the alternating output harder to see. Directional volumetric lighting
remains Phase 3; this correction must not invent sun or shadow data in HLSL.

## Fresh playtest evidence

The 2026-07-18 production-fog playtest proves:

- the strict FP16 atmosphere pipeline initialized successfully;
- the medium integration and production composition gates reached `Ready`;
- a production composition draw completed at 3440x1440 on the 8x MSAA FP16
  world target;
- the render path reported multiple second world-boundary callbacks in some
  Presents;
- during the visible failure, eight consecutive callbacks reached atmosphere
  with `world_color_captured_this_frame == false`, so the pipeline deliberately
  bypassed before composition;
- no atmosphere shader, D3D draw, device-reset, or resource error explains
  those bypasses.

The missing-capture warning does not by itself distinguish a silent
`RUNTIME.try_lock()` miss from a callback that arrived outside the eligible
main-world interval. Both are execution-ownership failures and this plan
records them independently before selecting the final branch.

The same run also proves the excessive-fog inputs:

- live distance density was `0.00000590`, although the saved default remains
  zero;
- height density was the shipped `0.00002000`;
- the effective camera/fog distance bound reached 10,240 world units;
- the selected native fog color was approximately neutral gray
  `(0.8627, 0.8627, 0.8627)`;
- the atmosphere contract had no directional sun input.

Near the configured base height on a roughly horizontal ray, the two density
terms can produce optical depth near 0.265 at that bound, or transmittance near
0.77 before height variation. Removing roughly one quarter of the existing
sunny scene and replacing most of it with nondirectional gray scattering
explains the reported rain-like image and weakened shafts.

## Non-negotiable concurrency rules

1. No engine, render, Present, Reset, input, or D3D hook added or changed by
   this work may call blocking `.lock()`.
2. Every relevant mutex access uses `try_lock()` and has a named outcome.
3. Lock failure is not equivalent to Disabled, NotRequested, Applied,
   Duplicate, or a valid contract rejection.
4. A failed attempt cannot increment the successful-execution guard or prevent
   a later eligible retry in the same Present.
5. Present epoch advancement cannot depend on acquiring a runtime mutex.
6. Current-frame color, depth, camera, TAA, environment, or underwater data is
   never reused after an epoch mismatch.
7. Only one successful atmosphere composition may modify the proven main-world
   target in one Present. Auxiliary targets never consume that ownership.
8. If all safe retry boundaries are missed, the source stays unchanged and the
   runtime reports `MissedDeadline`. It must not apply fog after first-person
   or UI merely to avoid the warning.
9. The shipped fix may not disable atmosphere, TAA, AO, MSAA, native fog,
   first-person rendering, or the known fence geometry.

## Work package 1: lock-independent Present epoch

Add one `AtomicU32` render epoch owned by the D3D Present hook. The hook loads
the current epoch for all work belonging to the pending Present and advances
it unconditionally after the original Present returns. Epoch advancement must
happen even when every runtime `try_lock()` fails.

Every mutable render owner caches the last epoch it observed. On its next
successful `try_lock()`, `begin_epoch(current_epoch)` lazily clears per-Present
guards and outcomes if the cached value differs. Correctness must no longer
depend on `finish_present_frame()` acquiring the general runtime mutex.

Keep cumulative atomic counters outside all mutexes for lock misses at:

- pre-world TAA jitter preparation;
- post-world depth capture;
- the primary world transaction;
- the pre-first-person retry;
- first-person depth publication;
- outer image-space entry;
- Present menu/final work;
- Present finish;
- Reset resource release.

Counters are consumed as deltas after a later successful acquisition. Do not
log from each failed callback.

## Work package 2: coherent published world settings

The world hook must not acquire the general runtime mutex merely to ask whether
depth, TAA, world color, fog, or a diagnostic is required.

Publish a small immutable `FnvWorldEffectsConfig` whenever startup, menu edits,
save, reload, or shader rescan changes the relevant settings. It contains only:

- global screen-space enable and FNV depth-provider selection;
- TAA enable and fixed options required by the world boundary;
- fog enable, quality, density, height parameters, distance, albedo, noise,
  and debug mode;
- lighting enable/debug state needed by the shared atmosphere foundation.

Use a tiny `WorldEffectsConfigMailbox` protected only by `try_lock()`. A writer
replaces the complete snapshot, increments its 32-bit generation, publishes the
derived atomic requirement bitset, and then publishes the generation with
release ordering. If publication is busy, set `CONFIG_PUBLISH_PENDING` and
retry from a later Present; the active render configuration remains unchanged.

The world owner checks the published generation. It attempts the mailbox only
when a newer generation exists. If that `try_lock()` is busy, it keeps its last
complete cached snapshot and reports `SettingsPublishBusy`; it never skips the
frame or observes partial settings. Hook requirement queries read the atomic
bitset directly and can no longer return `false` merely because
`RUNTIME.try_lock()` failed.

## Work package 3: dedicated non-blocking world pipeline owner

Move world-boundary mutable resources out of the large menu/general screen-pass
runtime into a focused `FnvWorldPipelineRuntime` protected by its own mutex.
Only world-boundary hooks, the bounded pre-first-person retry, and device-reset
coordination may call `try_lock()` on it. Present menu rendering, shader-list
layout, disk I/O, AO, bloom, DOF, and final image-space passes must never hold
this mutex.

The owner contains:

- the last complete `FnvWorldEffectsConfig` generation;
- per-epoch execution state and target identity;
- the source-format world-color copy;
- temporal-AA world resources needed at this boundary;
- atmosphere resources and creation-failure state;
- a dedicated D3D all-state block and attachment restore state;
- bounded counters and transition-log state.

This isolation is the primary contention fix. In normal rendering, only one
world callback owns the mutex. If duplicate engine callbacks overlap, the
callback that acquires it performs or completes the transaction; a losing
callback records contention but cannot cancel the successful owner.

All render-facing FNV depth-resolve calls used by the transaction must also
gain `try_lock()` variants with explicit `Busy` results. Do not add a blocking
depth access under the new non-blocking world owner. A busy depth resolver
leaves the transaction pending for the next safe retry and never returns a
default or stale `DepthFrame` as if it were current.

## Work package 4: one coherent world transaction

Replace the current separately locked sequence

```text
needs depth -> capture depth -> TAA -> needs color -> capture color
-> atmosphere
```

with one post-world transaction after a single successful world-pipeline
`try_lock()`:

```text
adopt current epoch/settings -> validate main target -> resolve current depth
-> apply current TAA resolve if eligible -> capture source color
-> reduce/integrate/compose atmosphere -> restore attachments/state
-> publish final outcome
```

The D3D state block encloses every draw and copy owned by the transaction.
Preserve the first D3D failure while still attempting full state and attachment
restoration.

Use a state model equivalent to:

```text
Inactive
PendingPrimary
PrimaryLockBusy
AuxiliaryTarget
DepthBusy
DepthRejected(reason)
SourceCaptured
AtmosphereIntegrated
AtmosphereComposed
DebugPresented
PendingFirstPersonRetry
Applied(target, depth_epoch)
MissedDeadline(reason)
DrawFailed(signature)
```

Intermediate states do not count as success. `Applied` means the requested
production or debug full-screen output completed and all engine state was
restored.

Remove `atmosphere_callbacks_this_frame > 1` as the ownership decision. Keep an
at-most-one successful write, keyed by Present epoch plus exact main target,
instead of raw callback order.

## Work package 5: target eligibility and safe retry boundaries

At the post-world return, classify the current RT0 before consuming ownership:

- nonzero FP16 render-target surface;
- current dimensions and multisample description;
- exact identity with the engine's main rendered-world texture/color surface;
- current world-depth projection epoch and camera contract.

An auxiliary or mismatched callback is recorded and left pending. It does not
become callback 1 and does not cause the later main callback to be skipped.

If the primary transaction cannot acquire either the world owner or current
depth owner, set an atomic pending bit tagged with Present epoch and target
identity. Retry once at `RenderFirstPerson` entry, before calling the original
function. This boundary is eligible only when:

- a post-world pending token exists for the current Present;
- the rendered-texture argument resolves to the same color surface recorded by
  the token;
- current RT0/depth identities still match;
- first-person drawing has not started;
- the transaction has not already reached `Applied`.

Review the existing Ghidra owner/caller output before implementing this retry.
If it does not prove the rendered-texture argument and attachment state for all
three `RenderFirstPerson` callers, add a focused script under
`analysis/ghidra/scripts/` and require its output before enabling the retry.
Do not infer the target layout from argument names.

At outer `ProcessImageSpaceShaders` entry, close the deadline. Compare the
native source surface with the recorded target and publish the outcome. Never
perform production atmosphere there when first-person has already rendered.

## Work package 6: correct behavior for every `try_lock` failure

| Site | Required behavior |
|---|---|
| Requirement query | Read the published atomic bitset; no mutex attempt. |
| Settings publication/read | Keep the last complete generation, set/retry the pending publication flag, and report busy; never read a partial update or skip rendering. |
| Primary world owner | Record pending and allow the pre-first-person retry. |
| FNV depth owner | Record `DepthBusy`; retain no borrowed/stale frame and retry before first-person. |
| Pre-first-person retry | Apply only with matching epoch/target; otherwise publish the exact deadline reason. |
| Duplicate callback | No-op only if the same epoch/target is already `Applied`; otherwise classify and retry. |
| Present finish | Advance the atomic epoch regardless; lazily reconcile runtime state later. |
| Menu/final runtime | Skip only that menu/final operation and increment its own counter; it cannot alter world ownership. |
| Device Reset | Acquire all affected owners with `try_lock()` in a fixed order. If any is busy, release acquired guards, mark reset pending, and return the normal lost/not-ready result so the engine retries. Never call original Reset after partial resource release. |

Do not reuse the previous composed image as a fallback. Camera motion makes it
the wrong world image and would replace blinking with full-screen ghosting.

## Work package 7: bounded outcome telemetry

Emit one transition log when the final per-Present outcome class changes and a
periodic aggregate while diagnostics are active. Record:

- Present epoch;
- world callback count and target identities;
- primary and retry lock-miss deltas;
- selected settings generation;
- depth capture/projection epoch;
- source-capture target and result;
- integration, composition, and debug draw counts;
- first-person entry/completion and outer image-space entry;
- final outcome and deadline reason.

Log an immediate bounded warning for `MissedDeadline`, target lineage mismatch,
stale epoch, or state restoration failure. A successful reduced integration is
not a successful visible atmosphere outcome.

Retain the existing D3D state/lineage diagnostics as conditional follow-up.
The fresh missing-source evidence makes execution ownership the first fix; it
does not prove that every previous debug blink had only one cause.

## Work package 8: conservative fog calibration

After the execution acceptance passes, change the production defaults:

```text
density = 0.0
height_density = 0.000002
height_falloff = 0.0001
base_height = 0.0
max_distance = 120000.0
scattering_albedo = 0.9
```

The tenfold height-density reduction targets roughly two percent horizontal
extinction at the observed 10,240-unit camera bound near base height. Keep
distance density exactly zero by default. Retain the existing distance/fog-end
and camera-far bounds; do not add an arbitrary production optical-depth cap.

Preserve explicit user values when loading an existing config. Do not silently
reinterpret `0.00002000` as an old default because it may be an intentional
profile. Add a fog-specific `Reset to calibrated defaults` action so an
existing installation can opt into the new profile without deleting its whole
OMV config.

Add density-specific controls rather than using a purely linear zero-to-0.001
slider:

- an explicit zero/off value;
- logarithmic adjustment from `0.0000001` through `0.0001` for normal tuning;
- precise increment/decrement and text entry;
- the existing sanitized upper bound remains available through explicit entry
  for intentional extreme-weather presets.

Show the current effective distance bound and an approximate camera-height
horizontal transmittance in the fog status panel. Label it as a tuning estimate,
not the per-pixel result.

Keep physical source-alpha preservation, native fog color, extended-sRGB
transfer, and user-controlled heavy fog. Do not:

- exclude the sky to fake sun preservation;
- brighten pixels from a guessed sun direction;
- derive a second global extinction value from native fog start/end/power;
- reduce scattering albedo merely to exchange gray washout for dark washout;
- claim that Phase 2 now has directional shafts.

Phase 3 must supply directional sun in-scattering and the proven shadow/shaft
contract. Phase 2 calibration only ensures that the supplemental nondirectional
medium is appropriately subtle in clear weather.

## Work package 9: tests

Add focused unit tests for:

- Present epoch advancement without any mutex acquisition;
- lazy per-owner epoch reconciliation;
- complete mailbox publication, deferred writer retry, and bounded reader-busy
  fallback;
- atomic requirement-bit reads while mailbox publication is busy;
- primary busy -> pending -> pre-first-person success;
- auxiliary callback -> later main-target success;
- primary success -> duplicate same-target no-op;
- depth busy -> retry success without stale-frame reuse;
- primary and retry busy -> explicit `MissedDeadline`;
- missed `finish_present_frame` -> clean next-epoch execution;
- target mismatch and first-person-started rejection;
- Reset deferral with no partial release;
- exactly one successful composition per epoch/target;
- new density defaults, sanitization, zero/logarithmic control mapping;
- approximate transmittance calculations;
- every embedded atmosphere/TAA HLSL variant still compiles;
- exact source-alpha preservation remains unchanged.

Use deterministic state-machine tests rather than timing-dependent threaded
tests wherever possible.

## Work package 10: build and playtest

Run:

```text
cargo fmt --all -- --check
cargo test -p omv
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
```

Then deploy with `build_fnv.sh` and perform:

1. Fog Off/On in the same clear exterior view.
2. Production fog and every debug mode while moving and rotating at the fence.
3. The same reproduction with the OMV menu open, closed, resized, and while
   editing density controls.
4. First-person weapon drawn/holstered, iron sights, scope, VATS, dialogue,
   Pip-Boy, loading screen, interior transition, underwater transition, and
   exterior return.
5. TAA Off/On and 8x MSAA unchanged.
6. Alt-tab and one supported device-reset/resolution-change path.
7. At least 10,000 requested atmosphere Presents at the known trigger.

Acceptance requires:

- zero `MissedDeadline` outcomes in 10,000 requested Presents;
- zero required-stage lock misses that lack a same-Present successful retry;
- exactly one production/debug presentation on every eligible requested
  Present;
- no stale epoch, target mismatch, state leak, or partial Reset release;
- no visible ordinary/fogged alternation;
- subtle clear-weather fog that does not turn the scene gray or erase sunny
  contrast at shipped defaults;
- deliberately higher density still produces a strong user-selected fog;
- first-person, UI, and source alpha remain unchanged by world composition.

If any missed deadline remains after the dedicated-owner extraction, stop and
capture the exact competing callback/owner. Do not add blocking acquisition,
reuse a previous frame, move production fog after first-person, or weaken the
effect until the blink becomes difficult to notice.

## File map

| File | Planned change |
|---|---|
| `omv/src/hooks.rs` | Lock-independent Present epoch, atomic outcome accounting, and non-blocking Reset coordination. |
| `omv/src/fnv_render.rs` | One primary world transaction, target-aware callback classification, pre-first-person retry, and deadline publication. |
| `omv/src/runtime.rs` | Remove world ownership from the general/menu runtime, publish coherent world settings, and consume aggregate diagnostics. |
| `omv/src/fnv_world_pipeline.rs` | New focused non-blocking owner for world TAA/color/atmosphere resources and the per-epoch state machine. |
| `omv/src/backend/fnv.rs` | Explicit `try_lock()` depth outcomes and no stale/default frame on contention. |
| `omv/src/backend/mod.rs` | Typed forwarding APIs for non-blocking FNV depth results. |
| `omv/src/effects/atmosphere.rs` | Use the transaction inputs, expose effective-bound/transmittance status, and update calibration tests. |
| `omv/src/effects/temporal_aa.rs` | Move world-boundary resource ownership into the focused pipeline without changing shader ABI. |
| `omv/src/config.rs` | New fog defaults and compatibility/sanitization tests. |
| `omv/src/shaders.rs` | Density-control metadata and synchronized embedded settings. |
| `psycho-imgui/src/bridge.cpp` and `psycho-imgui/src/lib.rs` | Reuse/extend precise logarithmic controls only as required for an explicit zero plus normal density range. |
| `omv/config/omv.toml` | Ship the calibrated profile and document strong-fog tuning. |
| `omv/README.md` | Document retry ownership, fail-closed deadline behavior, calibrated defaults, and the Phase 3 sun limitation. |
| atmosphere parent plans | Record this plan as the Phase 2 release blocker before directional lighting. |

No helper-DLL or xNVSE-side graphics change belongs in this work.

## Implementation order and stop gates

1. Add atomic epoch, outcome counters, and deterministic state-machine tests.
2. Publish coherent world settings/requirements without `RUNTIME` reads in the
   world hook.
3. Extract the focused world pipeline owner and convert relevant depth access
   to typed `try_lock()` outcomes.
4. Implement the single primary transaction and exact target eligibility.
5. Prove and implement the pre-first-person retry; stop for new Ghidra output
   if existing evidence does not close every caller/attachment question.
6. Add outer-entry deadline/lineage accounting and non-blocking Reset handling.
7. Build and run the fence execution playtest with the deliberately visible old
   fog strength. Do not tune before zero missed deadlines is proven.
8. Apply calibrated defaults and density UI changes.
9. Run the complete build and visual/fallback matrix.
10. Update parent plans only after both reliability and calibration acceptance.

Phase 2 is complete only after this plan passes. Directional Volumetric
Lighting remains the next phase, not a substitute for closing this contract.

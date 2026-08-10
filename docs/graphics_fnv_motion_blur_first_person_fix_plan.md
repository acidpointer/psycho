# FNV first-person motion-blur correction plan

## Implementation status

Implemented on 2026-08-10. The completed change follows the selected boundary,
world-only shader ABI, exact retry, dynamic scene-post graph, input ownership,
and lifecycle contracts below. Removing the preset-visible legacy control also
required config schema 2, a frozen `schema_v2.fields` manifest, and a
deterministic schema-1 migration that discards only motion blur's obsolete
`first_person_strength`; working schema-1 TOML and schema-1 presets remain
loadable.

Static evidence at completion:

- `cargo fmt --all`: passed;
- `cargo test --target i686-pc-windows-gnu -p omv`: 459 passed;
- `cargo build --release --target i686-pc-windows-gnu -p omv`: passed;
- `git diff --check`: passed;
- production motion-blur variants compiled under the suite and stayed within
  their bytecode/texture-operation budgets.

Ordinary FNV playtesting remains required. This status does not claim runtime
image correctness or measured frame-rate improvement, and it does not change
the known third-person player-body limitation.

## Objective and pre-fix status

This document is the implementation plan for the first-person defect only.
The pre-fix implementation blurred the completed scene after native
first-person geometry has been composited. It also contains an explicit
first-person camera reprojection branch, enabled by a nonzero default strength.
The required result is:

- camera motion continues to blur world geometry and sky in first-person view;
- native first-person hands, weapons, muzzle effects, and every other fragment
  drawn by `Main::RenderFirstPerson` are not inputs to motion blur;
- later native and OMV image-space processing continues normally;
- missing inputs or a missed render boundary leave the frame unblurred rather
  than falling back to a post-first-person draw.

The fix is an engine-ordering change, not a depth-mask heuristic. OMV will
blur the completed world before the engine draws the first-person layer. The
native first-person draw then overwrites the blurred world using the engine's
ordinary material, depth, alpha-test, and blending behavior.

The current third-person path, including its scene-post boundary and packed
depth history, remains in place. The known third-person player-body defect is
outside this plan and must neither block nor be represented as fixed by this
work.

## Acceptance contract

The implementation is complete only when all of these properties hold:

1. In exact first-person mode, motion blur can draw only after the primary
   world scene has completed and before the original `RenderFirstPerson` call
   begins.
2. No first-person execution path can reach motion blur from
   `ScenePostImageSpace`, including as a fallback after a busy lock, missing
   depth, shader-preparation miss, or D3D failure.
3. Wherever native first-person rendering produces an opaque fragment, the
   final pre-image-space color is exactly that native fragment over the
   already-blurred world. Alpha-tested holes reveal blurred world; translucent
   fragments use the engine's normal blend over blurred world.
4. First-person motion blur consumes only completed-world color, coherent
   world depth, the restored unjittered world camera, and the previous
   consecutive world camera. It does not request or sample first-person depth.
5. Unknown camera mode fails closed. A first/third-person transition primes a
   new temporal sequence and cannot turn the camera jump into a capped blur.
6. Third-person frames retain the existing late motion-blur route and depth
   history behavior. This plan makes no third-person quality claim.
7. The primary and retry paths are target- and epoch-exact, execute at most
   once per frame, use `try_lock` only, and restore all D3D9 state and
   attachments before native rendering continues.
8. Disabled, stationary, first-frame, cut, invalid-camera, and below-threshold
   frames perform no motion-blur color copy and no motion-blur draw.

## Scope boundaries

In scope:

- first-person render-boundary scheduling and one pre-first-person retry;
- camera-mode routing and transition invalidation;
- removal of first-person reprojection, depth, shader, configuration, and menu
  contracts from motion blur;
- scene-post pass accounting that excludes motion blur in first-person mode;
- resource, reset, failure, test, performance, and documentation updates
  required by those changes.

Out of scope:

- third-person player identification or coverage masks;
- changes to third-person history rejection or its HLSL equations;
- new native hooks, D3D device-vtable hooks, or geometry-draw interception;
- changes to ambient occlusion, depth of field, TAA, atmosphere, native PBR,
  or external shader algorithms;
- changing global shutter, quality, maximum-path, or minimum-velocity tuning;
- treating a zero first-person strength as the fix.

## Proven engine and OMV contract

The following facts are already established and do not require new engine
research:

- `Main::RenderWorldSceneGraph @ 0x00873200` completes before
  `Main::RenderFirstPerson @ 0x00875110` at the supported main render callers.
- OMV's `RenderWorldSceneGraph` detour already filters the primary world phase
  with `scene_graph_phase == 0` and runs after the original world function.
- At that return boundary, current RT0 is the completed world target. OMV
  publishes or resolves coherent world depth and completes its world TAA and
  atmosphere transaction there.
- The live world camera jitter guard has been dropped before those consumers,
  and `fnv_world_camera_frame` provides the persistent unjittered output
  camera used by existing motion reprojection.
- The two native main-render chains call `RenderFirstPerson` only after the
  world function returns. The engine activates its rendered-texture argument
  inside `RenderFirstPerson`; OMV must not pre-bind that argument.
- OMV's existing world-pipeline retry proves the safe retry shape: at
  `RenderFirstPerson` entry, compare current epoch, pending target, rendered
  texture color-surface identity, and current RT0, then operate on current RT0
  without binding the engine texture.
- `PlayerCharacter + 0x64C` is already read through
  `backend::fnv_third_person_view`. Exact `0` means first person, exact `1`
  means third person, and other values are rejected.

Primary evidence is indexed in:

- `docs/graphics_fnv_motion_blur.md`;
- `docs/graphics_fnv_depth_resolve.md`;
- `analysis/ghidra/output/perf/graphics_fnv_stage_boundary_order_deep_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`;
- `analysis/radare2/output/perf/graphics_fnv_motion_blur_player_coverage_contract.txt`.

## Current defect and why the boundary fix is required

Current first-person flow is:

1. native world rendering;
2. native first-person rendering;
3. native image-space processing;
4. OMV depth of field;
5. OMV motion blur over the combined scene.

`motion_blur.hlsl` samples first-person depth, reconstructs first-person camera
motion, selects `first_person_strength`, and feeds the receiver through the
same shutter integration as world pixels. Its layer test prevents taps from
crossing between world and weapon, but it does not preserve the weapon
receiver. The default strength is `0.2`, so the defect is the implemented
default behavior.

Returning current color for pixels classified by first-person depth is not a
complete fix. It remains dependent on complete, current first-person depth
coverage and can fail for absent external-provider depth, alpha-tested
materials, unusual view-model passes, or stale coverage. Drawing before the
first-person renderer instead uses native render ordering as the coverage
contract and covers all native materials without classifying them in OMV.

## Selected architecture

Motion blur will have two camera-mode routes:

| Camera mode | Execution boundary | Color ownership | Existing behavior |
|---|---|---|---|
| First person (`Some(false)`) | Completed world, before native first person | World and sky only | Replaced by this plan |
| Third person (`Some(true)`) | Existing `ScenePostImageSpace` position | Existing combined scene | Preserved |
| Unknown (`None`) | No draw | No color change | Fail closed |

The embedded source may retain `ScenePostImageSpace` as its menu/catalog
metadata because third-person execution still occurs there. Runtime scheduling
must no longer interpret that metadata as permission to execute motion blur in
first-person mode.

### First-person frame order

The required primary order in `hook_render_world_scene_graph` is:

1. call the original world renderer;
2. restore the unjittered camera;
3. publish external world depth or complete OMV coherent-world capture;
4. finish world TAA and atmosphere ownership;
5. preserve the existing optional world-color capture;
6. preserve the existing world-only AO transaction when applicable;
7. attempt first-person world motion blur on current RT0;
8. return to the native caller.

The required `hook_render_first_person` entry order is:

1. run the existing world-pipeline retry;
2. run at most one pending first-person motion-blur retry on the exact current
   world target;
3. close the motion-blur deadline;
4. call the original first-person renderer;
5. publish native first-person completion and capture first-person depth only
   for other active consumers.

Motion blur runs after the optional world-only AO primary transaction so its
input is the final world color currently available at this boundary. With the
OMV depth provider, AO retains its existing later masked phase; this plan does
not move or modify AO. Native image-space, OMV DOF, and final-color effects run
after the native first-person composition. That is an intentional ordering
change for first-person motion blur and must be covered by interaction tests.

### No late fallback

The retry deadline is immediately before the original `RenderFirstPerson`
call. If primary and retry both miss, the frame stays unblurred. Motion blur
must never compensate at scene-post, because that would reintroduce the exact
hand/weapon defect being fixed.

## Planned source ownership

| File or area | Required change |
|---|---|
| `omv/src/fnv_render.rs` | Invoke the primary post-world entry after existing world transactions; invoke the exact-target retry before the original first-person call; close the deadline on every exit. Add structural ordering tests. |
| `omv/src/runtime.rs` | Own camera-mode routing, pending/applied epoch-target state, the first-person post-world D3D transaction, scene-post exclusion, color-graph accounting, device lifecycle, and bounded diagnostics. |
| `omv/src/effects/motion_blur.rs` | Reduce shared temporal preparation and the non-history shader ABI to world data; expose explicit first- and third-person routes; preserve third-person depth history; add deterministic regressions and budgets. |
| `omv/shaders/embedded/motion_blur.hlsl` -> `motion_blur_world.hlsl` | Rename and convert the non-history variant to world-only reconstruction and sampling so its ownership is unambiguous. |
| `omv/shaders/embedded/motion_blur_third_person.hlsl` | Preserve the current algorithm and history contract. Only shared comments or ABI wiring may change. |
| `omv/src/config.rs` | Remove active `first_person_strength`, accept old files, remove the obsolete key when saving, and update config tests. |
| `omv/src/shaders.rs` | Remove the obsolete menu option and sync path, update descriptions and phase tests, and retain third-person catalog ordering. |
| `omv/config/omv.toml` | Remove the motion-blur first-person strength key and document the split boundary. Do not remove the unrelated DOF control with the same key name. |
| `docs/graphics_fnv_motion_blur.md` | Replace planned first-person language with the implemented contract, exact ordering, resource costs, validation evidence, and remaining third-person limitation. |

No change is planned for `omv/src/hooks.rs`, geometry hooks, the D3D device
vtable, or player-node ownership.

## Detailed implementation plan

### 1. Add regressions before changing behavior

Add a deterministic composition fixture that models:

- a moving world color/depth row;
- an opaque first-person receiver over that world;
- alpha-tested holes;
- representative translucent first-person coverage;
- the old post-first-person blur as a negative control;
- the new pre-first-person world blur followed by native composition.

The negative control must measurably change the opaque weapon color. The fixed
model must preserve opaque native fragments exactly, expose blurred world only
through rejected/transparent coverage, and reproduce the ordinary alpha blend
over blurred world. This test establishes regression power instead of merely
checking a source string.

Add structural tests that initially fail against current scheduling:

- the primary motion-blur call occurs after world depth/world-pipeline work and
  after the existing post-world AO call, but before the world detour returns;
- the retry occurs after `retry_before_first_person` and before the original
  first-person call;
- no motion-blur apply call exists after the original first-person call;
- first-person mode cannot prepare or draw the scene-post motion-blur stage;
- retry matching rejects wrong epoch, zero target, rendered-texture mismatch,
  current-RT0 mismatch, already-consumed work, unknown mode, and third person.

Keep the current camera, cut, depth-edge, viewport, packed-depth, shader
compilation, and instruction-budget tests. Rename tests that imply the current
first-person layer branch is desired.

### 2. Remove the obsolete user contract

Delete `first_person_strength` from `MotionBlurConfig`, sanitization, defaults,
menu schema, menu synchronization, embedded source bindings, and saved output.
The four retained controls are:

- quality;
- shutter angle;
- maximum blur pixels;
- minimum velocity pixels.

Serde's legacy input path must continue to accept a persisted
`first_person_strength` key without failing configuration load. Saving the
configuration must explicitly remove that key from the motion-blur table so a
successful save performs one-way cleanup. Tests must distinguish the obsolete
motion-blur key from DOF's still-valid `first_person_strength` key.

Update the in-game description to state that the effect blurs camera motion in
the world and keeps first-person geometry outside the shutter pass. Do not
offer zero strength as a compatibility switch: exclusion is invariant.

### 3. Make the non-history shader world-only

Convert the shader currently selected by `third_person == false` into an exact
world-only shader:

- remove `FirstPersonDepth : s2`;
- remove current and previous first-person frustum/depth/transform constants
  `c10..c16`;
- remove first-person availability/reversed-depth flags;
- remove receiver classification and the first-person reprojection branch;
- remove per-tap first-person classification and depth reads;
- reconstruct geometry and sky only from world depth and world camera rows;
- retain the accepted shutter direction, viewport clipping, soft velocity
  activation, depth discontinuity rejection, trapezoidal weights, alpha
  preservation, and compile-time 5/7/9 sample tiers.

Rename the file to `motion_blur_world.hlsl`, use world-specific names in Rust
(`WORLD_SHADER`, `world_*`, not `first_person_*`), update cache source labels,
and increment the shader contract revision. Do not alter third-person history
tolerance or filtering as part of this work.

Simplify Rust binding accordingly:

- never bind sampler 2 for motion blur;
- upload the existing world registers `c0..c9` only;
- set third-person history flags at their existing dedicated register rather
  than uploading zero-filled former first-person registers;
- clear every sampler actually bound by the selected variant;
- update shader-source and bytecode assertions to reject first-person symbols,
  samplers, and registers in every world variant.

Preserving the third-person history register number is preferred over
renumbering the third-person ABI. It confines the cleanup to data that is
actually obsolete and avoids an unrelated third-person shader change.

### 4. Split temporal preparation by explicit route

Replace the implicit `frame_inputs.third_person_view == Some(true)` branch with
an explicit internal route, for example:

```text
MotionBlurView::FirstPersonWorld
MotionBlurView::ThirdPersonWorld
```

The caller selects a route only after validating exact camera mode.
`MotionBlurTemporalState` then retains:

- previous world camera and capture epoch;
- last sanitized global motion-blur configuration;
- last target dimensions;
- last exact view route.

Remove `previous_first_person`, `current_first_person`,
`first_person_reprojection`, first-person reversed depth, first-person depth
availability, and first-person maximum-motion contribution.

Changing route, dimensions, or configuration resets the world camera pair.
This makes the first frame after a first/third-person transition a no-draw
prime frame. Epoch gaps and camera cuts retain their current rejection.

Preparation behavior remains route-specific:

- first-person: return no draw packet on first/stationary/rejected frames;
- third-person: retain a record-only packet when blur is not requested so the
  packed world-depth history continues to advance exactly as it does now.

Expose separate preflight names or an explicit route argument. Publicly visible
module APIs must document which boundary owns each route, which calls advance
temporal state, and why scene-post may never substitute for a missed
first-person boundary.

### 5. Add the primary completed-world transaction

Add a documented `pub(crate)` runtime entry dedicated to first-person motion
blur after world rendering. It must use `RUNTIME.try_lock`; it must not block.
Inside the locked runtime:

1. reconcile the current render epoch;
2. reject master-off, provider-without-world-depth, disabled/zero effect, a
   missing enabled motion-blur source, or a previously consumed boundary;
3. read and validate exact camera mode; continue only for `Some(false)`;
4. validate current RT0, dimensions, coherent world depth, depth direction,
   and world camera;
5. advance temporal preparation before any state block, resource creation,
   color copy, or draw;
6. if no blur is requested, mark the boundary consumed without GPU work;
7. if bytecode/device shader creation is unavailable, fail closed without a
   color copy;
8. capture render attachments and the complete state block;
9. copy current RT0 into an OMV-owned texture;
10. draw the world-only motion-blur shader back to the same RT0;
11. unbind textures and restore attachments/state on both success and error;
12. publish an applied/consumed result for the current epoch and target.

Reuse the existing scene-post full-resolution copy allocation because the
post-world and later scene-post transactions are serialized and never sample
it concurrently. Do not allocate another persistent full-resolution texture.
The post-world transaction must still perform a fresh copy immediately before
its draw; the earlier optional world-color snapshot may predate AO and is not a
valid unconditional substitute.

Do not mark `ShaderPhase::ScenePostImageSpace` as applied. DOF, final color,
spatial AA, and third-party scene-post shaders still own their later phases.

### 6. Add one exact-target retry

Use a small lock-free pending token containing at least render epoch and exact
world-target identity. Also publish a lock-free admission bit whenever runtime
configuration changes. That bit is true only when the screen-effect master is
on, the active provider supplies world depth, the motion-blur source and
effect are enabled, and shutter angle and maximum path are nonzero. It lets an
unlocked primary wrapper decide whether a busy `RUNTIME` can justify arming a
retry without reading mutable configuration.

The primary entry may arm the token only for a retryable miss, such as:

- the general runtime lock was busy;
- coherent world depth was not yet published because the world-pipeline owner
  was pending;
- the runtime became available only after the primary callback.

Do not arm a retry for disabled work, an inactive admission bit, invalid camera
mode, shader compilation failure, latched device creation failure, an empty
target, or a D3D draw/restore failure. An unlocked busy primary may arm
conservatively because it cannot calculate camera velocity. Once temporal
preparation establishes first-frame, stationary, cut, or below-threshold work,
complete the boundary without a draw and clear any pending token.

At `RenderFirstPerson` entry, after the existing world-pipeline retry, validate:

- pending epoch equals the current render epoch;
- pending target is nonzero;
- the rendered-texture argument resolves to that same color surface;
- current RT0 is that same surface;
- current camera mode is still exact first person;
- the first-person motion-blur boundary has not already been consumed.

If coherent world depth is still absent and the exact target predicate passed,
retry the ordinary coherent-world capture before entering motion blur. This is
required when motion blur is the only world-depth consumer and its post-world
capture lost a nonblocking depth-owner race; the world-pipeline retry alone
does not cover that case. An already-current same-stage capture must use the
provider's existing epoch/cache behavior rather than issue a second physical
copy.

Then call the same primary transaction logic against current RT0. Never bind
the rendered-texture argument. Clear the token before calling the original
first-person function regardless of retry outcome. An outer image-space call,
Present completion, render-epoch change, master disable, configuration change,
and device reset must also invalidate stale pending and admission state.

The retry performs no logging or allocation unless it reaches the same
already-admitted D3D transaction. Counters may be added to the existing
600-frame reliability report, but no per-frame message is permitted.

### 7. Make scene-post third-person-only

At `ScenePostImageSpace`, read exact camera mode as today:

- `Some(true)`: prepare and execute the existing third-person motion-blur
  pipeline at its current position after DOF;
- `Some(false)`: exclude motion blur from preparation and drawing because the
  first-person boundary has already expired;
- `None`: reset temporal routing when the runtime lock is available and draw
  neither route.

The general phase color graph must account for this dynamic exclusion. When
first-person mode removes the motion-blur stage, subtract its logical stage and
source-pass count before target selection, skip its planned-pass entry without
decrementing the already-adjusted remaining-stage count or advancing the phase
pass index, and avoid a fallback copy caused solely by the inactive
motion-blur placeholder. This can be implemented with precomputed counts plus
a boolean admission flag; it must not allocate or rebuild pass arrays per
frame.

Add tests for these graph cases:

- motion blur is the only scene-post source in first person: no phase copy and
  no scene-post draw;
- DOF followed by inactive first-person motion blur: DOF writes directly to
  the correct final location with no safety copy caused by motion blur;
- third-person DOF plus motion blur: existing order and ping-pong count remain
  unchanged;
- an external pass after inactive motion blur: pass indices, source constants,
  and final target selection remain correct.

### 8. Specialize scene-input requirements

Change motion blur's embedded input requirement to world depth only.
First-person depth remains requested when another enabled effect requires it,
but motion blur alone must no longer cause a `DepthResolveSlot::FirstPerson`
capture after native first-person rendering.

Retain world-depth publication so the resident scene hooks and coherent depth
producer remain active. Add union tests showing:

- motion blur alone requests world depth and no first-person depth/color;
- motion blur plus DOF retains DOF's first-person requirement;
- external world-only depth remains sufficient for first-person motion blur;
- disabling the last world-depth consumer clears the published requirement.

### 9. Complete lifecycle and failure ownership

Reset or invalidate first-person route state on:

- master disable;
- effect disable or zero shutter/max path;
- configuration reload affecting motion blur;
- camera-mode transition or unknown mode;
- target dimension/format change;
- render-epoch gap;
- device loss/reset or device-pointer change;
- shader/device-object creation failure according to the existing failure
  latch contract.

The existing default-pool release path must clear the pending token, prepared
packet, reused color-copy resources, device shaders, creation-failure latch,
and temporal state. Process-owned compiled bytecode may retain its current
lifetime.

Failure policy is always visual pass-through:

- do not modify RT0 unless the full copy/draw transaction is admitted;
- restore state and attachments after a partially started transaction;
- never suppress or delay the original world or first-person engine call;
- never call motion blur late;
- bound repeated warnings using the existing log limits.

## D3D9 pass contract after the change

The first-person world pass remains one full-resolution draw. It uses:

| Item | Contract |
|---|---|
| Input color | Fresh same-size/same-format copy of completed current RT0 immediately before draw |
| Input depth | Coherent current world depth, point sampled at owned texel centers |
| Output | The same completed-world RT0 |
| Shader model | `ps_3_0`, 5/7/9 compile-time sample variants |
| Color sampling | Linear clamp, explicit sRGB state matching the existing effect contract |
| Depth sampling | Point clamp, no first-person sampler |
| Geometry | Existing D3D9 half-pixel-correct fullscreen quad |
| Depth/stencil | Disabled for the fullscreen pass; native attachments restored afterward |
| Blend/alpha test | Disabled; source alpha preserved by the shader |
| Viewport/scissor | Exact full target; explicit state, no inherited scissor |
| Other state | Existing complete motion-blur pipeline state plus attachment/state-block restoration |

No render-target feedback is allowed. The source copy must be unbound before
it can later become a render target in another phase. Samplers unused by the
selected variant must be clear on exit.

## Static performance budget

For an accepted first-person moving frame:

- one full-resolution color copy;
- one full-resolution fullscreen draw;
- 5, 7, or 9 scene-color samples;
- one center world-depth sample plus at most one world-depth sample per
  non-center shutter tap;
- zero first-person-depth samples;
- zero packed-depth-history capture or history samples;
- zero routine allocations, blocking locks, file I/O, shader compilation, or
  per-frame logging.

First, stationary, cut, invalid, unknown-mode, below-threshold, disabled, and
unprepared frames perform zero effect color copies and draws.

The move can no longer share its initial copy with later DOF/scene-post work in
first-person mode, so a frame containing both first-person motion blur and a
later scene-post effect may perform a second phase color copy later. This is an
explicit correctness cost. Reusing the existing allocation avoids additional
persistent full-resolution memory, but it does not remove that bandwidth.
Static counters and tests must report the two transactions honestly. Do not
claim a runtime performance improvement from removing first-person depth reads
without vendor timing evidence.

When motion blur is the only consumer of first-person depth, the change also
removes one physical first-person depth capture. If another enabled effect
requires that depth, the shared capture remains.

## Required automated validation

### Configuration and menu

- legacy motion-blur `first_person_strength` parses without error and is
  ignored;
- saving removes only that legacy key;
- the shipped config and menu expose exactly four motion-blur controls;
- control round trips and sanitization retain current accepted ranges;
- descriptions state world-only first-person ownership.

### Shader and ABI

- compile all three world variants and all three unchanged third-person
  variants as `ps_3_0`;
- inspect bytecode for current instruction, texture, flow, sampler, constant,
  and register budgets;
- reject any first-person sampler, camera constant, reprojection, or strength
  symbol in the world source;
- preserve accepted output finiteness, alpha, borders, diagonal continuity,
  depth edges, sky rotation, translation parallax, and sample direction;
- prove the old implementation changes the opaque foreground negative control
  and the fixed composition does not.

### Temporal and route state

- first frame primes without GPU work;
- consecutive first-person world cameras produce a draw packet;
- first-to-third and third-to-first transitions prime new sequences;
- unknown mode, epoch gap, resize, config change, invalid camera, and cut reset
  or reject as specified;
- first-person frames never create or record packed depth history;
- third-person record-only and history-continuity tests remain unchanged.

### Hook and runtime scheduling

- primary and retry call order is structurally exact;
- primary/retry target and epoch predicates have positive and negative cases;
- duplicate world callbacks cannot draw twice;
- a busy primary can retry once before native first person;
- a missed retry never executes at scene-post;
- master-off and unsupported-provider paths call native rendering unchanged;
- no rendered-texture pre-bind, D3D device-vtable hook, or new executable hook
  is introduced.

### Resource and state behavior

- zero-work preflight precedes state block, allocation, copy, and draw;
- the post-world path reuses but freshly populates the existing color-copy
  allocation;
- format/dimension changes recreate resources safely;
- device reset clears pending/applied route state and device objects;
- all target slots, depth/stencil, shaders, streams, viewport, scissor, render
  states, samplers, and textures restore after success and injected failure;
- copy/draw counters match the static budget.

### Affected suite and build

After focused tests pass, run exactly:

```bash
cargo fmt --all
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
git diff --check
```

Inspect the final diff for accidental changes to DOF first-person strength,
third-person motion-blur math, unrelated shader phases, or submodules.

## Runtime acceptance matrix

Ordinary playtesting is still required because static tests cannot prove live
engine composition or GPU timing. Test at minimum:

- first-person idle, walking, sprinting, jumping, turning, and rapid 180-degree
  camera motion;
- weapon draw/holster, aim-down-sights, scopes, reloads, firing, muzzle flash,
  melee, unarmed, and no-weapon states;
- opaque, alpha-tested, emissive, translucent, and modded view-model materials;
- interior/exterior transitions, sky-heavy views, water, foliage, fog, and
  bright high-contrast silhouettes;
- first/third-person toggles during idle and camera motion;
- Pip-Boy, VATS, pause/loading transitions, screenshots, alt-tab, resize, and
  device reset;
- OMV and external Depth Resolve providers;
- TAA on/off, both AO families, native/OMV DOF combinations, atmosphere,
  bloom/color grading, each spatial AA option, and representative external
  scene shaders;
- Windows NVIDIA as the mandatory reported-defect platform, plus AMD/Intel or
  Proton/DXVK compatibility coverage when available.

Acceptance requires visibly blurred world motion with sharp native
first-person geometry, no silhouette color leak, no leading double image,
no first-frame/camera-toggle smear, no new state corruption, and no material
frame-time regression beyond the documented extra phase-copy case. Runtime
timing claims require measurements; static work counts alone are not FPS
evidence.

## Implementation sequence and stop gates

Implement in this order:

1. Add the negative-control composition, route, retry-predicate, and scheduling
   tests. Confirm they reject current behavior.
2. Remove the obsolete config/menu contract and add migration tests.
3. Simplify the world shader and CPU ABI; compile and budget every variant.
4. Split temporal preparation into explicit first- and third-person routes.
5. Add the post-world primary transaction and prove state restoration.
6. Add the one exact-target pre-first-person retry and deadline closure.
7. Gate scene-post execution and correct color-graph stage accounting.
8. Specialize input requirements and remove motion-blur-only first-person depth
   capture demand.
9. Complete reset/lifecycle paths, module documentation, public API docstrings,
   and bounded diagnostics.
10. Run the focused tests, full OMV test suite, release build, diff inspection,
    and ordinary runtime matrix.

Stop and revise the design if any implementation would require:

- binding the `RenderFirstPerson` rendered-texture argument before the native
  function activates it;
- drawing after native first-person composition;
- accepting unknown camera mode;
- blocking a render callback;
- adding a new executable or D3D device-vtable hook;
- using first-person depth as the correctness mask;
- changing third-person blur equations to make the first-person tests pass.

## Evidence classification

Proven facts are the current shader/config behavior, current source scheduling,
validated camera-mode read, current target and depth ownership, native caller
order, and existing exact-target retry contract cited above.

The selected camera-mode split, reuse of the existing color-copy allocation,
retry outcome policy, and dynamic color-graph accounting are implementation
decisions derived from those facts. They require the stated tests.

Live preservation of every modded first-person material and Windows GPU
performance remain runtime acceptance items. No such result is claimed by this
plan.

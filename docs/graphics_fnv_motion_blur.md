# FNV motion blur

The first-person world-only correction is implemented. Static validation and
the initial load-to-gameplay playtest pass. The playtest confirmed that the
motion-blur change works in ordinary first-person use; the extended visual
scenario matrix below remains recommended. Third-person player-body
exclusion is deliberately unchanged and remains a known defect because OMV has
no proven semantic player-coverage input at its retained late boundary.

The implementation follows
`docs/graphics_fnv_motion_blur_first_person_fix_plan.md`. The research and
rejected alternatives later in this document are retained as historical
evidence; where they describe the old combined first-person shader or a future
first-person fix, this current-contract section supersedes them.

## Current first-person contract

Motion blur may modify completed world color, but never first-person hand or
weapon color. OMV establishes that ownership structurally:

1. `Main::RenderWorldSceneGraph @ 0x00873200` returns with completed world RT0
   still active.
2. `omv/src/fnv_render.rs` publishes/resolves coherent world depth, completes
   the focused world pipeline, captures world color when another effect needs
   it, and applies world-only AO when applicable.
3. It then calls the dedicated first-person motion-blur entry. The runtime
   validates exact first-person mode, current epoch, current RT0, dimensions,
   world depth convention, and world camera before temporal state advances.
4. An accepted moving frame copies current RT0 once and draws the world-only
   shader back to that same target under a complete D3D9 state/attachment
   transaction.
5. Native `Main::RenderFirstPerson @ 0x00875110` runs afterward. Its ordinary
   depth, alpha-test, and blend behavior overlays hands and weapons without
   those pixels ever entering motion-blur input.

If the runtime or coherent-depth owner is busy at world return, a lock-free
token records the exact render epoch and RT0 identity. `RenderFirstPerson`
entry permits one retry only after the existing focused-world retry and only
when all of these remain equal: token epoch, current epoch, token RT0, current
RT0, the rendered-texture argument's color surface, and exact first-person
camera mode. Missing world depth gets one ordinary coherent-world capture
attempt, which uses the provider's existing same-stage epoch cache. The token
is cleared before native first-person rendering regardless of retry outcome.
Image-space entry, Present completion, epoch change, configuration publication,
master disable, and device-resource release also invalidate it.

A miss is visual pass-through. OMV never binds the `RenderFirstPerson`
rendered-texture argument as a speculative target, never delays the original
engine call, and never applies first-person motion blur later in scene post.
First, stationary, camera-cut, route-change, resize, and sub-threshold frames
advance or reset CPU temporal state as appropriate without a color copy or
draw.

## Current third-person contract and limitation

Exact third person retains the existing `ScenePostImageSpace` route after OMV
depth of field. It reconstructs camera motion from world depth and validates
reprojected samples against a packed previous-world-depth texture. This rejects
disocclusions and incompatible depth, but matching depth is not semantic object
identity. A player-body pixel whose history depth agrees can still blur. Fixing
that requires a separately proven third-person coverage carrier and is outside
this first-person change.

At scene post the camera mode is routed explicitly:

- `Some(true)` prepares and executes the retained third-person pass;
- `Some(false)` removes motion blur from the phase graph because its legal
  world boundary has expired;
- `None` resets temporal routing and executes neither motion-blur path.

Dynamic first-person exclusion subtracts the motion-blur logical writer and
source-pass count before output selection. The planned-pass entry is skipped
without advancing pass index or remaining-stage count. Therefore motion blur
alone causes no scene-post copy, DOF before inactive motion blur writes directly
to the engine target, and a following pass retains its original constants and
final-target selection.

## Configuration and source ownership

The active controls are:

| Control | Range/default | Contract |
|---|---:|---|
| `enabled` | `true` | Disabled performs no effect preparation, allocation, copy, or draw. |
| `quality` | `performance`, `high`, `ultra`; `high` | Fixed 5, 7, or 9-tap variants. |
| `shutter_angle` | `0..360`; `360` | Exposure fraction; zero is a no-work configuration. |
| `max_blur_pixels` | `0..48`; `36` | Hard output-pixel path bound; zero is no-work. |
| `minimum_velocity_pixels` | `0..2`; `0.15` | CPU no-draw threshold with smooth shader activation above it. |

`NVSEPlugin_Load` preserves the established process-owned shader-preparation
requests and existing scene-input publication. It does not activate the newly
added first-person callback route: `ScreenShaderRuntime::configure` closes the
route-specific admission bit, and `apply_initial_depth_activation` opens and
publishes it at DeferredInit before the resident scene hooks are installed. A
failed deferred installation closes only that admission bit; a retry reopens
it without changing established consumers or effect preparation.

The motion-blur `first_person_strength` field remains in `MotionBlurConfig`, the
shipped TOML, preset schema 1, and saved output solely as compatibility data.
It is deliberately absent from menu metadata, `MotionBlurSettings`, temporal
sequence identity, shader constants, and shader source. Changing it therefore
round-trips but cannot alter an image, draw decision, or camera history. Keeping
the frozen field also preserves the accepted `GraphicsMenuConfig` layout and
avoids introducing a schema migration on the preset worker that starts during
`NVSEPlugin_Load`. Depth of field's independent field with the same name is
unchanged and remains active.

Source ownership is:

- `omv/src/fnv_render.rs`: proven world/first-person hook order and retry
  deadline;
- `omv/src/runtime.rs`: admission publication, epoch/target token, D3D9
  transaction, dynamic scene-post graph, and lifecycle;
- `omv/src/effects/motion_blur.rs`: explicit view routes, temporal camera
  ownership, cut rejection, shader preparation, binding, budgets, and CPU
  reference tests;
- `omv/shaders/embedded/motion_blur_world.hlsl`: world-only first-person-route
  exposure filter;
- `omv/shaders/embedded/motion_blur_third_person.hlsl`: retained third-person
  depth-history filter;
- `omv/shaders/embedded/motion_blur_depth_history.hlsl`: packed depth record;
- `omv/src/config.rs`, `omv/src/shaders.rs`, and
  `omv/presets/schema_v1.fields`: persistence, active menu schema, and the
  frozen compatibility boundary.

## Current shader and D3D9 contract

The first-person-route shader uses only `SceneColor : s0`, point-sampled
`WorldDepth : s1`, and world constants `c0..c9`. Sampler 2 and constants
`c10..c16` from the removed view-model route are never bound or uploaded;
sampler 2 is explicitly cleared because D3D9 texture state persists. The
third-person history flags remain at `c17`, avoiding an unrelated ABI change.

The first-person transaction reuses the scene-post primary color texture but
does not allocate its scratch texture unless the later graph needs it. It
captures all native attachments and a complete state block, detaches MRT/depth
attachments before changing RT0, uses the existing half-pixel-correct
fullscreen quad, explicitly owns viewport/samplers/blend/depth/stencil/scissor/
multisample/sRGB/color-write state, clears bound textures, and restores native
attachments and state on success or error. The color copy is fresh and occurs
after early AO; the older optional world-color snapshot is not substituted.

An accepted first-person moving frame is bounded to one full-resolution color
copy, one fullscreen draw, 5/7/9 color taps, one center world-depth fetch plus
at most one depth fetch per exposure tap, zero first-person-depth fetches, and
zero packed-history work. Motion blur alone requests world depth but no
first-person depth or world-color snapshot. Third person retains one packed
depth-history draw plus its existing history samples.

## Validation and runtime acceptance

Static tests cover exact hook ordering, retry token mismatches, world-only
input requirements, scene-post graph subtraction, production shader variants
and instruction/texture budgets, absence of the old sampler/constants, route
and epoch resets, camera cuts, depth/sky edges, and a negative-control
composition test that smears a weapon only when blur is incorrectly applied
after native first-person color. Compilation proves syntax and bounded work;
it does not prove the runtime image.

On 2026-08-10, all 460 OMV tests passed for
`i686-pc-windows-gnu`, including the schema-1 compatibility and startup
admission regressions, and the supported optimized OMV release target built
successfully. A subsequent user playtest loaded through the previously failing
BaseObjectSwapper startup interval and confirmed working motion blur in game.

Ordinary playtesting must confirm sharp first-person hands/weapons (including
iron sights, alpha-tested geometry, translucency, water, sky silhouettes, and
camera motion), preserved world blur, no stale retry across transitions or
resets, and correct state restoration. Test native D3D9 and DXVK where
available. The third-person player-body case remains expected to fail until a
separate semantic-coverage implementation exists.

## Historical pre-fix research

The remaining analysis documents the defect that motivated the implemented
first-person route and the still-open third-person ownership problem.

## Pre-fix native phase and ordering

The supported executable is `fnv_reverse/FalloutNV.exe`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, image base `0x00400000`, size `16,084,808`, timestamp
`0x4E0D50ED`.

OMV uses the established outer
`ImageSpaceManager::ProcessImageSpaceShaders @ 0x00B55AC0` hook. Motion blur
currently has the fixed `scene_post_image_space` phase:

1. native image-space processing;
2. OMV depth of field, when applicable;
3. OMV motion blur;
4. final Bloom/halation and color grading;
5. chromatic aberration and spatial anti-aliasing;
6. loose final-image shaders and later UI ownership.

This placement lets the shutter integrate the visibly focused scene while
keeping final grading, AA, and UI stable, but it also makes the scene-color
input contain both categories that must stay sharp. First-person hands/weapons
have already been composited before `ProcessImageSpaceShaders`, and the
third-person body was already rendered as ordinary world geometry. Depth can
separate the first-person layer, but world depth has no semantic distinction
between terrain, an NPC, and the player body.

The established phase and depth evidence remains in:

- `analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_depth_independence_contract_audit.txt`;
- `docs/graphics_fnv_aa_performance_research.md`.

The executable also proves the usable replacement boundary:

- `Main::RenderWorldSceneGraph @ 0x00873200` returns before
  `Main::RenderFirstPerson @ 0x00875110` at both supported main callers;
- OMV already owns that world-return boundary in `omv/src/fnv_render.rs`;
- the completed world target and coherent world depth are available there;
- applying motion blur there lets later first-person rendering overwrite the
  world result naturally.

The player-coverage extension is documented in
`analysis/radare2/output/perf/graphics_fnv_motion_blur_player_coverage_contract.txt`.

### Camera-mode gate

The third-person correction uses a separately proven native field on the same
supported executable:

- the player singleton is `*(PlayerCharacter**)0x011DEA3C`;
- the camera-mode byte is `PlayerCharacter + 0x64C`, where `0` is first person
  and `1` is third person;
- `0x00950110` compares that byte to its Boolean argument and stores the
  argument's inverse back to `+0x64C`;
- caller `0x0058D025` obtains the player singleton and calls `0x00950110` with
  argument `1`, cohering with a `SetFirstPerson(true)` transition;
- direct reads of the same byte also occur at `0x0093FE86`, `0x0094061C`,
  `0x00941FA1`, `0x00942AFA`, `0x00943131`, `0x0094A0ED`, `0x0094AF64`,
  `0x0094B110`, and `0x0094B681`.

The byte is read through the validated Win32 memory-range wrapper each relevant
scene-post frame. Values other than exact engine Booleans are rejected. Both
proven first person (`Some(false)`) and third person (`Some(true)`) are
accepted. An unavailable or invalid value fails closed before temporal
preparation, state-block capture, color copy, or drawing.

NVR independently selects a first- or third-person MotionBlur profile through
`TheCameraManager->IsFirstPerson()` in
`.research/TESReloaded10-master/src/effects/MotionBlur.cpp`, and its shipped
defaults enable the first-person profile while disabling its unmasked
third-person profile. NVR's fullscreen shader has no player mask either; its
disabled third-person profile avoids rather than solves body exclusion. This is
reference behavior only, not OMV's implementation: OMV uses the same D3D9
depth-history path on every GPU.

## Pre-fix inputs, output, and shader ABI

The following is the current, defective ABI. All three shaders are `ps_3_0`,
entry point `Main`, on one full-resolution D3D9
triangle strip. The two blur families use a compile-time
`MOTION_BLUR_SAMPLES` value of 5, 7, or 9.

| Register | First-person blur input |
|---|---|
| `s0` | Point-copied current scene color, sampled linearly and clamped. |
| `s1` | Current owned world-depth resolve, sampled at point-filtered texel centers. |
| `s2` | Optional current owned first-person-depth resolve, sampled at point-filtered texel centers. |
| `c0` | Output width, height, and reciprocal dimensions. |
| `c1` | Shutter fraction, maximum path pixels, minimum velocity, and first-person strength. |
| `c2` | World/first-person reversed-depth flags and first-person input/pair availability. |
| `c3..c4` | Current world frustum and near/far planes. |
| `c5..c7` | Current-world to previous-world view transform rows. |
| `c8..c9` | Previous world frustum and near/far planes. |
| `c10..c11` | Current first-person frustum and near/far planes. |
| `c12..c14` | Current-first-person to previous-first-person view transform rows. |
| `c15..c16` | Previous first-person frustum and near/far planes. |

The third-person shader uses `s0`, `s1`, and world constants `c0..c9` from the
same ABI. `s3` is the previous packed world-depth history; `c17` reports
history availability and its depth convention. There is no player-mask
sampler, stencil contract, engine object ID, or player coverage constant. The
history writer reads current world depth at `s0`, uses dimensions at `c0`, and
writes packed raw depth to one full-resolution `A8R8G8B8` texture.

The output replaces RGB on the current phase render target and preserves the
current alpha exactly. Dimensions and format match that target. The shared
phase color texture has the same dimensions and format and receives a
point-filtered `StretchRect`; this also supplies the readable non-MSAA source
when the phase target is multisampled. The pass writes with sRGB decode/write
disabled, matching OMV's established numeric scene-target space. It makes no
unsupported claim that this legacy target is photometrically linear.

The pass explicitly sets its vertex shader/FVF, triangle topology, viewport,
RT0 and unused MRTs, depth-stencil surface, depth/stencil tests and writes,
culling, scissor, blend, alpha test/coverage, color mask, multisample state,
sRGB state, and every used sampler state. The outer phase state block restores
native state. Inputs are unbound after drawing, so the next target copy cannot
feed back through a still-bound texture.

## Pre-fix coordinate, depth, and reconstruction contract

The fullscreen quad uses D3D9's `-0.5` pixel-center positions. Every point
depth lookup first maps the requested UV to the actual source texel center.
Color remains linearly sampled along the exposure path. No derivative,
implicit-LOD, noise, or frame-varying sample rotation is used, so the
two-triangle diagonal and subpixel motion cannot change the reconstruction
equations.

World and first-person depth use their independently captured near/far and
standard/reversed convention. Geometry must lie strictly between normalized
depth endpoints. Standard-depth clear sky is `1`; reversed-depth clear sky is
`0`. The opposite endpoint and non-geometric values preserve current color.
The linearization equations are tested after D16- and D24-like quantization.

For geometry, the current view ray is multiplied by linear depth and transformed
into the previous camera basis. Projection through the previous frustum yields
the current-to-previous screen path. The path is multiplied by
`shutter_angle / 360`, bounded by `max_blur_pixels`, softly activated above
`minimum_velocity_pixels`, and clipped to valid texel-center viewport bounds.

Sky uses the same current/previous rotation but omits translation. Walking
therefore cannot smear infinitely distant sky; camera rotation still can.
First-person pixels currently use only the first-person camera pair. A missing
or stale first-person pair never falls back to world motion. A valid pair and
nonzero `first_person_strength` intentionally sends hand/weapon color through
the exposure filter; that is the direct first-person defect.

Third-person world geometry additionally compares the predicted previous
view-space depth with packed depth sampled at the reprojected coordinate. The
relative tolerance begins at 3% and grows to at most 10% for long motion.
Missing history, sky/invalid history at a geometry pixel, and material depth
mismatch all preserve current color. A matching prior player depth passes the
same test and is blurred. Sky retains rotation-only blur without a history
comparison because clear depth contains no surface to validate.
Twenty-four-bit RGB packing preserves either standard or reversed raw depth;
deterministic tests cover the round trip over representative FNV distances.

## Pre-fix exposure filter and edge protection

Samples run from the current pixel toward its previous-frame position. This is
a causal trailing shutter, rather than a symmetric blur that invents a leading
trail without a future frame. Trapezoidal half weights on both exposure
endpoints approximate a uniform interval without over-weighting the present or
oldest sample. All accepted weights are normalized, and the current sample is
always retained, so rejected taps cannot darken an edge.

Each tap classifies first-person versus world before accepting color:

- first-person and world samples never cross;
- sky and geometry never cross;
- invalid endpoints never contribute;
- geometry compares relative linear depth, which remains meaningful over
  FNV's large near/far ratio;
- the relative tolerance begins at 2.5% and grows only modestly with a long
  shutter path, preserving shallow/grazing surfaces while rejecting true
  foreground/background discontinuities.

This layer isolation prevents one layer from sampling deeply into the other;
it does not exclude the first-person receiver. The shader first chooses the
first-person branch and then integrates samples from that same layer. Likewise,
the third-person path's depth continuity is not a semantic player mask.

The color sample is deliberately still bilinear. A subpixel sample at a
silhouette can contain the bilinear footprint of both sides, but later
wrong-layer taps are rejected. Point-sampling color would remove that footprint
at the cost of visible stepping and banding, especially in the five-tap tier.
The deterministic thin-feature negative control verifies that the protected
filter retains the foreground while a naive gather averages it away.

## Pre-fix root-cause analysis

### Current frame flow

The current render flow is:

| Order | Owner | Relevant contents |
|---:|---|---|
| 1 | `Main::RenderWorldSceneGraph @ 0x00873200` | World color/depth; in third person this already includes the player body. |
| 2 | `Main::RenderFirstPerson @ 0x00875110` | In first person, hands/weapons are composited and their independent depth is captured. |
| 3 | `ImageSpaceManager::ProcessImageSpaceShaders @ 0x00B55AC0` | Native image-space processing consumes the combined scene. |
| 4 | OMV `scene_post_image_space` | Depth of field, then motion blur, then later OMV scene effects. |

`EmbeddedEffectsConfig::phase_for_kind` fixes motion blur to
`ShaderPhase::ScenePostImageSpace`. `build_frame_inputs` publishes camera mode
only in that phase, and `phase_has_applicable_work` prepares the temporal packet
there. The color graph copies the current combined scene and supplies it as
`SceneColor` to `MotionBlurEffect::draw`.

This means the full-screen pass receives a color texture in which world and
foreground are already composited. Depth/layer tests can decide which taps to
accept, but preserving a receiver requires a reliable ownership mask.

### First-person root cause

The first-person defect is direct and unconditional when its configured path
is active:

1. `MotionBlurConfig::default` sets `first_person_strength = 0.2`.
2. `motion_blur_source` exposes that value as a menu option from 0 through 1.
3. `MotionBlurTemporalState::prepare_frame` maintains
   `previous_first_person`, constructs `first_person_reprojection`, and includes
   its scaled maximum motion in the CPU draw decision.
4. `motion_blur.hlsl` classifies a receiver as first person from `s2`.
5. With a valid camera pair and strength above zero, lines 196-220 reconstruct
   the previous first-person position and set `layerStrength` to that strength.
6. The common exposure loop then samples `SceneColor` along that path and
   writes the blurred result over the hand/weapon pixel.

The layer-depth test prevents a hand tap from crossing into ordinary world
depth. It does not preserve the hand. Setting the slider to zero happens to
return current color, but world-only ownership must not depend on a user value.
Changing the default alone would leave persisted nonzero values and the public
contract capable of recreating the defect.

### Third-person root cause

The third-person shader receives only current scene color, current world depth,
previous packed world depth, and camera transforms. It has no semantic input
that identifies the player.

For one current geometry pixel it:

1. reconstructs the current position from world depth;
2. transforms that position with camera-only reprojection;
3. reads previous world depth at the resulting UV;
4. accepts the receiver if predicted and sampled previous depth differ by no
   more than the motion-dependent 3-10% tolerance;
5. integrates current scene color along the exposure path.

This test answers “was compatible geometry present here last frame?” It cannot
answer “is this geometry the player?” A stationary player, a slowly animating
body, or a player surface whose camera-reprojected location still overlaps the
previous body can match the tolerance and be blurred. Tightening the tolerance
only changes how often this happens; no tolerance can make depth encode object
identity.

The history therefore remains useful for disocclusion rejection, but it is not
a player-exclusion mechanism and must not be documented or tested as one.

### Why the existing tests passed

The reference-image fixture puts the player at depth 80 at one pixel, applies a
two-pixel camera motion, and leaves depth 1000 at the reprojected location. The
history mismatch correctly returns current color. That is a valid
disocclusion-style negative control, but it assumes the condition required for
rejection.

The nearby unit test even proves the opposite branch:
`previous_surface_matches(80, Some(81), 12)` returns true. It labels that input
as a static world surface, but the function has no information that would stop
the same numbers from representing a player surface. The missing regression is
a player-labeled pixel with matching prior depth; production currently blurs
it.

### Engine ownership available to a correct fix

The executable and existing OMV hooks provide two useful contracts:

- first-person ownership is temporal: `RenderFirstPerson` is a later native
  overlay, so a post-world effect is naturally overwritten by hands/weapons;
- third-person ownership is semantic: the player singleton at `0x011DEA3C`
  provides its ordinary world root through
  `PlayerCharacter::Get3D(false) @ 0x00950BB0`, and OMV's existing
  `NiDX9Renderer::RenderTriShape @ 0x00E745A0` and
  `RenderTriStrips @ 0x00E74840` hooks receive each `NiGeometry`.

`NiAVObject + 0x18` is the parent pointer. A bounded parent walk can therefore
classify whether a geometry belongs to the current player root. The root should
be read once for the primary world transaction, not by calling native code for
every geometry. This proves an identity source, not yet a complete screen-space
coverage carrier.

TESReloaded10's shadow code recursively sets `NiShadeProperty::kFirstPerson`
and `kThirdPerson` bits on the two player trees every 50 frames. That is useful
corroboration that the two trees are separate, but it also shows those bits are
mod-owned tags rather than a proven always-current engine publication. OMV
must not silently assume they remain correct across equipment changes.

### Rejected incomplete fixes

- Set the default first-person strength to zero: persisted nonzero values and
  the active shader path remain; third person is unchanged.
- Remove only the first-person shader branch: fixes opaque masked receivers at
  the current phase but does not provide exact translucent coverage and does
  nothing for the third-person body.
- Move only the full-screen pass earlier: correctly excludes first-person
  geometry, but third-person player geometry is already part of world color.
- Tighten or replace the temporal depth tolerance: changes false-positive and
  false-negative rates but cannot derive semantic ownership.
- Treat near/center-screen depth as player coverage: incorrectly protects
  walls, NPCs, and objects and fails with camera offsets, scopes, VATS, and
  unusual player poses.
- Disable third-person motion blur: avoids the visible defect by narrowing the
  requested feature instead of implementing world-only blur.
- Hook `IDirect3DDevice9` draw methods to discover the player: reintroduces the
  driver-vtable ownership and per-draw interception deliberately removed by the
  NVIDIA performance remediation.

## Original remediation analysis

This section records the combined first- and third-person end state. For the
current first-person-only implementation scope, the authoritative sequence is
`docs/graphics_fnv_motion_blur_first_person_fix_plan.md`; it deliberately
preserves the existing third-person scene-post route.

### Target architecture

Motion blur becomes a world-stage effect with one invariant:

```text
completed world color + coherent world depth + camera history
                         + optional semantic third-person player coverage
                                      |
                                      v
                              world-only blur
                                      |
                         first-person native overdraw
                                      |
                        native/OMV later image-space
```

First-person mode needs no foreground mask because the effect finishes before
the engine draws the foreground. Third-person mode requires an exact current
player coverage input. The temporal world-depth history may remain as an
additional disocclusion guard, but player coverage must reject the receiver
and every exposure tap independently of history agreement.

The implementation should be split so the proven first-person correction does
not depend on choosing an unsafe third-person carrier. Third-person blur must
fail closed until semantic coverage is current and complete: preserve the
unblurred frame for that mode rather than ship another heuristic.

Expected source ownership is:

| File/area | Planned responsibility |
|---|---|
| `omv/src/fnv_render.rs` | Arm the primary world transaction, publish the current third-person root/coverage lifetime, and invoke world-only motion blur after the original world render. |
| `omv/src/hooks.rs` | Reuse the engine-owned TriShape/TriStrips brackets for bounded player-geometry classification; do not add a D3D device-vtable hook. |
| `omv/src/runtime.rs` | Own the once-per-epoch post-world scheduler, color copy, target/state transaction, resource lifecycle, and fail-closed preflight. |
| `omv/src/effects/motion_blur.rs` | Reduce temporal state to world camera ownership, consume current semantic coverage, retain optional disocclusion history, and own deterministic tests. |
| `omv/shaders/embedded/motion_blur*.hlsl` | Collapse to world-only receiver/tap filtering and, if retained, a separate depth-history writer. |
| `omv/src/config.rs`, `omv/src/shaders.rs` | Remove active first-person strength while retaining the schema-1 compatibility leaf, update phase/menu contracts, and prevent old phase scheduling. |
| `omv/src/backend/fnv.rs` or a focused coverage module | Validate player singleton/root publication and carry `{target, dimensions, epoch, valid}` without locks or routine allocation. |
| `docs/graphics_fnv_motion_blur.md` | Replace this defect/plan status with the implemented carrier, costs, evidence, and playtest results. |

### Phase 1: lock the behavioral contract with failing tests

Add CPU/reference and source-contract tests before changing production flow:

1. A first-person receiver is bit-identical to current color for every legacy
   `first_person_strength`, including 1.
2. World pixels still blur in first-person view.
3. A player-labeled third-person receiver with matching previous depth remains
   current color. This must fail against the present reference function.
4. Exposure taps whose player-coverage bit is set contribute zero weight to a
   world receiver, preventing world-to-player color pickup at silhouettes.
5. A world pixel with matching history and no player coverage still blurs.
6. A disoccluded world pixel still returns current color when the retained
   history guard rejects it.
7. Missing, stale, wrong-size, wrong-target, or wrong-epoch player coverage
   suppresses third-person blur rather than treating the whole frame as world.
8. The motion-blur source is no longer scheduled through
   `ScenePostImageSpace`, and the post-world callback can apply it at most once
   per render epoch.

Rename existing tests that say depth history “preserves player” so they state
the property they actually prove: previous-surface mismatch rejects a receiver.
Keep the current background-mismatch fixture as a disocclusion negative
control.

### Phase 2: move motion blur to the completed-world boundary

Add a dedicated world-stage scheduler beside the existing post-world AO and
world-pipeline ownership in `omv/src/fnv_render.rs` and `omv/src/runtime.rs`.
Do not pretend this is an ordinary `ScenePreImageSpace` source if that phase's
general color graph can also run later from `ProcessImageSpaceShaders`.

The scheduler must:

- run only for primary `scene_graph_phase == 0` after the original
  `RenderWorldSceneGraph` returns;
- use the current RT0 identity already validated by world-color/depth capture;
- consume the coherent world depth and restored unjittered world camera;
- execute after OMV's world TAA/atmosphere stages that are contractually before
  first person, with an explicitly tested relative order;
- apply at most once per render epoch and use `try_lock`-only runtime access;
- retain first-frame, epoch-gap, resize, cut, zero-work, and unavailable-shader
  rejection before the scene-color copy;
- restore render targets, depth-stencil attachment, viewport, and all D3D state
  on success and every failure path;
- leave the target unchanged if preparation, copy, shader creation, or draw
  fails.

Move camera-mode publication so it is available at this boundary. Reading
`PlayerCharacter + 0x64C` is already validated and does not require waiting for
`scene_post_image_space`.

After the move, remove motion blur from the normal scene-post phase plan. The
menu may retain its ordering category, but runtime execution must have one
owner. Add source-order tests that prevent duplicate execution through the old
color graph.

This phase alone establishes exact first-person ownership: the engine's later
`RenderFirstPerson` call supplies all hand/weapon coverage by ordinary overdraw,
including alpha-tested and unusual view-model materials. Motion blur no longer
needs first-person depth, first-person camera history, first-person constants,
or a first-person shader family.

### Phase 3: simplify first-person ABI and configuration

Remove from active motion-blur rendering:

- `previous_first_person` and `first_person_reprojection`;
- current/previous first-person frustum, depth, and transform constants;
- `FirstPersonDepth` sampler `s2`;
- `first_person_depth_available` and first-person reversed-depth fields;
- the first-person receiver branch and layer strength;
- first-person motion from CPU maximum-motion preflight;
- the motion-blur requirement for a first-person depth resolve.

Remove `first_person_strength` from the active menu, but keep it in schema-1
deserialization, serialization, and preset snapshots as inert compatibility
data. Do not change the schema or `GraphicsMenuConfig` layout merely to remove
a control whose rendering semantics have already disappeared. Its value must
have no rendering or temporal effect. Update the menu description from
“isolated first-person motion” to an explicit world-only contract.

The result should compile one world shader per quality tier rather than separate
first/third-person blur families unless the player-mask ABI genuinely requires
a separate third-person variant.

### Phase 4: establish semantic third-person geometry identity

At entry to the primary world transaction:

1. Read the player singleton and validate exact camera mode.
2. Call or inline the proven `PlayerCharacter::Get3D(false)` contract once to
   obtain the current ordinary player root.
3. Publish that root only for the nested world transaction; clear it on every
   exit path.
4. Arm coverage work only when third-person motion blur is enabled, temporal
   preparation can need a draw, and the output/depth contract is valid.

At the existing engine-owned `RenderTriShape` and `RenderTriStrips` hooks,
classify the received geometry by a bounded `NiAVObject + 0x18` parent walk.
The walk must have a small hard maximum and cycle/null rejection. Do not call
`VirtualQuery`, allocate, log, take a lock, or call `Get3D` per geometry.

Before accepting these two entries as complete coverage, instrument bounded
counters in a diagnostic build and test naked, clothed, armored, weapon-drawn,
holstered, Pip-Boy, power armor, race/body replacer, dismemberment, death ragdoll,
VATS, dialogue, and modded skeleton cases. Any visible player material that
bypasses the entries requires another engine-owned renderer boundary or a
different producer; it must not be papered over with a depth heuristic.

### Phase 5: prove and implement a screen-space coverage carrier

Object identity alone is insufficient; the blur shader needs exact visible
pixel coverage. The preferred carrier to investigate is one reserved stencil
bit during the world transaction, immediately materialized into an OMV-owned
full-resolution coverage texture before leaving the post-world boundary.

That carrier is allowed only after proving all of the following:

- the active world depth surface has stencil storage on every supported path;
- one bit can be reserved without changing native water, portal, shadow,
  first-person, or mod stencil semantics;
- the reserved bit can be cleared without clearing native bits;
- alpha test and depth test update coverage for the same fragments that own
  final player color;
- later depth-passing non-player geometry writes zero to the reserved bit, so
  an occluder drawn after the player cannot leave stale player coverage;
- all relevant native stencil state is restored and the engine's state cache
  cannot diverge from the device;
- state publication does not require `GetRenderState` or a state block per
  geometry and does not create vendor-specific per-draw stalls.

Use an OMV-owned `A8R8G8B8` texture if D3D9 lacks a portable single-channel
render-target format on the supported devices. Materialize `0` for world and
`1` for player with one bounded full-screen stencil-tested draw, then consume
the texture from the blur shader. Do not make the later blur depend on the
engine stencil attachment still being bound.

Stencil is a candidate, not a proven fact. If any gate above fails, do not ship
that path. The fallback research branch is a player-only coverage replay into
an OMV target using an engine accumulator/render boundary that preserves
skinning, alpha test, and final world-depth occlusion. It is more expensive and
requires its own executable contract, but it avoids claiming ownership of
native stencil. A bounding rectangle, depth range, or temporal mismatch is not
an acceptable fallback.

The selected carrier must publish `{texture, width, height, render_epoch,
world_target_identity, valid}` atomically for the nested post-world draw. No
previous-frame player mask is allowed.

### Phase 6: consume coverage without color leakage

The third-person shader contract becomes:

- if the center pixel is player-covered, return current scene color and alpha;
- for a world center, reject every tap that is player-covered before sampling
  or weighting its color;
- retain current world-depth continuity and optional previous-depth history for
  sky/geometry edges and disocclusions;
- preserve current alpha exactly;
- treat unavailable coverage as no third-person draw, never as all-world
  coverage.

Point-sample coverage at exact texel centers. Do not linearly filter a binary
mask. If silhouette dilation is required to prevent bilinear scene-color
footprints from importing player color into neighboring world pixels, derive a
one-texel conservative rejection in the shader or a bounded mask pass. Dilation
may keep a thin ring of world sharp; document and test that tradeoff rather than
allowing player color to smear.

Once semantic coverage is proven, reassess the packed previous-depth history.
Keep it only if its disocclusion benefit is visible and worth one full-resolution
texture plus one draw per valid third-person frame. It must no longer be
described as the player-preservation mechanism.

### Phase 7: resource, failure, and performance ownership

All resources remain device-owned and default-pool:

- world motion-blur pixel shaders;
- optional packed depth history if retained;
- the current third-person coverage texture and any proven carrier scratch.

Create on first applicable use or resize, release before `Recreate`, and rebuild
after device recovery. A frame performs no allocation, compilation, file I/O,
blocking lock, or unbounded diagnostic work.

Required fail-closed behavior:

- first person: if motion blur fails, leave world color unchanged and allow
  native first-person rendering to continue;
- third person: missing identity root, incomplete hook capability, invalid
  coverage, carrier failure, or epoch mismatch leaves the complete world
  unblurred;
- a camera-mode transition resets camera history, player coverage, and retained
  depth history before another blur can occur;
- device reset, target change, missed world callback, or config change primes a
  fresh sequence.

Static work budgets must be updated. The fix should remove first-person depth
resolve demand and six first-person/third-person duplicate shader objects, but
may add one current coverage texture and a mask materialization draw. No plan is
accepted if it adds a D3D device-vtable hook, per-geometry state readback, or an
unbounded scene-tree traversal.

### Phase 8: validation and release gate

Run the focused OMV tests during implementation, then the required target suite
and release build:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

Also require:

- shader compilation and instruction/texture-fetch budgets for every tier;
- source-contract tests proving the legacy first-person ABI is gone;
- coverage epoch/size/target mismatch negative controls;
- state-restoration tests around the post-world transaction;
- a deterministic image fixture with matching-depth player history;
- a fixture proving world taps cannot sample player color;
- `git diff --check` and final diff inspection.

Runtime acceptance must be captured in both first and third person with slow
pans, fast turns, translation, stationary camera/player, player animation,
rotation in place, locomotion, occlusion by walls/foliage, alpha-tested hair,
weapons, armor changes, VATS, dialogue, scopes, water, loading, camera-mode
transitions, and resolution/device reset.

Acceptance is all of:

- world motion is visibly blurred in both views when above threshold;
- first-person hands/weapons remain current-frame sharp with no silhouette
  pickup for every legacy configuration value;
- the entire visible third-person body and equipment remain current-frame sharp
  even when previous depth matches;
- ordinary NPCs and moving world objects follow the documented camera-only
  world behavior unless a later feature explicitly adds per-object policy;
- no stale mask, sharp ghost silhouette, blur leak, native stencil corruption,
  duplicated draw, or frame-to-frame flicker;
- NVIDIA, AMD, and Intel frame time shows no catastrophic per-draw regression;
  in particular, the fix must not recreate the device-vtable or state-readback
  pattern associated with the prior NVIDIA 1 FPS investigation.

No claim of completion should be made from unit tests or compilation alone.
Third-person coverage correctness and vendor performance require playtest
evidence.

## Pre-fix temporal ownership and failure behavior

`MotionBlurTemporalState` is the sole previous-camera owner. A pair is usable
only when:

- both cameras and transforms are finite and valid;
- capture epochs are consecutive;
- target dimensions and configuration are unchanged;
- camera forward vectors remain at least `0.5` aligned;
- view-space translation remains no greater than the smaller of 25% of the
  two cameras' far planes and 4096 units.

The first frame, resize, config change, epoch gap, device reset, camera cut,
missing world depth, invalid projection, or unknown camera-mode value performs
no blur. In third person, the first valid frame and any frame after a history
gap record current depth but do not copy scene color or blur. Only a
consecutive camera pair plus consecutive depth history can blur. The history
epoch is published only after a successful history draw, so failed or partial
updates cannot be consumed. Intermittent first-person depth invalidates only
its own pair. The next consecutive valid frame resumes normally.

World motion is defined on the fixed, unjittered output grid. When TAA has
jittered the depth-producing projection, OMV uses the restored output camera
for current/previous motion, following the already proven TAA invariant that a
stationary camera must produce a null vector. Depth remains the current
resolved geometric distance. First-person uses its independent live projection.

Shader source is compiled off the render thread and cached by source/family
hash. The render thread observes readiness through an atomic flag, takes the
published bytecode with `try_lock` only during one-time D3D shader creation, and
never compiles or performs file I/O in a render callback. Until bytecode is
ready, phase preflight rejects motion-blur-only work. Compilation/resource
failure leaves the native scene intact and follows the existing bounded OMV
error logging path. A history-texture allocation failure suppresses
third-person motion-blur work until the next device lifecycle while leaving
the history-independent first-person path active.

## Pre-fix performance contract

An accepted moving first-person frame performs one full-resolution scene-color
copy and one full-resolution blur draw. Third person records one
full-resolution depth-history draw on every valid frame so the immediately
following frame can distinguish static world from independently moving
geometry. A moving consecutive third-person frame therefore performs one
scene-color copy, one blur draw, and one one-sample depth-history draw. The
first/history-gap frame performs only the history draw.

| Tier | Taps | First-person blur fetch bound | Third-person blur fetch bound |
|---|---:|---:|---:|
| Performance | 5 | 15 | 11 |
| High | 7 | 21 | 15 |
| Ultra | 9 | 27 | 19 |

The maximum assumes world geometry while first-person depth is also available:
one color, first-person-depth, and world-depth lookup per shutter position.
Third person samples current color/depth, one previous-depth value for
geometry, and one color/depth pair per later tap. Its separate history draw has
exactly one depth fetch and one packed-color write per pixel. Each compiled
shader is constrained to at most 512 static opcodes and a uniform
compile-time-bounded loop.

Persistent feature-specific GPU memory is six blur pixel shaders, one
depth-history shader, and one full-resolution four-byte-per-pixel history
texture while the device is live: about 7.9 MiB at 1920x1080 and 31.6 MiB at
3840x2160. A moving frame also needs the existing scene-post full-resolution
color-copy texture shared with other effects. Resources are created only on
first use/resize and released on device reset; no routine frame allocates.
CPU preflight evaluates a fixed 15 world projections and, when available, 15
first-person projections. It performs no allocation, file I/O, logging, or
lock acquisition.

Disabled, zero-shutter, zero-cap, unknown-camera-mode, and missing-depth frames
are rejected before effect work. First-person first, cut, stationary, and
sub-threshold frames still perform no effect-specific GPU work. Third-person
valid frames deliberately retain the one-sample history draw even while
stationary; record-only frames avoid the scene-color copy and blur draw.

These are static work bounds, not measured frame-time or FPS claims.

## Pre-fix validation coverage and its gap

Automated OMV coverage currently proves:

- all 5/7/9-tap production variants compile as `ps_3_0` within instruction and
  texture-work budgets;
- the first/third-person sampler/constant ABIs, explicit LOD, alpha
  preservation, one-sample history writer, and prohibited color-history and
  derivative contract;
- finite stationary, translation-parallax, sky-translation, and subpixel
  rotation reprojection;
- first frame, epoch gap, cut, invalid camera, resize, config change, disabled,
  zero, and missing-input rejection;
- a camera-only reprojection negative control produces material motion at a
  representative player depth, while both known camera modes are admitted and
  unknown mode fails closed;
- first-person preparation retains full world reprojection, while third person
  produces a record-only seed followed by an eligible world-blur packet;
- packed depth round-trips standard and reversed projections, a matching
  previous surface accepts blur, and a receiver reprojection landing on
  background or invalid history preserves the current pixel;
- native camera-mode decoding accepts only byte values `0` and `1`;
- constant fields, positive/negative borders, odd/even half-pixel placement,
  gradients, steep discontinuities, thin features, sky, invalid values, and
  world/first-person isolation;
- standard/reversed depth after D16- and D24-like quantization;
- a naive depth-unaware negative control produces silhouette color bleed while
  the production reference rejects it;
- menu bounds, persistence, ordering, and exact round-trip synchronization.

Required final validation commands are:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
```

These tests do not prove the required world-only foreground contract. In
particular, none supplies semantic player coverage when previous player depth
matches predicted depth, and the first-person ABI assertions deliberately
require the defective independent first-person blur branch.

Ordinary playtesting remains necessary for perceptual acceptance. Test a slow
subpixel pan, a rapid mouse turn, lateral motion past near posts and distant
terrain, bright sky/building silhouettes, foliage and water, first-person
weapons at strengths 0 and 1, and a moving/rotating third-person player against
high-contrast scenery. Also test repeated first/third-person transitions,
dialogue/VATS transitions, loading/teleport, resolution reset, and all three
tiers. The previous acceptance text expected first-person trailing motion; that
expectation is superseded by the world-only contract. Final acceptance requires
sharp first-person geometry, a sharp third-person player, and no leading double
image, fullscreen fill, diagonal seam, bands, wall lines, speckles, crawling,
flicker, cut ghost, sky translation smear, foreground halo, or
first-person/world leak.

## Evidence classification

Proven repository facts are the current native phase, current depth/camera
ownership, fixed-output TAA camera contract, camera-mode field and setter
behavior, source ordering, D3D resource lifecycle, and all automated properties
listed above.
The depth-history rejection design, 24-bit packing, choice of 5/7/9 samples,
2.5-10% spatial depth tolerance, 3-10% temporal depth tolerance, 4096-unit
absolute cut cap, and default slider values are engineering decisions
supported by deterministic negative controls and bounded-work analysis, not
facts recovered from the executable. It is proven that depth history has no
semantic player input; it is an inference, confirmed by the reported runtime
artifact, that matching-depth player pixels take its accepted blur branch.

No in-game capture or GPU timing result is claimed here. Perceptual smoothness,
comfort, compatibility with a user's complete mod stack, and actual low-end GPU
frame time remain runtime observations to establish through the normal
playtest matrix.

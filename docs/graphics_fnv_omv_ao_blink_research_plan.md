# OMV ambient occlusion blinking: research and fix plan

## Scope

This document covers OMV's Fallout New Vegas ambient occlusion pipeline and the reported symptom where AO appears to switch on and off depending on player position or height. It separates proven defects from hypotheses that still need engine or runtime evidence.

No AO feature should be globally disabled or removed to hide the problem. The fix must preserve AO and correct its render-state, capture, camera, resource, and stability contracts.

## Implementation status

Implemented on 2026-07-16:

- native-required alpha-test disable in the RESZ marker draw and every OMV full-screen pipeline binder;
- coherent world/first-person depth publication with a frame epoch and same-size validation;
- first-person mask rejection when its capture does not match the world capture;
- AO intermediate format tracking and fallback-target recreation when the scene format changes;
- camera world-transform capture paired with the resolved world depth;
- temporal AO reprojection with depth rejection, neighborhood clamping, first-person rejection,
  and history invalidation on generation or resource discontinuities;
- real weighted behavior for the Fast AO and Contact AO `stability` controls;
- focused tests for capture coherence, fallback-format matching, transform handedness,
  translation, rotation, generation invalidation, and every embedded HLSL program.

The temporal camera and handedness audits are complete. They prove the camera owner and timing,
the world-transform offsets, matrix-vector convention, and the direction/up/right column order.
The supported `i686-pc-windows-gnu` build and Wine-hosted 32-bit unit/HLSL tests pass.
In-game validation at the reported locations remains required because static analysis cannot
reproduce third-party D3D state or judge the visual stability/ghosting tradeoff.

## Current pipeline

OMV runs AO at the outer `ImageSpaceManager::ProcessImageSpaceShaders` hook, before vanilla image-space processing:

1. Capture world depth after `Main::RenderWorldSceneGraph` phase 0.
2. Copy the scene color from the rendered-texture source.
3. Run a half-resolution AO extraction pass.
4. Run horizontal and vertical bilateral blur passes.
5. Reproject the previous half-resolution AO into the current camera, reject disocclusions,
   and clamp accepted history to the current neighborhood.
6. Composite the stabilized AO into the full-resolution scene target.
7. Publish the stabilized AO/depth-key pair as next-frame history.
8. Restore the D3D9 state block and continue vanilla image-space processing.

The pipeline uses:

- world depth on sampler 1;
- first-person mask depth on sampler 2;
- half-resolution `G16R16F` AO and depth-key intermediates, with a scene-format fallback;
- scene color on sampler 0 and the blurred AO result on sampler 4;
- a reconstructed view position based on the captured near/far planes and frustum slopes.

The relevant implementation is in:

- `omv/src/fnv_render.rs`
- `omv/src/backend/fnv.rs`
- `omv/src/runtime.rs`
- `omv/src/effects/ambient_occlusion.rs`
- `omv/shaders/embedded/ambient_occlusion_extract.hlsl`
- `omv/shaders/embedded/ambient_occlusion_blur.hlsl`
- `omv/shaders/embedded/ambient_occlusion_temporal.hlsl`
- `omv/shaders/embedded/ambient_occlusion_compose.hlsl`

## Findings

### 1. OMV fails to disable alpha testing as required by the native image-space contract

Confidence: confirmed engine-contract defect and leading root-cause candidate.

The vtable follow-up resolves native `ImageSpaceShader::PresetStages` to `0x00C04120`. It installs these render states into the native image-space pass:

- state 7, `D3DRS_ZWRITEENABLE = 0`;
- state 14, `D3DRS_ZENABLE = 0`;
- state 27, `D3DRS_ALPHABLENDENABLE = 0`;
- state 15, `D3DRS_ALPHATESTENABLE = 0`;
- state 168, `D3DRS_COLORWRITEENABLE = 0x0F`.

Before the implementation described above, `AmbientOcclusionEffect::bind_pipeline_state` matched the Z-write, Z-test, alpha-blend, and color-write values and also set culling, but omitted `D3DRS_ALPHATESTENABLE`.

That omission matters even with alpha blending disabled. D3D9 alpha testing can reject a pixel-shader result before it reaches the render target. OMV's compose shader preserves the scene color alpha, so inherited alpha function/reference state can reject a position-dependent subset of the full-screen composite or effectively leave the unoccluded source in place. Native image-space shaders cannot inherit that alpha-test state because their pass explicitly disables it.

This is the best static-proven match for AO appearing to switch off based on recent geometry/render history. It should be fixed first and independently of any sampling change.

The RESZ point draw that produces OMV's sampled depth also omitted alpha-test state. Inherited alpha testing can reject that marker before the magic `D3DRS_POINTSIZE` resolve command, leaving the owned INTZ texture stale even when the D3D calls themselves succeed. The native alpha-test fix therefore applies to both the depth resolve and the AO color passes.

### 2. Stencil, scissor, and other full-screen states remain hardening candidates

Confidence: confirmed diagnostic gap; causal role unproven.

OMV also does not establish several states that can reject or alter full-screen pixels:

- `D3DRS_STENCILENABLE`, stencil function/reference/masks, and stencil operations;
- `D3DRS_SCISSORTESTENABLE` and the scissor rectangle;
- clip-plane enable, fill mode, separate-alpha blend, sRGB write, and MRT color-write states.

The all-state state block only restores the engine state after OMV draws. It does not sanitize the state before OMV draws.

The engine depth-stencil surface also remains bound while OMV renders its half-resolution targets. If stencil testing is inherited, those passes can be rejected by engine stencil contents whose meaning and dimensions belong to a different render phase.

The native `PresetStages` function does not add stencil or scissor state to its pass. This suggests that vanilla expects those states to be valid boundary invariants, but it does not prove their runtime values or protect OMV from state left by another loaded plugin. Engine stencil/scissor state can depend on water, shadow, first-person, portal, or local geometry paths. Inheriting it could make the AO composite affect only part of the screen, but that remains a hypothesis until runtime telemetry captures a good and blinking frame.

The same incomplete state setup is duplicated by other OMV screen effects. The eventual fix should use one small shared screen-pass state binder rather than accumulating effect-specific variants.

### 3. First-person depth capture ordering is current-frame and timely

Confidence: confirmed by the follow-up Ghidra output. This is not the reported root cause.

`Main::RenderFirstPerson` clears depth at `0x008751C6` and renders first-person accumulated geometry at `0x0087590A`. `ProcessImageSpaceShaders` at `0x00876136` is not inside that function. It belongs to the separate image-space owner at `0x00875FD0`.

The main render paths prove the ordering:

- `0x00870B21` calls `Main::RenderFirstPerson`, then `0x00870B89` calls the image-space owner;
- `0x00870F74` calls `Main::RenderFirstPerson`, then `0x008710E4` calls the image-space owner.

OMV's post-`RenderFirstPerson` hook therefore resolves the first-person depth after its geometry and before scene-pre AO. The published mask and projection are current-frame under these paths. If a path skips first-person rendering, the previous mask has already been cleared at `Present`, so it is not silently reused.

Generation telemetry is still useful to defend this contract and to diagnose nonstandard render paths, but moving the capture into `ProcessImageSpaceShaders` is no longer part of the fix plan.

### 4. Both `stability` settings were no-ops

Confidence: confirmed defect; implemented.

The Fast AO stability value is stored in `FastOption2.x`, and Contact AO stability is stored in `ContactOption1.w`. Neither value is read by the extract, blur, or compose shader. There is no AO history texture, camera reprojection, disocclusion rejection, or camera-cut reset.

The eight-sample kernel is rotated by a hash of the half-resolution screen pixel. A world point receives a different kernel orientation as it moves between pixels. This can produce shimmer or local AO instability during camera/player movement. It does not by itself explain a clean full-screen or whole-region toggle.

The temporal pass now weights the two stability settings by their enabled AO strengths. It uses
the camera transform captured with world depth, not the phase-mutable shader-manager camera.
History is rejected for nonconsecutive depth epochs, resource recreation, invalid transforms,
first-person pixels, off-screen reprojection, behind-near-plane reprojection, and depth mismatch.
Accepted history is clamped to the current AO neighborhood before blending.

### 5. Shader rejection paths are not observable enough

Confidence: confirmed diagnostic gap.

The AO pipeline deliberately returns no occlusion for several conditions:

- missing world depth;
- first-person mask hit;
- invalid depth endpoint;
- sky/far-plane classification;
- unavailable camera contract;
- both AO strengths disabled.

`debug_depth` distinguishes some missing/invalid/sky cases in the compose pass, but it does not identify every rejection reason or show whether the extraction target was written. A render-state rejection can also prevent the diagnostic shader from writing, making the existing view ambiguous.

### 6. Resource matching ignores intermediate format

Confidence: confirmed, low relevance to the current symptom.

`AmbientOcclusionTargets::matches` compares width and height only. It does not track whether the targets were created as `G16R16F` or with the fallback scene format. A format change without a size change will not recreate the AO targets. This should be corrected, but it is not a strong explanation for height/location-dependent blinking.

### 7. Current logs show a valid but incomplete contract

The latest OMV log shows:

- successful world and first-person RESZ resolves;
- reversed depth derived from `ZFUNC=7`;
- 3440x1440 depth surfaces and 1720x720 AO intermediates;
- separate world and first-person frusta;
- no AO initialization or draw error.

Both resolves report the same engine source surface pointer. That is consistent with a shared engine depth surface being cleared and reused at different phases; it is not proof that the owned INTZ copies alias. It makes capture timing and generation tracking especially important.

The logged far plane changes between render contexts. That can be legitimate, so it must not be called a bug without pairing each depth capture, camera pointer, render phase, and AO draw generation.

## Comparison with Vanilla Plus AO

The reference Vanilla Plus AO implementation in `.research/fnv-vanilla-plus-ao-main` registers an `ImageSpaceEffect` through Depth Resolve's `AppendPostDepthEffect`. Its passes run through the engine image-space effect machinery, including `ImageSpaceShader::PresetStages`, and it reads the engine camera and renderer projection when the effect renders.

OMV intentionally avoids that dependency and the associated hook collision surface. That is reasonable, but it means OMV must explicitly reproduce the complete full-screen D3D state and must pair its own depth/camera captures with the exact draw generation. Capturing/restoring state around the draw is only half of that contract.

## Remaining ground-truth research

The completed audits are:

- `analysis/ghidra/output/perf/graphics_fnv_ao_state_capture_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_image_space_pass_state_vtable_followup.txt`
- `analysis/ghidra/output/perf/graphics_fnv_ao_temporal_camera_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_ao_temporal_basis_handedness_followup.txt`

They prove:

1. first-person rendering precedes the separate image-space owner in the main render paths;
2. native image-space pass construction explicitly disables alpha testing;
3. OMV omits that native alpha-test state;
4. the native preset does not explicitly establish stencil or scissor state.
5. the persistent World scene-graph camera is republished immediately before image-space work;
6. camera rotation, translation, scale, and frustum offsets are established;
7. rotation columns are direction/forward, up, and right, while matrix multiplication uses
   row-dot-column semantics.

Static Ghidra output cannot show state left by other loaded DLLs or the exact D3D state on a failing frame. Runtime telemetry is also required.

## Fix plan

### Phase 1: reproduce the native alpha-test contract

Status: implemented; runtime validation at the reported locations is pending.

`D3DRS_ALPHATESTENABLE` is exported by the safe Direct3D9 wrapper and set to zero in every existing OMV full-screen binder and in the RESZ marker draw. Because this state is directly proven by `ImageSpaceShader::PresetStages`, the fix does not need a speculative runtime model. Binder consolidation remains a separate cleanup so it cannot obscure validation of the minimal state change.

Keep the all-state capture/restore and verify that alpha-test enable/function/reference are exactly restored after OMV.

Exit criterion: the reported location/height transition no longer disables or clips AO, and vanilla image-space output remains unchanged.

### Phase 2: capture residual failures without changing AO behavior

Add a bounded AO contract recorder at the outer `ProcessImageSpaceShaders` entry. Record only on state change and retain enough recent samples to compare a good frame with a blinking frame.

Record:

- frame/present generation and scene-pre application generation;
- world and first-person resolve generations and projection generations;
- render target 0 and depth-stencil pointers and descriptions;
- viewport and scissor rectangle;
- alpha-test enable/function/reference;
- stencil enable/function/reference/read mask/write mask/operations;
- scissor, clip-plane, fill, cull, Z, blend, separate-alpha, sRGB-write, and color-write states;
- world/current camera pointers, near/far planes, and frustum values;
- the rendered-texture arguments at the outer image-space call.

Add an AO diagnostic mode that writes explicit colors for:

- draw rejected before shader output;
- missing or generation-mismatched depth;
- invalid depth;
- sky depth;
- first-person mask;
- unavailable camera;
- valid AO extraction and valid compose.

This phase needs additional safe D3D9 wrappers in `libpsycho`, including scissor rectangle access and the currently unexported render-state constants. Do not add direct WinAPI calls in OMV.

Exit criterion: one reproducible good/bad capture identifies whether the failure occurs before the shader, in depth/camera classification, in the AO target, or during compose.

### Phase 3: harden the remaining full-screen state only from evidence

After telemetry confirms or excludes inherited state, use one shared OMV screen-pass state function for every AO pass. Alpha test is already mandatory from Phase 1. Establish additional states when the native boundary contract or failing-frame telemetry supports them:

- solid fill and no culling;
- alpha blending and separate-alpha blending off;
- stencil test off;
- scissor test off, with a full-target rectangle when enabled by any later pass;
- Z test and Z writes off;
- clip planes off;
- render-target 0 color writes enabled and unused MRT writes disabled;
- an explicit sRGB-write policy;
- target-sized viewport;
- known shader/FVF and sampler state.

Keep the existing state-block capture/restore and verify that the engine state is bit-for-bit restored after OMV. Detach the depth-stencil surface for AO color-only passes if the proven engine/device contract allows it; otherwise stencil must still be disabled explicitly.

Exit criterion: AO extraction, blur, and compose produce the same coverage regardless of the engine state captured at entry, and vanilla image-space behavior is unchanged after restoration.

### Phase 4: harden the proven depth-generation contract

Status: implemented.

Keep the current first-person capture boundary unless runtime evidence contradicts the proven main render paths.

The implementation now publishes a coherent capture record under one lock rather than exposing texture pointers and projections independently. It includes explicit generation IDs so the working ordering cannot regress silently:

- publish world and first-person resolve generations with their textures and projections;
- require world depth/projection to match the current scene-pre AO generation;
- consume a first-person mask only when its texture and projection generations match the current frame;
- treat a missing/mismatched first-person mask as no mask for that frame, not as a reason to disable world AO;
- log generation mismatches on change without per-frame spam.

Exit criterion: every AO draw has a current world contract, and every used first-person mask is provably from the same frame.

### Phase 5: implement real stability only after the frame contract is correct

Status: implemented; runtime visual validation is pending.

Do not mask a capture/state bug with extra blur or a shader-only history guess.

The camera transform/projection contract is now proven and the implementation includes:

- previous AO/depth-key history at the AO resolution;
- current-to-previous camera reprojection;
- depth rejection for disocclusions;
- neighborhood clamping;
- resets on skipped captures, effect gaps, resolution/format changes, and device reset, with
  reprojection/depth rejection handling camera motion, projection changes, and cell transitions;
- a real mapping from the two `stability` controls to history weight/rejection strength.

History is sampled at the reprojected previous-frame UV. It is never blended at the same screen
pixel merely because the camera moved.

Exit criterion: the same world point remains stable during walking, crouching, jumping, and camera rotation without ghosting or delayed AO.

### Phase 6: close smaller correctness gaps

- Track the actual AO intermediate format in `AmbientOcclusionTargets::matches`. Implemented.
- Recreate targets on size, relevant fallback format, and device changes. Implemented.
- Make diagnostic state and generation mismatches visible in the log without per-frame spam.
- Consolidate duplicated screen-pass state setup used by AO, bloom, sunshafts, DOF, and generic screen passes.
- Keep the `stability` controls covered by the temporal shader compile and transform tests.

## Validation matrix

Test each case with Fast AO alone, Contact AO alone, and both enabled:

- exterior and interior cells;
- above, at, and below water height;
- areas with and without projected shadows;
- first person with weapon, holstered weapon, and third person;
- standing, crouching, jumping, slopes, stairs, elevators, and vertical camera movement;
- near geometry, open terrain, sky boundary, heavy fog, and weather transitions;
- menus, loading screens, cell transitions, save load, alt-tab, and device reset;
- 3440x1440 and at least one 16:9 resolution;
- with known graphics plugins from `.research` present and absent where practical.

For every case verify:

- no frame-wide or region-wide AO disappearance;
- no stencil/scissor-shaped AO coverage;
- depth/camera/texture generations match;
- no AO on first-person geometry and no stale mask;
- no sky/fog darkening regression;
- engine render state is restored after OMV;
- no new image-space ordering conflict;
- GPU cost remains acceptable with the added temporal pass and history copy.

## Safe diagnostics before implementation

These are diagnostics only, not fixes:

1. Reproduce with `debug_depth=true`. If the depth view itself changes classification, investigate depth/camera generation. If the diagnostic draw is spatially missing, investigate render-state rejection first.
2. Reproduce near water height and in the same place without water/shadow coverage. A strong correlation raises the stencil/scissor hypothesis but does not prove it.
3. Set `first_person_mask=0` temporarily. If this removes the symptom, capture generation telemetry and inspect first-person mask classification. Do not keep it disabled as the fix.
4. Capture the exact position, facing, camera mode, stance, weather, and a short video for one good/bad transition so runtime contract records can be aligned with the visual frame.

## Recommended implementation order

1. Add the native-required alpha-test disable and verify state restoration.
2. Re-test the exact reported locations and height transitions before changing AO sampling.
3. If any switch remains, add bounded state/generation telemetry and reproduce once.
4. Harden only the additional screen-pass states identified by telemetry.
5. Add world/first-person generation pairing without moving the proven capture boundary.
6. Validate the implemented temporal stability for residual shimmer and ghosting.
7. Complete the validation matrix and remove temporary diagnostics.

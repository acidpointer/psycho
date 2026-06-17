# OMV Native PBR Recovery Plan

This document replaces the previous delivery-first PBR plan.

The current PBR bugs are not isolated shader math bugs. They are contract bugs: OMV is replacing native shaders before it fully owns the draw identity, shader ABI, constant maps, sampler state, material resources, terrain pass identity, and compile lifecycle that New Vegas Reloaded uses as one system.

The goal is not to patch around the current screenshots. The goal is to build an OMV PBR architecture where the same classes of bugs cannot reappear:

- shadowed terrain rectangles and chunk boundaries
- terrain fade and far terrain lines before LOD
- object metallicness flicker on distance, angle, and camera movement
- exterior and interior point-light regressions
- missing Pip-Boy light influence
- terrain material parameters ignored by close terrain and LandLOD
- shader compilation freezes during play
- persistent FPS loss from broad terrain/object replacement

NVR remains the reference implementation. OMV does not edit NVR. The port must use NVR source and Ghidra output to define the engine-side contract first, then implement shader replacements against that contract.

## References

- `docs/graphics_fnv_pbr_errata.md`
- `docs/omv_pbr_nvr_contract_gap_report.md`
- `docs/graphics_fnv_nvr_shader_contract_research.md`
- `docs/graphics_fnv_pbr_contract_map.md`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_vpt_nvr_contract_gap_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_shader_abi_closure_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_unknown_object_rows_57_59_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_true_land_discriminator_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_abi_contract.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_declaration_contract.txt`
- `.research/TESReloaded10-master/src/effects/PBR.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.cpp`
- `.research/TESReloaded10-master/src/effects/Terrain.h`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Object.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/PBR.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainLODTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainFadeTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Terrain.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Parallax.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainLODTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainFadeTemplate.hlsl`

## Current Failure Model

### 1. Shadowed Terrain Rectangles

The visible rectangle/chunk boundary means terrain is being replaced on only part of the terrain pass, or with the wrong pass identity. The current architecture can still classify draws from shader pair and partial selector state. That is insufficient for close terrain.

NVR/VPT terrain is not just "the PPLighting shader with a different BRDF." It is a pass-table contract:

- VPT/NVR pass rows identify active terrain material passes.
- The terrain selector and pass entry decide which texture layers exist for that draw.
- Terrain constants and samplers are mapped per pass.
- The active `TEX_COUNT` changes shader behavior.
- LandLOD and terrain fade are separate contracts and must stay visually coherent with close terrain.

If OMV applies close terrain PBR from a shader-pair match without proving the pass row, layer count, material slot binding, and fade/LOD relation, it can light one terrain block with PBR and adjacent terrain with vanilla. That produces the rectangular shadow/light chunk in screenshots.

### 2. Far Terrain Line Before LOD

The line before visible LOD is a close terrain, terrain fade, and LandLOD coherence failure. NVR has separate terrain templates for close terrain, terrain fade, and LandLOD. OMV cannot make close terrain PBR correct if fade and LOD remain unrelated.

The fix is not "tune fade math." The fix is to define one terrain family contract:

- close terrain pass rows
- terrain fade row
- LandLOD row
- shared fog, sun, ambient, wetness, noise, and material parameter policy
- explicit transition ownership between those stages

Until this exists, any close terrain change can expose a seam where vanilla and PBR lighting meet.

### 3. Object PBR Flicker With Distance And Angle

Object metallicness disappearing with distance means the object row family is incomplete or unstable. Distance changes the engine path:

- ordinary object rows
- LOD object rows
- EnvMap/reflection rows
- skin rows
- projected shadow or only-light helper rows
- point-light rows
- fallback or no-material rows

If only the close ordinary row has PBR, then a building, prop, weapon, or reflective object can switch between PBR and vanilla when the engine changes row. That creates visible blinking even if each individual shader compiles and draws correctly.

The recent EnvMap row audit showed object pixel rows 57, 58, and 59 are not ordinary object BRDF rows. They are reflection/EnvMap contracts. Treating them as object PBR candidates is wrong; treating them as unknown vanilla fallback without a stable row policy is also a flicker source.

### 4. Point Lights And Pip-Boy Light

The earlier interior lighting failure and the current Pip-Boy-light gap mean OMV still does not fully preserve the native point-light contract. PBR must not replace a point-lit shader unless it consumes the same light constants, attenuation, shadow/projection state, and helper textures as the original row.

For Pip-Boy light specifically, the problem must be treated as native light-row coverage or constant binding coverage, not a post-effect issue. If the Pip-Boy light is represented through the same PPLighting row family, the PBR shader must consume that data. If it uses a separate helper row or state update path, OMV must classify and support that row explicitly.

### 5. FPS Loss And Stutter

The latest logs showed asynchronous shader compilation lasting minutes after gameplay:

- `Native PBR async compile queued 124 shader(s) on 2 worker(s)`
- slow close-terrain compiles reached about 21 seconds per shader
- terrain shader compilation dominated the compile time
- visible gameplay happened while shader availability was still changing

This is two separate performance failures:

- compile lifecycle: heavy D3D compilation is still happening during play
- shader/runtime cost: terrain variants are too broad and expensive for the enabled draw coverage

The fix is not just "prewarm more." OMV needs a strict shader bytecode lifecycle: enabled PBR records must be compiled or loaded before visible replacement is allowed.

## Non-Negotiable Rules

1. No shader-pair-only PBR replacement.

   A vertex/pixel shader handle pair is not a draw contract. It is only one input into draw classification.

2. No visible replacement while shader bytecode is pending.

   If a replacement shader is not ready, the draw must remain vanilla. Runtime compilation may not cause a surface to switch between PBR and vanilla during normal play.

3. No terrain PBR without pass-row identity.

   Close terrain requires selector, pass entry, active layer count, material texture slots, and terrain constants. Shader row alone is not enough.

4. No object PBR row without a full replacement record.

   A row must define shader bytecode, vertex ABI, pixel ABI, constants, samplers, state preservation, material source, and fallback policy.

5. No "near objects only" object PBR.

   If a visible object family can switch to LOD, EnvMap, projected, only-light, or point-light rows, those rows need either implemented PBR or a stable explicit fallback that does not visually blink across distance.

6. No stale sampler reliance unless declared and validated.

   PBR code must not silently depend on whatever texture is currently bound in D3D state. Every sampler used by OMV must be either explicitly bound by the replacement record or explicitly marked as preserve-vanilla with a validation rule.

7. No global feature disable presented as a fix.

   Temporary diagnostic gates are allowed. A real fix must preserve intended PBR coverage by correcting classification, binding, shader ABI, or performance architecture.

8. Fail closed.

   Unknown rows, unproven vertex layouts, missing material sources, missing shader bytecode, and incomplete sampler contracts must render vanilla and log bounded diagnostics.

9. Performance is part of the contract.

   A correct-looking PBR shader that costs large constant FPS loss or one-time gameplay freezes is not shippable.

10. Logs must explain classification, not replace implementation.

   Diagnostics must show which contract was used or why vanilla fallback happened. They must not become per-draw spam or hide incomplete architecture.

## Target Architecture

### 1. Shader Contract Registry

Build a first-class registry that is the only source of truth for native PBR replacement.

Each contract entry must include:

- stable contract id
- feature family: object, close terrain, terrain fade, LandLOD, EnvMap, skin, helper, projected shadow
- native vertex shader row or group
- native pixel shader row or group
- NVR/VPT source reference
- Ghidra output reference
- supported scene scope: interior, exterior, menu, first person, world object, terrain
- required vertex ABI
- required pixel constants
- required vertex constants
- required samplers
- required render states and sampler states
- material source: mesh material, terrain layer, LandLOD material, EnvMap source, or none
- shader bytecode key
- fallback policy
- implementation status: implemented, stable vanilla fallback, diagnostic-only, unknown

The runtime must not decide PBR eligibility from ad hoc code branches spread across hooks. It must ask this registry.

### 2. Draw Identity Classifier

Create a classifier that maps each draw to a contract id or a precise fallback reason.

Required inputs:

- native vertex shader handle
- native pixel shader handle
- shader group and row if known
- current pass pointer
- VPT/NVR terrain selector when present
- terrain pass entry pointer and pass row
- active terrain layer count
- current land texture state
- current vertex declaration
- render target/depth context when needed
- scene state: interior/exterior, menu, load screen, first person, world
- current light mode and point-light row hints
- material flags relevant to alpha, EnvMap, skin, and projected rows

Expected classifier outputs:

- `ObjectPbr(contract_id)`
- `ObjectVanillaFallback(reason)`
- `ObjectEnvMap(contract_id_or_fallback)`
- `ObjectSkin(contract_id_or_fallback)`
- `CloseTerrainPbr(contract_id)`
- `CloseTerrainVanillaFallback(reason)`
- `TerrainFadePbr(contract_id_or_fallback)`
- `LandLodPbr(contract_id)`
- `HelperVanillaFallback(reason)`
- `UnknownVanillaFallback(reason)`

This classifier is the architectural fix for distance/angle flicker. Row transitions become visible in diagnostics and deterministic in rendering.

### 3. Replacement Record

Implement an NVR `ShaderRecord` / `SetCT` equivalent.

A replacement record must own the whole draw setup:

- vertex shader bytecode
- pixel shader bytecode
- constant update plan
- sampler binding plan
- sampler state plan
- state preservation plan
- required engine resources
- material parameter source
- fallback decision before mutating D3D state

Handle substitution must become an implementation detail of applying a complete replacement record. It must not be the contract itself.

### 4. Material Resource Binder

Add a binder that resolves all PBR resources before draw replacement.

Object binder responsibilities:

- albedo/current diffuse source
- normal map source
- optional specular/env/shine source when row requires it
- material defaults when a texture is absent
- alpha-test and alpha-blend compatibility
- first-person weapon compatibility

Terrain binder responsibilities:

- active close terrain layer textures
- active normal/material maps
- active layer count and `TEX_COUNT`
- LandLOD texture set
- terrain fade texture set
- VPT material arrays
- safe fallback when VPT material data is absent

The binder must cache by stable material/pass identity. It must not scan broad material arrays or do expensive string/path work in the draw hot path.

### 5. Shader Bytecode Cache And Startup Enable Boundary

Separate shader compilation from visible replacement.

Required behavior:

- Build a list of enabled contract records before PBR is allowed to render.
- Load cached bytecode by shader source hash, compile options, profile, and contract id.
- Compile missing bytecode at a controlled startup boundary or via an explicit prebuild step.
- Create D3D shader objects from bytecode before setting feature status to active.
- Never swap a visible draw to PBR while its shader is compiling.
- Never let a background compiler change visible coverage during free gameplay.

Acceptable modes:

- warm cache: no compilation during play
- cold cache: controlled startup/pre-menu compilation, then enable
- missing shader: feature family stays vanilla and logs a bounded error

Unacceptable mode:

- gameplay proceeds while terrain/object replacements appear as individual compiles finish

### 6. Frame State And Constant Ownership

Add a frame-level PBR state object.

It owns:

- camera position
- sun direction and color
- ambient color and scale
- fog constants
- wetness/rain state
- time-of-day relevant values
- interior/exterior state
- Pip-Boy or player light state if exposed by the native contract
- global material tuning from config

Per-draw code should only combine frame state with material/pass state. It should not rediscover global lighting or scene state opportunistically.

### 7. Diagnostics

Diagnostics must be contract-centric.

Per-frame summary:

- total candidate draws
- PBR draws by family
- vanilla fallbacks by reason
- unknown rows by shader id
- missing shader records
- missing resources
- terrain pass rows seen
- object rows seen
- compile/cache status

One-shot detail logs:

- first unknown row
- first missing sampler
- first unsupported vertex declaration
- first terrain pass with missing layer data
- first shader-bytecode miss after enable boundary

Debug overlay should show contract state, not just "PBR active."

## Implementation Phases

### Phase 0: Stop Unsafe Runtime Behavior

Purpose: prevent current architectural bugs from producing misleading playtest results while the real contract layer is built.

Tasks:

- Add a strict "replacement allowed only if contract record is complete" gate.
- Keep incomplete rows vanilla with explicit fallback reasons.
- Forbid visible PBR replacement when shader bytecode is pending.
- Make installed config comments match current code and feature gates.
- Add a startup log section listing enabled PBR families and whether each is ready, vanilla fallback, or diagnostic-only.
- Add bounded logs for object row transitions and terrain pass rows.

This is not the final fix. It is a safety boundary so later tests measure known contract coverage instead of random partial replacement.

Acceptance:

- No draw is replaced by PBR without a complete contract id.
- No `no_shader` replacement path is visible in gameplay.
- Logs can explain every fallback in one line by contract/fallback reason.

### Phase 1: Build The Contract Registry

Purpose: remove hard-coded scattered row assumptions.

Tasks:

- Define `ShaderContractRegistry` under the PBR/effects layer.
- Move all known object, EnvMap, close terrain, terrain fade, and LandLOD rows into registry data.
- Add source references for each row from NVR/VPT/Ghidra.
- Mark every row as implemented, stable vanilla fallback, diagnostic-only, or unknown.
- Treat object rows 57, 58, and 59 as EnvMap/reflection-family rows, not ordinary object PBR rows.
- Add row coverage tests where possible as pure Rust table/classifier tests.

Acceptance:

- Runtime PBR eligibility has one registry-backed path.
- Unknown row handling is deterministic and logged once.
- EnvMap rows cannot be accidentally classified as ordinary object PBR.

### Phase 2: Replace Ad Hoc Matching With Draw Identity Classification

Purpose: fix object distance flicker and terrain misclassification at the source.

Tasks:

- Implement `DrawIdentity` collection around the existing shader hook path.
- Add object classifier for ordinary, LOD, point-light, helper, projected, skin, and EnvMap rows.
- Add terrain classifier using VPT/NVR pass identity, not only shader handles.
- Record active terrain layer count and pass row before replacement.
- Add fallback reasons for unsupported vertex ABI, unsupported row, missing material data, and missing shader bytecode.
- Update overlay/debug logs to report classified family and contract id.

Acceptance:

- A playtest can show exactly which contract an object or terrain draw used.
- Moving camera distance cannot silently switch from implemented PBR to accidental vanilla without a logged contract transition.
- Close terrain is never classified from shader pair alone.

### Phase 3: Implement Replacement Records

Purpose: make each PBR replacement a complete engine-side draw contract.

Tasks:

- Introduce `ReplacementRecord`.
- Move shader handle, constants, samplers, sampler states, and fallback policy into each record.
- Apply replacement only after the record validates all required resources.
- Preserve vanilla state explicitly when a record says to preserve it.
- Restore or avoid mutating state outside the record's owned scope.
- Add record-specific validation for point-light rows and Pip-Boy light rows once identified.

Acceptance:

- No PBR shader depends on accidental prior D3D sampler state.
- Point-lit rows keep their native light inputs or stay vanilla.
- Interior lamps and Pip-Boy light cannot disappear because a generic object shader replaced a point-light contract.

### Phase 4: Fix Compile Lifecycle And Shader Cache

Purpose: remove one-time freezes and random visual enable timing.

Tasks:

- Build an enabled-record list at startup.
- Add bytecode cache keyed by source hash, defines, shader profile, and contract id.
- Precompile or load all enabled record bytecode before enabling visible PBR.
- Create D3D shader objects before setting PBR family status to active.
- Reject runtime compilation after the enable boundary except for explicit developer diagnostic mode.
- Split heavy terrain variants by actual enabled `TEX_COUNT` and pass family.
- Add logs for cold cache, warm cache, compile time, and active shader count.

Acceptance:

- Warm cache playtest has zero shader compile events after gameplay starts.
- Cold cache compile happens before PBR becomes visible.
- No surface changes from vanilla to PBR because a background compile finished.
- Startup logs show all enabled records ready before replacement begins.

### Phase 5: Complete Object PBR Row Coverage

Purpose: eliminate object PBR distance and angle blinking.

Tasks:

- Map all NVR object row families used by FNV PPLighting.
- Implement or explicitly stable-fallback each row:
  - ordinary object
  - object LOD
  - static instanced rows
  - point-light rows
  - projected rows
  - only-light rows
  - diffuse-only rows
  - only-specular rows
  - first-person rows
  - alpha-tested rows
  - EnvMap rows
  - skin rows
- Ensure unsupported skin and special rows do not steal ordinary object material state.
- Decide EnvMap support from NVR contract. Until implemented, make it stable fallback or a separate reflection PBR record.
- Match vertex output ABI per row. Do not use neutral-normal or neutral-material hacks for rows marked implemented.
- Validate object material constants and samplers against NVR PBR includes.

Acceptance:

- Metallicness does not disappear when walking toward or away from objects.
- Objects do not switch between PBR and vanilla due to LOD/EnvMap/helper rows unless the fallback is intentional and visually stable.
- Debug summary reports zero unknown object candidates in tested scenes.

### Phase 6: Rebuild Close Terrain PBR Around VPT/NVR Contract

Purpose: fix close terrain rectangles, wrong material params, and wrong lighting.

Tasks:

- Classify close terrain only through VPT/NVR terrain pass identity.
- Require selector, pass entry, pass row, active layer count, and material array availability.
- Port NVR/VPT terrain constants:
  - terrain UV transforms
  - layer weights
  - noise parameters
  - ambient/sun/fog
  - terrain material params
  - LandHeight/height blend inputs where supported
- Bind only active terrain layers.
- Compile variants by actual layer count instead of unconditional seven-layer work.
- Keep projected shadow/helper terrain rows vanilla until their own records exist.
- Remove any terrain path that guesses material layer 0 when active layer data is missing.

Acceptance:

- Close terrain PBR appears only on true close terrain material rows.
- Terrain respects metallicness, roughness, light scale, ambient scale, and albedo saturation.
- No rectangular terrain shadow/light chunks appear when rotating camera.
- FPS cost is measured by terrain family and blocked if over budget.

### Phase 7: Implement Terrain Fade And LandLOD As One Family

Purpose: remove far terrain line and distance-dependent terrain PBR.

Tasks:

- Implement LandLOD record from NVR/VPT `TerrainLODTemplate`.
- Implement terrain fade record from NVR/VPT `TerrainFadeTemplate`.
- Share frame constants and material tuning policy across close terrain, terrain fade, and LandLOD.
- Match fog and sun/ambient handling across all terrain stages.
- Add explicit transition diagnostics:
  - close terrain draw count
  - fade draw count
  - LandLOD draw count
  - unsupported terrain helper rows
- Validate with fixed camera positions that cross the close/fade/LOD transition.

Acceptance:

- No visible line before LOD terrain.
- Terrain PBR does not appear only near the player.
- Close terrain, fade, and LandLOD have coherent brightness and material response.

### Phase 8: Restore Full Light Compatibility

Purpose: ensure PBR does not break native dynamic lighting.

Tasks:

- Identify all point-light and Pip-Boy-light shader rows from NVR/Ghidra/logs.
- Add contract records for those rows or stable fallback.
- Verify light constant rows and sampler usage against native shader ABI.
- Preserve shadow/projection texture bindings unless the replacement record owns them.
- Add a focused light test mode:
  - interior lamp
  - Pip-Boy light
  - exterior local light
  - player weapon light if applicable
- Log light-row classification separately from ordinary object classification.

Acceptance:

- Pip-Boy light affects PBR surfaces or those surfaces intentionally remain vanilla under that light row.
- Interior lamps do not disappear under PBR.
- Exterior reflection/highlight placement does not jump or form rectangular stale-light regions.

### Phase 9: Performance Hardening

Purpose: make PBR viable on real gameplay, not just screenshots.

Tasks:

- Remove heap allocation from draw hot paths.
- Cache material lookups by stable object/terrain identity.
- Cache terrain pass binding plans.
- Diff sampler and render-state changes before applying them.
- Avoid broad scans of shader tables during draws.
- Avoid unconditional terrain layer sampling.
- Avoid point-light loops in rows that do not have point lights.
- Add family-level cost counters:
  - object PBR draw count
  - close terrain PBR draw count
  - fade PBR draw count
  - LandLOD PBR draw count
  - shader switches
  - sampler binds
  - fallback counts
- Add config presets:
  - object only
  - object plus LandLOD
  - full terrain experimental
  - diagnostics

Acceptance:

- No gameplay shader compilation freezes.
- Warm cache gameplay has stable frame pacing.
- Any persistent FPS loss is attributable by family and can be reduced without disabling unrelated PBR.
- Full terrain does not ship as default until its cost is acceptable.

## Playtest Matrix

Every phase that changes rendering must be tested in these scenarios.

### Interior Lighting

- small room with wall lamps
- same view with PBR on and off
- Pip-Boy light on and off
- close wall/floor/ceiling camera movement
- reflective/metal object near local light

Pass criteria:

- no light disappearance
- no rectangular light/shadow update
- no distance flicker
- no material pop when looking straight at a surface

### Exterior Objects

- nearby building wall
- far building wall
- metal prop or weapon
- object crossing LOD distance
- EnvMap/reflection object if present

Pass criteria:

- metallicness and roughness response stays stable with distance
- row changes are either fully PBR or intentionally stable fallback
- no angle-dependent PBR disappearance

### Close Terrain

- hill with multiple terrain layers
- road/ground transition
- rock/soil/sand blend
- camera rotate in place
- walk forward/back across several cells

Pass criteria:

- no shadowed rectangles
- no layer chunk flicker
- material params affect visible output
- performance remains within budget

### Terrain Fade And LOD

- elevated view over valley
- slow walk toward far terrain
- rotate camera across close/fade/LOD boundary
- compare at morning/noon/evening lighting

Pass criteria:

- no pre-LOD line
- coherent brightness from close terrain to fade to LandLOD
- PBR does not exist only near the camera

### Performance

- cold cache launch
- warm cache launch
- cell transition
- menu open/close
- fast travel or interior/exterior transition

Pass criteria:

- no shader compilation during gameplay in warm cache
- no multi-second frame stalls
- no broad FPS regression from disabled families
- terrain FPS cost is isolated to terrain family

## Required Research Before More Feature Work

Do not implement another visual PBR expansion until these are proven by source/Ghidra/logs:

1. Complete object row table, including LOD, point-light, helper, EnvMap, skin, and projected rows.
2. Exact Pip-Boy light row or state path.
3. Close terrain pass-row discriminator and active layer source.
4. Terrain fade row and constant/sampler contract.
5. LandLOD constant/sampler contract and fade relation.
6. Shader compile/cache lifecycle constraints under D3D9/Wine/Proton.

If existing NVR source answers a point, document the source reference in the registry. If not, prepare a Ghidra script and wait for output. Do not guess.

## Deliverables

1. Contract registry and draw classifier.
2. Replacement record system.
3. Bytecode cache and startup enable boundary.
4. Object PBR complete row coverage or stable row fallback.
5. Close terrain PBR rebuilt around VPT/NVR pass rows.
6. Terrain fade and LandLOD as one coherent terrain family.
7. Light compatibility records for point lights and Pip-Boy light.
8. Performance counters and hot-path cleanup.
9. Updated user documentation for dependencies, config paths, feature presets, and known experimental limits.

## Definition Of Done

Native PBR is not done when one surface looks metallic.

Native PBR is done when:

- every replaced draw has a registry contract id
- every unknown or unsupported draw falls back to vanilla deterministically
- object PBR does not blink with distance or angle
- close terrain has no rectangular chunk artifacts
- terrain fade and LandLOD are coherent with close terrain
- interior lights, exterior lights, and Pip-Boy light are preserved
- warm cache gameplay has no shader compilation stalls
- performance cost is measured, bounded, and attributable
- logs explain coverage without overwhelming gameplay

Until then, the correct status is "partial PBR contract implementation," not "fixed."

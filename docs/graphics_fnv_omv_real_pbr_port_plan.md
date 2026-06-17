# OMV Native PBR Recovery Plan

This is the current active plan for fixing OMV native PBR.

The immediate target is object PBR. Terrain PBR shows the same class of bugs,
but object PBR is the smaller and better-proven contract. Fixing object PBR
first gives us the architecture terrain must later use: exact shader-row
identity, owned replacement records, owned resources, and deterministic row
transitions.

The problem is not primarily shader math. Current screenshots and logs show that
OMV can render a PBR shader, but it does not consistently own which native draw
receives that shader. Objects, terrain, and lights can move between replaced and
vanilla shader contracts as distance, angle, LOD, material flags, or light rows
change. That produces the visible blinking, metallicness popping, terrain
rectangles, fade lines, and lighting corruption.

The fix is not to toggle shader families on/off. The fix is to make every native
replacement draw pass through one explicit contract.

## Ground Truth

Use these references before changing native PBR:

- `docs/graphics_fnv_pbr_errata.md`
- `docs/nvr_reference_contract.md`
- `docs/omv_pbr_nvr_contract_gap_report.md`
- `docs/graphics_fnv_pbr_contract_map.md`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_shader_abi_closure_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_unknown_object_rows_57_59_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_visible_variant_closure_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_true_land_discriminator_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_abi_contract.txt`
- `.research/TESReloaded10-master/src/effects/PBR.h`
- `.research/TESReloaded10-master/src/core/ShaderManager.cpp`
- `.research/TESReloaded10-master/src/core/ShaderRecord.cpp`
- `.research/TESReloaded10-master/src/NewVegas/Hooks/Render.cpp`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/ObjectTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/Object.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/Includes/PBR.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainLODTemplate.hlsl`
- `.research/TESReloaded10-master/src/hlsl/NewVegas/Shaders/TerrainFadeTemplate.hlsl`
- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`

## Current Proven Failure Model

### Object PBR Blinks Because Replacement Coverage Is Mixed

Fresh runtime logs prove that OMV applies object PBR to some rows while many
visible candidate rows fall back:

- ordinary object rows are replaced;
- skin vertex rows are rejected;
- EnvMap/reflection rows are rejected;
- unsupported vertex ABI rows are rejected;
- unsupported shader families are rejected;
- the game can switch between these rows during distance, angle, LOD, material,
  light, or helper-pass changes.

This means a single visible object can move between PBR and vanilla. That is the
object distance/angle blink.

### EnvMap Rows Are A Separate Reflection Contract

Ghidra identifies PPLighting pixel rows `57`, `58`, and `59` as
`lighting\2x\p\EnvMap.p.hlsl` rows paired with vertex rows `50..52` from
`lighting\2x\v\EnvMap.v.hlsl`.

They are not ordinary object BRDF rows. They must not be routed through the
ordinary object PBR shader. They need a separate reflection/EnvMap contract with
its own vertex ABI, pixel ABI, samplers, constants, and material policy.

This is the most likely source of angle-dependent object PBR blinking.

### Skin Rows Are Missing From The Object Contract

NVR `ObjectTemplate.hlsl` has explicit `SKIN` variants. Skin rows use different
vertex input and constants:

- `BLENDWEIGHT`
- `BLENDINDICES`
- `SkinModelViewProj c1`
- `Bones c44`

OMV currently rejects skin vertex rows before object replacement. Any object
path that switches through skin rows will visibly leave the PBR contract.

This is one likely source of distance/pass-dependent blinking.

### OMV Owns Handles Per Draw; NVR Owns Shader Records

NVR attaches replacement records to the actual `NiD3DVertexShaderEx` and
`NiD3DPixelShaderEx` shader objects. At `SetShaders`, NVR calls `SetupShader()`,
chooses Default/Exterior/Interior replacement records, applies `SetCT()`, and
then lets the original game `SetShaders` run.

OMV currently classifies the current draw, temporarily writes replacement
handles into native shader wrappers, calls original `SetShaders`, then restores
the handles. This can work only if classification is perfect. It is not perfect,
so row transitions become visible.

### OMV Trusts Current Texture Stages Too Much

NVR `ShaderRecord::SetCT()` owns texture binding, sampler states, constants, and
optional buffer resolves per shader record.

OMV object PBR still relies on current global texture-stage capture for many
ordinary object rows. That is not a row-owned resource contract. With partial row
coverage, stale or row-incompatible resources can leak across draws.

## Non-Negotiable Rules

1. Do not fix PBR by globally disabling or enabling shader families.

2. Do not treat shader-pair matching as a full contract.

3. Do not route EnvMap rows through ordinary object PBR.

4. Do not route skin rows through a non-skin vertex shader.

5. Do not call object PBR complete while any runtime-visible object row can
   silently alternate between PBR and vanilla.

6. Do not rely on stale D3D sampler state unless the contract explicitly says
   that sampler is preserved and validated.

7. Do not do visible replacement while shader bytecode or D3D shader objects are
   still pending.

8. Do not expand terrain PBR until the object contract layer is fixed.

9. Unknown rows must be deterministic and logged. They must not become accidental
   PBR one frame and vanilla the next.

10. Performance is part of correctness. A visually correct row that adds large
    per-frame cost or runtime compile stalls is not a valid fix.

## Target Architecture

### Shader Contract Registry

Create a registry that is the only source of truth for native PBR replacement.

Each row contract must record:

- contract id;
- feature family: object, object skin, object EnvMap, object helper, LandLOD,
  close terrain, terrain fade;
- native vertex group/index;
- native pixel group/index;
- NVR source reference;
- Ghidra/reference output;
- vertex ABI;
- pixel ABI;
- required constants;
- required samplers;
- required sampler states;
- material resource source;
- shader bytecode key;
- shader ownership policy;
- fallback policy;
- implementation status.

Runtime code must ask the registry. Runtime code must not spread object/terrain
row decisions through ad hoc `if` chains.

### Draw Identity Classifier

Create a classifier that converts the current native draw into one of:

- `ObjectPbr(contract_id)`
- `ObjectSkinPbr(contract_id)`
- `ObjectEnvMapPbr(contract_id)`
- `ObjectHelperPbr(contract_id)`
- `ObjectVanilla(reason)`
- `CloseTerrainPbr(contract_id)`
- `LandLodPbr(contract_id)`
- `TerrainFadePbr(contract_id)`
- `TerrainVanilla(reason)`
- `UnknownVanilla(reason)`

Required inputs:

- native vertex shader wrapper;
- native pixel shader wrapper;
- shader group and row index;
- current pass pointer;
- selector pointer;
- pass entry pointer where proven;
- render pass enum and native light count;
- current material/resource state;
- vertex declaration where required;
- scene scope: interior, exterior, first person, menu/load.

This classifier is the core fix for object blinking. Row changes become explicit
contract transitions instead of accidental visual pops.

### Replacement Record

Create an OMV equivalent of NVR `ShaderRecord::SetCT()`.

Each replacement record owns:

- vertex shader object;
- pixel shader object;
- vertex constants;
- pixel constants;
- sampler bindings;
- sampler states;
- resource validation;
- state preservation;
- restore behavior;
- one-line diagnostic identity.

Handle mutation is only an implementation detail inside a complete replacement
record. It is not the contract.

### Object Material Binder

The object binder must prepare row resources before replacement:

- diffuse/base texture;
- normal texture;
- optional glow texture;
- optional projected shadow textures;
- optional point-light or helper resources;
- EnvMap/environment resources for reflection rows;
- skin resources only for skin contracts;
- alpha-test and blend state requirements.

The binder must not invent missing resources with broad neutral fallbacks for
implemented rows. Neutral fallback is only allowed when the contract explicitly
declares it safe.

### Shader Bytecode Lifecycle

Visible PBR can start only after enabled records have ready D3D shader objects.

Required behavior:

- load bytecode from cache by source hash, defines, profile, and contract id;
- compile missing bytecode before visible replacement or keep that contract
  vanilla for the session;
- create D3D shader objects before setting contract status to active;
- do not let background compilation change visible coverage during gameplay.

## Implementation Plan

### Phase 1: Object Transition Proof And Classification

Purpose: prove exactly which object rows blink and replace summary counters with
contract diagnostics.

Tasks:

- Add an object row transition tracker keyed by stable draw identity:
  selector, pass, vertex row, pixel row, and material/resource identity when
  available.
- Log bounded transitions when the same visible object/material moves between:
  PBR, skin fallback, EnvMap fallback, unsupported ABI, and unsupported family.
- Add row labels for all PPLighting object candidate rows, including skin and
  EnvMap.
- Keep logs bounded and summary-based.

Acceptance:

- A playtest log can name the exact object rows that blink.
- The same object/material cannot change state without one contract transition
  log.
- We can separate distance blink, angle blink, and helper/light blink by row.

### Phase 2: Replace Object Row Buckets With Exact Contracts

Purpose: remove `ReplacementShaderKind` as the object contract.

Tasks:

- Build an exact NVR-derived object row table from `PBR.h`.
- Store exact vertex row, pixel row, source defines, sampler layout, constants,
  and ABI per row.
- Keep `ReplacementShaderKind` only as a compiled-shader cache key if still
  useful, not as eligibility.
- Mark every object row as:
  - implemented;
  - object skin contract pending;
  - EnvMap contract pending;
  - unknown and blocked.
- Make ordinary object, helper, point-light, projected-shadow, LOD, hair, STBB,
  diffuse-only, only-light, and only-specular rows explicit.

Acceptance:

- Runtime object replacement eligibility comes from the registry.
- EnvMap rows cannot be classified as ordinary object PBR.
- Skin rows cannot be classified as non-skin object PBR.
- Unknown object candidates produce deterministic logs.

### Phase 3: Port NVR ObjectTemplate Source-Equivalent Rows

Purpose: remove vertex/pixel ABI drift between OMV and NVR.

Tasks:

- Replace OMV's hand-shaped object vertex shader with source-equivalent NVR
  `ObjectTemplate.hlsl` logic for object rows.
- Preserve OMV include paths and constants only where they intentionally map to
  NVR registers.
- Implement exact low-light and high-light vertex outputs.
- Implement exact NVR sampler layout:
  - normal rows: `BaseMap s0`, `NormalMap s1`;
  - `DIFFUSE` and `ONLY_SPECULAR`: `NormalMap s0`;
  - SI/hair glow stage variants;
  - projected-shadow stage variants.
- Preserve NVR object constants:
  - `TESR_PBRData c32`;
  - `TESR_PBRExtraData c33`.

Acceptance:

- Implemented object rows use source-equivalent NVR ABI.
- Pixel shader inputs match the selected vertex row.
- Helper and projected rows do not borrow the wrong sampler layout.

### Phase 4: Implement Skin Object Contract

Purpose: remove one large source of object PBR fallback mixing.

Tasks:

- Add skin variants from NVR `ObjectTemplate.hlsl`.
- Add skin vertex input:
  - `BLENDWEIGHT`;
  - `BLENDINDICES`.
- Use skin registers:
  - `SkinModelViewProj c1`;
  - `Bones c44`.
- Port `SkinHelpers.hlsl` dependency or an OMV equivalent.
- Add exact contract rows for NVR skin object variants.
- Validate first on rows that share the ordinary object material layout.

Acceptance:

- Skin rows no longer hit generic `skin_vertex_abi` fallback.
- Skin rows never use non-skin object vertex ABI.
- Object PBR does not blink because a draw switches into a skin vertex row.

### Phase 5: Implement EnvMap/Reflection Contract

Purpose: fix angle-dependent object PBR blinking.

Tasks:

- Treat vertex rows `50..52` and pixel rows `57..59` as EnvMap contracts.
- Research exact EnvMap vertex/pixel ABI from vanilla sources/Ghidra output.
- Define EnvMap samplers, constants, and material resources.
- Implement EnvMap replacement only as a separate reflection record.
- Ensure ordinary object records and EnvMap records share material tuning where
  appropriate but do not share shader ABI.

Acceptance:

- Reflective objects do not switch between ordinary PBR and vanilla on camera
  angle.
- EnvMap rows are visible in contract diagnostics as reflection rows.
- No EnvMap row can consume ordinary object samplers by accident.

### Phase 6: NVR-Style Shader Ownership

Purpose: stop draw-local handle mutation from being the architecture.

Tasks:

- Replace temporary replacement ownership with persistent per-native-shader
  replacement records, modeled after NVR `ShaderProg`.
- Store records by native shader wrapper and scene scope where needed:
  default, exterior, interior.
- At `SetShaders`, select the record and apply constants/resources before the
  original game call.
- Restore only through owned record state, not ad hoc current-pass cleanup.
- Keep lazy ownership compatible with external shader loader hooks.

Acceptance:

- A shader wrapper has a stable OMV replacement record when implemented.
- Fallback rows restore native state deterministically.
- Object PBR coverage does not depend on whether the previous draw had PBR.

### Phase 7: Row-Owned Object Resource Binding

Purpose: eliminate stale texture/sampler leakage.

Tasks:

- Move object sampler validation into replacement records.
- Bind or explicitly preserve every sampler named by the row contract.
- Diff sampler states before applying them.
- Remove broad neutral normal fallback from implemented rows.
- Add row-specific missing-resource fallback reasons.

Acceptance:

- Implemented rows do not depend on stale global texture-stage capture.
- Missing normal/glow/shadow resources produce deterministic vanilla fallback or
  an explicitly safe declared fallback.
- Interior/exterior point lights do not lose resources because a helper row used
  a base object sampler layout.

### Phase 8: Object Performance Hardening

Purpose: keep object PBR quality without FPS collapse.

Tasks:

- Prebuild object shader bytecode and D3D shader objects before visible
  replacement.
- Remove heap allocations from object draw hot paths.
- Avoid broad shader-table scans during draws.
- Cache row lookup by native shader wrapper pair.
- Cache material/resource plans by stable selector/material identity.
- Add object-family performance counters:
  - replaced rows;
  - fallback rows;
  - shader switches;
  - sampler binds;
  - resource lookups;
  - cache misses.

Acceptance:

- Warm-cache object PBR causes no runtime shader compilation.
- Object PBR frame cost is measurable and attributable.
- No object PBR fix reintroduces multi-second stalls.

### Phase 9: Apply The Same Contract Layer To Terrain

Purpose: fix terrain with the same architecture after object ownership is proven.

Tasks:

- Move close terrain, LandLOD, and terrain fade rows into the same registry.
- Classify terrain from VPT/NVR pass identity, not shader pair alone.
- Bind active terrain layers by proven pass/material identity.
- Implement terrain fade and LandLOD as one coherent terrain family.
- Use terrain constants and samplers only from proven row contracts.

Acceptance:

- Terrain PBR cannot produce rectangular chunks from partial shader-row
  replacement.
- Close terrain, fade, and LandLOD share coherent lighting and material params.
- Terrain FPS cost is isolated by family.

## Immediate Next Change

Implement Phase 1 and Phase 2 together for object PBR:

1. Add contract-centric object transition diagnostics.
2. Add exact object row contract records from NVR `PBR.h`.
3. Stop using broad object buckets as eligibility.
4. Make skin and EnvMap rows explicit contract families instead of generic
   unsupported rows.
5. Build and install.

This should not try to "fix" terrain yet. It should make the object blink
mechanism visible and give the next patch a real row contract to implement.

## Playtest Gate For Object PBR

Test scenes:

- interior room with local lamps;
- nearby metal prop;
- reflective object/window if available;
- weapon/first-person object;
- exterior building wall at near/mid/far distance;
- object crossing LOD distance.

Pass criteria:

- object PBR does not blink with distance;
- object PBR does not blink with camera angle;
- metallicness/roughness response remains stable across row transitions;
- skin rows are either implemented or reported as skin contracts, not accidental
  ordinary object fallback;
- EnvMap rows are either implemented reflection contracts or reported as
  reflection contracts, not ordinary object rows;
- logs identify every object fallback by contract reason;
- warm-cache gameplay has no object shader compilation stalls.

## Definition Of Done

Object PBR is done when:

- every runtime-visible object PBR candidate has a registry contract;
- ordinary, helper, point-light, projected, LOD, hair/STBB, diffuse-only,
  only-light, and only-specular rows are implemented source-equivalent to NVR;
- skin rows are implemented with skin ABI or are explicitly tracked as a
  separate unfinished contract;
- EnvMap rows are implemented as reflection contracts or explicitly tracked as a
  separate unfinished contract;
- no visible object alternates between PBR and vanilla because of distance,
  camera angle, pass helper rows, or material flags;
- object resources and sampler states are row-owned;
- object shader ownership is stable per native shader record;
- object PBR has bounded, attributable performance cost.

Terrain PBR is not allowed to be called fixed until it passes the same contract
standard through close terrain, fade, and LandLOD.

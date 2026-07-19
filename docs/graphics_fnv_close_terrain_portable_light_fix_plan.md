# FNV Close-Terrain Portable Point-Light Fix Plan

## Status

This document is the implementation plan for the OMV close-terrain PBR failure
to receive portable point lights such as the Pip-Boy light and lighter/torch
lights at night.

The engine-side defect class is proven:

- the general active-light iterators are `FUN_00B70590` and `FUN_00B70680`;
- the non-shadow iterators are `FUN_00B70600` and `FUN_00B70700`;
- the non-shadow iterators reject every `ShadowSceneLight` whose byte at
  `+0xEC` equals `1`;
- vanilla close-land pass construction at `FUN_00BDF3E0` uses only the
  non-shadow iterators;
- Vanilla Plus Terrain (VPT) replaces `FUN_00BDF3E0` but retains the same
  non-shadow-only selection while expanding terrain to 24 point lights;
- VPT's source comment says that the remaining array should be filled with
  active shadow lights, but the implementation calls the non-shadow iterator
  again;
- OMV receives the VPT-selected row and staged constants downstream. It does
  not own or alter VPT's terrain-light membership.

The exact runtime identity bridge from the data-driven `PipBoyLight` form to
the resulting `NiLight` still requires one bounded runtime capture. Static
analysis proves form `0x00000147`, Pip-Boy effect application/removal, actor
shadow-candidate publication, the `+0xEC` writer, and the terrain iterator
filters, but it cannot prove that the actor candidate's `+0x128` source object
is the same object as the Pip-Boy candidate's `NiLight*` at `+0xF8`.

No production selection patch may be committed until Phase 0 closes that
runtime identity and bound-membership gap.

## Authoritative Evidence

Ghidra output is the ground truth for game behavior:

- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_portable_light_classification_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_pipboy_light_0147_shadow_path_audit.txt`

The scripts that produced those outputs are:

- `analysis/ghidra/scripts/graphics_fnv_close_terrain_portable_light_classification_audit.py`
- `analysis/ghidra/scripts/graphics_fnv_close_terrain_pipboy_light_0147_shadow_path_audit.py`

Relevant dependency source is present only as research material:

- `.research/fnv-vanilla-plus-terrain-main/VanillaPlusTerrain/main.cpp`
- `.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl`

`.research/` is not product source and must not become the release build input.
The actual VPT changes belong in an upstream repository or a maintained fork.

## Objective

Make close terrain receive the same active portable point-light contribution
as nearby objects while preserving:

- VPT ownership of the terrain pass, light list, constants, and shader rows;
- the native general-light ordering and active-light validity filters;
- the separate sun light passed to the landscape render pass;
- the VPT `0/6/12/24` point-light capacity rows;
- the 24-point-light maximum;
- light multibound membership;
- `PointLightColor.a` runtime fade;
- `PointLightPosition.w` radius;
- current OMV `c39/c63/c88` consumption and `c89/c90` ownership;
- per-draw native fallback;
- object PBR behavior;
- current close-terrain performance;
- TerrainFade and LandLOD as separate contracts.

This fix admits a shadow-classified light's illumination to close terrain. It
does not add point-light shadow-map sampling to terrain. Point-light shadow
projection would require a separate resource, buffer, sampler, constant, and
render-stage contract.

## Non-Goals

Do not use this work to:

- hook `FUN_00BDF3E0` from OMV while VPT owns it;
- change `ShadowSceneLight +0xEC` classification;
- hook `FUN_00B9DCB0`, `FUN_00B9E970`, or candidate cleanup;
- add a second fade or selection-history buffer;
- remove VPT's multibound filter globally;
- add point lighting to TerrainFade or LandLOD;
- broaden close-terrain replacement into interiors or unproven row families;
- change object PBR light selection;
- globally disable close-terrain PBR and present that as the fix;
- add a shader-only approximation for missing engine light data;
- make OMV load or initialize `VanillaPlusTerrain.dll`.

## Ownership Model

The final change spans two components.

### VPT owns

- landscape light enumeration;
- construction of the close-land render pass;
- selection of the `0/6/12/24` point-light row;
- attachment of `ShadowSceneLight` entries to the render pass;
- staging `PointLightColor c39`, `PointLightPosition c63`, and
  `PointLightCount c88`;
- VPT native terrain shader fallback;
- the detour at `FUN_00BDF3E0`.

### OMV owns

- dependency/capability detection after dependencies have loaded;
- exact VPT row-to-OMV shader-variant replacement;
- preservation of VPT's `c39/c63/c88` state;
- OMV terrain registers `c89/c90`;
- detailed same-draw diagnostics;
- user-visible degraded-contract reporting;
- the PBR point-light material response.

OMV must not install a second landscape pass or light-selection hook.

## Phase 0: Runtime Proof Gate

Prepare one diagnostic-only VPT build that compares the general and non-shadow
candidate lists inside `AddPass_Landscape` without changing the render pass.

### Capture trigger

Use a bounded, explicitly armed diagnostic. Do not log every terrain draw.
Capture candidate transitions during:

1. Pip-Boy light off;
2. Pip-Boy light on;
3. lighter/torch off;
4. lighter/torch on.

The diagnostic logger must be removed from the release render path or be behind
a disabled-by-default cold gate with no production I/O.

### Candidate fields

For each candidate returned by the general iterator, capture:

- `ShadowSceneLight*` address;
- `+0xEC` shadow classification;
- `+0xF4` point-light classification;
- `+0xF5` ambient-light classification;
- `NiLight*` at `+0xF8`;
- source object at `+0x128`, when valid;
- active marker at `+0x110`;
- `fLODDimmer`;
- `fFade`;
- light RGB and dimmer;
- world position;
- radius;
- `NiLight::IsLit()` result;
- `NiLight::IsInMultiBound()` result for the terrain geometry;
- whether the same candidate is returned by the non-shadow iterator.

### Required proof

The expected result is:

```text
portable light off:
    candidate absent or inactive

portable light on:
    candidate present in the general list
    +0xEC == 1
    +0xF4 == 1
    +0xF5 == 0
    spLight != null
    IsLit == true
    IsInMultiBound == true
    absent from the non-shadow list
```

### Stop conditions

Do not apply the iterator change if any of these occurs:

- the portable light has `+0xEC == 0`;
- it is absent from the general list;
- `bPointLight` is false;
- `spLight` is null;
- `IsLit()` is false;
- `IsInMultiBound()` is false.

Those results identify a different contract failure. In particular, do not
remove the multibound filter merely because a player-attached light fails it.
Research the portable-light bound contract and safe intervention point first.

## Phase 1: Correct VPT Landscape Light Selection

Change VPT's `BSShaderPPLightingProperty` wrappers from the non-shadow helpers:

```text
first: 0x00B70600
next:  0x00B70700
```

to the general active-light helpers:

```text
first: 0x00B70590
next:  0x00B70680
```

Rename the wrappers to reflect their real semantics:

```cpp
GetFirstActiveLight
GetNextActiveLight
```

Replace the current special first-light loop and second remaining-light loop
with one direct append loop equivalent to:

```cpp
for (pLight = GetFirstActiveLight(&pIter);
     pLight && usedPointLights < maxPointLights;
     pLight = GetNextActiveLight(&pIter)) {
    if (!pLight->bPointLight || pLight->bAmbientLight || !pLight->spLight)
        continue;

    if (!pLight->spLight->IsLit())
        continue;

    if (!pLight->spLight->IsInMultiBound(pMultiBound))
        continue;

    pointLights[usedPointLights++] = pLight;
}
```

The exact implementation should follow the VPT project's style, but these
filters are mandatory.

### Why pointer-only redirection is insufficient

Changing only VPT's two helper-address globals would cause the existing loop to
accept every general active light. A directional or ambient candidate could
then enter the point-light array, duplicate the separately supplied sun, alter
ambient ownership, or select an incorrect point-light row.

The corrected loop must explicitly accept point lights and reject ambient and
directional lights.

### State that must remain unchanged

Preserve:

- `ResortLights()` and its camera bound;
- general-list distance ordering;
- maximum 24 point lights;
- `apSun` as the separately supplied first light;
- render-pass `1 + usedPointLights` count;
- row base and canopy-shadow offset;
- capacity promotion at more than 6 and more than 12 lights;
- `IsLit()` behavior;
- `IsInMultiBound()` behavior;
- `UpdateLightsAlt` position transforms;
- light RGB/dimmer calculation;
- `fLODDimmer` and `fFade`;
- forced-darkness behavior;
- non-HDR clamping;
- all VPT hooks and ownership boundaries.

Do not skip zero-fade active candidates during selection. The existing fade is
the continuity contract and must be allowed to transition smoothly.

## Phase 2: Preserve Fade in VPT Native Terrain

VPT stages `ShadowSceneLight::fFade` in `PointLightColor.a`, but its native
terrain shader currently passes only `.rgb` to point-light evaluation.

Change:

```hlsl
PointLightColor[i].rgb
```

to:

```hlsl
PointLightColor[i].rgb * saturate(PointLightColor[i].a)
```

This is required for PBR-off terrain and per-draw native fallback. Without it,
the corrected selection can introduce abrupt chunk-shaped light transitions
outside the OMV replacement even though OMV itself consumes the fade.

Recompile every VPT close-terrain point-light pixel shader:

- texture counts `1..7`;
- 6-light variants;
- 12-light variants;
- 24-light variants.

This is 21 affected pixel shaders. Zero-light variants and the vertex shader do
not need functional changes. LandLOD and TerrainFade shaders are outside this
change.

## Phase 3: Publish a VPT Terrain Contract Version

The corrected VPT build must publish an explicit capability that OMV can query
without inspecting private module offsets or loading the dependency.

### VPT changes

- bump `PluginInfo.version` from `101` to `102`;
- add an exact C export:

```cpp
EXTERN_DLL_EXPORT uint32_t
VanillaPlusTerrain_GetTerrainContractVersion() {
    return 102;
}
```

Contract version `102` means:

- general active-point-light enumeration;
- shadow-classified point lights are eligible for close terrain;
- explicit point/ambient/directional filtering;
- unchanged light ordering and multibound filtering;
- unchanged `c39/c63/c88` layout;
- VPT native terrain consumes `PointLightColor.a` fade.

The export is preferred over PE-version parsing, private RVA inspection, or
signature scanning. OMV must resolve it only from an already-loaded module.

## Phase 4: OMV Compatibility Contract

### `omv/src/compat.rs`

Replace the single VPT-presence interpretation with two separate capabilities:

```text
base VPT terrain contract:
    VanillaPlusTerrain.dll present
    Fallout Shader Loader.dll present
    LODFlickerFix.dll present

portable-light terrain contract:
    base contract
    VanillaPlusTerrain_GetTerrainContractVersion export present
    returned version >= 102
```

Use `libpsycho::os::windows::winapi::get_module_handle_w` and
`get_proc_address`. Never call `LoadLibrary` for VPT.

Record:

- VPT module presence;
- export presence;
- returned contract version;
- base terrain-contract availability;
- portable-light-contract availability.

An absent export identifies legacy VPT. Do not infer compatibility from private
bytes or assume that every future DLL named `VanillaPlusTerrain.dll` has the
corrected contract.

### `omv/src/startup.rs`

Detect and publish both capabilities from `DeferredInit`, where current
dependency ownership is already resolved. Do not move graphics initialization
or config publication back into `NVSEPlugin_Load`.

### `omv/src/effects/pbr/engine_contracts.rs`

Store the base VPT contract and portable-light contract separately. A compact
atomic version/flag representation is sufficient. Do not add a lock to the
draw path.

### `omv/src/effects/pbr.rs`

Extend `NativePbrRuntimeStatus` with:

- `vpt_terrain_contract_version`;
- `close_terrain_portable_lights_ready`.

Keep base terrain readiness separate so TerrainFade and LandLOD are not
disabled by a close-terrain-only capability mismatch.

### `omv/src/runtime.rs`

Show a clear status beneath Close terrain:

```text
Portable terrain lights: supported (VPT contract 102)
```

or:

```text
Portable terrain lights: unsupported by legacy VPT; install contract 102+
```

Do not report the entire PBR system as failed solely because legacy VPT lacks
this capability.

### Legacy behavior

When the export is absent or returns less than `102`:

- log one prominent compatibility warning;
- mark portable terrain lighting degraded;
- do not silently claim support;
- do not terminate the game;
- do not install a competing OMV terrain hook;
- do not globally disable close-terrain PBR and present that as the fix.

The supported release/install path must provide the corrected VPT build.

## Phase 5: OMV Detailed Point-Light Telemetry

The release behavior does not need new OMV light writes. Detailed diagnostics
need enough native-state evidence to prove that the corrected VPT contract
reaches the selected OMV shader variant unchanged.

### `omv/src/effects/pbr/hooks.rs`

Create one helper that decodes a close-terrain pixel-table index into:

- texture count;
- point-light capacity.

For pixel table B, using base index `92`:

```text
offset within each eight-row texture block:
    0 -> 0 lights
    2 -> 6 lights
    4 -> 12 lights
    6 -> 24 lights
```

Reject every other offset as outside the proven close-terrain replacement
family.

When `debug_log_draws` is enabled, capture the native state after VPT selects
and binds its row and before OMV uploads `c89/c90`:

- pass index;
- pixel table/index;
- texture count;
- selected capacity;
- `PointLightCount c88`;
- active `PointLightColor c39` entries;
- active `PointLightPosition c63` entries;
- minimum and maximum active alpha;
- a stable signature of the active point-light constants.

Read no more entries than the selected capacity and clamp the diagnostic count
to `0..24`.

### `omv/src/effects/pbr/diagnostics.rs`

Store:

- last close-terrain pass;
- last pixel table index;
- last texture count;
- last capacity;
- last native point-light count;
- last light signature;
- last alpha range;
- transition count.

Log only when row, count, or signature changes. Do not log every draw.

### Production performance contract

With detailed diagnostics disabled, add no:

- D3D `GetPixelShaderConstantF` call;
- candidate walk;
- allocation;
- lock attempt;
- hashing;
- string formatting;
- logging;
- constant snapshot or restore.

The disabled path may contain only the existing diagnostic-mode load and early
branch. Put capture code in a cold routine.

### Expected draw transition

```text
portable light off:
    zero-light row
    c88 = 0

portable light on:
    6/12/24-capacity row
    c88 >= 1
    valid c39/c63
    alpha changes continuously during fade
```

OMV must continue to upload only terrain registers `c89/c90`. Do not copy,
rewrite, normalize, or reconstruct VPT's `c39/c63/c88` values.

## Phase 6: OMV Shader Scope

No functional OMV close-terrain shader change is planned.

The existing shader already:

- declares `PointLightColor` at `c39`;
- declares `PointLightPosition` at `c63`;
- declares `PointLightCount` at `c88`;
- clamps the runtime count to the compiled capacity;
- uses the same local coordinate space as VPT;
- uses `PointLightPosition.w` as radius;
- multiplies RGB by `saturate(PointLightColor.a)`.

Do not retune attenuation, roughness, light scale, or normal response to hide a
missing engine light. If corrected VPT supplies valid `c39/c63/c88` and terrain
is still dark, capture a matched native/PBR draw and diagnose shader response as
a separate evidence branch.

## Phase 7: Packaging and Distribution

### Recommended delivery

Publish the corrected VPT build as a separate, visible dependency component.
Do not hide or overwrite VPT from inside OMV's plugin data directory.

The corrected VPT package must include:

- `VanillaPlusTerrain.dll` with contract version `102`;
- all rebuilt close-terrain point-light `.pso` files;
- the GPLv3 license;
- the exact corresponding source commit or complete corresponding source;
- a changelog that identifies the modified build;
- dependency metadata for Fallout Shader Loader and LOD Flicker Fix.

OMV release metadata must declare the corrected VPT contract as the supported
close-terrain dependency.

If OMV and the VPT fork are distributed in one archive, keep them as separate
components and update `omv/THIRD_PARTY_NOTICES.md`. Do not silently replace an
existing user's VPT install.

### Build ownership

The current Rust workspace must not consume `.research/` or assume that the
external Visual Studio VPT project can be built by Cargo. Maintain the VPT build
in its own repository/toolchain until a reproducible supported i686 build is
deliberately added.

Do not add a prebuilt third-party DLL to the Rust build as an unexplained binary
blob.

## Phase 8: Documentation Changes

Update these existing documents when implementation begins:

### `docs/graphics_fnv_pbr_errata.md`

Record:

- the `+0xEC == 1` omission;
- the general and non-shadow iterator address pairs;
- why pointer-only redirection is unsafe;
- VPT contract version `102`;
- the required fade-alpha preservation;
- that point-light shadows remain a separate contract.

Add do-not-repeat rules:

- do not change `+0xEC` to make terrain see a light;
- do not hook VPT's landscape owner from OMV;
- do not remove multibound checks globally;
- do not ignore `PointLightColor.a`;
- do not globally disable close terrain as the fix;
- do not add guessed shadow textures or samplers.

### `docs/graphics_fnv_omv_dependency_compatibility_plan.md`

Define:

- base VPT terrain availability;
- portable-light contract `102`;
- legacy degraded behavior;
- unchanged VPT ownership of `FUN_00BDF3E0` and light staging.

### `docs/graphics_fnv_pbr_light_shadow_continuity_fix_plan.md`

Add a close-terrain branch for native light membership being absent before the
existing constant-divergence branch. The branch must direct selection fixes to
VPT rather than OMV shader math.

## Phase 9: Validation Matrix

Run the following outdoors at night:

- Pip-Boy light;
- lighter/torch;
- ordinary static non-shadow point light;
- shadow-classified static point light;
- multiple lights below and above 6;
- multiple lights below and above 12;
- camera movement across terrain chunks;
- cell transition with a fading light;
- PBR enabled;
- PBR disabled using VPT native terrain;
- one forced per-draw OMV fallback, if the diagnostic build supports it.

### Expected behavior

- close terrain and nearby objects both receive the portable light;
- the point-light count does not include the sun;
- no ambient or directional candidate enters the point-light array;
- the selected capacity matches the number of attached point lights;
- `c88` never exceeds the selected capacity or 24;
- point positions and radii remain stable;
- alpha changes continuously during toggles and transitions;
- no chunk-shaped pop, blink, or stale light remains;
- static non-shadow terrain lights remain unchanged;
- object PBR remains unchanged;
- TerrainFade and LandLOD remain unchanged;
- close-terrain interior admission remains unchanged;
- zero-light terrain continues to use the zero-light shader;
- no null-light crash occurs.

### Performance acceptance

- no logging or D3D readback in the normal draw path;
- no additional per-pixel work in zero-light shaders;
- the general iterator remains a single ordered list walk;
- the explicit point/ambient checks add no allocation or synchronization;
- exterior zero-light and representative multi-light frame times remain within
  measurement noise of the current VPT/OMV path;
- the historical close-terrain `-40 FPS` failure does not recur.

### Compatibility acceptance

- corrected VPT reports contract `102` and OMV recognizes it;
- legacy VPT produces one clear degraded warning;
- missing VPT/FSL/LODFF retains existing dependency behavior;
- OMV never loads VPT itself;
- no duplicate landscape hook is installed;
- object PBR remains available independently of the VPT portable-light
  capability.

## Failure Branches

### Portable candidate is not shadow-classified

Do not change iterators. Research the actual exclusion condition using the
Phase 0 snapshot.

### Portable candidate fails multibound

Do not remove `IsInMultiBound()` globally. Research the player-attached light's
world bound, terrain multibound ownership, and the native object-light handling
for the same candidate.

### Corrected pass selects a point row but `c88` remains zero

Inspect VPT render-pass light attachment and `UpdateLightsAlt`. Do not change
the OMV shader or synthesize a count.

### `c88` is positive but `c39/c63` are invalid

Fix VPT staging or capacity registration. Do not reconstruct engine constants
from the camera or form data in OMV.

### `c39/c63/c88` are correct but OMV terrain remains dark

Capture the same native draw with PBR on and off. Only then diagnose attenuation,
normal-space, roughness, or material response.

### Illumination works but terrain lacks point-light shadows

That is not a failure of this plan. Point-light shadow reception needs a new
engine-side contract for shadow texture, mask, projection constants, render
phase, lifetime, performance, and fallback.

## Build Verification

Build OMV explicitly for the supported 32-bit target:

```bash
cargo fmt --check
cargo build --release --target i686-pc-windows-gnu -p omv
```

Then run the repository's supported FNV build targets:

```bash
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Build and package the corrected VPT dependency with its own supported 32-bit
toolchain, including all rebuilt loose shaders.

## Completion Criteria

The fix is complete only when:

1. Phase 0 proves the portable candidate's exact exclusion;
2. VPT uses the general active-light list with explicit point filtering;
3. VPT native terrain consumes the staged alpha fade;
4. VPT publishes contract version `102`;
5. OMV reports and diagnoses the contract without taking VPT hook ownership;
6. PBR-on and VPT-native fallback both pass the portable-light matrix;
7. object PBR, TerrainFade, and LandLOD show no regression;
8. the normal render path has no new readback, logging, allocation, or lock;
9. the corrected VPT source and GPL obligations are present in distribution;
10. the evidence and final behavior are recorded in the graphics errata.

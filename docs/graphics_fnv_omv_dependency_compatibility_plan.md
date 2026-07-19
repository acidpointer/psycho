# Oh My Vegas Graphics Dependency And Compatibility Plan

The graphics mod is **Oh My Vegas!**. In code and logs, use the short name `OMV` / `omv` where a compact identifier is needed. The crate, DLL, config, and runtime paths are named `omv`.

## New Priority Order

1. NVR coexistence is no longer a requirement. Do not spend implementation budget on making OMV and New Vegas Reloaded safe together.
2. Dependencies are allowed when they own real engine contracts. Do not reimplement VPT/FSL/LODFF just to avoid dependency declarations.
3. Close terrain PBR should use the VPT terrain contract, not an OMV-only terrain guess.
4. Standalone OMV without those dependencies may still offer non-overlapping features, but dependency-backed features must fail closed and log the missing requirement.
5. Every hook is installed only after dependency detection. Early graphics hook grabs are not acceptable for VPT/FSL dependency handling.

## Dependency Policy

OMV should document exact dependency tiers:

- **Core OMV graphics runtime:** no hard NVR dependency.
- **Close terrain / terrain fade / terrain point-light PBR:** require Vanilla Plus Terrain's contract.
- **Vanilla Plus Terrain dependency chain:** VPT requires Fallout Shader Loader and LOD Flicker Fix. VPT source checks `Fallout Shader Loader.dll` version `>= 131` and requires `LODFlickerFix.dll`.
- **Portable close-terrain point lights in OMV PBR:** use the engine's general
  active-light list and deduplicate against the current native pass. No VPT
  version, export, filename, or private RVA is a portable-light capability
  signal.
- **NVR:** not a dependency and not a supported compatibility target.
- **Shader source reference:** TESReloaded10/NVR is reference material. OMV must not patch, edit, or depend on NVR internals.

Practical result:

- It is acceptable for OMV terrain PBR to require VPT/FSL/LODFF.
- It is acceptable for OMV to disable terrain PBR when VPT is missing.
- It is not acceptable for OMV to require NVR for OMV features.
- It is acceptable to document NVR co-installation as unsupported.

## Hook Ownership Rules

Graphics hooks must be module-aware. OMV is an xNVSE plugin and installs final graphics hooks only after xNVSE lifecycle messages make dependency and owner detection meaningful.

Known owners:

- `Fallout Shader Loader.dll` owns shader creation hooks at `CreateVertexShader @ 0x00BE0FE0` and `CreatePixelShader @ 0x00BE1750`, plus shader reload behavior.
- `VanillaPlusTerrain.dll` owns the VPT terrain substrate:
  - `BSShaderPPLightingProperty::SetLandscapeSpecularExponents @ 0x00B66640`
  - `BSShaderPPLightingProperty::AddPass_Landscape @ 0x00BDF3E0`
  - seven `BSShaderPPLightingProperty::AddPasses` vtable slots
  - `ShadowLightShader::InitShaderConstants` vtable `0x10AF414`
  - `ShadowLightShader::UpdateLights` call `0x00B7DBAC`
  - `ShadowLightShader::UpdateToggles` call `0x00B7DC5B`
  - `ShadowLightShader::LoadStagesAndPasses` vtable `0x10AF448`
  - `ShadowLightShader::Reinitialize` vtable `0x10AF418`
- `NewVegasReloaded.dll` owns a broad shader manager layer:
  - shader creation detours
  - `SetShaderPackage`
  - `BSShader::SetShaders @ 0x00BE1F90`
  - render/image-space/depth/reflection hooks
  - `NiD3DVertexShaderEx` / `NiD3DPixelShaderEx` object extension strategy

OMV rules:

- If VPT is loaded, do not install duplicate terrain pass/light/constant hooks.
- OMV may read the current engine pass and active PPLighting property at its own
  admitted replacement draw. This downstream read-only merge is not ownership
  of VPT's pass builder or constants.
- If FSL is loaded, do not install competing shader creation hooks unless an explicit chain is implemented and proven.
- NVR hook ownership is not an OMV compatibility target. Do not add special NVR hook chaining unless the project explicitly reopens that goal.
- If a known hook target has a non-vanilla prologue and the owner is unknown, disable the overlapping OMV feature and log the address, expected owner, and feature disabled.

## Feature Plan

### Object PBR

Object PBR remains the easiest OMV-owned native target.

Required cleanup:

- Remove accidental skin-variant matches from ordinary object PBR.
- Keep object `TESR_PBRData c32` / `TESR_PBRExtraData c33` object-only.
- Treat SI, HAIR, PAR/POM, only-light, only-specular, diffuse point, and skin as separate shader-family projects.
- Do not add NVR hook-chain work for object PBR unless NVR compatibility is explicitly reopened.

### Terrain PBR

Do not pursue dependency-free close terrain PBR. Use the VPT contract.

Required dependencies for terrain PBR:

- Vanilla Plus Terrain.
- Fallout Shader Loader, transitively required by VPT.
- LOD Flicker Fix, required by VPT and NVR.

Contract OMV may rely on when VPT is loaded:

- terrain rows `503..558`
- terrain fade row `560`
- `LandSpec c32/c33`
- `LandHeight c34/c35`
- fog `c36/c37`
- `LandLODSpec c38`
- point lights `c39/c63/c88`
- EyePosition vertex flags for land rows
- VPT terrain pass/light selection

Portable-light correction is OMV-owned and downstream:

- enumerate `0x00B70590/0x00B70680` only during an admitted OMV close-terrain
  replacement draw;
- filter point/non-ambient/IsLit/multibound candidates;
- deduplicate by `NiLight*` against the current pass;
- preserve general-list order and the combined 24-light cap;
- upload only missing entries through disjoint OMV constants;
- consume native and supplemental fade alpha in the OMV shader.

This makes an upstream fix self-disabling: once the current pass already owns
the identity, OMV supplies no duplicate. An incompatible future pass/shader ABI
must fail the normal OMV draw gate rather than be inferred from a module
version.

OMV/NVR terrain constants still need OMV-side ownership if OMV supplies the shader logic:

- `TESR_TerrainData c89`
- `TESR_TerrainExtraData c90`
- supplemental point-light count `c91`
- supplemental interleaved position/radius and color/fade `c92..c139`

Future terrain parallax constants must use a separately proven non-overlapping
ABI; `c91/c92` are no longer available for the old speculative parallax plan.

### LandLOD

Current OMV base LandLOD now follows the NVR/VPT terrain register split:

- use VPT `LandLODSpec c38`;
- use terrain controls `c89/c90` for NVR-style terrain tuning;
- split base LandLOD from projected-shadow/fade if runtime proof shows different ABI;
- keep projected-shadow/fade disabled until their ABI is proven.

### PAR/POM

Object parallax is not ordinary object PBR.

- NVR maps `PAR*` shaders to POM and uses `TESR_ParallaxData c35`.
- Ghidra proves PAR2 belongs to a separate `ParallaxShader` object with separate arrays.
- Keep this out of the OMV PBR survival path.

## Implementation Order

1. Add xNVSE-aware graphics dependency detection and log a concise compatibility report.
2. Move final OMV graphics hook installation to after xNVSE `PostLoad` / `DeferredInit`, or add a revalidation phase that can stand down before any conflicting draw hook is used.
3. Add feature ownership decisions:
   - VPT present -> use VPT terrain substrate; no duplicate VPT hooks.
   - FSL present -> no competing shader creation hook unless chained.
4. Rename user-facing graphics strings to Oh My Vegas / OMV without doing a risky crate/DLL rename in the same pass.
5. Fix object PBR matcher to exclude skin variants.
6. Correct LandLOD register ownership.
7. Only after those are stable, add terrain PBR that explicitly requires VPT/FSL/LODFF.
8. Add the OMV-only identity-deduplicated portable-light supplement and prove
   old-omission plus future-upstream-fix behavior with pure tests.

## Documentation Requirement

Every OMV release note and config UI must distinguish:

- feature disabled because dependency is missing;
- feature disabled because another unknown graphics mod owns the hook;
- feature disabled by user config.

Silent fallback is not acceptable for graphics feature ownership. The logs must explain exactly why a feature did or did not install.

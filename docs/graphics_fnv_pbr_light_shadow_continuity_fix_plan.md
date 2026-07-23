# FNV PBR Light and Shadow Continuity Static Plan

Date: 2026-07-19

## Decision

Treat the confirmed close-terrain portable-light omission as an OMV replacement
shader contract defect. Correct it downstream from native pass construction
with an identity-deduplicated supplemental merge. Do not patch dependency
source, add a version handshake, change the native sorter, or add diagnostic
gameplay work.

Other light/shadow continuity concerns remain separate unless static evidence
identifies an exact OMV mismatch.

## Scope Verdict

### Close-terrain portable point lights

Actionable. The engine audit proves two active-list classes:

- general: `0x00B70590/0x00B70680`;
- non-shadow: `0x00B70600/0x00B70700`, which additionally excludes
  `ShadowSceneLight+0xEC == 1`.

The researched expanded landscape builder uses the non-shadow class. OMV will
read the general class only for an already-admitted OMV close-terrain draw,
filter it by the proven terrain eligibility contract, and add identities absent
from the current render pass to OMV-owned shader constants.

### Point-light alpha continuity

Native terrain staging carries `ShadowSceneLight::fFade` in point-light color
alpha, but VPT and NVR `TerrainTemplate.hlsl` consume only RGB. OMV must do the
same for both native and supplemental close-terrain lights. Multiplying only
the replacement by alpha makes the same light change visibility when a
cell/pass admits or omits its native identity.

This does not claim to fix an external mod's native fallback shader.

### Object PBR distance/count transitions

Keep the material-faithful bounded object PBR and exact native fade/count
tests. Package-19 proves that only-light rows `2037..2044` use attenuation
lookup `s4`, diffuse-point rows `2045/2046` use `s3`, and their vertex partners
generate the corresponding lookup coordinates. OMV preserves that native ABI.
The native PPLighting sorter performs a stable camera-distance ordering and
invalidates pass state on a real order change. The static research does not
justify comparator hysteresis, frame-history blending, or generic light-alpha
reinterpretation.

### Projected shadows

Keep native ownership. Shadow candidate direction/fade and membership dirtying
are distinct from general point-light selection. Do not add a second shadow
fade or sample projected-shadow resources without a proven row/resource ABI.

### TerrainFade and LandLOD

Remain on their separate shader and constant paths. The close-terrain
supplemental ABI is not uploaded to or consumed by these families.

## Contracts Preserved

- Existing close-terrain pass/pixel mapping and exterior/resource gates.
- Canopy rows keep dedicated engine identities but compile to their paired base
  PBR material/light program; native `s14/s15` projected inputs are excluded.
- Native render-pass light array is read-only.
- Native point-light `c39/c63/c88` is read-only.
- OMV terrain configuration remains `c89/c90`.
- Native selection order is preserved.
- Native and supplemental point lights share a hard maximum of 24.
- Native forced-darkness, HDR dimmer, LOD dimmer, multibound, radius, transform,
  and alpha semantics are reproduced for supplemental entries.
- Invalid capture fails to zero supplemental entries, not to a broader shader
  or feature disable.

## Static Validation Architecture

The production merge helper is also the test target. Tests do not use a copied
model.

Pure merge tests cover:

- old pass omits candidate -> one supplemental entry;
- future fixed pass includes candidate -> zero supplemental entries;
- native and supplemental identity deduplication;
- iterator order;
- combined 24-light cap;
- candidate class, IsLit threshold, finite values, forced darkness, and
  multibound rejection;
- HDR/non-HDR color staging;
- engine D3D matrix convention, camera-relative offset, and scale-adjusted
  radius;
- count/interleaved constant layout and zero-count reset.

Row tests cover all 28 base variants, all 28 canopy companions, projected
sampler exclusion, paired production-bytecode identity, and foreign or
mismatched pairs.

Shader tests cover:

- native `c39/c63/c88` ABI;
- OMV `c91/c92..c139` ABI;
- RGB-only native and supplemental terrain inputs, with no alpha visibility
  gate;
- real compilation of every registered PBR shader permutation;
- complete object row coverage and implemented-pair light ABI;
- exact native object attenuation samplers/interpolators;
- finite attenuation, continuous half vectors, bounded BRDF/fade behavior, and
  inactive high-light branches;
- per-object-variant bytecode, instruction, and texture-sample budgets;
- representative close-terrain bytecode budgets.

Supported static commands:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

No external dependency project is compiled.

## Production Performance Contract

No new runtime diagnostics are permitted. Specifically, no new draw logs,
counters, UI status, D3D state readback, allocations, locks, frame history,
material-array scans, or texture resolution.

The OMV close-terrain hot path may perform only the bounded native pass scan,
bounded general-list walk, fixed-stack merge, exact engine transform/bound
calls, and the extended OMV constant upload described in
`graphics_fnv_close_terrain_portable_light_fix_plan.md`.

## One Playtest

After all static gates pass, perform one ordinary playtest at the known exterior
portable-light repro. Confirm light presence, no duplicate intensity, smooth
fade/movement, multibound behavior, stable terrain colors, no interior leakage,
and no material performance regression.

Static tests prove selection, mapping, constant layout, and compiler behavior.
They do not prove final pixels or live driver behavior.

## Acceptance Criteria

- The correction is entirely OMV-side.
- External source and packages are unchanged.
- Missing eligible identities are supplemented exactly once.
- Already-present identities are never duplicated, including future upstream
  fixes.
- Native pass and native constant ownership remain intact.
- All pure, mapping, shader, bytecode, i686 test, and release-build gates pass.
- The ordinary playtest clears the remaining pixel/runtime checks.

## Explicit Non-Fixes

- external source changes or builds;
- dependency version/export contracts;
- native comparator epsilon or hysteresis;
- a second general-light or shadow fade;
- frame-history blending;
- global terrain/object feature disable;
- new gameplay diagnostics;
- shader-pair-only broadening of terrain identity;
- claiming static compilation proves runtime pixels.

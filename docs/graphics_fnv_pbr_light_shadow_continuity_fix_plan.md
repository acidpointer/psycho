# FNV PBR Light and Shadow Continuity Fix Plan

## Status

This document is the implementation plan for the remaining camera-, distance-,
and elevation-dependent PBR light or shadow blink. It replaces speculative
plans to smooth native selection globally.

The static engine contract is now sufficiently understood to rule out two bad
fixes:

- Do not hook the native PPLighting light-list sorter to add arbitrary
  hysteresis.
- Do not add a second fade on top of the native projected-shadow candidate
  transition.

Static analysis cannot yet select one final PBR patch because current runtime
telemetry does not show the complete native state at the draw where the blink
occurs. The correct implementation therefore has two required runtime stages:

1. one bounded, targeted instrumented capture that contains same-draw native
   pre-bind state, PBR post-bind state, and controlled PBR-off draws;
2. one final validation after the evidence-selected correction is implemented.

Skipping the first stage would require guessing whether the failure is light
membership, count ABI, shader-row coverage, constant preservation, sampler
ownership, close-terrain admission, or projected-shadow resource binding.

## Objective

Make PBR output continuous wherever the native draw is continuous while
preserving:

- native general-light ranking and list limits;
- native shadow candidate selection and transition timing;
- VPT point-light alpha fades;
- exact PPLighting row, constant, sampler, and resource ownership;
- object, close-terrain, TerrainFade, and LandLOD as separate contracts;
- vanilla fallback for an individual unproven draw without globally disabling
  the target feature;
- no expansion of experimental close-terrain coverage as a side effect of this
  continuity fix.

## Authoritative Evidence

Use these Ghidra outputs as ground truth:

- `analysis/ghidra/output/perf/graphics_fnv_pbr_light_selection_continuity_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_shadow_selection_continuity_closure.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_light_shadow_continuity_final_followup.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_object_distance_specular_transition_contract_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_texture_semantic_stage_followup_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_vpt_nvr_contract_gap_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_entry_runtime_contract.txt`
- `analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_declaration_contract.txt`

Use these source contracts with the Ghidra output:

- `docs/graphics_fnv_pbr_errata.md`
- `docs/graphics_fnv_pbr_contract_map.md`
- `docs/graphics_fnv_pbr_object_temporal_instability_audit.md`
- `docs/nvr_reference_contract.md`
- `omv/src/effects/pbr/hooks.rs`
- `omv/src/effects/pbr/engine_contracts.rs`
- `omv/src/effects/pbr/diagnostics.rs`
- `omv/src/effects/pbr/samplers.rs`
- `omv/src/effects/pbr/shader_registry.rs`
- `omv/shaders/embedded/nvr_pbr_object/ObjectTemplate.hlsl`
- `omv/shaders/embedded/nvr_pbr_object/Object.hlsl`
- `omv/shaders/embedded/nvr_pbr_object/PBR.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_landlod.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_landlod.vs.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_terrainfade.hlsl`
- `omv/shaders/embedded/native_pbr_pplighting_terrainfade.vs.hlsl`

## Proven Native General-Light Contract

### Camera-relative ranking metric

`FUN_00B9DBE0` computes the scalar used by the PPLighting property light-list
sort. The decompile is in
`graphics_fnv_pbr_light_shadow_continuity_final_followup.txt:141-155`; the raw
x87 implementation is at lines 165-224.

For light/candidate `L` and draw bound `B`, the operation is:

```text
world_light_center = camera_position + L.center
surface_distance = length(world_light_center - B.center) - B.radius
metric = surface_distance / L.radius
```

The relevant fields are:

- candidate `+0xF8`: attached light object;
- light `+0x8C/+0x90/+0x94`: camera-relative center;
- light `+0xE0`: radius;
- bound argument `+0x00/+0x04/+0x08`: center;
- bound argument `+0x0C`: radius;
- camera `+0x1E4/+0x1E8/+0x1EC`: world position.

This is not Euclidean distance to the light origin alone. It ranks normalized
sphere separation, so camera movement, object bounds, and different light radii
can all move two candidates across the selection boundary.

### Sort direction and equality behavior

`FUN_00B70390` owns the property list at `property + 0x60`. Its decompile is in
`graphics_fnv_pbr_light_selection_continuity_closure.txt:1189-1252`; raw
instructions are at lines 6130-6222.

The sorter moves a candidate before an existing node only when its metric is
strictly smaller. Equal metrics do not move either node. Therefore:

- ordering is nearest normalized sphere separation first;
- exact equality preserves prior list order;
- the sort is stable at equality;
- there is no epsilon or near-equality hysteresis;
- a real metric crossing intentionally changes list membership/order.

If any node moves, `FUN_00B70390` clears property cache field `+0x38`. The
distance/pass updater calls the sort only when property dirty byte `+0x74` is
set; the relevant `FUN_00BB4740` call window is in the same output at
lines 15200-15240.

This proves that a list crossing and pass rebuild are native behavior. It does
not prove that a PBR-only visual discontinuity is acceptable.

### Selection and staging capacities are different

The engine has three distinct limits:

- the property list at `+0x60` is not inherently capped by the list container;
- `FUN_00B70820` writes shared staged color and light data only for indices
  below eight;
- `FUN_00B78A90` accepts up to ten pass arguments.

Evidence:

- `FUN_00B70820` checks `index < 8` at
  `graphics_fnv_pbr_light_selection_continuity_closure.txt:1737-1747`;
- its raw entry compares the index against eight at line 6504;
- `FUN_00B78A90` loops over pass arguments but breaks after index nine at
  lines 1965-1972 and raw line 6962.

These numbers must not be collapsed into one generic `light_count`. Runtime
capture must report the pass argument count, staged capacity, selected shader
template capacity, and the shader's actual count carrier separately.

### Native light RGB already contains engine attenuation state

`FUN_00B70820` stages RGB from candidate scalar `+0xD0`, attached-light color
`+0xD4/+0xD8/+0xDC`, the light dimmer, and the property/call scale. The final
writes are visible at
`graphics_fnv_pbr_light_selection_continuity_closure.txt:1812-1838`.

Consequences:

- PBR must consume staged RGB without inventing another generic light fade;
- `PSLightColor.a` and `LightData.w` cannot be interpreted globally;
- alternate PPLighting rows use those components for count, radius, gloss, or
  other row-specific data;
- the proven VPT `PointLightColor.a` contract is separate and applies only to
  the VPT close-terrain point-light array.

### General-light truncation has no outgoing candidate fade

The sorter changes order, invalidates the cache, and allows the pass to be
rebuilt from the new prefix. No general outgoing-list transition state was
found in the property list sort or current-pass staging path. Exact equality is
stable, but a real crossing can replace the last admitted light immediately.

That native fact is not permission to add global smoothing. If vanilla output
is acceptable at the same crossing while PBR blinks, the defect is in the PBR
row/constant/material contract and must be fixed there.

## Proven Native Shadow Contract

### Shadow owner and physical slot count

`FUN_00871290` is the RenderShadowMaps owner. It enumerates candidates, calls
the ranking/update path, renders admitted candidates, publishes resources, and
clears unused slots. See
`graphics_fnv_pbr_shadow_selection_continuity_closure.txt:1433-1723`.

Physical shadow slots are exactly `0x11..0x14`:

- initialization/clear loop: lines 1521-1530;
- unused-slot cleanup: lines 1706-1711;
- `FUN_00B9F780` maps candidate index `i` to physical slot `i + 0x11` at
  lines 8010-8019.

These physical render slots are not the same namespace as:

- PPLighting projected-shadow rows `0x10..0x13`;
- image-space effect ID `0x11`;
- shader constant register numbers.

### Candidate ranking lists and transition-aware replacement

`FUN_00B5CDE0` owns linked-list state at owner offsets `+0xC0`, `+0xD0`, and
`+0xD4`. See
`graphics_fnv_pbr_shadow_selection_continuity_closure.txt:5490-5608`.

It evaluates candidate transition target `+0xD8` and elapsed time `+0xDC`
against global duration `DAT_011AD834`. It can keep a fading candidate in the
admitted list while moving another candidate between dependent lists. This is
not equivalent to the general PPLighting light-list prefix replacement.

### Transition direction reversal preserves continuity

`FUN_00B9BB10` is the transition target setter. Its decompile and raw body are
in `graphics_fnv_pbr_light_shadow_continuity_final_followup.txt:282-368`.

When the target changes through the normal path, it computes:

```text
progress = clamp(elapsed / duration, 0, 1)
elapsed = (1 - progress) * duration
target = new_target
```

Reversing direction therefore starts from the current visible fade rather than
restarting at zero or one. The separate immediate path directly initializes
the transition state and must not be treated as the normal reversal formula.

### Per-frame shadow fade

`FUN_00B9E970` computes candidate distance/frustum state and transition fade.
See `graphics_fnv_pbr_shadow_selection_continuity_closure.txt:7687-7863` and the
cleaner final follow-up at lines 377-553.

The temporal portion is:

```text
elapsed = elapsed + frame_delta
progress = min(elapsed / duration, 1)
if target == 0:
    progress = 1 - progress
shadow_fade = distance_fade * progress
```

The corresponding decompile is at closure lines 7810-7819. Candidate distance
fades are computed first at lines 7772-7808.

Attached PPLighting properties are dirtied only when validity or zero/nonzero
membership state changes, not for every fractional fade update. The boundary
test and `property + 0x74 = 1` propagation are at lines 7821-7845.

### Rejected-candidate detach

`FUN_00B9EF30` walks candidate attachments and calls `FUN_00B717A0` during
cleanup. See
`graphics_fnv_pbr_shadow_selection_continuity_closure.txt:7908-7950`.

`FUN_00B717A0` removes the candidate from the eligible property's list, sets
property dirty byte `+0x74`, and clears property `+0x38` for the applicable
shadow candidate. See
`graphics_fnv_pbr_light_shadow_continuity_final_followup.txt:1040-1115`.

This proves lifetime and cache ownership. A PBR fix must not retain detached
candidate pointers or bypass this cleanup.

### Projected-shadow row and resource ownership

`FUN_00BDF650` emits one of rows `0x10..0x13` from two boolean selectors and
uses resource `param_4 + 0x1A0`. See
`graphics_fnv_pbr_shadow_selection_continuity_closure.txt:12384-12419`.

The established resource chain is:

```text
FUN_00BDF650
  -> FUN_00BA9EE0 pass entry
  -> entry resource fields +0x04/+0x08
  -> FUN_00E7EB00 / FUN_00E7EA00
  -> FUN_00E90B10
  -> NiDX9RenderState::SetTexture
```

OMV must validate the final D3D shadow and mask textures at draw time. A cached
`SetTexture` observation is supporting telemetry, not ownership proof.

Texture identity alone is also not enough to prove shadow continuity. A
physical shadow render target can retain the same D3D pointer while a different
candidate is rendered into that slot. Runtime evidence must correlate, where
the engine contract permits it:

- the active projected-shadow pass entry and its bounded argument table;
- the admitted shadow-candidate identity and transition state;
- the candidate index or physical slot `0x11..0x14`;
- the pass resource/owner record;
- the final shadow and mask D3D textures.

If the current outputs do not expose a safe draw-time candidate-to-slot bridge,
prepare a focused Ghidra script before adding that part of the telemetry. Do not
infer slot ownership from texture pointer changes.

## Current OMV Behavior and Gaps

### Draw ownership flow

`hook_set_shaders` calls native `SetShaders` before scheduling replacement, so
the engine selects and binds the native row first. Replacement is deferred to
`prepare_direct_draw`, immediately before the D3D draw:

- scheduling: `omv/src/effects/pbr/hooks.rs:505-585`;
- draw-boundary preparation: `hooks.rs:908-929`;
- direct pair bind: `hooks.rs:938-956`;
- restoration at the next batch boundary: `hooks.rs:889-906`.

This is the correct place to compare final native state with post-bind PBR
state. `SetShaders` alone is too early because constants and samplers may still
change before the draw.

### Existing D3D pair telemetry is sampled too early

`bind_object_replacement` calls `record_object_d3d_state` before
`bind_direct_pair`. See `omv/src/effects/pbr/hooks.rs:1304-1331`.

As a result, diagnostics normally record the valid native pair and cannot prove
that the replacement pair was actually active. The post-bind state and
native-to-replacement transition counters are therefore not authoritative.

### Existing light telemetry is incomplete

Current combined-specular diagnostics read `LightData c25[10]`, but retain only:

- `LightData[0].w`;
- selected template capacity;
- one signature that excludes `LightData[0].w`.

See `omv/src/effects/pbr/hooks.rs:1333-1353` and
`omv/src/effects/pbr/diagnostics.rs:391-455`.

Missing state includes:

- raw `LightData` values and changed slots;
- `PSLightColor c3[10]`;
- `PSLightPosition c19[8]`;
- row-specific count carriers;
- ordered property light-list membership;
- candidate pointer, attached light pointer, and candidate scalar fields;
- transitions where the light signature changes but the specular-fade bucket
  does not.

`record_object_specular_fade` logs only when the fade bucket changes. A light
membership transition within the same fade bucket is invisible.

The active high-light source has multiple count ABIs that must remain paired:

- non-optimized vertex rows use `fvars0.z`;
- optimized combined-specular vertex rows use `EyePosition.w`;
- optimized non-specular vertex rows use `LightData[0].w`;
- non-optimized pixel rows use `EmittanceColor.a`;
- optimized pixel rows use `PSLightColor[0].a` and shift point-light data by one
  slot.

See `omv/shaders/embedded/nvr_pbr_object/ObjectTemplate.hlsl:378-419` and
lines 663-677. Pixel slots two through six now use the native inclusive
`N >= lightsUsed` exclusion boundary at lines 719-735. Runtime capture must
prove that the paired vertex and pixel rows receive equivalent count values;
the presence of all five possible carriers is not permission to choose one
generic source.

### Contract transition telemetry is too coarse

`record_object_contract_transition` emits `[PBR_DRAW]` only when the coarse
`ObjectContractState` changes. See
`omv/src/effects/pbr/diagnostics.rs:1010-1054`.

Two different passes, rows, counts, or resources can share one contract state.
The current 64-slot/four-probe state table can also overwrite colliding entries
at `diagnostics.rs:1057-1081`.

### PBR-off cannot currently provide a passive draw-boundary control

`prepare_direct_draw` returns immediately when PBR is disabled at
`omv/src/effects/pbr/hooks.rs:908-911`. `hook_set_shaders` also returns after
native binding without scheduling draw-boundary PBR diagnostics when disabled.

The same scene can be observed visually with PBR off, but current logging cannot
capture the equivalent final native constants/resources at the authoritative
draw boundary. This is a matched control run; the native pre-bind snapshot on a
PBR-on draw is the synchronized state for that exact draw.

### Sampler tracking can trust stale cached state

`texture_stage_valid` uses the cached `SetTexture` pointer whenever
`TEXTURE_TRACKING_READY` is true and consults actual D3D state only otherwise.
See `omv/src/effects/pbr/samplers.rs:344-369`.

Detailed mode detects disagreement at `samplers.rs:378-405`, but disagreement
does not fail validation. A stale non-null cached pointer can therefore admit a
replacement even when the final D3D resource differs.

After device reset, texture tracking readiness is restored from general PBR
hook readiness even though `SetTexture` is optional. The texture hook needs its
own readiness state.

### Custom constant ownership is narrow but unverified at runtime

Current uploads are intentionally limited to:

- object pixel `c32/c33` in `omv/src/effects/pbr/constants.rs:56-68`;
- terrain pixel `c89/c90` in `constants.rs:71-97`.

That is the intended ABI. The missing proof is a same-draw pre/post capture
showing that `c25`, `c3`, `c19`, count carriers, shadow projection constants,
and sampler bindings remain unchanged around replacement binding.

The current bind path uploads custom constants before `bind_direct_pair`. If a
later bind or detailed verification fails, only the native shader pair is
restored. The plan therefore needs an explicit draw-state transaction that can
restore every register OMV intentionally wrote before declaring the draw a
vanilla fallback.

### Close-terrain point-light alpha is already preserved in HLSL

The close-terrain replacement declares:

- `PointLightColor` at `c39`;
- `PointLightPosition` at `c63`;
- `PointLightCount` at `c88`.

It multiplies RGB by `saturate(PointLightColor.a)` at
`omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl:319-340`.

Do not remove or replace this fade. The runtime gap is proving that the selected
`0/6/12/24` shader variant receives the same final `c39/c63/c88` state as the
native VPT draw.

The current VPT dispatch range is active pass `503..558`, vertex table C index
`100`, and even pixel table B indices `92..146`; see
`omv/src/effects/pbr/hooks.rs:56-60`. For texture count `t` in `1..7`, the
expected pixel index is:

```text
base = 92 + 8 * (t - 1)
0-light  = base + 0
6-light  = base + 2
12-light = base + 4
24-light = base + 6
```

This dispatch row is distinct from the companion material pass-entry rows
`0x1F2..0x1F5` used to prove close-land material ownership.

The numeric namespace must be stated exactly:

```text
503 = 0x1F7
558 = 0x22E
560 = 0x230
```

VPT replaces the existing vanilla landscape row family; it does not create a
separate numeric namespace. Rows `0x1F7..0x22E` are valid VPT close-land
dispatch candidates but are not, by themselves, proof of material-array
ownership. Row `0x230` is the separate TerrainFade contract.

### Close-terrain continuity telemetry is incomplete

The current point-light HLSL preserves `PointLightColor.a`, but point lights are
only one part of the close-terrain ABI. A valid close-terrain capture also needs:

- the exact vertex declaration or FVF and stream sources;
- active layer count matched exactly to the selected `TEX_COUNT` variant;
- `AmbientColor c1`, `SunColor c3`, `SunDir c18`;
- `LandSpec c32/c33`, `LandHeight c34/c35`, and fog `c36/c37`;
- material samplers `s0..s13` for only the active layers;
- point-light `c39/c63/c88` for the selected capacity;
- OMV terrain data `c89/c90` as the only intended upload.

The current close-terrain pixel shader declares `LandHeight` but does not
consume it. This plan must not use a light-continuity patch to claim complete
height/parallax coverage. A draw whose required height contract is unproven
remains native until that contract is implemented or the assumption is removed
from the replacement.

### TerrainFade and LandLOD lack continuity traces

The runtime protocol currently lists TerrainFade and LandLOD as possible
failing families, but the proposed raw capture covers only object and close
terrain. Family-specific snapshots are required before either family can be
included in the final verdict. Their registers, samplers, vertex ABI, and row
ownership must not be inferred from close terrain.

### Projected-shadow sampler layouts are row-specific

`omv/src/effects/pbr/samplers.rs:415-462` maps projected-shadow stages as:

- ordinary object: shadow `s6`, mask `s7`;
- only-light object: shadow `s5`, mask `s6`;
- only-specular object: shadow `s4`, mask `s5`.

The replacement HLSL uses the corresponding layouts. Runtime capture must prove
the final resources for each actual template rather than assuming one global
shadow stage pair.

## Required Change Set

### Phase 0: Freeze scope and row namespaces

Before changing runtime code, encode these rules in the plan and tests:

- PBR-on pre-bind state is the synchronized native state for that exact draw.
- PBR-off replay is a controlled visual/native comparison, not the same frame.
- `503..558` and `0x1F7..0x22E` are the same active landscape row range.
- The active landscape row proves dispatch only; it does not prove
  material-array ownership.
- Companion material entries `0x1F2..0x1F5` provide separate ownership evidence.
- TerrainFade row `560` / `0x230` is not close terrain.
- Object, close terrain, TerrainFade, and LandLOD use separate capture schemas
  and admission rules.
- This work preserves current intended coverage. It does not broaden an
  unproven terrain family merely to make the capture easier.

Split any unresolved engine identity into a named research prerequisite. In
particular, if the exact exterior discriminator, active pass-entry source,
vertex declaration, or shadow candidate-to-slot bridge is unavailable, prepare
a focused script under `analysis/ghidra/scripts/` and wait for its output before
implementing that gate. A runtime pointer heuristic is not a substitute.

### Phase 1: Add a bounded continuity capture

Modify `omv/src/effects/pbr/diagnostics.rs`.

Implement two diagnostic levels:

1. Discovery mode stores cheap row/pair/identity transition metadata in a
   rolling fixed-size buffer.
2. Focused mode records the complete native and replacement snapshots for one
   geometry/property identity selected from discovery output.

Use concrete bounded limits:

- 512 rolling discovery events;
- 128 rolling focused events;
- 24 selector pass entries;
- 10 pass arguments;
- 16 property light-list nodes;
- 24 VPT point lights;
- 16 D3D sampler stages.

All limits need independent truncation/overwrite counters. Keep the combined
static storage at or below 1 MiB and assert/log the actual byte size so a future
event-field expansion cannot silently create a large DLL data allocation.

The trace must have these properties:

- no heap allocation in the draw path;
- no unconditional per-draw logging;
- explicit `disabled`, `armed`, and `frozen` states;
- reset only on the disabled-to-armed edge or an explicit reset request;
- the first observation establishes a baseline and is not emitted as a change
  unless that identity is explicitly focused;
- record only when pass, row, count, light membership/signature, shader pair,
  sampler identity, or shadow resource identity changes;
- preserve a stable geometry/property identity while recording pass changes as
  events;
- assign a monotonic sequence number to every emitted event;
- expose overwritten, dropped, invalid-read, and truncated-walk counts so a
  bounded capture cannot look like complete proof;
- freeze immediately after the repro and serialize from `service_frame` or an
  explicit dump action, never from the draw hook;
- prefix serialized records consistently, for example `[PBR_CONTINUITY]`.

Both buffers are rolling: overwrite the oldest event and increment
`overwritten`. `dropped` is reserved for events rejected because the writer is
unavailable or the snapshot cannot be committed. Do not call an
append-until-full buffer a ring.

Use a non-blocking render-thread write path. A fixed `parking_lot::Mutex` with
`try_lock` is acceptable: increment `dropped` on contention and never wait in a
draw hook. Dumping may acquire the buffer only after capture is frozen. No
worker or UI thread may walk engine pointers or read live D3D state.

Every discovery and focused event must contain this shared header:

- sequence, capture mode, validity flags, and truncation flags;
- frame and draw ordinal;
- geometry, property, selector, and pass pointers;
- pass index and C/B table rows;
- native wrappers and native D3D handles;
- intended and observed replacement handles;
- contract state and rejection reason;
- property `+0x38/+0x74` values.

Every focused event additionally contains:

- active pass-entry pointer and the proven pass-entry fields `+0x00`, `+0x04`,
  `+0x06..+0x0B`;
- bounded pass arguments from `+0x0C`, with argument count, capacity, and a
  truncation flag recorded separately;
- staged capacity, selected template capacity, and every row-specific shader
  count carrier as separate fields;
- all signatures, raw snapshots, and changed-slot masks described below.

Resolve the active entry through the proven selector `+0x3C` list and current
row. If multiple entries match, record every bounded match plus an ambiguity
flag; do not silently choose the first entry. If no proven relationship selects
one match, that draw cannot support an ownership-sensitive final patch.

Stored pointer values are opaque identities. Validate and dereference them only
while taking the immediate render-thread snapshot; never dereference an address
later while dumping or comparing events.

Discovery mode must not perform complete D3D constant readback, a property-list
walk, or fourteen terrain `GetTexture` calls for every unrelated draw. Focused
mode may do the complete work for the selected identity. Cache one actual D3D
sampler snapshot per event and reuse it for validation, signatures, and logging.

Discovery still needs enough signal to find a same-row failure. Its per-family
minimal signatures are:

- object: row/pair, all explicit count carriers, and compact signatures of
  `c25/c3/c19` from one read of each range;
- projected shadow: row, pass resource owner, `c18..c23` signature, and cached
  versus final shadow/mask identities;
- close terrain: active row, layer count, selected capacity, `c88`, and compact
  active `c39/c63` signatures;
- TerrainFade/LandLOD: row/pair and the family-specific native constant
  signature.

Discovery stores signatures and changed masks, not the raw arrays or full
engine list snapshot. Measure and report discovery overhead separately. If even
this short diagnostic mode materially changes the repro, use a manual
geometry-name/pass/family filter and focused capture instead.

Expose minimal runtime controls and status:

- arm discovery;
- show recent geometry/property/family transition keys;
- select one key and arm focused capture, or enter a narrow geometry-name,
  pass, or family filter when no state transition identifies the visible draw;
- freeze;
- dump;
- reset;
- show capacity and all loss/truncation counters.

The controls manipulate diagnostic state only. They must not rewrite shader
wrappers, constants, selectors, pass entries, or engine light state.

Keep this diagnostic facility after the fix. It is bounded and is the only
practical regression tool for future row/constant transitions.

### Phase 2: Capture authoritative pre-bind native state

Modify `omv/src/effects/pbr/hooks.rs` and
`omv/src/effects/pbr/engine_contracts.rs`.

Capture after native handles and the exact implemented row are verified, but
before `upload_object_constants` or `bind_direct_pair`.

For object draws capture:

- VS `LightData c25[10]`;
- PS `PSLightColor c3[10]`;
- PS `PSLightPosition c19[8]`;
- `EmittanceColor c2.a`;
- `EyePosition c16.w`;
- `fvars0 c17.z`;
- `LightData[0].w`;
- `PSLightColor[0].a`;
- every actual sampler required by the selected template;
- projected-shadow constants `c18..c23` when applicable.

Also capture the active pass entry and its bounded argument table so the event
contains, independently:

- property-list length observed by the bounded walker;
- pass argument count and capacity;
- native staged capacity (`8` where applicable);
- selected replacement template capacity;
- the row-specific VS count value;
- the row-specific PS count value.

Snapshot object `c32/c33` before OMV writes them. They are the rollback state,
not native-light semantics. Record D3D read failures explicitly; a zero-filled
array without a validity bit is not evidence.

Store raw values in the bounded event and compute independent signatures plus
changed-slot masks against the previous event for the same focused identity and
capture mode. Do not use one hash as a substitute for count and semantic fields.
Do not compare a PBR-on event against an unrelated PBR-off event merely because
their pointers happen to match.

### Phase 3: Capture ordered property light membership

Add a validated bounded walker for property list `+0x60`.

For each node capture:

- node pointer and next pointer;
- candidate pointer at node `+0x08`;
- candidate vtable as an opaque class identity;
- cached native ranking metric at candidate `+0x0C`;
- candidate's attached light pointer at `+0xF8`;
- candidate staged scalar fields `+0xD0/+0xD4`;
- proven general candidate flags at `+0xF4/+0xF5`;
- candidate transition `+0xD8/+0xDC` only after its vtable/class is proven to
  be the shadow-candidate type;
- shadow-only fields such as `+0xEC` only after the same class proof;
- attached light center/radius fields used by `FUN_00B9DBE0`.

Safety requirements:

- validate every range through existing memory helpers;
- stop at a small fixed maximum;
- detect cycles and repeated nodes;
- retain addresses only as opaque identity values after the immediate snapshot;
- never walk or mutate this list from a worker thread;
- never duplicate the engine sort or detach logic.

This snapshot distinguishes a native membership crossing from an OMV
constant/resource divergence.

The cached metric is sufficient to observe the native ordering decision. Do not
recompute it from a guessed geometry bound. If the exact draw-bound storage is
needed to explain a crossing and is not already proven, prepare a focused
Ghidra script for that storage path rather than hooking or duplicating the
sorter.

### Phase 4: Add a passive native-control path

When PBR is disabled but detailed continuity capture is armed:

- call native `SetShaders` exactly as today;
- schedule a `PENDING_DRAW_NATIVE_CONTROL` event;
- capture the same final state in `prepare_direct_draw`;
- do not upload OMV constants;
- do not bind replacement shaders;
- do not alter wrappers or engine pass state.

Schedule the native-control event for every family supported by the capture,
not only object draws. Classification must remain passive and must not enable
fog, constants, or any other contract solely for diagnostics.

This permits one controlled session to alternate PBR on/off and compare the
same geometry, row, and motion without a separate diagnostic build. It is a
matched visual control, not the same frame. The native pre-bind snapshot on a
PBR-on draw remains the synchronized state comparison for that exact draw.

### Phase 5: Make replacement binding transactional

Create one explicit render-thread transaction for a pending replacement draw.
Before mutation it owns:

- native VS/PS handles;
- the exact OMV-written register values that must be restored (`c32/c33` for
  object or `c89/c90` for terrain);
- the intended replacement handles;
- the pre-bind diagnostic snapshot when detailed capture is enabled.

Preflight row ownership, replacement readiness, constant-read availability, and
required sampler state before changing shaders or constants. Do not upload
constants when the selected replacement pair is already known to be unusable.

On partial bind failure, constant-upload failure, or detailed verification
failure:

- restore the native shader pair;
- restore every OMV-written register from the transaction;
- clear direct-bind ownership;
- record the precise fallback reason;
- leave the draw on the native path.

On successful batch completion, restore the native pair and prior OMV-written
registers before clearing the transaction. Never restore an engine sampler from
an opaque pointer snapshot: OMV does not own sampler mutation in this path, and
the pointer was captured for immediate identity only.

Measure the cost of the two-register snapshot/restore in production. If it is
not acceptable, replace it only with a separately proven register-ownership
lifetime contract; do not silently drop rollback.

### Phase 6: Verify post-bind state

After successful `bind_direct_pair`:

- verify current D3D VS/PS handles equal the intended replacements;
- record D3D pair telemetry here, not only before the bind;
- read back the native lighting and shadow constants;
- verify all non-OMV registers are bit-identical to the pre-bind snapshot;
- verify actual D3D sampler pointers are unchanged;
- verify only object `c32/c33` or terrain `c89/c90` changed as intended.

In detailed mode, a mismatch must log the exact register/stage and keep that
draw vanilla through the transaction rollback. Production mode must not add
full native constant readback overhead.

### Phase 7: Make actual D3D sampler state authoritative

Modify `omv/src/effects/pbr/samplers.rs` and hook initialization/reset state.

- Track `SetTexture` hook readiness separately from mandatory `SetShaders`
  readiness.
- Preserve that separate state through device reset.
- Snapshot each required stage once with final `device.texture_raw(stage)` and
  reuse the result for admission, identity, and diagnostics.
- Retain cached selector/texture observations only for drift telemetry.
- Fail only the current replacement draw if a required final resource is null.
- Compare resource identity only where an expected owner/resource pointer is
  independently proven. Otherwise report cached/final drift without inventing
  an expected identity.
- Expose shadow and shadow-mask identities in runtime status.

This is a correctness change independent of which captured root cause wins.

### Phase 8: Capture and enforce the full close-terrain ABI

At the verified close-terrain draw boundary, before terrain constant upload,
capture:

- exact active row, vertex/pixel table indices, wrappers, and D3D handles;
- selector state, active layer count, and complete bounded pass-entry snapshot;
- exact vertex declaration or FVF, declaration elements, and stream sources;
- `AmbientColor c1`, `SunColor c3`, and `SunDir c18`;
- `LandSpec c32/c33`, `LandHeight c34/c35`, and fog `c36/c37`;
- active texture count and the selected compile-time `TEX_COUNT`;
- declared point-light capacity `0/6/12/24`;
- `PointLightCount c88`;
- active `PointLightColor c39` RGBA entries;
- active `PointLightPosition c63` entries;
- alpha and membership signatures;
- final material samplers for only the active diffuse and normal layers;
- pre-upload `c89/c90` for transaction rollback.

Verify that terrain upload changes only `c89/c90`. If `c39/c63/c88` changes
around replacement, repair the binding/upload path rather than modifying the
HLSL fade.

The close-terrain path must require more than a compatible shader pair.

Before admission require:

- proven exterior material state;
- active selected pass in VPT `503..558` / `0x1F7..0x22E`;
- the row must match the VPT formula for the exact active layer count, canopy
  state, and `0/6/12/24` point-light bucket;
- exact close-land material pass-entry ownership from companion rows
  `0x1F2..0x1F5`;
- selector state and material arrays valid for the current draw;
- active layer count in `1..7` and exactly equal to the selected `TEX_COUNT`;
- every active material layer represented by a valid companion entry whose
  layer byte is in `1..active_layer_count`;
- exact vertex ABI compatibility with the replacement vertex shader;
- all required native constants valid for the selected row;
- every active diffuse/normal sampler non-null in final D3D state;
- exact selected VPT point-light variant and available resources.

The current implementation uses only even pixel table indices. Keep canopy/odd
variants native until their exact shader pair and output ABI are implemented.

Exclude from admission:

- projected-shadow rows `0x10..0x13`;
- helper rows `0x62/0x63`;
- zero-resource rows `0x14A..0x152`;
- TerrainFade row `0x230`;
- SI, landlo-fog, interior room surfaces, canopy variants, height/parallax cases
  not consumed by the current shader, and any unproven owner.

Do not exclude `0x1F7..0x22E`: that is the required VPT close-land dispatch
range. Instead, forbid using an entry from that range as the material-array
ownership proof. Companion `0x1F2..0x1F5` entries provide that separate proof.

If the exact exterior or pass-entry source is not available at the current hook,
prepare a focused Ghidra script before implementing this gate. Do not infer it
from shader names or selector state alone.

### Phase 9: Add separate TerrainFade and LandLOD captures

Do not reuse the close-terrain event layout as an implicit ABI.

For LandLOD row `0xFE`, capture and verify:

- exact native and replacement VS/PS identities;
- the vertex constants declared by the LandLOD vertex shader, including
  matrices, fog, eye position, `LODLandParams`, and `LightData`;
- pixel `AmbientColor c1`, `PSLightColor c3[10]`, `LODTexParams c31`,
  `LandLODSpec c38`, and terrain `c89/c90`;
- final samplers `s0`, `s1`, `s4`, `s6`, and `s7`;
- exact vertex declaration/FVF and stream sources;
- pre/post proof that only `c89/c90` changes.

For TerrainFade row `560` / `0x230`, capture and verify:

- the exact fade pass entry with layer byte `9`;
- exact native and replacement VS/PS identities;
- the vertex constants declared by the TerrainFade vertex shader, including
  fog, eye position, `LandBlendParams`, and `LightData`;
- pixel `AmbientColor c1`, `PSLightColor c3`, `LandLODSpec c38`, and terrain
  `c89/c90`;
- final samplers `s0`, `s1`, and `s2`;
- exact vertex declaration/FVF and stream sources;
- pre/post proof that only `c89/c90` changes.

If either source contract lacks an exact native semantic or ownership bridge,
keep that family native and prepare the required Ghidra script. Do not let an
unproven TerrainFade or LandLOD result decide an object or close-terrain fix.

### Phase 10: Correlate projected-shadow candidates and resources

Use the active projected-shadow pass entry and bounded argument table to link
the draw to its candidate. Capture the candidate transition target/elapsed/fade,
pass resource owner, and final shadow/mask stages. Add physical slot identity
only if the Ghidra-proven bridge from that candidate to slot `0x11..0x14` is
available.

If the resource pointer stays stable while the candidate or slot changes, emit
that as a transition. If the candidate-to-slot bridge remains unknown, mark the
event `slot_unproven` and perform the focused static research before selecting
Branch D. Never infer a new resource merely from a changed pointer, and never
retain the candidate for later dereference.

### Implementation gates and stop conditions

The work proceeds in this order:

1. Implement the bounded diagnostic state machine, transaction rollback, and
   authoritative sampler snapshot foundation.
2. Add only the family snapshots whose current engine contracts are proven.
3. Prepare and run focused Ghidra research for every named missing bridge.
4. Run discovery and focused capture.
5. Record a capture verdict in this document: repro, focus identity, family,
   decisive sequence range, loss/truncation counters, native-control result,
   and selected branch.
6. Implement the smallest behavioral correction selected by that verdict.
7. Run static, shader, build, and final runtime validation.

Stop before behavioral HLSL, row coverage, light selection, or shadow changes
when any of these is true:

- the failing family is not identified;
- the decisive event was overwritten, dropped, invalid, ambiguous, or truncated;
- a required pointer class, pass-entry owner, vertex ABI, exterior identity, or
  shadow slot bridge is unproven;
- the PBR-off control was not repeated on the same scene and motion path;
- focused capture materially changes the repro and no narrower filter has been
  tried.

Sampler authority, hook-readiness separation, and transaction rollback are
independent correctness changes. They may land before the behavioral verdict,
but must still pass their own performance and fallback validation.

## Evidence-Selected Final Fix

The instrumented capture determines which branch is implemented. More than one
branch may be required if the same symptom has separate object and terrain
causes.

### Branch A: Native membership changes and OMV state matches native

Evidence:

- ordered property light list changes;
- `c25/c3/c19` and count carrier change consistently;
- pre/post replacement constants and resources match;
- PBR blinks more severely than the native control.

Fix:

- keep native selection unchanged;
- first separate a row/count handoff from a same-row candidate replacement.

For a row or count handoff:

- identify the exact old/new native and replacement rows;
- ensure both rows have proven matching vertex/pixel coverage;
- make direct diffuse response identical across the handoff;
- retain bounded material-faithful specular and the proven native specular fade
  only on combined-specular rows;
- correct the exact row-specific count source or inactive-slot handling if it
  differs from native bytecode;
- keep inactive light vectors finite before BRDF evaluation.

For a same-row candidate replacement:

- compare per-light RGB, direction/position, radius, attenuation, and count
  semantics against native bytecode;
- identify whether PBR is amplifying an otherwise small native replacement
  through an incorrect attenuation or unbounded material response;
- correct that exact shader math while retaining native membership and timing.

Do not add a history buffer or outgoing-light cache in this branch.

### Branch B: Native state is stable but OMV constants change

Evidence:

- ordered list and native-control constants remain stable;
- one or more non-OMV constants differ after replacement binding.

Fix:

- restrict uploads to proven OMV registers;
- remove or relocate the write that overlaps native state;
- restore the exact row-specific count carrier;
- add a regression test for the affected template and register range;
- roll back the complete draw transaction and keep the draw vanilla if
  pre/post verification fails in detailed mode.

### Branch C: Native state is stable but shader pair changes incorrectly

Evidence:

- constants and resources are stable;
- replacement handles alternate, fail to bind, or one side of a native row
  handoff lacks a proven replacement.

Fix:

- correct wrapper/template adoption or exact pair classification;
- implement the missing proven row with its matching vertex and pixel ABI;
- require the exact pair to be ready per draw;
- leave only the unavailable draw vanilla during warmup;
- never gate all object or terrain PBR on unrelated variants.

### Branch D: Projected-shadow resources or constants diverge

Evidence:

- native candidate fade remains continuous;
- projected-shadow row remains valid;
- candidate/pass argument, physical slot where proven, pass resource owner,
  shadow/mask texture, `c18..c23`, or sampler stage differs after OMV binding.

Fix:

- correct the selected template's exact sampler layout;
- preserve final native projection constants;
- preserve actual shadow/mask resources from the native row;
- implement any missing proven incoming/outgoing projected-shadow pair;
- keep `lerp(1, shadow, mask)` composition consistent with native ownership.

Do not hook `FUN_00B9BB10`, `FUN_00B9E970`, or candidate cleanup.

### Branch E: Close-terrain point-light state diverges

Evidence:

- selected VPT row/capacity is known;
- native `c39/c63/c88` is valid;
- OMV changes count, RGB, alpha, position/radius, or selects the wrong capacity.

Fix:

- preserve native `c39/c63/c88` through replacement;
- map exact VPT row to exact `0/6/12/24` shader capacity;
- keep `PointLightColor.rgb * saturate(PointLightColor.a)`;
- reject only malformed draws;
- fix close-terrain ownership if the draw is actually a helper or interior row.

### Branch F: Close-terrain identity or base ABI diverges

Evidence:

- the active VPT row, layer count, selected `TEX_COUNT`, companion entries,
  vertex declaration, material samplers, or `c1/c3/c18/c32..c37` disagree;
- point-light `c39/c63/c88` may remain valid;
- the admitted draw is not proven to be the exact exterior terrain contract.

Fix:

- correct the exact ownership, layer, vertex, sampler, or constant bridge;
- implement missing height/parallax behavior only after its engine contract is
  proven;
- keep only the malformed or unproven draw native;
- do not tune point-light alpha or broaden terrain rows to hide the failure.

### Branch G: TerrainFade or LandLOD state diverges

Evidence:

- the failing family is row `0x230` TerrainFade or row `0xFE` LandLOD;
- its family-specific native constants, samplers, vertex ABI, or replacement
  pair diverge;
- object and close-terrain snapshots remain correct.

Fix:

- change only that family's row, constant, sampler, or shader-pair contract;
- keep close terrain, TerrainFade, and LandLOD implementations separate;
- leave an unproven family native without presenting that diagnostic fallback
  as the final feature fix.

### Branch H: State and pair are stable but replacement output changes

Evidence:

- membership, counts, constants, samplers, rows, and D3D pair are stable;
- the replacement remains visibly unstable while the native control does not.

Fix:

- investigate the exact vertex inputs/interpolators, render state, sampled
  texture content/mips, and material math for that row;
- use shader disassembly and focused runtime values to identify the divergent
  input;
- prepare additional Ghidra research if an engine-owned input or stage remains
  unknown;
- do not assume another fade curve is the missing contract.

### Branch I: Native output also changes at the same general-light crossing

Evidence:

- native-control output and native constants change together;
- OMV pre/post state matches exactly;
- the visible transition is not PBR-specific.

Result:

- do not present an engine-wide comparator patch as the PBR fix;
- document the native limitation separately;
- only pursue a general engine-light continuity feature after proving a complete
  buffer/capacity/performance contract for both incoming and outgoing lights.

That feature would require separate design and is outside this PBR correction.

## Tests

Add focused tests for:

- continuity-buffer bounds, sequence numbers, overwrite/drop policy, and all
  loss counters;
- disabled/armed/frozen transitions and off/on starting a fresh capture session;
- discovery baseline behavior, focus selection, freeze, and deferred dump;
- stable identity with pass/row changes emitted as events;
- opaque pointer identities never being dereferenced during dump;
- invalid D3D/memory reads carrying validity flags instead of zero evidence;
- bounded pass-entry and argument capture with truncation accounting;
- separate property-list, pass-argument, staged, template, VS-count, and
  PS-count values;
- candidate metric capture and bounded cycle detection;
- post-bind D3D pair recording;
- pre/post non-OMV constant preservation;
- transaction rollback after partial shader bind, constant-upload failure, and
  detailed verification failure;
- successful batch completion restoring native pair and prior OMV registers;
- independent signatures and changed masks for `c25`, `c3`, and `c19`;
- every high-light integer count boundary;
- inactive light directions remaining finite;
- separate `SetTexture` hook readiness after device reset;
- final D3D texture state overriding stale cached tracking;
- one actual D3D sampler read per required stage per snapshot;
- ordinary, only-light, and only-specular projected-shadow layouts;
- projected-shadow candidate/resource transitions with `slot_unproven` handling;
- close-terrain `PointLightColor.a` consumption;
- exact `0/6/12/24` terrain variant mapping;
- `503..558` / `0x1F7..0x22E` accepted as dispatch candidates but rejected as
  material ownership proof;
- row `0x230` rejected by close terrain and accepted only by TerrainFade;
- exact layer count, `TEX_COUNT`, companion-entry coverage, and even/odd canopy
  handling;
- close-terrain rejection of helper, projected-shadow, SI, landlo-fog,
  height/parallax-unproven, and interior draws;
- close-terrain vertex declaration and full native constant validity gates;
- separate LandLOD and TerrainFade register/sampler schemas;
- all registered PBR variants compiling;
- representative object shader bytecode remaining bounded.

Run:

```bash
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

The build alone embeds HLSL source; it does not prove shader compilation. The
OMV tests must compile all registered variants through the runtime compiler.

## Runtime Capture Protocol

Use one fixed save, weather, time, resolution, graphics configuration, and
camera path. Perform one session without reloading the scene:

1. Arm discovery mode and reproduce the blink once.
2. Freeze discovery immediately and select the failing geometry/property and
   family from the recent transition records.
3. Reset and arm focused mode for that identity.
4. PBR on: rotate in place while keeping the failing surface visible.
5. PBR on: walk directly toward and away from it.
6. PBR on: strafe at approximately constant distance.
7. PBR on: change elevation or view pitch using the reported repro path.
8. PBR on: cross the observed light-count or projected-shadow boundary.
9. PBR off: repeat the same motions as a controlled visual/native comparison.
10. Freeze before leaving the scene and dump the trace outside the draw hook.

If discovery cannot identify a stable target, do not enable complete capture
for every draw. Improve the discovery key or add a narrow geometry-name/pass
filter first.

The capture must identify the failing family before final implementation:

- ordinary object;
- high-light object;
- projected-shadow object;
- close terrain with `0/6/12/24` point lights;
- TerrainFade;
- LandLOD;
- unproven/helper draw that should have stayed native.

The dump must report capture mode, focus identity, first/last sequence, capacity,
overwritten/dropped counts, invalid reads, truncated list/pass arguments, and
whether shadow slot ownership was proven. An incomplete trace is diagnostic
evidence only and cannot select a final behavioral patch.

## Final Validation Matrix

Validate after the evidence-selected patch:

- ordinary object, exterior and interior;
- high-light object near several lamps;
- projected-shadow object during candidate replacement;
- close terrain at each reachable point-light capacity;
- close-terrain/TerrainFade/LandLOD handoffs;
- ordinary interior walls and floors remain excluded from terrain replacement;
- PBR-off native comparison follows the same camera path;
- same-draw native pre-bind and PBR post-bind snapshots agree on all non-OMV
  state;
- no stale sampler/resource fallback;
- no replacement/native shader oscillation;
- bind failure and detailed mismatch paths restore native shaders and OMV-written
  registers;
- close terrain proves dispatch row, companion ownership, vertex ABI, constants,
  layer count, and samplers independently;
- TerrainFade and LandLOD retain their separate row and constant contracts;
- capture disabled has no measurable frame-time cost and focused capture reports
  its overhead;
- no meaningful frame-time regression without corresponding visual benefit.

## Acceptance Criteria

The issue is fixed only when all applicable criteria hold:

- Native and replacement draws have identical non-OMV constants and resources.
- PBR no longer blinks where the same-draw native state and matched PBR-off
  control are continuous.
- Native general-light ordering and list limits remain unchanged.
- Native shadow reversal, fade, dirty propagation, and detach remain unchanged.
- VPT point-light alpha remains active for every admitted close-terrain light.
- VPT rows `0x1F7..0x22E` are validated as dispatch rows and never used alone as
  material-array ownership proof.
- TerrainFade row `0x230` never enters close-terrain replacement.
- Every changing PBR row is either coherently implemented or correctly kept
  native for that draw.
- No interior/helper row enters close-terrain replacement.
- No shader consumes an unavailable light interpolator or invalid count slot.
- Every fallback after OMV mutation restores the transaction before the draw.
- The decisive capture has no unaccounted overwritten/dropped record or
  relevant truncated list/pass argument.
- The final fix does not broaden an unproven close-terrain, TerrainFade, or
  LandLOD contract.
- All shader tests and i686 release builds pass.
- Final runtime validation shows no recurrence under rotation, translation,
  strafing, elevation changes, or the reported light/shadow transition.

## Explicit Non-Fixes

Do not implement any of the following as the solution:

- comparator epsilon or hysteresis in `FUN_00B70390`;
- another fade in `FUN_00B9BB10` or `FUN_00B9E970`;
- frame-history blending to hide current-frame state corruption;
- treating every light alpha as a generic fade;
- using shader-pair names as close-terrain ownership;
- excluding `0x1F7..0x22E` while simultaneously claiming to support VPT
  close-terrain rows `503..558`;
- treating an active landscape dispatch row as its own material-array proof;
- globally disabling object, terrain, point-light, or projected-shadow PBR;
- narrowing intended feature coverage merely to avoid the failing row;
- retaining detached engine candidate pointers;
- accepting cached `SetTexture` state as final draw ownership;
- treating a stable or changed D3D texture pointer as proof of physical shadow
  slot ownership;
- complete per-draw capture for every unrelated geometry without discovery and
  focus filtering;
- declaring a mutated draw vanilla without restoring the draw transaction;
- another shader-only guess without same-draw native pre-bind evidence.

## Expected Files Changed During Implementation

- `omv/src/effects/pbr/diagnostics.rs`
- `omv/src/effects/pbr/hooks.rs`
- `omv/src/effects/pbr/engine_contracts.rs`
- `omv/src/effects/pbr/samplers.rs`
- `omv/src/effects/pbr/constants.rs`
- `omv/src/effects/pbr.rs`
- `omv/src/runtime.rs`
- `omv/src/effects/pbr/shader_registry.rs`
- the exact affected object or terrain HLSL file selected by evidence
- a focused `analysis/ghidra/scripts/` script only for an unresolved identity,
  vertex, bound, or shadow-slot bridge, followed by its user-generated `.txt`
  output
- `docs/graphics_fnv_pbr_errata.md`
- this plan, updated with the captured verdict and implemented branch

Do not change all listed files mechanically. The final behavioral patch must be
the smallest set selected by the captured evidence; the diagnostic, sampler
authority, and ownership-hardening changes are the common foundation.

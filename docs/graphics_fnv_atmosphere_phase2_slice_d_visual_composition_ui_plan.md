# FNV atmosphere Phase 2 Slice D visual composition and UI plan

Date: 2026-07-18

## Outcome

Ship the first production-visible result from the completed atmosphere
foundation. With debug view Off, enabling Volumetric Fog must visibly add the
integrated supplemental medium to the exterior world at OMV's proven
post-TAA, pre-first-person boundary. Disabling it must leave the captured world
unchanged.

The same delivery makes the OMV graphics workbench genuinely resizable and
removes the single-line radio-button layout. The preferred first-open size
remains compact, but the user can resize the window up to the current viewport
work area and long choice groups wrap cleanly.

This is the production-composition slice for volumetric fog. It does not
pretend that directional Volumetric Lighting is already implemented. Lighting
remains Phase 3 and must stay accurately described as non-production until its
sun/shaft/shadow contract is implemented.

## Evidence entering the slice

The fresh 2026-07-18 DXVK log closes the medium-execution gate:

- OMV loaded the current release i686 DLL;
- the world target was `A16B16G16R16F` at 3440x1440 with the active 8x MSAA
  path;
- reversed INTZ depth, camera/frustum, world transform, native fog color,
  exterior state, strict FP16 TAA alpha, and same-epoch above-water state were
  valid together;
- the High tier created 1720x720 `G16R16F` depth and
  `A16B16G16R16F` integration targets;
- density noise creation and the 12-sample integration draw succeeded;
- duplicate world callbacks were rejected before atmosphere work;
- no atmosphere shader, target, state, or D3D failure was reported.

Debug view 0 deliberately left the world target unchanged in Slice C.
Therefore the lack of a visible result is expected and is no longer an
integration mystery. Slice D must consume that proven current-frame result.

One contract remains deliberately open: the exact RGB transfer of the native
FP16 world source at this boundary. FP16 proves range and precision, not
whether RGB is native encoded or already linear. Production composition must
close this contract; it must not guess from the format.

## Non-negotiable acceptance

Slice D is not complete until all of these are true:

1. In an exterior, above-water scene, fog enabled plus debug view Off changes
   the world image visibly with the shipped nonzero height-fog defaults.
2. Fog disabled leaves the ordinary world image unchanged.
3. Changing density, height density, base height, maximum distance,
   scattering albedo, and noise controls produces the expected live response.
4. Source alpha is copied exactly on every composed pixel; OMV does not reuse,
   normalize, or replace it.
5. First-person geometry, menus, HUD, and later native image-space effects are
   outside the atmosphere write.
6. Silhouettes do not acquire foreground fog halos. When no safe reduced tap
   matches a full-resolution pixel, that pixel returns the source unchanged.
7. Interior, underwater, stale-epoch, missing-depth, missing-transform,
   unsupported-target, and resource-failure frames fail closed.
8. Production fog does not alternate between fogged and ordinary output while
   moving or rotating near the known fence trigger. If it does, the existing
   blink closure becomes a release blocker for this slice.
9. The graphics workbench can be resized from its edges beyond 1180x860 up to
   the current viewport work area.
10. Quality and long debug-view radio groups wrap without clipping or forcing
    the details pane wider than the window.

## Explicit exclusions

Do not add any of these in Slice D:

- directional sun in-scattering or Henyey-Greenstein phase;
- native local-light or shadow-map sampling;
- a guessed gamma switch or a user-facing transfer override;
- native distance-fog replacement or a global native-fog disable;
- atmosphere temporal history, animated jitter, or reprojection;
- interior or underwater volumetrics;
- a second full-resolution atmosphere target;
- a post-first-person or post-UI composition shortcut;
- masking a production blink by globally disabling fog;
- persistent ImGui layout files or new config fields only to remember window
  size.

Native distance fog remains active. The new result is supplemental.

## Work package 1: close the native source-transfer contract

Review the existing native image-space shader disassembly and the already
closed source/destination lineage as one bounded transfer audit. Record:

- whether the world source is sampled with an sRGB sampler state;
- whether the native world target is written with sRGB-write conversion;
- whether the first native HDR shaders perform explicit transfer conversion;
- how negative and overbright FP16 RGB are treated;
- the matching behavior in the FNV/NVR reference fog shader.

If static bytecode and state ownership do not select one exact behavior, add a
bounded runtime transfer probe rather than a user override. It may log native
sampler/render-state values and a small set of representative FP16 source
samples. It must run only until the contract is classified, avoid per-frame
readback, and leave world output unchanged.

Represent the result explicitly:

```text
AtmosphereSourceTransfer::Unavailable
AtmosphereSourceTransfer::ExtendedSrgb
AtmosphereSourceTransfer::Linear
```

Only one proven value may reach production composition. `Unavailable` is a
normal fail-closed reason. Do not select a mode because the render target is
FP16, and do not expose this enum in the user config.

The selected conversion must be signed/overbright safe:

- nominal [0, 1] values follow the proven native transfer;
- negative RGB keeps its sign;
- overbright RGB is not saturated before native image space;
- decode followed by encode round-trips representative negative, threshold,
  unity, and overbright values within FP16 tolerance.

Log the selected contract once with the target format and render boundary.

## Work package 2: separate medium and composition gates

Keep Slice C's medium gate and add a distinct composition gate. The medium can
remain current-frame valid even when composition is unavailable.

The composition gate is Ready only when:

- volumetric fog is enabled and has nonzero effective density;
- debug view is Off;
- the current integration draw completed successfully;
- the source-format world-color copy is current and available;
- the active world target is the captured target for this callback;
- full-resolution INTZ depth and depth direction are valid;
- near/far/frustum and the current world transform are valid;
- source transfer is proven;
- the target and both reduced FP16 resources match the current dimensions and
  quality scale;
- exterior is known and true;
- underwater is known, same-epoch, and false;
- settings and packed constants are finite;
- this is the single owned atmosphere execution for the Present epoch.

Change `AtmosphereSettings::requires_world_color()` so production fog requests
the existing source-format world copy even with debug view Off. This retains
exactly one full-resolution copy; it does not create another output texture.

Debug views remain mutually exclusive with production composition:

- debug view Off: integrate and compose;
- debug views 1-5: present the selected diagnostic;
- debug views 6-7: integrate and present the selected medium diagnostic;
- new debug view 8: present bilateral acceptance/confidence.

Each rejected gate has one stable reason. Status must distinguish medium
`Ready` from composition `Ready` so a future log cannot report "atmosphere
active" when only the invisible reduced pass ran.

## Work package 3: fixed composition ABI

Add `omv/shaders/embedded/atmosphere_compose.hlsl` as `ps_3_0` with:

```text
s0 = source-format non-MSAA world-color copy
s1 = full-resolution INTZ world depth
s2 = reduced logarithmic nearest/farthest depth
s3 = current reduced integrated atmosphere
```

Use one dedicated Rust binder for its constants:

```text
c0 = full width, full height, reciprocal width, reciprocal height
c1 = reduced width, reduced height, reciprocal width, reciprocal height
c2 = near, far, reversed-depth flag, atmosphere distance bound
c3 = frustum left, right, bottom, top
c4 = reduction scale, depth tolerance floor, relative tolerance, transfer id
```

The shader must use explicit sampler state:

- source color: point sampling at exact full-resolution pixel centers;
- full depth: point sampling and no filtering;
- reduced depth/integration: point gathers for the four selected taps;
- clamp addressing for screen resources;
- no implicit sRGB sampler or render-target conversion when transfer is
  handled explicitly.

Disable blending, depth testing, alpha testing, stencil testing, scissor, and
inherited multisample coverage controls through the existing atmosphere state
binder. Keep the existing all-state block and render-attachment restoration
around the complete transaction.

## Work package 4: conservative depth-bilateral upsampling

Slice C integrates each reduced texel only to that texel's nearest reduced
ray distance. Therefore nearest depth is the bilateral key. The older broad
"accept anything inside min/max" rule is unsafe because a background pixel
inside a mixed tile's interval could receive integration that stopped at the
foreground.

For every full-resolution pixel:

1. Decode the full-resolution INTZ sample with the exact reducer formulas and
   reconstruct its ray distance.
2. Locate the four neighboring reduced texels around the corresponding
   reduced coordinate.
3. Decode each texel's nearest and farthest distance.
4. Compare the full-resolution distance with the texel's nearest distance.
5. Use the min/max span only as an edge-confidence signal. A wide span makes
   the tap stricter; it never makes a far background pixel match a foreground
   endpoint.
6. Weight accepted taps by bilinear position and a bounded absolute/relative
   nearest-depth difference.
7. Normalize accepted weights and combine scattering/transmittance.
8. If total accepted weight is too small, return the source unchanged.

Sky uses the same bounded atmosphere distance as reduction/integration.
Tolerance scales with reduction scale and distance but is capped so it cannot
bridge a foreground/background discontinuity.

Debug view 8 visualizes:

- green: strong accepted weight;
- amber: weak or mixed-span acceptance;
- red: no accepted tap, source fallback;
- blue: sky-bound acceptance.

This diagnostic reports the actual production decision rather than a separate
approximation.

## Work package 5: production HDR composition

After a successful gather:

1. Sample source color and retain `source.a` unchanged.
2. Decode `source.rgb` through the proven source-transfer contract.
3. Read finite, nonnegative scattering and transmittance clamped only to
   [0, 1].
4. Compute:

   `linear_output = linear_source * transmittance + scattering`

5. Encode RGB back through the proven native transfer.
6. Return `float4(encoded_output, source.a)` without saturating HDR RGB.

If the source, gathered atmosphere, decoded depth, transfer result, or output
is non-finite, return the original source pixel. Never replace the whole frame
with black, identity fog, or a stale integration target because one pixel or
one prerequisite failed.

Write directly to the original MSAA world target while sampling the existing
non-MSAA source-format copy. This keeps first-person rendering after the
composition and avoids an extra full-resolution output allocation.

## Work package 6: runtime transaction and failure behavior

The owned atmosphere callback order becomes:

```text
capture source world color
capture state and render attachments
reduce depth
integrate current medium
compose production fog OR present one debug view
restore attachments
restore state
```

The first failed operation remains the reported error even if restoration also
fails. Target creation stays transactional. Reset, resize, target-format
change, device replacement, quality-scale change, or shader creation failure
must invalidate every dependent composition resource and gate.

Do not preserve a previous integration result across frames. Composition is
allowed only after the current callback's integration draw succeeded.

Add low-volume evidence:

- first successful production composition with quality, scale, dimensions,
  transfer, and target format;
- composition gate transition reason;
- counts for integration draws, production compose draws, debug draws, and
  duplicate skips;
- first resource/draw failure signature;
- current pass outcome in the existing atmosphere status line.

The normal ready path must not log every frame.

## Work package 7: visible defaults and honest controls

Keep the existing nonzero height-density default as the initial production
look. First validate that it produces an obvious but not opaque exterior
difference. Tune only after the transfer and composition path are correct.

The intended default signature is:

- stronger haze through long and low-elevation sightlines;
- preserved nearby contrast;
- native fog/horizon color family rather than an arbitrary tint;
- stable world-anchored low-frequency variation;
- no whole-screen brightness or gamma shift.

Update menu/config descriptions:

- Volumetric Fog: "supplemental exterior height and heterogeneous fog";
- debug Off: "production composition";
- modes 6-7: reduced integration diagnostics;
- mode 8: bilateral acceptance;
- Volumetric Lighting: explicitly marked as the following directional-lighting
  phase, not a currently visible production effect.

Do not make the lighting toggle secretly scale fog. Shared medium reuse starts
only when Phase 3 implements the lighting contract.

## Work package 8: resizable ImGui window

The current window is not marked `NoResize`, but
`psycho_imgui_set_next_window_centered` applies 1180x860 as the permanent
maximum constraint. Replace that ambiguous contract with a centered,
resizable helper:

- 840x560 remains the minimum usable size, clamped to small viewports;
- 1180x860 remains only the preferred first-open cap;
- the live maximum becomes the viewport work area minus a 16-pixel margin on
  each side;
- centering and preferred size use `FirstUseEver`;
- edge resizing is explicitly enabled in ImGui IO initialization;
- no persistent ini file or new OMV config key is added in this slice.

Resize is session-local. Closing and reopening OMV in a later game session
returns to the preferred centered size.

Expose current content-region availability through the Rust bridge. Replace
the fixed 315-pixel feature list with an adaptive width:

- target about 28 percent of available content width;
- clamp to a practical 260-380 pixel range;
- preserve the remaining width for the details child;
- retain independent scrolling and borders in both children.

At the minimum window size, the details pane must still show complete labels
and controls without horizontal clipping.

## Work package 9: wrapped choices and responsive header

Add a wrapped radio-button bridge operation rather than duplicating ImGui
geometry math in Rust. Before each non-first item, the C++ bridge calculates
the next radio's full width using ImGui's label, frame height, inner spacing,
and hidden-ID rules. It calls `SameLine` only when the next item fits inside
the current content region; otherwise the item starts a new row.

Use it for every integer choice group in `draw_shader_details`:

- three quality choices stay on one line when space permits;
- the nine atmosphere debug choices wrap over multiple lines;
- wrapping adapts immediately while the window is resized;
- keyboard/mouse selection and stable `##` IDs remain unchanged.

Make the header responsive without a new layout framework:

- title and session state may wrap;
- Save and Reload remain together where they fit;
- display the config path on its own wrapped line;
- keep render-stack actions together;
- place frame-pacing text/graph on a separate row instead of forcing it after
  all action buttons.

Do not convert radio choices to a combo box. The choices should remain visible
and quickly scannable.

## Work package 10: tests and static verification

Add or update unit coverage for:

- production fog requiring world color with debug view Off;
- medium-ready versus composition-ready gate combinations;
- missing transfer, stale underwater epoch, interior, underwater, missing
  color, and failed integration rejection;
- source-transfer round trips across negative, nominal, unity, and overbright
  values;
- nearest-depth bilateral acceptance, mixed-span tightening, sky bounds, and
  no-match fallback;
- config clamp and option ABI for debug modes 0-8;
- menu choice count and config synchronization;
- target recreation on dimension/scale changes and current-frame integration
  ownership;
- all compose and existing integration shader variants compiling as `ps_3_0`.

Run:

```text
cargo fmt --all -- --check
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
git diff --check
```

Always pass the explicit i686 target. Do not use the workspace's incorrect
default target.

## Runtime playtest matrix

Use one fresh release install and log.

### Visible production result

1. Exterior, above water, debug Off, High quality.
2. Capture fog disabled, then enabled without moving the camera.
3. Increase height density and density, then return to defaults.
4. Change base height, maximum distance, scattering albedo, noise amount, and
   noise scale one at a time.
5. Repeat Performance and Ultra long enough to log each compose path.

Expected: the world changes immediately and spatially as described; first
person and UI do not.

### Depth and stability

1. Move and rotate at the known fence trigger.
2. Cross nearby fence, foliage, water, actor, and terrain silhouettes.
3. Inspect debug view 8, then return to Off.
4. Look into sky and across a long terrain horizon.

Expected: no production alternation, foreground halo, or full-screen fallback.
Small conservative unchanged edge pixels are preferable to leaked fog.

### Contract fallback

1. Enter an interior.
2. Go underwater and return above water.
3. Toggle TAA off/on.
4. Alt-tab, resize/change resolution if available, and return.

Expected: rejected frames retain the original source, alpha remains stable,
and resources rebuild without stale fog.

### Menu

1. Resize from the preferred size to the viewport maximum and back to minimum.
2. Select Volumetric Fog and inspect all debug choices while resizing.
3. Confirm radio groups wrap, both child panes remain usable, and the frame
   graph no longer collides with action controls.

## File map

| File | Planned change |
|---|---|
| `omv/shaders/embedded/atmosphere_compose.hlsl` | New full-resolution transfer-aware bilateral composition shader. |
| `omv/shaders/embedded/atmosphere_debug.hlsl` | Add mode 8 from the same production acceptance math. |
| `omv/src/effects/atmosphere.rs` | Composition shader ownership, gate, binder, pass ordering, current-frame status, counters, and tests. |
| `omv/src/runtime.rs` | Request source color for production fog, expose status, and implement responsive menu layout. |
| `omv/src/config.rs` | Clamp fog debug mode through 8 and update tests. |
| `omv/src/shaders.rs` | Add the bilateral debug choice and honest fog/lighting descriptions. |
| `omv/config/omv.toml` | Document production composition and mode 8. |
| `omv/README.md` | Document visible fog behavior, transfer/alpha ownership, fallbacks, limitations, and UI resizing. |
| `psycho-imgui/src/bridge.cpp` | Viewport-bounded resize contract, content width query, wrapped radio geometry, explicit edge resize. |
| `psycho-imgui/src/lib.rs` | Safe Rust wrappers and FFI declarations for the new bridge operations. |
| `docs/graphics_fnv_volumetric_fog_phase2_implementation_plan.md` | Link this focused Slice D contract and correct nearest-depth upsampling ownership. |
| `docs/graphics_fnv_volumetric_fog_lighting_plan.md` | Record Slice D as the active visible-fog delivery while keeping lighting in Phase 3. |

No helper-DLL or xNVSE-side graphics changes belong in this slice.

## Implementation order and stop gates

1. Close and encode the source-transfer contract.
   Stop if the evidence cannot select one exact conversion.
2. Implement composition settings/gate/status and production world-color
   capture ownership.
3. Add and compile the compose shader with exact source-alpha preservation.
4. Implement conservative nearest-depth bilateral gather and debug mode 8.
5. Wire current-frame reduce -> integrate -> compose transaction and failure
   handling.
6. Add tests and complete the explicit i686 build.
7. Implement viewport-bounded resizing, adaptive child widths, wrapped radios,
   and responsive header rows.
8. Update config, menu, README, and parent-plan status.
9. Run the focused production/UI playtest.
10. If production fog still blinks, execute the existing blink-state closure
    against the real compose path; do not replace the feature with a disable.
11. Tune defaults only after correctness and transfer acceptance.

## Definition of done

Phase 2 visual composition is done when a clean release build makes the
Volumetric Fog toggle visibly affect supported exterior gameplay in debug
view Off, all fail-closed and alpha/stage contracts hold, the production path
is stable at the known blink trigger, and the resized workbench presents every
choice without a forced single-line layout.

That completes visible supplemental fog. Directional Volumetric Lighting
remains the next independently contracted Phase 3 feature.

# OMV render-hook performance contract

## Purpose and user-visible behavior

OMV keeps only its mandatory Present, Reset, menu, and independently required
depth-provider infrastructure resident so the in-game master switch can be
changed without restarting Fallout New Vegas. Optional native draw hooks and
the sky engine hook are prepared once and physically detached when their
consumers are disabled. PBR engine hooks remain resident under the mandatory
stale-wrapper safety contract, but bypass before selector/sampler work. The
disabled state is a live zero-visual-work state: the menu remains reachable,
native rendering continues, and visual D3D resources are released.

This contract addresses reports ranging from roughly half the expected frame
rate to single-digit frame rates. Static code inspection proved a
machine-sensitive render-thread I/O defect and several unnecessary disabled
hook paths. It does not prove that every reported slow machine has the same
cause, and static validation cannot establish an FPS improvement.

## Proven defect

Before this change, `ScreenShaderRuntime::scan_shaders_if_due` ran from
`apply_present_frame` and `apply_scene_phase`, both render callbacks. At the
default 200 ms interval it synchronously called:

- `luts::scan_luts`, which enumerates the LUT directory and reads file metadata,
  and reads changed LUT files;
- `shaders::scan_screen_shaders`, which enumerates the external shader
  directory, reads file metadata, reads changed bytecode, and may compile
  changed HLSL.

The scan happened before the phase's enabled-shader check. Present also entered
this path while `graphics.screen_space_shaders` was false. Therefore filesystem
latency, Wine/Proton path translation, antivirus, mod-manager overlays, a slow
disk, a very large asset directory, or concurrent I/O could stall the render
thread directly. The code establishes that unbounded external latency was on
the frame boundary; the relative contribution of each host condition is a
reasoned inference.

The disabled hook paths also performed work that was not needed for live
pass-through:

- every D3D draw entered both PBR and sky draw preparation;
- disabled PBR `SetShaders` cleared tracking state and attempted direct-state
  restoration before calling the predecessor;
- every Present serviced PBR, sky, screen effects, and world-pipeline cleanup;
- the disabled local-light hook tried to lock and clear three publications on
  every world-light traversal;
- scene-boundary hooks continued OMV depth, target, and phase checks.

These paths are proven by the pre-change source. They can amplify CPU overhead,
but their individual FPS cost has not been measured.

## RTX 5060 isolation results from 2026-07-29

The tester's controlled in-game comparisons refine the earlier pre-shader
hypothesis:

- with all OMV effects disabled, performance remains about 67 FPS;
- changing OMV depth production to external Depth Resolve gains only about
  1-2 FPS;
- windowed mode gains about 2-3 FPS over the tested fullscreen path;
- DOF alone costs about 4-5 FPS;
- TAA alone costs about 3-4 FPS;
- all remaining filters together account for roughly the smaller remainder
  between the disabled and fully enabled states.

These are runtime observations on the affected NVIDIA machine, not static
proof and not a universal GPU cost model. They establish two distinct
problems. DOF and TAA have real GPU costs worth optimizing immediately, but
their shaders cannot explain the approximately 67-FPS disabled ceiling.
Provider work is also not the dominant disabled ceiling because the true live
provider switch changed performance only slightly.

## 2026-09-27 log-based per-effect attribution (NVIDIA laptop)

### Measurement infrastructure

`.reports/omv-latest-perf.log` is the first capture from the log-based
attribution built into `omv/src/graphics_diagnostics.rs`. The
instrumentation is compiled into every build and armed from the in-game
menu's Customize tab through the session-only "Performance profiler"
checkbox (Configuration, General panel, next to the master switch). It is
never armed by default, its state is not saved to configuration, and
disabling is one relaxed atomic load per entry point with no counter, span,
timer query, lock, or window accounting behind it. The instrumentation is
temporary evidence collection and must be removed once the investigation
closes. Its outputs:

- `[GRAPHICS PERF SUMMARY]`: one line per ten sampled frames (one frame in
  120), with per-frame mean CPU wall-clock microseconds and call counts for
  every instrumented interval and counter. Menu frames are flagged so
  contaminated windows can be excluded.
- Per-family A/B lines also report `drew_calls/frame` for all six families
  so conditional effects are normalized per drawn frame, and summaries
  identify the active spatial-AA variant (`aa_fast_fxaa` through
  `aa_smaa`), phase-graph fallback commits (`phase_fallback`), and the
  letterboxed image-rectangle path (`image_rect_cropped`,
  `image_rect_changed`) used by the wrong-rectangle bug investigation.
- `[GRAPHICS PERF A/B]`: a rotating schedule that skips exactly one embedded
  effect family (ambient occlusion, spatial AA, final color, sunshafts,
  depth of field, motion blur) for one 600-frame window with a 120-frame
  settling prefix, and reports the median and p90 present-boundary frame
  interval of the clean samples. Window zero is an unmodified baseline; the
  delta against adjacent baseline windows attributes real frame time to the
  skipped family. This is the only trustworthy per-effect GPU-cost evidence
  on D3D9, which exposes no reliable per-pass timestamp query.

Skipped families reuse the pass graph's existing "effect has no work this
frame" state, so graph invariants are preserved; a skipped stage consumes
its predicted drawing-stage slot so the last real stage still writes the
engine target directly instead of a fallback commit. Each window boundary
also logs a `family=<name> armed` line, making the skip timeline auditable
against everything else in the log. CPU intervals are wall-clock
around serialized boundaries; a long interval can contain a driver wait and
is not proof that the GPU spent that duration executing OMV's commands.

### Session facts

1920x1200 fullscreen, backbuffer format 22, no MSAA, swap count 2;
`provider=omv`; shadows Ultra with 1024 cube maps, dynamic fade 0.178 s; one
local light expanding to seven during the session; 13 800 presents over
roughly 3.5 minutes. The main-menu phase (epochs 121-8401) shows OMV present
servicing of 4.0-6.6 us/frame with no effect work, which bounds the
instrumentation's own present-boundary overhead.

### A/B GPU attribution

Baseline (window 0): median 19.69 ms, p90 28.12 ms. Deltas of each skipped
family against that baseline:

| Family skipped | median | attributed cost | p90 |
|---|---:|---:|---:|
| baseline (nothing skipped) | 19.69 ms | — | 28.12 ms |
| ambient occlusion | 17.52 ms | ~2.2 ms | 22.68 ms |
| spatial AA | 13.33 ms | ~6.4 ms | 25.56 ms |
| final color/bloom | 18.01 ms | ~1.7 ms | 30.77 ms |
| sunshafts | 16.52 ms | ~3.2 ms | 25.91 ms |
| depth of field | 19.57 ms | ~0.1 ms (DoF never drew) | 24.80 ms |

The motion-blur window was not reached; the session ended after window five.

Interpretation bounds: the six windows cover roughly 90 seconds of gameplay
and are scene-sensitive. Each window has only the single earlier baseline as
reference, and effects draw conditionally (sunshafts drew 0.1-0.3 calls per
sampled frame in the surrounding summaries), so per-family deltas are
indicative, not exact. The spatial-AA delta is the standout: roughly a third
of the median frame. The sum of attributed fullscreen-effect cost is
approximately 13-14 ms per frame at 1920x1200, which is consistent with the
owner's report of losing about half the frame rate on this machine: a native
frame near the 60 Hz budget is pushed past it by the effect chain. The p90 of
the baseline (28.12 ms) shows roughly one frame in ten exceeding 28 ms;
temporal stutter and mean-frame-rate loss follow from the same distribution.

### CPU attribution (gameplay summaries, epochs 8521-13201)

| Interval | per frame | per call | notes |
|---|---:|---:|---|
| `shadow_pre` | 508-1660 us | 0.85-2.1 ms | 0.5-0.8 calls/frame |
| trishape + tristrips submission | ~520-770 us | ~0.4-0.5 us/draw | 239-1096 draws/frame |
| `pbr_selector` + `pbr_admission` | ~170-305 us | ~2 us/call | see table scan below |
| depth resolve (OMV route) | 37-76 us | cheap | 1.8-2.3 resolves/frame |
| state capture/apply, copies, phases | ~100-150 us | — | — |
| `present_total` (whole present servicing) | 4.6-7.8 us | — | menu frames excluded |

Two CPU findings need explanation:

1. `shadow_pre` (the `NativeShadowPreWork` span at
   `omv/src/fnv_local_lights.rs`) wraps `shadows::handle_common_entry`, which
   on the `ReplacementThenTail` path performs the complete OMV shadow map
   production — up to four sun cascades or 72 cube faces at 1024 resolution
   (`omv/src/effects/shadows/mod.rs:394`). The measured 0.85-2.1 ms per call
   is therefore the shadow feature's own production cost (submission plus
   likely driver wait), not removable hook overhead. It is the largest single
   OMV CPU item and correlates with the Ultra/1024-cube configuration.
2. The PBR shader-table lookup (`find_shader_array_index`,
   `omv/src/effects/pbr/hooks.rs`) scans the native PPLighting table linearly
   on a cache miss: `table_entry` reached 8.7k-16.8k per frame over 73-124
   `SetShaders` transitions and 85-163 misses, i.e. roughly 107-136 entries
   inspected per miss. Total cost is bounded (~0.15-0.25 ms/frame) but is a
   real per-draw tax.

Depth resolution is explicitly NOT a bottleneck: 37-76 us CPU per frame,
1.8-2.3 resolves, and the reliability line reports zero busy/deadline
failures. Its GPU cost is not separately attributable because depth cannot be
skipped without invalidating every depth consumer.

### Optimization plan

Ordered by attributed cost. Every item must pass the standing quality gates:
deterministic offline image oracles through the shipped shader path, compiled
bytecode budgets, the OMV suite, and the 32-bit release build. No FPS claim
is accepted without a new owner-run attribution capture. The A/B schedule is
the acceptance instrument: re-run after each change and require the targeted
family's delta to shrink while baselines stay stable.

0. **Persistent fullscreen stream for remaining passes (P0, CPU, cross-cutting
   quality-neutral).** `render_state.rs` already owns a persistent fullscreen
   vertex stream whose module documentation records the measured cost it
   removes: `DrawPrimitiveUP` performs a driver upload allocation per call,
   ~11-25 us per submission under DXVK. AO, sunshafts, and the shadow
   producer already submit through it, but spatial AA
   (`anti_aliasing.rs`), final color/bloom (`blooming_hdr.rs`), temporal AA,
   depth of field, motion blur, and atmosphere still call
   `draw_primitive_up` directly. SMAA alone submits three times per frame;
   with the full effect stack this is a recurring per-frame driver-side
   allocation cost paid on every pass of every family. Routing the remaining
   screen passes through the existing helper changes no shader, state, or
   image. The PBR geometry-test triangles and the shadow producer's test
   triangle are non-hot or diagnostic paths and are intentionally left as
   `UP` draws.

1. **Spatial AA (P0, ~6.4 ms attributed GPU).** The capture does not record
   which spatial variant drew, but the variant is attributable statically.
   The compiled-cost inventory test
   (`spatial_aa_variant_compiled_cost_inventory` in
   `omv/src/effects/anti_aliasing.rs`) pins every production variant's
   instruction tokens and texture sites through OMV's real compilation path,
   and the pass structure is static: Fast FXAA and NFAA are one pass with
   nine texture sites; AXAA is one pass with twelve sites (up to sixteen
   with search iterations, already adaptively bounded to one-to-three
   iterations with early exits); DLAA is two passes totalling twenty-two
   texture sites plus two full-resolution target writes; SMAA is three
   passes totalling thirty-one texture sites plus three full-resolution
   target writes. The measured family cost of roughly 6.4 ms at 1920x1200 is
   therefore statically plausible only for the heavy variants, in descending
   order SMAA, DLAA, AXAA. Concrete changes, in order:

   - SMAA weights: the four-pixel search is statically unrolled with one
     `[branch]` per orientation; once a side closes, `open` stays zero, yet
     the remaining pair samples still execute. Add an explicit bounded
     short-circuit per orientation so closed sides skip remaining pairs.
     Expected dynamic texture reduction on edge pixels only; byte-codes stay
     inside the pinned ceilings.
   - Route the AA quad through the persistent stream (item 0): three
     submissions per frame for SMAA become allocation-free.
   - The structural lever remains variant selection, which is user
     configuration and must not change silently. Resolution, filter
     footprint, and kernel reductions are rejected by
     `docs/graphics_fnv_aa_performance_research.md` and remain rejected.

2. **Sunshafts (P1, ~3.2 ms attributed, scene-confounded).** The pipeline is
   mask, 48-tap radial march, two separable blurs, and compose at half
   resolution (`sunshafts_radial.hlsl`, `SampleCount = 48`), with
   interleaved noise jitter already applied. Admission already rejects
   sunless frames (the capture contains explicit behind-camera rejections,
   and the pipeline drew only 0.1-0.3 calls per sampled frame), so the
   3.2 ms delta applies only while the sun is visible and must be normalized
   per drawn frame by the hardening item before and after the change. The
   candidate is reducing the march to 24-32 jittered taps and letting the
   existing blurs absorb the difference, with weight renormalization kept
   inside the existing equation; the deterministic sunshaft image oracle
   must prove equal-or-better quality against the unchanged 48-tap
   reference across occluder, grazing, and off-screen cases before the
   constant changes.

3. **Ambient occlusion (P1, ~2.2 ms attributed GPU).** Extract runs both
   families at half resolution: four depth fetches for normal reconstruction
   shared by both kernels, then an eight-tap kernel per family with one depth
   fetch per tap (twenty fetches per pixel in the combined path), followed by
   two blurs, optional temporal stabilization, and one full-resolution
   compose. Because both kernels already share directions, tangent basis,
   and rotation, the candidate is reducing each kernel from eight to six
   taps while keeping the existing sample-scale distribution shape and the
   `StableRotation` dither, with the temporal pass absorbing the difference.
   The AO suite owns deterministic reference oracles; the change must prove
   equal-or-better quality there, and the
   `ao_kernel_preserves_the_original_eight_samples_exactly` contract is
   updated only as part of that intentional, proven change. Kernel sample
   counts and target resolution are otherwise untouched.

4. **Shadow production (P1, 0.85-2.1 ms per production inside `shadow_pre`).**
   The pipeline already implements the scheduling levers this plan once
   proposed: static-face caching per cell, dynamic face masks from actor
   bounds, cascade refresh masks, per-light probing, and publication reuse
   across repeated common-entry invocations. The remaining first step is
   therefore measurement, not removal: extend the diagnostics counters with
   a per-production breakdown (cascades rendered, cube faces rendered,
   static-versus-dynamic faces, state-transaction stage costs) so
   `shadow_pre` wall time can be separated into GPU-bound rendering, driver
   submission, and the exact-state capture/restore overhead. Only after that
   breakdown exists can a cost-targeted change (for example resolution-tier
   or fade tuning as user-visible settings) be proposed without guessing.

5. **Final color (P2, ~1.7 ms attributed GPU).** The chain is one fused
   full-resolution compose (tone map, grade, LUT, deband, grain, vignette,
   halation, chromatic aberration) plus three quarter-res bloom draws and a
   512x1 auto-exposure pass; most of the cost is the inherent full-res pass.
   The concrete change is item 0 (the compose and bloom passes still use
   per-call `UP` draws). No shader change is planned. One measure-first
   candidate: `bind_target` calls `clear_texture` before binding each
   intermediate target; if the diagnostics show a measurable Clear cost per
   pass, prove the fullscreen draw covers the complete target (including
   half-pixel edges) before removing any clear.

6. **PBR table scan (P3, ~0.2 ms/frame CPU).** The lookup cache is a
   512-entry direct-mapped array keyed by `(shader, base)`; a miss linearly
   scans the ~130-slot native PPLighting table, and the capture shows 85-163
   misses per frame (one per first encounter of each distinct shader) at
   roughly 107-136 entries inspected per miss. The candidate is a persistent
   open-addressed pointer-to-index map per table, sized to the known table
   lengths (no heap allocation), populated lazily on first miss and
   invalidated by the same `SHADER_TABLES_READABLE` and package-transition
   lifecycle that already guards the scan. Verify with the existing
   `table_miss`/`table_entry` counters: misses stay constant, entries-per-
   miss drops to approximately one.

7. **Attribution hardening (P0 for evidence quality, no render-path change).**
   Add per-family drew-call counts to A/B lines so conditional effects
   (sunshafts, motion blur) are normalized per drawn frame, and capture at
   least two full A/B cycles (all seven windows) per scene type in the next
   run. This directly addresses the scene-confound limitation of the
   2026-09-27 capture, and the item-4 production counters ride the same
   diagnostics build.

#### Implementation batches

The items above execute as independently validatable batches, ordered so
measurement precedes shader-quality changes and zero-visual-risk CPU work
ships first:

1. **Batch A - diagnostics hardening (items 7, 4, 6 measurement part).**
   - `graphics_diagnostics.rs`: add one always-on atomic call counter per
     `Family`, incremented at each family's draw decision, and report
     per-family calls/frame in every `[GRAPHICS PERF A/B]` line; add a
     target-clear counter incremented in `clear_texture` (one site in
     `libpsycho`) to size the item-5 measure-first question; add
     per-production shadow counters (cascades rendered, cube faces rendered,
     static-versus-dynamic faces) incremented in `draw_maps` and surfaced
     through the summary line. All are zero-initialized POD atomics first
     used after the deferred handoff; the pre-DeferredInit footprint is
     unchanged.
   - Tests: profile-state tests for family-call accumulation and report
     contents; the OMV suite; no render-path behavior change.

2. **Batch B - persistent fullscreen stream adoption (item 0).**
   - Generalize `render_state::draw_fullscreen_quad` to accept the caller's
     vertex slice and primitive type, so the existing four-vertex strip
     callers and the three-vertex triangle callers (TAA, DoF) share one
     stream without changing submitted topology; changing a fullscreen
     triangle into a strip is deliberately not done because implicit-
     derivative sampling across the new diagonal would need seam proof.
   - Migrate the remaining hot-path `draw_primitive_up` sites:
     `anti_aliasing.rs`, `blooming_hdr.rs`, `temporal_aa.rs`,
     `depth_of_field.rs`, `motion_blur.rs`, `atmosphere.rs`. PBR and shadow
     test-module triangles stay as `UP` draws.
   - Tests: affected-effect suites (image oracles where they exist), OMV
     suite, release build. Expected effect is CPU-side (`present_total`),
     visible in the next attribution capture.

3. **Batch C - SMAA weights closed-side short-circuit (item 1).**
   - `aa_smaa_weights.hlsl`: guard each remaining search-pair fetch with an
     explicit `[branch]` on the running `open` value. The span equation is
     unchanged because closed sides contribute exactly zero; output is
     bit-identical by construction, proven by a deterministic CPU reference
     of the unrolled search over adversarial edge patterns.
   - The compiled instruction ceiling may rise by the added branch tokens;
     any ceiling movement is documented with the measured before/after
     counts, and dynamic texture-site execution drops on edge pixels.

4. **Batch D - PBR table index map (item 6).**
   - Per-table open-addressed pointer-to-index arrays sized to the static
     group counts (vertex A/B/C = 31/22/103, pixel A/B = 48/160; no heap
     allocation), populated lazily on first miss and cleared on the existing
     `SHADER_TABLES_READABLE` and shader-package transition lifecycle.
   - Tests: map insert/lookup/invalidation unit tests including collision
     and full-table cases; counters must show misses constant while
     entries-per-miss drops to approximately one.

5. **Batch E - sunshafts march reduction (item 2).** Owner-visible quality
   change, gated on the deterministic image oracle proving the reduced-tap
   march equal-or-better against the unchanged 48-tap reference; the oracle
   itself is the fail-first instrument and is added before the constant
   changes. Bytecode budget updated with measured counts.

6. **Batch F - AO kernel reduction (item 3).** Highest quality risk, executed
   last among shader changes, same oracle-first discipline as batch E, with
   the eight-sample contract test updated only inside the proven change.

7. **Final gate.** One release build, `git diff --check`, full diff review,
   then a new owner-run attribution capture over at least two full A/B
   cycles per scene type. A change is accepted only when its targeted
   family's A/B delta shrinks while baseline windows remain stable; no FPS
   claim is made without that capture.

### 2026-09-27 implementation status

Batches A through F are implemented and offline-qualified (757 OMV tests,
optimized 32-bit release build, formatting, and whitespace checks pass):

- **Batch A:** `note_family_draw` records per-family drew counts every
  frame; each `[GRAPHICS PERF A/B]` line now reports `drew_calls/frame` for
  all six families. New counters: `target_clear` (via the
  `render_state::clear_sampler` unbind wrapper), `shadow_cascade`,
  `shadow_face_static`, and `shadow_face_dynamic` at the cascade and cube
  face operation sites in shadow production.
- **Batch B:** `render_state::draw_fullscreen_vertices` generalizes the
  persistent stream to any `ScreenVertex` slice and primitive type with a
  capacity that grows to the largest submitted shape; the four-vertex strip
  helper delegates to it. Spatial AA, final color, temporal AA, depth of
  field, motion blur, and atmosphere now submit through the stream; the
  measured 11-25 us per-call `DrawPrimitiveUP` driver allocation is removed
  from every hot fullscreen pass.
- **Batch C:** the SMAA weights search skips closed sides' remaining pair
  fetches. A CPU reference proves span identity over the complete binary
  edge lattice; the compiled ceiling moved from 210 to 310 tokens, which is
  the documented trade of ~100 scalar branch tokens for up to six skipped
  point fetches per edge pixel.
- **Batch D:** each indexed PPLighting group owns an open-addressed
  shader-pointer index map sized to the largest group, populated by the
  first bounded scan and validated against the live table slot on every
  hit, so rebuilt shader packages self-heal. Entries-per-miss should drop
  to approximately one; the `table_miss`/`table_entry` counters verify it
  in the next capture.
- **Batch E:** the sunshafts radial march runs 32 jittered taps instead of
  48. Per-step decay goes to the 1.5 power, the weight ramp grows by
  1.014^1.5, and the sum renormalizes by the 48/32 step ratio, so the
  marched distance, total extinction, ramp endpoint, and brightness of
  mask-invariant shafts are preserved. The deterministic reference model
  bounds the discretization difference at 5 percent against the 48-step
  equation across open, hard-occluder, smooth-occlusion, and blocked
  fixtures (2 percent for a fully open shaft).
- **Batch F:** the AO extract kernel runs six taps at sixty-degree steps
  with a reshaped interior scale distribution (endpoints preserved) instead
  of eight taps at forty-five-degree steps; combined-family fetches drop
  from 16 to 12 per half-resolution pixel. The full AO property suite
  passes against the updated deterministic reference model, and the
  kernel/fetch contract tests pin the new shape. Per-pixel occlusion
  differences against the 8-tap kernel are bounded by the same model, but
  the visual acceptance on the affected machine remains the owner's
  judgment, as with every intentional quality-affecting change here.

Gameplay attribution (the A/B re-run) is pending and belongs to the owner.
The sunshafts and AO changes intentionally alter sampling cadence; if the
next capture shows a family delta that did not shrink, or the owner rejects
the visual result, the constants revert independently (each batch is a
self-contained change).

### 2026-09-27 second capture (`.reports/omv-latest-perf2.log`)

First capture after the batch A-F implementation. Session facts: same
machine and configuration; roughly 40 percent of the session ran with the
in-game menu open (the A/B schedule and summaries exclude those frames
correctly); the gameplay segments span multiple scenes, so cross-window
comparisons are noisier than the first capture.

Working improvements confirmed by the capture:

- `drew_calls/frame` in every A/B line does its job: window 9's halved draw
  rates (0.63 versus 1.25) mark it as a different-scene segment and rule it
  out for attribution, and window 1's missing motion blur (0.00) exposes a
  confound that would otherwise have been read as an AO gain.
- The persistent fullscreen stream and reduced marches did not regress
  anything measurable: present-boundary servicing stays at 6.6-9.4 us per
  gameplay frame.
- Shadow production is now separable: production frames cost 581-954 us
  inside `shadow_pre` with 8.2 static plus 0.6 dynamic cube faces counted,
  while publication-reuse frames cost ~2 us. No cascade renders appeared in
  sampled frames, consistent with the retention scheduler.
- `target_clear` quantifies the item-5 question at 90-204 unbinds per
  frame, dominated by the shadow producer's 16-sampler blanket clear and
  per-pass bind-target clears; a reduction pass is worthwhile.

Attribution from the clean windows (baseline 17.88/17.27 ms median):

| Family skipped | window | median | attributed |
|---|---|---:|---:|
| spatial AA | 2 | 14.84 ms | ~3.0 ms |
| final color | 3 | 13.27 ms | ~4.6 ms |
| sunshafts | 4 | 15.13 ms | ~2.4 ms at 0.27 draws/frame |
| motion blur | 6 | 16.54 ms | ~0.7 ms (see anomaly below) |
| ambient occlusion | 1, 8 | 11.46 / 18.81 ms | unreliable: motion-blur admission differs from baseline |
| depth of field | 5 | 15.85 ms | never draws |

The AA delta fell from ~6.4 ms (first capture, different scene) to ~3.0 ms;
the SMAA short-circuit and stream adoption are plausible contributors but
the scene changed between captures, so no improvement is claimed.

Two defects and one measurement gap surfaced:

1. **Motion-blur drew-counter anomaly.** Window 6 reports the skipped
   family drawing 1.25 calls/frame. Static review finds every path guarded
   (the first-person note is unreachable past its skip), but the graph-path
   image-space motion blur branch has no `note_family_draw` call at all, so
   baseline windows count first-person draws only. Next capture must add an
   armed-transition log line at every skip switch and the missing graph-path
   note; until then motion-blur attribution stays open.
2. **The PBR index map did not reduce `table_entry`.** Entries-per-miss
   remains ~103 at 240-275 misses per frame. The map serves positive
   first-encounters, which the previous direct-mapped cache already
   covered; the dominant cost is negative lookups (shaders absent from all
   PPLighting groups), which rescan unconditionally. The fix is negative-
   result caching in the same maps, invalidated at the existing
   `ShaderPackageTransition` boundary so a rebuilt package cannot hide a
   newly registered shader behind a stale negative entry.
3. **Menu contamination.** Future captures should keep the menu closed
   during A/B windows; the schedule excludes menu frames from statistics
   but the surrounding scene changes still blur cross-window deltas.

### 2026-09-27 follow-up fixes and second optimization round

Implemented after the second capture's analysis:

- **Skip-window fallback commits eliminated.** The second capture's
  reliability lines showed `fallback_commit` at ~0.86 per frame (first
  capture: 0.28) — a profile-skipped stage left its predicted drawing-stage
  slot unconsumed, so the last real stage wrote a graph texture and the
  graph finished through a full-resolution commit copy nearly every skipped
  frame. This both wasted a full-resolution transfer per skipped frame and
  understated every A/B delta by that copy's cost. A skipped stage now
  consumes its predicted slot, so the last real stage writes the engine
  target directly, exactly like the established "absent from graph"
  motion-blur path.
- **Graph-path motion-blur draw note added**, closing the counter gap that
  left window 6's `motion_blur=1.25-while-skipped` anomaly unattributable.
- **PBR negative-lookup caching.** The second capture proved the index map
  only served positive first-encounters (already covered by the direct
  cache) while `table_entry` stayed at ~24k-28k per frame: the dominant
  cost is shaders absent from all PPLighting groups, which rescanned
  unconditionally. A proven absence is now cached with the group's
  last-slot fingerprint; the fingerprint validation voids the entry if the
  table grows or is rebuilt, and the shader-package transition hook drops
  every cached entry outright. Expected: `table_entry` collapses from
  ~28k to hundreds per frame, and `pbr_selector` drops from 0.5-1.1 ms to
  a fraction of that in PBR-heavy scenes.

The reported freeze-plus-rectangle defect (picture frozen while walking or
after loading a save from a different location; a large top-right rectangle
filled with content that changes as the mouse moves) was researched through
two independent static audits before any code change:

- Every ImGui draw site (menu, PBR preparation overlay) binds the swapchain
  backbuffer explicitly and runs inside the screen transaction; the ImGui
  DX9 backend additionally captures and applies its own full state block,
  and the transaction journal restores viewport, scissor rect, and scissor
  enable error-safely. No OMV overlay draws with the menu closed except the
  centered PBR preparation overlay, which receives no mouse input.
- Every fullscreen-vertex-stream call site sits inside a transaction that
  restores stream 0, stream frequency, and FVF/declaration; ImGui rebinds
  its own buffers and self-restores; the discard lock covers the whole
  buffer; no FVF/declaration conflict exists.

Neither audit can reproduce the reported visual from shipped code, so no
speculative fix was made. The rectangle's content changing with mouse
movement means it shows either live camera content (a wrong image-space
rectangle would do this: the compose writes only inside the rectangle while
the rest of the presented target is stale) or mouse-driven UI content. The
next repro session must ship its `omv-latest.log`: the capture already
records `MenuFrame` counters, `fallback_commit` counts, reliability lines,
and per-family drew rates, which will discriminate between a wrong native
image rectangle (cropped phase path), a stuck menu/diagnostics overlay
(the second capture's `menu_frames=9-10` section shows the menu was open
for minutes mid-session), and a present-path stall. One deliberate
non-fix note: `draw_fullscreen_vertices` uploads fewer bytes than the
stream buffer holds for the 3-vertex triangle case, violating the
`replace_discard` documented byte-count contract while remaining benign
(draws read exactly the uploaded count); the contract should be narrowed
or the buffer sized exactly in a future cleanup.

### Root cause and fix: SMAA stale-image rectangle (2026-09-27)

The owner identified the SMAA effect as the trigger of the reported stale
picture plus a large rectangle filled with content that changed as the mouse
moved. The offline reproduction proved the mechanism and it is fixed:

- `draw_smaa` (and every spatial-AA variant path) never bound its own FVF,
  never cleared a leftover vertex shader, and never set a viewport. The
  passes inherited whatever the engine's last native draw had left. When
  that inherited state differed — after walking transitions or loading a
  save from a different location — `DrawPrimitive` either failed outright
  (reproduced offline as `D3DERR_INVALIDCALL` with no FVF bound) or
  interpreted the quad through the engine's leftover vertex format,
  producing garbage geometry over a rectangle of the target whose colors
  came from stale device state (changing with mouse-driven uploads) while
  the rest of the target kept the previous frame. This matches the reported
  symptom exactly and explains why disabling SMAA removed it.
- The fix binds the complete per-pass drawing state in AA's `bind_target`:
  `clear_vertex_shader`, `set_fvf(ScreenVertex::FVF)`, and a zero-origin
  viewport matching the pass target, for all AA variants and all three SMAA
  passes. RHW quads ignore the viewport offset under DXVK, so the viewport
  binding is ownership hygiene rather than a behavioral change; the FVF and
  vertex-shader bindings are the defect fix.
- The regression `smaa_letterboxed_phase_matches_a_fresh_reference_every_frame`
  drives the real letterboxed final-phase path with SMAA on a hardware
  device across two frames with different scene content and requires every
  frame to match a fresh same-frame reference drawn on an image-sized
  target, with the native letterbox bars bit-exact. It failed with the
  defect present (INVALIDCALL before the fix) and passes after it.
- Hardening in the same bug class: a failed persistent-stream submission
  now drops the cached buffer instead of keeping it, so a device recreated
  underneath the stream cannot poison every later fullscreen pass for the
  device's lifetime; the next submission re-creates the buffer.
- Log evidence that pointed here: `aa_smaa=1.0` identified the active
  spatial-AA variant, and the `image_rect_cropped`/`image_rect_changed`
  counters confirmed the letterboxed compose path was active. The changed
  counter reads high because it compares across scene and final phases
  within one frame; per-target tracking would make it precise.

### Unresolved unknowns

- Which spatial AA variant was enabled in the working config; the repo
  default ships all spatial AA disabled and the log does not name the
  variant. Static compiled-cost attribution (item 1) bounds the plausible
  candidates to SMAA, DLAA, or AXAA, which is sufficient to start work; a
  future A/B line with per-family call counts would close it exactly.
- The sun-visible fraction during the sunshafts window; without per-window
  call counts the 3.2 ms delta cannot be normalized per drawn frame.
- Motion-blur GPU cost: the rotation never reached its window.
- How much of `shadow_pre` wall time is driver wait versus CPU work; needs
  the per-face/per-cascade counters from item 4.
- Whether the fullscreen-effect deltas sum linearly (GPU headroom may absorb
  part of each family); only a new capture can confirm.


The remaining disabled-path candidate was OMV hook/resource residency. The
previous master-off implementation still routed every DP/DIP through OMV and
left PBR `SetTexture` sampler tracking plus the sky-constant hook active. Even
a fast branch at each draw is not the same experiment as restoring the
original entry, especially under a driver/DXVK stack whose NVIDIA behavior
differs from the RX 6800 XT reference machine.

The current implementation creates the hook objects once but treats enabled
state as physical ownership:

1. enabling a native PBR/sky consumer attaches both DP and DIP at the
   Present-owned quiescent boundary;
2. sky then attaches its prepared engine hook, while PBR's resident hooks leave
   their passive early-bypass state;
3. disabling reverses that order, restores replacement state, detaches the sky
   hook, makes PBR detours passive, and finally restores both original device
   draw entries;
4. pair transitions roll back on the second-entry failure, so DP and DIP can
   never cover different primitive families;
5. the reliability record reports `draw_hooks=attached`,
   `prepared-detached`, or `unavailable`.

Master-off also releases all OMV visual shaders, intermediate targets, temporal
histories, and state blocks while retaining ImGui and the machine-local depth
provider. It deliberately does not call `EvictManagedResources`, which would
affect resources owned by the game and other plugins. Re-enable recreates
device resources lazily and reuses process-owned shader bytecode.

This physical control is the necessary next root-cause test. Static source
proves the original entries are restored; only the affected machine can show
whether the 67-FPS ceiling moves.

OMV now also logs the primary swap-chain parameters at device-hook install and
after each successful Reset: windowed/fullscreen mode, backbuffer dimensions
and format, buffer count, MSAA type/quality, swap effect, fullscreen refresh,
presentation interval, and the driver's approximate available texture memory.
This makes the observed 2-3 FPS windowed advantage reproducible without
guessing which presentation contract the game actually created. These are
diagnostics at lifecycle boundaries, not per-frame queries.

## Tester-log findings from 2026-07-26

`.reports/omv-latest--performance-bad.log` provides two additional direct
observations:

- PBR reported 162 queued shaders even though most entries were cache hits.
  Ten missing close-terrain variants visible before the log ended then
  compiled individually for about 8.6-11.7 seconds each while the game was
  already running. Per-entry cache/resource messages also produced hundreds
  of info-level log records.
- Every world and first-person depth resolve returned D3D error `0x8876086A`.
  Depth-dependent work was nevertheless reached and its resources and phase
  copies were initialized.

The failed route remained selected and attempted up to three full
state-block-backed RESZ transactions per rendered frame. The log cannot
identify whether the failure came from the all-state block, a binding, the
marker draw, or the RESZ trigger. It also cannot by itself attribute the
tester's sustained frame rate to one pass. It does prove an incomplete PBR
cache, a long and poorly distinguished preparation period, and a device on
which the old RESZ-only transaction did not work.

### NVR-derived depth hot path

The working NVR source does not capture/apply `D3DSBT_ALL` for RESZ. It retains
only FVF, declaration, texture 0, vertex/pixel shaders, stream 0, Z-enable,
Z-write, and color-write, then resets the point-size trigger. OMV previously
performed that bounded work plus an all-state capture/apply on every resolve.
At the active world, coherent-world, and first-person capture points, that
broad transaction could occur up to three times per frame.

OMV now owns the same bounded state set through
`libpsycho::os::windows::directx9::ReszState9`. Owned COM references keep every
saved binding alive until restoration, and OMV preserves the incoming point
size rather than assuming it was zero. The error path still attempts every
state and depth-attachment restore. Only the RESZ helper lost its all-state
block; independent screen/world draw transactions still retain theirs.

NVR also treats an `INTZ` source surface as a texture level on native NVIDIA:
it obtains the `IDirect3DTexture9` container, registers that texture, and uses
it as the NvAPI copy source. OMV previously registered and copied the surface
unconditionally. OMV now retains and prefers the texture container with a
standalone-surface fallback, matching NVR on native NVIDIA.

These are direct source-contract fixes. Static evidence proves the removed
calls and corrected resource identity, but only the reported NVIDIA system can
measure the resulting frame time.

### Operational depth-route circuit breaker

OMV now treats `D3DERR_NOTAVAILABLE` from an advertised RESZ transaction as an
operational capability rejection. It tries native NvAPI once for the current
device generation and retries the current capture only if initialization
succeeds. Otherwise it caches depth as unavailable. This removes the repeated
marker draw, full-state capture/restore, and target churn from the incompatible
path. Other D3D failures retain RESZ so transient errors cannot permanently
reduce effect coverage. Device replacement/reset clears the cached decision
and probes again. This is secondary failure containment; the bounded NVR state
transaction and native source-container ownership are the compatibility and
performance fix. Full evidence is maintained in
`docs/graphics_fnv_depth_resolve.md`.

## Architecture and ownership

`omv/src/asset_scanner.rs` owns live external shader and LUT discovery. Runtime
configuration starts one named `omv-asset-scan` worker. The worker:

1. parks completely while the live master switch is off;
2. scans at the configured interval while it is on;
3. retains the last valid external shader and LUT catalogs;
4. publishes changed catalogs through a capacity-one channel;
5. retains only the latest unsent snapshot if the render thread has not
   consumed the prior publication.

`ScreenShaderRuntime::poll_asset_scanner` uses non-blocking `try_recv`. It does
no filesystem work. A received generation is committed in one render tick:
unsaved menu values are preserved, changed shader bytecode invalidates compiled
passes, changed LUT data invalidates the bloom/final-color resource owner, LUT
choices are rebuilt, and embedded and external source lists are merged.

Initial `runtime::configure` still constructs embedded effect sources
synchronously from in-memory configuration. If the worker cannot start, OMV's
embedded effects and menu remain usable; external shader discovery, external
LUT discovery, and their live reload are unavailable and one warning is
logged. A scan failure retains the last valid catalog and warning output is
bounded.

The scanner starts during OMV runtime configuration. This does not publish or
initialize the focused FNV world pipeline. Its first publication remains in
`DeferredInit`, as required by
`docs/graphics_fnv_atmosphere_startup_crash_errata.md`.

### Native PBR local preparation

OMV releases contain PBR HLSL source and never contain generated `.cso` or
`.pso` bytecode or a populated cache directory. The release packager rejects
an archive that violates that rule.

After `NVSEPlugin_Load` has staged an enabled native-PBR settings snapshot, the
named `omv-pbr-prepare` worker may begin one CPU-only preparation transaction.
Starting there overlaps cache work with data loading, but does not configure or
activate PBR. Engine inspection, hook installation, world publication, D3D
resource creation, and replacement remain behind DeferredInit and Present.

The transaction:

1. constructs exact compiler-input groups from source bytes, shader target,
   compiler flags, and PBR contract revision;
2. inventories the canonical content-addressed cache entry for each group;
3. accepts only entries whose envelope, source/contract hash, bytecode size,
   checksum, shader stage, and terminal token validate;
4. compiles only missing or invalid unique inputs;
5. publishes one immutable bytecode allocation to every engine-visible logical
   alias in the group; and
6. retains the complete verified logical catalog in process memory.

The current 162 logical PBR templates contain 132 exact compiler inputs. The 57
close-terrain entries are one vertex input and 28 base/canopy pixel pairs, so
they require only 29 cache reads or compiler calls. The alias is internal to
preparation: each SLS identity keeps its own ready/failed state and current D3D
resource slot. A group failure marks every logical alias failed, preserving the
existing whole-catalog and close-terrain-family atomic activation gates.

Compiler workers share a bounded queue. The automatic count is half the
available logical CPUs, rounded up, clamped to `1..=8`, and capped by the unique
miss count. This gives one worker on a two-thread system, two on four threads,
four on eight, and eight on sixteen or more. The game therefore retains CPU
headroom while Wine compiler implementations that permit parallel work can use
it. A controlled sweep through the game's exact native `d3dcompiler_47.dll`
compiled the same eight unique close-terrain inputs successfully at every
tested count. Its wall times were 13.73, 13.65, 13.69, and 13.60 seconds for
one, two, four, and eight workers respectively. That compiler effectively
serializes this workload, so source deduplication and startup overlap are the
proven native wins; higher worker count is not claimed as a native speedup.

The canonical cache hash still includes source, shader target, compiler flags,
cache format revision, representative logical identity, and PBR contract
revision. A changed input therefore invalidates only its affected group. Cache
publication writes a complete envelope to a unique temporary file, closes it,
renames it atomically, reopens it, and verifies it before reporting success.
The cache is reconstructible and self-validating, so it deliberately does not
force a physical `sync_all` for every shader. A process or power interruption
may lose the newest cache entry; it cannot make unchecked bytecode ready, and
the next inventory removes or rebuilds invalid data. Stale variants are
reclaimed by the bounded 64 MiB/48 MiB cache-maintenance policy instead of a
directory scan after every compiler result.

Aggregate logs distinguish logical and unique cache counts and report total,
inventory, compile-phase, summed compiler-work, and summed cache-work
milliseconds. Summed work counters may exceed wall time when a compiler truly
runs calls concurrently. Detailed per-input messages remain debug-level.

The previous transaction performed these operations independently for every
logical template:

1. inventory all expected content-addressed cache entries;
2. accept only entries whose envelope, source/contract hash, bytecode size,
   and checksum validate;
3. compile only missing or invalid entries, using two workers;
4. write a temporary file, flush it, rename it atomically, reopen it, and
   verify the committed entry;
5. retain the complete verified bytecode catalog in process memory.

Those steps explain the measured cold-cache cost: prior 162-entry sessions took
201.105 and 276.489 seconds, while the 2026-08-03 56-entry close-terrain rebuild
took 45.864 seconds. Removing 28 redundant close-terrain compiler calls is a
deterministic 50-percent reduction for that affected family. Final wall time in
the game still requires the normal cold-cache playtest because compiler and
storage behavior vary by Wine prefix and machine.

Device-owned shader handles are created from the process-owned bytecode at a
budget of four per Present. Device loss discards only D3D handles. A reset
recreates them from memory without rereading or recompiling the cache. Disabling
native PBR cancels outstanding preparation generations; already verified
in-memory entries remain reusable. Detailed per-entry cache, compile, and
resource messages are debug-level, while aggregate completion and failures
remain visible.

No render callback performs shader compilation or cache I/O. Present retains a
fallback start in case native PBR was enabled after startup and creates the
bounded number of required D3D resources because D3D9 device ownership is
render-thread-bound. Draw replacement remains atomic at the whole prepared
catalog boundary, including the mandatory close-terrain family boundary.

### Effect applicability preflight

Each depth-dependent embedded effect now exposes a side-effect-free
applicability predicate. Ambient occlusion rejects a frame when neither AO
family is selected or required depth is absent. Sunshafts rejects absent depth
or an unavailable sun contract. Depth of field rejects absent depth and
preserves its vanilla-DoF resume state when skipped.

`ScreenShaderRuntime` evaluates those predicates before effect creation and
before any `StretchRect`. It also evaluates all enabled sources in a phase
before creating/capturing its D3D state block or allocating/updating the phase
color-copy target. A phase containing only rejected effects therefore performs
neither operation. Depth of field also waits for its background shader
preparation before declaring its phase applicable. This changes no shader
equation, pass quality, or supported coverage; an applicable effect uses the
same render path as before.

### The v2.0.6 1-FPS report

`.reports/omv-latest--1fps.log` is a v2.0.6 runtime record at 3840x2160. It is
not evidence from the implementation documented below, but it exposes three
old structural defects:

- first use of atmosphere, AO, final color, and motion blur coincides with
  multi-second initialization gaps; old effect constructors compiled or read
  cached HLSL from the render callback;
- `completed_no_draw` rises from 0 to 560 while both `pre_alpha` and `primary`
  rise by the same 560 transactions; the old world path resolved depth and
  entered the coherent transaction before discovering that atmosphere had no
  visible contribution;
- the screen stack gave each embedded effect its own full-resolution
  copy-before-draw transaction. Final Output then copied its composed
  full-resolution result again before chromatic aberration, and the external
  depth-aware CAS pass began from another phase copy.

The same record contains exact ten-second 600-Present intervals when world
work is absent, but slower intervals while the no-draw world transactions are
accumulating. This is correlation rather than a GPU timestamp attribution.
The source and counters nevertheless prove that expensive work occurred before
the old no-draw decision.

No effect, effect family, default, user parameter, shader equation, sample
count, or CAS pass is disabled by the remediation. It changes scheduling,
resource ownership, and redundant transfer work only.

### Process-owned screen-effect preparation

AO, atmosphere, spatial AA, TAA, sunshafts, Final Output, DOF, and motion blur
now own immutable process bytecode catalogs. Enabling a configured family
starts an idempotent worker request. A process-wide background-only gate permits
one screen-effect compiler/cache transaction at a time, preventing several
effect workers from saturating the same machine while PBR retains its separate
preparation contract. The request path remains part of the established
`NVSEPlugin_Load` startup contract; first-person motion blur adds no new worker
owner there.

Render callbacks poll readiness and create only D3D9 device objects from
resident bytecode. They never acquire the compiler gate, invoke the HLSL
compiler, or read/write the shader cache. Device reset discards device objects
but retains process bytecode. A failed catalog leaves that effect safely
unavailable and logs the bounded preparation failure; it does not switch to a
different quality tier. Phase applicability and the world pipeline verify that
the selected consumer is ready before full-resolution color allocation or
physical depth resolve, so queued preparation does not create a copy-only
frame.

### Phase-local color graph and immutable execution plan

Every native image-space phase now has one color graph:

1. copy the engine target to a persistent primary texture once;
2. execute intermediate logical writers by alternating primary and scratch
   targets;
3. direct the final planned writer to the engine target;
4. if dynamic admission rejects a planned tail after an earlier writer drew,
   commit the current graph texture once.

AO and Final Output each expose multiple menu sources but remain one logical
writer. External `pass_count` values remain distinct ordered writers. Final
Output writes composition directly into its persistent exact-format
full-resolution target when chromatic aberration follows, so that second pass
samples the target directly; there is no internal full-resolution copy.

Configuration, asset, and preset changes build immutable phase plans from the
compiled source set. Each plan retains allocation-free shared source snapshots,
the exact compiled-pass positions, AO-present and AO-absent schedules, logical
writer totals, and source-pass totals. A render callback therefore walks only
its phase and does not clone source names, option vectors, or other owned
configuration data per effect.

The reliability line reports cumulative
`color_copies=phase_initial:<n>/fallback_commit:<n>`. The normal cost is one
initial full-resolution copy for each phase that actually draws, independent
of the number of enabled effects in that phase. Fallback commits should be
rare and correlate with dynamic applicability rejection.

### DOF and TAA GPU work

The RTX 5060 isolation made DOF and TAA immediate work rather than deferred
research. The quality contract remains strict: no lower resolution, history
precision, gather tap count, blur radius, or effect coverage was accepted.

DOF now:

- uploads frame/projection constants once per effect transaction and changes
  only target-size constants between passes;
- binds and clears only its proven sampler ABI, s0-s4, rather than s0-s9;
- uses a three-vertex full-screen triangle for every pass;
- compiles round and soft gather shapes separately, removing the runtime shape
  branch and unused exponential work from round gathers;
- compiles near/far soft filters separately, removing a per-tap layer branch;
- expresses the high-quality near upsample's exact `[1 2 1]^2 / 16` kernel as
  four phase-correct bilinear samples instead of nine explicit samples.

The pass graph, half/full target dimensions, gather tap counts, FP16 formats,
focus equations, CoC equations, and alpha composition remain unchanged.
Detailed ownership and visual acceptance are in
`docs/graphics_fnv_depth_of_field.md`.

TAA now queries `NumSimultaneousRTs` and
`D3DPMISCCAPS_MRTINDEPENDENTBITDEPTHS`. When both prove the contract, one
shader writes FP16 resolved color to COLOR0 and the R16F logarithmic depth key
to COLOR1. This removes the second full-resolution depth-key draw and its
duplicate depth sample. Devices without the exact capability retain the
original two-pass path. Both paths use a three-vertex full-screen triangle,
preserve engine alpha, maintain the existing temporal rejection equations, and
remain inside the complete world attachment/state transaction.

## Disabled live-pass-through contract

The master switch is published as one atomic flag. Prepared hooks remain
reusable, but optional hot entries are physically restored; no restart is
required.

- DP and DIP detours are attached as an atomic pair only when enabled native
  PBR or sky requires a draw boundary. Their internal master check remains a
  defensive transition guard, not the normal disabled path.
- Present keeps native Present, render-epoch ownership, failure/timing
  accounting when requested, and the menu boundary. PBR, sky, and screen-effect
  services are skipped when the master is off, the menu is closed, and ImGui
  has already initialized.
- FNV image-space, world-scene, and first-person hooks call their predecessors
  directly when disabled.
- PBR `SetShaders` and `SetTexture` bypass before hot replacement work, and the
  sky constant hook is detached. PBR shader-creation hooks retain only their
  one-time wrapper observation so an initially disabled configuration can be
  enabled live. PBR hooks stay resident because the proven engine contract
  forbids a runtime teardown that could restore stale wrapper ownership.
- Local-light and retained world-light publications are cleared once after
  capture is disabled. A busy `try_lock` leaves the one-shot cleanup pending;
  render callbacks never block.

Inline and vtable bytes are changed only at DeferredInit or Present, the
serialized render-thread boundaries where no covered native call can be in
flight. On PBR re-enable, the cleared sampler cache warms from subsequent
engine texture bindings; an incomplete layout fails closed to the vanilla
shader.

Switching the master back on first republishes subsystem configuration. The
scanner is unparked, embedded effects are already available, and native PBR
activation continues at its existing Present boundary. Hook addresses,
predecessor chaining, scene phase ordering, shader equations, and resource
formats are unchanged.

## Performance and memory bounds

Render callbacks perform no directory enumeration, metadata query, shader file
read, LUT file read, or external HLSL compilation. Catalog polling is a
non-blocking channel receive and returns immediately when empty. Allocation and
source-list rebuilding occur only when a changed catalog generation is
committed, not every frame.

Each active phase retains one additional scratch texture matching that phase's
exact dimensions and format. At 3840x2160 this is 33,177,600 bytes for a
four-byte target or 66,355,200 bytes for an eight-byte FP16 target. Final
Output retains one additional exact-format full-resolution target only when a
composition pass feeds chromatic aberration. These are persistent device
resources, replaced only on device/description changes; the steady-state path
does not allocate them. The memory trade removes one full-resolution transfer
per additional phase writer and Final Output's former internal transfer.

The worker owns one external source catalog and one LUT catalog. The channel
holds at most one snapshot and the worker holds at most one newer pending
snapshot. LUT pixel storage is shared with `Arc`; external shader snapshots
clone their bounded bytecode and option data. This trades bounded background
memory for removal of unbounded filesystem latency from the render thread.

When the master switch is off, the scanner is parked and issues no periodic
filesystem requests. OMV visual resources are absent, native draw and sky
entries point to their predecessors, and resident PBR detours take only their
early configured-state bypass. Other disabled visual overhead is limited to
the mandatory Present/menu boundary plus independently selected depth-provider
service.

## Validation and acceptance

Static regression coverage establishes:

- `runtime.rs` cannot directly call the LUT or external shader scan functions;
- the background scanner publishes through a capacity-one channel;
- LUT and shader discoveries are committed together before rebuilding source
  choices;
- a disabled master bypasses D3D draw work and FNV scene-boundary work while
  retaining the menu boundary;
- disabled PBR `SetShaders` calls native behavior before tracking work;
- scan intervals remain bounded to 50-5000 ms.
- rejected AO, sunshafts, and depth-of-field frames exit before effect
  resource creation and backbuffer copy;
- a phase whose enabled effects are all rejected allocates no color-copy
  target;
- a drawn phase performs one initial color copy, alternates intermediate
  targets without feedback, preserves reference ordering through dynamic
  rejection, and performs at most one fallback commit;
- immutable phase plans collapse AO and Final Output to one logical writer,
  preserve external pass counts, and avoid whole-source scans and owned source
  clones in the draw loop;
- every production screen-effect compiler/cache transaction is reachable only
  from a background preparation worker;
- atmosphere admission rejects proven no-contribution frames before pre-alpha
  or coherent depth resolve while unknown scene/local-light state proceeds;
- Final Output contains no internal full-resolution copy when chromatic
  aberration follows composition;
- the native-PBR render boundary contains neither local HLSL compilation nor
  shader-cache commit calls;
- release packaging cannot include generated shader bytecode or cache files;
- device reset preserves the process-owned PBR bytecode catalog, while
  disabling PBR cancels unfinished preparation;
- exact PBR compiler-input grouping covers every logical template once and
  holds the reviewed 162-to-132 unique-input budget;
- close-terrain grouping holds its reviewed 57-to-29 budget and shares one
  immutable bytecode allocation across every base/canopy alias pair;
- adaptive compiler workers reserve half the reported logical CPUs, never
  exceed eight, and never exceed the number of unique misses;
- cache publication retains atomic rename and strict readback verification
  without a per-shader durable disk flush; and
- early PBR preparation follows the deferred-settings handoff and cannot
  publish world state or install graphics ownership from `NVSEPlugin_Load`.

Required validation is:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
git diff --check
```

On 2026-07-26, the Windows/Wine OMV suite passed all 302 tests and the optimized
`i686-pc-windows-gnu` OMV release target built successfully.

The 2026-07-27 PBR preparation, depth-route, and applicability update passed
all 309 OMV tests and the optimized `i686-pc-windows-gnu` OMV release build.

The 2026-07-29 disabled-path lifecycle, DOF, and TAA update passed all 417 OMV
tests, including shader-variant compilation and the CPU reference proof for the
four-sample near reconstruction. The optimized `i686-pc-windows-gnu` OMV
release target also built successfully.

The subsequent world-only-provider AO phase correction passed all 419 OMV
tests and the same optimized release build. Its regression proves that
post-first-person world AO darkens a covered weapon pixel and that the
provider-aware ordering preserves the first-person color.

The structural scheduling update passed all 427 OMV tests. This includes the
pre-depth admission negative controls, exact-stage depth-cache identity,
phase-graph ordering through dynamic rejection, Final Output transfer/memory
budget, background shader-variant compilation, and the existing DOF/TAA image
and bytecode budgets.

The 2026-08-03 PBR preparation performance update passed all 450 OMV tests
under Wine and built the optimized `i686-pc-windows-gnu` OMV release target.
The suite includes every registered PBR variant, exact grouping and alias-state
proofs, cache publication recovery, startup source-order ownership, adaptive
worker bounds, and eight concurrent unique compiler inputs. A separate sweep
through the game's native `d3dcompiler_47.dll` passed at one, two, four, and
eight workers with the timings recorded above.

The Depth Resolve AO playtest follow-up corrected the world-only composition
target without changing shader parameters or adding a depth copy. AO now draws
on active RT0 immediately after world rendering instead of pre-binding the
`BSRenderedTexture*` argument at `RenderFirstPerson` entry. The structural
negative controls reject the old target path and require missed-frame AO
history invalidation before unrelated scene-pre work; all 428 OMV tests and
the optimized release build pass.

Ordinary gameplay remains the runtime acceptance gate. Test at least one
previously affected Wine/Proton setup with the master both off and on. With the
master off, FPS and frame-time distribution should be statistically
indistinguishable from the same setup without OMV, apart from hook dispatch
noise. With the master on, remaining cost must correlate with enabled effect
passes rather than 200 ms filesystem stalls. No FPS result is claimed until
that playtest evidence exists.

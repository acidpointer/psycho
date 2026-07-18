# FNV atmosphere debug blink contract-closure plan

Date: 2026-07-18

## Outcome

Close the camera- and geometry-dependent full-screen blink reported in every
atmosphere debug view before final Phase 2 acceptance. The failure presents as
a rapid switch between the selected debug view and the ordinary world image,
especially near a fence.

This stage is complete only when one captured failing frame identifies the
exact failing contract, the corresponding minimal fix is implemented from
evidence, and every atmosphere debug view remains continuously visible during
the fence reproduction.

Priority revision on 2026-07-18: this closure is deferred while the
source-independent Slice C integration feature is implemented. It no longer
blocks Slice C, but it must be resumed before Phase 2 is declared complete if
the symptom remains. Deferral does not authorize a speculative state fix or a
guessed production color transfer.

Second revision on 2026-07-18: production fog is now visibly active and the
fresh playtest captured consecutive frames where atmosphere bypassed because
the required world-color capture had not executed. The try-lock-only execution
and fog-calibration correction is specified in
`docs/graphics_fnv_atmosphere_phase2_reliability_calibration_plan.md`. That
focused plan supersedes work package 7A below. Blocking `.lock()` is not an
allowed render-path fix.

Do not treat the current MSAA/sample-mask, inherited-state, runtime-lock, or
native-HDR explanations as proven. The implementation must distinguish them
before selecting a fix.

## Current runtime evidence

The fresh `omv-latest.log` from the 2026-07-18 playtest proves:

- the atmosphere pipeline initialized without a D3D error;
- the world target was 3440x1440 `A16B16G16R16F`, render-target usage, with
  8x multisampling;
- reversed INTZ depth, camera projection and world transform, world-color
  capture, native fog, sky, exterior state, TAA alpha history, and the
  same-epoch above-water value were available together;
- the underwater publication hook installed and published `Some(false)` for
  the captured epoch;
- the log contains no atmosphere bypass, duplicate callback, device reset,
  resource failure, or draw failure during the reported reproduction.

The log does not prove that every render callback acquired the runtime lock,
that every debug draw reached the target, that inherited D3D coverage state was
safe, that the modified target remained the native image-space source, or that
native HDR presented the diagnostic RGB continuously. Those omissions are the
contract gap.

## Existing ground truth

The following Ghidra outputs remain authoritative:

- `analysis/ghidra/output/perf/graphics_fnv_atmosphere_phase2_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_atmosphere_phase2_contract_followup.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_atmosphere_underwater_epoch_publish_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_ao_state_capture_contract_audit.txt`;
- `analysis/ghidra/output/perf/graphics_fnv_image_space_pass_state_vtable_followup.txt`.

They prove:

- the post-world hook runs after the phase-1 world scene graph;
- TAA and atmosphere run before first-person and native image space;
- all supported Main callers pass the rendered world texture into the native
  image-space chain and force the caller destination for its last effect;
- native `ImageSpaceShader::PresetStages @ 0x00C04120` explicitly disables Z
  write, Z test, alpha blending, and alpha testing, and enables all RT0 color
  channels;
- native `ISHDRBLENDINSHADER` consumes source alpha, so production code must
  preserve it exactly;
- a D3D state block restores engine state after OMV, but does not establish a
  safe state before an OMV draw.

Static research cannot report the DXVK state inherited on the visually bad
frame or the pixel values presented after native HDR. Runtime evidence is
mandatory even after the additional audit below.

## 2026-07-18 blink audit result

The focused audit was run and closes the static ordering and target-global
questions for both supported Main paths:

- owner A calls the world path at `0x00870AE8`, first person at `0x00870B21`,
  and the outer image-space owner at `0x00870B89`;
- owner B calls the world path at `0x00870E18`, first person at `0x00870F74`,
  and the outer image-space owner at `0x008710E4`;
- `BSShaderManager::pCurrentRenderTarget @ 0x011F9438` has one writer, at
  `0x00872FDF` inside the rendered-target creator `0x00872F50`; its remaining
  references are reads in first-person rendering and `0x00B65C60`;
- the outer owner calls `0x00B55AC0` at `0x00876136`, and that function passes
  its source/destination values directly to `0x00B97900` before clearing the
  eight texture stages;
- native `ImageSpaceShader::PresetStages @ 0x00C04120` constructs exactly the
  state nodes 7/0, 14/0, 27/0, 15/0, and 168/15 for Z write, Z test, alpha
  blend, alpha test, and RT0 color-write ownership.

There is no static evidence that a supported Main path replaces the current
render-target global between OMV's post-world callback and native image space.
This makes a simple global-target replacement an unlikely explanation, but it
does not prove surface identity or contents on the bad frame. First person or
another pass can still overwrite pixels without writing that global.

The audit does not close the whole-program state-ID question. Its broad node-
builder scan stopped after 120 displayed matches out of 210 call references,
and its eight-instruction nearby-scalar heuristic can report unrelated
constants. Therefore the output proves only that native `PresetStages` omits
multisample enable/mask, vendor alpha-to-coverage, clip-plane, stencil,
scissor, and separate-alpha ownership. It does not prove those states are
disabled at runtime or absent from every native state builder.

The exact-immediate follow-up below was run to remove that display-cap and
nearby-scalar ambiguity without re-running the large boundary audit:

`analysis/ghidra/scripts/graphics_fnv_atmosphere_debug_blink_state_id_followup.py`

Expected output:

`analysis/ghidra/output/perf/graphics_fnv_atmosphere_debug_blink_state_id_followup.txt`

### State-ID follow-up result

The follow-up enumerated all 1,953 direct calls to the state-node builder. Its
mechanical summary classified 1,949 as an immediate state ID and four as
computed or unrecognized. Review of the four printed windows refines that
result:

- `0x00B8410F` pushes state 55 before loading `ECX`;
- `0x00BAC5E0` pushes state 15 before loading `ECX`;
- `0x00BB24E6` pushes state 52 before loading `ECX`;
- only `0x00B71A30` is genuinely dynamic, forwarding its caller-supplied state
  ID and value to the node builder.

The corrected census is therefore 1,952 constant-ID calls and one dynamic-ID
wrapper call. For the blink-relevant states, native node construction contains
17 constant stencil-enable nodes and eight constant clip-plane-enable nodes.
It contains no constant node for multisample antialias (161), multisample mask
(162), scissor test (174), `ADAPTIVETESS_Y` (181), or separate-alpha blending
(206). The previously captured `0x00B7A870` decompilation uses the dynamic
wrapper for color-write state 168; this follow-up does not enumerate every
caller of that wrapper.

This is sufficient for the current stage: native shader lists demonstrably do
not provide a universal full-screen baseline for the omitted states, while the
dynamic wrapper means whole-program absence must not be claimed. Neither fact
proves the value inherited by OMV on a blinking DXVK frame. Runtime snapshots
remain the decisive evidence, and no vendor/MSAA-specific fix may be selected
from this census alone.

## Unknowns to close

| Unknown | Required evidence |
|---|---|
| Did the render callback fail to acquire `RUNTIME`? | Atomic lock-miss counter outside the mutex, attributed to the current Present epoch. |
| Did world-color capture, depth reduction, or debug presentation skip? | One explicit outcome record for each stage and each Present. |
| Did the debug draw return success but inherit rejecting coverage state? | Before/bound/after state snapshots for the exact failing transition. |
| Did atmosphere modify a different surface from the first native image-space source? | Raw surface identity and description at post-world draw and outer image-space entry. |
| Did first-person or another engine pass overwrite the modified world surface? | Boundary sequence and surface identity, followed by a conditional canary/readback probe if identity alone is insufficient. |
| Did source alpha/native HDR suppress the visual diagnostic while the pre-HDR target remained correct? | Constant-color canaries with preserved versus diagnostic forced alpha, or bounded numeric readback before and after native image space. |
| Is the symptom only depth-edge instability rather than loss of the full-screen pass? | A constant canary that does not depend on depth, camera reconstruction, or scene RGB. |

## Non-goals

Do not include these changes in the closure stage:

- volumetric fog integration or production composition;
- directional volumetric lighting;
- shader noise, temporal atmosphere history, or ray jitter;
- disabling fog, lighting, TAA, MSAA, fences, foliage, or native HDR as the
  shipped fix;
- moving all atmosphere work to Present;
- changing PBR draw selection or shader packages;
- globally changing engine render state without capture/restore;
- retaining any engine render-target, water, camera, or shader pointer beyond
  its proven lifetime.

Temporary state overrides and alternate presentation phases are diagnostics
only until their contracts are proven.

## Root-cause decision table

| Evidence on a bad frame | Classification | Fix path |
|---|---|---|
| Runtime lock miss or callback absent | Scheduling/ownership failure | Work package 7A. |
| Capture or draw outcome is a bypass/error | Pipeline outcome failure | Work package 7A or the exact failing resource branch. |
| Draw succeeds, source identity matches, entry state differs and a rejecting state tracks the blink | Inherited D3D state | Work package 7B. |
| Draw succeeds but native image-space source identity differs | Render-target lineage failure | Work package 7C. |
| Identity matches but a later boundary overwrites the canary | Phase ownership failure | Work package 7C. |
| Pre-HDR canary is stable, preserved-alpha output blinks, and forced-alpha diagnostic is stable | Native HDR/alpha presentation | Work package 7D. |
| Constant canary is stable while depth modes shimmer locally | Depth reduction/reconstruction issue | Work package 7E. |
| More than one condition changes | Multiple contract failures | Fix and validate one proven failure at a time, starting with execution ownership. |

## Work package 1: focused Ghidra boundary/state audit

Add and run:

`analysis/ghidra/scripts/graphics_fnv_atmosphere_debug_blink_state_contract_audit.py`

Expected output:

`analysis/ghidra/output/perf/graphics_fnv_atmosphere_debug_blink_state_contract_audit.txt`

The audit must answer:

1. Which exact functions execute between the phase-1
   `RenderWorldSceneGraph @ 0x00873200` return, first-person rendering, and the
   outer image-space owner at `0x00875FD0`?
2. Does any supported Main path replace, copy, or rebind the rendered world
   color surface after the post-world hook and before native image space?
3. Which render-state-list functions are used by the world and native
   image-space paths?
4. Do native state builders explicitly mention
   `D3DRS_MULTISAMPLEANTIALIAS` (161), `D3DRS_MULTISAMPLEMASK` (162),
   `D3DRS_ADAPTIVETESS_Y` (181), clip planes, stencil, or scissor?
5. Which facts remain runtime-only under DXVK?

The script must decompile the two supported Main owners, world rendering,
first-person rendering, the image-space owner, the image-space manager, native
`PresetStages`, the generic shader render-state-list apply function, and the
render-state node builder. It must also print disassembly around the relevant
call sites and constant state-ID uses.

Stop condition: do not turn an absent static state write into proof that the
runtime state is disabled. Absence only increases the need for runtime
telemetry.

Status: complete. The boundary ordering, target-global, image-space forwarding,
`PresetStages`, exact constant-ID census, and dynamic-wrapper limitation are
recorded above. Proceed to runtime outcomes and state/lineage capture; further
static absence claims are neither justified nor required for that work.

## Work package 2: safe D3D9 diagnostic access

Extend `libpsycho/src/os/windows/directx9.rs`; do not call WinAPI or raw D3D9
methods directly from OMV.

Re-export the render-state constants needed by the recorder:

- alpha test enable/function/reference;
- stencil enable/function/reference/read mask/write mask and operations;
- scissor enable;
- clip-plane enable;
- fill and cull modes;
- Z enable/write/function;
- color and alpha blend enables, factors, operations, and separate-alpha
  enable;
- sRGB write;
- RT0 through RT3 color-write masks;
- multisample antialias and multisample mask;
- `ADAPTIVETESS_Y` for observation of vendor alpha-to-coverage state only.

Add safe wrappers for:

- `GetScissorRect`;
- existing viewport, render-state, render-target, and depth-stencil access are
  sufficient and should be reused;
- optional `GetRenderTargetData` plus a lockable 1x1/system-memory surface only
  if work package 6 reaches the numeric-readback gate.

The wrappers must return ordinary `Direct3DResult` values and own or borrow COM
references consistently with the existing module. No per-frame allocation is
allowed in the wrappers.

## Work package 3: explicit per-Present atmosphere outcomes

Replace boolean-only atmosphere accounting with a compact outcome model.

Use an enum equivalent to:

```text
Inactive
CallbackLockMiss
WorldColorNotRequested
WorldColorCaptured
DepthContractRejected(reason)
FoundationReduced
DebugPresented
DrawFailed(hresult/signature)
DuplicateInvocationSkipped
```

The concrete implementation may use counters plus a final enum, but it must
preserve these distinctions.

Record for each Present epoch:

- world scene callback count;
- runtime-lock misses for needs-depth, depth application, world-color needs,
  world-color capture, TAA, atmosphere, scene-pre image space, and frame finish;
- world depth capture epoch and projection epoch;
- world-color request/capture count;
- atmosphere callback, reduction, and debug-presentation counts;
- selected fog and lighting enable states and debug mode;
- the final outcome and exact bypass reason;
- first-person callback and outer image-space callback counts.

Lock-miss counters must live outside `RUNTIME`; otherwise the condition cannot
record itself. Use atomics and consume them at Present. Do not log from every
miss.

At `finish_present_frame`, emit:

- an immediate bounded warning for a requested debug view without exactly one
  successful presentation;
- a transition log when the outcome changes;
- a periodic aggregate summary while a diagnostic mode is active;
- no per-frame info log during normal play.

Do not silently label `atmosphere_called_this_frame` as success. Success means
the final debug quad returned successfully and all attachments/state were
restored.

## Work package 4: failing-frame D3D state recorder

Add a fixed-size `AtmosphereBoundarySnapshot`; it must not allocate on the
render path. Capture only while an atmosphere debug view is nonzero.

At minimum record:

- Present/depth epoch and debug mode;
- RT0 through RT3 raw identities and descriptions;
- depth-stencil identity and description;
- viewport and scissor rectangle;
- all states listed in work package 2;
- active pixel shader, vertex shader/FVF state if existing wrappers expose them
  safely;
- world-color copy identity and reduced-depth target identity;
- target size, format, usage, multisample type, and quality.

Capture three snapshots:

1. entry: immediately before OMV captures the all-state block;
2. bound: after `bind_pipeline_state` and `bind_target`, before the debug draw;
3. restored: after attachment and state-block restoration.

Logging rules:

- hash snapshots and log only changes;
- retain the most recent good and anomalous records;
- emit the full pair when a debug-present outcome changes or a canary is
  reported missing;
- cap detailed records per run;
- keep a compact aggregate count after the cap.

The bound snapshot is an internal assertion. It must prove that every state the
eventual binder claims to own actually has the requested value. The restored
snapshot must match entry for all observed engine-owned state and attachment
identities.

## Work package 5: render-target lineage and phase sequencing

Store value copies only:

- post-world RT0 raw identity and description;
- world-color copy identity;
- depth epoch;
- atmosphere debug output target identity;
- first-person completion epoch;
- outer `ProcessImageSpaceShaders` rendered-texture object value;
- the color surface resolved from that rendered texture;
- current RT0 at outer image-space entry.

At the outer image-space hook, compare the proven rendered-texture color
surface to the surface atmosphere modified. Log a mismatch as a first-class
contract failure. Pointer equality proves identity only; it does not prove that
the contents were not overwritten.

Record the event sequence for anomalous Presents:

```text
world return -> depth resolve -> TAA -> world-color copy -> atmosphere draw
-> first-person return -> outer image-space entry -> Present
```

If another world or image-space invocation occurs, include its call index and
surface identities. Keep the existing at-most-one atmosphere execution guard.

## Work package 6: presentation canaries and conditional readback

Add diagnostics that do not depend on depth reconstruction:

- constant-color canary with source alpha preserved;
- the same constant RGB with alpha forced to 1, explicitly labeled an unsafe
  diagnostic and never used by production fog;
- an outcome view that shows a distinct color only after depth reduction and
  target binding succeeded.

The ordinary modes 1 through 5 continue to preserve source alpha. Canary modes
must be excluded from saved production presets or clearly documented as
diagnostic.

Run the fence reproduction in this order:

1. constant RGB with preserved alpha;
2. constant RGB with forced diagnostic alpha;
3. nearest-depth view;
4. source-alpha view.

Interpretation:

- both canaries blink: execution, state rejection, overwrite, or lineage;
- preserved-alpha blinks but forced-alpha is stable: downstream alpha/HDR;
- both canaries are stable but depth view flickers locally: depth contract;
- log says `DebugPresented` while either canary shows reality: draw acceptance
  or downstream overwrite still needs proof.

Only if state/outcome/identity plus the canaries remain ambiguous, add bounded
numeric readback:

- resolve/copy one selected pixel from the post-atmosphere MSAA target;
- read the corresponding native image-space source at outer entry;
- optionally read final output after native image space;
- sample no more than a small diagnostic rate;
- disable readback outside an explicit debug mode;
- never stall every frame in normal play.

An alternate scene-pre re-presentation of the saved canary is permitted as a
temporary diagnostic. It must be labeled phase-unsafe and removed or kept
unreachable from production configuration after the cause is proven.

## Work package 7: evidence-selected fixes

### 7A: execution or lock ownership

Apply only if counters prove a missed callback, lock acquisition, capture, or
draw stage.

- keep every hook non-blocking and model `try_lock` failure as an explicit,
  recoverable outcome;
- move required world work into a focused owner with atomically published
  immutable settings so menu and final-pass work cannot contend with it;
- combine capture and atmosphere into one coherent transaction after one
  successful acquisition;
- leave a failed primary attempt pending for a proven pre-first-person retry;
- advance the Present epoch atomically even when `finish_present_frame` cannot
  acquire a runtime owner;
- preserve the at-most-one execution guard;
- never reuse a prior frame's world color, depth, or underwater classification
  after a missed stage.

The complete state model, retry rules, Reset behavior, and acceptance matrix
are owned by
`docs/graphics_fnv_atmosphere_phase2_reliability_calibration_plan.md`.

Acceptance: 10,000 diagnostic Presents report zero required-stage lock misses
and exactly one successful debug presentation whenever the effect is enabled.

### 7B: inherited D3D state

Apply only for states shown to differ on bad frames or required by proven
native/D3D semantics.

First patch the atmosphere binder alone so validation is isolated. Candidate
state ownership includes:

- solid fill and no culling;
- Z and stencil disabled, with depth-stencil detached for color-only targets;
- alpha test and all blending disabled, including separate alpha;
- scissor and clip planes disabled;
- RT0 color writes enabled and unused MRTs detached/disabled;
- explicit sRGB policy;
- full-target viewport;
- `MULTISAMPLEMASK = 0xFFFFFFFF` for an MSAA target;
- explicit multisample-antialias state consistent with the target;
- vendor alpha-to-coverage state only if runtime/static evidence identifies a
  supported disable contract.

Do not disable MSAA globally. Do not write unknown vendor FOURCC state from a
guess.

After the isolated fix passes, consolidate the proven common state into one
small OMV screen-pass binder used by atmosphere, AO, TAA, bloom, sunshafts,
DOF, and generic full-screen passes. Preserve effect-specific sampler and MRT
setup outside the common binder.

Acceptance: randomized inherited-state diagnostics produce identical
full-screen coverage and state/attachment restoration remains exact.

### 7C: render-target lineage or overwrite

Apply only if surface/event telemetry proves the post-world target is not the
stable native source or is overwritten before image space.

Keep world depth reduction and atmosphere integration at the post-world,
post-TAA boundary. If full-resolution presentation must move later:

- defer only composition/presentation to the proven outer scene-pre source;
- use the current-frame first-person mask so fog/debug output never affects
  weapons or other first-person pixels;
- require world integration, first-person mask, source surface, and Present
  epochs to match;
- bypass unchanged source color on any mismatch;
- leave UI and later overlays untouched.

This is a contract revision, not a convenience move. Update the Phase 2 plan
and Ghidra evidence if selected.

Acceptance: stable debug presentation with first-person and UI pixel identity
unchanged, including scopes, VATS, dialogue, and loading screens.

### 7D: native HDR/source-alpha presentation

Apply only if preserved versus forced-alpha canaries or readback prove it.

- production fog continues to copy source alpha exactly;
- select and document the actual pre-HDR RGB transfer/range;
- map diagnostic RGB so native HDR presents it predictably without changing
  production alpha;
- if necessary, present debug-only visualization after native HDR while
  keeping production composition at its proven world boundary;
- never solve diagnostic visibility by forcing production alpha.

Acceptance: source-alpha readback is bit-identical with fog off/on and every
diagnostic remains interpretable through native HDR.

### 7E: depth/reconstruction instability

Apply only if the constant canary is stable and the failure is local to depth
views.

- validate RESZ generation and reduced-depth write outcomes;
- compare nearest/farthest reduction against full-resolution depth at the
  selected pixel/block;
- preserve conservative intervals at alpha-tested geometry and silhouettes;
- fix axis/frustum reconstruction only from the world-height evidence;
- do not hide a depth error with blur or temporal accumulation.

Acceptance: fence, foliage, water, particles, sky, and silhouettes classify
continuously during subpixel camera motion.

## Work package 8: tests and build verification

Add focused tests for:

- outcome state-machine transitions and reason preservation;
- atomic lock-miss aggregation and Present-epoch reset;
- snapshot hashing/change detection;
- good/anomalous snapshot retention and log caps;
- surface-identity lineage comparisons;
- debug canary mode parsing and clamping;
- source alpha preservation in all ordinary atmosphere and TAA paths;
- shader compilation for every embedded atmosphere variant;
- common binder state tables if work package 7B is selected;
- resource release on reset/device replacement.

Run:

```text
cargo fmt --all -- --check
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
git diff --check
```

Always pass the explicit i686 target. Do not rely on `.cargo/config.toml`.

## Work package 9: runtime validation

### Diagnostic closure pass

Use the exact fence reproduction first. Capture:

- a short video showing good and blinking frames;
- fresh `omv-latest.log`;
- constant preserved-alpha canary;
- constant forced-alpha canary;
- nearest-depth and source-alpha views;
- TAA on and off;
- first- and third-person if the location permits.

The log must identify the bad frame without requiring visual guesswork.

### Fix confirmation pass

After the selected fix:

- repeat the fence camera positions and angles;
- walk, crouch, rotate, and cross the fence silhouette slowly and quickly;
- test exterior/interior, water surface/underwater, foliage, particles, sky,
  weapon, scope, VATS, menu, load, alt-tab, and device reset;
- verify modes 1 through 5 with TAA off/on;
- confirm no more than one atmosphere execution per Present;
- confirm no state/resource error or restored-state mismatch.

### Phase 2 final acceptance gate

Phase 2 may be declared complete only when:

- the root cause is named from captured evidence;
- the selected fix has no diagnostic-only dependency;
- every required debug view remains stable at the fence;
- source alpha and first-person/UI ownership remain intact;
- target transfer/range and depth coverage can again be evaluated reliably;
- the supported tests and release build pass.

## File-level change map

| File | Planned change |
|---|---|
| `analysis/ghidra/scripts/graphics_fnv_atmosphere_debug_blink_state_contract_audit.py` | New focused native boundary and state audit. |
| `analysis/ghidra/output/perf/graphics_fnv_atmosphere_debug_blink_state_contract_audit.txt` | User-generated authoritative audit output. |
| `analysis/ghidra/scripts/graphics_fnv_atmosphere_debug_blink_state_id_followup.py` | Exact immediate state-ID census for all node-builder calls; no display cap or nearby-scalar inference. |
| `analysis/ghidra/output/perf/graphics_fnv_atmosphere_debug_blink_state_id_followup.txt` | User-generated follow-up output. |
| `libpsycho/src/os/windows/directx9.rs` | Re-export missing state constants and add safe scissor/readback wrappers only as gated. |
| `omv/src/runtime.rs` | Per-Present outcomes, lock-miss aggregation, boundary snapshots, lineage comparison, anomaly logging, reset handling. |
| `omv/src/fnv_render.rs` | Boundary event publication and outer image-space/first-person sequencing values. |
| `omv/src/backend/fnv.rs` | Only value-copy surface/epoch helpers if runtime cannot obtain them through existing APIs. |
| `omv/src/backend/mod.rs` | Backend-neutral value types only if required by the runtime recorder. |
| `omv/src/effects/atmosphere.rs` | Draw outcomes, state snapshots, constant canaries, and the evidence-selected binder fix. |
| `omv/shaders/embedded/atmosphere_debug.hlsl` | Constant canaries and outcome diagnostics; preserve alpha in ordinary modes. |
| `omv/src/config.rs` | Extend debug-mode range/descriptions only; no production override. |
| `omv/config/omv.toml` | Document diagnostic modes and unsafe forced-alpha status. |
| `omv/README.md` | Document the diagnosed cause, fixed contract, and remaining Phase 2 gate. |
| `docs/graphics_fnv_volumetric_fog_phase2_implementation_plan.md` | Track this deferred closure and record evidence before final Phase 2 acceptance. |
| `docs/graphics_fnv_volumetric_fog_lighting_plan.md` | Update parent status only after the closure gate passes. |

Do not modify `psycho-engine-fixes-helper`; this is OMV/FNV renderer ownership.

## Performance and safety constraints

- Normal play performs no GPU readback and no per-frame info logging.
- Diagnostic snapshots use fixed-size values and bounded records.
- Atomics count lock misses; they do not carry engine pointers.
- No engine pointer is retained beyond the proven boundary lifetime.
- State-block and attachment restoration remain mandatory on every result path.
- The first error is preserved if draw and restore both fail.
- A failed diagnostic resource allocation disables that diagnostic and leaves
  the world image unchanged.
- No fix may globally disable MSAA, alpha-tested geometry, TAA, native HDR,
  fog, or lighting.

## Deferred implementation order and stop points

Resume this sequence after the active Slice C feature work, or earlier if the
blink prevents meaningful feature validation:

1. Record the completed boundary and exact state-ID audits.
2. Add safe D3D diagnostic access and per-Present outcome accounting.
3. Add state snapshots and surface/event lineage without changing rendering.
4. Add constant canaries; keep numeric readback gated.
5. Reproduce the fence blink once and classify it with the decision table.
6. Implement only the selected work package 7 fix.
7. Re-run the focused fence validation and all supported tests/builds.
8. Consolidate shared screen state only after the isolated fix is proven.
9. Complete the broader runtime matrix.
10. Mark this closure complete and clear the final Phase 2 acceptance gate.

If step 5 does not distinguish the cause, stop and add the bounded readback or
alternate presentation probe. Do not declare Phase 2 complete or treat
production presentation as validated while the diagnostic still blinks.

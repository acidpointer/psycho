# Atom first-person camera design

Status: the 2026-08-16 Atom-plus-OMV runtime exposed a graphics compatibility
defect in Atom's render-hook installation order. Atom installed the five shared
render callsites before OMV, so OMV became the outer wrapper. Atom consequently
restored its temporary camera before OMV's post-world depth, color, AO, motion,
and camera capture completed. Live OMV logs contain differing pre-alpha and
coherent-world camera positions inside the same transaction while reporting
every affected capability active and zero pipeline failures. Atom now arms the
render group at DeferredInit and installs it once from xNVSE's immediately
following MainGameLoop callback, after every DeferredInit listener. Atom is
therefore outermost around the complete graphics-owner chain without detecting
or modifying OMV. The correction is statically validated; an ordinary installed
visual test remains the runtime acceptance gate.

The current presentation correction extends world-camera motion with the same
render-only principle proven by third person: restrained gait roll/pitch is
applied to the world render, while every non-None authored action exclusively
owns weapon-relative motion. The close-up weapon camera no longer copies the
world gait because its separate projection magnifies that transform and FNV's
weapon graph already supplies locomotion. Positional world motion remains
sub-unit and has no fore/aft component.

## Implemented safe stage (2026-08-16)

Atom now implements the Stable Phase 2 wrapper:

- the complete `PlayerCharacter::UpdateCamera @ 0x0094AE40` entry is chained
  and sampled only after its live predecessor returns, covering all eleven
  native callers rather than one main-update branch;
- repeated UpdateCamera completions within one Atom Input frame are
  deduplicated before engine time or gait distance can advance twice;
- support-relative controller velocity comes from the closed native
  `0x00812B00 -> 0x00C6E300 -> 0x00458620` path in game units;
- PlayerMover's proven low direction nibble at `+0x94` independently admits
  gait; idle, stance, run, sneak, and auto-move state bits cannot turn
  persistent controller velocity into head bob by themselves;
- native controller states 0/1/2 drive grounded, jumping, and airborne motion;
- gait cadence derives from support-relative distance, is analytically filtered
  without frame-rate dependence, and cannot exceed 1.6 full strides per second;
- one-shot landing compression uses capped downward air velocity;
- grounded gait and landing publish one world head pose bounded to zero
  forward, 0.50 up, and 0.15 right game units;
- common world rotation is bounded to sub-degree gait roll/pitch; yaw remains
  zero and fore/aft near-wall parallax remains weapon-relative or absent;
- logical yaw/pitch deltas drive bounded analytic viewmodel inertia without
  changing input or the logical camera;
- the effective-projectile-count call at `0x00524413` publishes one event for
  each positive-count player invocation of the shared ranged-fire routine;
  the world listener converts it to a bounded pitch impulse which survives the
  native attack/recoil action, while multi-projectile loops remain one event;
- native `IsAiming` suppresses locomotion motion exactly and attenuates the
  relative weapon layer and shot listener to the configured precision fraction;
- every non-None `GetCurrentAnimAction` value immediately suppresses Atom's
  relative weapon layer; release fades over an analytic envelope while world
  locomotion continues through ordinary equip, fire, recoil, block, and reload
  animation;
- both main world callers publish a route/epoch token, all three
  RenderFirstPerson callers are wrapped, and the unclassified special route
  permanently passes through;
- DeferredInit only arms the five overlapping render callsites; xNVSE's first
  subsequent MainGameLoop installs the group after the complete synchronous
  DeferredInit listener walk, making Atom's scoped pose enclose compatible
  graphics predecessors regardless of plugin listener order;
- each world transaction snapshots the camera plus the native `Sky` and
  `Weather` roots, applies one posed local center to all three coordinate
  owners, recursively updates both finite scene graphs with FNV's native zeroed
  update contract, then restores their exact local/world transforms;
- OSGlobals' first-person camera world rotation/translation are snapshotted,
  rebased against the first-person player root when no existing owner has
  already zeroed that root, composed in the proven native column basis, and
  restored with the root after the caller-local live predecessor returns;
- MCM Extender owns `bEnabled`, `fCameraMotion`, `fWeaponMotion`,
  `fLandingMotion`, and `fAimMotion`; defaults are bounded and the entire
  feature is disabled by default pending playtest;
- menus, focus loss, VATS, TFC, POV transitions, disabled controls, furniture,
  knockout, ragdoll, death, scripted actions, cell changes, lifecycle resets,
  and an explicit external owner all fail closed to native presentation.
- xNVSE disabled-control ownership uses its published any-intersection mask
  predicate when the optional complete-mask interface slot is null, preserving
  one native ownership query per gate on the installed xNVSE layout.

The world pose is non-identity during ordinary grounded movement and contains
smooth vertical/lateral translation plus sub-degree roll/pitch. Its amplitude
uses the square of the analytic locomotion envelope, keeping low-speed
traversal restrained without changing distance-driven cadence. Rotation is
render-only and cannot add near-wall displacement. The separately projected
weapon camera receives no copy of the world pose and no procedural gait or
landing waveform. Atom adds only a tiny non-oscillating movement-weight offset
and critically damped look inertia there, without competing with FNV's
authored weapon graph.
Atom does not claim a general
collision-resolved displaced camera: the half-unit translation envelope is a
conservative inference and must be playtested against walls and low ceilings.
ADS publishes exact identity locomotion/landing motion while retaining only the
configured fraction of the camera-only shot response. `Camera Motion = 0`
prevents every world-camera write.

Source ownership is `atom/src/camera/`: `motion.rs` owns the pure generator,
`pose.rs` the native-basis composition, `state.rs` coherent publication and
the nonblocking single writer, `native.rs` engine contracts and exact restore,
`hooks.rs` the rollback-capable caller groups, and `config.rs` the MCM snapshot.
The top-level Atom config and `MCMExtUpdate` path publish settings. DeferredInit
arms first-person render admission, the first subsequent MainGameLoop installs
that group once, and lifecycle messages plus `OnFramePresent` invalidate
state/tokens.

Static and runtime evidence is recorded in
`analysis/radare2/output/perf/fnv_first_person_camera_contract.txt`. Focused
tests cover 30/60/120 Hz and uneven partitioning, a 1.6 Hz full-stride ceiling
under extreme native speed, a derived 6.7 game-unit/second steady-gait
translation-base velocity bounds,
stationary moving-support behavior, exact idle rejection despite deliberately
large residual controller velocity, landing monotonicity, exact ADS/zero-gain
boundaries, matrix axes, finite-sky recentering with exact graph restoration,
and million-unit viewmodel rebasing with unwind restoration. Static tests do
not establish final world render rotation, camera feel, or near-geometry image
correctness.

### Current OMV compatibility-correction evidence

The retained evidence excerpt is
`.reports/atom-omv-camera-chain-2026-08-16.txt`. Its source logs have SHA-256
`c282883c4df3f65fdf6e0b3c9101a0947f7b4a14992945bd0b6b1fb29b614ce1`
for Atom and
`7f07a8058c99d9a40daa8475add907264db16e91b4094efae566281c953883c1`
for OMV.

Proven runtime facts:

- Atom installed at `20:00:44.080Z` and captured the five vanilla render
  targets `0x00873200`/`0x00875110`;
- OMV installed the same caller-local world and first-person groups one second
  later at `20:00:45.060Z`, so the live chain was necessarily
  `engine -> OMV -> Atom -> native`;
- OMV reported presentation, image-space, world, first-person, pre-alpha,
  geometry, PBR selection/package/terrain, local-light, shadow, and every other
  deferred capability active;
- atmosphere and AO initialized and rendered, and the first retained
  reliability interval completed 505 pre-alpha, coherent-world, and
  first-person depth copies with zero busy, target, deadline, or failure count;
- at `20:01:46.165Z`, pre-alpha observed camera position
  `(-55617.27,-59550.54,13880.64)`, while the coherent-world capture for that
  same timestamp observed `(-55617.26,-59550.51,13880.62)`; a second moving
  pair at `20:01:46.615Z` disagreed in all three components as well.

The repository call graph closes causality. OMV performs pre-alpha work before
calling its captured world predecessor, then publishes coherent depth, camera,
world color, AO, and motion state after that predecessor returns. Atom's former
inner predecessor restored camera/Sky/Weather immediately before returning to
OMV. Thus one OMV transaction consumed rendered color/depth from Atom's posed
camera and post-world camera data from the restored pose. This is not an OMV
admission, shader-compilation, or depth-copy failure; it is an Atom scope error
which invalidates the shared reconstruction domain used by fog, lighting, AO,
shadows, TAA, motion blur, and related consumers.

The source evidence is `atom/src/camera/hooks.rs` for Atom's guard lifetime,
`omv/src/fnv_render.rs` for OMV's pre/predecessor/post order,
`libnvse/xnvse/nvse/nvse/Hooks_Gameplay.cpp` for DeferredInit/MainGameLoop and
OnFramePresent ownership, and `libnvse/xnvse/nvse/nvse/PluginManager.cpp` for
the synchronous listener iteration. Existing native caller/ABI evidence remains
in `analysis/radare2/output/perf/fnv_first_person_camera_contract.txt`; no new
executable assumption is introduced by this repository-local ordering fix.

The corrected lifecycle is proven by vendored xNVSE source. Its main-loop hook
at `0x0086B386` dispatches every DeferredInit listener synchronously once, then
dispatches MainGameLoop before returning to the engine; normal presentation is
the later `0x0087055E` callsite. Atom now only arms the render
group during its DeferredInit callback. A fixed atomic one-shot gate installs
the group from the first subsequent MainGameLoop callback and makes any later
callback a one-load no-op. The resulting chain is
`engine -> Atom -> OMV -> native`: Atom's world or viewmodel guard remains live
through OMV's complete pre/native/post work and restores exact native state
only after OMV returns. UpdateCamera, third-person, input, and Ballistics
installation remain at DeferredInit.

The implementation contains no OMV name, module inspection, OMV mutation,
shared-library camera policy, configuration change, thread, worker, TLS value,
file scan, or new import. It adds one zero-initialized byte-sized atomic gate
and a MainGameLoop match arm to Atom's already registered callback. This still
changes the final DLL's loader-visible code/data layout and therefore requires
the ordinary Proton/BaseObjectSwapper load-to-gameplay gate. Static proof can
establish call nesting and restoration; only the installed artifact can accept
the resulting PBR, atmosphere, lighting, AO, shadow, temporal, and camera
pixels.

The supported-target validation is green: all 99 Atom tests and all 701 OMV
tests pass through Wine staging 11.15; Atom Clippy passes for all targets with
dependencies excluded and warnings denied; workspace formatting passes; and
optimized explicit-target builds succeed for both Atom and OMV. The one-shot
gate tests prove that DeferredInit arming performs no installation, the first
post-Deferred activation invokes the installer exactly once, a failure is
terminal, and later callbacks cannot retry or mutate executable code.

The installed problem artifact is 6,802,785 bytes, SHA-256
`9408a1731e0952fe345ddac6d0073fe75cb4922030ebce5bbf36f3ff1c8ea171`;
its modification time precedes the retained Atom/OMV session. The corrected
worktree artifact is 6,814,297 bytes, SHA-256
`cc74f99695154109a59e85c10a8450bd7ec3cbf579379baf18f1bfaf4c54b3e0`.
Both retain the exact ordered 29 import descriptors and 320 imported symbols,
three named exports, PE32/i386 format, nine section roles, `0x2B04` import
directory, `0x8C` export directory, `0x574` IAT, `0x18` TLS directory, four
TLS callback roles plus null, zeroed eight-byte `.tls`, `0x1AD8` `.bss`, and
rounded image size `0x447000`. The correction changes `.text` from `0x2A68B0`
to `0x2A6970`, `.data` from `0x1F80` to `0x1F88`, `.rdata` from `0x1229D8`
to `0x122A18`, `.eh_fram` from `0x4F530` to `0x4F5B4`, and `.reloc` from
`0x2247C` to `0x224C0`. This is the complete current Atom worktree artifact,
including concurrent user changes; the exact small delta against the deployed
problem artifact is the relevant startup comparison.

### Prior presentation-quality correction evidence (historical)

All 15 public first-person behavior tests pass for explicit
`i686-pc-windows-gnu` through Wine staging 11.15. The six focused native
camera tests also pass, including the action-ownership, movement-gate,
finite-sky, origin-rebase, and exact-restoration contracts. Atom library and
first-person-test Clippy pass with dependencies excluded and warnings denied;
focused Rust formatting and `git diff --check` pass. The optimized Atom release
build succeeds.

The complete Atom run executes 93 tests: every first-person, input,
ballistics, MCM, and internal test passes, but two unrelated concurrent
third-person movement assertions fail in
`atom/tests/third_person_camera_behavior.rs` at lines 109 and 177. They compare
native direction-bit outputs in code outside this first-person change. This
document does not misreport the aggregate suite as green or modify that work.

The built worktree artifact is 6,801,120 bytes with SHA-256
`2df81cf6a0bb71cc455c090b3ef93b37b96f9b2cac10ed5052308e377816256f`.
It includes concurrent third-person and other user changes, so neither its hash
nor size delta is attributed solely to first-person presentation. This
correction adds no configuration field, import, export, TLS owner/data, static
lazy owner, thread, worker, file scan, allocation, lock, I/O, or render-time
native query. It removes the obsolete `0x008A8870` fingerprint/call and uses
the action value already sampled after UpdateCamera. The final DLL footprint
still requires the repository's ordinary load-to-gameplay startup acceptance.

### Prior idle-gait candidate evidence (historical)

The idle-gait candidate passes all 89 Atom tests for explicit
`i686-pc-windows-gnu` through Wine staging 11.15. This includes 13 public
first-person behavior tests and five native first-person contract/transaction
tests. Atom-only Clippy passes for all targets with warnings denied, the four
affected Rust files pass a direct rustfmt check, `git diff --check` passes, and
the optimized Atom release build succeeds. Workspace-wide `cargo fmt --check`
continues to report only a pre-existing unrelated import-wrap difference in
`omv/src/effects/shadows/contract_tests.rs`; this change does not rewrite it.

The candidate `atom.dll` is 6,801,468 bytes with SHA-256
`513d650da54702933c5b0e48d52c47c292c7fd0994bc028d2bdd3d90fbbfe156`.
Against the runtime-rejected installed `445831fa...` DLL, it preserves the
exact 29 import descriptors and 320 ordered imported symbols, three named
exports, PE32/i386 and large-address-aware/ASLR/NX characteristics, nine
section roles, import/export/TLS directory sizes `0x2B04/0x8C/0x18`, IAT size
`0x574`, four TLS callbacks plus null, and eight zero `.tls` bytes. `.text`
changes from `0x2A4E30` to `0x2A50B0`, `.data` from `0x1EC0` to `0x1E90`,
`.rdata` from `0x122608` to `0x1226D8`, `.eh_fram` from `0x4F3D8` to
`0x4F3B4`, `.bss` from `0x1B78` to `0x1B80`, and `.reloc` from `0x22334`
to `0x22328`; rounded image size changes from `0x445000` to `0x446000`.

The new work adds fixed deferred fingerprints, one rejection counter slot, and
hot-path code only. It adds no configuration field, import, export, TLS
callback/data, static lazy owner, thread, worker, file scan, or operation
before DeferredInit. The code/data layout is nevertheless loader-visible and
requires the ordinary Proton/BaseObjectSwapper load-to-gameplay acceptance;
the exact idle visual result also remains a runtime gate.

### Earlier combined-stage evidence (historical)

The 2026-08-16 combined Atom worktree passes all 62 tests under Wine staging
11.15 for `i686-pc-windows-gnu`. Those include seven public first-person
behavior tests, nine private first-person camera policy/math/state/restore
tests, and current concurrent Ballistics adapter tests. Atom-only Clippy passes
for all targets with dependency warnings excluded and Atom warnings denied.
Focused formatting for the affected camera modules, the Atom release build,
and the complete supported five-package release build also pass.

The resulting complete-build `atom.dll` is 6,718,469 bytes with SHA-256
`796f6f94b6b46efe30d8c1f421d0b191694b41a453bae6f87b0c88fd354136db`.
It remains PE32/i386, large-address-aware, ASLR/NX compatible, and retains the
same nine section roles, 29 import descriptors, and DLL-name sequence as the
pre-camera artifact. Its eight-byte `.tls` section and `0x18` TLS directory are
unchanged. The complete artifact has 320 imported symbols rather than 316, an
import directory of `0x2B04` rather than `0x2AB8`, and three exports rather
than two because it adds `AtomCamera_SetExternalOwner`.

Compared with the recorded pre-camera artifact SHA-256 `1371353b...`, the
combined DLL is 211,456 bytes larger. `.text` grows from `0x2822D0` to
`0x29B730`, `.data` from `0x1848` to `0x1BB0`, and `.rdata` from `0x11E7B8`
to `0x120CE8`; `.bss` shrinks from `0x276F8` to `0x1908` because the same
worktree also contains the separately documented deferred Ballistics-pool and
adapter work. The artifact additionally contains concurrent third-person work,
so these whole-DLL deltas must not be attributed solely to first-person code.
They are nevertheless the actual loader-visible candidate footprint.

The immediate accepted startup baseline is `141f6947...`, which the user's
15:25 UTC run took through successful Atom initialization and normal gameplay.
Relative to that DLL, the current artifact is 12,761 bytes smaller. Import
descriptors, all 320 imported symbols, the `0x2B04` import directory, three
exports, nine section roles, the `0x18` TLS directory, and the eight-byte TLS
section are unchanged. `.text` decreases from `0x29BE30` to `0x29B730`,
`.data` from `0x1BD0` to `0x1BB0`, `.rdata` from `0x120F08` to `0x120CE8`,
and `.reloc` from `0x2169C` to `0x215FC`; `.eh_fram` increases from `0x4EA94`
to `0x4EAA4`, while `.bss` remains `0x1908` and rounded image size remains
`0x438000`. The delta removes caller fingerprints and their error path; it adds
the input-side stable InterfaceManager read but no static owner or earlier
operation. The layout change is nevertheless a new pre-Deferred footprint and
requires another Proton/BaseObjectSwapper replay.

The predecessor `205df8...` artifact reached `DeferredInit` but rejected the
camera systems because it required xNVSE's null optional complete-mask slot.
Vendored xNVSE source proves its three-entry interface initializer publishes
the equivalent any-intersection mask predicate, which this replacement uses
as a one-call fallback. The next `6f6c2a...` artifact reached the first-person
native contract and exposed the mutable shared `MenuMode` entry described
below. Artifact `141f6947...` used the proven InterfaceManager fields, reached
gameplay, and then exposed the redundant caller-context gate described below.
The current artifact additionally uses the proven direct-call capability.
The import/export and code/data deltas remain material before `DeferredInit`
even though all camera pointer reads and hooks remain deferred. Static
validation therefore does not establish startup compatibility; the exact DLL
above still requires the Proton/BaseObjectSwapper load-to-gameplay acceptance.

The `141f6947...` runtime accepted its startup footprint and reached gameplay,
but exposed one more over-strict admission rule: the live caller setup at
`0x00870B10` differed before the `0x00870B21` RenderFirstPerson call. During
the same process, OMV admitted all three identical direct callsites and executed
8,476 first-person depth stages without a scene-transaction failure. Atom now
uses that already-proven capability contract. Each site must remain a direct
`E8` call to an executable live predecessor, which is captured and chained
transactionally; the wrapper forwards every argument unchanged. Surrounding
caller encodings are not Atom-owned invariants. The exact evidence and failure
boundaries are recorded in section 14 of the first-person camera ledger.

## Intended result

Atom will provide an ESP-less first-person camera wrapper for a deliberate,
grounded survival-shooter feel. It will make locomotion readable through
subtle gait motion, give landings and changes of momentum physical weight, and
let the hands and weapon lag and settle without delaying the player's look or
changing native combat rules.

The target is not a constantly shaking action camera. The desired result is a
stable view with restrained body cues:

- mouse and stick look remain immediate;
- walking, running, sneaking, jumping, and landing have distinct motion;
- aiming down sights becomes more stable, not less;
- the weapon can carry more motion than the world view;
- every additive layer is bounded, time-based, and returns exactly to neutral;
- zero intensity is byte-for-byte native camera behavior;
- VATS, free camera, menus, scripted cameras, death, and transitions retain
  native ownership.

This document specifies the complete target architecture, motion model,
compatibility rules, implementation sequence, and acceptance tests. The status
section above distinguishes static proof from the remaining live acceptance.

## Executive decision

Atom must separate three poses instead of treating the animated head, aim, and
weapon as one camera:

| Pose | Owner | Purpose |
|---|---|---|
| Control pose | FNV and Atom Input | Logical look, crosshair, activation, aiming, and combat direction. |
| World presentation pose | Atom camera wrapper | Small render-only body motion applied around the world draw. |
| Viewmodel pose | Native setup plus Atom | Native weapon animation plus bounded inertia after native iron-sight setup. |

The native control pose is never smoothed. Atom samples the completed native
camera and adds a short-lived presentation transform only while the renderer
consumes it. The exact native transform is restored before the wrapped call
returns. Hands and weapons retain FNV's native projection and animation, then
receive an independently tuned inertia transform only while Atom owns
weapon-relative presentation.

This is the central safety property:

```text
direct input -> native logical camera -> gameplay consumers
                         |
                         +---- immutable motion frame -----+
                                                         |
render world:      snapshot -> add world pose -> draw -> restore
                                                         |
render viewmodel:  native ADS setup -> add weapon pose -> draw -> restore
```

Atom will not parent the world view directly to a head bone, filter relative
mouse counts, modify the common `UpdateCamera` output as its presentation
mechanism, or move the reticle/UI with head bob.

## Scope and non-goals

The first implementation owns:

- locomotion gait motion;
- landing and bounded movement impulses;
- a bounded player-shot presentation impulse sourced from positive-count native
  ranged fire;
- viewmodel look inertia and settle;
- state-dependent attenuation for hip fire, iron sights, scopes, and menus;
- accessibility controls and exact pass-through;
- a small internal impulse interface for later Atom combat modules.

It does not initially own:

- visible first-person body rendering;
- skeleton replacement or animation authoring;
- gameplay recoil, spread, projectile direction, or weapon balance;
- camera collision replacement;
- dynamic FOV kick, motion blur, or post-processing;
- third-person behavior, which remains covered by
  [the third-person plan](atom_third_person_camera_plan.md);
- VATS, kill cameras, dialogue cameras, free camera, furniture, knockout, or
  death presentation;
- compatibility decisions based on DLL, ESP, or animation-pack names.

Visible-body systems may coexist if their live hooks and native state can be
chained. Atom does not need a visible body to deliver the camera and viewmodel
behavior described here.

## Evidence and confidence

All fixed-address claims refer only to Fallout: New Vegas 1.4.0.525:

| Property | Value |
|---|---|
| Executable | `fnv_reverse/FalloutNV.exe` |
| Format | PE32 x86, image base `0x00400000`, non-PIC |
| Size | 16,084,808 bytes |
| Timestamp | `0x4E0D50ED` |
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |
| Primary tool | radare2 MCP, analysis level 2 |

The direct address evidence is preserved in
[the first-person camera ledger](../analysis/radare2/output/perf/fnv_first_person_camera_contract.txt).
Input ownership is already established by
[the actor input contract](fnv_actor_input_contract.md) and
[Atom Input](atom_input_wrapper_design.md). OMV's camera and draw-stage facts
remain owned by [the OMV plan](omv-plan.md) and
[the motion-blur contract](graphics_fnv_motion_blur.md).

Confidence terms in this document are:

- **Proven:** direct supported-executable disassembly or repository-owned
  layout/source establishes the fact.
- **Derived:** the conclusion follows mechanically from proven observations.
- **Corroborated:** read-only third-party source demonstrates the same seam or
  failure mode but is not proof of vanilla behavior.
- **Design:** Atom's selected behavior.
- **Playtest:** evidence that only the user's Proton runtime can establish.

## What FNV actually renders

### Logical camera construction

The normal player update calls the player camera/input helper, then reaches
`PlayerCharacter::UpdateCamera @ 0x0094AE40` through one of three branch-local
calls, and only afterward continues to movement, attack, activation, and other
gameplay consumers. Eight additional native calls use the same function for
camera transitions, loading/cell work, screenshot rendering, and control-state
maintenance.

In normal first person, UpdateCamera consumes the world rotation and
translation of `Camera1st @ 0x011E07D0`, applies native first-person settings,
and joins the shared final camera path. The shared path writes local translation
and rotation and updates the selected logical camera.

That ordering rejects a tempting hook: modifying the common camera commit at
`0x0094BDC2` or `0x0094BDD5` is not proven presentation-only. Its result is
live before later gameplay work. Atom may wrap the UpdateCamera call to sample
state after the predecessor returns, but it must not write its head bob there.

### World rendering

The persistent World SceneGraph is `*(SceneGraph**)0x011DEB7C`; its camera is
obtained through `SceneGraph +0xAC`. The two supported main world calls are:

| Callsite | Target |
|---:|---:|
| `0x00870AE8` | `RenderWorldSceneGraph @ 0x00873200` |
| `0x00870E18` | `RenderWorldSceneGraph @ 0x00873200` |

The renderer consumes the camera's world rotation at `+0x68` and world
translation at `+0x8C`. Native preparation `0x00872B00`, however, has already
copied the camera's local translation at `+0x58` into the roots stored at
`0x011DEB34` and `0x011DEDA4`, then recursively updated both graphs through
`0x00A59C60`. Construction at `0x0086D9BB` and `0x0086DA96` names those roots
`Sky` and `Weather`. Moving only the camera afterward leaves two finite scene
graphs at the old center, which the rejected runtime exposed as sky motion.

The direct world callsites remain the presentation boundary, but all three
coordinate owners form one transaction. Atom snapshots the camera world
transform and both roots' local/world transforms, composes the bounded pose
against both the camera world and local bases, writes the world camera, gives
Sky and Weather the posed local camera translation, and performs FNV's own
zero-time/false-flag graph update. After the live predecessor returns, it
restores both graphs recursively and reapplies the exact root snapshots before
restoring the camera. No posed transform survives the draw.

This leaves the logical/local camera pose untouched outside rendering and lets
native culling, the finite sky graphs, and OMV world stages observe one
presented center. Static analysis does not prove the resulting image, so the
maximum offset and visual coherence remain playtest gates.

### Separate hands and weapon camera

FNV has a second camera at `OSGlobals +0xA0`. Native setup at `0x00874C10`
builds it from `Camera1st`, writes world translation/rotation, and optionally
replaces its position with `PlayerCharacter +0xE34`, the iron-sight node.

Setup precedes each direct `RenderFirstPerson @ 0x00875110` call:

| Route | Setup | Render |
|---|---:|---:|
| Special A | `0x00870927` | `0x0087093D` |
| Main B | `0x00870AF8` | `0x00870B21` |
| Main C | `0x00870F33` | `0x00870F74` |

RenderFirstPerson gets `PlayerCharacter::Get3D(true)`, clears first-person
depth, and renders the first-person accumulator with `OSGlobals +0xA0`.
Wrapping the three direct render calls therefore runs after native iron-sight
placement and immediately before the camera is consumed.

Route A does not pass through either proven world call. Atom must hook it only
for caller-group integrity and pass through unless a matching world token was
published. It must not invent a world pose for an unclassified route.

## Product principles from current camera systems

Modern engine guidance is useful as design input, not FNV evidence.

[Unity Cinemachine](https://docs.unity.cn/Packages/com.unity.cinemachine%402.2/manual/CinemachineOverview.html)
separates movement, aim, and procedural noise, and explicitly keeps additive
noise from feeding future follow state. Its
[impulse definition](https://docs.unity3d.com/ja/Packages/com.unity.cinemachine%402.6/api/Cinemachine.CinemachineImpulseDefinition.html)
separates an event source, time envelope, channel, and listener gain, while
[camera-local damping](https://docs.unity3d.com/ja/Packages/com.unity.cinemachine%402.6/api/Cinemachine.Cinemachine3rdPersonFollow.Damping.html)
is tuned independently per axis.
[Unreal Camera Shakes](https://dev.epicgames.com/documentation/en-us/unreal-engine/camera-shakes-in-unreal-engine)
uses composable wave, noise, and sequence patterns with per-axis amplitude,
frequency, blend timing, intensity, and camera-local play space.

Those systems converge on practices Atom should retain:

- deterministic locomotion and event impulses are different layers;
- every layer emits an additive, centered pose instead of changing the next
  frame's base pose;
- camera-local coordinates are explicit;
- sources and listeners allow the world camera and weapon camera to receive
  different gains from one event;
- a viewmodel-specific stage may add relative motion, but body/head motion
  shared by both views must remain common or the weapon floats against the
  scene;
- an authored sequence and procedural motion must not simultaneously own the
  same relative weapon degree of freedom;
- start/stop envelopes prevent discontinuities;
- tuning is in seconds, distance, degrees, and normalized gain, not fractions
  per frame;
- continuous random noise is not a substitute for meaningful movement events.

Valve's public
[Source SDK viewmodel code](https://github.com/ValveSoftware/source-sdk-2013/blob/master/src/game/client/c_baseviewmodel.cpp)
also keeps viewmodel rendering and viewmodel FOV/attachment conversion separate
from the world view. It is comparison evidence for a separate presentation
layer, not a contract Atom should copy literally.

## Camera ownership state machine

One state machine owns all world and viewmodel writes:

```text
Disabled / NativeOwned
        |
        | complete normal first-person update
        v
Candidate -- paired main world route --> Active
   ^                                      |
   |                                      | ownership loss
   +-------------- reset <---------------+
```

### NativeOwned

Atom performs no camera writes and clears phase, spring velocity, pending
impulses, look history, and render tokens. This is required when any of these
is true:

- camera feature or intensity is off;
- exact first-person state is not stable;
- player, process, controller, World SceneGraph, world camera, OSGlobals,
  first-person camera, or first-person 3D is missing;
- any VATS mode is nonzero;
- free camera, vanity camera, or another proven native camera owner is active;
- a blocking menu, Pip-Boy, dialogue camera, terminal, lockpick, loading screen,
  save/load transition, race menu, or console owns presentation;
- the player is dead, knocked out, ragdolled, in a kill camera, entering or
  leaving furniture, or under a scripted camera;
- a POV transition byte is active;
- the executable or required hook group failed validation.

Phase 0 must close the exact carriers for every gate above. A guessed field or
plugin-name blacklist is not acceptable.

The blocking-menu carrier is the side-effect-free native `MenuMode` policy:
InterfaceManager global `0x011D8A80` must be nonnull, its active byte at
`+0x00` must be nonzero, and its mode at `+0x0C` must differ from normal
gameplay mode 1. The `6f6c2a...` runtime proved that the shared helper entry at
`0x00702360` is no longer byte-identical by `DeferredInit`, while the on-disk
supported executable retains its vanilla prologue. Atom therefore validates
the global slot and reads the proven fields instead of fingerprinting or
calling that mutable entry. Private helper fingerprints remain strict; the
transparent callsites use the typed direct-call capability described below.
The direct evidence and inference boundary is recorded in the
[first-person camera ledger](../analysis/radare2/output/perf/fnv_first_person_camera_contract.txt).

The 2026-08-16 Proton summary exposed one incorrect ownership inference: Actor
`+0x0AC` is a persistent `bhkRagdollController` allocation, not an active
ragdoll flag. A normal live render was consequently rejected as ragdoll. The
hard render gate no longer reads that pointer. The post-UpdateCamera sample
already uses the process `GetKnockedState` virtual at `+0x40C`, alongside life
state `+0x108`, so actual knockdown/ragdoll and death remain native-owned.

### Candidate

After native ownership ends, Atom observes at least one complete normal
first-person UpdateCamera result. It seeds the base camera, position history,
look history, locomotion state, and all dampers from current native values with
zero additive output.

It becomes Active only when one of the two proven main world callsites consumes
that same coherent sample. This prevents stale state from a menu, load, VATS,
or special route from appearing on the first gameplay frame.

### Active

Atom may advance its motion generator once per accepted player update. The two
render wrappers may consume the resulting immutable frame, but never advance
it independently. Multiple render calls for one update see the same pose.

Any failed pointer check, non-finite value, epoch mismatch, unexpected nested
render, or ownership transition is immediate pass-through. Atom resets; it does
not ease a stale offset through a camera-owner boundary.

## Motion frame and modifier stack

One fixed-size `CameraMotionFrame` is published after native UpdateCamera:

```text
CameraMotionFrame
  epoch
  ownership and locomotion class
  native control pose
  world additive pose
  viewmodel additive pose
  aim and scope weights
  source diagnostics bitfield
```

The internal modifier order is deterministic:

1. stance and locomotion envelope;
2. gait waveform;
3. acceleration and landing springs;
4. combat/event impulses;
5. accessibility and state attenuation;
6. per-listener world/viewmodel gain;
7. final translation/rotation clamps and finite validation.

Each modifier returns zero-centered translation and rotation. No modifier
edits another modifier's state or uses the prior frame's final presented pose
as its new target. This prevents drift and positive feedback.

The world listener consumes the bounded head pose. The viewmodel listener
receives only its separate inertia pose with its own allowed axes and
gain. FNV remains the sole owner of close-up weapon locomotion. Authored actions
suppress Atom's weapon inertia; they do not manufacture an unnaturally motionless
world camera during ordinary movement.

## Locomotion inputs

Head bob must represent actual body movement, not keyboard intent.

The implemented gait contract uses both of these independent native signals:

1. character-controller horizontal velocity relative to its support supplies
   speed and distance;
2. grounded/jumping/in-air state supplies contact classification;
3. PlayerMover's low direction nibble supplies gait admission.

The coherent Atom Input frame supplies update identity and context, never
velocity or gait admission. Higher native flags such as walk, run, sneak,
swim, and auto-move do not admit gait without a low forward/back/strafe bit.

The supported executable already proves `Actor::GetCharController @
0x009306D0` and `bhkCharacterController::GetState @ 0x005C0880`. State values
0, 1, and 2 identify on-ground, jumping, and in-air operation. PlayerMover
virtual `+0x0C` stores the processed movement word at `PlayerMover +0x94`;
bits `0x01`, `0x02`, `0x04`, and `0x08` are forward, backward, left, and
right. Because normal UpdateCamera precedes the current frame's setter, Atom
observes the last completed native movement word, not an unfinished stack
local. That adds at most one native update of start/stop admission latency.

Support-relative velocity matters on elevators and moving surfaces. It remains
the magnitude source, but the user's idle runtime observation proves it is not
a sufficient activity predicate by itself. Requiring the processed native
direction nibble makes a stationary mover exact zero even when Havok retains a
horizontal residual. Requiring velocity as well avoids turning raw button
intent into cadence at the wrong analog magnitude. Integrating world position
would bob while a platform carries a stationary player. Animation-node
displacement is rejected because arbitrary skeletons and animation packs can
add noise or omit expected nodes.

If either native signal is unavailable, non-finite, unsupported, below the
speed threshold, or lacks a low direction bit, the gait target and cadence are
zero. The existing analytic stop envelope settles an already-active gait to
exact identity; a generator acquired while idle is exact identity immediately.

## Gait model

### Phase by distance, not wall clock

For accepted grounded relative horizontal speed `s` and mode-specific stride
length `L`, advance the full-stride phase by distance:

```text
distance = clamp(s * dt, 0, max_distance_step)
phase'   = wrap_tau(phase + tau * distance / L)
```

Distance phase keeps cadence consistent when speed changes and avoids a run
animation with walking-frequency bob. `L` is calibrated separately for walk,
run, and sneak against vanilla animation and representative kNVSE sets. A
locomotion-class change preserves phase but cross-fades frequency and gain.

Phase does not advance while speed is below threshold, unsupported, swimming,
flying, climbing, in a blocked action, or under native camera ownership. It may
be held briefly in air for landing continuity, but its output envelope decays
to zero.

Animation foot-contact events may later phase-correct the oscillator if Atom
can prove a capability-based, skeleton-independent event contract. They are
not required for the initial implementation.

### Centered waveform

A small harmonic rig gives two vertical events and one lateral weight shift per
full stride without random jitter:

```text
side     = sin(phase)
vertical = 0.75 * sin(2 * phase - pi/2)
         + 0.25 * sin(4 * phase + phase_bias)
fore     = sin(2 * phase + fore_bias)
roll     = -sin(phase + roll_bias)
pitch    = sin(2 * phase + pitch_bias)
```

Every component has zero mean. Translation is expressed in camera-local right,
forward, and up axes. Rotation uses a small-angle matrix or quaternion and is
composed once after all layers. The exact axis signs and multiplication order
must be verified against FNV matrices in Phase 0.

The envelope is driven by actual speed and stance, with a smooth start/stop
response. It reaches zero monotonically; it never snaps phase to a waveform
zero and never accumulates an offset into the native pose.

### Conservative calibration envelope

These are starting playtest bands, not approved shipped defaults:

| Component | World listener | Viewmodel listener |
|---|---:|---:|
| Vertical gait | `0.15-0.45%` eye height | native only |
| Lateral gait | `0.05-0.20%` eye height | native only |
| Fore/aft gait | zero | native only |
| Roll | at most `0.37 deg` | look inertia only |
| Pitch | at most `0.46 deg` | look inertia only |
| Yaw | zero | look inertia only |

Eye height is measured from a stable native first-person pose rather than a
hard-coded game-unit assumption. All final values require FOV, weapon,
animation, clipping, and comfort playtests at 30, 60, 120, and unstable FPS.

The current normalized implementation uses world-head coefficients `0.24` up
and `0.08` right, reduced from the rejected `0.32/0.12` candidate. Atom adds no
weapon-relative cadence because the native weapon graph already owns it.
`Weapon Motion` scales a tiny movement-weight offset plus critically damped
look inertia. These are game-unit
presentation coefficients, not claims about biological eye displacement. The
separate world/viewmodel composition is code-backed; only live play can accept
its subjective feel.

The current common head layer uses the same restrained render-only roll/pitch
principle accepted for third person. `Head Motion` scales translation and
rotation together, retains exact zero as native behavior, and never adds yaw or
dynamic FOV. This requested immersive policy supersedes the earlier
translation-only Stable proposal; final comfort and reticle behavior remain a
Proton playtest gate.

## Landing and movement impulses

Landing is an event, not a new periodic waveform. Atom records capped vertical
velocity while the controller is jumping or in air. A transition to on-ground
emits one impulse whose strength is a monotonic, saturating function of downward
speed above a dead zone.

The response has three parts:

- a short downward compression;
- a smaller upward recovery;
- a critically damped settle with no repeated bounce.

Ordinary step-downs should be almost invisible. Hard landings may move the
viewmodel more and the world view less. Fall-damage gameplay remains native;
the camera reads the event and does not alter velocity, fall height, damage,
animation, or sound.

Horizontal acceleration and sudden stops may feed a slower viewmodel-only
spring. World fore/aft acceleration is initially zero because it increases
wall clipping and reticle parallax for little information gain.

Unity's event-source/listener separation is the useful model: one `Landing`
source carries normalized strength, while the world and viewmodel listeners
choose different axes, gain, attack, and decay. Later Atom explosions or
suppression effects can use different channels without being mixed into the
gait oscillator.

## Viewmodel inertia

Viewmodel inertia is presentation lag, not input lag. Atom Input's direct
heading is applied normally. The weapon camera receives a bounded offset
derived from look angular velocity and acceleration:

```text
look delta -> angular rate -> bounded inertia target -> analytic spring
```

The target opposes a fast turn so the weapon trails, then settles. It never
feeds back into control yaw/pitch and never modifies input sensitivity. A
small dead zone suppresses mouse noise; a hard angular clamp prevents violent
motion from frame spikes or externally forced camera cuts.

Recommended axis policy:

- yaw look drives mostly weapon yaw plus small lateral translation;
- pitch look drives mostly weapon pitch plus small vertical translation;
- roll is derived sparingly from yaw acceleration;
- locomotion and landing add to the same viewmodel listener before one clamp;
- no independent random idle noise is enabled by default.

The native first-person camera has already been positioned for iron sights
when Atom's wrapper runs. Atom composes around that result and restores it
after the chained render call. It never writes `Camera1st`, the iron-sight node,
the player root, weapon nodes, or skeleton correction nodes.

## Aiming, scopes, and precision

The more precise the action, the less world motion Atom should add:

| State | World gait | Viewmodel gait | Look inertia | Landing |
|---|---:|---:|---:|---:|
| Hip fire | low | native | normal | normal |
| Iron sights transition | zero | native | fade down | zero |
| Iron sights held | zero | native | configured fraction | zero |
| Magnified scope | zero | native | configured fraction | zero |
| Melee/unarmed | low | native | low | normal |
| Reload/equip | low | native | zero | normal |

The aim weight follows proven native aiming state with a time-based blend. It
does not infer aim solely from the right mouse button. The world listener
switches to exact identity on the first aiming sample; leaving aim fades
ordinary motion back through the same analytic envelope. Native setup and
Smooth True Iron Sights remain authoritative for the base camera.

Weapon animation is already authored motion. During reload, equip, jam,
throwable, attack, recoil, block, and scripted sequences, Atom's relative
viewmodel pose is zero instead of double-animating the hands. FNV's
`GetCurrentAnimAction` returns `-1` only for None; every other known or unknown
value therefore fails closed to native relative animation. Entry is exact on
the first sample. After the native action returns to None, Atom releases its
suppression with a 12/s analytic envelope so procedural motion cannot pop back
on the clip boundary. World-camera head motion continues during ordinary
authored weapon actions without being copied into the weapon projection.

## Survival-state feedback

Hardcore atmosphere should come from meaningful state, not stronger shake.
Later profiles may scale restrained viewmodel breathing or settle from proven
runtime actor state such as exertion, limb condition, or weapon handling. They
must obey these constraints:

- no persistent world-camera drift;
- no random reticle displacement presented as weapon accuracy;
- no reading or parsing configuration per frame;
- no polling broad actor-value sets in the render hook;
- no new gameplay penalties in the camera module;
- no nausea-inducing low-frequency roll by default.

Breathing belongs primarily on the viewmodel listener. World-camera breathing
starts at zero and requires explicit opt-in. The Ballistics observer publishes
a pointer-free logical player-shot event from the shared ranged-fire routine.
Camera presentation adds a secondary kick, but native combat remains the owner
of actual aim, projectile behavior, and weapon animation.

## Time and numerical behavior

All temporal values are in seconds. Fixed interpolation fractions such as
`x += (target - x) * 0.1` are prohibited because response changes with frame
rate.

Continuous envelopes and inertia use an analytic critically damped spring. For
position `x`, velocity `v`, target `t`, angular rate `w`, and step `dt`:

```text
e  = x - t
c  = v + w * e
q  = exp(-w * dt)
x' = t + (e + c * dt) * q
v' = (v - w * c * dt) * q
```

Rules:

- clamp negative, non-finite, and implausibly large `dt`;
- split a large but valid update only where event detection needs it;
- reset instead of integrating across pause, load, teleport, cell transition,
  ownership change, or a large native camera cut;
- wrap angles before differencing;
- accumulate gait phase in bounded double precision, publish floats;
- validate every final scalar and matrix before writing native memory;
- one invalid source disables that frame and records only a rate-limited,
  out-of-hot-path diagnostic.

## Aim truth, parallax, and clipping

Presentation-only world motion has a real tradeoff: moving the rendered camera
without moving the logical activation/shot ray changes parallax; rotating it
also changes the screen-center direction. Calling the transform "visual" does
not make that mismatch disappear.

Atom's current policy remains conservative:

1. bound world rotation to sub-degree roll/pitch and allow no yaw;
2. suppress the complete world pose exactly while aiming;
3. clamp hip-fire translation to zero forward, 0.50 up, and 0.15 right units;
4. leave the reticle and UI fixed;
5. leave native weapon gait intact and add only bounded weapon inertia;
6. require reticle, activation, projectile, clipping, and comfort playtests for
   the final render behavior;
7. make zero camera intensity exact native behavior regardless of weapon
   intensity.

Fresh executable research closes why Atom cannot reuse the native chase-camera
cast as a generic clearance predicate. `0x00620BC0` has one caller at
`0x0094A344`, requires a result object constructed by `0x00621C40`, performs
camera-specific Havok filtering, and mutates both the desired endpoint and the
result. Its enclosing `0x0094A0C0` owner also changes chase-distance globals.
Calling that transaction from first-person update or render code would assume
unproven ownership and add collision work to a hot path.

Atom instead admits only the sub-unit Stable envelope above. This is not a
general collision-resolved camera. The claim that at most half a game unit of
translation remains inside normal first-person clearance is explicitly a
reasoned inference. Near-wall and low-ceiling runtime tests remain mandatory.
The full disassembly-derived boundary is in
`analysis/radare2/output/perf/fnv_first_person_camera_contract.txt`, section 16.

Required runtime assertions for world motion are:

- ADS center-ray impact is unchanged with motion on/off;
- activation selects the same reference at the same distance;
- no near-plane or wall crossing occurs at maximum amplitude;
- culling follows the presented pose without edge popping;
- camera snapshots restore exactly even when a chained predecessor returns
  early or fails internally.

## Hook and transaction design

### Coherent sample hook

Wrap the complete UpdateCamera entry at `0x0094AE40`. Eleven proven native
callers converge there, including branch-local calls at `0x0093FA08`,
`0x0094014A`, and `0x00943825` in the main PlayerCharacter update. The wrapper
calls one live entry trampoline with ECX and both stack arguments unchanged,
then samples native camera and locomotion state only after the predecessor
returns through its sole `ret 8` epilogue. It writes no camera transform.

The mutable entry bytes are a chainable capability and are not required to be
vanilla. Immutable receiver-store, logical-angle-store, and epilogue bytes
prove the supported function body and ABI. This admits compatible earlier
entry owners while still rejecting an incompatible executable body.

This hook consumes Atom Input's already-published gameplay-context frame and
samples the native logical yaw/pitch committed by UpdateCamera. Exact axis
closure maps adjusted horizontal heading to `0x011E076C` and raw Actor
`rotX`/pitch to `0x011E0764`; the native Z- and X-matrix consumers independently
prove that order. The same sample reads PlayerMover `+0x94` once and admits
gait only when its low direction nibble is nonzero. Only the first accepted
completion for a given input `frame_id` advances engine time and gait distance.
Duplicate transition or maintenance calls invalidate a pending render pair but
preserve the current immutable pose. A reset generation or cell change
bypasses deduplication so ownership reacquires immediately. Atom does not hook
its own mouse hook, repoll a device, or create a second action snapshot.

### World callsite group

Wrap both direct RenderWorldSceneGraph calls at `0x00870AE8` and `0x00870E18`.
Each callsite owns its own captured predecessor because another plugin can
redirect the two sites independently.

For exact world phase and an admitted first-person motion frame:

1. resolve the persistent World SceneGraph camera;
2. resolve the `Sky` and `Weather` roots and snapshot both local/world
   transforms before any write;
3. snapshot the camera world transform and read its local transform;
4. compose the same clamped local offset into the world camera and the local
   center used by the two finite graphs;
5. update Sky and Weather through the fingerprinted native `0x00A59C60`
   helper with the same zeroed `NiUpdateData` used by `0x00872B00`;
6. publish a render token and call that callsite's live predecessor;
7. recursively restore both graphs, reapply their exact root snapshots, and
   restore the exact camera snapshot on every unwind path;
8. retain the token only for the immediate paired first-person deadline.

A recursive or unexpected world call is pass-through. No allocation, lock,
file I/O, configuration parse, logging, collision query, or state advancement
belongs in this wrapper.

### First-person callsite group

Wrap all three RenderFirstPerson calls at `0x0087093D`, `0x00870B21`, and
`0x00870F74`, again with one predecessor per callsite.

The wrapper consumes a token only when its update epoch, route, camera mode,
and native pointers match. It snapshots OSGlobals +0xA0 plus the first-person
player root returned by `PlayerCharacter::Get3D(true)`. If another compatible
owner has already set both root translations to exact zero, Atom preserves
that ownership and composes against the existing origin-relative camera. If
not, Atom subtracts the root world origin from the camera, zeroes the root's
local/world translations, updates the graph, and composes the viewmodel pose in
that small coordinate frame. The live predecessor renders before native
`0x00875956` updates the root. Atom then restores the root recursively and the
camera exactly. The special A route has no paired world token and remains
native pass-through.

The token is invalidated on consumption, Present, configuration publication,
device/reset lifecycle, or any ownership loss. More than one render may reuse
the latest immutable update pose, but every world call publishes a fresh token
which only its immediate route-matched RenderFirstPerson call can consume. A
stale token never crosses a presented frame.

### Installation and rollback

The complete camera group is preflighted before the first write. The
UpdateCamera entry wrapper relocates its live complete instructions into a
typed trampoline. Each render wrapper accepts a valid direct `E8` call to any
callable current target and captures that caller-local predecessor. Neither
capability requires a mutable target to remain at its vanilla bytes or address.

On a validation failure:

- the incomplete group rolls back its own writes;
- the camera feature remains exact pass-through;
- Atom Input and unrelated Atom systems remain available;
- diagnostics name the unavailable capability and consequence;
- no hook is installed from `NVSEPlugin_Load`.

Native validation, configuration publication, and every non-overlapping hook
installation occur at xNVSE `DeferredInit`. The five shared world/first-person
render calls are armed there and installed once at the first subsequent
MainGameLoop, the proven quiescent point after all DeferredInit listeners and
before the frame renderer. Before changing either phase, the contributor must
read [the startup phase safety contract](nvse_startup_phase_safety.md), identify
the last load-to-gameplay-playtested Atom artifact, and compare the complete
pre-Deferred footprint. New static ownership or configuration fields can
change that footprint even when camera code executes later.

## OMV integration

OMV already wraps the same two world and three first-person CALL sites in
`omv/src/fnv_render.rs`. It uses caller-local live predecessors, performs world
effects inside the world call, and captures first-person depth inside the later
first-person call.

Atom must preserve that chain in either load order. Because DeferredInit
listener order determines which plugin would otherwise be outermost, Atom does
not install these five wrappers inside its own DeferredInit listener. It waits
for the immediately following MainGameLoop boundary and captures the complete
deferred chain as its caller-local predecessor:

```text
callsite -> Atom pose scope -> graphics predecessor -> native renderer
```

Atom's world pose must be active while OMV and native world rendering consume
the camera, then restored. Its viewmodel pose must be active while OMV and
native first-person rendering consume the separate camera, then restored.
Atom does not change OMV history, frustum jitter, depth ownership, render
targets, or image-space camera selection.

The two plugins touch different camera concerns, but runtime validation is
still mandatory:

- TAA history must see a coherent presented pose rather than alternating base
  and offset poses;
- motion blur must not interpret normal head bob as an unbounded camera cut;
- first-person depth must match the posed hands/weapon;
- camera fields and D3D state must restore in both load orders;
- missing OMV must not alter Atom behavior.

No Atom camera implementation should edit OMV as a shortcut. If a shared
camera publication ABI later becomes necessary, it requires a separately
reviewed cross-crate contract.

## Camera-mod ecosystem compatibility

Compatibility is capability-based. Atom never checks a DLL or ESP name.

### Smooth True Iron Sights

Read-only Stewie Tweaks source corroborates the native `0x00874EBF` seam and
interpolates OSGlobals +0xA0 after `DeferredInit`. Atom deliberately runs later,
at the RenderFirstPerson callsite, so the smoothed native result is its base.
Aim attenuation prevents Atom from fighting that transition.

### Viewmodel Shake Fix

[Viewmodel Shake Fix](https://www.nexusmods.com/newvegas/mods/84443) addresses
large-world-coordinate precision by performing first-person root/camera work
near the origin and restoring it inside RenderFirstPerson. Read-only Stewie
Tweaks source independently implements the same transaction around
`0x00875956`. Atom now uses that proven coordinate-space rule at its broader
RenderFirstPerson boundary. Exact-zero local and world root translations mean
an earlier owner already rebased the graph, so Atom does not write or restore
that root; otherwise it performs one scoped rebase and exact restoration.
There is no plugin-name check or patch to another owner. High-coordinate
testing remains mandatory because static restoration tests cannot prove the
live skeleton and every external hook ordering.

### B42 Weapon Inertia and recoil systems

[B42 Weapon Inertia](https://www.nexusmods.com/newvegas/mods/64335) already
adds skeleton-dependent weapon inertia. Atom must not detect or patch it. The
separate `Weapon Motion` control lets a user set Atom's viewmodel inertia to
zero while retaining world-camera head motion. Hook
preflight and exact snapshot restoration prevent lost predecessors, but visual
double-inertia outside FNV's authored action window still requires user choice
and playtest.

Recoil systems remain the owner of their gameplay and animation paths. Atom's
camera API accepts a bounded presentation impulse only through an explicit
capability; it never infers recoil by inspecting a mod or animation name. The
current capability is the positive effective-count result at `0x00524413` in
`0x00523150`. That call executes once before the count-controlled launch loop
at `0x005245BD`, so one shotgun or split-beam action cannot manufacture one
camera event per projectile. Exact player-singleton source classification,
first-person ownership seeding, and lifecycle generation changes prevent NPC,
third-person, or stale events from reaching the listener.

### Enhanced Camera and visible bodies

[New Vegas Enhanced Camera](https://www.nexusmods.com/newvegas/mods/55334)
demonstrates demand for visible bodies and forced first-person states, but also
expands camera ownership into sitting, knockout, death, and animation-driven
head motion. Atom does not recreate that scope or assume player +0x64C is
sufficient when another system forces first person.

If a visible-body system leaves the proven world and first-person calls as
chainable direct calls, Atom may operate only in its independently proven
normal gameplay states. Replaced routes, missing nodes, or forced special
states fail closed. A raw animated head transform is never Atom's base camera.

## Accessibility and comfort

Microsoft's
[Xbox Accessibility Guideline 117](https://learn.microsoft.com/en-us/xbox/accessibility/xbox-accessibility-guidelines/117)
specifically identifies camera bob, shake, motion blur, weapon sway, automatic
camera changes, and FOV as potential motion-sickness barriers. It recommends
avoiding them or providing controls that can disable them, including intensity
scales that reach zero.

A randomized trial of stabilized versus locomotion-oscillating first-person
360 video also found camera stability material enough to study as a
cybersickness intervention
([Litleskare and Calogiuri, 2019](https://doi.org/10.3389/fpsyg.2019.02436)).
The display context is VR video rather than desktop FNV, so it supports caution,
not a numeric Atom threshold.

Atom requirements:

- `Camera Motion = 0` performs no world-camera write;
- `Weapon Motion = 0` removes Atom's weapon inertia;
- camera, weapon, and landing gains are separately adjustable;
- no FOV pulse, sprint zoom, forced motion blur, or moving UI;
- common roll/pitch remains sub-degree and yaw stays zero;
- aim and scope attenuation is mandatory, not a hidden preset detail;
- menu changes apply from `MCMExtUpdate` after the INI save;
- disabling or changing mode clears temporal state at a safe epoch;
- native FOV remains untouched by this module.

XAG also recommends an adjustable FOV. Atom should coexist with the user's
native or established FOV owner rather than silently taking it over in this
first camera milestone. If Atom later exposes FOV, it needs its own ownership
and compatibility research.

## Configuration and MCM ownership

MCM Extender remains the sole writer of `Data/config/Atom/Atom.ini`. Camera
settings join Atom's existing typed load, sanitization, coherent publication,
and `MCMExtUpdate` path. The render hooks consume one lock-free immutable
snapshot; they never parse the INI.

Current implemented configuration:

```ini
[FirstPerson]
bEnabled=0
fCameraMotion=0.65
fWeaponMotion=0.65
fLandingMotion=0.45
fAimMotion=0.20
```

`bEnabled=0` is the safe pre-playtest default. Numeric values above are product
hypotheses for calibration, not approved shipping values. Sanitization clamps
all gains to `[0, 1]`; unknown fields remain owned by MCM/future Atom versions.
`iMotionMode` is not persisted because Stable is the only admitted world mode.
`fCameraMotion` independently reaches exact identity and is shown as `Head
Motion` on the MCM page. `fWeaponMotion` scales only weapon inertia, and
`fAimMotion` is the fraction retained while aiming.

Every visible MCM string must remain one to three words. A compliant initial
page can use:

| Role | Text |
|---|---|
| Page | `First Person` |
| Toggle | `Enable Motion` |
| Slider | `Head Motion` |
| Slider | `Weapon Motion` |
| Slider | `Land Motion` |
| Slider | `Aim Motion` |
| Help | `World bob strength` |
| Help | `Weapon inertia` |
| Help | `Head landing strength` |
| Help | `ADS inertia fraction` |

The shipped MCM artifact test must reject longer text, duplicate INI keys,
defaults outside bounds, and disagreement with Rust defaults.

## Source ownership

The implemented first-person wrapper occupies one focused camera namespace:

```text
atom/src/camera/
|-- mod.rs              lifecycle, admission, public motion API
|-- config.rs           typed MCM settings and coherent store
|-- native.rs           supported addresses, pointers, state gates
|-- pose.rs             Vec3/matrix pose math and clamps
|-- motion.rs           gait, landing, look inertia, and aim attenuation
|-- state.rs            ownership epochs and reset protocol
`-- hooks.rs            entry/render wrappers and transactional rollback
```

Shared camera math may later serve the third-person system, but the first
implementation does not extract a generic framework without a concrete shared
need. `atom/src/lib.rs` remains a thin lifecycle dispatcher, while
`atom/src/runtime.rs` coordinates the typed Atom configuration rather than
introducing a second file owner.

No WinAPI is required in the render path. If timing or memory validation later
needs a missing operation, add a safe wrapper to `libpsycho`; do not call WinAPI
directly from Atom.

## Performance and memory budget

Steady-state target per accepted player update:

- one character-controller/state read;
- one bounded velocity/state classification;
- a fixed number of scalar spring and waveform operations;
- one immutable motion-frame publication;
- zero allocation, lock, I/O, logging, node lookup, or raycast.

Per admitted world or first-person render call:

- fixed pointer and epoch checks;
- fixed transform snapshots (camera plus two small finite-scene roots for the
  world draw, or camera plus the first-person root for the viewmodel draw);
- one bounded pose composition;
- native graph updates only for the roots whose temporary center changes;
- one live predecessor call;
- one exact restore;
- zero state advancement and zero allocation.

Trigonometric gait values may use a small deterministic approximation or
paired sine/cosine once per update after numerical tests. They must not be
recomputed separately in both render listeners. Sky/Weather and viewmodel graph
updates follow existing native render work and allocate no Atom memory, but
their live cost remains a release-playtest measurement rather than a claimed
sub-0.05 ms bound. Telemetry measures only fixed counters in an opt-in window
and summarizes through the established logger outside
the hot path.

## Failure behavior and diagnostics

The camera feature is optional. Any failure preserves Atom Input and native
camera behavior.

Current lifecycle logs:

- `info`: `[CAMERA] Render-scoped first-person head and viewmodel motion is available`
- `debug`: `[CAMERA] Chained predecessors: ...`
- `warn`: `[CAMERA] First-person head and viewmodel motion is unavailable: ...`
- `warn`: `[CAMERA] ... First-person camera remains native`

Technical predecessor addresses are `debug`. Render callbacks never log, and
Atom creates no private telemetry file.

When Atom Input telemetry is enabled, the same requested-summary toggle also
reports bounded `[CAMERA_TELEMETRY]` path counters. They distinguish update
hook calls, accepted native samples, generated head and weapon poses, world and
viewmodel route pairing, successful transform application, and the ordered
native gate that rejected a sample or render. Hook-side work is limited to
fixed saturating 32-bit atomics. Formatting and logger calls occur only from
the existing MCM update handler after the summary request.

Non-finite pose, invalid pointer range, mismatched callsite predecessor,
unexpected recursion, or restore failure closes camera admission immediately.
The consequence is native pass-through, never a partially applied pose.

## Implementation phases

### Phase 0: close native safety contracts

Before any feature code:

1. validate exact character-controller velocity, support velocity, fall state,
   units, lifetime, and update thread against the supported executable;
2. prove the normal-gameplay gates for VATS, TFC, POV transitions, dialogue,
   Pip-Boy, furniture, death, knockout, ragdoll, scope, loading, and scripted
   cameras;
3. verify the camera matrix convention with basis-vector tests;
4. prove snapshot/write/restore fields for both cameras and whether any derived
   camera data needs an update;
5. classify the special first-person A route or retain permanent pass-through;
6. classify native camera collision ownership and admit only a world envelope
   which does not require reusing an unsafe transaction;
7. trace crosshair, activation, projectile, and muzzle convergence far enough
   to define the allowed world pose under hip fire and ADS;
8. record exact call instruction bytes and ABI for UpdateCamera, both world
   sites, and all three first-person sites;
9. inspect the installed call targets at DeferredInit and prove caller-local
   predecessor chaining in both OMV load orders;
10. record all new evidence in the radare2 ledger and update this document.

Exit criterion: a fixed behavioral test can reject a write outside normal
first-person render ownership, and static evidence closes every field used by
the hot path.

### Phase 1: pass-through wrapper and viewmodel inertia (implemented)

Implement the state machine, coherent update sample, hook groups, exact guards,
and viewmodel look inertia with world motion fixed at zero.

Acceptance:

- feature off is byte-for-byte native at both camera fields;
- every wrapper calls the correct live predecessor exactly once;
- all error and ownership paths restore snapshots;
- Smooth True Iron Sights and Viewmodel Shake Fix behavior is preserved;
- weapon motion is direct-input responsive and frame-rate consistent;
- high-coordinate jitter is not worse than native/fix baseline.

### Phase 2: locomotion, landing, and Stable head motion (implemented)

Add support-relative cadence, stance profiles, gait envelopes, and landing
impulses. The admitted world listener adds only sub-unit vertical/lateral local
translation plus bounded roll/pitch, with exact ADS suppression and independent
gain. The viewmodel retains native gait and adds only a subordinate look layer
when no authored action owns the weapon.

Acceptance:

- no bob while blocked against a wall or standing on a moving platform;
- cadence follows actual movement and analog magnitude;
- jump/in-air suppresses gait and landing fires once;
- slopes, stairs, and small step-downs do not emit repeated impacts;
- ADS/scopes converge to stable native presentation;
- no geometry crossing occurs at maximum supported gain.

### Phase 3: survival profiles and event API

The first internal event channel is implemented for authoritative player
ranged fire. Extend it only with restrained, proven-state breathing/handling
profiles or additional named combat capabilities. Do not add world random
noise by default.

Acceptance:

- every source has a named channel and bounded listener gain;
- event bursts saturate safely rather than summing without limit;
- gameplay recoil remains owned by Atom combat;
- camera-only disable leaves combat behavior unchanged.

### Phase 4: optional Full motion

Only after Stable ships and passes comfort/playtests, evaluate small world
pitch/roll, aim-compensated translation, and animation-event phase correction.
Each is independently disableable. None is required to call the core wrapper
complete.

## Automated validation

### Pure behavior tests

- gait phase advances by distance and is equivalent at 30, 60, 120, and
  jittered frame steps;
- the waveform is periodic, centered, continuous, and bounded;
- start/stop and stance transitions are monotonic without a one-frame pop;
- analytic springs converge and do not overshoot their configured bound;
- landing emits once for air-to-ground and scales monotonically with capped
  downward speed;
- on-ground-to-on-ground steps do not emit landings;
- unsupported, swimming, native-owned, paused, and invalid states output zero;
- aim weights reduce the correct listener axes;
- modifier order is deterministic and final clamps always hold;
- non-finite input resets to a finite zero pose;
- zero gains produce an exact identity pose.

### Hook and artifact tests

- executable fixtures validate all direct CALL contexts and ABI shapes;
- the complete UpdateCamera entry chains one live typed trampoline;
- every render callsite stores and invokes its own current predecessor;
- multiple UpdateCamera callers advance motion once per input frame;
- ownership reset reacquires even within the same input frame;
- partial group installation rolls back;
- nested and stale epochs pass through;
- special route A cannot consume a main-route token;
- scope/aim/menu/VATS/POV transitions invalidate state;
- an RAII transaction restores camera bytes after normal return and injected
  failure;
- MCM JSON and Rust defaults agree and visible text remains one to three words;
- the optimized `i686-pc-windows-gnu` Atom DLL retains expected PE imports,
  TLS, and startup footprint.

Tests should exercise pose math, state transitions, hook containers, and shipped
artifacts through real boundaries. They must not assert source-text call order
or use source parsing as a behavior substitute.

## Runtime acceptance matrix

Static tests and a release build cannot prove camera feel or image correctness.
The user must test the release artifact through Proton/Wine.

### Core feel

- idle, slow walk, walk, run, sneak, diagonal movement, analog partial tilt,
  auto-move, and a sprint provider;
- start, stop, rapid reverse, strafe, circle, stairs, slopes, elevators, moving
  platforms, collision-blocked movement, swimming, jump, fall, and soft/hard
  landings;
- 30, 60, 120, uncapped, and deliberately uneven frame times;
- slow pixel aiming, fast flicks, continuous turns, 180-degree turns, inverted
  axes, mouse and controller;
- multiple FOVs, aspect ratios, and viewmodel FOV configurations.

### Weapons and actions

- holstered, pistols, rifles, heavy guns, energy weapons, bows if mod-added,
  unarmed, one/two-handed melee, grenades, mines, and thrown weapons;
- hip fire, true iron sights, non-true sights, magnified scopes, variable zoom,
  weapon sway, recoil, reload, partial reload, jam, equip, holster, bash, and
  interrupted animation;
- vanilla animations, representative kNVSE animation packs, asymmetric
  weapons, left-handed/custom skeletons where supported, and missing optional
  nodes;
- B42 inertia/recoil individually on and off without plugin-name logic.

### Ownership transitions

- rapid first/third-person switching;
- every VATS mode and entry/exit timing;
- TFC/vanity camera, dialogue, Pip-Boy, console, pause, inventory, barter,
  container, terminal, lockpick, sleep/wait, furniture, knockout, ragdoll,
  player death, kill camera, scripted camera, and race menu;
- save, load, new game, cell transition, fast travel, teleport, alt-tab/focus
  loss, device reset, resolution change, and shutdown;
- Enhanced Camera-style forced first-person states if installed.

### Image and gameplay truth

- crosshair target, activation reference, projectile impact, muzzle convergence,
  scope center, and melee direction with motion off versus maximum supported
  Stable motion;
- walls, doorframes, ceilings, low cover, near-plane weapon clipping, extreme
  pitch, and high world coordinates;
- world culling, water, shadows, decals, particles, transparencies, and sky at
  maximum offset;
- OMV TAA, motion blur, AO, depth of field, fog, shadows, and device reset in
  both Atom/OMV load orders;
- hands/weapon depth and motion match their separately posed camera;
- no camera field remains modified after a wrapped call.

### Comfort

- `Camera Motion = 0` removes common head motion and `Weapon Motion = 0`
  removes relative weapon motion immediately and permanently;
- head rotation remains sub-degree and adds no yaw or dynamic FOV;
- motion remains subtle during long traversal and does not obscure targets;
- ADS and scopes become visibly stable;
- no UI element bobs;
- at least one motion-sensitive tester can complete a 20-minute traversal with
  camera motion off, and another can evaluate each nonzero level separately.

## Release gates

Before calling the complete wrapper startup-safe and visually accepted:

1. Phase 0 evidence is complete and linked from this document.
2. Focused behavior, hook, and MCM artifact tests pass.
3. All Atom tests pass for `i686-pc-windows-gnu`.
4. The optimized Atom release target builds explicitly for
   `i686-pc-windows-gnu`.
5. PE imports, TLS, and pre-Deferred configuration shape are compared with the
   accepted startup baseline.
6. `git diff --check` passes and only intended files changed.
7. Proton load-to-gameplay succeeds with the repository's startup compatibility
   test set, including BaseObjectSwapper.
8. The runtime matrix above is recorded with FPS, FOV, camera gains, installed
   camera/viewmodel capabilities, and any visible defect.

Until those gates pass, the correct status is "head-motion implementation
awaiting playtest," not "startup-safe," "visually accepted," or "finished."

### 2026-08-16 admitted-but-inert runtime correction

The deployed `b929ce25...` artifact reached gameplay and logged native
predecessors for every first-person callsite. OMV independently executed more
than 22,000 first-person stages without a scene failure. Those facts prove the
hook chain is callable, but the artifact did not record whether Atom admitted
an update, generated motion, paired the world/viewmodel route, or applied a
transform. Its availability log was therefore insufficient evidence for the
user-visible feature.

That implementation also rejected every render after the first consumption of
one UpdateCamera epoch, despite this document's requirement that multiple
renders for one update see the same immutable pose. The duplicate-epoch gate
is removed. Route matching, single token consumption, native-owner checks, and
Present invalidation still prevent cross-route or cross-frame leakage.

The existing requested telemetry summary includes end-to-end camera path
counters and per-gate rejection counts. It is optional developer evidence, not
a user acceptance workflow. Runtime acceptance is an ordinary Proton launch
and visual feature test; static validation cannot prove pixels produced by the
game process.

All 66 Atom tests pass on explicit `i686-pc-windows-gnu` through Wine staging
11.15, including two render-token regression tests and the bounded diagnostics
test. Atom-only Clippy passes for all targets with warnings denied; focused and
workspace formatting checks plus `git diff --check` pass; and the optimized
Atom release build succeeds. The candidate DLL is 6,746,087 bytes with SHA-256
`c55791250e2b9fe6fefa4d6ff7fcc704256ef6a7a4de7a34eca167cbd5b64968`.

Against deployed `b929ce25...`, it keeps PE32/i386 characteristics, the same
nine section roles, `0x2B04` import directory, `0x18` TLS directory, zeroed
eight-byte `.tls` section, and three exports. `.text` changes from `0x29B730`
to `0x29E3F0`, `.data` from `0x1BB0` to `0x1CE8`, `.rdata` from `0x120CE8`
to `0x1215D8`, `.eh_fram` from `0x4EAA4` to `0x4EC8C`, `.bss` from `0x1908`
to `0x1A30`, and `.reloc` from `0x215FC` to `0x219EC`; rounded image size
changes from `0x438000` to `0x43C000`. This comparison also contains the
separately documented Ballistics correction already present in the pre-camera
worktree. The camera diagnostics add fixed static counters and labels but no
import, export, TLS callback/data, worker, thread, file scan, or pre-deferred
operation. The layout remains a material startup-footprint delta and requires
the requested Proton/BaseObjectSwapper load-to-gameplay replay.

### 2026-08-16 Stable head-motion candidate

This historical candidate made the existing world pose real after the
admitted-but-inert runtime result. `GeneratedMotion` published independent
world and viewmodel poses from one distance phase. Ordinary grounded movement
produced bounded translation and forward-axis roll; aiming and authored
first-person actions published exact identity world motion immediately; both
listener gains had exact zero boundaries; and stopped envelopes snapped to
mathematical zero after convergence so render hooks stopped writing the native
camera.

Fresh radare2 evidence for the rejected native collision transaction and the
admitted world-pose boundary is in section 16 of the first-person ledger. The
new public behavior tests first rejected the identity-only implementation and
now cover non-identity world output, numeric bounds, exact yaw/pitch exclusion,
ADS suppression, independent listener controls, deterministic frame
partitioning, and exact rest settling. A matrix test proves that the allowed
roll leaves the native forward column unchanged.

All 74 Atom tests pass for explicit `i686-pc-windows-gnu` through Wine staging
11.15. Atom-only Clippy passes for all targets with dependency lint excluded
and warnings denied. The optimized Atom release build succeeds. The candidate
DLL is 6,762,674 bytes with SHA-256
`e2795a0ff3fa89d6d5d3c0e8f0c9da4d5605080a9d59975ed4fcd03233ba8e29`.

Relative to the currently deployed `5a289758...` DLL, the candidate retains
PE32/i386, large-address-aware, ASLR/NX characteristics, the same nine section
roles, `0x2B04` import directory, `0x8C` export directory, `0x18` TLS
directory, and eight-byte `.tls` section. `.text` changes from `0x29EA70` to
`0x2A0030`, `.data` from `0x1BB0` to `0x1D10`, `.rdata` from `0x1217A8` to
`0x121918`, `.eh_fram` from `0x4ECF0` to `0x4ED3C`, `.bss` from `0x1AA0` to
`0x1B08`, and `.reloc` from `0x219B4` to `0x21D6C`; rounded image size changes
from `0x43C000` to `0x43E000`. No import, export, section role, or TLS shape was
added. The code/data layout is still a material pre-Deferred footprint delta,
so static equivalence does not replace the required Proton/BaseObjectSwapper
load-to-gameplay test.

The first visible playtest later rejected this waveform as unplayable rapid
jitter. It is retained here only as artifact history; the then-current Stable
contract became the translation-only, cadence-capped correction documented
below. The current common render-rotation layer retains that cadence cap and
uses only its restrained smooth waveform.

### 2026-08-16 complete UpdateCamera entry correction

The next runtime summary rejected the remaining single-caller assumption. With
deployed DLL `3b78b995...` and `Head Motion=1.00`, Atom recorded 10,780 world
calls and 5,748 viewmodel calls but zero UpdateCamera wrapper calls, zero poses,
and zero applied transforms. The third-person interior hook independently
recorded 10,542 calls inside UpdateCamera. This is direct evidence that the
native camera function ran while the `0x0093FA08` wrapper did not; settings and
motion amplitude were not the cause.

Fresh radare2 xrefs establish eleven native callers to `0x0094AE40`, including
three calls in the main PlayerCharacter update. All pass the PlayerCharacter in
ECX, allocate two stack argument slots, ignore EAX, and converge through the
function's sole `ret 8` epilogue. Section 17 of the
[first-person camera ledger](../analysis/radare2/output/perf/fnv_first_person_camera_contract.txt)
records every caller, instruction boundary, ABI fact, runtime counter, and
evidence classification.

Atom now wraps the live UpdateCamera entry rather than one caller. The entry
trampoline covers all native branches and compatible external callers, calls
the complete predecessor first, and samples afterward. Immutable interior and
epilogue fingerprints prove the supported body without rejecting a compatible
earlier entry hook. The entry and five render wrappers remain one rollback
transaction, so partial admission leaves the first-person camera fully native.

The shared inline decoder admits an existing complete first-instruction
redirect when that single instruction is at least as wide as Atom's entry
jump. Relocating that redirect into Atom's trampoline preserves the earlier
owner's call/return chain. A short redirect, return, loop, or later terminal
jump still fails closed because unreachable trailing bytes cannot establish a
safe patch region. Focused decoder tests cover both the admitted five-byte
entry redirect and the rejected short redirect.

Because loading, transitions, screenshot paths, and maintenance can call the
same native function between normal input samples, `NativeUpdateSample` now
carries Atom Input's frame identity. The motion state publishes at most once
per input identity. Duplicate completions do not integrate the same engine
delta again or erase the current pose; reset generation and cell changes still
force a fresh identity frame. Two focused regression tests cover both rules.

The pre-change startup baseline for this correction is the same DLL that
produced the decisive gameplay log: SHA-256 `3b78b995...`, 6,762,674 bytes,
nine PE sections, import directory size `0x2B04`, export directory size
`0x8C`, TLS directory size `0x18`, and an eight-byte `.tls` section. The new
`LazyLock<InlineHookContainer>` has zero loader-time work and is first touched
only during the established DeferredInit camera installation. It replaces one
deferred callsite container; it adds no configuration field, parser, import,
export, TLS callback, thread, worker, file scan, or pre-Deferred publication.

The optimized candidate is 6,787,496 bytes with SHA-256
`04994492f6a504fb244bf313456de1463ab8a7c7d852989ed91859a231568b02`.
Against `3b78b995...`, all 320 imported DLL/symbol pairs are identical and in
the same order. It retains PE32/i386, large-address-aware, ASLR/NX, nine section
roles, three named exports, import directory size `0x2B04`, export directory
size `0x8C`, TLS directory size `0x18`, four established TLS callback roles,
and the zeroed eight-byte `.tls` section. `.text` changes from `0x2A0030` to
`0x2A34F0`, `.data` from `0x1D10` to `0x1D50`, `.rdata` from `0x121918` to
`0x121BD8`, `.eh_fram` from `0x4ED3C` to `0x4F0AC`, `.bss` from `0x1B08` to
`0x1B30`, and `.reloc` from `0x21D6C` to `0x21FC8`; image size changes from
`0x43E000` to `0x442000`. This artifact comparison includes concurrent
uncommitted Ballistics and third-person work already present in the shared
Atom crate, so the total section growth is not attributed solely to this
first-person correction. Any layout change still requires the user's ordinary
Proton load and feature test before the artifact can become the next startup
baseline.

### 2026-08-16 rapid-shake playtest correction

The first run of deployed DLL `c973e141...` that visibly moved the camera used
`Head Motion=1.00`. Startup completed, the complete UpdateCamera entry hook was
enabled, and its callable trampoline was logged at `0x0FF00000`. The user then
reported that the camera jittered very rapidly and was completely unplayable.
At `17:05:16Z`, the normal MCM reload disabled First Person. This is direct
runtime evidence that the prior visual result was rejected; no numeric native
speed trace was requested or required.

Source audit found three independently sufficient defects in the prior Stable
waveform. Full-stride cadence was `speed / stride_length` with stride length
capped at 158 game units but no frequency ceiling. Its vertical waveform added
a fourth phase harmonic, so after stride interpolation saturated that component
ran at `4 * speed / 158` Hz. Finally, it wrote sinusoidal world roll despite
this document's accessibility and Stable requirements explicitly prohibiting
automatic world roll. Existing tests bounded position and proved endpoint
partitioning, but did not bound frequency, derivative, or Stable rotation.

The corrected generator derives full-stride cadence from support-relative
speed, clamps its target to 1.6 Hz, analytically filters and integrates that
cadence, and uses a single smooth footfall sinusoid. Thus vertical gait cannot
exceed 3.2 Hz even for extreme SpeedMult values or physics spikes. At full head
gain, steady gait has a derived maximum translation speed below 6.7 game units
per second. The world listener now has exact zero forward translation and exact
identity rotation; the higher-frequency harmonic was also removed from the
viewmodel listener. Landing remains a bounded one-shot event.

The focused public suite now rejects the shipped failure class: speeds up to
20,000 game units per second are exercised at 30, 60, and 120 Hz; every phase
step must remain under the 1.6 Hz ceiling; every steady world-gait step must
remain under the derived velocity bound; and every Stable rotation must be
exact identity. All 12 first-person behavior tests pass through Wine staging
11.15 on explicit `i686-pc-windows-gnu`.

The complete current Atom suite passes 77 tests. The affected libpsycho suite
passes 42 unit tests and 16 doctests, including an end-to-end two-owner entry
hook test that installs the second redirect, calls through the first owner,
restores the first owner, and finally restores native code. Workspace formatting
passes. Clippy passes for both affected crates with warnings denied after
excluding three existing unrelated libpsycho lints and the existing Ballistics
`collapsible_if` lint. The optimized explicit-target Atom build succeeds.

The corrected DLL is 6,783,276 bytes with SHA-256
`a7bdf07e1ddd1c587b2b3c826d6144c2bf87be92c9825a5f8ed88fc9a7627642`.
Against rejected deployed DLL `c973e141...`, all 321 parsed imported
DLL/symbol pairs and all three named exports are identical. Both are PE32/i386,
large-address-aware, ASLR/NX, have the same nine section roles, image size
`0x442000`, import directory `0x2B04`, export directory `0x8C`, TLS directory
`0x18`, four established TLS callback roles plus null, and zeroed eight-byte
`.tls`. `.text` changes from `0x2A3870` to `0x2A30F0`, `.data` from `0x1D48`
to `0x1D10`, `.rdata` from `0x121C18` to `0x121B48`, `.eh_fram` from `0x4F0B4`
to `0x4EFC8`, and `.reloc` from `0x21FE0` to `0x22088`; `.bss`, `.edata`,
`.idata`, and `.tls` sizes are unchanged. The correction adds no configuration,
import, export, TLS role/data, thread, worker, file scan, or pre-Deferred work.

### 2026-08-16 finite-sky and large-coordinate correction

The next playtest rejected deployed `e34c81bf...`: the first-person hands
stepped and the whole sky jumped with them. The same run reached Atom
DeferredInit with the complete UpdateCamera and render hooks installed. OMV
recorded tens of thousands of coherent world and first-person stages with no
scene-transaction failure. This proves a visible output defect after hook
admission; it does not support blaming the support-relative velocity function
or asking the user for another diagnostic run.

Fresh radare2 research of the identified FalloutNV.exe found the first missing
render owner. Both main routes call `0x00872B00` before their world draw.
At `0x00872C55..0x00872CA1`, that function obtains World SceneGraph child zero,
reads its local translation at `+0x58`, copies it into the root at `0x011DEB34`,
constructs zero-time/false-flag `NiUpdateData`, and recursively updates the
root through `0x00A59C60`. It repeats the same sequence for `0x011DEDA4` at
`0x00872CA6..0x00872CF2`. Construction names those roots `Sky` and `Weather`
at `0x0086D9BB` and `0x0086DA96`. Atom's former hook ran later and changed only
camera world translation `+0x8C`, leaving both finite graphs centered on the
old camera. The runtime symptom follows directly from that ownership mismatch.

The corrected world guard resolves every object and finite transform before
its first write. It composes the Stable pose once against camera world space
and once against camera local space, applies the posed world camera, gives Sky
and Weather the posed local center, and calls the same fingerprinted native
update helper with the same initialized data contract. On every return or Rust
unwind it restores both graphs through their native recursive update, reapplies
the exact root local/world snapshots to remove multiplication rounding, and
restores the exact camera snapshot. A focused regression makes the graph
update observable, checks that Sky and Weather share the posed center during
the draw, and checks all owners after restoration.

The hands had a separate precision boundary. OSGlobals' first-person camera
and `PlayerCharacter::Get3D(true)` can carry large absolute `f32` coordinates,
where a sub-unit procedural offset is quantized before rendering. Native
`RenderFirstPerson @ 0x00875110` performs the actual draw at `0x0087590A` and
updates the player root later at `0x00875956`. Read-only Stewie Tweaks source
independently uses that exact later call to restore an origin-relative
Viewmodel Shake Fix transaction. Atom now rebases the camera against the root,
zeros and updates the root, composes the procedural pose near zero, renders,
and restores both objects. If both root translations are already exact zero,
Atom recognizes an existing rebase owner and touches only its camera snapshot.
A regression starts at million-unit coordinates, proves the rendered camera is
within four units of the origin, injects an unwind, and verifies exact root and
camera restoration.

This correction changes no MCM field, schema, import, export, TLS ownership,
thread, worker, file scan, or pre-Deferred operation. The native update helper
and Sky/Weather pointer slots are validated only at the established
DeferredInit camera admission boundary. Live visual coherence and graph-update
cost still require the ordinary release playtest; static analysis and Wine
unit tests cannot prove pixels or frame time in the game process.

All 87 Atom tests pass through Wine staging 11.15 on explicit
`i686-pc-windows-gnu`, including 12 public first-person behavior tests and the
four native coordinate/ownership regressions. Atom-only Clippy passes for all
targets with warnings denied. Workspace formatting, `git diff --check`, and the
optimized explicit-target Atom build pass. The resulting DLL is 6,800,001
bytes with SHA-256
`cc7c636ef24975c8e01e9a8b1637a854c945aac2ab15712193c85763b556b18d`.

Against rejected deployed `e34c81bf...`, it retains PE32/i386,
large-address-aware, ASLR/NX, nine section roles, the exact 320 ordered
imported DLL/symbol pairs, three named exports, import/export/TLS directory
sizes `0x2B04`/`0x8C`/`0x18`, IAT size `0x574`, four unchanged TLS callback
roles plus null, and eight zero `.tls` bytes. `.text` changes from `0x2A31B0`
to `0x2A4D70`, `.data` from `0x1D08` to `0x1ED0`, `.rdata` from `0x121B68` to
`0x122658`, `.eh_fram` from `0x4F00C` to `0x4F340`, `.bss` from `0x1B38` to
`0x1B70`, and `.reloc` from `0x22070` to `0x222FC`; image size changes from
`0x443000` to `0x445000`. The aggregate DLL includes all current dirty-worktree
Atom code, so total section growth is not attributed solely to this correction.

### 2026-08-17 complete render-route correction

The finite-sky correction above repaired one camera/root mismatch but retained
the wrong ownership seam. Atom still entered at `RenderWorldSceneGraph`, after
native route preparation `0x00872B00` had already consumed the unposed camera.
It compensated by manually posing and recursively updating Sky and Weather,
then restored snapshots and recursively updated them again. Together with the
two native preparation updates, an accepted first-person frame performed six
root graph walks. More importantly, earlier native preparation and later
image-space work did not belong to one camera transaction. The user's Atom/OMV
playtest continued to show native-sky blinking, missing PBR/effects, and poor
responsiveness; that runtime result rejects the former seam as a compatibility
solution.

Fresh radare2 evidence in
`analysis/radare2/output/perf/fnv_first_person_camera_contract.txt` establishes
the complete parent routes. `Main::Render @ 0x008706B0` calls route A at
`0x0087074B` and route B at `0x0087075E`. Each call passes the Main receiver in
`ECX`, one opaque 32-bit value and one byte value on the stack; both targets
return with `ret 8`. Their typed ABI is
`thiscall(Main*, u32, u8) -> void`. Route A and route B each perform native
Sky/Weather preparation, RenderWorld, the paired RenderFirstPerson call, and
their complete image-space owner before returning.

Atom now transactionally hooks those two caller cells together with the three
existing RenderFirstPerson cells at the established first post-Deferred
main-loop boundary. Every cell captures and invokes its exact live predecessor;
there is no hard-coded native fallback that could skip another compatible
owner. A missing predecessor or reentrant route invalidates only Atom's pending
world/viewmodel pair. The native render remains pass-through whenever the
captured chain is available, and the separately classified special
first-person route remains unposed.

The outer guard resolves the persistent `SceneGraph +0xAC` render camera,
SceneGraph child zero used by native sky centering, and both finite roots. It
prepares finite local/world transforms for both camera identities before the
first write and mutates only once when the pointers are equal. Native
`0x00872B00` then performs its ordinary Sky and Weather centering and graph
updates from the posed child-zero anchor. On return, the guard restores each
camera object exactly, restores only the child-zero-derived local translation
on Sky and Weather, and performs one recursive update per root. It deliberately does not
replay pre-route root rotation/world snapshots, so weather or controller
mutations made by the route survive. Atom's extra graph work falls from four
updates to two; no update, lock, allocation, file I/O, or diagnostic write was
added to the apply side.

The inner RenderFirstPerson guard is unchanged: it consumes the exact route
token, rebases the viewmodel camera/root near the origin, invokes the captured
predecessor, and restores the exact native values. The outer world camera stays
posed across this nested call and across the complete image-space owner, so
OMV and native consumers see a single coherent frame camera regardless of
which compatible DeferredInit owner is earlier in the captured chain.

Focused tests prove the route detour ABIs, route-exact single consumption,
reentrant-token invalidation, posed local/world camera visibility before a
modeled native sky preparation, preservation of in-route root rotation, and
exact restoration with only two Atom restoration updates. Static evidence does
not prove final pixels or responsiveness. Acceptance requires the Atom camera
on/off matrix with native sky, PBR, fog, volumetric lighting, bloom, shadows,
fast camera movement, loading transitions, and measured frame pacing.

This change adds no MCM/configuration value, schema, parser, import, TLS value,
thread, worker, file scan, or pre-Deferred operation. It replaces two existing
post-Deferred callsite containers with two other fixed callsite containers in
the same five-cell transaction. The final Atom DLL still changes code/static
layout and requires the repository's Proton/BaseObjectSwapper startup gate
before it can become a runtime-accepted artifact.

Static closure passes all 103 explicit-target Atom tests, strict all-target
Atom Clippy, formatting, and the complete supported release build. The
optimized `atom.dll` is 6,814,115 bytes with SHA-256
`2989c830b49c9546d2dcbbd7bcc42ae1b0c8b6b0aa35dda0be7376c6b547b401`.
Against the immediate pre-correction worktree artifact (6,816,065 bytes,
SHA-256 `62e997ee7eeb04d92d0da2843e15978f992fa0cf240b6ed1266a00e2b675b5f7`),
`.bss = 0x1AD8`, `.data = 0x1F80`, `.idata = 0x2B04`, and `.tls = 0x8`
are unchanged. `.text` changes from `0x2A6A30` to `0x2A6330`, `.rdata` from
`0x122A38` to `0x122A58`, `.eh_fram` from `0x4F5F8` to `0x4F5F4`, and
`.reloc` from `0x224B8` to `0x224CC`. This proves the bounded static delta, not
the required Proton/BaseObjectSwapper startup or camera/effect playtest.

### 2026-08-17 distinct sky-anchor correction and OMV rollback

The next installed playtest rejected the one-camera version: native sky moved
in direct synchrony with Atom's head bob, PBR remained absent, and the user
could not trust the other OMV effects. The deployed Atom and OMV hashes matched
the reviewed artifacts. OMV logged all major hook capabilities as active, PBR
resources prepared, and atmosphere/bloom passes executing. That is runtime
evidence against stale installation and simple hook admission; it is not proof
that any final pixel used the intended owner.

Fresh radare2 research closes the remaining native identity gap. The render
camera getter at `0x006629F0` returns `SceneGraph +0xAC`. Sky preparation does
not call it. At `0x00872C55` and `0x00872CA6`, `0x00872B00` calls
`0x00558310`, which obtains index zero from the NiTArray at
`SceneGraph +0x9C`, then calls `0x0043C490` to read that child's local
translation. The executable has two access paths and does not assert their
pointer equality. Vanilla commonly makes them equal; a chained camera owner is
allowed to make them distinct.

Atom now resolves both objects inside the synchronous parent-route callback.
It validates and composes both complete local/world transform pairs before the
first write, poses one object once when the pointers alias, and otherwise poses
both. Restoration returns each exact pair to its owner and recenters Sky and
Weather from child zero's original local translation. No object pointer is
published or retained. The additional work is four small matrix compositions
and four transform stores only in the uncommon distinct-identity case; it adds
no lock, allocation, graph walk, driver query, file I/O, or diagnostic write.

The regression deliberately supplies different render-camera and sky-anchor
objects with different base translations. It models native centering from the
posed anchor, verifies Sky/Weather coherence during the route, preserves an
in-route sky rotation mutation, and verifies exact restoration of both camera
owners plus two root updates. A same-pointer transaction still performs one
camera mutation by construction.

The same runtime result rejects the concurrent OMV-wide compatibility rewrite.
That candidate introduced new camera transactions into depth, atmosphere,
motion blur, image-space ordering, PBR/sky material arbitration, reset, and
diagnostics simultaneously, even though the last accepted OMV baseline was
already playtested without Atom. Production returns those non-shadow systems
to the accepted ownership paths and keeps the independently requested local
shadow fixes. Compatibility responsibility is now narrow: Atom owns its
complete temporary camera transaction and chains live predecessors; OMV owns
its established D3D stages without knowing Atom exists.

Static proof still cannot accept the image. Runtime acceptance requires Atom
camera off/on while checking stationary and moving sky, object and terrain PBR,
fog, volumetric lighting, bloom/HDR, shadows, menus/loading, reset/alt-tab, and
frame pacing. BaseObjectSwapper cold starts remain mandatory because the Atom
DLL layout changed even though no pre-Deferred operation or import was added.

Static closure passes all 104 explicit-target Atom tests, including distinct
and aliased camera-owner regressions, and the supported five-crate release
build. The optimized `atom.dll` is 6,814,953 bytes with SHA-256
`9da56cc6e2cc12e8e21f14a235f967e781b6d75323ee47406967fd2963d9eaca`.
Against the runtime-rejected deployed artifact, all 320 normalized imported
symbols, 29 DLL table rows, three exports, directory sizes, and eight zero TLS
bytes remain unchanged. The current section sizes are `.text = 0x2A6930`,
`.data = 0x1F90`, `.rdata = 0x122A18`, `.eh_fram = 0x4F5E0`,
`.bss = 0x1AE0`, and `.reloc = 0x224CC`. This is static artifact identity,
not the required load-to-gameplay or visual acceptance.

### 2026-08-17 delta-only native sky-anchor correction

The installed distinct-transform candidate remained rejected: the finite sky
still moved with head bob. The earlier interpretation proved the second pointer
but assigned it too much ownership. Radare2 shows `0x00872B00` reads only child
zero's local translation at `+0x58` before copying it to Sky and Weather. It
does not consume the anchor's rotation or world transform.

Composing the same camera-space pose independently through the render camera
and child-zero bases can produce different translation deltas when those bases
differ. Atom now computes the exact local-translation delta produced on
`SceneGraph +0xAC` and transfers only that delta to child zero. It preserves the
anchor's base offset, local rotation, and complete world transform. Restoration
returns the one local translation exactly before recentering the finite roots.

The complete parent-route and live-predecessor ownership remain unchanged.
The change adds no graph update, allocation, lock, configuration value, worker,
or pre-Deferred operation. Existing distinct/aliased native transaction tests
pass, but they are not image evidence. Runtime acceptance still requires the
installed Atom camera off/on comparison with stationary and moving native sky.

### 2026-08-17 rejected local/world native sky-anchor correction

The installed local-only candidate was rejected because stars still moved with
head bob. The existing regression modeled the local-translation copy in
`0x00872B00`; it did not model the final matrix construction in
`SkyShader::UpdateConstants @ 0x00B89D80`. That routine subtracts the world
translation retained at `0x011F95D8` after copying the geometry/model
transform. The candidate incorrectly treated that pointer as child zero and
wrote both child-zero translations. The installed result rejected that
interpretation because stars still moved with head bob.

### 2026-08-17 CameraNode/NiCamera native sky correction

`BSSceneGraph::BSSceneGraph @ 0x00C517B0` proves child zero is a CameraNode and
the render NiCamera is stored separately at `SceneGraph +0xAC`.
`0x00872B00` reads only the CameraNode local translation when centering Sky and
Weather. Initialization at `0x0086D873..0x0086D88A` instead stores the NiCamera
in `0x011F95D8`, so `SkyShader::UpdateConstants @ 0x00B89D80` subtracts the
NiCamera world translation, not the CameraNode world field.

The scoped route now computes the composed NiCamera's world-translation delta
and adds exactly that delta to the distinct CameraNode local translation. It
does not alter the CameraNode world transform, rotation, or scale. Restoration
returns the CameraNode local translation exactly before Sky and Weather are
recentered; the aliased defensive path still mutates only the render camera.

The regression reproduces the complete observable translation path: distinct
CameraNode and NiCamera state, native root preparation, and the SkyShader
camera-relative matrix. The rejected local-plus-world transaction leaves a
`[2, -2, 0]` residual under a rotated two-unit head-bob pose; the corrected
transaction leaves zero. This closes the specific stars-follow-headbob defect
with behavior, while ordinary installed visual quality remains a separate
playtest concern.

## Rejected designs

### Attach the camera directly to the animated head

Rejected. Animation packs, skeletons, breathing, recoil, and correction nodes
would become unbounded camera input. Head motion is noisy, can clip geometry,
and is not a stable gameplay target. Enhanced-camera-style body rendering is a
separate feature.

### Smooth mouse input

Rejected. FNV's native path and Atom Input already provide a direct final
heading seam. Temporal filtering adds input latency and makes precision depend
on frame time. Smoothness belongs in additive body/viewmodel response.

### Write the common UpdateCamera output

Rejected as the presentation seam. The common commit is shared by camera modes
and occurs before later player gameplay consumers. It cannot currently prove
visual-only ownership.

### Use keyboard input as bob cadence

Rejected. It bobs against walls, during blocked movement, and at the wrong
controller magnitude. Actual support-relative locomotion is required.

### Copy world motion to weapon

Rejected by live play. FNV projects the close-up weapon through a separate
camera, so copying an equal world-head transform makes the hands move farther
on screen than the scene. Atom leaves native weapon locomotion intact and adds
only a smaller look-inertia pose whose gain, aim attenuation, and authored
animation ownership are independent.

### Add procedural noise everywhere

Rejected. Gait is periodic, landing is event-driven, recoil belongs to combat,
and breathing is state-driven. Unstructured noise obscures cause and is harder
to make accessible.

### Detect camera mods by filename

Rejected by repository policy and design. Atom chains live hook capabilities,
checks native state, and exposes independent gains. It never patches, disables,
or reorders another mod based on identity.

## Final recommendation

Build Atom First Person as a render-scoped, additive camera wrapper over the
native control pose. Preserve immediate look and native gameplay truth; drive a
distance-phased, support-relative world gait plus event-based landing; leave
native weapon locomotion intact; put only bounded inertia into the
separate viewmodel listener; and make zero gains exact native behavior.

The native renderer provides the right structural split for this design. The
remaining hard problems are not waveform creativity: they are velocity and
state proof, positional clearance, reticle/parallax truth, hook-chain ordering,
and runtime comfort. Phase 0 closes those before the first world-camera write.

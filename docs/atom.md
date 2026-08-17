# Atom gameplay overhaul

Status: Atom Input, first-person head/viewmodel motion, native physical
Ballistics, and third-person follow/360 movement/aim convergence are
implemented. Physical Ballistics is runtime accepted and defaults on; camera
features retain their separately documented gates.

## Purpose and scope

Atom is Psycho's gameplay-oriented xNVSE mod for an urban-survival, hardcore
Fallout: New Vegas experience. Its ownership includes combat, NPC AI, loot and
weapon balance, camera behavior, input controls, and vanilla gameplay mechanic
fixes.

Atom is ESP-less. The shipped mod contains no ESM, ESP, or ESL and reserves no
load-order slot. Future gameplay systems must classify forms dynamically from
runtime type, data, capabilities, and relationships so mod-added items,
weapons, actors, and other records participate without per-plugin patches. A
record identity check is allowed only for a separately documented mechanic
which inherently targets that exact record; it is not Atom's generic
compatibility strategy.

The first gameplay milestone implements an engine-semantic input wrapper. It
does not replace DirectInput or XInput, and it does not claim that every source
of perceived input latency has been removed. The research and design contracts
are in `docs/fnv_actor_input_contract.md` and
`docs/atom_input_wrapper_design.md`.

The implemented third-person milestone replaces presentation-only skeleton
rotation with one explicit camera, locomotion, facing, VATS, collision, and aim
ownership model. Its native evidence, compatibility audit, staged
implementation, behavioral tests, and Proton acceptance plan are in
`docs/atom_third_person_camera_plan.md`. The separate first-person head and
viewmodel wrapper remains implemented under the staged contract in
`docs/atom_first_person_camera_design.md`.

The first combat milestone is a compatibility-first Ballistics Core. Its
shot-to-impact observer, MissileProjectile update probe, and native
physical policy are implemented. Eligible ordinary hitscan missiles are routed
through FNV's physical branch during native initialization; native simulation
then moves them through space. Atom does not tune damage, mutate shared forms
or completed projectile objects, or replace collision and impact ownership.
Implementation state, gates, data model, tests, and playtest matrix are in
`docs/atom_ballistics_core_plan.md`.

## User-visible behavior

Atom appears in MCM Extender through four feature categories: Input, Camera,
Ballistics, and Diagnostics. Input contains General, Mouse, Controller, and
Triggers sections. Camera contains First Person, Third Person, Third Orbit,
and Third Movement sections. Every row is either a section header or a real
persisted setting; there are no overview, status, readiness, module, or planned
feature rows. Every visible label, help value, and choice uses one to three
words so it remains inside the MCM viewport. Atom Input and both camera systems
remain disabled by default because this expanded artifact still needs the
required in-game startup and behavior acceptance.

When enabled, the current input milestone:

- retains FNV and xNVSE as the authoritative device owners;
- captures one coherent keyboard, mouse, and controller snapshot after the
  normal xNVSE-aware native sample;
- applies a stateless direct transform at final player heading X/Y calls;
- publishes radial controller sticks and hysteretic triggers after a neutral
  live-toggle handoff, while bypassing FNV's second camera deadzone/curve;
- resolves all 28 FNV actions from simultaneous keyboard, mouse, and controller
  bindings with explicit gameplay, menu, and focus state;
- captures ordered keyboard events through xNVSE, preserves subframe taps for
  bound gameplay controls, and mirrors those events to later native consumers;
- leaves menu side effects, console/text entry, Pip-Boy pointer behavior,
  wheel, fly camera, movie, and focus-flow device ownership native;
- optionally records bounded sample-to-camera-consumer and
  sample-to-`OnFramePresent` histograms.

`Native` returns the chained final heading float bit-for-bit. `Direct` scales
that native final heading. `Fallout 4 Direct` rebuilds it from relative counts
with the supplied Fallout 4 installation's nominal
`0.0300 * 0.021 = 0.00063` radians-per-count product. None of the profiles adds
smoothing, acceleration, temporal history, or frame-time multiplication. The
Fallout 4 unit/context equivalence remains an explicit inference awaiting A/B
playtest, hence the preset is not named `Exact Fallout 4`.

The normal input sample has not been moved later. Static research proved that
`0x0086F390` couples the sample to controller and 28-control maintenance, while
moving that entire helper would cross unproven menu/UI/world consumers. Atom
does not ship a speculative late-sample toggle or register Raw Input.

Ballistics is enabled by default. `Physical Rounds` controls capability-based
conversion of ordinary discrete hitscan MissileProjectiles to FNV's native
physical path. Beams, flames, continuous emitters, explosives, grenades,
thrown projectiles, targeting/VATS-like launch policies, unknown state, and
invalid data remain native. Atom scopes the launch by callback thread and live
projectile form, chains the initializer's current hitscan-policy owner once,
and changes only a true predicate answer to false. FNV derives the complete
physical runtime state itself. Forms, completed objects, damage values, source
attribution, collision, effects, and `ApplyHit` remain native.

`Ballistics Trace` enables bounded launch-to-contact/update diagnostics, and
`Write Ballistics` emits one summary after MCM closes on a false-to-true
request edge. The wrappers chain the native projectile-count, launch,
hitscan-policy, hit-build, `ApplyHit`, collision-effect, and MissileProjectile
update owners exactly once. Update telemetry distinguishes the immutable
launch-time selection from later live runtime markers and reports candidates,
forced physical rounds, already-physical predecessor results, context rejects,
policy misses, and capacity failures. The live hitscan/physical marker pair is
reported separately as hitscan-only, physical-only, both, or neither.
Policy-scope exhaustion or an admission mismatch leaves that individual round
native.

First-person presentation is also disabled by default. When enabled, Atom
combines FNV's support-relative controller velocity with the processed native
PlayerMover direction bits after UpdateCamera. Velocity supplies magnitude;
the direction bits are a separate hard gait gate, so persistent physics
velocity cannot manufacture head bob while the mover is idle. Engine time then
drives filtered distance-phased gait, one-shot landing compression, and
bounded look inertia. A 1.6 Hz full-stride ceiling prevents extreme SpeedMult
values or physics noise from becoming rapid camera shake. The Stable head
listener applies only sub-unit lateral/vertical translation around the world
draw; it adds no rotation or fore/aft parallax, and aiming suppresses the world
pose immediately. The separately rendered hands/weapon camera inherits that
exact head translation, then receives a smaller relative gait/look/landing
layer only while no authored weapon action owns presentation. Every non-None
native animation action suppresses the relative layer immediately, with an
analytic release after the action ends. The world guard recenters FNV's finite
Sky and Weather graphs with the posed camera, while the hands guard performs
its sub-unit work in an origin-relative frame to avoid large-coordinate `f32`
steps. Scoped guards restore both cameras and every temporarily moved root
before their wrapped calls return.

The `First Person` MCM page exposes `First Person`, `Head Motion`, `Weapon
Motion`, `Land Motion`, and `Aim Motion`. `Head Motion = 0` removes common head
motion. `Weapon Motion = 0` removes only motion relative to the head, so hands
remain registered whenever head motion is nonzero.

Third-person follow is disabled by default. When enabled, Atom requires one
stable no-write native frame before acquiring an ownership epoch, follows the
logical player pivot through dead/soft zones, bounded horizontal lookahead,
and analytic damping, and composes the result into FNV's desired endpoint while
preserving the native collision pivot. Follow-only mode retains native
actor/view coupling.

`360 Movement` separately admits immediate free orbit, camera-relative reuse
of FNV's existing movement vector, low-direction-bit policy, and bounded
authoritative actor facing. Because the native yaw setter is void and may
normalize or reject a request, Atom reads raw Actor `rotZ` after invoking that
setter and compensates movement only against the heading FNV will actually
consume. Native magnitude and all higher movement/action flags remain
unchanged. Every VATS mode, POV transition, TFC, menu, disabled
control, furniture/scripted action, death/ragdoll, incomplete world state,
cell change, and explicit external owner revokes the complete output set before
another Atom write. `Drawn 360` selects relaxed drawn locomotion; aim, fire,
block, and ready/reload intent still select view-facing combat policy. On AIM
or Combat entry, Atom hands the existing logical view yaw to the authoritative
Actor setter and immediately compensates PlayerCharacter's camera offset. The
body therefore faces the already-rendered direction without moving the camera.
Subsequent horizontal AIM input stays on FNV's Actor-yaw route and Atom adopts
the raw result, while non-aiming Explore input remains camera-only.

Returning from Pip-Boy, menus, VATS, or another native camera owner requires
150 ms of uninterrupted normal gameplay before Atom begins its existing
no-write seed frame. Any renewed owner restarts that interval. On the first
camera-only frame Atom also checks live Actor `rotX`, so a native interruption
cannot erase cleanup of a stale AIM pitch merely by clearing temporal state.

When both native aim callsites are unowned at deferred admission, Atom reuses
the normal ViewCaster result, resolves the real weapon projectile node, and
converges the native muzzle-origin shot while preserving the sampled native
spread delta. Unsupported projectile types, stale view samples, first person,
VATS, TFC, other aim owners, or missing native context remain exact native
behavior. Near cover remains authoritative because the original projectile is
still launched from the real muzzle through its normal collision path.

## Source ownership

| Path | Ownership |
|---|---|
| `atom/src/lib.rs` | xNVSE query/load exports, load-owned service capture, and lifecycle message routing. |
| `atom/src/runtime.rs` | Deferred logger/config/input admission plus one-shot post-Deferred first-person render admission. |
| `atom/src/config.rs` | One-file top-level deserialization and independent subsystem snapshots. |
| `atom/src/ballistics/mod.rs` | Ballistics config, deferred admission, lifecycle, and requested summaries. |
| `atom/src/ballistics/adapter.rs` | Fail-closed thread/form policy scope with nested-launch restoration. |
| `atom/src/ballistics/native.rs` | Audited x86 ABIs, form/runtime views, addresses, and capability classification. |
| `atom/src/ballistics/hooks.rs` | Caller fingerprints and one rollback-capable callsite/vtable transaction. |
| `atom/src/ballistics/context.rs` | Immutable pointer-free launch and projectile-profile values. |
| `atom/src/ballistics/flight.rs` | Constant-acceleration shadow math and bounded chord subdivision. |
| `atom/src/ballistics/pool.rs` | Fixed open-addressed correlation table and generation handling. |
| `atom/src/ballistics/telemetry.rs` | Saturating launch/contact/update counters, histograms, and thread identities. |
| `atom/src/camera/config.rs` | First-person MCM deserialization, bounds, and coherent live snapshot. |
| `atom/src/camera/motion.rs` | Support-relative gait, landing event, aim blend, and analytic look inertia. |
| `atom/src/camera/pose.rs` | Native column-basis additive pose composition and finite checks. |
| `atom/src/camera/state.rs` | Nonblocking update writer, ownership epochs, and coherent render publication. |
| `atom/src/camera/native.rs` | First-person owner gates, audited helpers/offsets, finite-sky transaction, origin rebase, and exact restoration. |
| `atom/src/camera/hooks.rs` | Shared complete UpdateCamera entry plus a post-Deferred rollback-capable first-person render group. |
| `atom/src/camera/third_person/mod.rs` | Third-person public API, fixed temporal state, lifecycle, and output admission. |
| `atom/src/camera/third_person/config.rs` | Camera/movement INI sections, bounds, and coherent atomic publication. |
| `atom/src/camera/third_person/ownership.rs` | Deterministic native/acquire/explore/combat/release epochs. |
| `atom/src/camera/follow.rs` | Dead/soft zones, horizontal lookahead, and analytic follow springs. |
| `atom/src/camera/movement.rs` | Immutable camera-relative intent, post-setter compensation, vector/flag policy, and bounded facing math. |
| `atom/src/camera/aim.rs` | Render-camera selection ray, logical direction, and spread-preserving convergence math. |
| `atom/src/camera/third_person/native.rs` | Hard owner gates, audited view/pitch helpers, virtual facing, camera origin, and real-muzzle reads. |
| `atom/src/camera/third_person/hooks.rs` | Independent follow/movement transactions, reticle alignment, and optional launch convergence. |
| `atom/src/input/config.rs` | Serde/serini section model, validation, bounds, and atomic live config. |
| `atom/src/input/frame.rs` | Native value types, derived edges, controller processing, and coherent frame publication. |
| `atom/src/input/actions.rs` | 28-action binding resolution, mixed devices, focus epochs, contexts, and coherent publication. |
| `atom/src/input/buffered.rs` | Ordered DirectInput keyboard capture, native mirror, peek/overflow behavior, and health counters. |
| `atom/src/input/hooks.rs` | Fingerprints and transactional callsite, entry, and pointer-slot chaining. |
| `atom/src/input/native.rs` | Audited FNV offsets, globals, layouts, and native reads. |
| `atom/src/input/mouse.rs` | Stateless player-camera mouse transform. |
| `atom/src/input/controller.rs` | Radial stick shaping and trigger hysteresis. |
| `atom/src/input/telemetry.rs` | Optional QPC markers and saturating fixed histograms. |
| `atom/mcm/Atom.json` | The shipped MCM Extender UI and persistence contract. |

Gameplay hooks belong in Atom, not `psycho-engine-fixes-helper`, OMV, Syringe,
or an ESP. Atom reuses `libpsycho` for the logger, WinAPI wrappers, validated
memory reads, ownership-aware callsite hooks, and rollback transactions.

## xNVSE lifecycle and startup boundary

`NVSEPlugin_Query` publishes plugin version 2 and admits only the normal
FalloutNV.exe 1.4.0.525 runtime. It rejects the editor, no-gore executable, and
other packed runtime versions before any fixed address can be reached.

`NVSEPlugin_Load` constructs the xNVSE callback owner and captures the runtime
directory, event-manager wrapper, and player-controls interface while xNVSE
identifies Atom as the currently loading plugin. The registered lifecycle
closure owns those services and the callback thunk for the process lifetime.
The player-controls interface is captured here because it is an xNVSE service,
but its read-only function-pointer view is not constructed or called until
`DeferredInit`. Load does not read configuration, initialize Psycho's logger,
query QPC, inspect native memory, or install a hook.

This ownership split is mandatory. `NVSEInterface::from_raw` obtains the plugin
handle as part of construction, and xNVSE permits `GetPluginHandle` only from a
plugin's Query or Load handler. Deferred callbacks consume the wrappers acquired
during Load and never reconstruct an `NVSEInterface`.

At `DeferredInit`, Atom performs this ordered transaction:

1. initialize `libpsycho::logger::Logger` as `atom-latest.log`;
2. resolve `Data/config/Atom/Atom.ini` from xNVSE's runtime directory;
3. deserialize and validate the unified current MCM configuration;
4. initialize QPC-domain telemetry bounds outside the hook path;
5. validate the fixed data globals and immutable caller contexts;
6. capture every Deferred-owned callsite, entry, and keyboard-slot predecessor;
7. enable the complete input bridge in one rollback-capable transaction;
8. obtain the load-captured xNVSE combined-control reader, validate and install
   the complete shared UpdateCamera entry, then arm the five first-person
   render calls for post-Deferred installation; the reader uses xNVSE's
   established combined-mask predicate when its optional complete-mask slot is
   null;
9. validate the third-person hard-owner data contract, independently admit the
   follow transaction and complete heading/movement/facing transaction, admit
   the reticle when movement is available and its call remains vanilla, then
   additionally admit launch convergence only when spawn also remains vanilla;
10. independently fingerprint and enable the five Ballistics callsites plus
   MissileProjectile update slot in one rollback-capable transaction;
11. subscribe to MCM Extender's `MCMExtUpdate` event for menu-close reloads.

xNVSE dispatches DeferredInit listeners synchronously, then emits MainGameLoop
from the same main-loop hook before world rendering. On that first subsequent
MainGameLoop, Atom validates and transactionally installs its two world and
three first-person render calls. Waiting for the completed DeferredInit walk
lets Atom capture any compatible graphics wrappers as predecessors and keep
one temporary camera pose around their complete pre-render, native-render, and
post-render work. A fixed atomic gate makes installation one-shot; later
MainGameLoop callbacks perform one acquire load and return.

If native input validation or installation fails, the input transaction leaves
its callsites under their prior owners and Atom initialization fails. If only
camera or Ballistics validation/installation fails, that subsystem transaction
restores every earlier callsite and Atom Input remains active. If only `MCMExtUpdate`
subscription fails, installed modules stay active and settings apply after
restart. Atom never identifies, inspects, patches, disables, or reorders
another mod by name.

This milestone adds code, imports, atomics, `OnceLock`/`LazyLock` storage, Serde/serini,
and Psycho logger code to Atom's final DLL. Those are loader-visible footprint
changes even though their operational first use is deferred. Static checks and
a release build therefore cannot establish startup safety. The required
Proton/BaseObjectSwapper load-to-gameplay acceptance remains mandatory under
`docs/nvse_startup_phase_safety.md`.

### 2026-08-16 DeferredInit crash and correction

The first runtime playtest failed before native input validation or hook
installation. `atom-latest.log` ended immediately after `[INIT] Atom
DeferredInit started`. `nvse.log` then recorded xNVSE's assertion from
`PluginManager.cpp:498`: a plugin called `NVSEInterface::GetPluginHandle`
outside its Query/Load handlers. CrashLogger reported the halt through three
Atom frames from xNVSE's main-loop `DeferredInit` dispatch.

Code inspection proved the direct cause: Atom retained only the raw xNVSE
pointer during Load and called `NVSEInterface::from_raw` from `DeferredInit`.
That constructor unconditionally obtains the plugin handle before querying the
messaging interface. The failing build was the reviewed DLL with SHA-256
`faea3d86f6bf80bc77ca6e87dc527f935214d6eceb7bff19de9b7707f2508d7e`.

The correction follows OMV's process-lifetime callback ownership: Atom creates
one `PluginContext` during Load, obtains the runtime directory and event-manager
wrapper there, and moves those values into the registered lifecycle closure.
`DeferredInit` now receives borrowed, previously acquired services. It performs
no plugin-handle acquisition and still defers config reads, logger startup,
native validation, and hook installation. The corrected `c489be...` artifact
subsequently reached gameplay and is the accepted startup comparison described
under Runtime evidence. The expanded input bridge is a newer material delta and
requires its own playtest.

### 2026-08-16 player-controls interface compatibility correction

The first combined-camera runtime reached `DeferredInit` but logged
`GetDisabledPlayerControls function pointer is NULL` and left both camera
systems native. This was an Atom admission defect, not a missing user
dependency. The repository's vendored xNVSE source proves that
`libnvse/xnvse/nvse/nvse/PluginManager.cpp` publishes only
`DisablePlayerControlsAlt`,
`EnablePlayerControlsAlt`, and `GetPlayerControlsDisabledAlt` in
`g_NVSETogglePlayerControlsInterface`; the later
`GetDisabledPlayerControls` structure slot is therefore zero-initialized.
`libnvse/xnvse/nvse/nvse/Hooks_Gameplay.cpp` proves that the published
predicate returns true when any bit in `flagsToCheck` intersects the selected
per-mod and/or vanilla disabled-control state.

`libnvse::api::player_controls::PlayerControlsReader` now accepts either read
capability. Its camera hot-path query prefers the complete mask when present
and otherwise passes Atom's complete relevant-control mask to the established
predicate in one native call. Full-mask callers can reconstruct all 16 known
flags with allocation-free single-bit queries. Admission still fails closed
when both read capabilities are absent. Predicate-only and complete-mask-only
unit tests exercise the two interface shapes without shared mutable fixtures.

The correction does not move service acquisition, pointer reads, native
validation, hooks, configuration parsing, or logging before `DeferredInit`,
and it adds no import, thread, worker, TLS value, or file access. It does alter
code/data layout in the final DLL, so the replacement artifact below still
requires the normal Proton/BaseObjectSwapper replay. The expected result is
that the prior combined-player-control warning disappears and the camera
availability logs are reached; that runtime result is not yet observed.

### 2026-08-16 shared MenuMode fingerprint correction

Artifact `6f6c2a...` confirmed that player-controls admission now succeeds, but
first-person camera admission then rejected the live `0x00702360` entry because
its first three bytes no longer matched the vanilla `MenuMode` prologue. The
warning did not capture the replacement bytes or its owner, so the only proven
runtime fact is that the entry had changed by `DeferredInit`.

Fresh radare2 analysis of the identified FalloutNV.exe confirms that this
no-argument cdecl predicate has 55 native callers and no side effects. Its
entire native result is derived from InterfaceManager global `0x011D8A80`,
active byte `+0x00`, and mode `+0x0C`: active and outside gameplay mode 1 means
a blocking menu owns presentation. First-person camera admission now validates
the global slot and reads those fields in its current main-thread callback. It
no longer requires byte identity or alters the shared helper entry. Strict
fingerprints remain on Atom's private body-dependent helpers.

This correction adds no hook, import, thread, worker, TLS value, file access,
or pre-`DeferredInit` engine operation. It changes final code/data layout and
therefore produces another exact artifact requiring the normal startup replay.

### 2026-08-16 first-person callsite capability correction

The `141f6947...` replacement reached gameplay and initialized Atom
successfully, accepting that artifact's startup footprint. First-person
admission still stopped at a caller-context fingerprint beginning at
`0x00870B10`, immediately before the direct RenderFirstPerson call at
`0x00870B21`. The on-disk supported executable retains the researched bytes;
the runtime warning proves only that the live surrounding instructions differ.

The same run closes the capability boundary without inspecting another mod.
One second after Atom's rejection, repository-owned OMV admitted the exact same
three RenderFirstPerson direct calls through `Rel32CallHookContainer`, reported
`first_person=true`, and subsequently completed 8,476 first-person depth stages
with zero scene-transaction failures. Atom's wrapper forwards all receiver and
stack arguments unchanged and uses no value from the surrounding setup.

The camera caller group now follows the existing OMV and documented Atom
contract: each supported-runtime address must contain a readable direct `E8`
call to an executable live predecessor. The shared callsite abstraction
captures and chains that typed predecessor, detects changes before activation,
and rolls back without overwriting a later owner. A missing direct call,
invalid predecessor, ownership race, or partial transaction still fails closed.
Private native helpers whose bodies Atom consumes retain strict fingerprints.
The correction removes only redundant caller-context constants and validation;
it adds no import, hook, static owner, TLS value, thread, worker, file access,
configuration field, or earlier lifecycle operation. Its final DLL layout is a
new pre-Deferred footprint and still requires the normal Proton replay.

### 2026-08-16 input context ownership correction

The same `141f6947...` run showed that the camera modules had been corrected to
read the proven InterfaceManager fields, but Atom Input still called the live
`0x00702360` entry once per sample to classify its action context. That was an
inconsistent and incomplete correction: third-person ownership consumes the
published action context, so a changed shared helper could keep the entire
camera state machine native even though third-person hook installation logged
as available. The log does not record the replacement helper's return value,
so this is a repository-proven policy defect rather than proof about another
provider's behavior.

Atom Input now validates the `0x011D8A80` global slot at `DeferredInit` and
uses the same exact side-effect-free predicate as both camera modules:
manager is valid, active byte `+0x00` is nonzero, and mode `+0x0C` is not
gameplay mode 1. It no longer executes the mutable helper entry. A focused unit
test protects inactive, gameplay, and blocking-menu cases. The change adds no
hook, import, static initializer, TLS value, thread, worker, file access, or
earlier engine operation; it changes final code/data layout and therefore still
requires a new Proton/BaseObjectSwapper runtime replay.

### 2026-08-16 third-person control correction

The installed `3b78b995...` artifact is invalidated by the user's report of
vertical-only look and diagonal, directionally broken movement. Static reverse
engineering found that it returned logical yaw from the native pitch call at
`0x0094AE94 -> 0x00931D70` and compensated movement before changing the actor
heading that native code subsequently used.

The retained log proves both broken paths executed: startup captured
`yaw=0x00931D70`, followed by 4,845 camera overrides and 4,849 movement
overrides. This was active incorrect logic, not disabled configuration.

The same log recorded zero calls through the old `0x0093FA08` single-caller
wrapper while the UpdateCamera interior executed 10,542 heading calls, so that
callsite cannot own the scope. Atom now leaves the pitch call untouched and
reuses its complete `0x0094AE40` entry wrapper while a pointer-slot hook chains PlayerCharacter adjusted
heading at vtable `+0x2BC` (`0x0108ACF8`). Only the matching player inside that
owned scope receives Atom view heading. Movement now invokes its bounded
facing setter first, re-reads the resulting raw Actor `rotZ`, and compensates
the actor-local vector against that observed heading. The native raw-`rotZ`
transform at `0x0092F260` therefore produces exactly the intended
camera-relative world vector even if the void setter normalizes or rejects the
request. The focused public regression composes both
matrices across nonzero, opposing, diagonal, and wrap-boundary headings. No
corrected in-game result is claimed without runtime evidence.

All 75 Atom tests pass on explicit `i686-pc-windows-gnu`, including 8 public
third-person tests. All-target Atom Clippy passes with warnings denied and the
release build succeeds. The 6,790,904-byte candidate has SHA-256
`3917d677700814aa982cf1577e7f5a7c90af6770d3ba4c74fa98d9bbef4a739e`.
Relative to the broken `3b78b995...` runtime footprint, all 320 imported
DLL/symbol pairs, three exports, nine section roles, import/export/TLS
directory sizes, TLS callback roles, and the eight-byte `.tls` section remain
unchanged. Code/data/relocation layout and image size change because the
invalid pitch-call owner is replaced by a chained adjusted-heading pointer-slot
owner and fixed atomics. The complete entry owner is shared with first person.
Those owners are first touched
at the established `DeferredInit` boundary; static PE agreement still does not
claim startup acceptance.

### 2026-08-16 third-person ownership hardening

A comprehensive implementation review found four additional defects in the
unaccepted correction candidate:

- follow and movement were admitted as one hook transaction and some runtime
  gates still required follow even when only `360 Movement` was enabled;
- first-person render validation owned the complete UpdateCamera entry, so an
  unrelated first-person mismatch could suppress all third-person behavior;
- follow and recenter state mutated from separate native callbacks, allowing
  one UpdateCamera call to observe different headings or offsets; and
- movement compensation treated the requested setter argument as successful
  even though the native setter ABI returns no result.

The corrected ownership model installs the shared complete UpdateCamera entry
first. First-person rendering, follow, movement/facing, and aim then have
separate admission boundaries. Follow and movement settings remain independent
through configuration, ownership, and output gates; aim is conditional only
on the complete movement seam. Consequence-specific startup messages report
exactly which capability remains native.

Before chaining native UpdateCamera, Atom now advances recenter and analytic
follow exactly once per input frame from `TimeGlobal::secondsPassed`, then
publishes one immutable heading/follow snapshot for every scoped heading and
collision query. Follow-only mode refreshes adjusted native heading every
frame. Scope identity includes player or mover, owner thread, generation, and
a monotonic reset generation; a lifecycle reset cannot publish stale prepared
state or let an old guard clear a newer reentrant scope.

Movement is a two-stage operation. It first captures immutable world intent
and an optional facing target, invokes the live native yaw setter, samples raw
Actor `rotZ`, and only then resolves the actor-local vector consumed by
`0x0092F260`. Invalid or unavailable post-setter state resets the ownership
epoch and chains native movement. Internal tests cover one temporal advance per
input frame and follow-only heading refresh; public tests cover all four
follow/movement toggle combinations, analytic follow behavior, and rejected or
normalized facing requests. These are code and automated-test results, not a
claim of corrected in-game behavior or startup acceptance.

Validation for this candidate passes all 87 Atom tests under Wine staging
11.15 on explicit `i686-pc-windows-gnu`: 43 library/ABI/state tests, 5 public
Ballistics tests, 12 public first-person tests, 14 public Input tests, 2 shipped
MCM tests, and 11 public third-person tests. Atom all-target Clippy passes with
warnings denied, the Atom release build passes, and the complete supported
five-package release build passes.

The resulting `atom.dll` is 6,801,376 bytes with SHA-256
`d0604bc6137e6b3e1cb84db80c1426dffccdfae86890e56066bdddf82f84a43b`.
Against the last load-to-gameplay artifact retained as
`.reports/artifacts/atom-native-policy-accepted-e34c81bf.dll`, all 29 import
descriptors and 320 imported symbols remain identical and ordered, as do the
three exports, nine section roles, `0x2B04` import directory, `0x8C` export
directory, `0x18` TLS directory, eight-byte `.tls` section, and four TLS
callback roles/order. Code/data layout changes: `.text = 0x2A4F30`, `.data =
0x1E88`, `.rdata = 0x122698`, `.eh_fram = 0x4F3C0`, `.bss = 0x1B78`, `.reloc =
0x22304`, and image size is `0x445000`. This is a material pre-Deferred
footprint delta and is not promoted to a startup or gameplay-accepted baseline
by static evidence.

## Native hook contract

The fixed executable is FalloutNV.exe 1.4.0.525, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

| Purpose | Boundary | Native target | ABI |
|---|---:|---:|---|
| Normal input sample | `0x0086F39E` | `0x00A23010` | x86 `thiscall(input_owner) -> void` |
| Player-camera mouse X | `0x00945995` | `0x00A239E0` | x86 `thiscall(input_owner, axis) -> i32` |
| Player-camera mouse Y | `0x009459A8` | `0x00A239E0` | x86 `thiscall(input_owner, axis) -> i32` |
| Final heading X | `0x00945F90` | `0x00931D30` | x86 `thiscall(player, f32) -> void` |
| Final heading Y | `0x00945FD8` | `0x00931E50` | x86 `thiscall(player, f32) -> void` |
| Camera deadzones | four calls `0x009455EC`-`0x00945707` | `0x00EC7D40` | x86 `cdecl(i32) -> i32` |
| Camera exponents | `0x00945839`, `0x0094587C` | `0x0043D4D0` | x86 `thiscall(setting) -> *i32` |
| Camera minimum | `0x009458A4` | `0x00403E20` | x86 `thiscall(setting) -> *f32` |
| Bound actions | entry `0x00A24660` | captured trampoline | x86 `thiscall(owner, control, state) -> i32` |
| Keyboard data | live vtable slot `+0x28` | captured capability | x86 COM `GetDeviceData` |
| Shared complete UpdateCamera scope | entry `0x0094AE40` | captured trampoline | x86 `thiscall(player, u8, u8) -> void` |
| Third-person adjusted heading | vtable slot `0x0108ACF8` (`+0x2BC`) | captured live target (`0x00953F20` native) | x86 `thiscall(player, u8) -> f32` |
| Follow collision input | `0x0094B7D2` | `0x0094A0C0` | x86 `thiscall(player, desired*, pivot*, bool) -> void` |
| PlayerMover scope | entry `0x009E9E50` | captured trampoline | x86 `thiscall(mover, dt) -> void` |
| Movement request | `0x008A6339` | `0x0092F260` | x86 `thiscall(actor, dt, vector*, flags) -> process*` |
| Reticle ray | `0x0070C130` | `0x00631D60` | x86 `thiscall(caster, start*, direction*, range, distance*, alternate*) -> reference*` |
| Projectile spawn | `0x005245BD` | `0x009BCA60` | x86 `cdecl`, exact 14-argument ranged-launch ABI |

Atom fingerprints private helpers and caller contexts whose exact bodies it
consumes, but the first-person render group requires only the proven typed
direct-call capabilities because its wrappers forward every argument unchanged.
No callsite requires its displacement to still name the vanilla target. The
target present at DeferredInit becomes Atom's typed predecessor, preserving
capability-based chaining. The keyboard slot is resolved from the live input
owner and chained without identifying its module owner. All writes occur at
DeferredInit, when targets are quiescent, because x86 executable writes are not
atomic.

The sample detour calls its predecessor first, then copies:

- keyboard current `input_owner + 0x18F8`, 256 bytes;
- keyboard previous `input_owner + 0x19F8`, 256 bytes;
- current `DIMOUSESTATE2` at `+0x1B24`, 20 bytes;
- previous `DIMOUSESTATE2` at `+0x1B38`, 20 bytes;
- current/previous 16-byte XInput state at `0x011F35A8`/`0x011F35B8`;
- 28 keyboard, mouse, and active XInput bindings at `+0x1B94`, `+0x1BB0`,
  and `+0x1BE8`;
- controller mode, foreground ownership, and the proven InterfaceManager
  `MenuMode` fields.

Mouse getter detours retain the chained relative counts. The later heading
detours receive FNV's final float: disabled/`Native` returns it unchanged,
`Direct` scales it, and `Fallout 4 Direct` derives a fractional heading from
the retained count. The Y transform owns final inversion while accounting for
the vanilla `bInvertYValues` value at `0x011E0A60`. Wheel call `0x009459BB`
remains native.

Controller enable/disable waits for a physically neutral sample. When active,
Atom writes only FNV's current XInput slot after the engine has already copied
the preceding processed state to `previous`. Buttons and packet identity are
unchanged. Dynamic deadzone/setting call hooks turn the later player-camera
transfer into identity; inactive paths call their exact predecessors.

The keyboard event mirror retains the newest 32 complete 20-byte events. It
drains only while Atom Input is enabled, calls xNVSE's current wrapper first,
and answers later native normal/peek requests in order. The bound-action entry
adapter opens only after the current normal helper returns and closes at
`OnFramePresent`, preventing stale events from being replayed during FNV's
internal control-maintenance loop. Native nonzero results win and menu control
14 always passes through because its provider owns a side effect.

Raw disassembly evidence and the established field contract live in
`analysis/radare2/output/perf/fnv_actor_input_contract.txt`.

## MCM Extender and configuration ownership

The installed menu is `Data/MCM/Atom.json`. Its DLL requirement uses Atom
plugin version 2, so a stray menu cannot advertise a plugin which did not load.
MCM persists values to `Data/config/Atom/Atom.ini`.

The page hierarchy follows user-facing features rather than implementation
modules:

| Page | Sections | Ownership |
|---|---|---|
| Input | General, Mouse, Controller, Triggers | All device processing and response settings. |
| Camera | First Person, Third Person, Third Orbit, Third Movement | Both perspective modes and camera-relative movement. |
| Ballistics | Projectiles | Native physical-flight policy. |
| Diagnostics | Runtime, Ballistics | Opt-in counters, traces, and summaries. |

Section headers use MCM type `0`. Every interactive row owns exactly one INI
key, and informational type `7` rows are prohibited. This keeps the menu short
without separating controller settings from Input or perspective modes from
Camera.

MCM Extender is the sole writer. Atom uses `serini` 0.3 and Serde nested structs
to deserialize recognized sections, converts MCM's numeric `0/1` booleans, and
then applies documented bounds. Atom never serializes the INI. Unknown sections
and keys are ignored by Serde and remain preserved because Atom performs no
writeback. Missing files or fields use safe defaults. A malformed recognized
value, non-finite float, invalid boolean, or unknown mouse profile rejects the
entire candidate; live reload keeps the previous coherent configuration.

| Setting | Default | Accepted/bounded value |
|---|---:|---|
| `Ballistics:bEnabled` | `1` | `0` or `1` |
| `Input:bEnabled` | `0` | `0` or `1` |
| `Mouse:iProfile` | `2` | Native `0`, Direct `1`, Fallout 4 Direct `2` |
| `Mouse:fSensitivity` | `1.00` | `0.05` to `8.00` |
| `Mouse:fHorizontalScale` | `1.00` | `0.10` to `4.00` |
| `Mouse:fVerticalScale` | `1.00` | `0.10` to `4.00` |
| `Mouse:bInvertX/Y` | `0` | `0` or `1` |
| `Controller:fLeftDeadzone` | `0.15` | `0.00` to `0.95` |
| `Controller:fRightDeadzone` | `0.12` | `0.00` to `0.95` |
| `Controller:fResponseExponent` | `1.00` | `0.25` to `4.00` |
| `Controller:fAntiDeadzone` | `0.00` | `0.00` to `0.75` |
| `Controller:fOutputSaturation` | `1.00` | `0.25` to `1.00` |
| `Controller:fRightHorizontalScale` | `1.00` | `0.10` to `4.00` |
| `Controller:fRightVerticalScale` | `1.00` | `0.10` to `4.00` |
| `Controller:bInvertRightX/Y` | `0` | `0` or `1` |
| `Controller:fTriggerPress` | `0.12` | `0.01` to `1.00` |
| `Controller:fTriggerRelease` | `0.08` | `0.00` to at least `0.01` below press |
| `Diagnostics:bTelemetry` | `0` | `0` or `1` |
| `Diagnostics:bWriteSummary` | `0` | edge-triggered `0`/`1` request |
| `Diagnostics:bBallisticsTrace` | `0` | `0` or `1` |
| `Diagnostics:bBallisticsSummary` | `0` | edge-triggered `0`/`1` request |
| `FirstPerson:bEnabled` | `0` | `0` or `1` |
| `FirstPerson:fCameraMotion` | `0.65` | `0.00` to `1.00` |
| `FirstPerson:fWeaponMotion` | `0.65` | `0.00` to `1.00` |
| `FirstPerson:fLandingMotion` | `0.45` | `0.00` to `1.00` |
| `FirstPerson:fAimMotion` | `0.20` | `0.00` to `1.00` |
| `Camera:bFollowCamera` | `0` | `0` or `1` |
| `Camera:fFollowSpeed` | `7.50` | `1.00` to `20.00` |
| `Camera:fSoftZone` | `12.0` | `0.0` to `48.0` game units |
| `Camera:fLookAhead` | `8.0` | `0.0` to `32.0` game units |
| `Camera:bAutoCenter` | `1` | `0` or `1` |
| `Camera:fCenterDelay` | `1.25` | `0.00` to `5.00` seconds |
| `Camera:fCenterSpeed` | `120` | `15` to `360` degrees/second |
| `Camera:fZoomStep` | `2.0` | `1.0` to `10.0` game units |
| `Movement:b360Movement` | `0` | `0` or `1` |
| `Movement:fTurnSpeed` | `540` | `90` to `1080` degrees/second |
| `Movement:bDrawn360` | `0` | `0` or `1` |

Native defaults and every shipped MCM default are behaviorally compared by the
shipped-artifact test. Settings apply when MCM closes. To request another
telemetry summary, close MCM once with the request off, then close it with the
request on.

MCM Extender saves every cached INI before dispatching `MCMExtUpdate` with one
array argument. xNVSE's native-handler API accepts only an event name already
known to the event manager, while script listeners normally create this event
implicitly. Atom therefore attempts to define `MCMExtUpdate` with one `Array`
parameter and `ALLOW_SCRIPT_DISPATCH`, treats a registration collision as the
expected already-defined case, and then admits its native handler. The handler
reads `Atom.ini` once, validates the complete candidate, and atomically
publishes changed settings. It does not poll pause state or touch the file each
frame.

Atom depends on the user's installed MCM Extender stack and does not
redistribute or modify it, The Mod Configuration Menu, xNVSE, JIP LN NVSE,
JohnnyGuitar NVSE, ShowOff xNVSE, or User Interface Organizer assets.

## Coherent state, performance, and memory

The live configuration, device frame, action frame, and latest keyboard batch
use sequence-validated arrays of 32-bit atomics. Every payload access is atomic,
so publication does not rely on an `UnsafeCell` data race. MCM writes are rare
and main-thread owned.

One device frame stores 41 words; one action frame stores 59; one keyboard
batch stores 163. Capture performs bounded keyboard comparisons, 28 binding
resolutions, radial controller arithmetic, and fixed publication. The only
mutex protects the 32-event native keyboard mirror and is always acquired with
`try_lock`; contention forwards to the predecessor and increments a saturating
counter. There is no hook-path allocation, file I/O, blocking lock, logging,
second relative-mouse read, or mouse history.

The camera publishes one 14-word immutable frame and retains one fixed motion
generator behind a nonblocking exclusive lease. An accepted update performs
bounded native reads, scalar envelopes, and one set of waveform operations.
Render wrappers perform pointer/owner checks and, only for a nonidentity pose,
snapshot the fixed camera/root set. World motion updates and restores the two
native finite-sky graphs; viewmodel motion updates the first-person graph only
when another owner has not already rebased it. They allocate no Atom memory,
perform no file I/O or logging, and never block. Native graph-update cost is a
runtime acceptance measurement, not a statically claimed budget.

Third-person configuration is another coherent atomic snapshot. Its temporal
state is one fixed `UnsafeCell` protected by an atomic try-lease; contention or
reentrancy chains native output instead of waiting. Ownership, follow,
recenter, movement, facing, and aim samples are fixed size. The hook path adds
no allocation, blocking lock, file I/O, or routine log. It reuses FNV's one
normal ViewCaster invocation and adds no collision or aim cast.

Telemetry is off by default. When enabled, each admitted marker performs one
wrapped QPC call and 32-bit atomic updates. Bucket thresholds and the two-second
discontinuity limit are converted to QPC ticks at configuration time, so the
hot path performs no division. Counts saturate at `u32::MAX`. A requested
summary is emitted at `INFO` through Psycho's asynchronous logger after MCM
closes; Atom creates no separate report or telemetry file.

## Logging and failure visibility

Atom uses `libpsycho::logger::Logger` and writes the rotating
`atom-latest.log`. Messages use stable tags:

- `[INIT]` for normal lifecycle completion or a capability-wide failure;
- `[CONFIG]` for read-only load, live reload, and restart-only fallback;
- `[INPUT]` for hook admission and predecessor detail;
- `[INPUT_TELEMETRY]` for availability and requested summaries;
- `[CAMERA]` for first- and third-person admission, settings, and fallback;
- `[MOVEMENT]` and `[AIM]` for locomotion and convergence capability;
- `[BALLISTICS]` for physical-policy admission and requested summaries.

Normal milestones and requested summaries are `INFO`, validated predecessor
addresses are `DEBUG`, recoverable fallback is `WARN`, and a failed requested
capability is `ERROR`. Atom does not use `println!`, `eprintln!`, or direct
diagnostic file writes.

## Installation and release layout

`build_fnv.sh` builds Atom explicitly for `i686-pc-windows-gnu` and installs:

```text
<MO2 mods>/Atom/
|-- MCM/Atom.json
`-- NVSE/plugins/atom.dll
```

The GitHub release workflow produces `atom-nvse-<tag>.zip`:

```text
Data/
|-- MCM/Atom.json
`-- NVSE/plugins/atom.dll
```

The archive allowlist rejects an ESP, generated INI, report file, script, or
accidental development asset.

## Validation and runtime acceptance

The focused behavioral suite covers:

- real MCM-shaped serini deserialization, missing defaults, unknown data,
  invalid numeric booleans/profiles, non-finite rejection, and bounds;
- native mouse passthrough, direct odd symmetry, independent axes, repeated
  history-free output, and exact vanilla-Y inversion compensation;
- radial controller monotonicity, direction preservation, output bounds, and
  noisy trigger hysteresis;
- coherent keyboard/mouse/controller snapshot publication and derived edges;
- mixed 28-action resolution, merged device edges, meaningful-device policy,
  focus epochs, held-key suppression, and menu context transitions;
- ordered press/release tap preservation, non-consuming peek replay, and
  32-event overflow bounding;
- final float Fallout 4 scale and sub-native-threshold radial stick actions;
- filtered and cadence-capped support-relative gait, extreme-speed continuity,
  frame partitioning, translation-only Stable output, landing events, aim
  attenuation, invalid-state reset, bounded pose composition, and exact scoped
  native-transform restoration;
- native/acquire/explore/combat/release traces, all VATS ownership classes,
  cell and live-disable invalidation, analytic follow partitioning,
  camera-relative cardinal mapping, magnitude/high-flag preservation,
  shortest-angle facing, and spread-preserving convergence;
- native Ballistics form/runtime layouts, thread/form policy matching,
  repeated same-form initialization, earlier-owner physical results,
  nested-launch restoration, immutable launch-path correlation, four-way live
  marker reporting, accepted-on defaults, and special-context fallback;
- the shipped MCM JSON, four-page feature hierarchy, section order, absence of
  filler rows, per-page setting ownership, DLL version gate, persistence path,
  unique persisted keys, slider bounds, equality of MCM/native defaults, and
  the one-to-three word viewport limit for every visible text value.

Required static gates are:

```bash
cargo test --target i686-pc-windows-gnu -p atom
cargo build --release --target i686-pc-windows-gnu -p atom
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv -p atom
cargo fmt -p atom -- --check
git diff --check
```

Runtime acceptance remains mandatory:

1. Confirm `atom-latest.log` reaches `[INIT] Atom initialized successfully`
   and records the active input bridge.
2. Open Atom in MCM and visually inspect all shipped pages, help text, sliders,
   dropdown, and toggles.
3. Close MCM after changing settings and confirm one `[CONFIG]` reload/applied
   sequence without restart.
4. Verify Native behavior is unchanged; then A/B Direct and
   Fallout 4 Direct across hip, aim, scope, first/third person, menus, Pip-Boy,
   VATS, console, fly camera, focus loss, and overlays.
5. Enable telemetry, play representative indoor/outdoor combat, request a
   summary, and inspect the two bounded histograms plus buffered-keyboard
   health counters in `atom-latest.log`.
6. With BaseObjectSwapper in the representative modlist, complete at least
   three cold Proton starts into gameplay without its documented startup fault.
7. Confirm no mouse loss, duplication, stair-step, periodic hitch, camera/aim
   disagreement, or new CrashLogger fault at high mouse polling rates.
8. Exercise both sticks, both triggers, and controller buttons around their
   thresholds. Toggle Atom Input while controls are held and confirm activation
   and deactivation wait for neutral without a jump or false edge.
9. Exercise xNVSE tap, hold, and disable injection plus quick keyboard taps.
   Confirm gameplay sees every edge while console, menus, text entry, and other
   `GetDeviceData` consumers neither lose nor duplicate events.
10. Enable `First Person` and compare idle, walk, run, strafe, diagonal,
    moving-platform, jump, and soft/hard landing motion at 30, 60, 120, and
    uneven frame rates. Verify no gait while stationary relative to support.
11. Exercise hip fire, iron sights, scopes, reloads, equip/holster, VATS,
    Pip-Boy, dialogue, furniture, knockout, death, TFC, POV transitions, and
    representative animation/viewmodel mods. Verify ownership transitions are
    native and every disabled or zero-gain state is exact pass-through.
12. With OMV in both plugin orders, inspect hands/weapon depth, TAA, motion
    blur, shadows, device reset, and high-coordinate cells. Verify no camera
    field remains posed after a wrapped call and no new clipping or jitter.
13. Enable `Follow Camera` alone and test manual look, collision contraction
    and recovery, doors, corners, ceilings, stairs, slopes, teleports, cell
    changes, loads, death, menus, POV, TFC, and repeated VATS modes 1 through 4
    at 30, 60, 120, and uneven frame rates. Native facing must remain coupled.
14. Enable `360 Movement` and exercise all digital directions and analog
    circles while idle, walking, running, sneaking, auto-moving, jumping,
    falling, landing, swimming, drawing, aiming, firing, reloading, melee, and
    blocking. Repeat with documented animation/movement providers. Test real
    muzzle obstruction and standard mod-added hitscan/physical weapons only
    after confirming no other convergence owner is active.
15. The focused `Physical Rounds` gate is accepted: the retained run recorded
    68/68 forced-physical decisions, 68 first updates, progressive movement,
    delayed contact, and two hit builds followed by two native `ApplyHit`
    calls, with zero policy misses or capacity failures. Tracer presentation
    remains content-owned; that run also exposed Improved Bullet Tracers'
    missing `small_rifle_projectile.nif` asset.
16. Broader Ballistics hardening later covers multi-projectile, explosive,
    grenade/thrown, beam, flame, continuous, geometry, cell, and frame-rate
    matrices. Those unsupported families must remain native; they are not
    required for the first focused physical-policy acceptance.

Until these steps are recorded, Atom is statically validated but is not claimed
startup-safe, visually accepted, or proven to match Fallout 4's feel.

### Prior input build evidence

On 2026-08-16, for the current expanded input bridge:

- all 19 focused behavioral/artifact tests passed under Wine staging 11.15 for
  `i686-pc-windows-gnu` (2 plugin-boundary, 1 live-buffer-mirror, 14 public
  input-behavior, and 2 shipped-MCM tests);
- Atom-only Clippy passed with `--all-targets --no-deps -- -D warnings`;
- the Atom release build and the complete supported five-package release build
  passed for `i686-pc-windows-gnu`;
- Atom formatting and `git diff --check` passed.

The complete Clippy dependency run is not an Atom gate and remains blocked by
pre-existing `libpsycho` warnings in `hardware/cpu.rs` and
`os/windows/registry.rs`; Atom's own targets are warning-free.

That release `atom.dll` is 6,435,204 bytes with SHA-256
`8847a27d4adcff4854834c0685d4f65f322028da81d9b411ddc82562901231a8`.
PE inspection establishes:

- PE32 i386, large-address-aware, ASLR and NX compatible;
- exactly `NVSEPlugin_Load` and `NVSEPlugin_Query` exported;
- 316 imported symbols in 29 descriptors representing 22 distinct DLL names,
  exactly matching the accepted comparison artifact;
- `.text`, `.data`, `.rdata`, `.eh_fram`, `.bss`, `.edata`, `.idata`, `.tls`,
  and `.reloc` sections;
- an unchanged `0x2AB8` import directory and eight-byte `.tls` section.

That DLL is 112,862 bytes larger than the accepted `c489be...` artifact.
Its import count, import-directory size, section roles, and TLS data size are
unchanged, but executable/data layout and deferred static ownership changed.
That remains a material startup-footprint delta which only the required
Proton/BaseObjectSwapper playtest can accept.

### Current Ballistics build evidence

For the current Ballistics observer and update-probe artifact on 2026-08-16:

- all 33 Atom tests pass under Wine staging 11.15 on
  `i686-pc-windows-gnu`: 12 library/ABI/state tests, 5 public Ballistics tests,
  14 public Input tests, and 2 shipped-MCM tests;
- Atom-only Clippy passes with `--all-targets --no-deps -- -D warnings`;
- the Atom release build and complete supported five-package release build
  pass for the explicit 32-bit target; and
- constant-acceleration integration is frame-partition invariant within float
  tolerance, invalid steps leave state unchanged, and curvature subdivision
  never exceeds eight chords.

The complete-build release `atom.dll` is 6,532,646 bytes with SHA-256
`289403c34dfd59c788d060555900ff529eb1b42e57ca7fbbfc35b0d3c93e7daf`.
Compared with the user's tested `137135...` Ballistics artifact, it retains the
same PE32/i386 flags, nine section roles, 29 import descriptors and exact DLL
name sequence, `0x2AB8` import directory, `0x18` TLS directory, and eight-byte
`.tls` section. Code grows from `0x282400` to `0x285400` and initialized data
from `0x412000` to `0x415200`. Moving the 2,048-slot observation table to its
documented `DeferredInit` allocation reduces uninitialized data from `0x27800`
to `0x1800` and image size from `0x440000` to `0x41D000`.

The import and TLS shape is stable, but code/data layout and a new small static
pointer-slot hook container change the complete pre-`DeferredInit` footprint.
The current artifact therefore still requires the explicit Proton/
BaseObjectSwapper load-to-gameplay acceptance before it can be called
startup-safe.

### Current combined camera build evidence

For the first-person plus third-person implementation artifact on 2026-08-16:

- all 62 Atom tests pass under Wine staging 11.15 on the explicit
  `i686-pc-windows-gnu` target: 27 library/ABI/state tests, 5 public Ballistics
  tests, 7 public first-person tests, 14 public Input tests, 7 public
  third-person tests, and 2 shipped-MCM tests;
- Atom-only Clippy passes with `--all-targets --no-deps -- -D warnings`;
- focused formatting for the affected camera modules, the Atom release build,
  and the complete supported five-package release build pass;
  and
- the third-person suite proves ownership release/reacquisition, cell/live
  disable invalidation, analytic spring partitioning, cardinal yaw mapping,
  magnitude/high-flag preservation, shortest wrapped facing, configuration
  rejection/bounds, and spread-preserving convergence.

The release `atom.dll` is 6,718,469 bytes with SHA-256
`796f6f94b6b46efe30d8c1f421d0b191694b41a453bae6f87b0c88fd354136db`.
It remains PE32 i386, large-address-aware, ASLR/NX compatible, and retains the
same nine section roles, 29 import descriptors, 22 distinct DLL names,
`0x18` TLS directory, and eight-byte `.tls` section as the pre-build
`289403...` Ballistics artifact. The intended
`AtomCamera_SetExternalOwner` C ABI is now the third export beside the two xNVSE
entry points.

The complete footprint is nevertheless changed. The import directory grows
from `0x2AB8` to `0x2B04` and the inspected import-symbol count from 316 to 320;
the CRT math descriptor now includes `exp`. `SizeOfCode` grows from `0x285400`
to `0x29B800`, initialized data from `0x415200` to `0x431400`, uninitialized
data from `0x1800` to `0x1A00`, and image size from `0x41D000` to `0x438000`.
Source inspection establishes no new pre-deferred file read, logger start,
thread, worker request, or hook: configuration parsing, native validation,
state first use, and all hook writes still begin at `DeferredInit`. Plugin load
retains only the documented xNVSE services and callback owner.

Relative to the rejected `205df8...` complete-mask-only admission artifact,
the compatibility correction retains the import directory, import set, TLS,
exports, and section roles. The current image is also an aggregate of concurrent
Ballistics adapter work, so its `0x438000` image size is not attributable to
the camera correction alone. The exact replacement sections are
`.text=0x29B730`, `.data=0x1BB0`, `.rdata=0x120CE8`,
`.eh_fram=0x4EAA4`, `.bss=0x1908`, `.edata=0x8C`, `.idata=0x2B04`,
`.tls=0x8`, and `.reloc=0x215FC`.

The user's 2026-08-16 15:02 UTC run reached `DeferredInit` but rejected an
earlier artifact because `0x00702360` no longer had vanilla entry bytes. Static
analysis proves that native `MenuMode` is only the active `InterfaceManager`
check plus mode `+0x0C != 1`. Artifact `141f6947...` read those live fields
directly and reached gameplay, preserving the exact base-engine owner policy,
but then exposed the redundant `0x00870B10` caller-context gate. The current
replacement also removes that gate in favor of the proven direct-call
capability and applies the same stable InterfaceManager policy in Atom Input.
It still requires a fresh gameplay run.

Those PE/static results are not a startup or gameplay acceptance claim. The
new code, atomics, export, import/layout change, and deferred call graph are a
material delta. Three cold Proton load-to-gameplay runs with
BaseObjectSwapper, followed by the full third-person transition/collision/
animation/aim matrix, remain required before this artifact can be called
startup-safe or behaviorally accepted.

### Superseded post-launch adapter build evidence

For the default-off Ballistics adapter on 2026-08-16:

- all 62 Atom tests pass under Wine staging 11.15 on the explicit
  `i686-pc-windows-gnu` target: 27 library/ABI/state tests, 5 public Ballistics
  tests, 7 first-person tests, 14 Input tests, 7 third-person tests, and 2
  shipped-MCM tests;
- Atom-only Clippy passes with `--all-targets --no-deps -- -D warnings`;
- `cargo fmt -p atom -- --check` and `git diff --check` pass; and
- the complete supported five-package release build passes for the explicit
  target, with only the established mimalloc and MinGW linker warnings.

The release `atom.dll` is 6,731,230 bytes with SHA-256
`141f6947a9e6e42b92849b7f99fdca90f963f5d29f57ed3c60c7d53bb19c1959`.
The comparison baseline is the user's immediately preceding successful
load-to-gameplay/telemetry DLL `6f6c2a...`. Both are PE32/i386 with identical
characteristics, nine section roles, three exported names, exact 29-descriptor
and 320-symbol import sequence, `0x2B04` import-directory size, `0x18` TLS
directory, and an eight-byte zeroed `.tls` section.

The adapter grows `.text` from `0x29AF30` to `0x29BE30`, `.rdata` from
`0x120DC8` to `0x120F08`, `.eh_fram` from `0x4E9A4` to `0x4EA94`, `.bss` from
`0x18F0` to `0x1908`, and `.reloc` from `0x215CC` to `0x2169C`; `.data`
decreases from `0x1C68` to `0x1BD0`. Rounded image size grows from `0x437000`
to `0x438000`. The new `Ballistics:bEnabled` field changes deferred
configuration shape, but no import, TLS callback/data, export, thread, worker,
file scan, dependency, or startup phase is added. Parsing and hook admission
remain at the established `DeferredInit` boundary.

This remains a material pre-deferred footprint delta despite the stable loader
categories. The required Proton/BaseObjectSwapper cold-start acceptance and
the focused physical-round smoke test remain outstanding; static validation
does not call this artifact startup-safe or gameplay-accepted.

### Superseded cached-direction correction evidence

The user's enabled run of deployed SHA-256 `b929ce25...` reached gameplay and
recorded 230 launches: 168 discrete hitscan, 39 beam, and 23 flame. Native
damage ownership was observed for the first time with 16 hit builds and 16
`ApplyHit` calls. Every eligible hitscan was rejected by the same pre-write
runtime gate, with zero flag rejections, conversions, or write failures. The
run therefore changed no projectile state. Its exact summary is retained in
`.reports/atom-ballistics-adapter-2026-08-16.log`.

Static closure found that the rejected state is vanilla: Projectile constructor
`0x009BBEF0` writes the engine zero vector to cached direction `+0x104`, while
MissileProjectile movement `0x009BF300 -> 0x009BF370` builds displacement from
effective speed and the object transform. The adapter now accepts a finite zero
cache and retains every other freshness, path, flag-family, and checked-write
gate. A dedicated regression test covers that exact admission state.

For the corrected artifact:

- all 63 Atom tests pass under Wine staging 11.15 on explicit
  `i686-pc-windows-gnu`: 28 library/ABI/state tests, 5 public Ballistics tests,
  7 first-person tests, 14 Input tests, 7 third-person tests, and 2 shipped-MCM
  tests;
- Atom-only Clippy passes with `--all-targets --no-deps -- -D warnings`;
- `cargo fmt --all -- --check` and `git diff --check` pass; and
- the complete supported five-package release build passes with only the
  established mimalloc and MinGW linker warnings.

The complete-build DLL is 6,718,733 bytes with SHA-256
`a72abd6c5298a20b0890fcc2bb061655ca35a35bba263ce312356f20aec3ae29`.
Against the gameplay-tested `b929ce25...` artifact it retains PE32/i386
characteristics, the exact 29-descriptor/320-symbol import sequence, three
exports, nine section roles, the `0x2B04` import directory, `0x18` TLS
directory, and eight zero TLS data bytes. `.text` changes from `0x29B730` to
`0x29B4B0`, `.rdata` from `0x120CE8` to `0x120CC8`, `.eh_fram` from `0x4EAA4`
to `0x4EABC`, and `.reloc` from `0x215FC` to `0x21618`; `.data`, `.bss`, and
rounded `0x438000` image size are unchanged. The correction adds no setting,
import, export, TLS data/callback, hook, static owner, thread, worker, or
startup action.

The baseline already satisfies load-to-gameplay startup acceptance. The
corrected DLL still needs one focused load-to-gameplay run to accept its new
code layout and prove nonzero conversions, `hitscan/physical` updates,
progressive native movement, and exactly-once native collision/damage; static
evidence cannot establish those runtime outcomes.

### Superseded rejection-diagnostics evidence

The next run loaded deployed and workspace-matching SHA-256 `0ec38c51...` and
reached successful initialization with Ballistics and tracing enabled. Its
summary contains 227 player hitscan launches and 6,694 tracked hitscan updates.
During the enabled interval the adapter evaluated 200 rounds and rejected all
200 at the aggregate runtime gate. It recorded zero conversions, flag
rejections, write failures, early contacts, or early updates, so it again left
every projectile native. Removing the zero cached-direction requirement was
correct but did not resolve the remaining admission failure.

The replacement diagnostics classify each runtime rejection into one of 19
fixed reasons. The launch path performs only one additional relaxed saturating
counter increment; the MCM-requested summary formats the counters later. This
preserves the allocation-free hook and avoids another test that can only say
"runtime rejected."

Focused validation passes 32 Atom library tests, 5 public Ballistics tests, 2
MCM artifact tests, and strict Atom-library Clippy. The complete supported
five-package release build also passes. The repository's unrelated
first-person camera integration test currently fails to compile against its
simultaneously changed public API, so the full Atom integration command cannot
be claimed for this dirty worktree.

The complete-build DLL is 6,748,090 bytes with SHA-256
`8972d21636b60eecd8ce91b907f111c5d999571ff558f7b317f690afff7c3458`.
Against tested `0ec38c51...`, it retains PE32/i386 characteristics, the exact
29-descriptor/320-symbol import sequence, three exports, nine section roles,
`0x2B04` import directory, `0x18` TLS directory, eight zero TLS data bytes, and
rounded `0x43C000` image size. The bounded reason counters increase `.bss`
from `0x1A30` to `0x1A80`. Other code/data section changes are aggregate dirty
worktree output and are not attributed to Ballistics. The new artifact still
requires a load-to-gameplay run before its loader footprint or diagnostics can
be accepted.

The three sections above record why the post-launch design was removed. They
are historical evidence, not the current architecture or a candidate artifact.

### Native-initialization physical policy evidence

The replacement hooks the live hitscan predicate call at `0x009B7D08` while
the canonical launch predecessor is executing. Radare2 proves the form pointer
is in `ECX`, the Boolean returns in `AL`, and the following instructions store
that result as the single local policy from which FNV derives the complete
MissileProjectile runtime flag family. VATS state 4 supplies false to the same
local path without changing the shared form. The wrapper validates immutable
instructions on both sides of the mutable call, captures its current owner,
and changes only a scoped true answer to false.

The former post-launch flag writer and its 19 rejection gates are deleted.
The new scope uses eight fixed atomic slots, is keyed by Windows callback
thread plus live projectile-form token, restores nested same-thread launches,
and cannot move its RAII guard to another thread. A current owner that already
returns false remains authoritative. Unmatched forms, special contexts, calls
outside launch, scope exhaustion, and unobserved policy calls all remain
native. The hot path allocates nothing, blocks on no lock, retains no engine
pointer, and performs no file I/O or routine logging.

The installed mod audit covers Kyu's 24 final projectile overrides, Improved
Bullet Tracers' live form and presentation edits, the native Third Person Aim
Fix launch owner, the script-based 3rd Person Aim Fix temporary physical form,
and Bullet Trails' event-facing presentation. No compatibility path identifies
or patches any of those mods; admission depends only on the final live
projectile capability and launch context.

Final supported-target test, release-artifact, and PE evidence for this policy
is recorded here after the combined workspace build gate completes.

### 2026-08-16 first-person admitted-but-inert correction

The deployed `b929ce25...` run removed both earlier first-person admission
warnings and captured the expected live predecessors. OMV recorded more than
22,000 first-person stages, so the shared render calls executed, but Atom had
no runtime counters beyond installation and the user observed no motion.

Atom now reuses the latest immutable motion pose across multiple renders of one
native update instead of suppressing every render after the first. Its existing
requested diagnostics summary also emits bounded `[CAMERA_TELEMETRY]` counts
for update sampling, native rejection reasons, non-identity generation,
world/viewmodel pairing, and applied transforms. Hook callbacks remain free of
allocation, locks, formatting, and logging. A focused Proton run is still
required to establish which live path counters are nonzero and to accept the
visual result.

All 66 Atom tests, Atom-only strict Clippy, formatting checks, `git diff
--check`, and the explicit optimized Atom build pass. The resulting DLL is
6,746,087 bytes with SHA-256 `c55791250e2b9fe6fefa4d6ff7fcc704256ef6a7a4de7a34eca167cbd5b64968`.
The candidate retains the deployed DLL's PE32/i386 characteristics, import and
TLS directory sizes, nine section roles, zeroed eight-byte `.tls` section, and
three exports. Its rounded image grows from `0x438000` to `0x43C000`; the
fixed diagnostic counters and labels are a material loader-visible delta and
therefore require the normal startup replay.

### 2026-08-16 first-person coordinate correction

The runtime that followed the cadence correction still showed stepped hands
and a sky that jumped with them. Executable research proved that FNV centers
the finite Sky and Weather roots from the camera before Atom's world hook, so
the former camera-only write split one rendered scene across two centers. The
first-person camera also needs origin-relative composition at large world
coordinates.

Atom now treats camera/Sky/Weather as one scoped world transaction and uses the
engine-corroborated first-person root rebase around RenderFirstPerson. Focused
tests prove common finite-sky centering, million-unit viewmodel precision, and
exact restoration after normal scope exit or injected unwind. Full addresses,
ABIs, ownership, evidence classification, and remaining runtime gates are in
section 19 of
`analysis/radare2/output/perf/fnv_first_person_camera_contract.txt` and the
current architecture is in `docs/atom_first_person_camera_design.md`.

### 2026-08-16 first-person idle-gait correction

The installed coordinate candidate at SHA-256 `445831fa...` initialized and
ran with first-person motion enabled from 18:35:35Z to 18:37:23Z. The user's
direct visual observation showed that head bob remained active while the
player stood idle. That rejects support-relative controller velocity as a
sufficient gait-activity predicate even though it remains the correct speed
and moving-support-relative carrier.

The corrected sample also reads the prior completed PlayerMover word at
`+0x94`. Only its proven low forward/back/left/right nibble may admit grounded
gait; walk, run, sneak, auto-move, and other high state bits alone cannot.
Missing PlayerMover state fails closed to native presentation. A public
regression drives both cold idle and post-movement idle for 600 frames with
deliberately large horizontal residual velocity. Cold idle must remain exact
identity; post-movement idle must stop phase immediately and settle both poses
to exact identity. A native-boundary unit test proves that every low direction
bit admits gait and high locomotion flags alone do not. The exact executable
evidence and ordering are in section 20 of the first-person camera ledger.

### 2026-08-16 first-person presentation correction

The user accepted that gait now occurs only while moving, but rejected its
quality: the head and independently posed hands felt disconnected, procedural
weapon movement mixed with native animation, and the landing/look layers were
not clearly distinguishable. Fresh radare2 research proved that the former
helper at `0x008A8870` returns true only for reload action 9 and reload-loop
actions 15 through 17. Treating it as a general authored-animation predicate
left equip, attack, recoil, block, stagger, dodge, and other actions exposed to
Atom's second motion layer.

Atom now composes two explicit presentation layers. A restrained common head
translation moves the world and first-person cameras identically; a smaller
weapon-relative pose adds gait weight, hard-landing response, and bounded look
inertia. Every non-None value from the already sampled
`GetCurrentAnimAction` suppresses that relative pose on entry, then releases it
through a time-based envelope after native animation ends. This keeps ordinary
locomotion present during reload or fire without double-animating the weapon.
Slow-motion amplitude is reduced by squaring the gait envelope, and the former
independent viewmodel gait coefficients are substantially reduced.

Public regressions prove exact head/viewmodel registration when relative
weapon motion is zero, exact native ownership during authored actions, visible
stationary look inertia without world motion, exact settling, ADS attenuation,
landing monotonicity, moving-only gait, cadence/velocity bounds, and frame
partition stability. Section 21 of the first-person ledger records the exact
function body, caller set, action layout, implementation boundary, and evidence
classification. Static proof establishes ownership and numeric behavior; the
subjective feel still requires an ordinary installed playtest.

All 15 focused first-person behavior tests, six native camera tests, strict
Atom-only Clippy, focused formatting, `git diff --check`, and the optimized
Atom build pass for `i686-pc-windows-gnu`. The full 93-test Atom run has 91
passes and two unrelated concurrent third-person movement assertion failures;
the first-person, input, ballistics, MCM, and internal suites are green. The
built DLL identity and exact remaining evidence are recorded in section 21 of
the ledger and the design document's current evidence block.

### 2026-08-16 Atom/OMV camera-domain correction

The user's next combined run made OMV's PBR, atmosphere/fog, lighting, AO, and
other graphics appear absent or broken while first-person motion was enabled.
The logs disprove an OMV initialization failure: OMV published every deferred
capability active, initialized atmosphere and AO, and completed thousands of
world/depth transactions with zero failures. They instead prove an Atom hook
nesting error. Atom installed the shared world/first-person callsites at
`20:00:44.080Z` and captured vanilla targets; OMV installed one second later,
so OMV became the outer wrapper. During moving frames OMV then logged different
pre-alpha and coherent-world positions at the same timestamp. Atom had posed
the camera for native rendering but restored it before OMV's post-world camera
and depth consumers ran.

Atom now leaves the five overlapping render calls armed during its DeferredInit
listener and installs them once from xNVSE's immediately following MainGameLoop
callback. Vendored xNVSE source proves that callback follows the completed
synchronous DeferredInit listener walk and precedes the frame renderer. Atom
therefore captures OMV or any other compatible deferred caller-local wrapper
as its predecessor and holds camera/Sky/Weather or viewmodel state around the
entire graphics transaction. It does not identify OMV, alter OMV state, move
camera policy into `libpsycho`, or weaken either feature.

The retained hashes, timestamped log excerpts, call-chain proof, exact affected
stages, implementation boundary, and remaining runtime acceptance are recorded
in `docs/atom_first_person_camera_design.md` and
`.reports/atom-omv-camera-chain-2026-08-16.txt`.

### Runtime evidence

The 2026-08-16 first launch reproduced the xNVSE lifecycle assertion documented
above; it did not reach input hook installation. The corrected partial-input
artifact at SHA-256
`c489be721719b8709d30790e5ef5fb732203961dfdd461b05dd57b0bc372bfb3`
then completed the user's load-to-gameplay playtest. Its retained
`atom-latest.log` reaches `[INIT] Atom initialized successfully`, proves live
`MCMExtUpdate` registration, records Native/Direct/Fallout 4 Direct switches,
and contains 22,761 camera-consumer plus 38,738 present intervals without an
invalid interval.

That evidence accepts `c489be...` only. The current `8847a2...` DLL adds direct
controller output, the 28-action layer, and the buffered keyboard bridge; it
has not been installed or runtime-tested. Its load-to-gameplay, MCM visual,
controller, short-tap, compatibility, and input A/B acceptance remain pending.

The user's 2026-08-16 Ballistics session then tested DLL SHA-256 `137135...`.
It reached successful deferred initialization while chaining launch predecessor
`0x10CC11B4`, captured 251 canonical launches and exactly 251 first contacts,
reported no early contact, invalid value, or pool overflow, and observed one
callback thread. Its 89 repeated and 102 untracked collision-effect callbacks
are now reported separately; 133 same-address replacements are allocator reuse,
not stale correlation. The exact excerpt is retained in
`.reports/atom-ballistics-phase1-2026-08-16.log`.

That session sampled only discrete hitscan and beam launches and recorded no
actor `ApplyHit`; it does not admit physical conversion. The current `289403...`
artifact adds the read-only MissileProjectile update-slot chain, runtime motion
telemetry, and DeferredInit pool allocation. It has not yet been installed or
runtime-tested.

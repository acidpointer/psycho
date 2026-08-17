# Atom ballistics core implementation plan

## Status and decision

This document is the implementation plan and durable implementation record for
Atom's first combat feature. Phase 1's observation kernel, the read-only Phase
2 update probe, and the Phase 3 native-initialization policy are implemented.
The physical policy is runtime accepted and enabled by default. Material
response and damage policy are not implemented.

The product decision is to start with a **Ballistics Core**, but to implement it
in evidence-gated slices:

1. observe the native shot-to-impact lifecycle without changing it;
2. prove per-projectile ownership and compare native physical flight with an
   Atom shadow model;
3. convert only capability-proven, discrete hitscan bullets to the native
   physical path;
4. add material response and terminal-energy policy only after physical flight
   preserves native impact and damage semantics.

Atom will not begin with global damage tuning, shared-form edits, delayed
hitscan damage, or a replacement `ApplyHit`. Those approaches can make combat
harder, but they do not make a shot physically exist between muzzle and impact,
and they cannot preserve arbitrary mod-added content reliably.

The underlying engine contract is in
[Atom's combat research](atom_combat_engine_contract.md), with address-level
evidence in the
[radare2 combat ledger](../analysis/radare2/output/gameplay/fnv_combat_contract.txt).
The camera-facing aim contract remains separately owned by the
[third-person camera plan](atom_third_person_camera_plan.md).

### Implemented Phase 1 - 2026-08-16

The current change implements the complete no-op observation slice:

- one top-level `AtomConfig` reads the shared INI once and publishes the
  existing input snapshot plus an independent `BallisticsConfig` snapshot;
- MCM exposes disabled-by-default `Ballistics Trace` and `Write Ballistics`
  diagnostics, both applied from `MCMExtUpdate` after MCM saves;
- immutable caller fingerprints guard the projectile-count, launch, hit-build,
  projectile `ApplyHit`, and collision-effect callsites;
- those five typed direct-call hooks plus the live MissileProjectile update
  vtable slot capture their current targets and enable in one Ballistics-only
  rollback transaction at `DeferredInit`;
- disabled wrappers call their predecessors once without reading engine form
  or projectile state;
- tracing snapshots live projectile-form capabilities and launch arguments,
  then correlates only the numeric returned projectile address in a fixed
  2,048-slot, 32-probe open-addressed table;
- every slot field is atomic, publication is release/acquire, generation reuse
  is explicit, and the about 152 KiB table is allocated once at `DeferredInit`
  rather than occupying loader-visible `.bss`;
- QPC timing, saturating counters, and eight thread-identity slots are bounded;
  formatting and logging occur only on the MCM request callback;
- `PreLoadGame`, `NewGame`, `ExitToMainMenu`, `ExitGame`, and console exit clear
  correlation state; and
- a Ballistics mismatch rolls back only Ballistics and leaves Atom Input active.

No wrapper mutates an argument, return, shared form, runtime projectile, hit
data, actor object, projectile tail, or save state. Deferred installation
changes only the five validated call displacements and one validated vtable
function-pointer slot through ownership-aware transactions. Pool exhaustion,
invalid live data, and missing correlation affect telemetry only.

Static and automated evidence completed for this slice:

- the supported `i686-pc-windows-gnu` Atom suite passes under Wine, including
  ABI offsets, generation reuse, lifecycle miss accounting, capability
  classification, unified INI behavior, and shipped MCM defaults/text bounds;
- callsite bytes and typed ABIs derive from the supported executable identity
  below; and
- the supported release build and complete-repository build gates are recorded
  later in this document when run.

One initial runtime observation is recorded below. It closes neither the Phase
1 matrix nor startup acceptance: no-op equality, actor hits, physical and
special projectile families, multi-projectile fire, prolonged pool behavior,
and the final artifact's Proton/BaseObjectSwapper startup still require the
matrix below.

### Initial Phase 1 runtime evidence - 2026-08-16

The user tested DLL SHA-256
`1371353bbd4945bd1cd746a31e6237f601b31635ffdcef4fe5cfff707d5e4d77`
under Proton with the representative mod stack. The observer captured a live
non-vanilla launch predecessor at `0x10CC11B4` while the other four callsites
retained their vanilla targets. The retained evidence is
`.reports/atom-ballistics-phase1-2026-08-16.log`.

Proven runtime observations:

- 251 launches comprised 88 player and 163 actor launches, with 192 discrete
  hitscan missiles and 59 beams;
- all 251 launches reached a first correlated contact: 340 world-effect
  callbacks minus 89 repeated callbacks equals 251 first contacts;
- no contact occurred before the chained launch predecessor returned;
- one callback thread, Windows thread ID 984, owned all observed callbacks;
- no classification fallback, invalid value, or pool overflow occurred; and
- 133 same-address replacements demonstrate normal allocator address reuse,
  while one live launch expired without a contact.

The old summary's `missing=102` means untracked collision-effect callbacks,
not 102 lost launches. Those callbacks can originate from objects alive before
trace admission or projectile producers outside the canonical weapon-fire
seam. Likewise, the old `stale_generations=133` label means address reuse; no
stale generation was accepted. The implementation now reports these roles
separately.

Open cells are material. This session recorded no actor hit-build or
`ApplyHit`, physical missile, explosive, grenade/thrown, flame, continuous
beam, or multi-projectile discharge. It also did not provide trace-off/on
health, ammunition, script-event, or effect equality. This sample therefore
did not authorize physical conversion on its own.

### Implemented update-probe slice - 2026-08-16

Focused radare2 research proves MissileProjectile vtable `0x0108FA44`, update
slot `+0x310` at `0x0108FD54`, vanilla target `0x009B8030`, and ABI
`void __thiscall(MissileProjectile*, float)`. Atom now CAS-chains the slot's
current live owner in the same Ballistics transaction as Phase 1. This avoids
claiming the common update prologue already used by ecosystem code.

With tracing disabled the wrapper calls its predecessor once and returns. With
tracing enabled it snapshots live common-projectile state before and after the
predecessor, samples authoritative effective speed through `0x009669C0`, and
records form/runtime path pairs, first and early updates, frame delta,
progressive versus stationary movement, impact-in-update, callback thread, and
native displacement versus `effective_speed * dt`. It never moves an object or
changes a field.

The common caller continues using the projectile after the subtype returns,
which proves post-call reads are live at this seam. Analytic constant-
acceleration shadow math is implemented independently with finite-state
validation and an eight-chord hard bound. Gravity-unit calibration and
per-projectile shadow-state admission remain gated on update telemetry from
already-physical discrete missiles.

The fresh Proton run of DLL SHA-256
`6f6c2a8ac51097da8aa3bfe94b89db3f14ca9b29a5e83ee51fd7e6381dbe5fb0`
then started successfully and recorded 182 launches: 164 discrete hitscan, 17
beam, and one grenade/thrown projectile. Every hitscan launch reached its first
Missile update; 615 tracked samples retained the native hitscan path, 156 of
165 unobstructed samples matched `effective_speed * dt` within one percent,
and no contact or update occurred before the chained launch owner returned.
The same nine stationary/non-impacted movement outliers and two callback
threads reproduced in a fresh process, so both are systematic. One invalid
sample is isolated by counter reconciliation to launch/contact latency rather
than a runtime update. No actor hit-build or `ApplyHit` was observed. This is
runtime evidence for the selected post-launch intervention point, not proof of
physical collision or actor-damage acceptance.

### Implemented native-initialization policy - 2026-08-16

Two enabled Proton runs proved that the original post-launch adapter was the
wrong intervention, not merely an over-strict version of a sound design. The
first run evaluated 168 eligible hitscan launches and the second evaluated 200;
both produced zero conversions. The second run recorded 6,694 tracked
hitscan/hitscan updates, zero hitscan/physical updates, and no flag write. Those
logs prove that the released code changed no gameplay. They are retained in
`.reports/atom-ballistics-adapter-2026-08-16.log`.

Atom now intervenes at the engine's authoritative decision instead. During
`MissileProjectile` initialization, `0x009B7CC0` calls the live projectile
form's hitscan predicate at callsite `0x009B7D08`. The returned byte is the
single local value from which FNV derives the complete runtime policy. Atom
chains the target currently encoded at that callsite. For an eligible launch
it changes only a true return value to false; FNV then constructs the complete
physical projectile before common initialization and process admission.

This is materially safer than reconstructing a completed object:

- Atom never writes runtime flags, direction, age, distance, damage, condition,
  impact lists, transforms, or subclass state;
- FNV itself derives gravity, tracer interaction, initialization, hitscan, and
  physical flags through its existing `0x005DE0A0` bit setter;
- the shared `BGSProjectile` form remains unchanged, so other weapons, scripts,
  saves, and later form queries see the mod stack's data;
- native speed, range, source actor, source weapon, condition, damage,
  collision, impact effects, attribution, and `Actor::ApplyHit` remain owned by
  their original engine paths; and
- VATS already uses the same native precedent: state 4 skips the predicate and
  supplies false to this exact derivation without changing the shared form.

The outer canonical launch wrapper publishes an eight-slot, thread-owned scope
containing only the current thread ID and numeric projectile-form token. The
scope exists only while the captured launch predecessor runs. It uses atomics,
has no heap allocation, mutex, TLS value, engine reference, I/O, or hot-path
logging, and its RAII guard is not `Send`. Nested same-thread launches replace
and restore the outer frame on the Rust stack. Different callback threads use
different slots. Capacity exhaustion, an unmatched form, or failure to reach
the audited initializer call leaves the round native.

The predicate detour calls its captured predecessor exactly once. If an
earlier owner already returns false, Atom preserves false and records
`already_physical`; if it returns true for the scoped form, Atom returns false
and records `forced_physical`. Every same-form initialization inside one launch
scope receives the same answer, preserving multi-projectile launch owners. A
different form, a later predicate use, and all calls outside the scope receive
the chained predecessor's result unchanged.

Admission is capability-based and independent of FormID, EditorID, plugin,
load-order position, or a curated weapon table. It admits only a live
non-explosive MissileProjectile form whose current form flags select hitscan,
with a known nonzero source and an ordinary launch context. Physical missiles,
explosive missiles, grenades, thrown projectiles, beams, flames, continuous
beams, always-hit launches, ignore-gravity launches, and launches with a live
target remain native.

The installed Default profile was audited directly:

- Kyu's Ballistics Fixed - TTW patches 24 projectile records. All 24 are
  type-1 Missile forms with hitscan flags `0x0289` or `0x028D`, ranges from
  10,000 to 53,000 units, speeds from 7,000 to 54,400 units/second, and gravity
  from 0 to 20. They are classified from those final live values, so the same
  policy also covers equivalent mod-added records.
- Improved Bullet Tracers changes tracer chance, pass-transparent policy,
  model, presentation, and optional speed/range. The installed configuration
  uses tracer chance 1, `iSpeed=0`, and `iRange=0`. Atom changes neither the
  form nor those presentation values, and native initialization performs the
  tracer draw before deriving its physical flags.
- Third Person Aim Fix owns the live launch predecessor captured in the prior
  run (`0x10CC11B4`) and blends spawn position to the camera at 100 percent.
  Atom's scope surrounds and calls that current predecessor, so its launch
  transform remains authoritative.
- The script-based 3rd Person Aim Fix explicitly creates a temporary type-1
  projectile with hitscan cleared and classifies beam, flame, and continuous
  families separately. Atom sees that temporary form as already physical and
  does not adapt it.
- Bullet Trails consumes fire/projectile presentation events; it does not own
  the initializer's local hitscan value. Because Atom keeps the original form,
  model, tracer chance, and native projectile instance, its event-facing
  identity remains intact.

Automated tests cover matching versus nonmatching form identity, repeated
same-form initialization, prior-owner physical policy, nested launch scope
restoration, release after the native call, and special launch rejection. The
audited ABI/layout and lifecycle tests remain in place. Requested telemetry now
reports candidates, forced physical, already physical, context rejects, policy
misses, and capacity failures; obsolete post-launch runtime/flag/write gates
are removed.

### Native physical-policy runtime acceptance - 2026-08-16

The user ran deployed and workspace-matching DLL SHA-256
`e34c81bfecf2ab729962c65f1701fb1c93e55d7805df1557b697854693aacd26`
under Proton with the representative mod stack and BaseObjectSwapper. Atom
reached successful deferred initialization while chaining Third Person Aim
Fix's live launch owner at `0x10CC11B4`. The retained summary is
`.reports/atom-ballistics-native-policy-2026-08-16.log`.

The session closes the Phase 3 runtime gate for the exercised path:

- 68 final live discrete-hitscan forms entered the scoped policy and all 68
  reported `forced_physical`; there were zero policy misses, context rejects,
  capacity failures, invalid samples, or observation-pool overflows;
- all 68 converted objects reached a first MissileProjectile update, 106 of
  168 samples moved progressively, and 68 updates ended with native impact
  state;
- 71 first contacts were correlated after the launch predecessor returned,
  including two actor hit constructions and exactly two native `ApplyHit`
  calls; and
- impact latency materially diverged from the retained hitscan baseline. The
  baseline placed 230 of 251 first contacts at or below 16 ms. This run placed
  only 7 of 71 at or below 16 ms and 55 between 33 and 100 ms. This is observed
  time of flight, not a policy-counter inference.

The old update summary nevertheless placed all 168 samples in `other`. Static
revalidation confirms the initializer still sets mutually exclusive `0x2000`
and `0x8000` markers at runtime flags `+0xC8`; the summary defect was that it
used the later live marker pair as the source of truth for the already-recorded
launch decision. Runtime presentation owners may rewrite or retain those bits.
Atom now stores the scoped initializer result with the launch observation,
reports form/selected-path pairs from that immutable result, and reports the
four live marker combinations separately. It does not overwrite another
owner's later flags.

Visual presentation has a separate content failure in the same run. FNV's
error log repeatedly requests
`meshes\projectiles\ImprovedTracers\small_rifle_projectile.nif`, while the
installed Improved Bullet Tracers package contains
`small_rifle_tracer.nif` at that location. Atom neither owns nor repairs that
third-party filename mismatch. Physical flight, collision, and damage remain
valid for an invisible projectile; tracer visibility requires a valid model
from the content owner.

### Post-acceptance correction build evidence - 2026-08-16

The correction stores the scoped initializer result in the existing bounded
observation pool and treats the later live marker pair as a separate
four-state diagnostic. A regression test rejects the former coupling by
proving that a hitscan-form/physical-selection sample remains physical even
when its live markers are `both` or `neither`. Missing INI data and the shipped
MCM artifact now both enable the runtime-accepted physical policy; tracing and
summary requests remain off.

All 86 Atom tests pass on `i686-pc-windows-gnu`, including 42 library tests,
five Ballistics behavior tests, two shipped-MCM artifact tests, and the
camera/input suites. Strict all-target Atom Clippy passes with warnings denied.
The complete supported five-package release build also passes. The resulting
Atom DLL is 6,801,339 bytes with SHA-256
`c17a73d395235ccc58cdd11a42e508157d8c890c0a2c4df33e003431d3f29f6e`.

Against the accepted `e34c81bf...` runtime artifact, the candidate remains
PE32/i386 with the exact 29-descriptor/321-symbol import sequence, three
exports, nine section roles, `0x2B04` import directory, `0x574` IAT,
`0x18` TLS directory, and eight zero TLS data bytes. The rounded image grows
from `0x443000` to `0x445000`; section growth includes the combined dirty Atom
camera work and cannot be attributed solely to Ballistics. The corrected DLL
therefore still needs the repository-required Proton load-to-gameplay
acceptance for its new loader-visible code layout. That gate is distinct from
the already-observed physical-flight behavior.

## Desired outcome

The completed Ballistics Core should make an admitted firearm round a coherent
event with:

- one native-authorized launch;
- an immutable snapshot of the actual weapon instance, ammunition, projectile,
  source, condition, spread result, and launch transform;
- progressive time of flight when the projectile family is safely adaptable;
- continuous path collision rather than damage delayed along a preselected ray;
- exactly one native impact traversal and native damage commit for each native
  contact;
- bounded, deterministic material continuation when penetration or ricochet is
  later enabled;
- visible and audible flight/impact timing that other Atom systems can consume;
  and
- native fallback whenever Atom cannot prove the content or runtime capability.

The player-facing target is not a firearms laboratory. It is readable,
convincing gunfire: near cover matters, moving targets require real travel time,
the path through space is consistent with the impact, and hit feedback follows
the physical event instead of a synthetic timer.

## Acceptance criteria

The first gameplay-capable release is successful only when all of these are
true:

- Atom changes no ammunition consumption, native cadence, jam, reload, spread,
  weapon damage, DT/DR, critical, limb, or difficulty calculation.
- A supported discrete bullet either follows the proven physical route or stays
  completely native. There is no partially converted state.
- Vanilla and mod-added forms are classified from live type, flags, links, and
  effective values, never plugin name, EditorID, load-order index, or a curated
  FormID list.
- Shared weapon, ammunition, projectile, explosion, and actor forms remain
  read-only.
- Player, NPC, companion, turret, script-driven, automatic, semi-automatic, and
  multi-projectile fire that reaches the native launch seam retains native
  ownership.
- Beams, flames, continuous beams, explosives, grenades, mines, thrown weapons,
  VATS, and unknown projectile families remain native until separately
  admitted.
- Existing callsite owners are chained by current capability. Atom never
  identifies another mod or assumes a vanilla predecessor.
- The hot path allocates nothing, performs no file I/O, takes no blocking lock,
  parses no configuration, and emits no routine log lines.
- Pool or telemetry exhaustion increments a counter and falls back to native
  behavior for that round.
- The supported 32-bit release target builds, artifact checks pass, the final
  diff is clean, and the required Proton/BaseObjectSwapper load-to-gameplay
  acceptance passes.

## What modern shooter practice means here

Modern engines normally separate launch authorization, projectile simulation,
collision, impact response, and damage. That separation is valuable in FNV too,
but Atom must wrap existing owners rather than pretending it is a new engine.

### Authoritative shot event

Input is intent, not a shot. Native fire admission remains responsible for
animation, ammunition, cadence, jams, sounds, VATS state, scripts, and AI. Atom
creates a `ShotContext` only at the canonical launch call, after those systems
have committed the shot.

### Continuous path collision

A fast projectile cannot rely on overlap at its final frame position. Its path
must be swept between the previous and next positions, with bounded substeps
when curvature makes a single chord inaccurate. This matches the established
continuous-collision model: sweep to time of impact, resolve, and continue only
when policy permits. Unity's official CCD documentation also notes the CPU cost
of extra sweeps, which is why Atom needs a strict bound rather than unlimited
substeps: <https://docs.unity3d.com/2018.3/Documentation/Manual/ContinuousCollisionDetection.html>.

Unreal's projectile component similarly time-slices updates when substepping is
required rather than treating one long frame as an unbounded simulation loop:
<https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/Engine/UProjectileMovementComponent/ShouldUseSubStepping>.

These sources establish useful design practice, not FNV behavior. Native FNV
behavior is established only by the executable evidence below.

### Deterministic simulation and presentation

Logical flight owns position, velocity, collision order, and impact time.
Tracers, trails, sound, camera shake, and animation consume that state but do
not move the logical round. A frame-rate hitch may reduce presentation quality;
it must not duplicate a hit or teleport damage through intervening cover.

### Data-driven content

The live projectile and ammunition records are the primary ballistic profile.
Atom consumes native effective speed, gravity, range, projectile count, source
weapon condition, and ammunition effects. It does not infer caliber from a
name, infer velocity from damage, or normalize every mod to a hard-coded weapon
table.

FNV does not provide mass, diameter, sectional density, or ballistic
coefficient for arbitrary ammunition. Atom therefore starts with native speed,
gravity, and range. Aerodynamic drag and terminal energy remain neutral unless
the engine data is sufficient or a future explicit profile contract supplies
the missing dimensions.

## Proven native pipeline

All addresses below apply only to Fallout: New Vegas 1.4.0.525, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

```text
player / NPC / script / animation
               |
               v
      shared fire 0x00523150
               |
       count loop 0x0052441E
               |
               v
 call 0x005245BD -> spawn 0x009BCA60
               |
      subtype allocation and fields
               |
     virtual +0x308 at 0x009BD1AC
       Missile: 0x009B7CC0
       common:  0x009BDA10
               |
       process admission 0x009BD50B
               |
               v
 common update 0x009BECC0
   virtual +0x310 at 0x009BEF8F
       Missile: 0x009B8030
               |
 move 0x009BF300 -> 0x009BF370
 speed 0x009669C0
               |
        impact-data list +0x88
               |
 Missile wrapper 0x009B8B10
 common traversal 0x009C1B70
               |
 hit build 0x009C1E61 -> 0x009B5650
 ApplyHit  0x009C1E96 -> 0x0089A760
 effects   0x009C2058 -> 0x009C20E0
               |
 result / retain / kill 0x009BC8F0
```

### Launch facts

- `0x00523150` is the shared ranged-fire owner reached by player, NPC,
  animation/event, and script fire paths.
- It computes the authoritative effective projectile count through
  `0x00525B20`, then loops once per pellet/projectile from `0x0052441E`.
  Automatic and burst weapons are not one artificial simultaneous spawn; their
  normal cadence invokes fire repeatedly.
- `0x005245BD` is the normal direct call to `0x009BCA60`. The current call target
  is the compatibility predecessor Atom must capture and call.
- `0x009BCA60` selects and allocates the derived projectile type, copies source
  and weapon context, applies throwing-velocity perk entry point 59, and
  initializes native range and launch state.
- The other direct executable caller at `0x0046A176` is part of generic
  reference/cell construction with no normal shooter or weapon context. It is
  not a second firearm-shot seam and will not be hooked as one.

### Spawn-time hitscan policy

Spawn calls the new projectile's vtable `+0x308` method synchronously at
`0x009BD1AC`, before process admission at `0x009BD50B`. MissileProjectile's
override is `0x009B7CC0`. At callsite `0x009B7D08` it invokes
`BGSProjectile::IsHitScan` at `0x009A7F80` with the form pointer in `ECX` and no
stack arguments. The byte result in `AL` is stored as one local Boolean and
drives every hitscan-dependent flag before common initialization at
`0x009BDA10`.

The form's hitscan bit directly selects runtime flags `0x0001` and `0x0008` and
selects `0x2000` for hitscan versus `0x8000` for non-hitscan. Focused static
closure established the rest of this MissileProjectile block:

- `0x0010` mirrors the native tracer-chance draw and remains independent;
- `0x0020` is tracer-selected and hitscan, while `0x0002` is non-tracer and
  hitscan;
- `0x0040` is positive native gravity and non-hitscan;
- `0x0100` is set for the initialized missile;
- `0x8000` is non-hitscan and `0x2000` is hitscan; and
- VATS state 4 forces the local hitscan result false before this derivation.

Returning false at that callsite makes native code clear `0x0001`, `0x0002`,
`0x0008`, `0x0020`, and `0x2000`, set `0x8000`, derive `0x0040` from native
gravity, and preserve the independent tracer and initialization bits. Atom
does not reproduce those writes. The existing VATS state-4 branch sets this
same local Boolean false without changing the form, establishing a native
per-object precedent for the intervention.

Consequences:

- globally clearing the form's hitscan bit is incompatible;
- changing only `0x2000/0x8000` is an incomplete conversion;
- changing a completed object requires reconstructing initialization
  invariants and is no longer an admitted design;
- the compatible seam is the scoped `0x009B7D08` predicate answer, with the
  current call target chained exactly once; and
- a custom delayed `ApplyHit` is not an equivalent fallback.

Atom publishes its policy before calling the current launch predecessor and
closes it immediately after that predecessor returns. Matching includes both
callback thread and live form token. The initializer detour therefore cannot
affect a different projectile form or any predicate use after launch. The
normal spawn body and process-admission helper continue unchanged.

### Update and movement facts

`0x009BECC0` is the common Projectile update. It calls the subtype's vtable
`+0x310` method at `0x009BEF8F`, then increments age at `+0xD8` and performs
common lifetime/range work. MissileProjectile's update is `0x009B8030`.

Its ordinary movement branches call `0x009BF300`. That helper obtains effective
speed through `0x009669C0`, multiplies it by frame time, and forwards movement
through `0x009BF370`. The native speed helper combines:

- `BGSProjectile::speed` at form `+0x68`;
- runtime power at `+0xCC`;
- runtime speed multiplier at `+0xD0`; and
- the native power/speed interpolation setting.

Atom should consume that helper or its already-computed result. Reconstructing
speed independently would miss native ammunition, charge, weapon modification,
perk, and mod-added behavior.

The runtime object also exposes range `+0xD4`, age `+0xD8`, damage `+0xDC`,
weapon condition `+0xF4`, source weapon `+0xF8`, source reference `+0xFC`,
direction/vector `+0x104`, and distance travelled `+0x110`. These are live
observations, not storage reserved for Atom.

### Impact and damage facts

MissileProjectile's impact vtable slot points to `0x009B8B10`. That wrapper
calls common traversal `0x009C1B70` and interprets the subtype result as kill,
bounce, impale, stick, or retention behavior.

Common traversal walks every record in the projectile's `+0x88` impact list.
For an actor contact it builds native hit data at
`0x009C1E61 -> 0x009B5650` and commits it once at
`0x009C1E96 -> Actor::ApplyHit 0x0089A760`. Collision presentation follows at
`0x009C2058 -> 0x009C20E0`; traversal eventually marks the projectile's
has-impacted state at `+0x90`.

`Actor::ApplyHit` owns script events, hostility, AI notification, health and
fatigue, armor and weapon wear, limb damage, reactions, cripple, death,
experience, challenge, interface, and VATS side effects. Ballistics must
preserve it. Atom may later adjust complete hit data at the proven policy seam,
but may not suppress a native hit globally and synthesize a second partial
commit.

## Compatibility and content admission

### Capability classifier

Every launched projectile is assigned one of these runtime classes:

| Class | Initial policy |
|---|---|
| Discrete physical bullet | Observe, then shadow; native flight remains authoritative |
| Discrete hitscan bullet | Observe; physical conversion only after all gates pass |
| Explosive missile | Native |
| Grenade or thrown | Native |
| Mine or placed explosive | Native |
| Beam | Native |
| Flame | Native |
| Continuous beam | Native |
| Unknown or contradictory | Native |

Classification uses the actual linked projectile form, derived type, flags,
explosion link, live-target/throwing launch arguments, and effective weapon and
ammunition context. Form origin is irrelevant.

A mod-added rifle with a normal discrete missile-type projectile can therefore
participate automatically. A vanilla or mod-added continuous beam remains
native for the same capability reason. This is compatibility by behavior, not
compatibility by a maintained mod list.

### Required live context

The launch wrapper snapshots values that can change independently of base
forms:

- source reference token and source kind;
- weapon form token and equipped-instance condition;
- effective ammunition and projectile form tokens when the native helper can be
  sampled without changing state;
- effective projectile count and a per-launch sequence within an observed
  discharge where correlation is proven;
- source position, launch position, rotation, and resolved direction;
- power, speed multiplier, effective speed, native range, and native damage;
- always-hit, ignore-gravity, live-target, VATS, and projectile-family flags;
  and
- a monotonically wrapping shot sequence plus generation.

Raw pointers may be used only during the live hook that received them. Stored
identity is a numeric correlation token plus generation and stable form/ref
tokens, revalidated whenever engine data is accessed.

### Balance policy

The Ballistics Core initially changes path and timing, not damage balance.
Native weapon/ammunition damage, perks, DT/DR, criticals, limb multipliers,
difficulty, and reaction remain authoritative.

This matters for a mixed mod list: Atom does not erase another mod's intended
damage values in order to make trajectories physical. A future terminal-energy
module starts at multiplier `1.0` for profiles without explicit energy data and
is separately testable and disableable. It must never derive velocity or armor
performance from damage merely to force every record into a guessed model.

## Source architecture

The first implementation should add only the files needed by its phase. Later
files are listed here to keep ownership stable; they should not be created as
empty scaffolding.

| Path | Ownership |
|---|---|
| `atom/src/ballistics/mod.rs` | Deferred admission, public lifecycle, native fallback state |
| `atom/src/ballistics/adapter.rs` | Bounded per-launch policy scope and fail-closed admission |
| `atom/src/ballistics/native.rs` | Audited form/runtime layouts, ABIs, addresses, and classification |
| `atom/src/ballistics/hooks.rs` | Typed callsite/vtable containers, predecessor chaining, transaction |
| `atom/src/ballistics/context.rs` | Immutable `ShotContext` and `ImpactContext` values |
| `atom/src/ballistics/pool.rs` | Fixed-capacity slots, generation handles, expiry, counters |
| `atom/src/ballistics/telemetry.rs` | Saturating counters/histograms and requested snapshots |
| `atom/src/ballistics/profile.rs` | Capability classification and native-data profile resolver |
| `atom/src/ballistics/flight.rs` | Analytic shadow trajectory and bounded chord subdivision |
| `atom/src/ballistics/impact.rs` | Material and continuation policy after Phase 4 admission |

`atom/src/lib.rs` remains the xNVSE lifecycle router. `atom/src/runtime.rs`
continues to own deferred logger/config initialization and MCM updates. The
ballistics module may not initialize from `NVSEPlugin_Load`.

### Configuration shape

The current persisted type is input-specific. The first implementation should
introduce a small top-level `AtomConfig` that contains the existing
`InputConfig` unchanged plus a `BallisticsConfig`. One file read and one
menu-close reload publish independent immutable module snapshots.

The observation release needs only diagnostic controls:

```ini
[Diagnostics]
bBallisticsTrace=0
bBallisticsSummary=0
```

The accepted gameplay release uses:

```ini
[Ballistics]
bEnabled=1
```

It should not expose drag, gravity, penetration, or damage sliders before those
policies exist. Physical flight is enabled by default after runtime acceptance;
diagnostics remain opt-in. Values apply after `MCMExtUpdate` and use
one-to-three-word visible text. The shipped labels are `Physical Rounds`,
`Ballistics Trace`, and `Write Ballistics`.

Configuration publication is atomic and lock-free. MCM owns the INI and Atom
never writes it back, so unrelated and future fields remain intact.

## State and hot-path design

### Observation records

Phase 1 uses a fixed open-addressed table of compact records. Launch snapshots
only argument-derived data, calls the captured predecessor exactly once, and
then publishes the returned address as an opaque correlation token without
dereferencing it after the call. A returned null address is rejected.

Later native callbacks may compare their live projectile address with that
token. Engine fields are read only while the callback owns a live object. A
slot is replaced on same-address generation reuse, reclaimed opportunistically
after bounded age, or emptied by a game lifecycle clear. Contact state remains
available for repeated native callbacks.

The 2,048-slot table is about 152 KiB, below its 1 MiB budget, and is allocated
once at `DeferredInit`; capacity is not a user setting. A 32-slot probe limit
bounds launch cost. Overflow increments a saturating counter and leaves the
shot native.

### Thread gate

Static evidence does not authorize assuming that every projectile callback is
on one thread. Observation therefore records a bounded set of first-seen thread
identities without logging in the hook. The first session observed one owner,
but that result covers neither update callbacks nor the required matrix. Mutable
per-projectile shadow state is not admitted until update telemetry shows a
compatible owner or the table is designed for the observed concurrency.

No `Mutex`, `RwLock`, heap-backed map, vector growth, or per-shot allocation is
allowed in launch, update, impact, or hit wrappers. Atomic counters are relaxed
unless publication requires stronger ordering.

### Future trajectory state

Once admitted, a flight slot contains only Atom-owned values:

```text
slot generation
opaque live correlation token
shot handle
previous position
current position
velocity
elapsed time
distance
penetration count
ricochet count
capability flags
```

Atom never stores this state in projectile tail bytes. Existing extensions use
`+0x149..+0x14C`, and derived projectile sizes differ.

## Hook plan

### Phase 1 direct callsites

The observation kernel prefers caller-owned direct calls because
`Rel32CallHookContainer` can capture the target currently encoded at that
callsite and chain it without naming its owner.

| Purpose | Callsite | Vanilla target | Wrapper rule |
|---|---:|---:|---|
| Discharge count | `0x00524413` | `0x00525B20` | Call predecessor once, record returned count |
| Launch observation | `0x005245BD` | `0x009BCA60` | Snapshot args, call predecessor once, retain opaque result token |
| Actor hit construction | `0x009C1E61` | `0x009B5650` | Correlate live projectile, call predecessor once |
| Actor hit commit | `0x009C1E96` | `0x0089A760` | Count commit, call predecessor once |
| Collision presentation | `0x009C2058` | `0x009C20E0` | Observe world/material contact, call predecessor once |

Fingerprints cover immutable instructions around each caller but exclude the
call displacement. Installation is one Ballistics transaction at
`DeferredInit`. A mismatch rolls back Ballistics only; Atom Input remains
active.

### Update observation

The common update entry `0x009BECC0` is useful for movement and thread evidence,
but read-only ecosystem source already hooks that entry. Atom therefore does
not claim its prologue. Focused binary research selected MissileProjectile's
vtable `+0x310` slot at `0x0108FD54`. The slot supplies the live projectile and
frame delta, and the common caller keeps the object alive after the subtype
returns.

`PointerSlotHookContainer` captures the slot's current target, uses
compare-and-exchange for ownership, and participates in the same rollback
transaction as the five callsites. Its behavioral harness covers current-owner
chaining, changed-owner rejection, ownership-loss preservation, and container
publication. Runtime evidence from the new artifact must still show which live
owner is captured and whether every required MissileProjectile reaches it.

### Physical-conversion intervention

The implemented conversion is a **native-initialization policy**. Atom retains
the native runtime projectile and changes the scoped answer at
`MissileProjectile`'s existing hitscan-predicate callsite `0x009B7D08`. FNV
then constructs the full non-hitscan policy before common initialization,
allowing native movement, collision, impact traversal, effects, attribution,
and `ApplyHit` to remain in control.

This is behind an MCM gate rather than a custom raycaster. The
immutable caller instructions on both sides of the mutable `E8` are validated
before a transactional hook installation. The hook captures and calls the
current target exactly once. A bounded launch scope matches by callback thread
and live form token, so unrelated predicate calls and later form semantics are
unchanged. There is no post-launch projectile mutation.

The 2026-08-16 accepted runtime proves the following on the supported process:

- the captured third-party launch owner reaches the audited initializer policy;
- ordinary shots report `forced_physical` without `policy_misses`;
- native update produces progressive positions and delayed contacts;
- the original collision-effect and actor-hit paths remain active, with two
  hit builds followed by exactly two native `ApplyHit` calls;
- Proton startup and hook composition remain stable with BaseObjectSwapper and
  the installed combat stack.

The broader matrix still covers misses, moving targets, content families, and
frame-rate extremes. Any per-round admission failure retains the chained
native result and its counter identifies whether admission, hook composition,
or policy observation failed. Atom will not restore post-launch flag mutation
or substitute delayed hitscan damage. A per-shot form proxy or Atom-owned
collision producer would be a separate, larger feature requiring new evidence.

## Implementation phases

### Phase 0: research closure - current document

Deliverables:

- launch, spawn initialization, update, speed, impact, and damage call chains;
- capability coverage table;
- hook ownership and startup constraints;
- implementation gates and runtime matrix.

Exit: documentation and evidence ledger validate with no code build required.

### Phase 1: no-op observation kernel

Implement:

- `ballistics/{mod,native,hooks,context,pool,telemetry}.rs` only;
- direct launch, hit-build, hit-commit, and collision-effect callsite wrappers;
- fixed observation table and saturating counters;
- top-level configuration publication and MCM diagnostic toggles;
- lifecycle clears on `PreLoadGame`, `NewGame`, `ExitToMainMenu`, and
  `ExitGame`;
- requested out-of-hot-path summary logging under `[BALLISTICS_TELEMETRY]`.

Required summary data:

- launches by source kind and projectile capability;
- native hitscan versus physical;
- effective projectile-count distribution from the native count call;
- actor hits, world impacts, misses/expired observations, and duplicate
  correlations;
- launch-to-first-impact time histogram;
- invalid values, pool overflow, address reuse, and unclassified fallback;
- observed callback thread identities; and
- contacts that occur before the launch predecessor returns, if observable
  without dereferencing an invalid result.

Acceptance:

- disabled mode is byte-for-byte pass-through at each wrapper;
- enabled tracing changes no health, ammunition, impact timing, projectile
  position, effect, script event, or save state;
- current predecessors are called exactly once;
- full-auto and shotguns produce the same native shot/contact counts with and
  without tracing; and
- the summary is emitted only on an MCM request outside combat hooks.

### Phase 2: lifecycle probe and shadow flight

The read-only update probe, runtime view, authoritative-speed sampling, and
analytic math are implemented. Per-projectile shadow-state correlation remains
gated. The completed phase must:

- observe pre/post native update position, vector, age, range, distance, flags,
  impact-list state, and destruction state;
- sample native effective speed through the proven helper;
- run an Atom shadow trajectory without moving the projectile or changing
  collision;
- compare predicted versus native positions for already-physical discrete
  bullets; and
- establish frame-time, curvature, thread, lifetime, and pool budgets.

The initial shadow model is constant acceleration using native effective speed
and projectile gravity. Drag remains zero because arbitrary FNV ammunition has
no ballistic coefficient. Collision approximation uses swept chords with a
bounded curvature error and a hard maximum of eight segments per update. No
unbounded catch-up loop is allowed.

Acceptance:

- shadow mode remains behaviorally inert;
- no-acceleration trajectories are invariant to frame partitioning within
  float tolerance;
- constant-acceleration position uses the analytic term
  `p + v*dt + 0.5*a*dt^2` and velocity uses `v + a*dt`;
- invalid/NaN state immediately drops the slot and preserves native behavior;
  and
- the measured per-round CPU and memory budgets are recorded before Phase 3.

### Phase 3: native physical discrete bullets - implemented and accepted

Admit only MissileProjectile-family rounds that are:

- native hitscan;
- discrete rather than beam, flame, or continuous;
- non-explosive;
- not grenade, mine, thrown, or live-target launch;
- outside VATS, always-hit, live-target, and ignore-gravity launch policies;
- presented by a known nonzero source and form token.

The scoped wrapper changes only the initializer's local hitscan predicate
answer. It never mutates the linked BGSProjectile form or an initialized
runtime object. Native initialization, update, collision, impact, effects,
damage, attribution, and destruction stay in control.

Acceptance adds moving targets, doors closing after launch, near muzzle cover,
thin geometry, water, destructibles, corpses, multiple actors, high/low FPS,
paused transitions, cell boundaries, and save/load cleanup. Every rejected
round stays native.

### Phase 4: flight feedback

The native sound, tracer, impact, installed-content, performance, and
implementation contracts for this phase are complete in
[`atom_ballistics_flight_feedback_research.md`](atom_ballistics_flight_feedback_research.md).
Its first production slice is local-listener flight audio only. It explicitly
excludes view effects, AI suppression, damage, generic impact replacement, and
explosion behavior.

The research remains complete, but implementation is deferred behind Phase 5
gameplay ricochet. This changes delivery priority, not the proven audio
contract.

Once rounds physically traverse space, expose read-only flight events to Atom's
future audio, suppression, AI, and presentation systems:

- near-miss segment and closest distance;
- supersonic capability and pass time;
- source/target relation without retained raw pointers;
- impact material capability; and
- tracer/trail state without replacing logical trajectory.

These consumers may drop presentation work under load. They may not alter the
logical hit or block the projectile update.

### Phase 5: material response

The first production material-response slice is the strict, one-bounce
gameplay ricochet specified in
[`atom_ballistics_ricochet_research.md`](atom_ballistics_ricochet_research.md).
The native collision, material map, terminal impact, same-projectile movement,
damage attenuation, safe hook, installed-content compatibility, failure, test,
and bounded-playtest contracts are complete there.

Penetration remains a separate later impact policy. It still requires a proven
exit-point and thickness query, remaining-energy representation, maximum
depth, and repeat-target prevention; ricochet must not introduce it implicitly.

Native is the fallback when material is absent or contradictory. Continuation
must preserve source, weapon, condition, impact effects, attribution, and one
damage commit. Shared forms and projectile tails remain read-only.

### Phase 6: terminal energy and damage integration

Only after the physical and material paths are stable, introduce an optional
terminal-energy contribution at the complete projectile hit-data seam. Native
damage is calculated first. Atom policy receives the complete breakdown and
defaults to multiplier `1.0`.

This phase requires a separately documented balance model and black-box tests
for DT/DR, ammunition effects, criticals, limbs, armor wear, perks, difficulty,
shotguns, NPC damage, and mod-added records. It does not replace
`Actor::ApplyHit`.

### Phase 7: VATS and special families

VATS, beam, flame, continuous beam, explosive missile, grenade, mine, and
thrown support are independent follow-up contracts. They are not enabled by
loosening the discrete-bullet classifier.

## Test design

### Pure behavior tests

- capability classifier accepts/rejects complete synthetic form views;
- effective profile validation rejects zero, negative, NaN, and infinite data;
- table generation prevents a reused address matching an old projectile;
- overflow, expiry, and lifecycle clear preserve native fallback;
- launch-to-impact correlation handles pellets and repeated automatic fire;
- constant-acceleration integration and bounded chord subdivision;
- configuration defaults, bounds, unknown-field tolerance, and atomic
  publication; and
- saturating counters and histogram boundaries.

Tests exercise exported behavior through real module boundaries. They do not
search implementation source text.

### Hook and artifact tests

- typed x86 ABI sizes and offsets for every field Atom reads;
- immutable caller fingerprints around each admitted callsite;
- callsite transaction rollback when any member fails;
- predecessor chaining in a synthetic rel32-call harness;
- update-entry or vtable chain ownership harness before Phase 2;
- MCM artifact parses, retains existing defaults, and keeps all visible strings
  to one-to-three words;
- Atom remains ESP-less; and
- final DLL PE imports, TLS, sections, and configuration shape are compared with
  the last accepted Atom startup artifact.

### Runtime matrix

At minimum, exercise:

| Axis | Cases |
|---|---|
| Shooter | player, NPC, companion, turret, script |
| Fire mode | semi, automatic, burst, shotgun/multi-projectile |
| Projectile | hitscan bullet, physical bullet, explosive, beam, flame, continuous, grenade, mine, thrown |
| Context | hip fire, iron sight, crouch, movement, crippled arms, low condition |
| Target | actor, armor, limb, corpse, destructible, static, movable, terrain, water |
| State | pause, cell transition, load, new game, death, weapon swap |
| Timing | 30, 60, 120+ FPS and induced hitch |
| Ownership | vanilla predecessor and at least one synthetic chained predecessor per seam |
| Content | base game, DLC, and capability-equivalent mod-added records |

For Phase 1, record equality of health, ammunition, hit count, script events,
impact effects, and timing with tracing off/on. For Phase 3, compare native
fallback classes against baseline and physical classes against the documented
travel/collision expectations.

## Build, startup, and playtest gates

For each code phase:

1. run focused Atom tests on `i686-pc-windows-gnu`;
2. run the affected Atom test suite;
3. format and run `git diff --check`;
4. build the supported Atom release target explicitly;
5. build the complete supported FNV release set required by repository policy;
6. inspect the final diff and shipped MCM artifact;
7. compare Atom's complete pre-`DeferredInit` PE/config footprint against the
   last load-to-gameplay-playtested artifact; and
8. perform the explicit Proton load-to-gameplay test with BaseObjectSwapper
   installed, including three cold launches for any pre-deferred footprint
   delta.

Phase 1 additionally needs a prolonged no-op combat session before its evidence
can authorize mutable Phase 2 shadow state or Phase 3. Phase 3 needs encounter
playtests, not only a firing range, because moving actors, AI fire, doors,
cover, and cell activity expose the difference between real flight and delayed
ray damage.

## Failure behavior

- Unsupported executable: Atom rejects fixed-address gameplay work.
- Fingerprint mismatch: Ballistics rolls back; Atom Input remains available.
- Missing update ownership: observation stays available; shadow/physical modes
  remain unavailable.
- Unknown form or flags: that projectile stays native.
- Policy-scope capacity full or invalid source/form token: that projectile
  stays native and a counter increments.
- Observation pool full, lifecycle race, or invalid token: gameplay remains
  native; diagnostics lose correlation and generation-owned material response
  is unavailable for that projectile.
- MCM reload failure: the previous valid snapshot remains active.
- Policy call not observed: the projectile keeps the chained owner's answer
  and the requested summary records a miss.

No failure path disables another mod, rewrites a form, drops a native hit, or
turns an unsupported family into a guessed bullet.

## Research gates still open

These are runtime-acceptance or later-phase limits, not invitations to guess:

1. **Phase 3 hardening:** establish the broader callback-thread and
   nested-launch
   profile; current scope ownership is statically bounded for both.
2. **Phase 3 hardening:** expand runtime coverage across tracer,
   positive/zero-gravity, moving targets, and high/low frame rates. VATS,
   always-hit, live-target, and ignore-gravity routes are rejected by policy.
3. **Phase 3:** prove native collision uses the required swept path for the
   admitted speed/FPS envelope.
4. **Phase 5 implementation:** validate the proven canonical material map and
   strict stone/metal/hollow-metal admission across representative terrain,
   static, destructible, and movable collision in the bounded acceptance
   session.
5. **Phase 5 implementation:** prove the researched same-projectile
   continuation at runtime without duplicate damage or missing effects.
6. **Phase 7:** map VATS queued timing/playback and every special projectile
   family separately.

The focused Phase 3 gate has passed. The remaining Phase 3 items harden its
coverage and do not block the accepted default. Phase 5's static material and
continuation contract is complete; its Rust implementation, build, and bounded
runtime acceptance evidence remain open.

# Atom combat engine contract

## Status and purpose

This document is the research and architecture baseline for a future Atom
combat overhaul. It covers firearm handling, accuracy, projectiles, impacts,
explosions, melee, armor and damage, actor reactions, AI, VATS, and compatibility
with arbitrary vanilla and mod-added content.

The first combat change is now implemented and runtime accepted:
capability-proven discrete hitscan missiles may be routed into FNV's complete
native physical policy during MissileProjectile initialization. Atom changes only a scoped
hitscan-predicate answer; it never mutates a completed projectile, shared form,
or damage value. Static analysis proves the ownership and initialization
boundaries described here; it does not prove game feel or Proton acceptance.
Those remain governed by the phased plan below.

The address-level evidence is recorded in the
[radare2 combat evidence ledger](../analysis/radare2/output/gameplay/fnv_combat_contract.txt).
The established player control boundary is documented in
[the actor input contract](fnv_actor_input_contract.md).
The evidence-gated implementation sequence for the first combat milestone is
documented in the [Ballistics Core plan](atom_ballistics_core_plan.md).

## Supported executable and evidence

All address claims refer only to Fallout: New Vegas 1.4.0.525:

| Property | Value |
|---|---|
| Executable | `fnv_reverse/FalloutNV.exe` |
| Format | PE32 x86, image base `0x00400000` |
| Timestamp | `0x4E0D50ED` |
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |

The evidence has three strengths:

- **Proven:** direct radare2 disassembly/decompilation, xrefs, and binary data
  references from that executable.
- **Corroborated:** ABI layouts from the vendored xNVSE headers and names or
  compatibility observations from read-only source under `.research/`.
- **Inferred:** design conclusions assembled from proven facts. These remain
  subject to focused runtime tests.

Third-party source is not treated as vanilla behavior and is never a target for
mod-specific detection. It is useful for finding shared hook surfaces that Atom
must chain safely.

## Product model: modern combat is a pipeline

Modern-feeling combat cannot be obtained from a global damage multiplier or a
single spread value. Atom should treat it as seven related but independently
owned systems:

1. **Handling:** input response, view/weapon recoil, recovery, sway, movement,
   aiming, animation, cadence, reload, and jam feedback.
2. **Accuracy:** the weapon cone plus actor skill, stance, motion, condition,
   aiming, ammunition, modifications, and perks.
3. **Ballistics:** launch speed, gravity, range, travel time, drag if added,
   energy retention, and projectile lifetime.
4. **Impact:** material, incidence angle, target location, penetration,
   ricochet, effects, and continuation policy.
5. **Damage:** native weapon/ammunition baseline, DT/DR, resistance type,
   armor wear, limb damage, fatigue, criticals, and difficulty.
6. **Reaction:** pain, stagger, knockback, knockdown, cripple, dismemberment,
   death, scripts, AI hostility, and presentation.
7. **AI:** perception, weapon and ammunition choice, effective range, cover,
   burst timing, aggression, melee selection, and consumable use.

Their native flow is:

```text
input / AI / script / animation
             |
             v
      native attack admission
             |
       +-----+------------------+
       |                        |
       v                        v
  ranged fire              melee animation
  0x00523150               contact 0x00899CB0
       |                        |
       v                        v
  spawn 0x009BCA60      melee hit 0x009B5170
       |
       v
 projectile impact 0x009C1B70
       |
       v
 projectile hit 0x009B5650
       |
       +------------+-----------+
                    v
        protection/damage 0x009B5A30
                    |
                    v
          Actor::ApplyHit 0x0089A760
                    |
                    v
     scripts / AVs / reactions / death / AI

explosion 0x009B00A0 -> falloff + LOS -> explosion hit 0x009B5770
                                      -> same protection and ApplyHit path
```

The core architectural rule follows from this graph: Atom may calculate policy
around native boundaries, but it must retain native attack admission, launch,
protection, and final hit side effects unless a separately proven module owns a
specific replacement.

## Data-driven compatibility contract

Compatibility means behavior follows runtime capabilities, not the content's
origin. Atom must work without knowing whether a form came from the base game,
a DLC, or another plugin.

### Required classification rules

- Never branch on plugin name, load-order index, EditorID, or a curated FormID
  list to identify a weapon, ammunition, projectile, explosion, armor, chem, or
  actor.
- Read the actual `TESObjectWEAP` type, flags, data, modification slots, and
  linked forms.
- Resolve the equipped `InventoryEntryData`, instance `ExtraDataList`, current
  condition, and installed modifications. Base-form data alone is incomplete.
- Resolve the actual effective ammunition from the actor process. A weapon's
  ammunition field may be a `TESAmmo` or `BGSListForm`; selecting the first list
  member is not valid.
- Respect the ammunition projectile override and use the native effective
  projectile-count helper. Pellet count is not simply a weapon field.
- Preserve ammunition effects, perk entry points, active effects, actor values,
  weapon requirements, combat style, VATS state, and difficulty context.
- Treat unknown projectile subtypes and flags conservatively. Native behavior is
  the fallback.
- Read shared forms but never mutate them to express per-shot, per-instance, or
  per-actor state. Such writes change every user of the form and are unsafe with
  mod-added content.

### Why chems and perks need live context

Chems, perks, equipment, scripts, and active effects can alter actor values and
perk entry points without changing a weapon form. Relevant native entry points
include weapon damage, critical chance/damage, range, limb damage, spread,
reload and attack speed, knockdown, strength requirement, aiming movement,
attacker/defender DT, throwing velocity, item damage, and explosion radius.

Atom must sample effective values at the shot, contact, or hit boundary. A cache
keyed only by FormID would silently ignore temporary effects and instance state.

## Weapon and ammunition model

The native weapon form already describes a broad capability surface. Important
properties include:

- weapon family: unarmed, one- or two-handed melee, pistol, rifle, automatic,
  energy variants, launcher, grenade, mine, or thrown;
- automatic, burst, long-burst, scope, fixed-range, NPC-ammunition, and
  resistance flags;
- attack damage, skill and strength requirement, critical data, resistance
  actor value, limb multiplier, reach, and impact-data set;
- ammunition or ammunition list, ammunition use, clip size, projectile,
  projectile count, and minimum/maximum range;
- minimum spread, spread, aim arc, sight FOV, and sight usage;
- fire rate, animation shots per second, attack animation multiplier,
  semi-automatic delays, reload time, jam time, and animation selectors;
- on-hit dismemberment/body-part-explosion policy; and
- three installed modification slots, whose effects can change damage, clip,
  spread, weight, ammunition regeneration, equip time, rate of fire, projectile
  speed, condition, silence, split beam, VATS, or zoom.

Ammunition adds speed, projectile count, a projectile override, consumption,
ignore-resistance policy, casing, and ordered effects for damage, DR, DT,
spread, condition, and fatigue.

These are inputs, not a complete modern gun model. Atom should expose typed,
read-only views over them and derive per-action state without rewriting them.

## Ranged attack, cadence, reload, and jam

### Native ownership

Player controls express intent: attack is control 4, aim/block 6, ready/reload
7, VATS 16, and ammunition swap 18 in the native input path at `0x0093E860`.
They are not authoritative shot events. AI, scripts, VATS, animation events, and
`ForceFireWeapon` can commit attacks without the ordinary player-input edge.

The shared ranged-fire routine is `0x00523150`. It is reached by player and NPC
animation/event execution and by the script `FireWeapon` path. It owns effective
equipment resolution, muzzle and aim, dispersion, projectile count and spawn,
sounds, clip state, and ammunition consumption.

The canonical launch call is `0x005245BD -> 0x009BCA60`. The spawn function
allocates the correct projectile subtype and applies native source, equipment,
range, throwing-velocity perk, and launch context.

`PlayerCharacter::Update` calls the camera/input helper at `0x0093F8D9`, the
attack-input processor at `0x009420FC`, Actor animation/event update
`0x008BA600` at `0x0094380E`, and its final camera update at `0x00943825`.
Actor update reaches the shared fire routine at `0x008BADE9`. A camera policy
which follows only the physical attack button can therefore return to relaxed
facing before the later animation event launches a shot. The player high
process exposes the authored lifetime as current animation actions 2 through 6:
attack, follow-through, latency, throw attach, and throw release. Buffered
attack input is the entry edge; those process phases retain view-facing combat
until the native action ends. Neither observation is permission to authorize,
delay, or synthesize the shot.

For relaxed drawn locomotion, Atom retains only its presentation policy after
the active native or hip-fire-pose lifetime ends: 650 ms of view-facing grace
followed by 350 ms of shortest-angle movement-facing yaw recovery. The envelope
advances once per input frame, restarts on any new fire/aim/block/ready intent,
and clears at hard camera, lifecycle, world, cell, or holster boundaries. It
never writes the native action, restarts an animation, or delays projectile
admission. Actor pitch is never interpolated by this timer; native Combat look
retains its last value and the established Explore ownership edge performs one
neutralization. During recovery, camera recenter remains suppressed.

Supported player hip fire has a separate visual lifetime. One buffered attack
edge opens the session before native attack admission; held input, native
actions 2 through 6, and active Attack-family graph slots refresh it. When the
last action ends, Atom retains the view-facing weapon-ready pose for a default
800 ms. Observed between-shot gaps can extend that bounded quiet interval to
1.4 seconds, so automatic, burst, low-frame-rate, and replacement animation
cadences remain one session instead of alternating families. The Combat facing
envelope does not begin its fade grace until this session ends. Physical ADS,
holster, POV, menu, VATS, cell/world, lifecycle, external-owner, unsupported
weapon, and invalid graph boundaries clear the session.

Release is a bounded transaction rather than a posture-family morph. Atom
first stops remapping new native groups, then searches only the live Aim/AimIS
posture family. If one is visible it calls `AnimData`'s native sequence-type 4
stop owner once; if the graph is temporarily unavailable it retries for at
most 750 ms. No visible Aim-family sequence means there is nothing left for
Atom to release. Attack groups remain event-driven and are never selected by
explicit entry or exit, so retry cannot replay a shot.

The native adapter is the entry of
`AnimData::MorphToSequenceIDOrGroup` at `0x004948C0`, with ABI
`BSAnimGroupSequence* __thiscall(AnimData*, u16 group, i32 sequenceType)`.
Its researched body resolves the requested group at `0x004948E6` and performs
the transition at `0x00494989`. Atom remaps only the live third-person player's
supported ranged Aim/Attack normal/up/down triplet to the corresponding IS
triplet while the session is active. It preserves high group bits and the
sequence-type argument, then calls the captured predecessor exactly once.
Explicit posture morphs call that same captured chain with automatic sequence
type. This retains FNV's authored transition and kNVSE's internal
custom-path and blend hooks; Atom neither writes sequence weights nor moves a
weapon or skeleton node per frame. The admission fingerprint covers immutable
interior instructions and the epilogue rather than the mutable entry, allowing
Atom's inline owner to chain a compatible complete jump installed earlier. A
weapon whose flags declare `No3rdPersonISAnims` keeps camera-facing policy but
never enters the group adapter.

Release uses the separate native owner at `0x004994F0`, with ABI
`void __thiscall(AnimData*, u32 sequenceType, u8 flag)`. The supported-runtime
animation-group table at `0x011977D8` classifies Aim and AimIS as sequence type
4, their up variants as type 5, and their down variants as type 6. The type-4
branch stops types 5 and 6 before stopping type 4, using FNV's existing fade
and process callbacks. Therefore `AimIS -> Aim` is not relaxation: both groups
remain the same upper-body combat sequence type. Atom fingerprints this owner
through immutable interior lookup and epilogue instructions before admitting
the hip-fire adapter and never calls it from a per-frame path.

FNV exposes process IsAiming independently from the physical aim action, and
third-party animation/controller mods may retain that process bit after
automatic fire. Atom admits physical aim immediately. Process-only aim must be
stable for 120 ms outside a firing session; a bit observed during hip fire is
quarantined until it clears or a new physical aim edge proves a fresh ADS
transition. This prevents a retained bit from permanently routing head/body
look to one shoulder while preserving toggle-aim providers.

The pose does not become ballistic authority. Camera-facing Actor yaw/pitch
keeps the IS animation registered toward the logical view, while the existing
single-projectile real-muzzle convergence remains the exact gameplay path to
the rendered cursor target. Atom never translates the Actor to hide parallax.
Static contract and Wine-hosted suites pass; this presentation remains an
unaccepted candidate until a fresh Proton process verifies the full transition
matrix and confirms Atom, rather than another launch owner, owns convergence.

Broad attack admission occurs earlier in `0x00893A40`. That function mixes
action state, process state, animations, ammunition, condition, jam decisions,
VATS, and player/NPC behavior. It is not an appropriate first policy hook.

### Contract

- Observe a shot only after native attack admission. Do not convert raw attack
  input into an Atom projectile.
- Capture one immutable `ShotContext` at the canonical fire/spawn seam. The
  normal native path must still own clip consumption, animation, sound, jam,
  scripts, AI state, and projectile allocation.
- Preserve native semi-automatic, automatic, burst, and long-burst timing until
  a dedicated cadence module has separately proven every action-state branch.
- Preserve the ten weapon-condition curves used for rate of fire, jam, and
  reload jam.
- Preserve perk-driven attack, reload, equip, and aiming-movement speed.
- Keep one hip-fire pose session across repeated shots; do not force the native
  aiming flag, restart attack animations, or write animation weights per frame.
- Treat reload as a stateful native operation, including extended clips, ammo
  swaps/hotkeys, animation selection, and VATS playback. An instant inventory
  transfer is not an equivalent replacement.
- Support script-fired, player-fired, companion-fired, turret-fired, and NPC-
  fired weapons through the same data-driven capture path.

This boundary allows modern handling and ballistics to be layered onto a shot
without breaking the systems that authorized it.

## Accuracy, sway, and recoil

### Proven native spread

The native cone begins with:

```text
(effective weapon spread * actor spread factor
    + effective weapon minimum spread) * degrees-to-radians
```

Ammunition spread effects are then applied, and each projectile independently
samples radial and angular dispersion. The effective projectile count accounts
for the weapon, ammunition, ammunition use, and Split Beam modification.

The actor factor includes stance, walking/running, aimed versus unaimed state,
crouch and iron sights, skill, weapon requirements, arm/head condition, weapon
condition, perks, gun drift/wobble, and minimum-spread settings. Native code
caches multiple spread modes on the actor, and NPCs have an additional wobble
limit.

### Separation required by Atom

Spread is not recoil. Atom should retain distinct state and tuning for:

| Layer | Meaning | State owner |
|---|---|---|
| Base precision | Weapon/ammunition mechanical cone | Effective shot data |
| Actor error | Skill, stance, motion, injury, aiming | Native actor context |
| Sway | Low-frequency aim motion and breath | Per-actor handling state |
| Recoil impulse | Immediate view/weapon displacement | Per-shot handling state |
| Recovery | Return speed, damping, pattern memory | Per-actor handling state |
| Animation | First/third-person visual response | Native animation plus adapter |

A modern handling module may derive recoil from effective caliber/proxy energy,
weapon family, mass, stance, burst history, and actor state, but those are Atom
policy. It must not overwrite shared weapon spread or use spread as camera kick.

First- and third-person recoil camera/animation ownership remains an open
focused research item. The proven hip-fire group adapter does not authorize a
recoil hook or any per-frame skeleton manipulation.

### Aim convergence and cover

Third-person aiming has two distinct geometric questions: where the view ray
points and whether a projectile starting at the real muzzle can reach that
point. A shoulder camera that changes launch origin can shoot around nearby
cover; a system that aims only along the muzzle forward can miss the crosshair
at distance.

The camera follow-up research closes both native boundaries. At
`0x0070C130 -> 0x00631D60`, the existing `ViewCaster` accepts start, direction,
maximum distance, and distance/alternate-hit outputs, excludes the player, and
uses the native reticle collision filter. While Atom owns stable third person,
a scoped wrapper supplies Atom's logical view ray and chains the live
predecessor only through the eye-centered activation-reach interval. The caller
also publishes the resolved crosshair point at `InterfaceManager +0x104`.
Native states pass the original arguments unchanged. This interaction result
is never reused as weapon depth because activation reach is shorter than valid
projectile range.

At the normal ranged spawn call `0x005245BD -> 0x009BCA60`, Atom can resolve the
real `##ProjectileNode` muzzle and synchronously query the completed render
camera ray through `TES::PickObject` at `0x00458420`. The stack-owned,
16-byte-aligned `bhkPickData` is constructed by `0x004A3C20`; its `0xB0` layout
places the collision filter at `+0x24`, hit fraction at `+0x40`, and failure
byte at `+0xAC`. `PlayerCharacter::GetCollisionFilter` at `0x00931ED0` supplies
the live collision group, while Atom replaces only the low collision layer
with projectile layer 6. The query therefore ignores the firing player's own
group and observes projectile-relevant world collision without mutable global
scratch state.

Atom points the native projectile at the first camera-ray collision, preserves
the sampled angular spread already in the launch arguments, and calls the live
spawn predecessor exactly once. Because the real native projectile starts at
the muzzle, native collision makes near obstruction win; an additional muzzle
cast is neither necessary nor desirable.
Projectile class, hitscan/physical flags, velocity, gravity, range, collision,
and impact remain engine-owned. The visual and damaging shot are the same
native instance launched from the real muzzle. Visual camera shake never feeds
back into the logical view ray.

The fire wrapper accepts only a live player, owned camera epoch, supported
weapon/projectile pair, finite render-camera basis, and validated ray output.
The first launch in an input frame publishes a pointer-free depth sample keyed
by player, ownership epoch, frame, camera origin/direction, and projectile
range. Shotgun pellets reuse that depth but retain their independently sampled
native spread. Any mismatch or native ray failure leaves the launch unchanged.

This needs an exclusive capability owner. Atom must chain an existing launch
predecessor and fail admission if another inline aim transformation cannot be
safely composed. It must not detect a named aim-fix plugin. First person, NPCs,
VATS, continuous beams, and thrown objects keep native convergence until their
individual geometry is proven.

## Projectile and physical ballistics

### Native projectile contract

Projectile forms describe type, hitscan/physical policy, gravity, speed, range,
timer, proximity, explosion, tracer, sounds, muzzle flash, impact force, bounce,
rotation, and collision flags. Runtime projectiles retain source actor, weapon,
weapon condition, speed multiplier, direction, range, age, damage, distance
travelled, impact list, and subtype-specific state.

The cached runtime direction at `+0x104` is not a launch-admission vector.
The common constructor initializes it to the engine's zero vector, while
MissileProjectile movement constructs a frame displacement from effective
speed and applies projectile orientation through the native movement route.
A fresh zero cached direction is therefore valid; only non-finite components
are corrupt state.

Derived types include beam, flame, grenade, missile, and continuous beam. Their
virtual update and impact behavior must remain intact. A generic struct cast or
whole-family vtable replacement is not acceptable.

### Extension-state rule

Existing xNVSE extensions already use bytes near the end of the vanilla
projectile object, and different projectile subtypes extend the object. Atom
must not write spare-looking tail bytes.

New state belongs in a fixed-capacity side table keyed by a validated projectile
identity plus generation/liveness token. It may store, for example:

```text
launch position and time
previous position
initial and remaining energy proxy
drag/drop integration state
penetration count and travelled material depth
ricochet count
originating ShotContext handle
```

The table must have deterministic overflow behavior, no allocation in the
update/impact path, and cleanup on projectile death, reference destruction,
load, new game, and relevant lifecycle transitions. A raw pointer alone is not
a persistent identity.

### Native-initialization physical policy

Changing every hitscan form into a physical projectile by mutating forms is
incompatible. It can alter other mods' assumptions, VATS timing, beam/tracer
presentation, scripts, impacts, and projectile subtypes globally.

The physical-ballistics module therefore uses a per-shot policy that:

- preserves the original weapon, ammunition, source, condition, count, sounds,
  impact-data set, scripts, and kill attribution;
- uses the native spawn path where possible;
- defines the treatment of beam, flame, continuous beam, shotgun, launcher,
  thrown, mine, and already-physical projectile families;
- keeps native VATS unless queued timing and playback are explicitly solved;
- has a bounded fallback to the original projectile when it cannot safely adapt;
  and
- is tested against synchronous hitscan observations and existing projectile
  extensions.

Focused static analysis proves MissileProjectile's complete launch-time flag
derivation at `0x009B7CC0`. The initializer retrieves its live projectile form
and invokes `BGSProjectile::IsHitScan` (`u8 __thiscall(BGSProjectile*)`) at
callsite `0x009B7D08`. The result byte is the only local hitscan policy used by
the remaining block. Hitscan selects `0x0001`, `0x0008`, `0x2000`, plus exactly
one of tracer-dependent `0x0020` or non-tracer `0x0002`. Physical flight
selects `0x8000` and selects `0x0040` when native gravity is positive.
Independent tracer `0x0010` and initialization `0x0100` remain intact.

VATS state 4 supplies false to this same local policy before the flags are
derived. It does not clear the shared form's hitscan flag. This is direct native
precedent for a per-object physical policy while later consumers retain the
form's original semantics.

Atom captures the current target encoded at `0x009B7D08` and calls it exactly
once. Immutable fingerprints cover instructions before and after the mutable
five-byte call without requiring a vanilla displacement. The canonical launch
wrapper publishes a bounded thread/form scope only while its own captured
launch predecessor executes. A matching true result is changed to false; a
matching false result from an earlier owner stays false; unmatched forms,
threads, and calls outside the scope preserve the predecessor result. FNV then
derives every runtime field and flag before common initialization and process
admission. Atom performs no post-launch runtime mutation.

The initial 2026-08-16 Proton observation recorded 251 canonical launches and
exactly 251 first correlated contacts while chaining a non-vanilla launch
owner. It observed no contact before that predecessor returned, no invalid
value or pool overflow, and one callback thread. This is positive evidence for
the sampled hitscan and beam session, not general admission: it contained no
actor `ApplyHit`, physical missile, special projectile family, or
multi-projectile launch. The retained excerpt and exact DLL identity are in
`.reports/atom-ballistics-phase1-2026-08-16.log`.

Focused follow-up analysis proves a composable read-only update seam.
MissileProjectile vtable `0x0108FA44` stores its `+0x310` subtype update at
`0x0108FD54`, with vanilla target `0x009B8030` and ABI
`void __thiscall(MissileProjectile*, float)`. Common update calls that slot and
continues to use the live object after it returns. Atom may therefore CAS-chain
the slot's current owner and compare pre/post position `+0x30`, runtime policy
flags `+0xC8`, age/range/distance, impact state, and authoritative speed from
`0x009669C0` without taking movement ownership. A fresh Proton process then
recorded 164 first hitscan updates and no early update/contact; two callback
threads and nine non-impacted movement outliers reproduced systematically.

The implemented scope uses eight fixed atomic slots and stores only Windows
thread ID, numeric form token, and Boolean state. Nested launches temporarily
replace and restore their thread's outer frame. The RAII guard is not `Send`.
There is no heap allocation, blocking lock, TLS value, engine pointer, file I/O,
or routine log in either hot path. Slot exhaustion, unsupported context, or an
unobserved policy call keeps the round fully native.

The accepted Proton run of DLL SHA-256 `e34c81bf...` recorded 68 policy
candidates, 68 forced-physical decisions, 68 first MissileProjectile updates,
106 progressive update steps, 71 delayed first contacts, two actor hit builds,
and exactly two native `ApplyHit` calls. No policy miss, invalid sample, or pool
overflow occurred. The previous summary incorrectly derived launch success
from the later live `0x2000`/`0x8000` marker pair and classified every update
as `other`. Atom now retains the immutable initializer selection in its
observation record and reports later marker coexistence separately; it does
not repair or overwrite another runtime owner's flags. The scoped policy is
therefore enabled by default. The broader content, movement, miss, and
frame-rate matrix remains hardening work rather than an admission blocker.

The installed content audit supports the capability boundary. Kyu's Ballistics
Fixed - TTW contains 24 patched type-1 Missile projectile records, all with
hitscan flags and live speed/range/gravity data. Improved Bullet Tracers edits
those live forms' tracer/model/presentation fields and optionally speed/range;
the installed configuration leaves speed and range unchanged. Third Person Aim
Fix owns the launch predecessor captured by prior telemetry. Because Atom
scopes around and chains that owner, reads the final live form, and changes only
the initializer-local answer, these mods do not require names, FormIDs, or
load-order-specific patches.

### Thrown weapons, grenades, mines, flames, and beams

Grenade, mine, lunchbox mine, and thrown are distinct weapon types. Their launch
context can carry a live target, gravity policy, angular momentum, rotation,
bounce, timer, proximity, detonation, pickup, and disarm state. Native launch
also dispatches the throwing-velocity perk entry point.

Flame, beam, and continuous-beam projectiles have subtype-specific virtual
update and impact behavior. They cannot be treated as one discrete ballistic
bullet merely because they derive from the same runtime base.

Atom must therefore classify and preserve:

- thrown arc and angular momentum;
- grenade fuse, alternate trigger, source, and live target;
- mine placement, arming, proximity, pickup, and disarm;
- explosion attribution through source reference, weapon, and `ActorCause`;
- flame/beam duration, repeated contact, presentation, and native subtype; and
- native fallback for any family whose update cadence is not yet proven.

Firearm recoil, drag, penetration, or one-shot damage transformations do not
automatically apply to these families.

## Impacts, material response, penetration, and ricochet

Native impact records provide the hit reference, position, surface vector,
rigid body, material, and hit location. Projectile virtual impact processing
walks those records, builds projectile hit data, and decides whether the
projectile is destroyed, bounced, impaled, stuck, or retained.

Atom should introduce an immutable `ImpactContext` that combines:

- the associated shot/projectile context;
- impact reference, location, position, normal, and material capability;
- incoming direction, speed/energy proxy, and incidence angle;
- actor/body-part context where present; and
- the native impact result and presentation data.

Penetration and ricochet must be explicit impact policies, not global random
chances. A compatible design needs material capability, angle and remaining
energy thresholds, maximum continuation depth/count, repeat-target prevention,
and deterministic overflow. Continuation must preserve source/weapon/condition
and use a proven native spawn/update path.

The first production ricochet contract is now closed in
[`atom_ballistics_ricochet_research.md`](atom_ballistics_ricochet_research.md).
Static evidence proves the raw-to-canonical material map, ordinary impact
result, common target/effect traversal, reference-rotation movement authority,
per-projectile speed/damage controls, list reset, and safe pre-terminal callsite.
Its strict first slice runs native first-contact work once, then continues the
same projectile only for a shallow stone, metal, or hollow-metal non-Actor
impact. Every unknown or special case remains native.

Penetration, actor armor deflection, multiple bounces, and special projectile
families remain unproven and require separate research. Do not generalize the
ricochet admission rules to them.

## Explosions

### Native model

Explosion forms independently describe damage, force, radius, image-space
radius, radiation, sounds, lights, impact data, placed objects, LOS policy, and
knockdown policy. Runtime explosions retain source reference, source weapon,
ActorCause, target list, closest point/normal, radius, and calculated damage.

The target loop begins at `0x009B00A0`. Native distance falloff called at
`0x009B01A8` is:

```text
0                                  when distance >= radius
1 - (distance / radius)^2          when distance < radius
```

Line of sight is evaluated through `0x009B1810` unless the explosion form
ignores LOS. The explosion producer `0x009B5770` then uses the common native
protection and final hit paths.

### Contract

- Keep damage falloff, target distance, LOS, physical force, knockdown,
  radiation, image-space effects, sound, and water behavior as separate policy
  channels. Changing damage must not silently change physical presentation.
- Retain the source actor/reference and source weapon so kill attribution,
  resistance actor values, perks, hostility, and scripts receive the correct
  context.
- Chain the currently installed falloff, distance, LOS, and hit call targets.
  Existing extensions use all of those surfaces.
- Do not implement self-damage, ally damage, or occlusion rules by suppressing
  `Actor::ApplyHit` globally.
- Respect mod-added explosion flags and radiation data. Unknown combinations
  fall through to native behavior.

Perk entry point 72 can modify explosion radius. The effective runtime radius,
not only the base form radius, belongs in `ExplosionContext`.

## Melee, unarmed, and blocking

Native melee is animation-contact driven. Attack input and animation admission
do not prove a hit. The contact event reaches `0x00899CB0`, which resolves the
target, nodes, material, position, and direction before the melee hit producer
at `0x009B5170` builds complete hit data.

The producer accounts for the actual weapon/unarmed state, health and fatigue,
power attack and VATS context, criticals, protection, blocking, location, and
final multipliers. Relevant data includes weapon reach, animation selection,
skill and strength, condition, directional power attacks, hand damage/fatigue,
attack fatigue, and combat-style attack/block policy.

The common protection routine calculates blocking through native defender
state and a valid block source. `0x006463A0` derives the skill contribution from
`fBlockSkillBase + skill * fBlockSkillMult`; the resulting contribution is
recorded in hit data before final DT processing.

### Contract

- Observe successful native contact, not attack-button input.
- Preserve animation events and action state so player, AI, creatures, power
  attacks, directional attacks, and modded animation sets remain functional.
- Classify unarmed, one-handed, two-handed, thrown, and special weapon forms by
  effective type and capability.
- Preserve block state, shield/weapon source where valid, fatigue cost, DT/DR,
  perks, reach, and native critical/limb logic.
- Do not copy ranged locational rules onto melee; the native branches differ.
- Treat parry windows, timed blocks, poise, and melee hit-stop as future Atom
  policy layered around contact and reaction, not as reasons to replace native
  attack admission.

Creature natural attacks and unknown special attacks must retain native
behavior until their contact context has been proven.

## Damage, armor, criticals, and limbs

### Native live calculation

The live weapon damage family at `0x00644CE0` uses weapon damage/type, source
skill and strength, requirements, arm state, weapon instance condition,
effective ammunition/projectile count/modifications, perks, and action context.
Atom must not use an inventory-display damage value as a hit baseline.

Native weapon condition is full strength from 75 to 100 percent and scales
linearly down to 50 percent at zero condition. Other condition curves separately
control spread, fire rate, jam, and reload jam.

### ActorHitData is the policy boundary

The engine builds a complete 0x64-byte `ActorHitData` for melee, projectile,
generic direct, explosion, and physics damage. The common calculation at
`0x009B5A30` resolves ammunition effects, DR, DT, block, armor wear, resistance
actor value, perks, minimum damage, fatigue, and context-specific multipliers.

The independent post-calculation call sites are:

| Damage family | Call to native calculation |
|---|---:|
| Melee/unarmed | `0x009B5623` |
| Projectile | `0x009B5702` |
| Generic direct | `0x009B575C` |
| Explosion | `0x009B58AE` |
| Physics collision | `0x009B5A10` |

A damage policy can chain the installed predecessor, inspect the complete
record, and then make a coherent bounded adjustment before native
`Actor::ApplyHit`. The initial Atom module should cover only explicitly owned
combat families; generic direct and physics damage should remain native unless
their desired scope is separately defined.

### Native ordering that must be preserved

The native calculation includes, in order, a minimum-damage floor, ammunition
fatigue, target DR and ammunition DR effects, armor wear, target DT and
ammunition DT effects, native block contribution, attacker/defender DT perk
entry points, threshold subtraction and multi-projectile handling, ammunition
damage, final damage perks, resistance actor value, fatigue reconciliation, and
contextual player/VATS combat multipliers. Player-versus-NPC difficulty is
applied later in the native health/fatigue commit path.

Weapons and ammunition may ignore normal resistance, and a weapon/projectile
may name another actor value as a percentage resistance. A replacement formula
that models only DT is not compatible.

### Coherent adjustment rules

Any Atom damage transformation must explicitly define how it changes:

- final health damage;
- base/weapon damage retained for later logic;
- limb damage and cripple thresholds;
- fatigue damage;
- armor wear and source weapon wear;
- block contribution;
- critical and sneak flags/damage;
- stagger/knockdown inputs; and
- minimum-damage and difficulty semantics.

Scaling only `healthDamage` can make limb, fatigue, armor wear, reactions, and
UI disagree. The wrapper should expose a named `DamageBreakdown` and require a
policy to state which components it owns. Native values remain the default.

Critical chance/damage, critical effects, hit location, and limb multipliers
are native stages after source/equipment context has been established. Atom
must preserve their perk dispatch and weapon on-hit policy.

### Anatomy is target data, not a humanoid assumption

Actors expose effective `BGSBodyPartData`. Its 15 nullable slots cover torso,
head variants, segmented arms and legs, brain, and weapon. A `BGSBodyPart`
provides node and VATS target names, damage multiplier, limb-health percentage,
actor value, VATS chance, head/sever/explode flags, debris, explosions, and
impact-data sets.

Those slots define capacity, not guaranteed anatomy. Creatures and mod-added
races can omit or repurpose entries and nodes. Atom must resolve the target's
effective body-part data, accept no-location/custom/null cases, and let native
location logic remain authoritative. It must not assume that every enemy has a
human head, two arms, two legs, or a conventional skeleton.

## Enemy damage handling and final reactions

`Actor::ApplyHit` at `0x0089A760` is not a convenient damage setter. It is the
central commit operation for combat side effects, including:

- last-hit process records;
- `OnHit` and `OnHitWith` script events;
- hostility, combat state, target awareness, and AI notification;
- health and fatigue actor-value damage;
- armor and weapon condition damage;
- limb damage, cripple, dismemberment, and body-part explosion;
- pain, stagger, knockback, knockdown, critical weapon drop, and ragdoll;
- essential/fatal/death handling;
- experience, kill credit, perks, challenges, interface, and VATS effects.

Health/fatigue application also invokes native player-versus-NPC difficulty
handling. Replacing or returning early from `Actor::ApplyHit` would require
reimplementing all of these observable contracts and would break scripts and
other mods.

Therefore:

- Atom may change complete hit data before the call.
- Atom must let the native call commit the hit.
- Atom must not hook generic `DamageActorValue` as a gunplay policy surface;
  that path also receives scripts, hazards, magic, radiation, and other damage
  without complete weapon/impact context.
- Reaction tuning should use the native hit context and dedicated seams rather
  than replaying damage or inventing a second hit.
- Essential and scripted-death behavior remains native.

This is the key rule for correct enemy damage handling.

## AI combat

Native AI separates planning from execution. The combat controller owns weapon
and ammunition candidates, DPS comparisons, selected weapon and combat style,
target/LOS/threat state, dangerous explosives, timers, cooldowns, and tactical
actions. Combat styles describe cover, wait/fire timing, effective ranges,
semi-automatic delays, target FOV, combat radius, dodge, block, attack,
power-attack, stagger/knockout, and movement/skill coefficients.

The effective style is dynamic: actor, base/template, and `ExtraCombatStyle`
can contribute. It cannot be safely cached or selected by hard-coded FormID.

Once AI commits an attack, ranged execution reaches the common fire path and
melee execution reaches common contact/damage paths. This supports a safe split:

1. The first combat wrapper observes AI shots and contacts through the shared
   execution seams and applies the same capability-driven rules as the player.
2. A later AI module may alter scoring, range choice, burst timing, cover, or
   consumable policy after those planner contracts receive focused research.

Atom must not replace the AI planner merely to make bullets or damage modern.
Likewise, global GameSetting edits are too coarse for per-actor weapon handling
and commonly conflict with other overhauls.

## VATS

VATS hit chance is calculated by `0x00646F70`. It has distinct paths for ranged,
melee, grenade/projectile, and destructible targets and uses range, visibility,
screen percentage, target limb, arm condition, skill, weapon VATS data, spread,
and specialized settings.

VATS also owns admission, displayed chance, queued attacks, action points,
playback, target/projectile selection, critical behavior, and special reload
timing. Although an executed VATS attack eventually converges on projectiles and
hits, that does not make its earlier timing interchangeable with real-time fire.

The first Atom combat implementation must preserve VATS. Physical ballistics or
handling changes may opt out during VATS until queued-shot timing, displayed
chance, camera playback, and hit resolution are separately proven. Silent
desynchronization between the displayed chance and actual policy is not
acceptable.

## Proposed wrapper architecture

The wrapper should be split by ownership so an unsupported capability disables
one feature rather than all combat.

```text
combat::native
  executable admission, instruction fingerprints, typed calls, process guards

combat::forms
  read-only WeaponView, EffectiveAmmo, ProjectileSpec, ExplosionSpec,
  CombatStyleView

combat::shot
  immutable ShotContext capture at the native fire/spawn boundary

combat::handling
  bounded per-actor recoil, recovery, sway, and burst history

combat::projectile
  fixed-capacity sidecar state and scoped native physical-flight policy

combat::impact
  ImpactContext, material observation, penetration/ricochet policy

combat::damage
  native-first ActorHitData policy and coherent DamageBreakdown

combat::explosion
  effective radius, falloff, LOS, attribution, and force policy

combat::melee
  contact, block, power-attack, fatigue, and future parry/poise policy

combat::ai
  initial observation; later planner scoring as a separately admitted module
```

Conceptual interfaces, not final Rust ABI:

```rust
struct ShotContext {
    source: RefToken,
    weapon_form: FormToken,
    weapon_instance: InstanceToken,
    ammo_form: Option<FormToken>,
    projectile_form: FormToken,
    condition: f32,
    projectile_count: u8,
    ammo_use: u8,
    origin: Vec3,
    direction: Vec3,
    native_spread_radians: f32,
    native_damage: f32,
    flags: ShotFlags,
}

struct ImpactContext {
    shot: ShotHandle,
    projectile: RefToken,
    target: Option<RefToken>,
    position: Vec3,
    normal: Vec3,
    hit_location: i32,
    material: MaterialCapability,
    speed: f32,
    incidence: f32,
}

trait DamagePolicy {
    fn adjust(&self, context: &DamageContext, damage: &mut DamageBreakdown);
}
```

Tokens must validate identity and liveness. No raw engine pointer may survive a
frame, cell unload, process demotion, save/load, or reference destruction
without revalidation.

## Hook ownership and compatibility

Potential seams are not permission to patch all of them. Each implementation
phase should admit only what it owns.

The implemented Ballistics transaction owns six caller-local seams plus one
stable vtable slot: effective projectile count `0x00524413`, launch
`0x005245BD`, MissileProjectile hitscan policy `0x009B7D08`, hit construction
`0x009C1E61`, projectile `ApplyHit` `0x009C1E96`, collision effects
`0x009C2058`, and MissileProjectile update slot `0x0108FD54`. Each wrapper
chains the target currently encoded at its seam exactly once. Disabled mode
does not inspect engine data. Enabled mode reads the live projectile form only
during launch and common runtime fields only while the native update callback
owns the object; stored values are pointer-free and engine addresses remain
opaque numeric correlation tokens.

| Need | Preferred seam | Rule |
|---|---|---|
| Capture launched shot | call `0x005245BD` to `0x009BCA60` | Call current predecessor; preserve returned subtype |
| Select physical missile policy | call `0x009B7D08` to live hitscan predicate owner | Scope by thread/form; change only true to false before native derivation |
| Observe missile flight | vtable slot `0x0108FD54` | CAS-chain current owner; never move the projectile |
| Projectile impact observation | virtual path under `0x009B8B10`/`0x009C1B70` | Do not replace whole virtual family |
| Projectile damage policy | call `0x009B5702` | Native calculation first, policy second |
| Melee damage policy | call `0x009B5623` | Native calculation first, policy second |
| Explosion damage policy | call `0x009B58AE` | Native calculation first, policy second |
| Explosion falloff | call `0x009B01A8` | Separate from distance, LOS, and force |
| Explosion LOS | call `0x009B045C` | Preserve form ignore-LOS policy |
| Melee contact observation | `0x00899CB0` family | Observe resolved contact, not input |
| Final hit commit | `0x0089A760` | Never replace or suppress globally |

Every patch must:

1. Admit only the executable identity above.
2. Install no earlier than Atom's established `DeferredInit` lifecycle boundary.
3. Validate the local opcode, stack/register contract, and surrounding caller
   context, not only an address.
4. Capture and call the current predecessor so established hook chains remain
   intact. Do not require the target still to be the vanilla function.
5. Be transactional and independently reversible. A mismatch disables only the
   affected module and logs the consequence.
6. Avoid identifying, inspecting, disabling, or special-casing another mod.
7. Avoid shared-form mutation, projectile-tail storage, global vtable takeover,
   or a second synthetic ApplyHit.

## Runtime ownership and performance

Combat fire, projectile update, impact, and damage are hot paths. Their wrappers
must have:

- no allocation, file I/O, blocking lock, configuration parsing, shader work,
  or routine diagnostic formatting;
- bounded work per projectile, impact, and actor;
- fixed-capacity tables with visible counters and deterministic native fallback;
- immutable published configuration snapshots;
- main-thread ownership unless a specific engine path is proven otherwise;
- stable logger messages only for lifecycle, admission failure, capacity
  degradation, and explicitly requested summaries; and
- cleanup on load/new-game and destruction boundaries.

Actor process data must be capability checked. Low-process actors do not expose
all `MiddleHighProcess` or `HighProcess` fields. A missing detail capability is
a reason to retain native behavior, not to dereference an assumed layout.

## Native settings dependency index

Native combat reads many global GameSettings. They are dependencies to preserve,
not a proposed Atom configuration surface. Other mods may already tune them, so
the wrapper should consume the resulting native calculation rather than restore
hard-coded vanilla values.

| Area | Settings used by the mapped paths |
|---|---|
| Posture and movement spread | `fStandingSpreadPenalty`, `fWalkingSpreadPenalty`, `fRunningSpreadPenalty`, `fUnaimedSpreadPenalty` |
| Injury and spread | `fCrippledArm1HSpreadPenalty`, `fCrippledArms1HSpreadPenalty`, `fCrippledArm2HSpreadPenalty`, `fCrippledArms2HSpreadPenalty` |
| Spread formula | `fGunSpreadSkillBase/Mult`, `fGunSpreadArmBase/Mult`, `fGunSpreadNPCArmBase/Mult`, `fGunSpreadHeadBase/Mult`, `fGunSpreadCrouchBase/Mult`, `fGunSpreadRunBase/Mult`, `fGunSpreadWalkBase/Mult`, `fGunSpreadCondBase/Mult`, `fGunSpreadIronSightsBase/Mult`, `fGunSpreadDriftBase/Mult`, `fWobbleToSkillConversion`, `fMinGunSpreadValue`, `fNPCMaxGunWobbleAngle` |
| Weapon condition | `fWeaponConditionSpread1..10`, `fWeaponConditionRateOfFire1..10`, `fWeaponConditionJam1..10`, `fWeaponConditionReloadJam1..10` |
| Weapon damage | `fDamageWeaponMult`, `fDamageSkillBase/Mult`, `fDamageStrengthBase/Mult`, `fDamageArmConditionBase/Mult`, `fDamageGunWeapCondBase/Mult`, `fDamageMeleeWeapCondBase/Mult`, `fMinDamMultiplier`, `fDamageToArmorPercentage`, `fDamageToWeaponValue` |
| Unarmed/melee | `fHandDamageSkillBase/Mult`, `fHandDamageStrengthBase/Mult`, `fHandFatigueDamageBase/Mult`, `fHandHealthMin/Max`, `fHandReachMult`, `fDamagePowerAttackBonus`, `fDamagePowerAttackBack/Forward/Side/StandBonus`, `fFatigueAttackWeaponBase/Mult` |
| Blocking | `fBlockSkillBase/Mult`, `fFatigueBlockBase/Mult`, `fFatigueBlockSkillBase/Mult` |
| Reactions | `fKnockbackAgilBase/Mult`, `fKnockbackDamageBase/Mult`, `fKnockbackForceMax`, `fKnockbackTime`, `fKnockdownAgilBase/Mult`, `fKnockdownDamageBase/Mult`, `fKnockdownBaseHealthThreshold`, `fKnockdownCurrentHealthThreshold`, `fKnockdownChance`, `iCombatCrippledTorsoHitStaggerChance` |
| Death impulse | `fDeathForceDamageMin/Max`, `fDeathForceForceMin/Max`, `fDeathForceRangedDamageMin/Max`, `fDeathForceRangedForceMin/Max`, `fCombatDismemberedLimbVelocity` |
| Explosions | `fExplosionForceMultLinear`, `fExplosionForceMultAngular`, `fExplosionForceKnockdownMinimum`, `fExplosionLOSBuffer`, `fExplosionLOSBufferDistance`, `fExplosionMaxImpulse`, `fExplosionSourceRefMult`, `fExplosionSplashRadius`, `fExplosionWaterRadiusRatio`, image-space and shudder settings |
| Difficulty | `fDiffMultHPByPCE/PCH/PCN/PCVE/PCVH`, `fDiffMultHPToPCE/PCH/PCN/PCVE/PCVH`, `fDifficultyDamageMultiplier` |
| AI execution | `fCombatAbsoluteMaxRangeMult`, `fCombatCurrentWeaponAbsoluteMaxRangeMult`, `fCombatProjectileMaxRangeOptimalMult`, `fCombatFiringArcStationaryTurnMult`, `fCombatIronSightsDistance`, `fCombatIronSightsRangeMult`, `fCombatRangedStandoffTimer`, `fCombatInventoryUpdateTimer`, `fCombatLineOfSightTimer`, `fCombatLOSBufferTime`, grenade, cover, threat, and search setting families |
| VATS | `fVATSMaxChance`, `fVATSHitChanceMult`, `fVATSSkillFactor`, `fVATSScreenPercentFactor`, `fVATSRangeSpreadMax`, `fVATSSpreadMult`, shotgun/grenade/thrown/melee range and chance families, `fVATSCriticalChanceBonus`, `fVATSPlayerDamageMult` |

The table is an index of the families reached by the researched subsystems, not
a claim that every similarly named setting participates in every attack. The
binary call graph determines relevance for a particular path.

## Failure behavior

Compatibility failures must be local and fail closed:

- executable or instruction mismatch: do not install that module;
- missing actor/equipment/ammunition context: use native shot behavior;
- unsupported projectile subtype: use its native update and impact path;
- side-table exhaustion: stop adding Atom extension state, retain native
  projectile behavior, and emit a rate-limited warning outside the hot path;
- invalid or stale token: discard Atom state without touching the engine object;
- unknown material or collision type: native impact;
- unavailable complete hit context: native damage;
- VATS or scripted special case not admitted by the feature: native behavior.

Disabling the requested combat system globally is not an acceptable fallback.

## Implementation sequence

The research supports incremental delivery. Each phase should ship only after
its focused and cross-feature gates pass.

### Phase 0: observation and native context

- Implement executable admission, typed read-only views, process guards, and
  effective weapon/ammunition/projectile resolution.
- Capture bounded shot, impact, and hit summaries without changing outcomes.
- Prove player, NPC, script, VATS, melee, and explosion attribution in game.

### Phase 1: damage policy shell

- Chain the projectile, melee, and explosion post-calculation seams.
- Expose native `DamageBreakdown`; initially return it unchanged.
- Add one narrowly scoped policy at a time while preserving ApplyHit.
- Prove DT/DR, resistance types, armor wear, criticals, limbs, scripts, and
  difficulty through behavioral tests and playtest.

### Phase 2: handling and accuracy

- Research first-/third-person camera and animation ownership.
- Add per-actor recoil, recovery, and sway separately from effective spread.
- Preserve native cadence, jam, reload, AI execution, and VATS until admitted.

### Phase 3: physical ballistics

- Retain the projectile side table and native physical-projectile observation.
- Select the scoped native initialization policy only for admitted discrete
  hitscan missiles; keep native fallback for every other family and context.
- Prove native frame-time integration, collision, and bounded cleanup in the
  supported runtime.

### Phase 4: material impacts

- Implement the strict one-bounce stone/metal/hollow-metal ricochet contract in
  [`atom_ballistics_ricochet_research.md`](atom_ballistics_ricochet_research.md).
- Prove the same generation reaches a later native contact and damage path in
  one bounded Proton acceptance session.
- Preserve native effects, scripts, decals, sounds, attribution, and complete
  fallback for unsupported materials and projectile families.
- Research penetration separately; do not infer it from ricochet.

### Phase 5: explosions

- Introduce `ExplosionContext` and independently configurable damage falloff,
  LOS, force, knockdown, and radiation behavior.
- Test source weapon attribution, self/allies, water, and existing hook chains.

### Phase 6: melee and block

- Add contact-driven melee policy, stamina/poise, timed block/parry, and reaction
  tuning only after animation/action-state ownership is proven.
- Retain native creature/special attack fallback.

### Phase 7: AI policy

- Research and wrap planner scoring independently of execution.
- Teach AI about effective range, penetration risk, burst discipline, cover,
  melee commitment, explosives, and consumables without form lists.

## Acceptance matrix

No combat phase is complete based on compilation or a player-only test. At a
minimum, the affected phase must cover:

### Sources and lifecycle

- player, companion, ordinary NPC, turret, and creature where applicable;
- high- and lower-process actors, cell transition, equip swap, death, reference
  unload, save, load, new game, and configuration publication;
- first person, third person, iron sights, scope, hip fire, crouch, movement,
  crippled limbs, and weapon-condition bands; and
- real-time, script `FireWeapon`, AI fire, and VATS/queued playback.

### Content capabilities

- vanilla and arbitrary mod-added weapons, ammunition, projectiles, explosions,
  armor, perks, chems, and active effects;
- direct ammunition and ammunition lists, projectile override, ammunition
  effects, weapon modifications, Split Beam, ammo use, and multi-projectile
  combinations;
- hitscan, missile, grenade, mine, thrown, flame, beam, continuous beam, and
  unknown/special projectile fallback;
- unarmed, one-handed, two-handed, power/directional melee, block, and creature
  special attacks; and
- semi-automatic, automatic, burst, long burst, reload, ammo swap, extended
  clip, jam, and reload jam.

### Damage and reaction

- DR, DT, block, resistance actor values, ignore-normal-resistance flags,
  armor wear, weapon wear, difficulty, critical, sneak, location, limb damage,
  cripple, stagger, knockback, knockdown, dismemberment, death, and essential
  behavior;
- `OnHit`/`OnHitWith`, kill credit, experience, perks, challenges, hostility,
  combat state, and UI feedback; and
- explosion self/ally rules, LOS/occlusion, inner and outer radius, force,
  radiation, image-space behavior, and water interactions.

### Compatibility and performance

- coexistence through capability and predecessor chaining with common xNVSE
  projectile, damage, explosion, reload, and animation extensions;
- no plugin-name detection or load-order assumptions;
- no shared-form or engine-object-tail writes;
- deterministic native fallback under unsupported state or capacity pressure;
- sustained firefight CPU and memory plateau under Proton/Wine; and
- an explicit load-to-gameplay playtest on the supported release artifact.

Behavioral tests should validate shipped data or callable boundaries. They must
not assert source text, hook symbol names, or textual call order.

## Open research before implementation

The following issues still require focused static work or runtime acceptance:

1. First-/third-person recoil camera and animation ownership.
2. Physical adaptation of native hitscan, especially VATS, beams, tracers,
   shotguns, script observations, and synchronous impact ordering.
3. Runtime acceptance of the now-proven reticle/spawn convergence seam,
   including same-epoch capture, spread preservation, near cover, impact
   ordering, and composition with another hook owner.
4. Stable material capabilities across all collision object families.
5. Safe projectile continuation for penetration and ricochet.
6. A black-box matrix for native multi-projectile DT scaling.
7. AI weapon/action scoring, cover, and target-selection internals beyond the
   proven controller and combat-style ownership.
8. VATS queued-shot synchronization with non-native travel time.
9. Runtime coexistence and performance under the user's Proton mod stack.

Each needs focused binary evidence and runtime acceptance. None should be filled
in with guessed offsets or behavior during implementation.

## Decisions established by this research

- Atom combat will be capability-driven and content-agnostic.
- Native attack admission, effective equipment resolution, projectile spawn,
  protection ordering, and `Actor::ApplyHit` are compatibility anchors.
- A shot is the immutable context unit; shared forms are inputs, not state.
- Projectile extension state belongs in a bounded side table.
- Handling, accuracy, ballistics, impact, damage, reaction, and AI remain
  separately owned modules.
- Damage policy runs on complete native hit data before native hit commit.
- AI and VATS are not implicit side effects of a ballistics change; each needs
  its own admission and validation.
- Unsupported or ambiguous capabilities retain native behavior.

These decisions provide the wrapper foundation for an immersive, hardcore, and
responsive combat overhaul without narrowing support to known vanilla records
or breaking the engine systems and mod-added content already participating in
combat.

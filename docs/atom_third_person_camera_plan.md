# Atom third-person camera and 360 movement plan

Status: Phase 0 static contract complete. Phases 1 through 4 are ready for
implementation; every mutating phase still requires its listed Proton runtime
acceptance before it can be enabled by default.

## Intended result

Atom will provide one ESP-less third-person system with two coordinated parts:

1. a responsive free-orbit camera whose position follows the player with
   controlled, human-like lag instead of remaining rigidly attached; and
2. camera-relative 360-degree locomotion in which view direction, movement
   direction, actor facing, animation, aiming, and native camera ownership stay
   consistent through every state transition.

Manual mouse or stick look must affect the view immediately. The word
"smooth" applies to how the camera catches up with player motion, how actor
facing follows locomotion, and how the view optionally recenters after manual
input. It must never mean filtering mouse deltas into a delayed view.

The feature will work from native runtime type and state, not form IDs or
plugin names. It will add no ESP, ESM, ESL, quest, reference, animation event,
or required skeleton node. Mod-added weapons and projectiles will participate
through their normal engine capabilities when Atom later owns aim convergence.

This plan covers the player. It does not redesign NPC locomotion, replace the
animation graph, or alter first-person camera behavior. Those are separate
systems.

## Executive decision

Atom must not reproduce the installed 360 Movement mod as native code. That
mod rotates presentation-only skeleton correction nodes while the player,
camera, aiming, interaction, and VATS retain different authoritative headings.
Its main script has no VATS-mode gate and its interpolation is a fixed fraction
per GameMode update. The resulting split ownership directly permits the two
reported bug classes: stale orientation through VATS and a body pointing away
from its logical action direction.

Atom's design instead separates four values and gives each one an explicit
owner:

- **view heading**: where the camera and crosshair look;
- **movement intent**: the camera-relative world direction and magnitude;
- **actor heading**: the authoritative gameplay-facing direction;
- **aim target**: the view ray target with muzzle obstruction accounted for.

The camera module will consume Atom Input's coherent frame rather than poll
devices again. It will divert normal horizontal look from actor yaw only while
Atom owns the free-orbit state, publish its view heading into the normal camera
construction, compose a damped follow target before native camera collision,
and drive authoritative locomotion/facing at the proven native boundaries.
VATS and other native camera states receive exclusive ownership, with a
transactional release and reacquisition protocol.

## Evidence and confidence

### Supported executable

| Property | Value |
|---|---|
| Game | Fallout: New Vegas 1.4.0.525 |
| Path | `fnv_reverse/FalloutNV.exe` |
| Format | PE32 x86, image base `0x00400000`, non-PIC |
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |
| Primary tool | radare2 MCP, analysis level 2 |

The raw address and installed-mod audit is
[fnv_third_person_camera_contract.txt](../analysis/radare2/output/perf/fnv_third_person_camera_contract.txt).
The input side is already established by
[fnv_actor_input_contract.md](fnv_actor_input_contract.md) and
[atom_input_wrapper_design.md](atom_input_wrapper_design.md). This document
does not duplicate their device acquisition and input-latency analysis.

### Confidence terms

- **Proven** means direct executable disassembly, repository-owned xNVSE
  layout/source, or an installed artifact establishes the fact.
- **Derived** means the conclusion follows mechanically from proven behavior.
- **Corroborated** means a read-only third-party implementation demonstrates
  the same problem or viable boundary but does not establish FNV's contract.
- **Design** means Atom's selected behavior, not a claim about vanilla.
- **Playtest** means runtime evidence under the user's Proton setup.

## What vanilla does

The normal player update orders the relevant work as follows:

```text
Atom/native input frame
        |
        v
0x009445B0 camera/input helper
        |
        +--> 0x00945F90 -> 0x00931D30 changes authoritative actor yaw
        |
        v
0x0093FA08 -> PlayerCharacter::UpdateCamera (0x0094AE40)
        |
        +--> snapshots authoritative pitch/yaw
        +--> builds third-person shoulder target
        +--> resolves native camera collision/distance
        +--> commits the camera transform
        |
        v
0x0093FC57 commits actorMover movement flags
```

`0x00931D30` calls the actor's current-yaw virtual function, adds the supplied
delta, and calls its yaw setter. Normal horizontal look is therefore actor
rotation first and camera construction second. That coupling is why vanilla
third person feels rigid: looking and gameplay facing are the same operation.

`PlayerCharacter::UpdateCamera` snapshots pitch to `0x011E076C` and actor yaw
to `0x011E0764`. Its normal third-person branch consumes native shoulder
settings such as `fOverShoulderPosX`, `fOverShoulderPosZ`, and
`fOverShoulderRotMult`. It calls `0x0094A0C0` before final construction. That
helper reads the player's collision world at `+0x21C`, casts between prepared
camera points, records collision at `0x011E07C2`, and updates the current
third-person distance at `0x011E0768`.

This produces two hard rules:

1. free orbit must supply a camera-only heading before native third-person
   matrices are built; and
2. follow offsets must be composed before native collision, not applied to the
   completed camera afterward.

### VATS is another camera owner

The VATS singleton is `0x011F2250`; its mode is at `+0x08`. Mode 4 causes
`UpdateCamera` to construct the third-person view from VATS camera data instead
of the normal shoulder route. Modes 1 through 3 already own target selection,
zoom/limb selection, and transition behavior in player input and camera state.

Atom will therefore treat every nonzero VATS mode as native-owned. Checking
only playback mode 4 is too late. On VATS entry Atom must stop all camera,
movement-remap, and facing writes in that same update, discard temporal follow
state, and never attempt to correct the VATS camera. On return to mode 0 it
must observe one stable normal third-person frame, seed every Atom state from
the native result, and only then reacquire ownership. No stale spring velocity,
view offset, recenter timer, or actor-turn target may cross that boundary.

### Movement boundary is closed

The final player movement flags are committed through `actorMover` virtual
slot `+0x0C` at `0x0093FC57`. Direct branches in `PlayerCharacter::Update`
prove low bits `0x01`, `0x02`, `0x04`, and `0x08` as forward, backward, left,
and right. The same bits are produced by keyboard and controller paths. The
native analog scalar is `0x011A3B3C`; it multiplies the native speed before the
horizontal vector is transformed by the actor-heading matrix.

The resulting three-float movement vector is local `var_1E0` in
`PlayerCharacter::Update`. At `0x0094280B`, `0x009EA570` copies that vector to
`PlayerMover +0x88`; the immediately following virtual `+0x14` update consumes
it. `0x009E9E50` normalizes the override direction but restores the magnitude
of the native vector and applies its low-bit diagonal policy.

The final coupled seam is later: `0x008A6339 -> 0x0092F260` passes frame time,
the post-`PlayerMover` vector, and movement flags together into the native
movement request. `0x0092F260` stores vector and flags in the same request and
keeps animation, physics, scene/root transform, and landing work downstream.
Atom will replace that scoped call, rotate the existing vector while preserving
its length, map only its low direction nibble according to the active facing
policy, and chain the live predecessor. It will preserve every high flag and
will not edit `PlayerMover` state or a skeleton/root transform.

The direct callsite is shared by the actor movement wrapper, so player identity
alone is not sufficient scope. A chained entry hook on `PlayerMover::Update`
at `0x009E9E50` opens a stack-scoped, main-thread movement token only when its
`this` equals the current player's mover at `+0x190` and the ownership snapshot
is current. The nested `0x008A6339` wrapper may transform only while that token
is active. Reentrancy or a second entry fails native. The token is cleared by
RAII on every return path and contains no retained engine pointer.

For a native vector already transformed by actor heading `a`, camera-relative
view heading `v` is derived in the same engine convention as
`R(a - v) * native_vector`. In `Explore`, the actor faces nonzero movement and
the downstream low nibble becomes native forward `0x01`, producing forward
locomotion. In `Combat`, actor facing is view-relative and the original low
nibble remains the correct forward/back/strafe animation intent. Unsupported
states retain both original vector and flags.

## Why the installed 360 Movement fails

The installed package is Nexus mod 71940, version 1.2.0.0. Its ESP SHA-256 is
`c9dba22b490a22488c2853a84f48a9c6590f93a45ea15f9d6c3e59e4d4d50c7d`.
The ESP contains the source of an auto-start `Begin GameMode` quest script.

The script calculates a movement angle, then rotates `360Corr0`, `360Corr1`,
`360Corr2`, `HHRoot`, pelvis, spine, neck, and head NIF blocks. It reads the
player's world angle to preserve a visual offset but does not make that offset
the actor's authoritative heading. It requires a compatibility skeleton and
ships an ESP plus animation overrides.

Its state handling has four structural faults:

- no `GetVATSMode` gate covers VATS selection, transitions, or playback;
- visual correction and logical actor facing can disagree;
- node and interpolation state are not one symmetric enter/exit transaction;
- turn and lean updates use fixed per-execution fractions, so their real-time
  response changes with frame rate.

It also detects `Diagonal movement.esp` by filename. Atom compatibility must be
based on hook capability and native state, never a mod identity.

The fix is not a longer blacklist of states. The fix is one authoritative
state machine which knows whether Atom or the engine owns each output and which
can neutralize its state without touching skeleton correction nodes.

## Lessons from current camera systems

This research uses modern engine documentation as design guidance, not as
evidence for FNV internals.

[Unity Cinemachine Third Person Follow](https://docs.unity.cn/Packages/com.unity.cinemachine%406.6/manual/CinemachineThirdPersonFollow.html)
uses a target, shoulder pivot, vertical arm, and camera distance; provides
per-axis damping; separates steady aim from noisy camera motion; and resolves
collision with distinct damping into and out of obstruction.

[Unity Position Composer](https://docs.unity.cn/Packages/com.unity.cinemachine%406.6/manual/CinemachinePositionComposer.html)
uses dead and soft zones to let the target move before the virtual operator
reacts. It also warns that raw animation motion makes predictive lookahead
jitter, and supports ignoring vertical movement in lookahead.

[Unity Orbital Transposer](https://docs.unity.cn/Packages/com.unity.cinemachine%402.6/manual/CinemachineBodyOrbitalTransposer.html)
models manual orbit separately from automatic recentering, including a wait
after user input and an accelerated/decelerated return.

[Unreal's spring arm](https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/Engine/GameFramework/USpringArmComponent)
maintains distance, retracts for collision, springs back after collision, and
offers lag substeps specifically for fluctuating frame times.

[Fortnite's orbit camera](https://dev.epicgames.com/documentation/fortnite/using-orbit-camera-devices-in-fortnite-creative)
explicitly lets the view rotate without turning the character and distinguishes
camera orbit from movement direction. Its control guidance separates facing a
movement direction from facing a target.

These sources converge on the same design:

- input controls a view axis immediately;
- the camera follows a stable target through a bounded rig;
- target motion, not look input, is damped;
- collision contracts quickly and recovers more slowly;
- dead zones suppress animation noise;
- user orbit and automatic recenter are separate policies;
- movement, facing, camera, and aim are separate intent channels.

### Fallout 4 comparison

The user-supplied Fallout 4 executable is version 1.10.163.0, SHA-256
`5b2a58004f1856e51235132ab304b20c1434017067703e4282e8b0d5bc539623`.
Its strings expose `ThirdPersonState` plus settings for third-person angular
acceleration, free rotation, first/third transitions, collision rig cast length
and radius, collision spring/recovery, chase speed, combat and melee shoulder
profiles, and third-person aim distance/FOV.

That is direct evidence of a richer explicit state and tuning vocabulary. It
does not prove Fallout 4's formulas or that any single setting explains its
subjective responsiveness. Atom will reproduce the useful architecture:
direct view control, separate state profiles, explicit collision recovery, and
separate character-facing policy. It will not advertise an unproven exact
Fallout 4 camera clone.

## Atom ownership model

### State machine

Atom will classify one state once per player update and publish one ownership
decision for all camera/movement consumers.

| State | Camera | Movement | Actor facing | Aim |
|---|---|---|---|---|
| `Native` | Engine | Engine | Engine | Engine |
| `Acquire` | Engine | Engine | Engine | Engine |
| `Explore` | Atom follow | Atom relative | Movement | View target |
| `Combat` | Atom follow | Atom relative | View/target | View target |
| `Release` | Engine | Engine | Engine | Engine |

The classifier samples the following native values once near the start of the
player update, before any Atom output. All addresses and offsets are for the
supported executable:

| Native owner | Proven predicate | Atom decision |
|---|---|---|
| POV/stable third person | player bytes `+0x64A`, `+0x64B`, and `+0x64C` | Atom requires all three to be nonzero. Any mismatch is a native POV transition. `0x00950BE0` proves `+0x64B` selects the active first- or third-person 3D. |
| Special camera | byte `0x011E07B8` | Any nonzero value is native-owned. |
| VATS and kill camera | `VATSCameraData` mode from `0x011F2250` via `0x0044DDC0` | Every nonzero mode is native-owned. Kill camera enters mode 4 through `0x009CA2C0 -> 0x009C6C30`, so it is covered by the same predicate. |
| TFC | `(*0x011DEA0C)->isFlycam` at `+0x06` | Nonzero is native-owned. |
| Controls and Pip-Boy | player disabled-control flags at `+0x680`: movement `0x01`, look `0x02`, Pip-Boy `0x04`, fight `0x08`, POV `0x10` | Movement, look, Pip-Boy, or POV disabled is native-owned; combat admission also rejects disabled fight control. Atom queries the xNVSE combined player-controls interface so per-mod disables are honored as well as this vanilla byte. |
| Blocking UI | `0x00702360` (`MenuMode`) | True is native-owned. The predicate requires an active `InterfaceManager` and excludes only gameplay mode 1, covering Pip-Boy, dialogue, loading, pause, console, and text-entry menus. |
| Furniture | process virtual `+0x4BC` | Every sit/sleep state 1 through 10 is native-owned; only state 0 is normal. |
| Scripted animation | process virtual `+0x3E4` | animation actions `0x0D` and `0x0E` are native-owned. |
| Death/ragdoll | life state at player `+0x108`; ragdoll pointer at `+0x0AC` | Any nonzero life state or nonnull ragdoll is native-owned. |
| World readiness | process `+0x68`, parent cell `+0x40`, selected 3D from `0x00950BE0`, collision owner `+0x21C` | A missing value is native-owned. A parent-cell identity change forces `Release` and one stable frame before reacquisition. |

Base FNV exposes no general predicate saying that an arbitrary vehicle mod owns
the player. The installed camera preset package confirms this is normally an
external capability (`*_TFinVehicle`), not a vanilla player state. Atom will
therefore accept an explicit vehicle-owner interop token/service and release
ownership while it is set. It will not guess from animation, inspect a named
plugin, or claim automatic compatibility with otherwise unknown vehicle mods.
Without that interop signal, the camera feature must remain off for a vehicle
profile.

`Native` includes disabled Atom, first person, every predicate in the table,
and an asserted external vehicle-owner capability. Predicates are evaluated
before output admission in the same player update. A newly observed native
owner enters `Release` immediately; no Atom write is allowed later in that
frame.

The snapshot is not permission to ignore a transition that occurs later in
the call chain. Every mutating wrapper performs a final allocation-free hard
owner check immediately before its write: live player/mover identity, the
three POV bytes, special-camera byte, VATS mode, TFC, blocking menu/control
state, life/ragdoll, process/cell/3D, and its scoped token/epoch. Any mismatch
chains the native predecessor unchanged and invalidates the epoch before
another Atom output can run. This is the same-update transition guarantee for
VATS, POV, death, menu,
load, and lost-world states.

`Acquire` requires one stable normal third-person frame. It samples the native
camera and authoritative actor values and seeds view yaw/pitch, follow position,
spring velocity, actor target, and recenter time. It performs no output writes.

`Explore` is the free-orbit 360 state. The view is independent. Movement is
camera-relative. A moving actor faces movement intent through a bounded turn
rate; when stationary it holds its last valid heading.

`Combat` starts from proven gameplay intent, not merely the presence of a
weapon model. Aim, fire, melee, block, and other actions whose correctness
depends on facing make the actor converge on view/target heading while movement
becomes strafing around that heading. Weapon-drawn relaxed 360 behavior is
admitted only after its animation and projectile transitions pass Phase 4.

`Release` stops Atom output before native special-state code consumes the
frame. It discards temporal state and transitions immediately to `Native`.
There is no blend across VATS, kill camera, free camera, loading, or first-person
ownership. The native camera may perform its own transition.

### Ownership epoch

Every transition into or out of Atom control increments an ownership epoch.
All temporal values carry that epoch. A spring, recenter timer, or movement
target from an older epoch is invalid even if the player returns to the same
mode in the next frame. This prevents stale VATS offsets and delayed callbacks
from resurrecting prior state.

State is fixed-size and player-main-thread owned. Hooks do not allocate, lock,
perform I/O, reload configuration, or emit routine logs. Atomic configuration
publication remains outside the hot path.

## Follow-camera design

### Rig

The desired camera is built from four components:

```text
logical player position
        |
        +--> stable stance pivot
        |
        +--> bounded horizontal lookahead
        |
        v
dead/soft-zone target -> per-axis follow spring
        |
        +--> native/base shoulder and height
        +--> Atom view yaw and pitch
        +--> desired camera distance
        |
        v
native FNV collision and distance solver
        |
        v
native final camera construction
```

The follow target uses the player's logical transform, not head, pelvis, or
gait-animation nodes. Crouch and other proven stances add an explicit pivot
offset. This prevents breathing, footfall, and animation corrections from
becoming camera noise.

The base shoulder, height, and distance are sampled from the final native game
settings. That makes Advanced 3rd Person Camera a compatible static profile
provider: it may transition those settings while Atom adds dynamic follow
motion. Atom will not overwrite the same globals every frame.

### Direct view input

Atom Input already owns the final horizontal and vertical heading callsites.
The camera module will integrate with those existing detours rather than hook
Atom's own hook:

- when camera ownership is native, call the captured predecessor exactly as
  today;
- in `Explore` or `Combat`, apply the selected Atom Input transform, add the
  resulting delta directly to view yaw/pitch, and do not send horizontal view
  delta to actor yaw;
- preserve all first-person, menu, free-camera, wheel, inversion, and disabled
  control behavior already defined by Atom Input.

No follow parameter multiplies or smooths relative mouse counts. Controller
look retains its configured response curve, but camera follow does not add a
second deadzone or temporal filter.

### Dead and soft zones

The player pivot is projected into the view-horizontal, view-vertical, and
view-depth axes around the current follow target. Motion inside a small dead
zone produces no target displacement. Motion through the surrounding soft zone
gradually increases the correction. Motion outside the hard bound moves the
target enough to keep the player inside it.

Horizontal and vertical zones are independent. Vertical tolerance is larger
by default so stair steps and gait do not bob the camera. Teleports, cell
changes, load completion, and implausibly large per-frame position deltas reset
the target immediately rather than asking the spring to traverse the world.

### Lookahead

Lookahead is derived from low-pass logical horizontal velocity, clamped to a
small distance, and attenuated at low speed. Vertical prediction is disabled
by default. Direction reversals decay the prior prediction before building the
new one. Animation-node velocity is never an input.

Lookahead is an optional composition aid, not input prediction and not a way to
hide latency. Its default must remain subtle; the camera should feel operated,
not dragged ahead of the player.

### Frame-rate-independent spring

Each follow axis uses an analytic critically damped spring. For current
position `x`, velocity `v`, target `t`, angular rate `w`, and step `dt`:

```text
e  = x - t
c  = v + w * e
q  = exp(-w * dt)
x' = t + (e + c * dt) * q
v' = (v - w * c * dt) * q
```

Horizontal, vertical, and depth response use separate rates. The analytic
update avoids the fixed-frame interpolation defect in the installed mod. Atom
will clamp implausible `dt`, split unusually large valid steps into bounded
substeps where collision or target-zone decisions need them, and reset on
pause/load/teleport ownership changes. Non-finite input resets the solver and
records one recoverable diagnostic outside the hot path.

### Manual orbit and recenter

Any manual look input cancels recenter immediately and refreshes a no-input
timer. After a configurable delay, and only while movement magnitude exceeds a
threshold, auto-center may rotate view yaw toward locomotion heading along the
shortest wrapped angle. It has bounded angular speed plus acceleration and
deceleration; it never snaps and never changes pitch.

Aim, fire, VATS, free camera, and native-owned states suppress auto-center.
Stationary players keep their chosen view. Recenter is a policy toggle, not a
requirement for 360 movement.

### Collision

Atom initially performs no extra collision cast. The desired follow target and
rig are composed at the proven pre-collision seam, then the native helper runs
unchanged. This keeps FNV's world filters and camera distance ownership.

Collision response is asymmetric:

- contraction toward the player must be immediate enough that the camera never
  eases through a wall;
- recovery after obstruction may be damped and monotonic;
- follow spring velocity cannot push the camera past the native resolved
  distance;
- shoulder offset must collapse or recenter when native clearance cannot
  support it.

If native behavior cannot provide clean recovery, a later refinement may hook
the proven resolved-distance seam and damp only outward recovery. Atom will not
post-offset the final camera and will not replace the native cast without a
complete collision-filter and ownership proof.

### Shake and visual noise

Camera shake is a final visual perturbation. It must never feed back into the
follow target, movement axes, auto-center heading, crosshair ray, or actor
facing. Compatibility with a separate shake mod requires playtest because an
ESP script may write the same camera settings; Atom will not detect that mod by
name.

## 360-movement design

### Intent mapping

Atom consumes one coherent movement vector from Atom Input. Digital diagonals
are bounded to prevent a speed boost. Controller magnitude remains radial and
continuous. With horizontal camera basis `forward` and `right`:

```text
world_intent = forward * input_forward + right * input_right
speed        = clamp(length(input_vector), 0, 1)
direction    = normalize(world_intent) when speed is nonzero
```

FNV builds both keyboard and controller intent into the same native vector and
uses `0x01/0x02/0x04/0x08` for forward/back/left/right. Its heading transform
uses the engine rotation matrix with the negative authoritative horizontal
heading. Atom will reuse that convention and rotate only the final existing
vector at `0x008A6339`; it will not synthesize a new speed. It maps the low
nibble only to express the documented Explore or Combat animation policy and
preserves all higher walk/run/sneak, auto-move, disabled-control, action, and
controller-magnitude semantics.

### Facing policies

| Intent | Facing policy | Locomotion |
|---|---|---|
| Explore moving | Movement heading | Forward-style motion in world intent |
| Explore idle | Hold heading | Idle |
| Aim/fire | View target | Strafe/backpedal relative to aim |
| Melee/block | View or attack target | Combat-relative |
| VATS/native | Engine | Engine |

Facing turns through the live player's virtual slot `+0x2C4`, never raw
transform storage and never skeleton correction nodes. The slot resolves to
`0x008A6A00`, which gates the actor state and calls absolute-heading setter
`0x00931B60`; that setter normalizes the angle and routes it through the
native actor/3D update. Calls are admitted only from the scoped
`0x008A6339` player movement-request context, before the native movement
predecessor, with explicit reentrancy protection. Shortest-angle wrapping,
maximum turn speed, and acceleration prevent visual snapping while the
separately rotated movement vector remains authoritative.

Weapon-drawn relaxed movement is staged separately. Holstered 360 is the first
admitted route. Drawn guns, sneak with a weapon, melee, jump, falling, swimming,
and scripted idles each enter only when their animation and gameplay behavior
is proven. The final feature goal includes them where native semantics permit;
the staged rollout is not a permanent coverage reduction.

### Animation ownership

Atom will initially use the game's active animation providers and alter only
the admitted movement vector, authoritative facing, and native low direction
nibble passed into the existing animation/movement request. It will not bundle
animation files or require kNVSE. Enhanced Animations' base locomotion package
can remain installed. Its separate patch specifically made for legacy 360
Movement must be removed while
Atom 360 is active because it assumes that mod's skeleton-node convention.

If a directional animation gap remains, it needs its own runtime-capability
design. Atom must not silently install asset overrides as part of the native
movement feature.

## Aim convergence

Changing camera orbit and shoulder position makes FNV's existing third-person
crosshair error more visible. The view ray and muzzle ray cannot be left as an
undefined side effect.

The installed Third Person Aim Fix NVSE 1.2.1 is native and ESP-less. Its public
design moves hitscan origin toward the camera and uses a view tracer plus a
visual zero-damage projectile for physical projectiles, with a later raycast to
prevent shooting around cover. Its installed PDB confirms camera, projectile,
aim, and point-to-point raycast boundaries. This is useful corroboration, not
code Atom will copy.

Atom's eventual convergence policy is:

1. replace only the native reticle call at `0x0070C130 -> 0x00631D60` while
   Atom owns stable third person, supplying Atom's logical view origin and
   direction to the existing `ViewCaster`;
2. capture its target distance/hit result with the current camera ownership
   epoch and logical-view snapshot, so crosshair interaction and projectile
   aim use the same native collision filter without performing an additional
   hot-path cast;
3. at `0x005245BD -> 0x009BCA60`, resolve the real `##ProjectileNode` muzzle,
   point the shot from that muzzle at the captured target (or the effective
   projectile-range endpoint when the view cast has no hit), and call the live
   native spawn predecessor;
4. recover the native unspread base angles, retain the exact sampled angular
   spread deltas already present in the spawn arguments, and reapply those
   deltas around the converged muzzle-to-target direction;
5. preserve native projectile class, hitscan/physical flag, velocity, gravity,
   range, ownership, collision, and impact. The visual and damaging shot remain
   one native projectile launched from the real muzzle, whose native collision
   makes near cover win; Atom does not need an approximate second muzzle cast;
6. fail to the original call unchanged if any required node, context, matching
   ownership/view snapshot, finite result, or chain capability is absent.

`0x00631D60` has the proven ABI
`thiscall(ViewCaster*, Vec3 *start, Vec3 *direction, float max_distance,
float *out_distance, bool *out_alternate_hit) -> TESObjectREFR*`. It constructs
`start + direction * max_distance`, performs the native Havok query, excludes
the player, filters reticle candidates, and writes the nearest distance. The
camera collision helper `0x00620BC0` is camera-specific and is not an admitted
aim ray.

The native caller later publishes the selected references at
`InterfaceManager +0xFC/+0x100` and the exact
`start + direction * out_distance` world point at `+0x104`
(`0x0070C2E8..0x0070C345`). `out_distance` begins as `FLT_MAX`; Atom treats only
a finite value in `[0, max_distance]` as a hit and otherwise extends the same
logical view ray to the effective projectile range. The spawn wrapper accepts
only the latest completed sample whose player, ownership epoch, origin, and
direction match the current logical view. If player-update/UI ordering makes a
fresh sample unavailable, that shot remains native; Phase 5 cannot enable by
default until telemetry proves the sample-age policy across input and frame
rates.

The first projectile group is ranged weapon types 3 through 9 whose effective
projectile reports native type `0x10000` (`MissileProjectile`). Its native
flags continue to select hitscan or physical behavior. Native type `0x40000`
(`BeamProjectile`) is a separate reviewed group. Grenade, flame, continuous
beam, thrown, mine, melee, NPC, first-person, VATS, and TFC routes stay native
until separately admitted. This classification includes mod-added standard
weapons without a form list.

Camera motion or shake never changes the logical aim ray after view heading is
resolved. Standard mod-added weapons participate by projectile/weapon
capability, not a form list.

Atom may coexist with Third Person Aim Fix while Atom's aim capability is off.
Two plugins cannot safely own the same projectile call without an explicit
interop ABI; when Atom aim convergence is enabled, another uncoordinated aim
fix must be disabled. Atom will report the ownership conflict from hook
capability, not scan for a named DLL.

## Native hook plan

Every address below belongs only to the supported executable identity. Phase 0
has closed argument, ABI, lifetime, and semantic ownership. Implementation must
still validate the immutable caller bytes and live predecessor at
`DeferredInit` before enabling each hook.

| Capability | Candidate boundary | Plan |
|---|---:|---|
| Horizontal view | existing Atom hook at `0x00945F90` | Dispatch transformed delta to native actor yaw or Atom view yaw by ownership state. |
| Vertical view | existing Atom hook at `0x00945FD8` | Preserve native route or update Atom view pitch without adding a second input filter. |
| Camera yaw | call at `0x0094AE94` | Scoped callsite replacement returns Atom view yaw only during admitted normal third person. |
| Follow target | call at `0x0094B7D2` | Compose proven vector arguments, then call the exact captured native collision predecessor. |
| Player movement scope | entry `0x009E9E50` | Chain `PlayerMover::Update` while opening a stack-scoped token only for the current live player mover. |
| Movement request | call at `0x008A6339` | Rotate the post-`PlayerMover` vector, preserve magnitude/high flags, map only the low direction nibble by facing policy, then chain `0x0092F260`. |
| Actor facing | live player virtual `+0x2C4` | Call the absolute native yaw route (`0x008A6A00 -> 0x00931B60`) only from the scoped movement-request seam with reentrancy protection. |
| Reticle/view target | call at `0x0070C130` | Substitute Atom's logical view ray only while owned, chain the live `ViewCaster` predecessor, and capture its result by ownership epoch. |
| Projectile convergence | call at `0x005245BD` | For admitted projectile capabilities, preserve native sampled spread and spawn the native class from the real muzzle toward the captured view target. |

The camera-yaw callsite is preferable to changing the global actor-yaw getter:
it scopes the semantic substitution to `UpdateCamera` and leaves AI, gameplay,
interaction, VATS, and other callers untouched.

The follow detour must call the target present at `DeferredInit`, not assume the
vanilla displacement remains. Immutable caller bytes prove context; the live
target becomes the typed predecessor. Installation is one rollback-capable
transaction using `libpsycho` hook abstractions. Each optional capability can
fail closed, but no partial combination may advertise 360 movement if view,
movement, and facing ownership are incomplete.

No hook is installed in `DllMain`, query, load, or before `DeferredInit`. Before
implementation, the agent must read
[nvse_startup_phase_safety.md](nvse_startup_phase_safety.md) completely and
compare the final DLL's complete pre-deferred footprint with the accepted Atom
playtest baseline. New imports, statics, TLS, dependency features, or layout
changes count even when first execution is deferred.

## Planned source ownership

| Path | Planned ownership |
|---|---|
| `atom/src/camera/mod.rs` | Module API, lifecycle, and capability admission. |
| `atom/src/camera/config.rs` | Serde/serini camera and movement settings, validation, and atomic publication. |
| `atom/src/camera/state.rs` | Native-state classifier, ownership epochs, release/acquire protocol. |
| `atom/src/camera/follow.rs` | Dead/soft zones, lookahead, analytic spring, recentering, and reset behavior. |
| `atom/src/camera/movement.rs` | Camera-relative intent, authoritative facing, movement injection, and transitions. |
| `atom/src/camera/aim.rs` | Later view/muzzle convergence capability. |
| `atom/src/camera/native.rs` | Audited addresses, layouts, predicates, and safe reads. |
| `atom/src/camera/hooks.rs` | Fingerprints, typed predecessors, detours, and rollback transaction. |
| `atom/src/input/hooks.rs` | Existing final heading hooks extended with an internal camera dispatch, not hooked again. |
| `atom/src/runtime.rs` | Deferred initialization and existing MCM update routing. |
| `atom/mcm/Atom.json` | Laconic live camera/movement configuration. |

Public Rust APIs and modules will have doc comments describing ownership,
units, valid states, and failure behavior. Complex comments will explain why a
native seam or reset rule exists. All Rust comments and docstrings remain
ASCII. Errors use `thiserror`; diagnostics use `libpsycho::logger::Logger` and
the `log` facade.

## MCM Extender plan

MCM Extender remains the only settings UI and INI writer. Settings apply from
the existing `MCMExtUpdate` event after its INI save. Atom will deserialize one
coherent candidate through Serde/serini, validate it, and atomically publish it.
It will not poll pause state or read the INI each frame.

Proposed visible copy is deliberately short:

| Page | Setting | Choices or unit |
|---|---|---|
| `Camera` | `Follow Camera` | `Off`, `On` |
| `Camera` | `Follow Speed` | scalar |
| `Camera` | `Soft Zone` | scalar |
| `Camera` | `Look Ahead` | scalar |
| `Camera` | `Auto Center` | `Off`, `On` |
| `Camera` | `Center Delay` | seconds |
| `Camera` | `Center Speed` | degrees/second |
| `Movement` | `360 Movement` | `Off`, `On` |
| `Movement` | `Turn Speed` | degrees/second |
| `Movement` | `Drawn 360` | `Off`, `On` |

Every title, description, help value, status, and choice remains one to three
words. The shipped-menu artifact test must continue rejecting longer copy.
Advanced safety policy, VATS ownership, collision behavior, and aim obstruction
are invariants, not toggles.

Camera and 360 movement default off until their respective runtime acceptance
is complete. A malformed live candidate keeps the last coherent configuration.
Disabling either feature uses the same `Release` protocol and returns exact
native behavior without a restart.

## Compatibility contract

| Component | Policy |
|---|---|
| Legacy 360 Movement | Must be disabled while Atom 360 is active. Both own facing/presentation and cannot chain safely. Atom does not detect it by name. |
| Advanced 3rd Person Camera | Compatible as a static native-setting profile. Atom samples final offsets and does not compete for their globals. |
| Enhanced Animations | Base locomotion may remain. Remove its legacy 360-specific patch. |
| Enhanced Movement | Preserve coherent input magnitude and action semantics; chain live hook capabilities without name checks. Requires a joint playtest matrix. |
| Third Person Aim Fix | Compatible while Atom aim ownership is off. Only one aim-convergence owner may be active. |
| Camera shake mods | Noise must remain visual-only. Shared setting writers require playtest; no filename policy. |
| Mod-added weapons | Classify by runtime weapon/projectile behavior. Never require an Atom patch ESP. |
| Mod-added actors | Player feature does not enumerate actor forms. NPC behavior remains native. |

Hook compatibility is capability-based: validate the caller, capture the live
predecessor, preserve its ABI, and chain it. If a predecessor is unsafe or the
caller contract is no longer recognizable, log the unavailable capability and
leave native behavior intact. Never inspect, patch, reorder, or disable another
mod as a compatibility strategy.

## Failure and logging policy

Examples of stable subsystem tags are `[CAMERA]`, `[MOVEMENT]`, and `[AIM]`.

- `debug`: validated address, fingerprint, admitted predicate, or captured
  predecessor detail;
- `info`: feature ready, configuration applied, ownership summary requested by
  the user, or clean live disable;
- `warn`: a recoverable capability is unavailable and the resulting native
  fallback;
- `error`: a requested feature cannot preserve correctness and is disabled.

Routine per-frame state, camera coordinates, and spring values are never
logged. Optional bounded diagnostics may count state entries, rejected `dt`,
teleport resets, and capability failures, then emit a user-requested summary
outside the hot path. There are no direct file writes, overlays, or custom
ImGui telemetry.

## Implementation phases

### Phase 0: close the native contract

Static research is complete against the identified executable. The raw ledger
records the direct disassembly and the proof/inference boundary. Closure is:

1. `0x0094A0C0` receives mutable desired endpoint `var_12C`, read-only pivot
   `var_138`, and a mode byte. It casts pivot-to-desired and writes only the
   resolved endpoint back through argument 1.
2. `0x0094BB61 -> 0x00440460` commits the resolved position to camera
   `0x011E0C20 +0x58`; rotation follows through `0x00A59C60`. The native helper
   already owns both contraction and outward distance recovery, so Phase 2
   needs no separate recovery hook.
3. Direction bits, analog carrier, native heading transform, vector setter,
   coupled vector/flag request, downstream animation/physics/root-transform
   ownership, and `PlayerMover` lifetime are closed. The admitted request seam
   is `0x008A6339`.
4. The native ownership table above closes every base-game state. Arbitrary
   mod vehicles have no base-game predicate and require an explicit external
   ownership capability; this is a proven compatibility boundary, not a
   guessed offset.
5. The authoritative absolute heading route is live player virtual `+0x2C4`,
   resolving through `0x008A6A00` to `0x00931B60`, called from the scoped
   movement-request context before the native predecessor.
6. Native reticle casting, muzzle lookup, base and spread angles, spawn ABI,
   projectile subtype dispatch, hitscan/physical ownership, continuous types,
   range, and obstruction ownership are closed. The admitted Phase 5 seams are
   `0x0070C130` and `0x005245BD`.

Gate result: mutating implementation may begin with Phase 1 and proceed in
order. This is a static safety result, not runtime acceptance. Every hook still
needs a validated instruction fingerprint/live predecessor, focused behavior
tests, the supported release build, and the listed Proton playtest before its
capability is enabled by default.

### Phase 1: lifecycle and passive observer

Implement the camera module, configuration model, native readers, and state
classifier without modifying camera, actor, or movement outputs. Publish fixed
state snapshots only to the main thread and bounded diagnostics.

Acceptance:

- every native/Atom transition is deterministic from observable input;
- all VATS modes enter native ownership before any future output site;
- one stable frame is required before reacquisition;
- live disable produces `Release` and cannot leave state behind;
- no hot-path allocation, lock, I/O, or log;
- the supported release target builds and the existing input behavior is
  unchanged.

### Phase 2: follow position

Install the scoped camera-yaw and pre-collision follow hooks, but retain native
actor-facing and native locomotion. Add direct manual orbit only if the actor
remains stationary or Phase 3's movement seam is already available; otherwise
ship follow-position behavior first with native view coupling.

Implement stable pivot, dead/soft zones, bounded horizontal lookahead, analytic
per-axis spring, teleport/load reset, native collision composition, and live
configuration.

Acceptance:

- manual look reaches the next camera update without follow smoothing;
- follow response is equivalent across 30, 60, 120, and unstable frame rates;
- camera never enters tested geometry;
- collision contraction is prompt and recovery is monotonic;
- VATS, POV, TFC, menus, load, and death transitions have no snap-back or stale
  velocity;
- Advanced 3rd Person Camera preset transitions remain coherent.

### Phase 3: holstered free orbit and 360 movement

Connect Atom Input's existing heading detours to the camera state. Inject the
proven camera-relative direction and magnitude at the native locomotion seam.
Drive authoritative actor facing toward movement through the proven setter.
Admit normal holstered standing/crouched movement first.

Acceptance:

- all eight digital directions and the full analog circle map correctly at
  camera yaw 0, 90, 180, and 270 degrees;
- analog magnitude and walk/run/sneak speed remain unchanged;
- no diagonal speed boost;
- actor visual forward, interaction forward, and locomotion agree;
- stationary orbit never turns the actor;
- auto-center cancels instantly on manual look and uses shortest-angle wrap;
- transitions to every native state are symmetric.

### Phase 4: complete locomotion and combat transitions

Add weapon-drawn relaxed 360, aim/fire strafing, reload, melee, block, sneak
with weapons, jump/fall/landing, swimming, auto-move, and proven scripted-idle
routes. Each route uses explicit state policy; none is enabled by a generic
"not VATS" fallback.

Acceptance:

- drawing, holstering, aiming, firing, reloading, melee, and blocking cannot
  leave actor facing behind movement or crosshair intent;
- repeated enter/cancel/confirm/playback VATS cycles recover exactly;
- jump, landing, slopes, stairs, water, furniture, and ragdoll do not preserve
  a stale turn target;
- Enhanced Movement and base Enhanced Animations pass the joint matrix;
- the legacy 360 animation patch is absent from the test profile.

### Phase 5: aim convergence

Implement native `ViewCaster` reticle alignment plus real-muzzle projectile
convergence at the two proven callsites. Preserve native spread, native muzzle
collision, and physical projectile behavior. Admit weapon classes by capability
in small reviewed groups.

Acceptance:

- close, medium, and long-range crosshair convergence is correct within the
  weapon's native spread;
- a nearby wall is hit by the native muzzle-origin projectile even when the
  camera can see around it;
- hitscan and physical projectiles retain correct visual and damage ownership;
- NPC, first-person, VATS, TFC, thrown, mine, and unsupported continuous routes
  remain exact native behavior;
- representative mod-added standard weapons need no form list or patch ESP;
- another aim-fix owner cannot be active simultaneously without an explicit
  interop contract.

### Phase 6: release hardening

Tune only from recorded behavior and playtest feedback. Run the full artifact,
behavior, build, startup, compatibility, and runtime matrix. Update this
document from planned to implemented ownership with exact final source paths,
configuration bounds, hook fingerprints, and accepted playtest artifact hash.

The feature remains off by default until its load-to-gameplay, transition, and
behavior acceptance is complete.

## Behavioral test plan

Tests exercise public behavior or shipped artifacts. They must never inspect
implementation source text, textual call order, or symbol-name presence.

### Deterministic camera tests

- analytic spring endpoints and velocities match a high-precision reference;
- one `1/30` step, two `1/60` steps, and four `1/120` steps produce equivalent
  state within a documented floating-point tolerance;
- response is finite, critically damped, and non-overshooting for valid ranges;
- dead-zone motion produces no correction; soft/hard-zone motion is continuous;
- vertical noise does not enter horizontal lookahead;
- teleport, invalid `dt`, pause, and ownership epoch reset all temporal state;
- collision contraction clamps before smoothing and outward recovery is
  monotonic;
- angle wrap chooses the shortest path around `-pi/pi`;
- manual input cancels recenter in the same update.

### State and movement tests

- a table-driven state harness covers VATS modes 0 through 4, POV transition,
  TFC, menus, dialogue, furniture, ragdoll/death, load, missing 3D, and live
  enable/disable;
- native-owned states produce no camera, movement, facing, or aim write intent;
- reacquisition seeds from native output and rejects stale epochs;
- digital and analog movement mapping covers all quadrants and magnitudes;
- Explore maps nonzero locomotion to native forward while Combat preserves the
  original forward/back/strafe low nibble; both preserve every higher flag;
- explore and combat policies produce their documented facing behavior;
- draw/aim/fire/reload/holster and VATS transition sequences are replayed as
  observable state traces, not source-structure tests.

### Aim and artifact tests

- the Atom-aligned native reticle ray selects the target while the native
  muzzle-origin projectile still hits near cover;
- native spread and projectile characteristics pass through unchanged;
- shipped MCM copy remains one to three words;
- the built Atom package contains no ESP, ESM, or ESL;
- configuration is a strict behavioral round trip through shipped INI fields;
- malformed live configuration keeps the prior coherent settings.

## Build and runtime validation

For each code phase:

```bash
cargo test --target i686-pc-windows-gnu -p atom
cargo build --release --target i686-pc-windows-gnu -p atom
git diff --check
```

Run the broader supported release build once after all affected crates are
stable. Formatting and linting are useful but do not replace behavioral tests
or the release build.

Any change to Atom's pre-`DeferredInit` footprint additionally requires the
repository startup-safety artifact checks and an explicit Proton
load-to-gameplay playtest with BaseObjectSwapper installed. Static validation
cannot prove that compatibility boundary.

### Runtime matrix

Test at 30, 60, 120, and fluctuating frame rates with mouse/keyboard and a
controller:

- interior/exterior, narrow rooms, corners, doorways, low ceilings, stairs,
  slopes, ledges, and rapid wall approach/exit;
- walk, run, sneak, auto-move, sprint provider, jump, fall, land, and swim;
- idle orbit, forward/back/strafe/diagonal motion, rapid reversal, and analog
  circles at different magnitudes;
- holster, draw, aim, fire, reload, melee, block, weapon switch, and unsupported
  weapon types;
- VATS enter, cancel, confirm, playback, rapid repetition, and return to both
  moving and idle states;
- POV switch, Pip-Boy, pause, console/text entry, dialogue, furniture, TFC,
  kill camera, ragdoll, death, load, fast travel, cell change, and alt-tab;
- Advanced 3rd Person Camera, Enhanced Movement, base Enhanced Animations,
  Third Person Aim Fix before Atom aim ownership, and representative camera
  shake;
- mod-added hitscan and physical-projectile weapons after Phase 5.

### Acceptance targets

- manual look changes the next normal third-person camera update;
- no Atom spring or input history is applied to manual view deltas;
- no wrong-direction interaction, shot, melee, or body orientation;
- no stale offset or snap after any VATS/native ownership cycle;
- deterministic spring state differs by no more than `0.01` world unit and
  `0.01` degree across the reference frame partitions;
- no tested camera geometry penetration;
- no diagonal speed gain and no analog magnitude loss beyond quantization;
- zero routine allocations, locks, I/O, and logs in the per-frame hook path;
- initial follow adds zero collision casts beyond native;
- camera/facing math, excluding the native cast and chained owners, stays below
  `25 us` p99 on the user's runtime telemetry profile;
- shipped package remains ESP-less and requires no per-mod form patch.

## Remaining risks

The largest remaining technical risk is runtime animation compatibility, not a
missing locomotion carrier. Static evidence proves that the admitted movement
seam remains upstream of native animation, physics, and root-motion handling;
only the Proton matrix can prove that every installed directional animation
looks correct through diagonal turns, jumps, slopes, swimming, and combat.

Camera collision semantics and the final commit are closed. The remaining
collision risk is behavioral: native outward recovery and shoulder collapse
must remain monotonic when the desired follow pivot itself is moving. Phase 2
must measure that under real interiors before considering any recovery
refinement.

Third-person aim has closed static seams but remains a separately admitted
Phase 5 capability. Runtime tests must prove same-epoch reticle capture,
spread preservation, native hitscan/physical impact ordering, near-cover
behavior, and safe coexistence with a chained hook owner. Camera and movement
can operate while aim remains native or is owned by the installed aim fix.

Unknown vehicle mods remain an explicit interoperability limit. Base FNV has
no universal vehicle-owner flag, so safe automatic admission is impossible
without a capability signal from the vehicle provider or user profile.

Finally, the subjective target is a human-operated camera. Static evidence can
prove ownership and eliminate structural delay; it cannot choose the final
follow rate, zone size, recenter delay, or turn acceleration. Those values need
repeatable A/B playtests after the solver is correct. Tuning will not be used
to conceal an ownership, collision, frame-rate, or input-latency defect.

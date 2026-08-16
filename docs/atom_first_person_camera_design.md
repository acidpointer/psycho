# Atom first-person camera design

Status: native and product research complete; implementation is intentionally
gated by the Phase 0 contracts and Proton playtests in this document.

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

This document specifies the wrapper architecture, motion model, compatibility
rules, implementation sequence, and acceptance tests. It does not implement
the feature.

## Executive decision

Atom must separate three poses instead of treating the animated head, aim, and
weapon as one camera:

| Pose | Owner | Purpose |
|---|---|---|
| Control pose | FNV and Atom Input | Logical look, crosshair, activation, aiming, and combat direction. |
| World presentation pose | Atom camera wrapper | Small render-only body motion applied around the world draw. |
| Viewmodel pose | Native setup plus Atom | Separately scaled hands/weapon motion applied after native iron-sight setup. |

The native control pose is never smoothed. Atom samples the completed native
camera and adds a short-lived presentation transform only while the renderer
consumes it. The exact native transform is restored before the wrapped call
returns. Hands and weapons receive a related but independently tuned transform
through FNV's separate first-person camera.

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

The normal player update calls the player camera/input helper, then
`PlayerCharacter::UpdateCamera @ 0x0094AE40`, and only afterward continues to
movement, attack, activation, and other gameplay consumers.

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
translation at `+0x8C`. These direct callsites are the candidate transaction
boundary for the world presentation pose: snapshot the live world fields,
compose a bounded camera-local offset, call the live predecessor, and restore
the snapshot on every exit path.

This leaves the logical/local camera pose untouched outside rendering. It also
lets native culling and OMV world stages observe the same presented world pose.
Static analysis does not prove the resulting image, so the maximum offset and
matrix convention remain playtest gates.

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
[Impulse model](https://docs.unity.cn/Packages/com.unity.cinemachine%402.6/manual/CinemachineImpulse.html)
separates a six-axis signal, event source, and listener.
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
4. later combat/event impulses;
5. accessibility and state attenuation;
6. per-listener world/viewmodel gain;
7. final translation/rotation clamps and finite validation.

Each modifier returns zero-centered translation and rotation. No modifier
edits another modifier's state or uses the prior frame's final presented pose
as its new target. This prevents drift and positive feedback.

The world and viewmodel listeners consume the same source phases so motion
feels connected, but their gains and allowed axes differ. The weapon may move
more than the world without making the horizon unstable.

## Locomotion inputs

Head bob must represent actual body movement, not keyboard intent.

The preferred inputs, in order, are:

1. proven character-controller horizontal velocity relative to its support;
2. proven grounded/jumping/in-air state;
3. native movement flags for walk, run, sneak, swim, and auto-move classes;
4. the coherent Atom Input frame only as context, never as velocity.

The supported executable already proves `Actor::GetCharController @
0x009306D0` and `bhkCharacterController::GetState @ 0x005C0880`. State values
0, 1, and 2 identify on-ground, jumping, and in-air operation. Phase 0 must
validate the controller velocity and support-velocity carriers and their units
before gait ships.

Support-relative velocity matters on elevators and moving surfaces. Integrating
world position would bob while a platform carries a stationary player.
Integrating input would bob against a wall, during a blocked animation, or at
the wrong analog magnitude. Animation-node displacement is rejected because
arbitrary skeletons and animation packs can add noise or omit expected nodes.

If a trustworthy velocity is unavailable for a frame, the gait target gain is
zero. Pass-through is better than synthetic foot motion disconnected from the
character.

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
| Vertical gait | `0.15-0.45%` eye height | `0.3-1.0%` eye height |
| Lateral gait | `0.05-0.20%` eye height | `0.2-0.7%` eye height |
| Fore/aft gait | initially zero | `0.1-0.5%` eye height |
| Roll | initially zero in Stable | `0.10-0.45 deg` |
| Pitch | initially zero in Stable | `0.05-0.30 deg` |
| Yaw | zero | at most `0.15 deg` |

Eye height is measured from a stable native first-person pose rather than a
hard-coded game-unit assumption. All final values require FOV, weapon,
animation, clipping, and comfort playtests at 30, 60, 120, and unstable FPS.

The `Stable` mode keeps gait rotation off on the world listener. An optional
`Full` mode may admit very small world pitch/roll only after reticle and motion
sickness tests. Rotation must never be hidden inside the basic intensity
slider.

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
| Hip fire | low | normal | normal | normal |
| Iron sights transition | fade down | fade down | fade down | reduced |
| Iron sights held | zero by default | low | low | low |
| Magnified scope | zero | zero or absent | zero | zero |
| Melee/unarmed | low | profile-dependent | low | normal |
| Reload/equip | low world only | avoid fighting animation | zero | reduced |

The aim weight follows proven native aiming and scope state with a time-based
blend. It does not infer aim solely from the right mouse button. Native setup
and Smooth True Iron Sights remain authoritative for the base camera.

Weapon animation is already authored motion. During reload, equip, jam,
throwable, and scripted sequences, added viewmodel inertia should normally
fade to zero instead of double-animating the hands. The world listener may
retain a reduced locomotion cue if camera ownership is otherwise normal.

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
starts at zero and requires explicit opt-in. Atom combat may later publish a
logical recoil event; camera presentation can add a secondary kick, but the
combat module remains the owner of actual aim and projectile behavior.

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

Atom's initial policy is therefore conservative:

1. never rotate the Stable world listener;
2. attenuate world translation to zero while aiming or scoped;
3. keep hip-fire translation inside the calibrated envelope;
4. leave the reticle and UI fixed;
5. make viewmodel motion carry most of the perceived weight;
6. do not ship `Full` world rotation until reticle, activation, and projectile
   tests establish acceptable behavior;
7. make zero camera intensity exact native behavior regardless of weapon
   intensity.

Any positional offset can also cross nearby geometry because vanilla first
person does not expose the proven third-person collision transaction for this
new pose. Phase 0 must prove either a side-effect-free micro-clearance query or
a conservative native clearance carrier. Until then, positional world bob is
an implementation gate, not an assumed-safe write.

If clearance cannot be proven, the safe first milestone is viewmodel motion
plus zero world translation. Disabling the requested world layer is not the
final feature; it is a phase boundary while the collision contract is closed.

Required runtime assertions for world motion are:

- ADS center-ray impact is unchanged with motion on/off;
- activation selects the same reference at the same distance;
- no near-plane or wall crossing occurs at maximum amplitude;
- culling follows the presented pose without edge popping;
- camera snapshots restore exactly even when a chained predecessor returns
  early or fails internally.

## Hook and transaction design

### Coherent sample hook

Wrap the direct UpdateCamera call at `0x0093FA08`. The wrapper calls its live
predecessor first, then samples native camera and locomotion state and advances
the motion generator once. It writes no camera transform.

This hook consumes Atom Input's already-published frame ID and look delta. It
does not hook Atom's own mouse hook, repoll a device, or create a second action
snapshot.

### World callsite group

Wrap both direct RenderWorldSceneGraph calls at `0x00870AE8` and `0x00870E18`.
Each callsite owns its own captured predecessor because another plugin can
redirect the two sites independently.

For exact world phase and an admitted first-person motion frame:

1. resolve the persistent World SceneGraph camera;
2. snapshot world rotation and translation;
3. compose and clamp the world additive pose;
4. publish a render token for the paired first-person stage;
5. call that callsite's live predecessor;
6. restore the exact snapshot on all unwind paths;
7. retain the token only for the immediate paired first-person deadline.

A recursive or unexpected world call is pass-through. No allocation, lock,
file I/O, configuration parse, logging, collision query, or state advancement
belongs in this wrapper.

### First-person callsite group

Wrap all three RenderFirstPerson calls at `0x0087093D`, `0x00870B21`, and
`0x00870F74`, again with one predecessor per callsite.

The wrapper consumes a token only when its update epoch, render serial, route,
camera mode, and native pointers match. It snapshots OSGlobals +0xA0 world
rotation/translation, composes the viewmodel pose, calls the live predecessor,
and restores exactly. The special A route has no paired world token and remains
native pass-through.

The token is invalidated on consumption, Present, image-space entry if needed,
epoch change, configuration publication, device/reset lifecycle, or any
ownership loss. A stale token never crosses a frame.

### Installation and rollback

Each semantic hook group is preflighted before the first write. A group accepts
a valid direct `E8` call to any callable current target, captures that live
target, and installs Atom's wrapper. It must not require the target to remain
the vanilla address.

On a validation failure:

- the incomplete group rolls back its own writes;
- the camera feature remains exact pass-through;
- Atom Input and unrelated Atom systems remain available;
- diagnostics name the unavailable capability and consequence;
- no hook is installed from `NVSEPlugin_Load`.

All native validation, configuration publication, and hook installation occur
at xNVSE `DeferredInit`. Before implementation, the contributor must read
[the startup phase safety contract](nvse_startup_phase_safety.md), identify the
last load-to-gameplay-playtested Atom artifact, and compare the complete
pre-Deferred footprint. New static ownership or configuration fields can
change that footprint even when camera code executes later.

## OMV integration

OMV already wraps the same two world and three first-person CALL sites in
`omv/src/fnv_render.rs`. It uses caller-local live predecessors, performs world
effects inside the world call, and captures first-person depth inside the later
first-person call.

Atom must preserve that chain in either load order:

```text
callsite -> outer plugin -> inner plugin -> native renderer
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
near the origin and restoring it inside RenderFirstPerson. Atom never touches
the player root and snapshots whatever camera transform is live at its own
boundary. High-coordinate testing remains mandatory because adding a tiny
offset to a large float can otherwise recreate visible quantization.

### B42 Weapon Inertia and recoil systems

[B42 Weapon Inertia](https://www.nexusmods.com/newvegas/mods/64335) already
adds skeleton-dependent weapon inertia. Atom must not detect or patch it. The
separate `Weapon Motion` control lets a user set Atom's viewmodel gain to zero
while retaining world motion. Hook preflight and exact snapshot restoration
prevent lost predecessors, but visual double-inertia still requires user
choice and playtest.

Recoil systems remain the owner of their gameplay and animation paths. Atom's
camera API accepts a bounded presentation impulse only through an explicit
capability; it never infers recoil by inspecting a mod or animation name.

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
- `Weapon Motion = 0` performs no viewmodel-camera write;
- camera, weapon, and landing gains are separately adjustable;
- `Stable` is the default mode; `Full` is explicit opt-in;
- no FOV pulse, sprint zoom, forced motion blur, or moving UI;
- no automatic camera roll in Stable mode;
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

Proposed internal configuration:

```ini
[FirstPerson]
bEnabled=0
iMotionMode=1
fCameraMotion=0.35
fWeaponMotion=0.65
fLandingMotion=0.45
fAimMotion=0.20
```

`bEnabled=0` is the safe pre-playtest default. Numeric values above are product
hypotheses for calibration, not approved shipping values. Sanitization clamps
all gains to `[0, 1]`; unknown fields remain owned by MCM/future Atom versions.

Every visible MCM string must remain one to three words. A compliant initial
page can use:

| Role | Text |
|---|---|
| Page | `First Person` |
| Toggle | `First Person` |
| Mode | `Motion Mode` |
| Choices | `Off`, `Stable`, `Full` |
| Slider | `Camera Motion` |
| Slider | `Weapon Motion` |
| Slider | `Land Motion` |
| Slider | `Aim Motion` |
| Help | `World movement` |
| Help | `Weapon movement` |
| Help | `Landing impact` |
| Help | `Aiming movement` |

The shipped MCM artifact test must reject longer text, duplicate INI keys,
defaults outside bounds, and disagreement with Rust defaults.

## Proposed source ownership

Implementation should extend Atom with one camera namespace:

```text
atom/src/camera/
|-- mod.rs              lifecycle, admission, public motion API
|-- config.rs           typed MCM settings and coherent store
|-- native.rs           supported addresses, pointers, state gates
|-- pose.rs             Vec3/matrix pose math and clamps
|-- locomotion.rs       velocity class, distance phase, gait envelope
|-- impulses.rs         landing and later event channels
|-- viewmodel.rs        look inertia and aim attenuation
|-- state.rs            ownership epochs and reset protocol
`-- hooks.rs            transactional callsite wrappers and rollback
```

Shared camera math may later serve the third-person system, but the first
implementation should not extract a generic framework until both call paths
have concrete needs. `atom/src/lib.rs` remains a thin lifecycle dispatcher.
`atom/src/runtime.rs` may coordinate one typed Atom configuration rather than
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
- one transform snapshot;
- one bounded pose composition;
- one live predecessor call;
- one exact restore;
- zero state advancement and zero allocation.

Trigonometric gait values may use a small deterministic approximation or
paired sine/cosine once per update after numerical tests. They must not be
recomputed separately in both render listeners. Camera work should remain far
below 0.05 ms on the supported CPU target; telemetry measures it only in an
opt-in bounded window and summarizes through the established logger outside
the hot path.

## Failure behavior and diagnostics

The camera feature is optional. Any failure preserves Atom Input and native
camera behavior.

Normal lifecycle logs:

- `info`: `[CAMERA] First-person camera active`
- `warn`: `[CAMERA] World motion unavailable; native camera retained`
- `warn`: `[CAMERA] Viewmodel motion unavailable; native camera retained`
- `error`: only when the user requested the feature and no safe capability can
  remain available.

Technical addresses, fingerprints, state rejects, and measured costs are
`debug` and rate-limited. Render callbacks never log. A summary request is
latched and emitted later through `libpsycho::logger::Logger`; Atom creates no
private telemetry file.

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
6. prove a side-effect-free clearance strategy for positional world motion;
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

### Phase 1: pass-through wrapper and viewmodel inertia

Implement the state machine, coherent update sample, hook groups, exact guards,
and viewmodel look inertia with world motion fixed at zero.

Acceptance:

- feature off is byte-for-byte native at both camera fields;
- every wrapper calls the correct live predecessor exactly once;
- all error and ownership paths restore snapshots;
- Smooth True Iron Sights and Viewmodel Shake Fix behavior is preserved;
- weapon motion is direct-input responsive and frame-rate consistent;
- high-coordinate jitter is not worse than native/fix baseline.

### Phase 2: locomotion and landing

Add support-relative cadence, stance profiles, gait envelopes, and landing
impulses. Enable viewmodel listener first. Admit bounded Stable world
translation only after clearance and aim tests pass.

Acceptance:

- no bob while blocked against a wall or standing on a moving platform;
- cadence follows actual movement and analog magnitude;
- jump/in-air suppresses gait and landing fires once;
- slopes, stairs, and small step-downs do not emit repeated impacts;
- ADS/scopes converge to stable native presentation;
- no geometry crossing occurs at maximum supported gain.

### Phase 3: survival profiles and event API

Add restrained, proven-state breathing/handling profiles and an internal fixed
capacity impulse interface for Atom combat. Do not add world random noise by
default.

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
- each callsite stores and invokes its own current predecessor;
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

- `Camera Motion = 0` and `Weapon Motion = 0` independently remove their
  effects immediately and permanently;
- Stable does not add world roll or dynamic FOV;
- motion remains subtle during long traversal and does not obscure targets;
- ADS and scopes become visibly stable;
- no UI element bobs;
- at least one motion-sensitive tester can complete a 20-minute traversal with
  camera motion off, and another can evaluate each nonzero level separately.

## Release gates

Before calling the wrapper implemented:

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

Until those gates pass, the correct status is "research complete" or
"implementation awaiting playtest," not "startup-safe" or "finished."

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

### Apply one transform to world and weapon

Rejected. It makes the horizon as busy as the hands, fights iron sights, and
wastes FNV's proven separate first-person camera. One source may feed two
listeners, but each listener needs its own axes and gain.

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
distance-phased, support-relative gait plus event-based landing; put most
weight into the separate viewmodel listener; make Stable subtle and Full
explicit; and make zero gains exact native behavior.

The native renderer provides the right structural split for this design. The
remaining hard problems are not waveform creativity: they are velocity and
state proof, positional clearance, reticle/parallax truth, hook-chain ordering,
and runtime comfort. Phase 0 closes those before the first world-camera write.

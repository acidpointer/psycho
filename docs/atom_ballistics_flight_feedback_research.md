# Atom Ballistics flight feedback research

Research status: complete for the first production implementation.

Implementation status: not started by this research change.

Date: 2026-08-16.

## Executive conclusion

This document closes the first production contract for **listener-centric
projectile flight audio** for physical bullets. Its implementation is deferred
behind the gameplay ricochet phase documented in
[`atom_ballistics_ricochet_research.md`](atom_ballistics_ricochet_research.md).
When scheduled, it should restore the missing supersonic near-pass cue at the
point where an enemy bullet actually crosses the local listener, while leaving
projectile movement, collision, damage, impacts, tracers, explosions,
animation, recoil, spread, and view behavior with their current owners.

This is not a generic audiovisual effects layer. It is a narrowly scoped
presentation consumer of Atom's already-proven physical projectile path. The
first implementation should:

- handle both vanilla and mod-added discrete MissileProjectile records by live
  engine capabilities rather than FormID lists;
- use the projectile record's existing Supersonic flag and projectile sound;
- calculate passage against each finite, actually travelled update segment;
- submit the sound through FNV's ordinary 3D audio entry points;
- attempt the cue at most once per projectile generation;
- apply fixed, allocation-free presentation limiting under pellet and automatic
  fire;
- fail open by dropping only the optional cue; and
- make no view, input, weapon-animation, AI, hit, damage, or explosion change.

The engine research explains why this route is needed. FNV has two projectile
sound paths:

1. A non-supersonic physical projectile receives a persistent, attached sound
   handle and starts playing when it comes within its authored attenuation
   range.
2. A supersonic hitscan projectile can create an immediate near-pass one-shot
   during the hitscan collision query.

Atom's native physical conversion deliberately clears the runtime hitscan
policy. That preserves real movement and collision, but it also bypasses the
only native MissileProjectile call chain that reaches the supersonic near-pass
branch. The ordinary physical update does not call that branch later. The
result is a real travelling bullet without the sound cue that tells the player
where a dangerous miss crossed. This is a presentation gap, not a damage or
balance defect.

No native near-pass suppression hook is needed for this scope: selected
physical bullets do not reach that native route, while hitscan fallback remains
native and must not receive an Atom duplicate.

## Scope and non-goals

### In scope

- Local-listener sound for a supersonic physical bullet passing nearby.
- Live use of vanilla or mod-authored BGSProjectile and TESSound data.
- Finite-segment passage geometry and exactly-once state.
- Automatic presentation limiting for high projectile counts.
- Pointer-free observations that later combat systems may consume without
  taking ownership of the projectile.
- Compatibility with the current Atom launch, update, tracer, impact, and
  damage boundaries.
- Bounded diagnostics sufficient to prove coverage in one playtest.

### Explicitly out of scope

- Any view transform, view shake, view kick, or view-state dependency.
- Weapon recoil, animation, sway, spread, aim, controls, or locomotion.
- A damage rebalance, armor model, hit-location rewrite, penetration, or
  ricochet system.
- AI suppression, morale, awareness, or actor scanning.
- Replacement impact sounds, decals, particles, or material effects.
- Muzzle report replacement or physically delayed muzzle audio.
- Explosion arming, dud, LOS, concussion, ringing, damage, force, or effects.
- Beam, flame, continuous beam, grenade, mine, thrown, or placed projectiles.
- New projectile meshes, tracers, or visual bullet instances.
- Detection, patching, reordering, or configuration of another mod.

The local listener is obtained from the audio system. No feature in this design
needs to read, hook, or modify a view subsystem.

## Evidence rules

This document uses the following labels:

- **Proven - binary:** direct disassembly, xrefs, data, or call-graph evidence
  from the identified FalloutNV executable.
- **Proven - header:** a checked-in xNVSE 1.4.0.525 record or runtime layout.
- **Observed - runtime:** a Proton playtest log from the current Atom build.
- **Observed - content:** read-only inspection of the active mod profile or
  third-party source used only to understand interoperability.
- **Design inference:** a proposed policy derived from the proven contracts.
- **Open:** a fact that has deliberately not been claimed.

Third-party source is never the authority for an engine address or ABI. It is
used only to identify how an installed mod composes with an established engine
route. The raw native evidence is preserved in
[`fnv_projectile_feedback_contract.txt`](../analysis/radare2/output/gameplay/fnv_projectile_feedback_contract.txt).

## Modern shooter design model

The important modern-game principle is not "add more shake" or "raise
damage." It is to derive feedback from authoritative simulation events and
make every presentation layer answer a distinct question:

| Layer | Player question | Atom ownership |
|---|---|---|
| Muzzle report | Where and what fired? | Existing sound and weapon owners |
| Projectile passage | Where did the dangerous round cross me? | Missing for selected physical supersonic rounds; this feature |
| Impact | What did it strike and where? | Native impact resolver and IMPACT |
| Injury | Was I hit and what did it do? | Native hit path and future damage/injury modules |
| Explosion | What detonated and how did the area respond? | Native and installed explosion owners |

Separating these layers prevents one exaggerated effect from impersonating all
of combat. Peer-reviewed gunshot-acoustics work distinguishes muzzle blast and
the ballistic shock wave as different acoustic events. Supersonic projectile
shock waves have characteristic propagation and arrival geometry rather than
being a louder copy of the muzzle report. See the ballistic-wave measurement
work by [Lo et al.](https://pubmed.ncbi.nlm.nih.gov/28679249/), the recent
[shooting-acoustics study](https://pubmed.ncbi.nlm.nih.gov/38341747/), and
NASA's [sonic-boom flight research overview](https://ntrs.nasa.gov/api/citations/20220015115/downloads/NASA%20Sonic%20Boom%20Flight%20Research_2022Oct_rev0_v2.pdf).

Those sources guide event separation; they do not establish FNV world-unit
scale, speed of sound, or an acoustic solver.

Modern audio engines likewise separate spatial attenuation, voice/concurrency
policy, and propagation. Unreal documents sound attenuation as asset-owned
spatial behavior and concurrency as a separate voice-management policy:
[Sound Attenuation](https://dev.epicgames.com/documentation/en-us/unreal-engine/sound-attenuation-in-unreal-engine)
and [Sound Concurrency](https://dev.epicgames.com/documentation/en-us/unreal-engine/sound-concurrency-reference-guide).
Its [Audio Mixer overview](https://dev.epicgames.com/documentation/en-us/unreal-engine/audio-mixer-overview-in-unreal-engine)
describes the same separation at system level. Steam Audio treats direct-path
occlusion and propagation as explicit simulation stages; see its
[integration guide](https://valvesoftware.github.io/steam-audio/doc/capi/guide.html)
and [simulation model](https://valvesoftware.github.io/steam-audio/doc/capi/simulation.html).

The corresponding Atom design rules are:

1. Simulation decides whether and where a bullet travelled.
2. Live content records choose the sound and its attenuation.
3. A presentation policy decides whether the cue is important enough to play.
4. Presentation failure never changes combat truth.
5. A future propagation layer may add proven occlusion, but it may not invent a
   collision query or block the current feature on an unaudited ABI.

## Executable identity

All absolute addresses in this document apply only to:

| Property | Value |
|---|---|
| File | `fnv_reverse/FalloutNV.exe` |
| Version | Fallout: New Vegas 1.4.0.525 |
| Format | PE32 i386, image base `0x00400000` |
| PE timestamp | `0x4E0D50ED` |
| File size | `16084808` bytes |
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |

The plugin already rejects unsupported runtimes. Future implementation must
keep all function declarations explicitly x86/`thiscall` or x86/C ABI as
proven and must use the existing DeferredInit admission boundary.

## Existing Atom Ballistics baseline

Atom already owns the difficult simulation-side prerequisite:

- The canonical launch call at `0x005245BD` is chained through its current
  owner.
- A bounded, thread-owned scope changes only the existing
  MissileProjectile hitscan predicate at `0x009B7D08`.
- FNV then constructs its own complete physical runtime state. Atom does not
  mutate a completed projectile or substitute delayed hitscan damage.
- The MissileProjectile subtype update vtable slot at `0x0108FD54` is captured
  transactionally. Its vanilla target is `0x009B8030`, with ABI
  `void __thiscall(MissileProjectile*, float)`.
- The wrapper samples the live position before and after calling its captured
  predecessor exactly once. It never moves the projectile.
- Launch correlation uses a fixed 2048-slot side table with generation-safe
  replacement and bounded probing. It stores numeric tokens, not retained Rust
  references.
- Actor hit construction, ApplyHit, and collision presentation remain native
  and are observed only through already-established chaining seams.

The accepted 2026-08-16 Proton run reported:

- 68 eligible hitscan launches and 68 successful native physical decisions;
- 68 first MissileProjectile updates and 106 later progressive updates;
- 71 delayed first contacts;
- two actor hit constructions followed by two ApplyHit calls; and
- zero contacts entered while the subtype update predecessor was active.

This is runtime evidence that selected bullets move through progressive update
segments and later reach the native contact/damage path. It does not prove how
the result sounds.

One current implementation detail must change before flight feedback ships:
the correlation pool, launch sequence, and pre/post update samples are used
only when diagnostic telemetry is enabled. Production feedback must be driven
by the feature gate, not the diagnostic gate. Diagnostics may observe the same
state but may never be required for behavior.

## Native data contracts

### BGSProjectile

The checked-in xNVSE layout and executable agree on the fields used here:

| Offset | Type | Meaning |
|---:|---|---|
| `+0x60` | `u16` | Projectile flags |
| `+0x62` | `u16` | Projectile family/type |
| `+0x64` | `f32` | Gravity |
| `+0x68` | `f32` | Authored speed |
| `+0x6C` | `f32` | Authored range |
| `+0x70` | pointer | Light |
| `+0x74` | pointer | Muzzle light |
| `+0x78` | `f32` | Tracer chance |
| `+0x7C` | `f32` | Alternate proximity |
| `+0x80` | `f32` | Alternate timer |
| `+0x84` | pointer | Explosion form |
| `+0x88` | pointer | Projectile TESSound |
| `+0x8C` | `f32` | Flash duration |
| `+0x90` | `f32` | Fade duration |
| `+0x94` | `f32` | Impact force |
| `+0x98` | pointer | Countdown sound |
| `+0x9C` | pointer | Disable sound |
| `+0xA0` | pointer | Default source weapon |
| `+0xA4` | data | Rotation data |
| `+0xB0` | `f32` | Bouncy multiplier |
| `+0xB4` | data | Muzzle-flash model |
| `+0xCC` | value | Sound level |

Relevant flags are:

| Flag | Meaning |
|---:|---|
| `0x0001` | Hitscan |
| `0x0002` | Explosion behavior |
| `0x0004` | Alternate trigger |
| `0x0008` | Muzzle flash |
| `0x0020` | Can be disabled |
| `0x0040` | Can be picked up |
| `0x0080` | Supersonic |
| `0x0100` | Pins limbs |
| `0x0200` | Passes small transparent geometry |
| `0x0400` | Detonates |
| `0x0800` | Rotation |

The Supersonic flag is the only established semantic classification for this
feature. Projectile speed is an authored engine value, but no researched fact
maps it to meters per second or establishes a speed of sound in FNV units.
Atom must not guess a Mach threshold.

### TESSound

The live projectile sound at BGSProjectile `+0x88` points to a `0x68`-byte
TESSound. Relevant fields are:

| Offset | Type | Meaning |
|---:|---|---|
| `+0x30` | `TESSoundFile` | Sound file component |
| `+0x44` | `u8` | Minimum attenuation distance |
| `+0x45` | `u8` | Maximum attenuation distance |
| `+0x46` | `i16` | Frequency adjustment |
| `+0x48` | `u32` | Sound flags |
| `+0x4C` | `u16` | Static attenuation |
| `+0x50` | array | Attenuation curve |
| `+0x5A` | `u16` | Reverb attenuation |
| `+0x5C` | `u32` | Priority |

Function `0x00553B90` returns byte `+0x45`. Native projectile spawn multiplies
that value by 100 and stores the result in runtime projectile `+0x14C`.
Therefore `+0x14C` is the linked sound's maximum attenuation distance in
world units, not a second projectile range.

The feature must pass the whole live TESSound to the audio manager. It must not
reimplement its attenuation curve, priority, randomization, reverb, static
attenuation, or 2D/3D flags. Reading maximum distance is only an inexpensive
broadphase rejection; the sound record remains authoritative for mixing.

### Runtime Projectile

The relevant common runtime fields are:

| Offset | Meaning |
|---:|---|
| `+0x20` | Base projectile form |
| `+0x30` | World position, three floats |
| `+0x88` | Impact-data list head |
| `+0x90` | Impacted byte |
| `+0x94` | Transform/collision state |
| `+0xC8` | Runtime flags |
| `+0xCC` | Power |
| `+0xD0` | Speed multiplier |
| `+0xD4` | Runtime travel range |
| `+0xD8` | Age |
| `+0xDC` | Damage |
| `+0xF4` | Weapon condition |
| `+0xF8` | Source weapon |
| `+0xFC` | Source reference |
| `+0x100` | Live target |
| `+0x104` | Direction/movement vector |
| `+0x110` | Distance travelled |
| `+0x114` | Light |
| `+0x11C` | Scene node |
| `+0x128` | 12-byte BSSoundHandle |
| `+0x148` | Projectile-sound-started byte |
| `+0x14C` | Sound maximum attenuation distance |

Atom may read a live view only while the native callback owns the object. Any
state that survives the callback remains pointer-free. A later callback must
revalidate the object token/generation and read current form data again.

## Native sound execution

### Audio objects and ABI

`0x00453A70` returns the BSAudioManager/BSWin32Audio singleton at
`0x011F6D98`. `0x0044EDB0` obtains its listener object at `+0x10`, and the
listener virtual at `+0x0C` supplies the position used by the native near-pass
calculation.

A BSSoundHandle is 12 bytes:

| Offset | Meaning |
|---:|---|
| `+0x00` | Sound ID; `0xFFFFFFFF` is invalid |
| `+0x04` | Assume-success byte and padding |
| `+0x08` | State |

The established audio entries are:

| Address | Operation |
|---:|---|
| `0x00AD7480` | Initialize handle from path, flags, and TESSound |
| `0x00AD8830` | `Play(bool)`, Boolean in AL, `ret 4` |
| `0x00AD8870` | Delayed play |
| `0x00AD88F0` | Stop |
| `0x00AD8B60` | Set 3D position |
| `0x00AD8D10` | Release |
| `0x00AD8F20` | Attach to a scene node |

The proven initializer ABI is:

```text
BSSoundHandle* __thiscall initialize_sound(
    BSAudioManager* manager,
    BSSoundHandle* out,
    const char* path,
    uint32_t flags,
    TESSound* sound);
```

It has four stack arguments, returns `out` in EAX, and ends with `ret 0x10`.
Both native immediate projectile branches use flags `0x102`, set a 3D
position, and call `Play(false)`.

After submission they call `0x00483710` on the stack wrapper. That function is
a no-op in this executable; it does not stop or release the playing one-shot.
The Atom wrapper must mirror this ownership. In particular, an ordinary Rust
drop guard must not stop a successfully submitted one-shot merely because its
local handle goes out of scope.

The initializer uses the engine's existing Windows TLS internally. Calling it
does not require Atom to add a TLS object or loader-time owner.

### Native non-supersonic physical path

Projectile spawn `0x009BCA60` performs this sequence:

1. At `0x009BD1E0`, call `0x009BC870` to test BGSProjectile flag `0x0080`.
2. A supersonic result skips persistent sound construction.
3. Otherwise, read the live projectile sound from form `+0x88`.
4. At `0x009BD247`, initialize a handle with flags `0x40000012`.
5. Copy it to runtime `+0x128`, position it, and attach it to the projectile
   node.
6. Read TESSound maximum attenuation byte `+0x45`, multiply it by 100, and
   store it at runtime `+0x14C`.
7. A runtime hitscan result plays immediately and sets `+0x148`.
8. Otherwise, common update waits until the projectile enters `+0x14C`, plays
   the attached sound, and sets `+0x148` exactly once.

The executable's projectile-debug help calls this the blue diamond for a
non-supersonic/non-hitscan projectile sound start.

Consequence: a physical subsonic bullet already owns native moving sound.
Atom must not add a second whiz, replace its handle, or overwrite its form
sound.

### Native supersonic hitscan path

The MissileProjectile vtable at `0x0108FA44` contains:

| Slot | Entry | Target | Purpose |
|---:|---:|---:|---|
| `+0x308` | `0x0108FD4C` | `0x009B7CC0` | Subtype initialization |
| `+0x310` | `0x0108FD54` | `0x009B8030` | Subtype update |
| `+0x314` | `0x0108FD58` | `0x009B8B10` | Impact |
| `+0x328` | `0x0108FD6C` | `0x009C03F0` | Hitscan collision/near-pass dispatch |

Common initialization calls `0x009BEC90`. That helper tests runtime flag bit 1
and dispatches virtual `+0x328` only when the bit is set. The virtual reaches
shared collision/broadphase routine `0x009C0D80`, which contains the immediate
projectile sound branches.

The local-listener branch:

- rejects a player-owned source through `0x00874480`;
- gets the audio listener position through the functions above;
- computes a closest point and listener distance;
- requires distance strictly below the hard-coded `600.0` value at
  `0x01088210`;
- initializes the live projectile TESSound at `0x009C18D5` with flags `0x102`;
- positions the handle at the computed point at `0x009C1905`; and
- calls Play at `0x009C1912`.

The executable's debug help calls the corresponding teal diamond a near-miss
sound from a supersonic projectile.

The branch does not read or write runtime `+0x148`; it contains no own
exactly-once state. Exact caller cadence can limit repetition, so this document
does not claim repeated audible playback for every native family.

### Why selected physical bullets lose this route

Atom's scoped policy makes FNV answer false to the hitscan predicate. The
initializer therefore clears the runtime condition that calls virtual
`+0x328`. A whole-executable callsite scan found no corresponding `+0x328`
dispatch from MissileProjectile update `0x009B8030` or its ordinary movement
helpers `0x009BF300 -> 0x009BF370`.

The ownership split is therefore:

```text
native hitscan MissileProjectile
    -> initializer runtime bit 1
    -> virtual +0x328
    -> collision query and native supersonic near-pass

Atom-selected physical MissileProjectile
    -> initializer runtime bit 1 clear
    -> subtype update +0x310
    -> progressive physical movement and later native contact
    -> no +0x328 near-pass replay
```

This is the precise reason the new physical path can work correctly while
still sounding incomplete.

## Defects in the native near-pass calculation

Let:

```text
A = line start
B = line end
D = B - A
L = audio listener position
```

The native branch calculates:

```text
t = dot(L - A, D) / dot(D, D)
Q = A + t * D
distance = length(L - Q)
```

It does not clamp `t` to `[0, 1]`. The result is the closest point on an
infinite line, not on the segment that the projectile actually tested or
travelled. It also has no explicit zero-length guard. Non-finite results happen
to fail the later comparison, but this is not a robust geometric contract.

The branch additionally:

- uses a fixed 600-world-unit trigger corridor instead of the linked sound's
  authored attenuation distance;
- has no explicit ray from the passage point to the listener;
- has no explicit obstruction or acoustic propagation test; and
- has no projectile xref to delayed play `0x00AD8870`.

These facts prove limitations of the local branch, not the absence of every
environmental effect later in the audio mixer.

## Tracer ownership

`0x006A78F0` returns BGSProjectile tracer chance at `+0x78`.
`0x004FDF60` performs the native percentage draw, and MissileProjectile
initialization calls it at `0x009B7CE8`. The independent result selects runtime
flag `0x0010`.

For hitscan MissileProjectiles, flags `0x0020` and `0x0002` also encode
hitscan/tracer-dependent runtime policy. Atom's scoped native conversion clears
those hitscan-dependent results but preserves independent tracer selection
`0x0010`, the projectile model, and the native instance.

Flight feedback may expose `tracer_selected` as read-only event metadata. It
must never:

- redraw tracer chance;
- spawn a second visual projectile;
- rewrite a projectile model;
- make visual selection decide collision; or
- add a tracer because the audio cue was admitted.

## Impact and material ownership

Native collision effects are owned by `0x009C20E0`. It reads the live source
weapon from runtime projectile `+0xF8` and passes the raw collision material to
weapon resolver `0x00522BA0`.

That resolver reads the weapon's current BGSImpactDataSet at `+0x24C`.
`0x0058E8F0` maps raw material values `0..31` to ten data-set slots, and
`0x0058E9D0` returns the pointer from the set's array beginning at `+0x1C`.
Out-of-range raw material values use default index 4.

A BGSImpactData record is `0x78` bytes. Its first and second TESSound pointers
are at `+0x4C` and `+0x50`. Native collision effects read those sounds through
`0x0068A810` and `0x0068A830`, position them at the exact collision point, and
play them around `0x009C2B66..0x009C2C6E`. The same owner creates the effect
model and decal.

Consequences:

- The existing collision wrapper must call its captured predecessor exactly
  once.
- Flight audio must not play an impact sound when its passage segment ends.
- Atom must not cache a weapon's impact set because scripts and mods can patch
  the live field.
- A future material-response wrapper may observe a pointer-free post-contact
  event, but it is a different feature with a separate continuation contract.

## Explosion boundary

BGSProjectile flag `0x0002` and form `+0x84` select explosion behavior/data.
BGSExplosion owns sounds, impact data, radius, force, image-space radius,
radiation, and multiple behavior flags. The installed Explosive Overhaul also
owns arming, duds, LOS, concussion, ringing, and related policies.

Atom's current capability classifier excludes a MissileProjectile when either
explosion indication exists. Flight feedback must preserve that exclusion even
if an explosive projectile also carries a Supersonic flag or a projectile
sound. Generic projectile passage is not permission to duplicate or reorder
explosion behavior.

## Installed compatibility audit

The active profile was inspected read-only on 2026-08-16. This table records
behavior relevant to the design; it is not a named-mod dependency list.

| Installed component | Observed behavior | Required Atom response |
|---|---|---|
| Kyu's Ballistics TTW | Overrides projectile records and models | Read live form fields; never use vanilla FormID/value tables |
| Bullet Trails | Chains canonical launch and spawns a separate visual `MadBulletTrail` projectile for ballistic hitscan forms | Keep form hitscan semantics unchanged; require Atom launch correlation so the visual child is ignored |
| Improved Bullet Tracers | A GECK script mutates live projectile tracer chance, transparency flag, model, and optional speed/range by EditorID | Snapshot live data; do not redraw chance, replace its model, or repair its content |
| IMPACT | Iterates loaded weapons and patches live impact-data sets by weapon/ammo class | Leave `0x009C20E0` and the live weapon resolver authoritative |
| Explosive Overhaul | Owns explosion arming, duds, LOS, damage/effects, concussion, and ringing | Exclude explosion-linked projectile families |
| ITR NVSE | Hooks common Projectile update for `ITR:OnNearMiss`; also exposes impact-data and sound-played events | Keep Atom on the Missile subtype vtable slot; do not hook the common update prologue or republish ITR events |
| Sound Extender | Opaque installed audio extension | Submit through normal engine audio calls; do not inspect or depend on it |
| B42 Recoil and animation stacks | Own recoil/animation presentation | Do not modify those domains |
| Consistent Spread | Owns spread behavior | Do not modify spread |
| Combat AI Tweaks | Owns AI behavior | Do not scan or modify actors in flight audio |

### Bullet Trails composition

Read-only source at
`.research/Stewie Tweaks 10.00 Source/code/Features/BulletTrails.cpp` shows that
Bullet Trails hooks canonical call `0x005245BD`, chains the target already
encoded there, and then spawns a separate visual projectile. Atom already
captures and calls the current canonical owner, so both wrappers compose.

Atom deliberately does not mutate the shared BGSProjectile hitscan flag. Bullet
Trails therefore still sees the authored hitscan form and can create its
visual. Its child is spawned outside the canonical weapon launch seam and has
no Atom correlation record. Although every Missile instance uses the same
subtype vtable slot, the update wrapper finds no matching generation and must
ignore that child. This prevents duplicate audio and makes the rule
capability-based rather than name-based.

### Improved Bullet Tracers composition

The active configuration sets tracer chance to 1 and leaves speed/range at
zero, while enabling lingering behavior. Its script resolves EditorIDs and
mutates live form data. Atom must neither cache startup copies nor assume
vanilla meshes. The inspected profile also contains a small-rifle mesh-name
mismatch; that is content-owned and Atom must not detect or repair it.

### IMPACT composition

The installed IMPACT plugin describes itself as auto-patching weapon shells
and impact sets without weapon-mod patches. Its embedded script iterates loaded
weapon forms and calls the live impact-data-set setter. Because FNV's collision
owner resolves `weapon + 0x24C` at contact time, leaving that path untouched is
the strongest automatic compatibility policy.

### ITR NVSE composition

The active ITR configuration uses near-miss radius 256 and cooldown 250 ms.
Read-only checked-in source shows that its near-miss listener hooks common
Projectile update `0x009BECC0` and queues actor events. The installed DLL also
contains `ITR:OnNearMiss`, `ITR:OnImpactDataSpawn`, and `ITR:OnSoundPlayed`.

Atom must not claim the common update prologue. Its existing MissileProjectile
`+0x310` slot is the correct compatible seam. The local-listener feature does
not scan actors, publish an ITR event, or depend on ITR. Calling FNV's normal
sound initializer/Play route allows a generic sound observer to see the sound
without Atom knowing that observer exists.

## Compatibility contract

"Compatible with all vanilla and mod-added weapons" has a precise, testable
meaning:

1. Admission depends only on live engine capabilities and relationships:
   projectile family, explosion ownership, selected physical path,
   Supersonic flag, source kind, sound link, and valid runtime movement.
2. No vanilla FormID, plugin filename, load order, EditorID, damage value,
   caliber table, or named-mod check participates.
3. Live records remain authoritative. A mod-added weapon using the standard
   weapon -> ammo -> BGSProjectile -> TESSound relationships receives the same
   behavior automatically.
4. A naturally physical mod projectile is supported as well as an
   Atom-converted hitscan projectile, provided it is a discrete non-explosive
   MissileProjectile and reaches the canonical launch seam.
5. Missing, invalid, 2D, silent, or proprietary metadata is not silently
   invented. The cue is omitted and a bounded diagnostic counter explains the
   coverage gap.
6. Unknown/custom projectile families remain entirely native.
7. Presentation capacity pressure drops presentation, never a projectile or
   hit.
8. Existing hook owners are chained through the current-owned seams. Atom does
   not inspect or patch another plugin.

No native plugin can promise composition with an arbitrary later overwrite of
the same vtable slot or with proprietary projectile instances that bypass every
standard launch path. Atom's honest boundary is: preserve native behavior,
chain current owners, support standard live record capabilities, and fail open
when ownership cannot be established. It must log one stable warning with the
consequence rather than pretending the feature is active.

## Proposed production architecture

### One presentation consumer, not a second ballistics simulation

The feature consumes the trajectory FNV already produced:

```text
canonical launch
    -> immutable pointer-free launch context
    -> native initializer selects physical flight
    -> fixed generation record
    -> MissileProjectile +0x310 wrapper
        -> sample A
        -> call captured update owner exactly once
        -> sample B
        -> classify finite travelled segment
        -> compare with audio listener
        -> optionally submit one 3D sound
    -> native contact, impact, and damage continue unchanged
```

It must never integrate velocity itself, predict a future hit, move the native
object, perform collision, or delay damage. FNV's post-update position is the
truth.

Planned source ownership is deliberately narrow:

| File | Responsibility |
|---|---|
| `atom/src/ballistics/flight.rs` | Pure segment geometry, eligibility, passage outcome, and limiter policy |
| `atom/src/ballistics/native.rs` | Callback-local projectile/sound/listener views and typed native audio calls |
| `atom/src/ballistics/context.rs` | Immutable pointer-free launch facts and public read-only value types |
| `atom/src/ballistics/pool.rs` | Generation-safe production correlation and terminal feedback state |
| `atom/src/ballistics/hooks.rs` | Existing launch/update predecessor chaining and consumer invocation |
| `atom/src/ballistics/telemetry.rs` | Optional saturating reason counters and lifecycle snapshot |
| `atom/src/ballistics/mod.rs` | Configuration publication, lifecycle clear, and human-readable summaries |

No feedback code belongs in the camera, input, OMV, engine-fixes, or helper
crates. If pure geometry becomes large enough to need submodules, that should
be justified by the implementation diff rather than pre-created scaffolding.

### Eligibility matrix

| Condition | Flight cue |
|---|---|
| Atom-converted discrete Missile, physical selected | Eligible |
| Mod-authored discrete Missile, already physical | Eligible |
| Hitscan fallback after policy rejection/failure | Native only |
| Non-supersonic physical Missile | Native attached sound only |
| Player-owned round | No local passage cue |
| Non-player actor-owned round | Eligible |
| Unknown/null source | Native only in the first implementation |
| Always-hit or live-target launch context | Native only in the first implementation |
| Explosion flag or explosion link | Native/explosion owner only |
| Grenade, mine, thrown, beam, flame, continuous beam | Native only |
| No projectile TESSound or empty file | Silent, counted as missing metadata |
| TESSound is explicitly 2D | Silent, counted as non-spatial metadata |
| Invalid/zero attenuation range | Silent, counted as invalid metadata |
| No valid listener | Silent for that update |
| No finite non-degenerate movement segment | No attempt |
| Uncorrelated visual/helper projectile | Ignore |

Eligibility is immutable at launch for family, source kind, and selected flight
path. Supersonic and sound data should be validated from the live form during
the owned callback and compared with the launch form token; no raw form or
sound pointer survives the call.

Atom must not clear an authored 2D sound flag to force localization. A 2D
projectile sound cannot answer where the passage occurred, so the first
listener-centric consumer omits it and reports the metadata reason.

### Finite-segment passage geometry

For finite pre-update position `A`, finite post-update position `B`, and finite
audio-listener position `L`:

```text
D = B - A
denominator = dot(D, D)
t_unclamped = dot(L - A, D) / denominator
t = clamp(t_unclamped, 0, 1)
Q = A + t * D
distance_squared = dot(L - Q, L - Q)
```

Required numerical rules:

- Reject non-finite inputs and results.
- Reject `denominator` below a small squared-distance epsilon; do not divide a
  stationary segment.
- Use squared distance for the broadphase and take a square root only if a
  consumer needs the linear value.
- Require a genuine passage through the listener plane (`0 < t < 1`, with a
  small numerical boundary tolerance) before playing. An endpoint-only closest
  point means the bullet is still approaching, already leaving, or stopped at
  contact. This avoids playing a wall-adjacent cue merely because the infinite
  continuation would have passed the listener.
- Treat an impacted post-state as contact-owned. It may supply observation
  metadata, but an endpoint at that impact must not create a flight cue.
- Mark a terminal attempt only after a genuine passage is found. A bullet may
  enter the attenuation sphere while still approaching and should remain
  eligible until it crosses or terminates.

The chance of an exact perpendicular crossing on a frame boundary is small.
The implementation should retain the previous signed along-track relation in
the fixed generation state so tests can accept a sign change across adjacent
segments without widening endpoint admission. This closes the mathematical
boundary case without using an infinite ray.

### Audible range

The broadphase radius should be the live TESSound maximum attenuation byte
multiplied by 100, exactly as native projectile spawn interprets it. The audio
record still applies its real attenuation curve and priority after submission.

Do not expose a global "near miss radius" or use native `600.0` as a balance
knob. A content author who changes the standard sound record automatically
changes the useful range. Invalid or zero record range is a metadata gap, not
permission to invent a caliber table.

Because the source is a byte, the native conversion is inherently bounded to
`0..25500` world units. No second arbitrary hard radius is necessary.

### Sound submission

For one admitted passage:

1. Revalidate the live projectile form and its TESSound.
2. Obtain the existing sound-file path using the engine-compatible form
   component layout/getter.
3. Initialize a stack-local 12-byte handle through the live entry
   `0x00AD7480`, using native immediate flags `0x102`.
4. Position it at finite closest point `Q` through `0x00AD8B60`.
5. Call `Play(false)` through `0x00AD8830`.
6. Record the attempt outcome in the fixed generation state.
7. Let the submitted one-shot remain manager-owned; do not stop it on local
   scope exit.

Atom must call the public engine entry, not copy its implementation or require
a vanilla prologue. This preserves composition with generic sound extensions
that hook the normal route.

No acoustic-delay call is justified yet. The physical projectile reaches `Q`
at simulation time, so immediate submission already occurs at bullet passage
rather than at muzzle fire. A further `Q`-to-listener propagation delay would
require a proven world-unit scale and speed of sound. Muzzle reports also
remain owned by their existing immediate path; delaying only one layer with a
guessed conversion would create inconsistent timing.

### Exactly-once state

Each generation record needs a small terminal state, for example:

```text
Pending
Played
SuppressedByBudget
MissingSound
InvalidData
AudioRejected
Terminated
```

`Played` means Play accepted the one-shot. Every other terminal reason prevents
repeated retries or log spam for the same generation. A pointer token reused by
a later projectile starts at `Pending` only after generation replacement is
published atomically.

This Atom state is necessary because the native immediate branch does not use
runtime `+0x148`. Atom must not repurpose a runtime flag or write into unused
projectile tail storage.

### Automatic presentation limiting

One physical pellet is one authoritative projectile, but one audible voice per
pellet can turn shotgun and automatic fire into noise and waste mixer voices.
Modern concurrency policy treats voice admission separately from event
generation. Atom should do the same with a fixed, allocation-free limiter.

The first limiter should have two layers:

1. **Per-source/weapon burst grouping.** Key a small fixed table by source
   token, weapon token, a short monotonic time bucket, and a coarse direction
   bucket. Within one group, admit the first qualified passage and terminally
   suppress later near-identical pellet passages. All pellets still retain
   their independent movement, contact, and observation state.
2. **Global voice budget.** Use a small token bucket over a short monotonic
   window, split into a general lane and a close-pass reserve. Classify close
   versus distant by passage distance normalized to the live sound's authored
   attenuation range. Distant cues cannot consume the close reserve, so an
   earlier distant cue cannot starve a later dangerous one.

No weapon category, caliber, damage value, fire-rate table, or plugin name is
needed. Grouping derives from the actual launch and trajectory. Constants are
internal presentation limits with deterministic tests, not user balance
sliders.

The current `ShotContext.sequence` advances only while telemetry is enabled and
assigns one sequence per launch, not one sequence per multi-projectile shot.
Implementation must make sequence generation independent of diagnostics and
must not pretend that launch sequence alone groups pellets. The existing
effective-projectile-count hook can be used only after a nested/threaded shot
scope has a proven lifetime; until then, source/weapon/time/direction grouping
is safer than a false exact correlation.

The limiter must not defer sound work to an unproven thread. Projectile update
already executes at the native simulation boundary that owns the live object
and calls native audio elsewhere. All hot-path state remains atomic or
thread-owned and bounded.

### Pointer-free event boundary

The first implementation may keep the consumer internal, but its data contract
should be suitable for later systems without retaining engine pointers:

```text
FlightSegmentObservation
    projectile token and generation
    launch sequence
    source kind and numeric source token
    numeric weapon and projectile-form tokens
    immutable capability and selected path
    pre/post positions
    delta seconds and observed effective speed
    tracer-selected bit
    supersonic bit

NearPassObservation
    projectile token and generation
    closest point
    squared distance
    segment fraction
    sound-submission outcome
```

Tokens are for correlation and diagnostics only. No API may cast them back to a
retained Rust reference. Consumers that need live engine data must operate
inside an explicitly owned native callback and validate it again.

Do not publish an xNVSE event from the projectile update hot path in the first
implementation. Script dispatch, allocations, third-party reentrancy, and event
parameter lifetime need their own contract. Future AI suppression can consume a
bounded native queue after its actor and threading model is researched.

## Occlusion and propagation

The native near-pass branch performs no explicit passage-point-to-listener ray.
A finite travelled segment fixes its infinite-line false positive and prevents
a cue after a bullet stops before the listener plane. It does not solve a
parallel wall between a valid passage point and the listener.

A production-safe FNV Havok ray payload, collision-layer mask, world ownership,
lock/thread contract, and ignore-object policy are not established for this
feature. Existing third-party ray structures are corroboration only and must
not be copied as engine authority. Repository crash research also shows that
Havok ray ownership and concurrent world lifetime are safety-sensitive.

Therefore:

- The first implementation should not add an unaudited raycast.
- It should rely on actual travelled-segment truth and the current sound
  record/audio environment.
- It should expose an internal `Direct`, `Unknown`, or future `Occluded`
  propagation result without claiming `Direct` until a ray exists.
- A later occlusion phase requires focused native research of the exact
  main-thread point-to-point ray entry, payload layout, layer policy, reference
  filtering, world lock, ABI, and cost.

This is a documented limitation, not hidden uncertainty. No current fact
justifies a fake wall test or a third-party dependency.

## Failure behavior

| Failure | Required result |
|---|---|
| Ballistics hook transaction cannot own every required seam | Roll back Ballistics feature hooks; other Atom modules remain available |
| Current Missile update slot cannot be chained | Physical policy/flight feedback unavailable with one error stating the consequence |
| Per-launch policy slot unavailable | Keep chained native hitscan answer |
| Correlation pool unavailable/full | Keep projectile fully native; omit optional feedback |
| Token generation changed | Reject stale state |
| Unsupported family or explosion link | Native behavior only |
| Invalid form, sound, listener, segment, or attenuation | Drop cue; increment bounded reason counter |
| Presentation limiter full | Suppress cue only |
| Audio initialization or Play fails | Mark terminal failure; do not retry every update |
| Generic sound hook is present | Call normal entry and allow it to observe/chains its own route |
| Another owner replaces Atom's vtable slot later | Do not fight or repatch it; report ownership loss at a safe lifecycle summary |
| Load/new game/main menu | Clear all generations, limiter buckets, and diagnostic counters at the established lifecycle boundary |

No failure path may write projectile position, flags, damage, target, collision
state, sound record, impact data, or another mod's memory.

## Performance and memory contract

Per correlated update, before sound admission, the intended cost is:

- two already-required finite position samples;
- one audio-listener lookup only for eligible supersonic non-player rounds;
- one finite segment projection;
- one fixed-table state lookup;
- no heap allocation, file I/O, logging, actor enumeration, script dispatch,
  raycast, or blocking lock.

Only a genuine admitted passage initializes a sound handle. The cue is at most
once per projectile generation and additionally limited by presentation
budget.

The existing 2048-slot observation pool occupies `152 KiB + 4 bytes` in its
current tested layout. Feedback state should extend or pair with that pool
without creating another unbounded map. A 32-byte addition per slot would cost
64 KiB; the final implementation must assert its actual i686 size and justify
any larger payload. The limiter should be a much smaller fixed table.

All process-lifetime storage is allocated/initialized at the existing
DeferredInit boundary. The change must not add a pre-DeferredInit LazyLock
first-touch, TLS value/destructor, worker, import, file scan, parser, or global
constructor. Before implementation changes configuration layout or startup
reachability, `docs/nvse_startup_phase_safety.md` must be read and its artifact
and playtest gates applied.

## Configuration ownership

The first production surface should remain minimal:

- Ballistics master gate: existing owner.
- Flight Audio: one on/off gate, default on only after the accepted artifact.
- Diagnostics: existing bounded diagnostics gate, default off.

There should be no user-facing projectile list, damage slider, caliber table,
near-pass radius, speed-of-sound number, volume multiplier, pellet count, or
per-mod patch. Content records and actual trajectories provide automatic
tuning. Internal concurrency and corrupt-data safety bounds remain tested
implementation constants.

Any MCM Extender text must remain one to three words. If the new toggle is
added, `MCMExtUpdate` must remain the writer-to-native publication route after
its INI save; no per-frame INI parsing is allowed.

## Implementation plan

This is an implementation plan, not a statement that the code already exists.

### Phase A: pure geometry and policy

1. Add a small Ballistics-owned flight-feedback module with module-level docs.
2. Implement finite-vector validation and closest-point-on-segment as pure Rust.
3. Implement the eligibility classifier from `ShotContext`, selected path, live
   form facts, and source kind.
4. Implement terminal exactly-once state and a fixed limiter model independent
   of native audio.
5. Unit-test every numerical, classification, generation, and capacity edge.

Acceptance: all behavior is deterministic and testable without FNV pointers.

### Phase B: extend live native views

1. Add only the proven BGSProjectile fields needed after `+0x84`, including the
   projectile sound.
2. Add a minimal audited TESSound/TESSoundFile view and BSSoundHandle layout.
3. Add listener lookup and typed audio function declarations with explicit x86
   ABI.
4. Add offset, size, invalid-handle, and return-convention tests where
   executable in the supported Windows target.
5. Keep raw pointers callback-local and expose validated values through narrow
   safe wrappers.

Acceptance: layouts match xNVSE headers and the binary contract; no public API
can retain a native reference.

### Phase C: production correlation

1. Decouple launch sequence and correlation admission from telemetry.
2. Track both successfully converted discrete hitscan rounds and already
   physical discrete Missile rounds.
3. Preserve the current generation, bounded probing, expiry, and lifecycle
   rules.
4. Store only the additional immutable flags and terminal feedback state needed
   by the consumer.
5. Keep telemetry as a passive observer of production state.

Acceptance: feature behavior is identical with diagnostics on or off.

### Phase D: update-path consumer

1. In the existing `+0x310` wrapper, sample the live object and locate its
   generation before the predecessor.
2. Call the captured predecessor exactly once.
3. Resample, reject stale/invalid/impacted state, and calculate the finite
   travelled segment.
4. Query the audio listener only for eligible supersonic physical rounds.
5. Apply passage and limiter policy.
6. Submit the live TESSound at closest point `Q` through the normal engine
   entry.
7. Record one terminal outcome without modifying simulation.

Acceptance: synthetic hook-owner tests prove predecessor chaining and fail-open
behavior; runtime summaries reconcile launch, eligible, attempted, played,
suppressed, missing-metadata, and audio-failure counts.

### Phase E: configuration and documentation

1. Add the laconic MCM/config gate through the established event publication
   route.
2. Update this document from design to implemented source ownership, exact
   memory cost, tests, artifact fingerprint, and accepted runtime result.
3. Update the Ballistics core plan and Atom feature index without changing
   unrelated modules.
4. Run configuration artifact/round-trip tests and the supported release gates.

### Deferred Phase F: acoustic occlusion

Perform the focused native research listed in the occlusion section. Implement
only if the exact ray ownership and cost are proven and the audible benefit is
worth one query per already-admitted cue. It is not a prerequisite for Phase A
through E and must not be approximated with an unsafe payload.

## Test plan

### Pure behavior tests

- Closest point for a perpendicular crossing.
- Segment start/end ordering independence.
- Rejection of zero-length and sub-epsilon movement.
- Rejection of NaN and infinity in every input and derived value.
- No infinite-line admission before the segment or beyond it.
- Exact/near endpoint boundary behavior across adjacent segments.
- Impact endpoint does not create a flight cue.
- Distance comparison at just inside, exactly at, and just outside range.
- Player, unknown source, explosive, unsupported family, hitscan fallback,
  subsonic, missing sound, and invalid attenuation rejection.
- Converted physical and already-physical admission.
- Exactly one attempt per projectile generation.
- Pointer reuse starts clean only after generation replacement.
- Pool and limiter overflow drop presentation deterministically.
- Pellet grouping and global budget never affect simulation counters.

### Native boundary tests

- `BGSProjectile`, `TESSound`, `TESSoundFile`, runtime Projectile, and
  BSSoundHandle offsets/sizes on i686.
- Typed initializer, position, and Play declarations match stack cleanup and
  return conventions.
- Listener null paths remain safe.
- Empty/invalid sound path fails without calling Play.
- Synthetic current-owner Missile update is called exactly once.
- A changed or lost vtable owner does not overwrite the new owner.
- Diagnostics-disabled behavior still admits and plays from production state.
- Hook transaction rollback leaves other Atom modules available.

### Compatibility artifact tests

- MCM text remains one to three words.
- INI serialization and `MCMExtUpdate` publication round-trip the new gate.
- No named plugin, EditorID, FormID, projectile mesh, or weapon table enters the
  shipped policy data.
- Supported DLL imports, TLS directory, and pre-DeferredInit footprint are
  compared with the accepted baseline when affected.

### Build gates for implementation

When Rust/build inputs change:

```bash
cargo test --target i686-pc-windows-gnu -p atom
cargo build --release --target i686-pc-windows-gnu -p atom
```

Then run the repository's required full supported release build if shared code
or complete packaging is affected. Formatting, `git diff --check`, and final
diff inspection remain required but do not replace tests or the build.

## One bounded runtime acceptance

Static analysis cannot prove audibility, direction, mix level, or asset quality.
After the implementation and release artifact pass static gates, request one
ordinary load-to-gameplay firefight, not repeated manual diagnostics.

The automatic shutdown/lifecycle summary must report at least:

- correlated physical launches;
- eligible supersonic enemy rounds;
- genuine finite-segment passages;
- sounds initialized and Play accepted;
- passages suppressed by grouping/global budget;
- missing sound/path/attenuation metadata;
- invalid listener or geometry;
- duplicate attempts prevented;
- audio failures;
- hitscan fallbacks left native;
- subsonic physical rounds left native; and
- uncorrelated helper/visual projectiles ignored.

The user need only answer these perceptual questions:

1. Is an enemy round passing close clearly localizable and threatening?
2. Do automatic fire and shotguns remain readable rather than noisy?
3. Are there obvious duplicate cues at impact or from tracer helpers?
4. Does ordinary combat remain stable through load, cell travel, death/reload,
   and return to menu?

If counts prove correct routing but the cue is weak, investigate live sound
record/assets and mixer priority. Do not alter damage, movement, or add view
effects to disguise an audio problem.

## Proven facts, inferences, and open work

### Proven

- The exact supported executable identity and all addresses listed above.
- The BGSProjectile, TESSound, impact, and runtime Projectile fields used here.
- Native persistent sound ownership for non-supersonic physical projectiles.
- Native immediate near-pass sound construction and listener geometry.
- Native hard-coded distance 600 and unclamped infinite-line projection.
- Absence of an explicit local ray/delayed-play call in that branch.
- Atom-selected physical Missile initialization bypasses the hitscan-only
  virtual that reaches native near-pass.
- Ordinary physical Missile update does not redispatch that virtual.
- Native tracer selection is independent and retained by Atom conversion.
- Native/live weapon impact resolution and exact collision-effect ownership.
- Existing installed mods compose through live forms and established hook
  seams as described.

### Design inferences

- Finite pre/post physical segments are the safest truthful source for passage
  presentation.
- The live authored Supersonic flag and projectile TESSound are more compatible
  than a guessed velocity/caliber database.
- The current subtype update wrapper is the correct intervention point.
- Exactly-once and concurrency state belong in Atom's fixed generation sidecar.
- An immediate 3D one-shot at physical passage is coherent without a guessed
  acoustic delay.
- No native suppression hook is required for physical-only admission.

### Open and not claimed

- FNV world units per meter and an engine-unit speed of sound.
- A production-safe point-to-point acoustic ray ABI, layer mask, and lock
  contract.
- Downstream mixer occlusion behavior beyond the inspected projectile branch.
- Exact audible quality and record coverage across every active content item.
- Native near-pass caller cadence for every non-Missile projectile family.
- Composition with proprietary projectiles that bypass the canonical launch
  seam or with a later destructive vtable overwrite.

These open facts do not block the first implementation because its contract
does not depend on them. They must remain explicit rather than being filled by
assumption.

## Evidence index

Primary repository evidence:

- [Raw projectile feedback contract](../analysis/radare2/output/gameplay/fnv_projectile_feedback_contract.txt)
- [Raw combat contract](../analysis/radare2/output/gameplay/fnv_combat_contract.txt)
- [Atom Ballistics core plan](atom_ballistics_core_plan.md)
- [Atom combat engine contract](atom_combat_engine_contract.md)
- [Accepted Ballistics runtime log](../.reports/atom-ballistics-native-policy-2026-08-16.log)
- `libnvse/xnvse/nvse/nvse/GameForms.h`
- `atom/src/ballistics/adapter.rs`
- `atom/src/ballistics/context.rs`
- `atom/src/ballistics/hooks.rs`
- `atom/src/ballistics/native.rs`
- `atom/src/ballistics/pool.rs`
- `atom/src/ballistics/telemetry.rs`

Read-only interoperability evidence:

- `.research/Stewie Tweaks 10.00 Source/code/Features/BulletTrails.cpp`
- `.research/itr-nvse-master/itr-nvse/handlers/OnNearMissHandler.cpp`
- `.research/itr-nvse-master/itr-nvse/handlers/OnSoundPlayedHandler.cpp`
- Active FalloutNV TTW profile, plugin order, mod metadata, and shipped configs
  inspected on 2026-08-16.

External design references:

- [Unreal Engine Sound Attenuation](https://dev.epicgames.com/documentation/en-us/unreal-engine/sound-attenuation-in-unreal-engine)
- [Unreal Engine Sound Concurrency](https://dev.epicgames.com/documentation/en-us/unreal-engine/sound-concurrency-reference-guide)
- [Unreal Engine Audio Mixer](https://dev.epicgames.com/documentation/en-us/unreal-engine/audio-mixer-overview-in-unreal-engine)
- [Steam Audio integration guide](https://valvesoftware.github.io/steam-audio/doc/capi/guide.html)
- [Steam Audio simulation](https://valvesoftware.github.io/steam-audio/doc/capi/simulation.html)
- [Lo et al., ballistic shock-wave measurement](https://pubmed.ncbi.nlm.nih.gov/28679249/)
- [2024 shooting-acoustics study](https://pubmed.ncbi.nlm.nih.gov/38341747/)
- [NASA sonic-boom flight research overview](https://ntrs.nasa.gov/api/citations/20220015115/downloads/NASA%20Sonic%20Boom%20Flight%20Research_2022Oct_rev0_v2.pdf)

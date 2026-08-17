# Atom Ballistics gameplay ricochet research

Research status: complete for the first production implementation.

Implementation status: not started by this research change.

Date: 2026-08-16.

## Executive decision

Gameplay ricochet should be the next Ballistics feature. The already researched
near-pass audio remains useful, but it is presentation. Ricochet changes the
fight itself: a shallow strike on hard world material can redirect the same
live round, lose speed and damage, and later produce a normal native hit.

The first production slice should be deliberately strict:

- support vanilla and mod-added discrete bullet projectiles through live engine
  capabilities, not FormID, EditorID, weapon, ammunition, or caliber lists;
- admit only ordinary non-explosive MissileProjectile impacts against known
  stone, metal, or hollow-metal world material;
- allow one deterministic gameplay bounce per projectile generation;
- run FNV's complete native impact traversal exactly once at the first surface;
- redirect the same projectile through native reference yaw/pitch ownership;
- attenuate only that projectile's live speed and damage;
- leave its later collision, ActorHitData, damage, attribution, tracer, impact
  data, and destruction on their native routes; and
- fail to the complete native terminal result whenever any fact is missing or
  another owner makes the seam ambiguous.

This is a real continuation, not a spark, sound, or terminal Havok bounce. The
acceptance criterion is not "a ricochet effect appeared." It is "the redirected
round travelled on the reflected path and could cause a later ordinary native
hit with reduced damage."

Camera movement, view kick, shake, recoil, and view-state reads are explicitly
outside this feature. Ricochet does not require a camera subsystem. It also does
not require new sound work to have gameplay value.

The detailed static evidence is retained in
[`fnv_projectile_ricochet_contract.txt`](../analysis/radare2/output/gameplay/fnv_projectile_ricochet_contract.txt).
The broader combat model remains in
[`atom_combat_engine_contract.md`](atom_combat_engine_contract.md), while
[`atom_ballistics_core_plan.md`](atom_ballistics_core_plan.md) owns phase order.

## Player-visible contract

When the feature is enabled and all admission checks pass:

1. A physical bullet strikes eligible hard world geometry at a shallow angle.
2. The normal authored impact effect appears once at the real contact.
3. The struck non-Actor object receives the same native first-contact behavior
   it would have received without Atom.
4. The existing projectile changes direction and continues from that contact.
5. Its physical speed and possible later hit damage are lower.
6. A later actor or object collision uses the ordinary native impact and damage
   paths, including source attribution, weapon context, perks, armor, scripts,
   and mod-authored impact data.
7. The projectile terminates normally at its next genuine impact, range limit,
   lifetime limit, or another native kill condition.

The player and NPC use the same policy. An NPC bullet can ricochet toward the
player; a player bullet can ricochet toward an NPC. Difficulty modifiers and
all existing source-dependent damage rules continue to apply downstream.

The first slice intentionally does not ricochet:

- head-on or moderately oblique hits;
- actors, creatures, corpses, or body parts;
- dirt, grass, glass, wood, organic, cloth, or water;
- explosive missiles, grenades, mines, thrown weapons, beams, flames, or
  continuous beams;
- VATS, always-hit, or live-target projectiles;
- native impale, stick, pickup/debris bounce, or other special outcomes;
- uncorrelated visual trail children; or
- an impact whose material, normal, direction, state, or hook ownership cannot
  be proved safe.

Glass, wood, and cloth belong to later penetration research. Treating every
hard-looking material as "metal" would create broad but synthetic behavior and
would be less compatible with authored content.

## Evidence vocabulary

This document separates fact from design:

- **Proven - binary:** direct radare2 disassembly, xrefs, binary data, or call
  graph from the identified executable.
- **Proven - header:** a checked-in xNVSE 1.4.0.525 layout or enum.
- **Observed - runtime:** a retained Atom Proton playtest log.
- **Observed - content:** read-only inspection of the active MO2 profile,
  installed artifact, or authored records.
- **Corroboration:** read-only third-party source used to understand possible
  interoperability; never the authority for an engine address or ABI.
- **Design inference:** the proposed production policy derived from proven
  contracts.
- **Open:** a claim that still requires implementation evidence or a bounded
  playtest.

The executable researched with the radare2 MCP is:

```text
fnv_reverse/FalloutNV.exe
Fallout: New Vegas 1.4.0.525
PE32 i386, image base 0x00400000
PE timestamp 0x4E0D50ED
size 16084808 bytes
SHA-256 42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c
```

## Modern shooter architecture

Modern combat does not make a ricochet decision from a weapon name or play a
sound and pretend the simulation changed. It separates four responsibilities:

| Responsibility | Authoritative input | Output |
|---|---|---|
| Contact | Swept movement or trace | Point, normal, struck object, material |
| Response | Contact plus live projectile state | Stop, ricochet, penetrate, detonate |
| Damage | Resolved hit plus source/target state | Native damage and injury consequences |
| Presentation | Resolved event | Impact data, particles, decals, audio, tracer response |

Unreal's official collision API exposes impact point, impact normal, struck
actor/component, bone, and physical material in the hit result. Its Physical
Material system exists to attach dynamic response properties to surfaces, and
its physical-material API includes restitution and a physical-surface type.
Those are examples of the general architecture, not code to transplant into
FNV. See [Break Hit Result](https://dev.epicgames.com/documentation/en-us/unreal-engine/BlueprintAPI/Collision/BreakHitResult),
[Physical Materials](https://dev.epicgames.com/documentation/unreal-engine/physical-materials-in-unreal-engine?lang=en-US),
and [UPhysicalMaterial](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/PhysicsCore/UPhysicalMaterial).

PhysX similarly resolves pairwise material properties through explicit combine
modes rather than a list of weapon records. That supports Atom's decision to
classify the actual contact material and retain current projectile values. It
does not imply that FNV's authored materials contain physically calibrated
coefficients. See [PxCombineMode](https://nvidia-omniverse.github.io/PhysX/physx/latest/_api_build/structPxCombineMode.html).

Ballistics literature describes ricochet boundaries as dependent on incidence
angle, impact velocity, projectile/target material, and geometry. It does not
provide one universal coefficient that can be truthfully applied to every FNV
weapon. See the Defence Science Journal's
[ricochet-model study](https://publications.drdo.gov.in/ojs/index.php/dsj/article/view/15803)
and this [impact and ricochet review](https://res.mdpi.com/d_attachment/applsci/applsci-10-06810/article_deploy/applsci-10-06810-v2.pdf).

The practical AAA lesson for Atom is therefore:

- use the engine's real collision point, normal, and material;
- decide response at one authoritative impact seam;
- preserve the native hit/damage pipeline rather than recomputing it;
- use live runtime projectile values as the balance baseline;
- make response deterministic and bounded; and
- publish a resolved ricochet event for optional later presentation, never let
  presentation manufacture gameplay.

The desired flow is:

```text
native swept movement
        |
        v
native ImpactData (point, normal, material, target)
        |
        v
native target work + live IMPACT effect, exactly once
        |
        v
Atom response policy
   | terminal                     | eligible ricochet
   v                              v
native destroy              redirect same projectile
                             attenuate live state
                             clear terminal contact
                                      |
                                      v
                              next native movement/hit
```

## FNV's real projectile and impact pipeline

### Relevant runtime state

The proven common Projectile fields are:

| Offset | Meaning | Ricochet use |
|---:|---|---|
| `+0x020` | Base projectile form | Capability and authored data |
| `+0x024` | Reference rotation X / pitch | Next physical trajectory |
| `+0x028` | Reference rotation Y / roll | Remains zero for ordinary bullet flight |
| `+0x02C` | Reference rotation Z / yaw | Next physical trajectory |
| `+0x030` | World position | Runtime validation and recontact distance |
| `+0x088` | Impact-data list | Current contact ownership |
| `+0x090` | Has-impacted byte | Terminal processing guard |
| `+0x094` | Projectile attachment transform | Stick/attachment state, not ordinary movement authority |
| `+0x0C8` | Runtime flags | Capability and special-state rejection |
| `+0x0CC` | Runtime power | Native effective speed input |
| `+0x0D0` | Runtime speed multiplier | Per-projectile post-bounce speed loss |
| `+0x0D4` | Native range-kill distance | Range and state validation |
| `+0x0D8` | Age | Lifetime and diagnostics |
| `+0x0DC` | Runtime hit damage | Per-projectile post-bounce damage loss |
| `+0x0F4` | Weapon condition context | Preserved, never reconstructed |
| `+0x0F8` | Source weapon | Native attribution and effects |
| `+0x0FC` | Source reference | Native attribution |
| `+0x100` | Live target | Initial exclusion |
| `+0x104` | Last actual movement vector | Incoming direction and immediate coherence |
| `+0x110` | Distance travelled | Generation state and recontact bounding |
| `+0x144` | Rock-It inventory entry | Native pickup/debris semantics |
| `+0x150` | Missile impact result | Only ordinary destroy is eligible |

The relevant BGSProjectile fields are live flags/type at `+0x60/+0x62`,
gravity `+0x64`, speed `+0x68`, range `+0x6C`, explosion `+0x84`, projectile
sound `+0x88`, impact force `+0x94`, authored rotation `+0xA4`, and bouncy
multiplier `+0xB0`.

These record values are inputs. Atom must never change a shared BGSProjectile,
weapon, or ammunition form to produce a per-shot result.

### Collision records

The common collision callback `0x009BF5A0` appends a 0x30-byte ImpactData
record under Projectile `+0x88`. Its proven fields are:

| Offset | Value |
|---:|---|
| `+0x00` | Target reference, possibly null for world geometry |
| `+0x04` | Contact position |
| `+0x10` | Contact normal |
| `+0x1C` | Havok rigid body or null |
| `+0x20` | Raw Havok material |
| `+0x24` | Hit location |
| `+0x28/+0x29` | Native processing markers |

The Missile callback `0x009B8900` runs this common ingestion and then selects
the impact outcome through `0x009B8A20`.

### Impact outcomes

The engine and checked-in enum agree on:

| Value | Name | Meaning in native Missile handling |
|---:|---|---|
| 0 | `IR_NONE` | No terminal action |
| 1 | `IR_DESTROY` | Ordinary projectile kill |
| 2 | `IR_BOUNCE` | Special physical/pickup handling |
| 3 | `IR_IMPALE` | Pins-limbs behavior |
| 4 | `IR_STICK` | Attached/stuck behavior |

An ordinary populated bullet impact selects destroy. Pins-limbs state can
select impale/stick. Form flag `0x0010` or a live Rock-It entry selects native
bounce. Atom must only consider `IR_DESTROY`; all special results retain their
complete native meaning.

## Why native `IR_BOUNCE` is not the feature

It is tempting to change the result to `IR_BOUNCE` and let FNV do the rest.
Static evidence rejects that design.

The native handler at `0x009B8C90` computes and feeds reflected physical state
to Havok, but it neither resets Projectile `+0x90` nor clears the impact list at
`+0x88`. The next ProcessImpacts entry rejects an already impacted projectile.
The selector reaches this handler from special form/pickup state, including the
Rock-It inventory entry, rather than from incidence angle and material. It also
does not read BGSProjectile `+0xB0` as a universal bullet ricochet coefficient.

Therefore native bounce is terminal object/pickup presentation. It is not a
later damaging bullet continuation. Reusing it would produce an effect that
looks plausible while failing the core gameplay acceptance criterion.

## The complete native traversal must run first

Missile ProcessImpacts wrapper `0x009B8B10` validates state and makes one direct
call at `0x009B8BD8 -> 0x009C1B70`. The direct function:

- walks ready impact records;
- selects Actor or non-Actor target handling;
- builds ActorHitData at `0x009C1E61 -> 0x009B5650` when the native target
  branch is Actor;
- commits the Actor hit at `0x009C1E96 -> 0x0089A760`;
- calls the target's native damage virtual for applicable non-Actors;
- dispatches collision effects at `0x009C2058 -> 0x009C20E0` using live weapon,
  raw material, point, normal, and rigid-body context;
- performs the native direction/effect helper; and
- marks `+0x90` before returning success.

Only after that return does `0x009B8B10` switch on `+0x150` and kill, bounce,
impale, or stick the projectile.

This ordering creates a high-quality intervention point: Atom can allow all
native first-contact behavior to complete, then return false to prevent only
the terminal switch. That is superior to manually playing an impact effect
because it also preserves destructible/non-Actor damage, script-facing native
virtuals, Atom's existing collision telemetry, and the live IMPACT chain.

The existing Rust `native::CollisionFn` has the correct machine-width ABI for
the `0x009C2058` effect call, but its last two parameter names are misleading.
The fifth stack argument is the rigid-body-derived value and the sixth is the
raw material. Implementation must rename them before policy uses the material;
using the fifth argument as material would classify a pointer-like value and
incorrectly fall through the engine's metal default.

The first policy excludes Actor targets, so the first hard-surface strike does
not become a full actor hit followed by a continuation. Actor armor deflection
would require a separate model for armor coverage, damage, limb ownership, and
injury effects.

## Movement authority: the critical engine detail

### What drives the next step

At construction, `0x009BBEF0` stores launch yaw at reference `+0x2C`, pitch at
`+0x24`, and zero roll at `+0x28`. Ordinary Missile movement is:

```text
0x009B8030 Missile update
  -> 0x009BF300 effective movement step
     -> 0x009669C0 effective speed
     -> local displacement (0, speed * dt, 0)
     -> 0x009BF370
        -> 0x0092F260 MobileObject movement and swept collision
```

The local `+Y` displacement is transformed by the reference rotation. The
cached vector at `+0x104` is not read by `0x009BF300`.

After movement, `0x009BF370` subtracts old position from new position and calls
`0x009C4E60`. That helper stores the actual displacement at `+0x104` and adds
its length to distance travelled `+0x110`. Thus `+0x104` describes the step
that just happened. It does not direct the next step.

`0x009B7010` merely copies `+0x104` to an output vector. It does not rebuild
orientation. This corrects a misleading claim found in comparison source.

### Correct redirection

FNV already contains a projectile helper at `0x009C6330` that accepts a
NiMatrix33, extracts yaw/pitch with `0x00A59400`, and sends those values through
the native reference-rotation setters. For MissileProjectile:

- vtable `+0x2C4 -> 0x00931B60 -> 0x005757D0` writes rotZ/yaw `+0x2C`; and
- `0x00931D90 -> 0x00575770` writes rotX/pitch `+0x24`.

The matrix supplied for a reflected unit direction `R` must use `R` as local
`+Y`. A stable orthonormal basis is:

```text
Y = R
X = normalize(cross(Y, world_up))
Z = cross(X, Y)
```

For a near-vertical `Y`, use a fixed horizontal fallback axis before computing
`Z`. Reject non-finite or degenerate bases rather than publishing a malformed
rotation.

The implementation should also write the reflected vector to `+0x104`, keeping
the original vector's magnitude. This keeps immediate direction readers
coherent. The next native movement replaces it with the actual continued
displacement.

Projectile `+0x94` is initialized as a NiTransform and is used by attachment
and stick paths. It is not the authority used by ordinary `0x009BF300`
movement. The ricochet continuation should not pretend that overwriting this
attachment transform redirects gameplay.

### Important comparison-source finding

A newer read-only itr-nvse source snapshot contains a proposed same-object
ricochet that reflects `+0x104` and writes the matrix at `+0x94`. It does not
update reference yaw/pitch. That source is useful corroboration that other
authors want the same feature, but the executable proves the method is
incomplete for ordinary movement. Atom must not copy it.

The same snapshot implements penetration by temporarily changing a shared
projectile-form hitscan flag while spawning a child. Atom must not copy that
pattern either. Shared records remain read-only.

## Material classification

### Native map

FNV helper `0x0058E8F0` maps the raw Havok material to ten canonical
BGSImpactDataSet slots. `0x0058E9D0` selects the authored impact-data entry at
`impact_set + 0x1C + slot * 4`.

| Slot | Canonical surface | First-slice response |
|---:|---|---|
| 0 | Stone | Ricochet candidate |
| 1 | Dirt | Native terminal |
| 2 | Grass | Native terminal |
| 3 | Glass | Native terminal; later penetration candidate |
| 4 | Metal | Ricochet candidate |
| 5 | Wood | Native terminal; later penetration candidate |
| 6 | Organic | Native terminal |
| 7 | Cloth | Native terminal; later penetration candidate |
| 8 | Water | Native terminal |
| 9 | Hollow metal | Ricochet candidate |

The complete raw map is:

```text
raw:   00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15
slot:  00 07 01 03 02 04 06 06 08 05 00 04 05 04 04 04

raw:   16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
slot:  09 09 01 00 04 04 09 09 03 09 04 04 09 09 05 05
```

The binary defaults raw values above 31 to metal slot 4. That fallback is
reasonable for selecting some visual effect instead of none. It is not enough
evidence to grant a gameplay bounce. Atom must reject an out-of-range raw
material to native terminal behavior.

### Why no per-mod surface list is required

IMPACT and content mods author entries in the live impact-data sets resolved by
the projectile's current weapon and material. Atom leaves that lookup intact.
It uses the canonical native material slot only to decide whether continuation
is possible. It does not replace the resulting decal, particle, sound, or
impact record.

A mod-added weapon automatically works when it launches a supported discrete
physical MissileProjectile with valid live values. A mod-added surface works
when its collision reports one of the known raw materials that FNV maps to an
eligible canonical slot. Unknown values fail native.

## Deterministic response policy

### Geometry

Let `D` be the normalized incoming vector and `N` the normalized contact
normal. If `dot(D, N) > 0`, negate `N` so the normal opposes incoming travel.

Define:

```text
normal_cos   = clamp(-dot(D, N), 0, 1)
grazing      = asin(normal_cos)
reflected    = normalize(D - 2 * dot(D, N) * N)
```

`grazing` is measured from the surface plane:

- `0 degrees` is nearly tangent;
- a small angle is a plausible deflection candidate; and
- `90 degrees` is head-on and terminal.

Normal orientation is corrected before the calculation because collision
providers do not always guarantee which side a normal faces. Every operand and
result must be finite. Zero-length vectors fail native.

No random chance is needed. Given the same projectile state and contact, the
outcome is the same. This makes balancing, replay reasoning, telemetry, and
mod interoperability substantially clearer than an opaque global percentage.

### Conservative initial tuning envelope

FNV has no per-projectile mass, construction, jacket, hardness, or physically
meaningful velocity unit. A universal real-world model would therefore be
false precision. The initial coefficients are gameplay hypotheses and must be
versioned as policy, not advertised as measured ballistics.

A conservative implementation starting point is:

| Material | Maximum grazing angle | Speed retention, threshold to tangent |
|---|---:|---:|
| Stone | `12 degrees` | `0.45 .. 0.60` |
| Metal | `20 degrees` | `0.55 .. 0.75` |
| Hollow metal | `18 degrees` | `0.50 .. 0.68` |

At the material threshold use the lower retention; toward a tangent contact,
interpolate smoothly toward the upper retention. Then derive later-hit damage
retention from the square of speed retention:

```text
t = clamp(grazing / material_limit, 0, 1)
speed_keep = lerp(max_keep, min_keep, t)
damage_keep = clamp(speed_keep * speed_keep, 0.20, 0.60)
```

Apply the results multiplicatively:

```text
Projectile.speed_multiplier *= speed_keep
Projectile.runtime_damage    *= damage_keep
```

The exact table is intentionally small and material-based. It does not know
which mod supplied the weapon. Multiplication preserves the balance already
present in the live runtime values. A mod that raises or lowers weapon damage,
condition effects, ammunition effects, perk results, or projectile speed keeps
that relative choice after the bounce.

The attenuation has gameplay purposes beyond visual plausibility:

- the redirected bullet remains dangerous but usually less decisive;
- a shallow hard-metal bounce retains more momentum than a threshold stone
  strike;
- a second damaging contact cannot equal the original shot by default; and
- one-bounce plus loss prevents pinball combat and runaway work.

These values should be accepted or adjusted from one bounded scenario after
the implementation proves trajectory and damage ownership. They should not be
tuned from repeated blind playtests before the engine path works.

### Complete admission matrix

All conditions are required:

| Category | Required condition |
|---|---|
| Generation | Present in Atom's live bounded launch table with current generation |
| Capability | Discrete physical MissileProjectile |
| Form | No explosion, native special bounce, pickup/debris, or unsupported type semantics |
| Launch | Real-time, no VATS, always-hit, or live target |
| Outcome | Current `+0x150 == IR_DESTROY` |
| Target | Native traversal does not select the Actor branch |
| Impact | First ready record with finite point and normal |
| Material | Raw `0..31`, canonical stone/metal/hollow metal |
| Direction | Finite nonzero incoming `+0x104` |
| Energy | Finite positive effective speed, `+0xD0`, and `+0xDC` |
| Geometry | Finite reflection and grazing within material limit |
| Budget | Bounce count is zero |
| Ownership | Direct predecessor is proven vanilla common traversal |

There is no plugin-name check and no exception list. If a future mod changes a
capability while leaving the seam valid, Atom observes the final live state. If
it takes ownership of impact policy, Atom yields through hook composition.

## Continuation transaction

### Hook seam

Atom should hook the rel32 call at `0x009B8BD8`, not the
MissileProjectile `+0x314` vtable slot.

The immutable fingerprints around the mutable call are:

```text
before 0x009B8BCD:
  0F B6 55 FE 85 D2 74 0B 8B 4D F4

after 0x009B8BDD:
  88 45 FF 0F B6 45 FF 85 C0 0F 84 81 00 00 00
```

The direct ABI is simply:

```text
u8 __thiscall common_impacts(Projectile* projectile)
ECX = projectile
AL  = result
```

The full callee does not consume EDI or ESI as input. Those register claims
belong to a different outer-vtable context in comparison code.

At deferred installation, Atom must:

1. validate the immutable bytes while excluding the mutable E8 displacement;
2. capture the current rel32 target;
3. install transactionally with the other Ballistics hooks;
4. enable policy mutation only when the captured target is vanilla
   `0x009C1B70`; and
5. chain an unknown direct owner once with no Atom continuation.

This rule is conservative but deterministic. Atom cannot safely run a
pre-terminal continuation around a direct predecessor whose damage, list,
return, and lifetime semantics are unknown.

### Per-impact sequence

The detour sequence should be exact:

1. Read no more than the first ready ImpactData record.
2. Reject continuation when a second ready record is already present; one
   native sweep must not commit several contacts before a first-surface bounce.
3. Snapshot only value data: generation, target token, point, normal, raw
   material, incoming vector, distance, damage, speed multiplier, and outcome.
4. Evaluate all preconditions without mutation.
5. Call the captured common-impact predecessor exactly once in every ordinary
   path.
6. If the candidate was ineligible, return the predecessor result unchanged.
7. If the predecessor returned false, return false without mutation.
8. Revalidate the correlated generation and required post-state.
9. Compute the reflected unit direction and finite local-`+Y` basis.
10. Send the basis through native `0x009C6330` to publish yaw/pitch.
11. Store reflected `+0x104` with the incoming vector magnitude.
12. Multiply live `+0xD0` and `+0xDC` by the bounded retentions.
13. Reset `+0x90` to zero.
14. Clear impact records through the current vtable `+0x2FC` entry.
15. Publish bounce count and recontact state for the same generation.
16. Return false so `0x009B8B10` skips its terminal result switch.

No source, weapon, condition, form, cell, tracer, or attribution field changes.
No child projectile is spawned. No native hit is manually synthesized.

### Immediate same-surface recontact

A sweep starting exactly at a contact can report the same plane again even
when the new direction points out of it. Moving the reference by an arbitrary
epsilon risks bypassing thin geometry and creates a second collision system.
The first implementation should keep movement native and use one bounded
duplicate escape instead.

State retained after a successful bounce:

- projectile generation;
- bounce count;
- raw material and target token;
- contact point and oriented normal;
- distance travelled at the bounce; and
- whether the one duplicate escape was consumed.

Before the normal predecessor, a new record may be classified as the same
immediate outward contact only when all of these match within strict finite
tolerances and almost no additional distance was travelled. Atom may clear
that record once without another effect, damage application, or attenuation.
A second repeat falls native. A later contact elsewhere on the same reference
must not be suppressed.

Because world geometry can have a null target reference, the key cannot rely on
FormID or pointer alone.

## Damage and balance ownership

Native effective speed helper `0x009669C0` combines authored projectile speed,
runtime power `+0xCC`, runtime speed multiplier `+0xD0`, and native
interpolation policy. Atom should call this helper for validation and modify
only `+0xD0`.

Native damage getter `0x00885D70` returns runtime `+0xDC`. Hit builder
`0x009B5650` places it into ActorHitData before native protection, armor,
difficulty, perks, and final hit handling. Atom modifies only this future input.

This answers the mod-balance problem:

- no damage is copied from a vanilla weapon table;
- no ammunition or caliber database becomes stale;
- no mod-added weapon needs an Atom patch;
- current weapon condition and launch-time perk/ammunition results remain;
- NPC and player rounds retain their own native source context; and
- armor, limbs, criticals, scripts, and difficulty still see a normal later
  native hit.

Ricochet is not the place to solve the whole damage model. It supplies one
bounded, explainable loss to an already resolved live projectile. A future
terminal-energy phase can work at the complete ActorHitData seam after this
continuation is proven.

## Compatibility with the active mod stack

The active profile currently contains Bullet Trails, Kyu's Ballistics Fixed -
TTW, Improved Bullet Tracers, IMPACT Compatibility Edition, IMPACT, itr nvse
config, and itr nvse. These names are audit evidence only; production code must
not branch on them.

| Owner | Observed interaction | Atom contract |
|---|---|---|
| Kyu's Ballistics | Edits live projectile behavior/records | Read final form and runtime values; multiply, never overwrite with vanilla tables |
| Improved Bullet Tracers | Edits projectile tracer/model presentation | Keep the same projectile; native next update follows redirected yaw/pitch |
| Bullet Trails | Can create visual trail children around canonical launch | Only the launch-correlated logical projectile receives gameplay state |
| IMPACT | Owns authored impact sets/effects | Native traversal and current `0x009C2058` chain run once before continuation |
| itr nvse | Installed plugin has near-miss and impact-data routes; future builds may own outer impact policy | Hook inside vanilla terminal traversal so an outer owner keeps priority |
| Unknown record mods | May add weapons, ammo, projectiles, materials | Capability and live-value classification; unknown semantics fail native |

The installed itr-nvse artifact has SHA-256
`a7203e78459cf273957b38df9802e112e65c4129b2a37cbe3d059f4b56268b34`.
The current xNVSE log identifies version 20101. Its strings expose OnNearMiss
and OnImpactDataSpawn routes but not named ricochet/penetration/ProcessImpacts
events. This does not justify assuming that every future build behaves the
same, which is why the hook design composes structurally.

### Outer-owner priority

If another mod replaces Missile `+0x314` ProcessImpacts:

- if it handles the impact without calling vanilla, Atom is not entered;
- if it chains the vanilla wrapper for an ordinary impact, Atom is entered at
  the inner direct call;
- Atom never replaces or restores that outer slot; and
- no DLL detection, load-order check, or mod-specific patch is required.

If another owner replaces the exact direct call at `0x009B8BD8` before Atom,
Atom captures and chains it but disables ricochet mutation. Correct native
fallback is more important than guessing the owner's postconditions.

## State, lifetime, and performance

The current Ballistics pool is a 2048-entry bounded open-addressed table with a
32-probe limit and atomic generation publication. The accepted Phase 1 Proton
session observed 251 correlated launches and first contacts, no overflow, and
same-address reuse across generations. Raw runtime evidence is retained at
`.reports/atom-ballistics-phase1-2026-08-16.log`.

Ricochet should extend that ownership model rather than create a second map.
Policy state must be admitted whenever ricochet is enabled, not only when
telemetry is enabled. The current launch path returns before pool insertion
when diagnostics are off; implementation must separate required policy state
from optional diagnostic sampling.

Hot-path constraints:

- fixed capacity;
- no heap allocation;
- no blocking lock;
- no file or configuration I/O;
- no raycast or extra collision query;
- no per-impact log line;
- no retained engine pointer beyond the live generation token;
- finite scalar validation before every division, square root, trigonometric
  operation, or engine write; and
- predecessor called exactly once unless the record is the single proven
  outward duplicate, where the already resolved first impact owns the effect.

The runtime session observed one callback thread, but the design must not turn
that observation into an undocumented threading guarantee. Reuse the existing
atomic publication and lifecycle-clear contract.

## Failure behavior

Ricochet is optional; native combat is not. Every failure must preserve the
complete predecessor and terminal path.

Native fallback is required for:

- fingerprint mismatch;
- unknown direct-call predecessor;
- missing pool or pool overflow;
- stale/reused projectile address;
- lifecycle clear race;
- null or implausible engine pointer;
- non-finite position, normal, direction, speed, damage, or range;
- zero-length normal/direction or degenerate basis;
- raw material above 31;
- unsupported canonical material;
- Actor target or special impact result;
- unsupported subtype or launch semantics;
- bounce budget exhaustion;
- predecessor returning false; or
- post-predecessor state no longer matching the snapshot.

Installation failure disables only Atom ricochet and emits one stable-tagged
error explaining that native terminal impacts remain. Runtime degeneracy is a
bounded counter in the summary, not a log flood.

## Configuration ownership

The first implementation needs one laconic MCM setting: `Ricochet`. It should
be off only when the user explicitly disables the gameplay feature; all
unsupported records already fail native automatically.

Do not expose per-weapon, per-ammo, per-mod, or all-ten-material tables. They
would transfer engine-policy maintenance to the user and undermine automatic
balance. The small material response table belongs to the versioned native
policy and can be revised from evidence.

If a later user-facing intensity option is justified, it should scale the
bounded retention envelope without changing capability admission, native
ownership, or the one-bounce cap. MCM event application must use the existing
`MCMExtUpdate` publication route after INI save. No configuration parsing or
lock may enter the impact hot path.

## Proposed source ownership

Implementation should remain inside `atom` and reuse established Ballistics
boundaries:

| File | Ownership |
|---|---|
| `atom/src/ballistics/native.rs` | Audited offsets, impact views, direct ABI, native rotation/clear/effective-speed helpers |
| `atom/src/ballistics/ricochet.rs` | Pure material map, geometry, deterministic policy, attenuation, and state transition types |
| `atom/src/ballistics/pool.rs` | Generation-owned bounce/recontact state and policy admission independent of telemetry |
| `atom/src/ballistics/hooks.rs` | Fingerprinted direct hook, exactly-once predecessor sequencing, native continuation transaction |
| `atom/src/ballistics/telemetry.rs` | Bounded counters and one summary, never policy ownership |
| `atom/tests/ballistics_behavior.rs` | Observable pure-policy and state-machine acceptance tests |
| `docs/atom_ballistics_ricochet_research.md` | Durable engine and feature contract |

Keep APIs narrow. Any public policy types or functions must receive module
documentation and Rust doc comments. Unsafe functions must state pointer,
lifetime, thread, and predecessor requirements. Comments should explain why a
native order or fallback is required, not narrate obvious writes.

No startup callback, helper DLL, shared form patch, or new pre-DeferredInit
owner is needed. Hook installation remains at Atom's established deferred safe
boundary.

## Test plan

### Pure behavior tests

Tests should exercise shipped logic, not source text:

- all 32 raw materials map to the proven canonical slots;
- raw values above 31 reject gameplay even though the visual helper defaults
  them to metal;
- only stone, metal, and hollow metal are initial candidates;
- normal flipping makes opposite-facing representations equivalent;
- grazing angle is zero at tangent and 90 degrees at head-on;
- reflection preserves unit length and reverses the normal component;
- degenerate, NaN, and infinite inputs reject without mutation;
- material thresholds are exact at both sides of every boundary;
- speed retention is bounded and monotonic from threshold to tangent;
- damage retention derives from the bounded square and never exceeds the
  configured envelope;
- matrix local `+Y` aligns with the reflected vector, including vertical
  fallback;
- direction to native yaw/pitch and back agrees with Atom's established FNV
  `+Y`-forward convention;
- one successful bounce exhausts the gameplay budget;
- one immediate outward duplicate can clear without a second event;
- a second duplicate or later genuine same-reference contact is terminal;
- reused projectile addresses cannot inherit prior-generation bounce state;
- overflow and lifecycle races select native fallback; and
- player and NPC sources receive identical response policy.

### Hook-boundary tests

Use test doubles for the typed ABI and real transition logic:

- ineligible impact calls predecessor once and returns its byte unchanged;
- eligible candidate whose predecessor returns false does not mutate;
- successful eligible traversal applies native first-contact work once, then
  publishes continuation and returns false;
- actor and special outcomes cannot continue;
- unknown direct predecessor disables mutation while preserving the call;
- clear failure or invalid post-state preserves terminal behavior;
- policy does not read telemetry enablement; and
- collision effects are not manually duplicated after native traversal.

An artifact test may validate shipped MCM text and packaged configuration. It
must not parse Rust source as a substitute for behavior.

### Required build evidence after implementation

Code changes require:

```bash
cargo test --target i686-pc-windows-gnu -p atom
cargo build --release --target i686-pc-windows-gnu -p atom
git diff --check
```

Run the full supported release build if shared build inputs or cross-crate code
change. Compilation alone does not prove runtime projectile continuation.

## One bounded runtime acceptance session

The user should not need endless exploratory playtests. The implementation
must aggregate enough evidence for one deliberate session.

The summary should report at least:

- supported correlated physical launches;
- hard-material candidates by canonical slot;
- rejection counts by stable reason;
- successful continuations;
- immediate duplicates cleared and duplicate budget failures;
- post-bounce native contacts and ActorHitData builds;
- bounce-to-later-hit correlation;
- invalid values, stale generations, lifecycle races, and pool overflow;
- player versus NPC continuations; and
- predecessor addresses and whether mutation was admitted.

The bounded playtest matrix is:

1. Shallow player shots against one metal, one hollow-metal, and one stone
   surface visibly continue and terminate at a later surface.
2. One redirected round hits an actor or damageable object later; native damage
   is lower than the same direct shot and attribution is correct.
3. Head-on shots at those hard surfaces remain terminal.
4. Dirt, wood, glass, organic, cloth, and water remain terminal.
5. One supported mod-added firearm uses the same automatic policy without a
   patch.
6. An NPC fires shallow hard-surface shots and receives the same response.
7. IMPACT's authored first and terminal effects each appear once at their real
   contacts.
8. Improved tracer/trail presentation follows or at minimum does not alter the
   logical redirected collision.
9. Explosives, VATS, grenades, beams, flames, and special pickup/pins-limbs
   projectiles remain native.
10. Save/load or main-menu lifecycle clear leaves no inherited bounce state.

The feature is accepted only when logs prove the same generation continued and
the later native hit path ran. A spark, sound, transform write, or absence of a
crash is not sufficient.

## Proven facts, design decisions, and open work

### Proven

- Collision records contain target, point, normal, body, material, and hit
  location.
- The native material map and ten canonical impact slots are known.
- Ordinary Missile impact selects destroy; native bounce is a special terminal
  path.
- `0x009B8BD8` is the only direct executable call to common impact traversal.
- Common traversal owns Actor/non-Actor damage and live collision effects, then
  sets has-impacted before the wrapper kills the projectile.
- Clear-impact-data frees the list but does not reset has-impacted.
- Ordinary movement uses reference yaw/pitch and local `+Y` displacement.
- `+0x104` is written from actual movement after the step.
- `0x009B7010` only reads `+0x104`.
- Native `0x009C6330` maps a matrix to the reference yaw/pitch setters.
- Runtime `+0xD0` controls effective speed and `+0xDC` feeds later hit damage.
- The accepted Phase 1 session correlated all first contacts without overflow.

### Design decisions

- Implement gameplay ricochet before near-pass audio.
- Run native first-contact traversal before continuation.
- Hook the inner direct call, not the outer Missile vtable slot.
- Continue the same object and never mutate shared forms.
- Admit hard known materials only and use one deterministic bounce.
- Exclude actors and every special projectile family initially.
- Apply bounded multiplicative loss to live speed and damage.
- Preserve outer-owner priority and fail native on unknown direct ownership.
- Keep camera and view behavior entirely outside the feature.

### Open until implementation evidence

- The final conservative angle/retention table may need one measured adjustment
  after trajectory correctness is proven.
- The compiled Rust layout, detour, and native helper calls require tests and a
  release build.
- Proton must prove a later native hit on the redirected generation.
- Visual tracer orientation after the first continued update remains runtime
  acceptance, not a reason to take presentation ownership.
- Penetration, actor armor deflection, multiple bounces, VATS, explosives, and
  special projectile families require separate research and must not be
  enabled by weakening admission.

## Implementation order

1. Add pure material, geometry, attenuation, and transition tests.
2. Extend the existing bounded generation slot with policy and recontact state;
   decouple this admission from telemetry.
3. Add audited impact views and native helper ABIs in `native.rs` with layout
   tests.
4. Add and fingerprint the `0x009B8BD8` hook, initially in observe-only mode.
5. Prove exactly-once predecessor and post-state in tests.
6. Enable the strict stone/metal/hollow-metal one-bounce transaction.
7. Add bounded diagnostics and the laconic MCM setting through the established
   event publication route.
8. Run Atom tests, the supported release build, diff checks, and artifact
   checks once.
9. Perform the single bounded Proton acceptance matrix above.
10. Adjust only the small material envelope if evidence shows the gameplay loss
    is too weak or too strong; do not broaden unsupported families as tuning.

This sequence delivers a gameplay subsystem, not a cosmetic approximation,
while preserving FNV and mod-added content as the source of record balance,
damage, attribution, and authored impact presentation.

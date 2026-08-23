# Atom Ballistics ricochet engine contract

Status: runtime accepted by the repository owner on the supported Proton/FNV
setup. Child-projectile continuation, full known-material and angle coverage,
energy-depleting chains, and per-material MCM policy are active.

Date: 2026-08-22.

## Purpose and player contract

Atom gives deterministic, energy-depleting ricochets to an eligible discrete
projectile that strikes known world geometry at any finite incidence. Every
contact keeps FNV's complete native impact effects and non-Actor target work. A
fresh native child then begins beyond the completed surface contact with
reduced speed and damage. A confirmed child may repeat the same transaction
while its predicted retained speed and damage remain above the continuation
floors. Movement, collision, damage, attribution, tracer, range, and lifetime
remain engine-owned.

The initial policy supports player and NPC projectiles without FormID, weapon,
ammunition, caliber, or mod allowlists. It admits ordinary non-explosive
MissileProjectile instances on every known canonical material from 0 through
90 grazing degrees. It rejects Actor targets, special impact outcomes, VATS and
targeted launches, native bounce, explosive and non-discrete projectile
families, invalid geometry, unknown raw material, depleted energy, unsupported
critical child seams, and every incomplete native contract.

The acceptance boundary is an outward first movement step by each child,
followed by either a later ordinary native hit or another energy-admitted child.
A reflected impact effect or a successful spawn alone is not acceptance.

## Root cause of the failed implementation

The first implementation tried to continue the object whose native impact
lifecycle had already become terminal. It ran the common impact predecessor,
rewrote that object's yaw and pitch, cached direction, speed, and damage, reset
`hasImpacted`, cleared its impact list, and returned zero from the callsite at
`0x009B8BD8`.

The retained runtime failure in
[`atom-2026-08-21-ricochet-failure.log`](../.reports/atom-2026-08-21-ricochet-failure.log)
proved that publication was not the problem. In that run all 85 candidates were
published, reference yaw/pitch remained within 0.5 degrees of the reflection at
the next update entry, and all 85 completed movement steps were non-outward.
The later 2026-08-22 owner log reproduced the same boundary with four of four
published candidates and four non-outward first steps. The exact downstream
native writer responsible for the old object's step remains unresolved; it is
not required by the corrected design.

The supplied read-only comparison source
`.research/FNV-Penetrate-And-Ricochet-main` closes the architectural gap. Its
working path does not continue the impacted object. It backtracks two units,
validates at least 32 units of outbound clearance, calls FNV's projectile spawn
routine for a child, and lets the parent retain its terminal impact result.
Atom's real root cause was therefore the same-object continuation architecture,
not configuration, material mapping, reflection math, or failure to publish the
new rotation.

The first child-projectile candidate never reached this path in the retained
[`2026-08-22 owner run`](../.reports/atom-2026-08-22-child-hook-install-failure.log).
Atom logged a fingerprint mismatch at `0x009BDC8F`, followed by zero launch,
collision, update, impact, and ricochet callbacks. Executable disassembly proves
that the expected immutable pre-muzzle sequence begins at
`0x009BDC97`; `0x009BDC8F` begins an earlier native call. The eight-byte address
error was introduced with the synthetic-child muzzle hook. Because the complete
base fingerprint set is validated before any Ballistics hook is initialized,
that single mismatch kept the entire subsystem native despite its enabled
configuration. The correction moves only this fingerprint boundary to
`0x009BDC97`; the mutable call at `0x009BDCA2` remains excluded and predecessor
chaining is unchanged.

The next retained owner run proved a separate admission defect after hook
installation succeeded. In
[`atom-2026-08-22-launch-owner-gate-failure.log`](../.reports/atom-2026-08-22-launch-owner-gate-failure.log),
Atom observed 152 player launches and common-impact calls, 136 measurable stone
or metal contacts, and 41 hard contacts at no more than 10 degrees. It produced
zero candidates because all 152 impacts were rejected as ownership failures.
The common-impact and child-presentation predecessors were the audited native
targets, while the ordinary weapon-launch predecessor was `0x0A7DE850`.

That launch predecessor is not a child-spawn dependency. Atom already chains
it for the original weapon shot, while the reflected continuation deliberately
calls the audited native spawn routine at `0x009BCA60`. Requiring the ordinary
launch owner itself to be vanilla therefore disabled a safe child path and made
ricochet depend on unrelated hook load order. The correction removes launch
ownership from mutation admission without bypassing the launch owner for any
ordinary shot.

The corrected owner-independent build then passed the physical gameplay
boundary. The retained
[`limited-coverage baseline`](../.reports/atom-2026-08-22-limited-coverage-energy-chain-baseline.log)
recorded 21 candidates, 14 published children, 13 outward first steps, and 14
later contacts more than 32 units from their parent contacts. The owner also
visually confirmed ricochets from low-angle metal and concrete impacts.

That run proved the remaining absence was policy, not another native-hook
failure: 27 first contacts were rejected only by the old angle ceilings, one
dirt contact was rejected by hard-material-only admission, and every one of the
14 child contacts was rejected by the fixed bounce budget. Six admitted child
spawns also failed the aggregate fresh-state check. The expanded implementation
therefore removes the angle/material/count limits and instruments each child
state invariant separately; it does not alter the proven hook or parent-impact
architecture.

## Executable and evidence

The native contract is for the supported Fallout: New Vegas 1.4.0.525 PE32
executable at `fnv_reverse/FalloutNV.exe`.

Primary binary evidence is retained in:

- [`fnv_projectile_ricochet_contract.txt`](../analysis/radare2/output/gameplay/fnv_projectile_ricochet_contract.txt)
- [`fnv_combat_contract.txt`](../analysis/radare2/output/gameplay/fnv_combat_contract.txt)
- [`atom_combat_engine_contract.md`](atom_combat_engine_contract.md)

The 2026-08-22 radare2 audit reconfirmed these additional contracts:

| Address | Contract |
|---:|---|
| `0x00458440` | `TES::RayCast(RayCastData*, bool)`; `thiscall`, returns the first hit object or null |
| `0x009BCA60` | Cdecl projectile spawn with the 14-argument ABI already used by Atom's launch hook |
| `0x009BC8F0` | Projectile terminal handler; `thiscall` on one live projectile |
| `0x009BDC97` | Immutable instruction boundary immediately before the synthetic-child muzzle call |
| `0x009BDCA2` | Direct call to `0x009C2FF0` during projectile initialization for muzzle presentation |
| `0x009B8BD8` | Direct common-impact call to `0x009C1B70` before the outer Missile impact-result switch |

The checked-in xNVSE layouts prove runtime base form at `+0x20`, parent cell at
`+0x40`, and the remaining Projectile fields below. The comparison source is
corroboration for the successful child lifecycle and supplies the exact
`RayCastData` layout and loaded-endpoint behavior; executable disassembly remains
the authority for called addresses and ABIs.

## Native state and ownership

| Offset | Field | Atom use |
|---:|---|---|
| `+0x020` | Base projectile form | Child spawn and capability validation |
| `+0x024/+0x02C` | Pitch/yaw | Child launch authority and first-step evidence |
| `+0x030` | Position | Backtracked ray origin |
| `+0x040` | Parent cell | Child spawn ownership |
| `+0x088` | Impact list | Single ready-contact admission |
| `+0x090` | Has impacted | Ordinary pre/postcondition validation |
| `+0x0C8` | Runtime flags | Flight evidence; never copied to the child |
| `+0x0CC` | Power | Scalar transfer |
| `+0x0D0` | Speed multiplier | Attenuated scalar transfer |
| `+0x0D4` | Base range | Scalar transfer |
| `+0x0D8` | Lifetime/age | Scalar transfer |
| `+0x0DC` | Hit damage | Attenuated scalar transfer |
| `+0x0F4` | Weapon condition | Scalar transfer |
| `+0x0F8/+0x0FC` | Source weapon/reference | Native spawn and attribution validation |
| `+0x100` | Live target | Must be null |
| `+0x104` | Completed movement vector | Incoming direction and first-step evidence |
| `+0x110` | Distance travelled | Scalar transfer and follow-up evidence |
| `+0x140` | Flight target | Diagnostics only; never copied |
| `+0x144` | Rock-It entry | Must be null |
| `+0x150` | Missile impact result | Only ordinary destroy is eligible |

Atom never mutates a shared BGSProjectile, weapon, ammunition, impact-data, or
material form. Native spawn owns every child reference, list, flag, render
object, collision object, and auxiliary pointer. Atom transfers only the
audited scalar fields listed above. It does not copy the parent's impact list,
runtime flags, cached direction, flight target, Rock-It entry, render state, or
opaque pointers.

## Child transition

The common-impact detour performs this bounded transaction:

1. Sample the tracked parent, single ready impact, material, incoming completed
   movement, native impact result, and launch context.
2. Build the reflection and predicted child energy. Require retained effective
   speed of at least 6400 and retained damage of at least 6.
3. Reserve an original `available` generation, an outward-confirmed child, or
   a published/probing child whose current contact proves positive completed
   distance, positive point separation, and travel away from its prior surface.
   Retain the prior state for exact rollback.
4. Call the captured common-impact predecessor exactly once.
5. Require its nonzero result, ordinary destroy state, world target, unchanged
   source and scalar values, and the still-reserved generation.
6. Set ray start to `position - normalize(incoming) * 2` and ray end to
   `start + normalize(reflection) * 1024`.
7. Call `0x00458440` with FNV's 0xB0-byte `RayCastData`, player collision group,
   and layer 6. Require a finite fraction whose clearance is strictly greater
   than 32 units. A no-hit result is accepted only when FNV's current interior
   or loaded exterior grid proves the endpoint is loaded.
8. Set the child origin to `start + normalize(reflection) * 32` and derive its
   native yaw/pitch from that reflected unit vector.
9. Open a thread- and form-scoped child policy, then call `0x009BCA60` with the
   parent's base form, source, source weapon, and cell. Hitscan forms are made
   physical by the existing native initializer decision hook; physical forms
   remain physical.
10. Suppress only the matching synthetic child's muzzle call at `0x009BDCA2`.
   Ordinary launches always chain their captured predecessor.
11. Validate the fresh object's form, cell, source, weapon, empty impact state,
    null target/Rock-It state, and physical-policy result. Transfer the audited
    scalar state with speed and damage retention.
12. Atomically replace the parent observation with the child token, including
    safe replacement of a stale reused child address. Publish the original
    contact, expected reflected direction, and incremented bounce depth for the
    one first-step probe.
13. Return the original common-impact result unchanged. The outer native switch
    terminates the parent normally; the child enters ordinary native movement.

If a spawned child cannot be validated or published, Atom calls the proven
native terminal handler once for that child and leaves the parent's complete
native terminal result intact.

## Reflection and energy policy

Normals are normalized and oriented against incoming travel. Grazing angle is
measured from the surface plane. The reflected unit vector is
`I - 2 * dot(I, N) * N`; native launch yaw is `atan2(x, y)` and pitch is
`asin(-z)`, matching FNV's local `+Y` convention.

Every known canonical material with configured energy above zero is eligible
through 90 degrees. The former maximum angles mark where attenuation reaches
its minimum; they no longer reject the contact. MCM owns an integer retained
grazing-energy percentage `P` in `0..=75` for every material:

| Material | Default `P` | Attenuation saturation | Minimum speed ratio |
|---|---:|---:|---:|
| Stone | 36 | 12 degrees | 0.45 / 0.60 |
| Dirt | 18 | 12 degrees | 0.45 / 0.60 |
| Grass | 15 | 12 degrees | 0.45 / 0.60 |
| Glass | 12 | 12 degrees | 0.45 / 0.60 |
| Metal | 56 | 20 degrees | 0.55 / 0.75 |
| Wood | 20 | 12 degrees | 0.45 / 0.60 |
| Organic | 0 | 12 degrees | 0.45 / 0.60 |
| Cloth | 0 | 12 degrees | 0.45 / 0.60 |
| Water | 10 | 12 degrees | 0.45 / 0.60 |
| Hollow metal | 46 | 18 degrees | 0.50 / 0.68 |

At zero-degree grazing incidence, damage retention is `P / 100` and speed
retention is `sqrt(P / 100)`. The angle curve interpolates speed retention
toward the table's minimum ratio, after which damage retention is the square
of the resulting speed retention. There is no minimum damage-retention clamp;
therefore a low configured value cannot silently retain more energy than the
menu requests. `P = 0` is an explicit material-disabled terminal result.

The solid defaults preserve the accepted Atom response after converting its
former grazing speed values to energy. Lower soft, brittle, and liquid values
are conservative Fallout gameplay profiles. The supplied comparison mod's
material percentages remain research evidence for repeat-bounce chance only;
Atom does not relabel that probability as energy.

Before native spawn, predicted child effective speed must remain at least 6400
and predicted child damage must remain at least 6. These defaults are the
explicit live speed and damage floors used by the supplied working comparison
implementation. They are FNV gameplay-energy proxies, not a kinetic-energy
claim; no proven projectile mass is available.

There is no fixed bounce limit and no repeat-bounce random draw. Because speed
retention never exceeds `sqrt(0.75)` and damage retention never exceeds 0.75,
each finite chain strictly loses both values and reaches an energy floor.
Non-finite, degenerate, non-positive, unknown-material, and disabled-material
inputs fail closed.

## Compatibility and lifecycle

Every ordinary weapon launch calls the currently captured predecessor exactly
once. Its address, module, version, and load-order position do not participate
in ricochet admission. The child instead starts at `0x009BCA60` with Atom's
reflected transform; applying an aim or weapon wrapper again would reinterpret
the continuation as a new weapon shot.

Ricochet mutation still requires the captured common-impact and synthetic
muzzle predecessors to be the verified native targets. Atom depends on the
former's terminal-parent contract and suppresses the latter for the matching
synthetic child. Unknown owners at either critical seam cannot be assumed to
preserve those semantics. This is a capability boundary, not a mod allowlist:
Atom performs no DLL-name, version, FormID, or load-order classification.

The observation pool is fixed-capacity, allocation-free in hooks, and keyed by
opaque runtime address plus generation. Callback flags are generation-tagged,
so a callback that loses an address-reuse race cannot mark the replacement.
Its transition is:

```text
parent available -> parent reserved -> child published -> child probing
                                      |             \-> failed / native terminal
                                      \-> outward confirmed
                                      |             \-> energy depleted / native terminal
                                      \-> outward contact during update
                                                    \-> reserved -> next child published ...
```

The parent key is removed only when the child key is published. Lifecycle clear
races remove transactional state. Reservation records whether the parent was
available, published, probing, or confirmed so any failed transaction restores
the exact prior state. When a nested contact publishes the next child before
the enclosing Missile update returns, the consumed parent's generation-owned
reservation completes that first-step probe without a false state race. The
minimal published-to-confirmed transition runs whenever ricochet is enabled;
tracing only adds counters and therefore cannot control multi-bounce gameplay.
No impact is cleared and no duplicate-effect exception is needed because every
spawn requires a clear outbound origin.

The eligible-impact hot path adds one stack-only native raycast and one native
projectile spawn. Rejected impacts do bounded arithmetic and atomic operations.
There is no heap allocation, blocking lock, file I/O, logging, or form mutation
inside the hook.

## Failure behavior

Every missing or ambiguous fact preserves the parent's native result. Telemetry
separates clearance, child spawn, child policy, each fresh-child invariant, and
pool-transfer failures from unknown material, configured material disablement,
invalid energy, speed depletion, damage depletion, first-step state, critical
admission, and postcondition rejection. It also aggregates material, angle,
energy, and chain-depth coverage.
Normal launch behavior remains active even when ricochet mutation is
observe-only.

## Qualification and regression gate

Offline qualification executes the production reflection/path and energy
functions, every canonical material and finite angle boundary, runtime and
raycast layouts, nested policy scope, stale-address child rekey, generation-safe
callback races, confirmed-child reservation and rollback, first-update child
transfer, full Atom test suite, and supported 32-bit release build. Static
qualification cannot prove expanded FNV gameplay movement or damage.

Release qualification additionally requires owner gameplay acceptance using
this runtime matrix:

- installation with a non-native ordinary launch predecessor and zero
  critical-admission rejections;
- candidates and publications across shallow, medium, and steep angles and at
  least one newly admitted non-hard material;
- exact child-state subreason evidence for every rejected fresh child;
- at least two sequential outward-confirmed children from an energy-sufficient
  round under suitable geometry;
- no second muzzle flash at the ricochet point;
- the first native impact effect exactly once;
- decreasing live speed and damage at every depth; and
- an explicit speed, damage, clearance, or supported-state termination reason.

Configuration acceptance additionally requires all ten MCM sliders to persist
through `MCMExtUpdate`, one enabled material to stop at zero, and the same
material to resume eligible continuation after a nonzero menu-close update.

Owner gameplay confirmation closes the runtime gate. Any later change to the
native path, material policy, configuration layout, or startup footprint
reopens the applicable matrix before release.

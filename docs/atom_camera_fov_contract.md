# Atom camera FOV ownership contract

Status: implementation complete; configuration, tangent scaling, and frustum
math are offline-tested. The required Proton/BaseObjectSwapper load-to-gameplay
run and the visual/ADS matrix below remain unexecuted and are the final gate.

## Scope

Atom exposes three independent base-angle targets:

| Setting | MCM key | `0` behavior |
|---|---|---|
| First-person world camera | `Fov:fFirstPerson` | native |
| Third-person world camera | `Fov:fThirdPerson` | native |
| Hands/weapon camera | `Fov:fViewmodel` | follow the effective first-person angle |
| Pip-Boy/terminal camera | `Fov:fPipboy` | native |

Non-zero values are clamped to `1..=150` degrees. Negative values are rejected
as invalid configuration; non-finite values are rejected. MCM Extender remains
the only writer of `Data/config/Atom/Atom.ini`. The deferred camera callbacks
consume one seqlock snapshot and never parse the INI.

The target is the desired native hip-fire lens for that camera, not a fixed
replacement for every live angle. Atom learns each player field's widest normal
(hip-fire) value as its base and computes

```text
scale   = tan(target / 2) / tan(hip_fire_base / 2)
new_fov = 2 * atan(tan(live_fov / 2) * scale)
```

so at hip fire the rendered angle is exactly the configured target, while
native aim, scope, POV-transition, and compatible external FOV changes keep
their relative zoom. A zero target returns the original float bit-for-bit.

The learned base matters because gameplay mods, kill cameras, and special
cameras can transiently change either the `fDefault*` settings or the live
`+0x670`/`+0x674`/`+0x678` fields. Only normal gameplay can widen a base, so a
menu, ADS frame, transition, or special camera cannot redefine the configured
lens. This is what keeps the configured FOV stable across a kill-camera scene
and makes menu, first-person, and third-person targets agree.

## Executable identity

All addresses refer only to `FalloutNV.exe` 1.4.0.525, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Raw radare2 output is under
`analysis/radare2/output/atom_camera_fov_*_20261019.txt`. Decompiler output is
a hypothesis; the disassembly, callers, and live pointer checks are the
authority.

## Native pipeline

### Player base angles

`PlayerCharacter` owns three related floats:

| Offset | Meaning | Initial source |
|---|---|---|
| `+0x670` | normal world FOV | `fDefaultWorldFOV`, value `0x01203160` |
| `+0x674` | first-person FOV | `fDefault1stPersonFOV`, value `0x0120316C` |
| `+0x678` | over-shoulder FOV | `fOverShoulderFOV`, value `0x011CDA5C` |

The GameSetting registration table also establishes the separate values used by
the Pip-Boy paths:

| Value address | Setting | Owner |
|---|---|---|
| `0x01203154` | `fDefaultFOV` | native screen projection base |
| `0x01203160` | `fDefaultWorldFOV` | `+0x670` |
| `0x0120316C` | `fDefault1stPersonFOV` | `+0x674` |
| `0x01203178` | `fPipboy1stPersonFOV` | `+0x674` while the Pip-Boy is active |

The initialization sequence at `0x0093917F..0x009391C1` reads the three
`GameSetting` value slots into those fields. `PlayerCharacter::UpdateFOV`
(`0x0095DE30`) interpolates the normal and first-person fields from live aim,
iron-sight, and dialogue state. The over-shoulder field is a third-person
profile. Atom does not write any of these gameplay fields and does not change
the game settings. Instead it observes the widest valid value each field reaches
in normal gameplay and uses that as the stable hip-fire base. The `fDefault*`
setting is only a startup fallback before the first normal observation.

### World camera writers

`PlayerCharacter::UpdateCamera` (`0x0094AE40`) applies the resolved base angle
through a pair of functions:

- `0x0094AF11..0x0094AF43` applies `+0x670`;
- `0x0094B4A1..0x0094B4D3` applies `+0x678` for the over-shoulder profile.

Both call `BSSceneGraph::SetCameraFOV` (`0x00C52020`) followed by the aspect
companion (`0x00B54000`) with the same degree value.

The setter detour classifies each incoming angle by the player field that
produced it (`+0x670`, `+0x674`, `+0x678`, or another source) using exact float
bits. The stable third-person branch applies `+0x678`, whose native base is
`fOverShoulderFOV`; first person uses `fDefault1stPersonFOV`; the unconditional
world pass uses `fDefaultWorldFOV`. Each field therefore reaches the requested
target from its own live base instead of being flattened onto one angle. A
transformed or constant angle uses the active mode's base.

The shared owner gate classifies `+0x64A`, `+0x64B`, and `+0x64C` as one POV
state: stable third person requires all three nonzero and stable first person
requires all three zero. An earlier unconditional `+0x64A` rejection would have
discarded every stable third-person FOV call.

`0x00C52020` is `thiscall` with this in `ECX` and four stack arguments, ending
in `ret 0x10`. It:

- writes the live degree value to the scene graph scalar `+0xBC`;
- derives the world NiCamera frustum from `tan(fov / 2)` and writes
  `+0xDC..+0xF0` (left, right, top, bottom, near, far);
- refreshes the scene graph `+0x110` ratio from `fDefaultFOV`.

`0x00B54000` is `cdecl` with one float argument. It converts the same angle into
the global tangent compensation at `0x011ADCC8`, which `0x00BA5320` consumes
for native 3D projection/UI scaling. Scaling only the camera writer would make
that projection disagree with the rendered frustum, so Atom admits the pair as
one inseparable capability.

### First-person and viewmodel

The first-person setup path (`0x008746D0`) reads `+0x674` through
`PlayerCharacter::GetFirstPersonFOV` (`0x00874900`), then writes the world
camera and aspect pair. The shared world-preparation route (`0x00872B00`) also
applies `+0x670` before its sky work. Atom classifies every argument by its
source field, so `First Person FOV` applies through either field while each keeps its
own native base. The viewmodel render path (`0x00875110`) repeats the `+0x674`
write and then copies the completed world NiCamera frustum into the separate
camera at `OSGlobals + 0xA0`:

```text
0x008752A2..0x008752D3   world FOV from +0x674, then 0x00C52020 / 0x00B54000
0x008752D6..0x008752F2   copy world frustum into OSGlobals +0xA0 via 0x00A6FAF0
```

`0x00A6FAF0` copies the first six floats and the trailing orthographic byte.
Atom therefore has one exact viewmodel seam: the direct call at `0x008752F2`.
The viewmodel renderer is reached through `0x00870A00 -> 0x00875110`; the three
first-person render callsites (`0x0087093D`, `0x00870B21`, `0x00870F74`) all use
that renderer.

For an independent viewmodel target, the copied frustum already contains the
active first-person ratio when world FOV ownership is active. Atom applies the
additional ratio

```text
additional = viewmodel_scale / first_person_scale
```

where `viewmodel_scale = 1` (follow) for `Viewmodel FOV = 0`. This makes the
viewmodel base exactly `First Person FOV` when following and exactly `Viewmodel FOV`
when independently configured, while preserving its live native zoom.

### World render enforcement

Atom owns the rendered lens in every presentation state, not only normal
gameplay. The same policy is applied at the two first-person world callsites,
the normal/third-person route (`0x008706B0 -> 0x008707C0`), and the fallback
route guard:

1. Pip-Boy latch/tails select the `Pip-Boy FOV` target.
2. A stable first/third-person state computes the expected angle from the live
   player field and that field's learned hip-fire base, preserving ADS/scope
   relative zoom and making hip fire exactly the configured target.
3. A menu forces the current coherent POV target; a POV transition forces the
   last coherent POV target.
4. VATS, special, fly, and death cameras retain their authored angle and receive
   the player's relative FOV ratio. On the first normal frame after such a
   camera, Atom immediately rewrites the normal angle so the scene cannot leave
   the screen at the authored/vanilla lens.
5. Invalid player/camera state or an explicit external camera-owner token
   leaves the lens native.

The route guard compares `SceneGraph +0xBC` with the expected angle, writes the
NiCamera extents and scalar only when they differ, and restores both after the
route. It is a no-op when the native writer wrappers already produced the same
value, so it cannot double-scale. This is what prevents menus, transitions, and
the first Pip-Boy open frame from rendering vanilla FOV even when their native
setter path is skipped.

### Pip-Boy and terminal FOV

`PlayerCharacter::SetPipBoyFOV` at `0x00950610` stores its degree argument at
player `+0x65C`, then calls `0x00C52020` and `0x00B54000` with that field.
The Pip-Boy and terminal camera paths call it from `0x00958F91` and
`0x0095C895`. Atom owns those two proven arguments instead of applying a
menu-wide field heuristic. This matters because the same `+0x65C` field is also
used by temporary gameplay FOVs, which follow the active POV policy instead of
being forced to the Pip-Boy target.

The selected argument is written back to `+0x65C` by the native setter. A later
call therefore passes the already-selected value, and the tangent conversion is
idempotent (`target -> target`). Outside the Pip-Boy latch, generic world
scaling applies the active POV/menu target; the explicit callsites and the
latch own the Pip-Boy frames.

The native Pip-Boy **screen texture** is a separate renderer. It builds its own
frustum from `fDefaultFOV` (`0x01203154`) times a native multiplier at
`0x011DB5EC`; it does not consume the world camera, the first-person camera, or
`fPipboy1stPersonFOV` (`0x01203178`). Atom deliberately does not patch that
projection. A direct callsite hook at `0x007FD2E9`, `0x007FDE6F`, or
`0x007FF42B` was evaluated but removed: the callsites did not reach the visible
menu path in the tested build, and patching a screen renderer shared with
HDPipboy/Pip-Boy Screen Effects risks a hard crash. The `Pip-Boy FOV` setting
therefore owns the **world/device lens** and the open/close animation, while
the screen texture retains its native/mod-owned fixed projection. This is the
verified boundary, not a claim that the UI texture changes with the setting.
The first Pip-Boy frame emits one `[CAMERA_FOV] Menu FOV observed` line with the
dedicated field, the first-person field, the world field, the shoulder field,
and the target, followed by the applied line and one `Pip-Boy lens` line. This
covers the menu camera and any interpolated open/close value.

The menu predicate is not sufficient for either animation edge. The Pip-Boy
open setup at `0x7F7F40` runs before `0x011DB378` is set at `0x7F8065`; Atom
starts a 150 ms leading latch at that entry and immediately applies the Pip-Boy
target through the captured native setter/aspect pair, so the first open frame
is already the Pip-Boy lens instead of the previous gameplay angle.
`FOPipboyManager` then clears the InterfaceManager menu state before the visual
return, but its presentation byte stays set until `0x7F82F2`, after the close
animation calls. Atom uses that byte as the authoritative latch and retains the
Pip-Boy lens for the same 150 ms return interval already used by Atom's
camera-reacquisition contract. Ordinary first/third-person FOV resumes after
that interval. The first open and close frames emit `open latch engaged` and
`close latch engaged` lines, and one `Pip-Boy lens` line records the world
scalar and the first-person camera angle so any mismatch with the separately
rendered screen texture is visible in evidence.

## Ownership and failure behavior

- At `DeferredInit`, after the complete `UpdateCamera` owner is admitted, Atom
  installs function-entry inline hooks on `0x00C52020` and `0x00B54000` in one
  rollback-capable transaction. Either hook failing disables the pair and leaves
  every FOV field native.
- At the first post-Deferred `MainGameLoop`, after the five render hooks are
  active, Atom installs the viewmodel frustum call and the third-person route
  correction as separate fail-soft capabilities. Their failure leaves native
  writer scaling active.
- The detours chain the captured predecessor exactly once. A call whose
  `this`/camera target is not the live world scene graph, whose angle is
  non-finite or outside `1..179`, whose base setting is invalid, or whose
  configuration is zero passes the original value through unchanged.
- The two Pip-Boy/terminal camera callsites are owned independently of the
  motion owner gate. FOV ownership is continuous across normal gameplay,
  menus, POV transitions, and animation/control locks; an explicit external
  camera-owner token or an invalid player/camera state is the only pass-through.
- `0x00C5257F` re-applies the scene graph's current `+0xBC` scalar with the
  native force flag. The setter detour recognizes that force-flagged
  re-application, keeps an unchanged target idempotent, rebases a changed target
  from the current scalar, and restores the live player world field when the
  target becomes native. Normal player-camera calls use the non-forced form and
  are scaled once.
- FOV ownership selects one of three policies:
  - normal first/third person preserves the live field's relative ADS/scope
    zoom against the field's learned hip-fire base;
  - menus and POV transitions force the last coherent POV target;
  - VATS, special, fly, and death cameras retain their authored angle and
    receive the player's relative FOV ratio.
- A force-flagged re-application of a special camera's own scalar passes through
  unchanged. Replacing it with the world target would destroy VATS or
  kill-camera framing; the next normal writer restores the configured lens.
- The first normal frame after a special camera rewrites the normal angle
  immediately from the learned base, so a kill camera or VATS scene cannot leave
  the screen at its authored/vanilla lens when gameplay resumes.
- Each player FOV field's widest valid value in normal gameplay is learned as its
  hip-fire base. Menus, transitions, ADS/scope frames, and special cameras never
  update it, so a runtime setting or kill-camera mutation cannot change the
  configured lens.
- Every normal, menu, and transition world render route applies the same policy
  at route entry. A menu or transition therefore cannot render a vanilla lens
  even when its native setter is skipped; the scoped guard restores the exact
  prior camera state afterward.
- Authored special cameras are owned by the writer/aspect path, not by the
  render guard. A force-flagged re-application of their own scalar passes
  through unchanged; the first normal frame afterward immediately restores the
  configured lens.
- The Pip-Boy open setup, presentation byte, dedicated callsites, and bounded
  leading/trailing intervals own the Pip-Boy **world/device** target through the
  complete open and close animations. The separate screen-texture projection is
  native/mod-owned and is not patched. Other menu frames use the current or last
  coherent POV target.
- Screen-texture callsite hooks must not be reintroduced without a runtime
  trace proving they execute on the visible menu. The evaluated
  `0x007FD2E9`/`0x007FDE6F`/`0x007FF42B` callsites did not produce a screen-lens
  trace in the tested build, and patching that shared renderer can conflict with
  HDPipboy or Pip-Boy Screen Effects.
- FOV diagnostics must never reset on a per-frame camera rejection. The native
  update path rejects samples while menus, special cameras, and the Pip-Boy are
  active; resetting trace latches or learned bases there produced per-frame file
  I/O and unstable presentation state. Resets belong only to configuration
  publication and lifecycle transitions.
- No detour allocates, blocks, reads a file, logs per frame, or retains an
  engine pointer. Configuration is a bounded seqlock read. Trace latches and
  learned hip-fire bases reset only on configuration publication or an explicit
  lifecycle reset, never on a per-frame camera rejection; this keeps the native
  render/update path free of diagnostic I/O and avoids resetting presentation
  state during menus, special cameras, or Pip-Boy animation.
- Atom never rewrites `fDefaultFOV`, `fDefaultWorldFOV`,
  `fDefault1stPersonFOV`, `fOverShoulderFOV`, or a `PlayerCharacter` field.

## Compatibility

Atom scales whatever live angle the native camera owner produced. A compatible
mod which writes through the same two native functions is scaled by Atom's
current base ratio; a mod which replaces the frustum after Atom's entry owner,
or which owns a different camera, is outside this ownership claim. Atom does
not identify, inspect, patch, disable, or reorder another mod by name. A mod or
special camera that mutates the live FOV settings or player fields only affects
the configured lens if it does so during normal gameplay; the learned hip-fire
base keeps the configured hip-fire angle and its relative ADS scaling stable.

The scene graph degree scalar, NiCamera frustum, `+0x110` ratio, and native 3D
projection compensation therefore describe one lens. OMV's shadow FOV
compensation reads `SceneGraph + 0xBC` and its depth/TAA consumers read the same
frustum, so no separate graphics-owner adjustment is required.

## Acceptance

Offline checks execute the production parser and math:

- `camera_fov_behavior.rs`: section isolation, native sentinel bit-exactness,
  base-target reachability, ADS/scope tangent preservation, independent and
  follow-first viewmodel composition, absolute Pip-Boy targeting, bounds, and
  invalid-input fallback.
- `camera::fov` unit tests: frustum center preservation, near/far and
  orthographic preservation, identity, invalid frustum rejection, and coherent
  configuration publication.
- `mcm_contract.rs`: every shipped row persists one setting, every default
  matches the runtime default, labels remain one to three words, and the
  `Field of View` section is filed under Camera.

The first successful application per feature and the first third-person render
correction emit one `[CAMERA_FOV]` info line. The latch resets on every
MCM publication, so a playtest log can prove which path ran without per-frame
spam. The first learned hip-fire value per field, the first entry into each
special-camera kind, the first special exit, and one Pip-Boy lens line add
bounded diagnostics for the kill-camera, VATS, and Pip-Boy menu paths.

The following require the real game and are not claimed by an offline build:

1. load-to-gameplay with first-person, third-person, viewmodel, and Pip-Boy
   targets set;
2. live MCM save/close applying without a restart;
3. 30/60/120 FPS, 16:9 and 4:3;
4. ADS, iron sights, scopes, weapon swap, reload, and fire;
5. the normal third-person route and over-shoulder aim;
6. Pip-Boy open/close, its 3D screen, and terminal transitions;
7. dialogue, VATS, kill camera, TFC, menu, loading, and cell transitions;
8. independent viewmodel angles under the same first-person zoom;
9. coexistence with an installed external FOV owner.

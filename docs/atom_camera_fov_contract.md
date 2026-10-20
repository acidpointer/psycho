# Atom camera FOV ownership contract

Status: implementation uses native FOV base ownership. Offline configuration and
mapping tests pass. The required load-to-gameplay, kill-camera/VATS, JVO marker,
and visual FOV matrix remains the final runtime gate.

## Scope

Atom exposes four independent base-angle targets:

| Setting | MCM key | Native owner | `0` behavior |
|---|---|---|---|
| First Person FOV | `Fov:fFirstPerson` | `fDefaultWorldFOV`, player `+0x670` | native |
| Third Person FOV | `Fov:fThirdPerson` | `fOverShoulderFOV`, player `+0x678` | native |
| Viewmodel FOV | `Fov:fViewmodel` | `fDefault1stPersonFOV`, player `+0x674` | follow First Person; native if that is also zero |
| Pip-Boy FOV | `Fov:fPipboy` | `fPipboy1stPersonFOV` | native |
| Terminal FOV | `Fov:fTerminal` | `fRenderedTerminalFOV` | native |
| Iron Sight FOV | `Fov:fIronSightFov` | `fIronSightsZoomDefault` | native |
| Iron Sight Speed | `Fov:fIronSightSpeed` | `fIronSightsFOVTimeChange` | native |
| Dialog Zoom In | `Fov:fDialogZoomIn` | `fDialogZoomInSeconds` | native |
| Dialog Zoom Out | `Fov:fDialogZoomOut` | `fDialogZoomOutSeconds` | native |
| Dialog Delay | `Fov:fDialogDelay` | `fDialogSpeechDelaySeconds` | native |
| Scope Scissor | `Fov:fScopeScissor` | `fScopeScissorAmount` | native |
| Near Distance | `Fov:fNearDistance` | `fNearDistance` | native |

Non-zero base angles are clamped to `1..=150` degrees. `Terminal FOV` is a
projection scale (not a base angle). `Iron Sight FOV` is a base angle.
`Iron Sight Speed`, `Dialog Zoom In/Out`, and
`Dialog Delay` are seconds. `Scope Scissor` is a normalized amount.
`Near Distance` is a world-unit clip distance. Negative and non-finite values
are rejected. MCM Extender remains the only writer of
`Data/config/Atom/Atom.ini`. The native callbacks consume one seqlock snapshot
and never parse the INI.

The terminal screen projection scale is separate from the Pip-Boy/terminal
world/device angle. Atom owns the scale only when configured; the Pip-Boy
world/device lens remains `Pip-Boy FOV`.

The target is the native **base** FOV. FNV's own `PlayerCharacter::UpdateFOV`
derives ADS, scope, dialogue, POV-transition, VATS, kill-camera, and Pip-Boy
angles from these bases. Atom does not scale individual camera writer arguments.

## Executable identity

All addresses refer only to `FalloutNV.exe` 1.4.0.525, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

Relevant native slots:

| Address | Meaning |
|---|---|
| `0x01203154` | `fDefaultFOV` screen-projection base (left native) |
| `0x01203160` | `fDefaultWorldFOV` |
| `0x0120316C` | `fDefault1stPersonFOV` |
| `0x01203178` | `fPipboy1stPersonFOV` |
| `0x011CDA5C` | `fOverShoulderFOV` |
| `0x011DB5F0` | `fRenderedTerminalFOV` projection scale |
| `0x011E0974` | `fIronSightsZoomDefault` |
| `0x011CE874` | `fIronSightsFOVTimeChange` |
| `0x011D3EE4` | `fDialogZoomInSeconds` |
| `0x011D2440` | `fDialogZoomOutSeconds` |
| `0x011D32C8` | `fDialogSpeechDelaySeconds` |
| `0x011DEA90` | `fScopeScissorAmount` |
| `0x01203148` | `fNearDistance` |
| player `+0x670` | live world FOV field |
| player `+0x674` | live first-person / viewmodel field |
| player `+0x678` | live over-shoulder field |
| `0x00C52020` | `BSSceneGraph::SetCameraFOV` |
| `0x00B54000` | native aspect/3D-UI compensation writer |

Raw evidence remains under `analysis/radare2/output/atom_camera_fov_*` and
`analysis/radare2/output/atom_camera_fov_ui_projection_reset_20261020.txt`.
Decompiler output is a hypothesis; disassembly and caller coverage are the
authority.

## Why native bases

The engine already has one coherent FOV pipeline. `UpdateFOV` reads the
`fDefault*` settings and writes the live player fields; `UpdateCamera` feeds
those fields into `SetCameraFOV` and the aspect companion. Everything downstream
consumes that state:

- native ADS/scope interpolation;
- dialogue and POV transitions;
- VATS and the vanilla kill camera;
- Pip-Boy and terminal paths;
- 3D-UI projection and world-to-screen consumers.

Scaling individual writer arguments changes only the camera call while leaving
the live player field and native settings at their old values. That breaks:

1. Epilogue consumers that validate the writer argument against the live field.
   JohnnyGuitar NVSE's `WorldToScreen` hook at `0x00C5244A` copies its camera
   only when `arg_fov == PlayerCharacter::GetWorldFOV()` (`0x00710AB0`,
   playing `+0x670`). Just Visual Objectives calls that function for every
   marker; a scaled argument leaves its cache frozen at stale coordinates.
2. VATS/kill-camera resets. `UpdateFOV` VATS mode 4 writes the native
   `fDefaultWorldFOV`/`fDefault1stPersonFOV` values (or the iron-sight values)
   into the live fields. Scaling those values against a different learned base
   produces the wrong kill-camera and return FOV.

Both reference implementations use native bases rather than writer-argument
scaling:

- **FOV Slider** writes `fDefaultWorldFOV`, `fDefault1stPersonFOV`,
  `fPipboy1stPersonFOV`, and terminal/scope settings, then calls
  `SetCameraFOV`. It explicitly reapplies the settings after `GetVATSMode` and
  `IsInKillCam` transitions.
- **Enhanced FOV** exposes exactly 1st person, 3rd person, viewmodel, and
  Pip-Boy targets. It uses the engine `FOV` command (`0x005C58B0` writes player
  `+0x670`/`+0x674` and the two settings) and `SetCameraFOV`, updates
  `fPipboy1stPersonFOV`, and reapplies on POV changes and cell exits.

## Apply behavior

At `DeferredInit`, after the shared `UpdateCamera` owner is admitted, Atom
validates the writer/aspect pair and all twelve setting slots. Nothing is
written yet.

On the first stable normal-gameplay `UpdateCamera`:

1. Capture the original four bases and eight detail values once, together with
   the live player fields, before any target can seed them.
2. Resolve the configured targets:
   - `world = first_person != 0 ? first_person : original_world`;
   - `first_person = viewmodel != 0 ? viewmodel : (first_person != 0 ? first_person : original_first)`;
   - `over_shoulder = third_person != 0 ? third_person : original_shoulder`;
   - `pipboy = pipboy != 0 ? pipboy : original_pipboy`;
   - each detail value `= configured != 0 ? configured : original`.
3. Write `fDefaultWorldFOV`, `fDefault1stPersonFOV`, `fOverShoulderFOV`,
   `fPipboy1stPersonFOV`, `fRenderedTerminalFOV`,
   `fIronSightsZoomDefault`, `fIronSightsFOVTimeChange`, the three dialogue
   intervals, `fScopeScissorAmount`, and `fNearDistance`.
4. Write player `+0x670`, `+0x674`, and `+0x678` to the same values.
5. Apply the current camera lens through the native writer/aspect pair:
   `+0x678` in stable third person, otherwise `+0x670`.
6. Leave `fDefaultFOV` at its native screen-projection value.

The native writer pair uses its force flag so the frustum, scene-graph scalar,
and `+0x110` ratio are refreshed together. Atom installs no writer detours, so
the angle passed by every engine caller remains the native field value.

## Reapply and restore

After every native `UpdateCamera`, Atom checks only bounded state:

- A configuration publication or lifecycle reset requests one reapply.
- A POV change requests one reapply.
- A return from a special camera, VATS, kill camera, menu, or transition
  requests one reapply.
- In stable normal gameplay, a native base that differs from the configured
  plan is repaired once. This covers engine or external resets after
  VATS/kill-camera/menu transitions.

No per-frame file I/O, allocation, configuration parsing, or diagnostic logging
occurs in this path.

When every target is zero or the capability is released, Atom restores the
captured native bases, detail values, player fields, and camera lens. A target
that is zero individually restores only that setting.

## Compatibility

Atom owns the native FOV bases only while at least one target is non-zero. A
compatible FOV owner must not write the same bases concurrently; the last writer
would win. Enhanced FOV, FOV Slider, and similar base-setting providers must be
disabled when Atom FOV is enabled. Atom does not identify, inspect, patch, or
reorder another mod by name.

Because the writer argument and live player field remain consistent, compatible
world-to-screen consumers (such as JohnnyGuitar's cached W2S) update normally.
No separate receiver callback or per-frame camera copy is required.

`fDefaultFOV` and the separately rendered Pip-Boy screen texture remain native
and are not patched. The world/device Pip-Boy lens follows
`fPipboy1stPersonFOV`.

## ADS and scopes

ADS and scope targets are computed by the engine from the configured bases and
the native iron-sight/weapon sight values. Atom owns the global
`fIronSightsZoomDefault` base and `fIronSightsFOVTimeChange` transition speed.
Per-weapon sight FOVs are not rewritten in this change. If a weapon has its own
authored sight FOV, that value overrides the global iron-sight base; per-weapon
relative-zoom compensation remains a separate compatibility item.

## Failure behavior

If the native setting slots or writer pair cannot be validated, installation
fails closed and every FOV base remains native. A failed player-field capture
defers the first apply until a stable gameplay update. Restoring an invalid or
unavailable field is skipped rather than writing a non-finite value.

## Acceptance

Offline checks execute the production parser and target resolver:

- four independent angle targets plus terminal scale, global iron-sight FOV,
  iron-sight speed, dialogue intervals, scope scissor, and near distance;
- zero/native sentinels, viewmodel-follow-first, clamping, negative/non-finite
  rejection;
- coherent configuration publication;
- resolved base and detail mapping for all zero/non-zero combinations;
- MCM rows persist the same settings and defaults.

Runtime acceptance:

1. load-to-gameplay with first, third, viewmodel, and Pip-Boy targets;
2. JVO/JAM quest markers move with the world and remain anchored;
3. kill camera and VATS: authored camera behavior during playback, exact
   configured base after exit;
4. first person, third person, ADS, iron sights, scopes, weapon swap, reload,
   fire;
5. Pip-Boy/terminal open/close and 3D screen;
6. dialogue, TFC, menus, loading, and cell transitions;
7. live MCM save/close without restart;
8. disable/restore leaves native bases and fields intact.

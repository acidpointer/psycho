# Fallout: New Vegas actor input contract

## Status and scope

This document is the native input contract and design audit for Atom. It covers
how Fallout: New Vegas 1.4.0.525 acquires keyboard, mouse, joystick, and XInput
state; turns that state into bindings and player actions; applies mouse and
controller look; and carries one frame of input toward presentation. It also
classifies the input defects and modern-practice gaps that an ESP-less gameplay
overhaul can address without making assumptions about forms added by plugins.

"Actor input" is precise only for the player. The physical-device route feeds
`PlayerCharacter`. NPC `Actor` objects are driven by packages, combat AI, and
engine commands. The investigation found no generic route that assigns hardware
input to every NPC. Atom can build player action semantics on this contract;
changes to NPC responsiveness require a separate AI contract.

The issue register is comprehensive for the paths and executable inspected. It
does not claim that every perceived delay is an input-transport defect. Weapon,
animation, camera, menu, and gameplay state machines can delay or reject an
action after input has already been accepted, and each such report needs its own
consumer trace.

No Atom feature is implemented by this research. Addresses are evidence for the
supported executable, not permission to install broad or unverified patches.

## Executive findings

The normal gameplay path is frame-polled DirectInput/XInput:

```text
device reports
    |
    v
DirectInput / XInput state accumulated by the native or compatibility runtime
    |
    v
0x00A23010 once in the normal rendered frame
    |  copies previous state, then snapshots current state
    v
binding and edge queries -> PlayerCharacter consumers -> camera/world/AI/render
    |
    v
xNVSE OnFramePresent -> native presentation -> runtime/compositor -> scanout
```

The important conclusions are:

- The executable does not directly register Raw Input. It creates DirectInput 8
  keyboard and mouse devices and polls immediate state. It also polls XInput
  user index zero and enumerated DirectInput joysticks.
- Current Wine implements DirectInput 8 mouse and keyboard devices on a Raw
  Input-backed path. Therefore "replace DirectInput with Raw Input" is not, by
  itself, a demonstrated latency fix under Proton. The engine's once-per-frame
  sample and its position within the frame remain.
- Gameplay retains only current and previous snapshots. A press and release
  completed between two samples can disappear, and several transitions collapse
  into one. Buffered menu/focus paths can observe events that gameplay misses.
- Input is sampled early enough that the remainder of the simulation/render
  frame lies between sampling and presentation. VSync, presentation queues,
  the compatibility runtime, compositor, and scanout can add more latency.
- There is no proven mandatory extra one-frame action queue after sampling.
  Reported delay beyond the transport budget must be attributed to a particular
  consumer rather than guessed.
- Actor mouse look uses relative `DIMOUSESTATE2.lX/lY`, a shared
  `fMouseSensitivity`, optional Y inversion, and camera-state scaling. The
  `fForegroundMouse*` acceleration settings and Windows Control Panel mouse
  sensitivity affect the interface cursor, not player camera rotation.
- Controller look applies the default XInput right-thumb threshold independently
  to X and Y. This creates axial component suppression and cardinal snapping
  rather than a radial deadzone. Triggers are active at any value above zero.
- Vanilla selects controller mode instead of merging controller and
  keyboard/mouse activity seamlessly. Existing xNVSE fixes corroborate several
  resulting action-map and device-switch defects.
- The native binding schema has 28 one-byte action entries per device, one bind
  per action, no chords, no multiple alternatives, no source-device identity,
  and no Hotkey2 entry.
- Player action consumption is fragmented. xNVSE hooks distinct attack, aim,
  jump, run, VATS, wait, reload, and disabled-control sites. A new action layer
  cannot assume one universal consumer interception point.

## Evidence and confidence model

### Supported executable

The native analysis used the current repository binary:

| Property | Value |
|---|---|
| Path | `fnv_reverse/FalloutNV.exe` |
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |
| Size | 16,084,808 bytes |
| Format | PE32 x86, image base `0x00400000`, non-PIC |
| PE timestamp | 2011-07-01 07:45:33 UTC |
| Embedded PDB path | `D:\_Fallout3\Platforms\Common\build\win32\FalloutNV.pdb` |
| Primary native tool | radare2 MCP, analysis level 2 |

The address ledger is
[analysis/radare2/output/perf/fnv_actor_input_contract.txt](../analysis/radare2/output/perf/fnv_actor_input_contract.txt).
Established window identity and input policy are reused from
[window_input_policy.md](window_input_policy.md) and its linked evidence rather
than re-researched.

### Meaning of terms

- **Proven** means direct executable disassembly/data/xrefs, repository source
  that owns an installed hook, or a cited platform contract establishes it.
- **Derived** means it follows mechanically from proven behavior, such as a
  short tap disappearing when only before/after snapshots exist.
- **Corroborated** means a read-only third-party implementation targets the same
  behavior, but that implementation is not the authority for the executable.
- **Runtime-dependent** means Proton/Wine/DXVK version, configuration, device,
  refresh, compositor, or game state must be measured in the user's setup.
- **Design recommendation** is Atom policy, not a claim about vanilla behavior.

## Device creation, ownership, and lifetime

`0x00A22660` constructs the native input owner. Its only observed caller is
`0x0086C80C`, and the allocation is `0x1C04` bytes. The process-global owner
pointer is at `0x011F35CC`.

| Owner field | Purpose | Lifetime |
|---:|---|---|
| `+0x04` | input flags | owner lifetime |
| `+0x08` | `IDirectInput8` | owner lifetime |
| `+0x2C` | keyboard `IDirectInputDevice8` | owner/device lifetime |
| `+0x30` | mouse `IDirectInputDevice8` | owner/device lifetime |
| `+0x18F8` | current 256-byte keyboard state | overwritten per sample |
| `+0x19F8` | previous keyboard state | overwritten before current sample |
| `+0x1B24` | current 20-byte `DIMOUSESTATE2` | overwritten per sample |
| `+0x1B38` | previous `DIMOUSESTATE2` | overwritten before current sample |
| `+0x1B4C` | swapped-button state | initialized from Windows |
| `+0x1B50` | Control Panel `MouseSensitivity` byte | initialized from registry |
| `+0x1B54` | Windows double-click interval | initialized from Windows |
| `+0x1B58` | mouse event/auxiliary state | reset/updated by input routes |
| `+0x1B94` | 28 keyboard bindings | preferences/owner lifetime |
| `+0x1BB0` | 28 mouse bindings | preferences/owner lifetime |
| `+0x1BCC` | 28 controller/joystick bindings | preferences/owner lifetime |

The constructor calls `DirectInput8Create`, creates `GUID_SysKeyboard` and
`GUID_SysMouse`, configures formats/cooperative levels, reads
`HKCU\Control Panel\Mouse\MouseSensitivity`, and calls `SwapMouseButton` and
`GetDoubleClickTime`.

It also configures a 32-event DirectInput keyboard buffer with
`DIPROP_BUFFERSIZE` at `0x00A227D7` through `0x00A22812`. Mouse setup calls
`SetDataFormat` but does not configure an equivalent buffered-event queue.
Consequently the existing keyboard side route can preserve distinct events up
to its small buffer limit, while normal mouse input has only immediate relative
state and buttons.

The keyboard is foreground-only and may be exclusive or nonexclusive; both
native branches request `DISCL_NOWINKEY`. The mouse is also foreground-only and
has exclusive and nonexclusive branches.

| Device/site | Flags | Meaning |
|---|---:|---|
| keyboard `0x00A22782` | `0x16` | nonexclusive, foreground, suppress Windows key |
| keyboard `0x00A227A1` | `0x15` | exclusive, foreground, suppress Windows key |
| mouse `0x00A229A9` | `0x06` | nonexclusive, foreground |
| mouse `0x00A229CB` | `0x05` | exclusive, foreground |
| mouse reacquire `0x00A23C7C` | `0x06` | nonexclusive, foreground |
| mouse reacquire `0x00A23CAD` | `0x05` | exclusive, foreground |

Microsoft defines cooperative level as the sharing and foreground/background
policy for a DirectInput device; foreground devices are automatically
unacquired when the application loses focus. See
[DirectInput cooperative levels](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee416848%28v%3Dvs.85%29)
and
[`SetCooperativeLevel`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee417921%28v%3Dvs.85%29).

Psycho already has an independently audited, capability-based policy for system
key passthrough. xNVSE also contains optional cooperative-level patches because
its source notes that background-mouse configuration is ignored on focus
regain. The relevant source is
[`libnvse/xnvse/nvse/nvse/nvse.cpp`](../libnvse/xnvse/nvse/nvse/nvse.cpp).
This research does not change those policies.

The stable top-level/input HWND is stored at `0x011C6FC0`, the renderer HWND at
`0x011C6FBC`, and Fallout's WndProc is `0x0086A0A0`. Focus ownership is therefore
window-lifetime behavior, while the COM interfaces and state arrays have native
input-owner lifetime.

## Native acquisition and sampling

### OS interfaces

The executable imports DirectInput 8 and XInput 1.3 ordinal 2. The ordinal call
from the input sampler takes user index zero and matches the `XInputGetState`
ABI. Microsoft documents that `XInputGetState` retrieves the current state for
a specified controller and returns device-not-connected when it is unavailable:
[`XInputGetState`](https://learn.microsoft.com/en-us/windows/win32/api/xinput/nf-xinput-xinputgetstate).

The executable has no Raw Input API import. Microsoft describes Raw Input as a
route that receives unprocessed device data and can distinguish multiple
devices. The same guidance says DirectInput offers no mouse/keyboard advantage
over the newer Windows message/Raw Input routes for new applications:
[Raw Input overview](https://learn.microsoft.com/en-us/windows/win32/inputdev/about-raw-input),
[high-definition mouse movement](https://learn.microsoft.com/en-gb/windows/win32/dxtecharts/taking-advantage-of-high-dpi-mouse-movement).
That is a modern API assessment, not proof that DirectInput is the dominant
problem in Fallout under Proton.

### Normal frame sampler

`0x00A23010` is the immediate-state sampler:

1. It copies the current XInput globals to the previous XInput globals, then
   calls XInput for controller index zero. Enumerated DirectInput joysticks are
   processed separately.
2. It copies the current 256-byte keyboard array to the previous array.
3. It calls keyboard `Acquire`, `Poll`, and `GetDeviceState(256)`. If the route
   fails, it clears the current keyboard array.
4. It copies the current 20-byte mouse state to the previous mouse state and
   clears the auxiliary mouse field.
5. It calls mouse `Acquire`, `Poll`, and `GetDeviceState(20)`. If the route
   fails, it clears the current mouse state.

The COM slots agree with xNVSE's wrappers: `GetDeviceState` is vtable `+0x24`
and `GetDeviceData` is `+0x28`. Microsoft defines `GetDeviceState` as an
immediate snapshot and `GetDeviceData` as retrieval of buffered device events:
[`GetDeviceState`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee417897%28v%3Dvs.85%29),
[`GetDeviceData`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee417894%28v%3Dvs.85%29).
Buffered `DIDEVICEOBJECTDATA` carries object data, timestamp, and sequence
fields:
[`DIDEVICEOBJECTDATA`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee416611%28v%3Dvs.85%29).

The normal call is `0x0086F39E` inside `0x0086F390`. Other calls support movie,
blocking, and focus/window flows:

| Call site | Flow |
|---:|---|
| `0x0086F39E` | normal frame |
| `0x008674B2` | movie |
| `0x008674F1` | optional second movie-flow sample |
| `0x007040FC` | blocking flow |
| `0x00871CC8` | focus/window flow |

`0x00A237B0` drains buffered keyboard events with `GetDeviceData` on a
message/focus route. This is not the normal gameplay action source.

### Immediate-state consequences

The following are derived directly from retaining only current and previous
snapshots:

- A digital press and release wholly between normal samples can be invisible.
- Multiple digital transitions collapse to the final state.
- Edge identity has frame granularity rather than device-event timestamps.
- Relative mouse X/Y deltas accumulate between polls, preserving total motion
  in the normal case while losing timing and report sequence.
- Mouse wheel behavior uses the sign of one accumulated `lZ` value for two
  pseudo-buttons. Opposing wheel reports can cancel; notch count/magnitude is
  not preserved as action data.
- A buffered menu/focus route can see a short event that gameplay misses.
- A state-read failure clears current state, which can appear as releases
  relative to the prior snapshot. Focus-gap continuity is not preserved.

An extra engine-side mouse poll is unsafe as a casual latency optimization.
Relative state is consumable/accumulated state; a second `GetDeviceState` can
split or consume the delta expected by vanilla and by xNVSE's installed
wrappers.

## Bindings and action queries

`0x00A22EF0` iterates 28 entries at `0x011A7E60`, reads hexadecimal values from
`[Controls]` in `FalloutPrefs.ini`, and applies them through `0x00A24F60`.
Each device array holds one byte per action; `0xFF` means unbound.

| ID | Preference/action | Native gameplay meaning |
|---:|---|---|
| 0 | Forward | forward movement |
| 1 | Back | backward movement |
| 2 | Slide Left | strafe left |
| 3 | Slide Right | strafe right |
| 4 | Use | attack/fire |
| 5 | Activate | interact |
| 6 | Block | aim/block |
| 7 | Ready Item | ready/reload |
| 8 | Crouch/Sneak | crouch/sneak |
| 9 | Run | run modifier |
| 10 | Always Run | run mode toggle |
| 11 | Auto Move | automatic movement |
| 12 | Jump | jump |
| 13 | Toggle POV | first/third-person toggle |
| 14 | Menu Mode | menu/Pip-Boy route |
| 15 | Rest | wait/rest |
| 16 | Vats | VATS |
| 17 | Hotkey1 | item hotkey 1 |
| 18 | Ammo Swap | ammunition swap; occupies Hotkey2's ordinal |
| 19-24 | Hotkey3-Hotkey8 | item hotkeys 3-8 |
| 25 | QuickSave | quicksave |
| 26 | QuickLoad | quickload |
| 27 | Grab | grab/manipulate |

The missing native Hotkey2 is not a documentation typo. Stewie Tweaks'
read-only implementation `TwoHotkeyRestored.cpp` works around the conflict with
Ammo Swap, corroborating the table.

The core state queries are:

| Function | Purpose |
|---:|---|
| `0x00A24180` | keyboard current/pressed/released/changed query |
| `0x00A23A50` | mouse button/wheel pseudo-button query |
| `0x00A23E10` | controller query |
| `0x00A24560` | device/action dispatch |
| `0x00A24660` | bound-control query |
| `0x00A24280` | keyboard-state injection |
| `0x00A253D0` | iterate all 28 controls through `0x00A25410` |

The keyboard query's modes are current/held, pressed edge, released edge, and
changed. Mouse uses current and previous button arrays; button IDs 8 and 9 are
wheel-direction pseudo-buttons.

xNVSE's `SetControl` behavior swaps a duplicate binding with the action's old
binding. This preserves the one-action/one-byte schema; it does not add native
chords, modifier combinations, multiple alternate bindings, contexts, or
source-device identity. Its DirectInput mouse macro route supports eight
buttons plus wheel pseudo-directions.

Keyboard values are DirectInput scan codes. That is useful when gameplay binds
should stay on a physical key position across layouts, but it is insufficient
for layout-aware labels, text/IME input, richer devices, or an accessible
action-remapping presentation without a separate semantic layer.

## Player control consumers

`0x0093E860` is the large `PlayerCharacter` input/update path. It calls camera
and input helper `0x009445B0` at `0x0093F8D9`. Direct examples include aim/block
control 6 at `0x00941F4F` and `0x00941F5F`, jump control 12 at `0x0094215F`,
VATS control 16 at `0x00942884`, quicksave at `0x0094284E`, and quickload at
`0x00942869`.

Disabled-player-control flags are a byte at `PlayerCharacter +0x680`:

| Bit | Disabled behavior |
|---:|---|
| 0 | movement |
| 1 | looking |
| 2 | Pip-Boy |
| 3 | fighting |
| 4 | POV |
| 5 | rollover |
| 6 | sneak |

`0x005A03F0` tests a requested mask. The practical architecture fact is that
xNVSE must hook many distinct consumers: disabled flags, attack, remembered
automatic attack, VATS, jump, aim, controller and noncontroller run paths,
wait, sleep, fast travel, and reload. The engine does not expose one complete
high-level action queue through which every player action can be transformed
or suppressed safely.

xNVSE also documents a concrete suppression defect. A prevented automatic
weapon attack can remain remembered through `ForceFireWeapon`; its gameplay
hook handles the prevented condition at `0x00948A18` and `0x009491BC` and skips
to `0x00949676`. This does not prove that every vanilla attack is delayed. It
proves that suppression must clear or bypass downstream remembered state for
that consumer.

## Mouse-to-camera route

`0x00A239E0(axis)` returns the current relative mouse values:

| Axis ID | Field |
|---:|---|
| 1 | `DIMOUSESTATE2.lX` at owner `+0x1B24` |
| 2 | `DIMOUSESTATE2.lY` at owner `+0x1B28` |
| 3 | `DIMOUSESTATE2.lZ` at owner `+0x1B2C` |

Player camera helper `0x009445B0` reads X at `0x00945995`, Y at
`0x009459A8`, and wheel at `0x009459BB`. It applies `bInvertYValues`
(`0x011E0A5C`) at `0x009459C6`. If disabled-looking bit 1 is active, the check
at `0x009459E5` zeros input.

`fMouseSensitivity:Controls` is the setting object at `0x011E0A6C`. The helper
multiplies the same scalar directly into horizontal movement at `0x00945DB2`
and vertical movement at `0x00945FA4`, followed by camera-state-specific scale.
A separate camera/flycam helper at `0x0094A8C0` reads mouse X/Y, applies the same
sensitivity family, and accumulates camera rotation at object fields
`+0x7E0/+0x7E4`.

### What actor mouse look does not do

No explicit actor-look smoothing buffer or actor-look acceleration setting was
found in these paths. No frame-time multiplication of direct relative mouse
deltas was found. It would therefore be unsupported to claim that Fallout's
mouse camera is intrinsically frame-rate-scaled or smoothed by a hidden vanilla
buffer.

Four commonly recommended settings are interface-cursor settings:

| Setting object | Setting |
|---:|---|
| `0x011F35F4` | `fForegroundMouseMult` |
| `0x011F3600` | `fForegroundMouseBase` |
| `0x011F360C` | `fForegroundMouseAccelTop` |
| `0x011F3618` | `fForegroundMouseAccelBase` |

Their accessors are consumed by `InterfaceManager` function `0x007118D0`, which
also uses the Windows Control Panel sensitivity byte at `0x00711A8A` to update
the interface cursor. They do not feed player camera helper `0x009445B0`.
Changing them may change menu cursor feel, but is not an actor-look acceleration
fix.

### Proven mouse limitations

- Horizontal and vertical actor look share one user-facing scalar.
- Y can be inverted; there is no equivalent native X-invert action setting.
- Camera-state-specific scaling prevents a stable universal cm/360 guarantee
  across first person, third person, aim, scope, vanity, and flycam states.
- Event timing is coalesced to one state per rendered frame.
- Wheel events become two sign-only pseudo-buttons.
- The binding layer identifies a logical mouse button, not a physical source
  mouse, and its xNVSE-compatible route exposes only eight buttons plus wheel.
- Stewie Tweaks' `SeparateHorizontalVerticalSensitivity.cpp` patches the same
  vertical reads (`0x00945FAF`, `0x0094A9FE`, `0x0094AA6C`), corroborating the
  lack of independent native axis sensitivity.
- `VanityCamRotationFix.cpp` targets native wrap/clamp behavior at `0x00945D53`
  and `0x0094B521`, corroborating a separate vanity-camera defect.

## Controller route

The controller-mode byte is at `0x011F35C8`. `0x00A23E10` returns zero when
that mode is false. This is a binary mode gate, not a modern last-active-device
presentation policy layered over a device-agnostic action state.

### Right-stick look

`0x009445B0` reads right-stick axes 9 and 10 through `0x00A23390`. It sets each
axis independently to zero when `abs(axis) < 0x21F1` (8689), normalizes the
remaining vector, and applies an acceleration exponent. `0x21F1` is the XInput
default right-thumb deadzone.

Applying the threshold independently creates axial component suppression:

```text
|X| < 8689 -> output X = 0, even when Y remains live
|Y| < 8689 -> output Y = 0, even when X remains live
both true   -> the complete stick vector is zero
```

The vertical band suppresses the X component and the horizontal band suppresses
the Y component. Their overlap is a square fully-dead center. Near-center
diagonals outside that overlap can lose one component and snap toward a cardinal
direction.

Microsoft's XInput sample instead computes stick-vector magnitude, compares
that magnitude to a deadzone, and rescales the remaining magnitude. That is a
radial treatment and is the appropriate baseline for a modern configurable
curve:
[XInput deadzone example](https://learn.microsoft.com/en-us/windows/win32/xinput/getting-started-with-xinput).

Controller look references `iXenonHorizLookAccel` (`0x011E0A90`),
`iXenonVertLookAccel` (`0x011E08A0`), `fXenonMinLookSpeed` (`0x011E0818`), and
additional look values at `0x011E0928` and `0x011E08B8`. Stewie Tweaks'
`SmootherControllerAiming.cpp` patches `0x0094591F` and `0x0094593F` to retain
non-normalized X/Y deltas, corroborating poor native curve behavior. The native
controller route does use a time argument later, so this evidence does not
justify a blanket claim that all controller sensitivity is FPS-dependent.

### Triggers and device mixing

Trigger codes `0x10` and `0x11` treat any current byte greater than zero as
held, with current/previous comparison for edges. There is no native trigger
threshold. Small device noise can therefore become a logical press.

`ControllerTriggerDeadzones.cpp` in the Stewie snapshot hooks `0x00A2469C` and
adds independent left/right thresholds. `AllowControllerMovementWithKeyboardConnected.cpp`
patches player device predicates around `0x00941118` through `0x009413B5`.
`ActivateSwapsInputDevice.cpp` hooks the normal sampler call site near
`0x0086F397` and switches active device from mouse click or controller A. These
implementations independently corroborate vanilla trigger and mixed-device
limitations.

Only XInput user index zero is sampled by the proven XInput route. DirectInput
joysticks are enumerated separately, but the final action layer still exposes a
mode-selected, low-dimensional controller state rather than modern per-device
identity, stable hotplug routing, simultaneous-device actions, or user-specific
controller assignment.

## Focus, menus, and known device-state defects

Foreground cooperative levels mean the devices can become unacquired when the
window loses focus. The sampler attempts acquisition each time and clears
current state on failure. Consequences include synthetic releases, lost
transitions during the gap, and different first-frame behavior after focus
returns.

The native setup has separate startup and focus-reacquire cooperative-level
sites. This explains why changing only initialization can appear to work until
the first alt-tab. xNVSE's optional patch explicitly calls out that mismatch.

Other corroborated native defects include:

- `EscapeResetsKeybinds.cpp` uses `GetAsyncKeyState` because Escape is not read
  normally in the relevant action-mapping path while a controller is connected.
- `NoPipboyOnAltTab.cpp` prevents alt-tab from opening or closing the Pip-Boy.
- gameplay snapshot handling and buffered menu/focus handling do not share
  equivalent temporal semantics.
- vanilla's mode gate can reject otherwise valid keyboard/mouse activity while
  the controller UI mode is active, or present the wrong glyph/device mode
  until a specific input switches it.

These are player-visible input correctness issues, not merely menu polish:
focus and mode transitions can create or suppress gameplay actions.

## Proton/Wine input transport

The executable itself does not call Raw Input. Current Wine source, however,
sets `use_raw_input = TRUE` for DirectInput 8 keyboard and mouse devices. Its
mouse raw-input hook accumulates relative `lLastX/lLastY`, and DirectInput
`Poll` services the queued input events. Its keyboard raw-input hook maps scan
codes into DirectInput device state, and keyboard `Poll` services events as
well. Primary source:

- [Wine DirectInput mouse implementation](https://raw.githubusercontent.com/wine-mirror/wine/master/dlls/dinput/mouse.c)
- [Wine DirectInput keyboard implementation](https://raw.githubusercontent.com/wine-mirror/wine/master/dlls/dinput/keyboard.c)

This establishes current Wine behavior, not the exact installed Proton build.
The deployed Proton/Wine revision must be captured before relying on a detail of
Wine master.

The practical deduction is important: on such a stack, changing Fallout's API
name from DirectInput to Raw Input does not automatically change when the game
samples state. It may add device identity or different configuration control,
but it cannot remove the once-render-frame action snapshot unless the engine
boundary is changed too.

## Where input delay comes from

End-to-end visible latency is a pipeline, not one setting:

```text
L_visible = L_device
          + L_until_game_sample
          + L_sample_to_present_cpu
          + L_gpu_or_translation_queue
          + L_present_vblank_compositor
          + L_scanout_display
```

### 1. Device and compatibility-runtime delivery

The mouse, keyboard, or controller reports at its own cadence. The OS and
Proton/Wine translate or accumulate those reports for DirectInput/XInput.
This portion varies with hardware, USB/Bluetooth mode, polling rate, runtime
version, and scheduler behavior. The executable alone cannot yield an exact
number.

### 2. Wait until Fallout's frame sample

The top-level frame function is `0x0086E650`. It calls the normal input helper at
`0x0086E88C`; the helper calls `0x00A23010` at `0x0086F39E`. With one sample per
rendered frame, an event just before sampling can affect that frame, while one
just after waits almost a full frame.

For uniformly distributed arrival within a stable frame of duration `T`, this
sampling contribution alone averages `T/2` and approaches `T` in the worst
phase:

| Render rate | Frame time | Average sample wait | Worst phase, nearly |
|---:|---:|---:|---:|
| 30 FPS | 33.33 ms | 16.67 ms | 33.33 ms |
| 60 FPS | 16.67 ms | 8.33 ms | 16.67 ms |
| 120 FPS | 8.33 ms | 4.17 ms | 8.33 ms |
| 144 FPS | 6.94 ms | 3.47 ms | 6.94 ms |

Unstable frame pacing increases both variability and the long-tail wait even
when average FPS appears adequate. NVTF's local source uses high-resolution
timing fixes and optional presentation changes, which can improve cadence
indirectly, but it does not replace Fallout's native input snapshot.

### 3. Sample-to-presentation CPU work

The proven frame order is:

1. `0x0086E88C -> 0x0086F390 -> 0x00A23010` samples devices.
2. player, camera, world, AI, and render preparation continue.
3. `0x0086EDE8 -> 0x0086FF70` enters display/presentation work.
4. `0x0087055E` reaches xNVSE's `OnFramePresent` hook and then native
   `0x00B6B730`.
5. native renderer vtable slots `+0x180/+0x184` perform the final presentation
   state machine.

Everything between steps 1 and 4 adds sample-to-present CPU time. This is the
specific engine-side source of the familiar feeling that input is "early in the
frame." It is not proof of an extra buffered frame.

### 4. Presentation interval and queues

The executable contains `iPresentInterval:Display`. Direct3D 9 presentation
parameters define whether presentation waits for vertical retrace; interval
one waits for a retrace, while immediate permits updates without that wait:
[`D3DPRESENT_PARAMETERS`](https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dpresent-parameters),
[`D3DPRESENT_INTERVAL`](https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dpresent).

GPU work and translation/runtime presentation can queue. The D3D9Ex API, for
example, documents a default maximum frame latency of three for that API, but
that number must not be projected onto Fallout's exact D3D9/Proton path without
measurement:
[`SetMaximumFrameLatency`](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9ex-setmaximumframelatency).

Current DXVK exposes `d3d9.maxFrameLatency`, `d3d9.presentInterval`, and
`dxvk.latencySleep`. Its configuration explains that latency sleep assumes an
application samples input after the preceding `Present` returns. Fallout's
normal loop is compatible with that broad ordering, but the user's bundled
DXVK version and active values remain runtime facts:
[DXVK configuration reference](https://github.com/doitsujin/dxvk/blob/master/dxvk.conf).

Atom should not silently own D3D presentation. OMV and the installed runtime
already own graphics/presentation policy. An input option may describe and
measure the dependency, but any actual queue/present intervention belongs to
that subsystem and needs its own startup and compatibility proof.

### 5. Display scanout and perceived action response

VBlank phase, compositor, VRR, scanout direction, pixel response, and display
processing complete visible latency. Even a zero-queue game cannot remove them.

Finally, visible feedback may begin later than action acceptance. Fire-rate
gates, attack state, equip/reload state, VATS, animation transitions, camera
blend, and script work are downstream. To classify such a delay, telemetry must
record both the input/action acceptance frame and the consumer's state change.

## Comprehensive issue register

Severity here describes user impact and architectural risk, not a release
priority. "Proven" issues follow from native evidence. "Gap" means vanilla
lacks a facility expected by modern action systems; it is not always a bug.

| ID | Class | Evidence | User-visible effect | Correct ownership/direction |
|---|---|---|---|---|
| IN-01 | Proven | normal state sampled once per rendered frame | response cadence and jitter track frame cadence | late, once-per-frame action snapshot; timestamped capture for transitions |
| IN-02 | Derived from proven snapshots | only current/previous digital state retained | very short taps can disappear | capture buffered/timestamped transitions before collapse |
| IN-03 | Derived | multiple transitions collapse | double taps/order cannot be reconstructed | ordered event ring with bounded retention |
| IN-04 | Proven | mouse/wheel read as one accumulated state | motion timing coalesced; opposite wheel motion can cancel | preserve native X/Y total; capture wheel events discretely |
| IN-05 | Proven | immediate gameplay versus buffered menu/focus routes | same input can behave differently by context | one action semantic layer with explicit contexts |
| IN-06 | Proven | sample precedes the rest of simulation/render and Present | CPU work remains in sample-to-visible path | sample as late as safely possible before simulation; measure |
| IN-07 | Runtime-dependent | present interval, GPU/DXVK queue, compositor | one or more additional variable frames | presentation subsystem measurement and explicit policy |
| IN-08 | Proven | focus device failure clears current state | synthetic release/lost held state on alt-tab | explicit focus reset/resync without action generation |
| IN-09 | Proven | foreground/exclusive/NOWINKEY branches and separate reacquire sites | blocked system keys/background input inconsistency | existing window-input owner; transactional patch of all owned sites |
| IN-10 | Proven | mouse look shares `fMouseSensitivity` | no independent X/Y sensitivity | MCM Extender axis values, applied in action/camera transform |
| IN-11 | Proven | camera-specific scaling after shared sensitivity | inconsistent cm/360 across camera/aim contexts | opt-in normalized context scales with compatibility defaults |
| IN-12 | Proven negative evidence | no actor-look smoothing or acceleration found | common INI advice targets the wrong subsystem | do not add a fake fix; expose only evidenced transforms |
| IN-13 | Proven | `fForegroundMouse*` and Control Panel sensitivity are UI-only | menu cursor and look feel diverge; myth-driven tuning | configure UI cursor and actor look separately |
| IN-14 | Corroborated/proven sites | vanity camera wrap/clamp sites | abrupt or incorrect vanity rotation | focused camera-consumer fix |
| IN-15 | Proven | independent X/Y threshold of 8689 | axial deadzone, diagonal loss, cardinal snap | radial deadzone with rescaling and optional anti-deadzone |
| IN-16 | Proven | controller acceleration/min-speed curve | difficult low-speed aiming and nonlinear feel | configurable monotonic curve with preview/behavioral checks |
| IN-17 | Proven | triggers activate at any value above zero | accidental aim/fire from trigger noise | independent press/release thresholds, preferably hysteresis |
| IN-18 | Proven | controller mode byte gates controller query | no seamless simultaneous devices | merge logical actions; use last-active device only for glyphs |
| IN-19 | Proven/corroborated | controller-connected Escape/action map paths | Escape or rebinding can fail/reset unexpectedly | device-independent menu commands and explicit cancel action |
| IN-20 | Corroborated | Alt-tab/Pip-Boy consumer fix exists | focus transition can toggle Pip-Boy | suppress focus-generated transitions at consumer boundary |
| IN-21 | Proven | XInput user index zero only | limited controller assignment/hotplug semantics | explicit device selection only if runtime contract is proven |
| IN-22 | Proven | one-byte, one-bind-per-action schema | no alternate binds or chords | overlay action map outside native schema; mirror compatibility bind |
| IN-23 | Proven | only 28 native actions | missing actions and fixed categories | extensible Atom action IDs without plugin-form dependence |
| IN-24 | Proven | ID 18 is Ammo Swap; no Hotkey2 | inaccessible second native item hotkey | focused compatibility restoration |
| IN-25 | Proven | no source-device identity; limited mouse buttons | multi-mouse and extended-button inputs unavailable | optional modern device backend only with preservation proof |
| IN-26 | Proven | DirectInput scan-code keyboard model | weak layout-aware labels/text/accessibility presentation | separate physical binding and localized display identity |
| IN-27 | Proven | action consumers are fragmented | global suppression can leak or leave stale consumer state | per-consumer adapters until complete boundary is proven |
| IN-28 | Proven/corroborated | prevented attack can remain remembered | weapon fires after suppression is removed | clear/bypass the consumer's remembered attack state |
| IN-29 | Modern gap | no timestamped action/event stream | no deterministic ordering or accurate tap duration | bounded monotonic timestamps and frame association |
| IN-30 | Modern gap | no general input-buffer/grace facility was found in the input/action layer; consumer-specific behavior is not ruled out | jump/activate/weapon actions can remain unforgiving near state boundaries | per-action configurable buffer only after consumer proof |
| IN-31 | Modern gap | no general movement grace facility was found; individual movement consumers still require research | frame-edge acceptance may be unnecessarily strict | gameplay-owned grace windows, never global transport hacks |
| IN-32 | Modern gap | no full remap/hold-toggle alternatives | accessibility and preference limitations | MCM action remap, hold/toggle choice, conflict reporting |
| IN-33 | Modern gap | no independent stick X/Y invert controls | incomplete camera customization | independent X/Y inversion for each relevant stick/context |
| IN-34 | Modern gap | no calibration UI | drift/deadzone tuning requires external edits/mods | MCM live values and non-destructive reset defaults |
| IN-35 | Modern gap | no late-latch or decoupled input update | simulation/render stalls increase response | do not promise until thread/renderer ownership is proven |
| IN-36 | Runtime-dependent | Wine/DXVK implementation and settings vary | mod-list/machine-dependent latency | capture versions/config in diagnostics, avoid version assumptions |
| IN-37 | Design risk | a second relative mouse read can consume/split delta | lost/doubled camera input and wrapper incompatibility | observe/transform the existing snapshot, not a blind repoll |
| IN-38 | Design risk | generic D3D changes would cross Atom/OMV ownership | startup and renderer conflicts | keep presentation fixes in OMV/runtime owner |

Microsoft's current Xbox accessibility guidance provides a useful acceptance
baseline: all gameplay actions should be remappable across input types; camera
axes should support independent inversion; and alternatives should exist for
holds, rapid presses, and simultaneous inputs. See
[XAG 107: input](https://learn.microsoft.com/en-us/xbox/accessibility/xbox-accessibility-guidelines/107)
and
[XAG 117: camera motion](https://learn.microsoft.com/en-us/xbox/accessibility/xbox-accessibility-guidelines/117).
GameInput's modern reading model also demonstrates timestamps as a first-class
part of input history:
[`IGameInputReading`](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/input/gameinput/interfaces/igameinputreading/igameinputreading),
[`GetTimestamp`](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/input/gameinput-v2/interfaces/igameinputreading/methods/igameinputreading_gettimestamp-v2).

These references define a quality target. They do not require Atom to replace
the installed OS backend or to claim certification.

## Misdiagnoses to avoid

1. **"Foreground mouse acceleration causes actor look acceleration."** False
   for the inspected executable. Those settings feed `InterfaceManager` cursor
   math, not player camera look.
2. **"Vanilla smooths mouse look in a hidden buffer."** No such buffer was
   found in the actor-camera route. The frame snapshot coalesces event timing,
   which can feel different from smoothing but is not the same mechanism.
3. **"Mouse sensitivity is multiplied incorrectly by frame time."** The direct
   relative mouse route was not found to multiply its deltas by frame time.
4. **"DirectInput alone is the input delay."** Current Wine already backs its
   DirectInput 8 devices with Raw Input. Fallout still samples only once per
   normal rendered frame.
5. **"There is always one extra action-buffer frame."** No generic post-sample
   action queue was found. Presentation may queue frames, and individual
   gameplay consumers may wait, but those are separate claims.
6. **"Higher polling rate fixes everything."** It can reduce device-report
   delay, but it does not remove the wait to Fallout's frame sample or the work
   and presentation after that sample.
7. **"A second poll later in the frame is harmless."** It can split relative
   mouse accumulation and change what vanilla or xNVSE sees.
8. **"NVTF is an input rewrite."** Its timing/presentation work can improve
   frame pacing, but its local source does not replace the native action
   snapshot.

## Atom design contract

Atom's eventual input module should remain ESP-less and form-agnostic. The
input layer deals in devices, logical actions, camera/movement values, and
engine capability boundaries; it must not enumerate a fixed list of weapon,
NPC, or plugin forms to decide whether input works.

The implementation proposal derived from this contract is
[atom_input_wrapper_design.md](atom_input_wrapper_design.md).

### Responsibility split

| Owner | Responsibility |
|---|---|
| native/xNVSE wrapper | acquire devices and preserve compatibility-visible state |
| Atom input capture | observe one authoritative snapshot/event stream and assign timestamps |
| Atom action layer | bind, merge devices, resolve contexts/conflicts, produce edges/holds |
| Atom gameplay consumers | optional action buffers, grace periods, suppression cleanup |
| Atom camera/control transforms | mouse axes, stick radial deadzone/curve, triggers |
| MCM Extender | configuration, reset/defaults, conflict/calibration presentation |
| Psycho window input | focus/cursor/system-key policy |
| OMV/DXVK/runtime | presentation interval, queue/latency policy |

No custom ImGui menu should own Atom configuration. Every user-facing input
option belongs in MCM Extender, consistent with Atom's project contract.

### Minimum invariants

- Preserve the exact native snapshot seen by vanilla and xNVSE unless a feature
  explicitly owns and behaviorally validates a transformed action.
- Never infer lost transitions from current/previous state. Capture them before
  collapse or report that the backend cannot provide them.
- Keep timestamps monotonic and bound storage. No allocation, file I/O,
  blocking lock, or logging belongs in the per-frame input hot path.
- Focus loss clears internal pending actions without generating gameplay
  presses or releases. Reacquisition begins from a neutral synchronized state.
- Controller and keyboard/mouse may contribute simultaneously. Last-active
  device affects glyph/presentation only, not whether the other device works.
- Use a radial stick deadzone, rescale its remaining range, and keep the curve
  continuous and monotonic. Independent axis scale/invert happens after radial
  treatment.
- Trigger press and release thresholds must reject noise; hysteresis prevents
  flicker near the boundary.
- Action buffering is per action and per consumer. A buffered jump must not
  become a buffered attack; menus and focus transitions clear inappropriate
  pending actions.
- Suppression owns downstream remembered state. The prevented-attack evidence
  is the model for why merely returning false from an early query is unsafe.
- Existing native binds remain a compatibility surface. Extended bindings may
  mirror a primary native binding but must not corrupt `FalloutPrefs.ini` or
  silently steal another action.
- Hook admission uses the supported executable fingerprint and owned
  signatures/capabilities. Never detect or patch a third-party mod by name.
- Atom does not change D3D presentation, DXVK configuration, or OMV state.

### Safe native boundary

The proven normal boundary is the call to `0x00A23010` at `0x0086F39E` inside
`0x0086F390`. An eventual action snapshot may run after the native sample and
before player consumers. That boundary alone does not solve missed subframe
taps: a timestamped/buffered transition source must exist earlier than the
collapse.

Any proposal to sample later must prove:

- what work occurs between the new sample point and every player consumer;
- that mouse relative state is read exactly once or deliberately forwarded;
- that xNVSE `GetDeviceState`/`GetDeviceData` wrappers keep their ABI and
  observation order;
- that menus, console, movies, focus, and blocking paths retain their required
  samples;
- that no input is sampled under loader lock or before safe xNVSE lifecycle;
- that the change does not cross into OMV's presentation ownership.

## Behavioral validation plan for future implementation

Repository policy rejects source-text, manifest, and call-order tests. Input
work should therefore use high-value behavioral or artifact checks only where
they can reject a real regression.

### Deterministic behavioral checks

- Feed timestamped digital transitions containing press/release inside one
  render interval. The action layer must emit both in order exactly once.
- Feed multiple transitions and verify order, duration, bounded retention, and
  context routing.
- Feed radial stick vectors across every angle near the deadzone. Output must
  be continuous, preserve direction outside the center, and remain bounded.
- Feed trigger noise around thresholds. Verify hysteresis and exactly one press
  and release per deliberate crossing.
- Interleave mouse, keyboard, and controller actions. All remain active while
  glyph ownership follows the defined last-active policy.
- Enter focus loss with held and buffered actions, then reacquire. No synthetic
  gameplay action or stale buffer may escape.
- Suppress and release automatic attack. No remembered `ForceFireWeapon` action
  may fire afterward.
- Round-trip MCM-owned values through their real configuration interface and
  verify defaults, bounds, and unknown-field preservation where the format
  requires it.

These checks should exercise public behavior or the built DLL/config artifact,
not search source code for expected strings or implementation order.

### Runtime latency capture

A load-to-gameplay capture is required before calling any latency feature safe
or effective. Record:

- Fallout executable hash;
- xNVSE, Proton/Wine, DXVK, NVTF, OMV, and overlay versions;
- effective presentation interval, frame limiter, DXVK latency options, VRR,
  compositor, refresh rate, and window mode;
- device model/connection/report rate;
- timestamp of raw/buffered event arrival if available;
- timestamp of `0x00A23010` completion and Atom action publication;
- timestamp of the relevant player consumer accepting the action;
- `OnFramePresent`, runtime Present return, and an external high-speed-camera or
  photodiode-visible response where practical.

Test stable 30/60/120/144 FPS, an intentionally uneven frame-pacing case,
VSync on/off where supported, focus transitions, overlays, menu/gameplay
boundaries, high-rate mouse motion, subframe taps, low-stick diagonals, trigger
noise, and simultaneous controller/keyboard use.

The acceptance decision must separate:

1. event-to-sample latency;
2. sample-to-action acceptance;
3. action-to-Present;
4. Present-to-visible response.

Without this separation, a weapon animation wait can be mistaken for input
transport, and a presentation queue can be mistaken for an action buffer.

## Performance and memory budget

The native sampler copies 256 keyboard bytes, 20 mouse bytes, and a small
controller state once per frame. A future Atom layer should remain the same
order of cost:

- fixed-capacity event storage sized from a measured worst case;
- no heap allocation in capture, publication, or query paths;
- no blocking mutex in frame or input callbacks;
- constant-time action lookup for the normal 28 native actions and Atom's own
  bounded extension;
- logging limited to opt-in, rate-limited diagnostics outside the hot path;
- configuration parsing and MCM synchronization outside input capture.

If buffered DirectInput is introduced, buffer overflow must be explicit and
observable. Silent loss followed by guessed edges is unacceptable. Failure
should leave vanilla input operational and disable only the unavailable Atom
capability.

## Proven facts, design inference, and unverified runtime behavior

### Proven for the supported executable

- DirectInput keyboard/mouse ownership, cooperative levels, state offsets, and
  immediate sampler.
- XInput user-zero sample and controller-mode gate.
- current/previous query semantics and buffered keyboard side route.
- 28-entry binding schema and action identities.
- PlayerCharacter consumer sites and disabled-control byte.
- actor mouse-look axes, sensitivity/inversion route, and UI-only ownership of
  `fForegroundMouse*`.
- axial right-stick threshold and zero-threshold triggers.
- input-before-presentation ordering and xNVSE final-present boundary.

### Reasoned design conclusions

- subframe digital events can disappear and several events can collapse;
- radial deadzones, trigger hysteresis, timestamped events, and simultaneous
  devices are appropriate corrections;
- an action layer after the native sample is a useful transform boundary but
  cannot recover already-collapsed transitions;
- presentation policy must remain outside Atom.

### Still requiring runtime observation

- exact installed Wine DirectInput and XInput behavior;
- exact active DXVK queue, interval, and latency configuration;
- end-to-end delay in each window/VSync/VRR/limiter state;
- device-specific noise, report cadence, and hotplug behavior;
- whether a reported delayed action is transport, action acceptance, animation,
  weapon state, scripting, rendering, or presentation;
- compatibility of any future intervention with the user's complete mod stack.

## Evidence index

Native and established local evidence:

- [focused radare2 address ledger](../analysis/radare2/output/perf/fnv_actor_input_contract.txt)
- [window input policy](window_input_policy.md)
- [window input radare2 evidence](../analysis/radare2/output/perf/window_input_policy_contract.txt)
- [established display/message/input audit](../analysis/ghidra/output/perf/display_message_input_contract_audit.txt)
- [Psycho dashboard and final presentation boundary](psycho_dashboard.md)
- [`GameOSDepend.h`](../libnvse/xnvse/nvse/nvse/GameOSDepend.h)
- [`Hooks_DirectInput8Create.cpp`](../libnvse/xnvse/nvse/nvse/Hooks_DirectInput8Create.cpp)
- [`Commands_Input.cpp`](../libnvse/xnvse/nvse/nvse/Commands_Input.cpp)
- [`Hooks_Gameplay.cpp`](../libnvse/xnvse/nvse/nvse/Hooks_Gameplay.cpp)
- [`PluginAPI.h`](../libnvse/xnvse/nvse/nvse/PluginAPI.h)
- [`GameObjects.h`](../libnvse/xnvse/nvse/nvse/GameObjects.h)
- [`nvse.cpp`](../libnvse/xnvse/nvse/nvse/nvse.cpp)
- [NVTF timing source](../.research/New-Vegas-Tick-Fix-master/nvtf/internal/TickFix.cpp)
- [NVTF D3D source](../.research/New-Vegas-Tick-Fix-master/nvtf/internal/D3DHooks.cpp)

Read-only corroborating Stewie Tweaks source is under
`.research/Stewie Tweaks 10.00 Source/`. Relevant files include
`SmootherControllerAiming.cpp`, `ControllerTriggerDeadzones.cpp`,
`AllowControllerMovementWithKeyboardConnected.cpp`,
`ActivateSwapsInputDevice.cpp`, `EscapeResetsKeybinds.cpp`,
`TwoHotkeyRestored.cpp`, `SeparateHorizontalVerticalSensitivity.cpp`,
`VanityCamRotationFix.cpp`, and `NoPipboyOnAltTab.cpp`. These snapshots are not
patched or built.

Primary platform references:

- [DirectInput immediate state](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee417897%28v%3Dvs.85%29)
- [DirectInput buffered events](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee417894%28v%3Dvs.85%29)
- [DirectInput event record](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee416611%28v%3Dvs.85%29)
- [DirectInput cooperative levels](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee416848%28v%3Dvs.85%29)
- [Raw Input overview](https://learn.microsoft.com/en-us/windows/win32/inputdev/about-raw-input)
- [XInput state and deadzone guidance](https://learn.microsoft.com/en-us/windows/win32/xinput/getting-started-with-xinput)
- [Direct3D 9 presentation parameters](https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dpresent-parameters)
- [Xbox accessibility input guideline](https://learn.microsoft.com/en-us/xbox/accessibility/xbox-accessibility-guidelines/107)
- [Xbox accessibility camera guideline](https://learn.microsoft.com/en-us/xbox/accessibility/xbox-accessibility-guidelines/117)
- [Wine DirectInput mouse source](https://raw.githubusercontent.com/wine-mirror/wine/master/dlls/dinput/mouse.c)
- [Wine DirectInput keyboard source](https://raw.githubusercontent.com/wine-mirror/wine/master/dlls/dinput/keyboard.c)
- [DXVK configuration reference](https://github.com/doitsujin/dxvk/blob/master/dxvk.conf)

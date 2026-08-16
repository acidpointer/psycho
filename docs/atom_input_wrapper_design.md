# Atom input wrapper design

## Implementation status (2026-08-16)

Stages 0 through 3 are implemented as an opt-in playtest build. Atom captures
the post-xNVSE sample, publishes coherent device and 28-action frames, records
bounded latency/heading telemetry, and applies direct mouse and radial
controller transforms at the proven player boundaries.

`Fallout 4 Direct` now uses the supplied game's nominal
`0.0300 * 0.021 = 0.00063` heading scale at FNV's final float heading calls.
The value is a documented radians-per-count inference, not a claim that every
Fallout 4 camera context is identical. `Direct` instead scales FNV's native
final heading, while `Native` remains exact float passthrough.

Controller output is published only after a physically neutral handoff. Four
player-camera deadzone calls and three curve setting calls are dynamically
bypassed only while that output is active. The action layer merges keyboard,
mouse, and controller bindings, tracks focus epochs and menu context, and
prevents held controls from becoming presses after a context boundary.

The keyboard bridge drains the chained xNVSE-aware 32-event buffer once per
enabled gameplay sample, retains ordered events for Atom, and mirrors them to
later native `GetDeviceData` consumers with peek and overflow semantics. A
frame-phase gate prevents the shared bound-action adapter from replaying a
preceding batch inside FNV's own sample maintenance.

Stage 4 research is complete and rejects a production late-sample patch for
this executable. The direct sampler is coupled to post-sample controller and
28-control maintenance inside `0x0086F390`; moving the whole helper would cross
unproven menu/UI/world consumers between `0x0086E88C` and `0x0086EC98`.
Atom therefore keeps native sample placement. Stage 5 remains optional and is
not implemented because stages 1-3 do not require Raw Input takeover.

Configuration is MCM-owned `Atom.ini`, deserialized read-only through Serde and
`serini`. Diagnostics use Psycho's established asynchronous logger; there is no
custom ImGui UI or subsystem-owned telemetry file.

The 2026-08-16 runtime stack changes the broadly shared `MenuMode` entry at
`0x00702360` before Atom's deferred callbacks. Atom Input originally continued
to call that mutable entry even after both camera owners had moved to the
proven InterfaceManager state. Input now validates global slot `0x011D8A80`
and classifies context directly as `manager != null && active(+0x00) != 0 &&
mode(+0x0C) != 1`. This is the complete side-effect-free native policy, avoids
executing an unknown replacement, and keeps the action context consumed by the
third-person owner consistent with both camera hard gates.

## Decision

Atom should implement an **engine-semantic input wrapper**, not an operating
system input replacement in its first release.

The wrapper will sit after xNVSE's existing DirectInput processing and before
Fallout: New Vegas player/action/camera consumers. It will preserve vanilla and
xNVSE-visible device state, publish one coherent action snapshot, apply a
direct Fallout 4-inspired mouse-to-heading transform, correct controller
curves, and optionally move the normal gameplay sample later only after the
intervening native consumers have been proven.

It must not:

- ship another `dinput8.dll` or change Syringe's generic proxy;
- independently register keyboard/mouse Raw Input as an ordinary plugin;
- call the relative mouse device twice per frame;
- add smoothing, interpolation, or a mandatory action-delay queue;
- change DXVK, D3D9, OMV, VSync, or presentation policy;
- assume every perceived delayed action is an input-transport defect;
- use an ESP, form list, plugin-name compatibility check, or custom ImGui menu.

This design can remove all avoidable delay owned by Atom's input and player
control boundary. It cannot remove hardware report time, display scanout,
runtime/GPU presentation queues, or an intentional weapon/animation gate. Those
parts must be measured and fixed by their actual owner.

## Why the Fallout 4 comparison is useful

The user's observation is credible even though it is subjective. Equal FPS does
not imply equal latency or equal control feel. Two games at 60 FPS can differ in
when they sample input, how much CPU work follows the sample, queue depth,
camera transfer function, animation feedback, and frame-time variance.

The supplied Fallout 4 GOG 1.10.163 executable provides concrete differences:

| Area | Fallout: New Vegas | Fallout 4 GOG 1.10.163 |
|---|---|---|
| OS keyboard/mouse API | DirectInput 8 immediate state | direct foreground Raw Input |
| Mouse packet handling | relative `DIMOUSESTATE2` sampled once in normal frame | `WM_INPUT` packets accumulated into a PC mouse device |
| Action representation | 28 fixed one-byte bindings and current/previous queries | typed input events, named actions, handlers, and contexts |
| Mouse controls | one actor-look sensitivity plus camera-specific scale | sensitivity, separate X/Y heading scales, and a normalize limit |
| Graphics path | D3D9 | D3D11/DXGI |

The direct Fallout 4 evidence is preserved in
[fallout4_gog_input_comparison.txt](../analysis/radare2/output/perf/fallout4_gog_input_comparison.txt).
The complete FNV contract remains
[fnv_actor_input_contract.md](fnv_actor_input_contract.md).

These facts make a more coherent event and heading pipeline a plausible reason
for the reported feel. They do not prove a specific millisecond advantage. The
current Fallout 4 event-build-to-Present order and the user's actual Proton/DXVK
pipeline still need controlled telemetry.

## Why Atom must not simply copy Fallout 4's Raw Input registration

Microsoft documents that only one window per raw-input device class can be
registered within a process. The last registration wins, and Microsoft
explicitly warns libraries not to call `RegisterRawInputDevices` because doing
so can interfere with the host application's input:
[RegisterRawInputDevices](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerrawinputdevices).

That warning is directly relevant under Proton. Current Wine implements
DirectInput 8 keyboard and mouse devices using Raw Input internally. Atom
registering the same keyboard/mouse classes can displace the Wine DirectInput
registration on which FNV and xNVSE depend.

An authoritative Raw Input backend would therefore have to replace, not merely
supplement, the complete native contract:

- `GetDeviceState` for keyboard and relative mouse state;
- `GetDeviceData`, including peek, overflow, timestamps, and xNVSE injection;
- acquisition, cooperative level, focus loss, and reacquisition;
- scan-code mapping, swapped buttons, wheel, and eight mouse buttons;
- all xNVSE input commands and any plugin that observes the wrapped COM device;
- console, menu, movie, blocking, and normal-gameplay paths.

That is possible as a later independently reviewed backend, but it is not the
safe first step toward better mouse feel.

## Product name and ownership

The subsystem should be called **Atom Input**. Its internal boundary can be
named `InputPipeline`; it should not be called a Raw Input mod because the
default backend deliberately retains native DirectInput ownership.

Proposed source ownership when implementation begins:

```text
atom/src/input/
|-- mod.rs            lifecycle, admission, and public snapshot
|-- native.rs         supported-executable addresses and native-state adapter
|-- buffered.rs       fixed-capacity keyboard capture and native mirror
|-- actions.rs        contexts, bindings, edges, holds, and optional buffers
|-- mouse.rs          direct heading transform and camera context
|-- controller.rs     stick and trigger transforms
|-- telemetry.rs      bounded QPC markers and out-of-hot-path summaries
`-- hooks.rs          transactional hooks and rollback
```

`atom/src/lib.rs` should continue to own only xNVSE lifecycle admission. No
engine hook or WinAPI work belongs in `NVSEPlugin_Load`; engine-facing startup
remains at xNVSE `DeferredInit`.

Reusable WinAPI operations must be safe wrappers in
`libpsycho::os::windows::winapi`. Atom must not call WinAPI directly. Adding
`libpsycho` or new final-DLL imports changes Atom's loader-visible baseline and
requires the repository startup-safety process before implementation.

## Pipeline architecture

```text
native DirectInput/XInput devices
            |
            v
xNVSE FakeDirectInputDevice
  injection, hold/tap, disable, buffered compatibility
            |
            v
FNV 0x00A23010 native sample
            |
            +----------> unchanged native OSInputGlobals state
            |                     |
            v                     v
Atom CaptureSnapshot       vanilla/menu/console compatibility
            |
            v
Atom ActionResolver -----> per-consumer action adapters
            |
            +-----------> Atom MouseHeading -> player camera/aim consumer
            |
            `-----------> Atom ControllerCurve -> player movement/look
```

The key rule is **one authoritative relative-mouse read**. Atom copies the
already-produced post-xNVSE mouse delta. It never calls `GetDeviceState` again
in the same frame merely to be later.

### Layer 1: native snapshot adapter

Immediately after the supported normal call to `0x00A23010`, Atom copies:

- the 256-byte current and previous keyboard states;
- current and previous `DIMOUSESTATE2`;
- XInput current and previous state;
- the native controller-mode state;
- focus and menu/player-control context needed by the action resolver.

The copy is small and fixed-size. It performs no allocation, I/O, logging, or
blocking synchronization. Keyboard and mouse arrays remain unchanged.
Controller current state changes only after the neutral activation policy has
admitted Atom's processed output.

Atom consumes post-xNVSE state rather than bypassing the xNVSE wrapper. This
preserves `TapKey`, held/injected keys, disabled controls, script-visible state,
and any established wrapper ordering.

### Layer 2: captured input frame

The published immutable frame should conceptually contain:

```text
InputFrame
  frame_id
  sampled_qpc
  focus_epoch
  context
  keyboard_down[256]
  keyboard_pressed[256]
  keyboard_released[256]
  mouse_delta_x, mouse_delta_y, wheel_delta
  mouse_down[8], mouse_pressed[8], mouse_released[8]
  controller_raw
  controller_processed
  overflow/error flags
```

Use double-buffered or sequence-guarded fixed storage. The game thread publishes
exactly once for a normal gameplay frame. Readers receive either the prior
complete frame or the new complete frame, never partially written fields.

No field uses wall-clock time. QPC is the monotonic diagnostic clock; native
DirectInput buffered timestamps remain supplemental evidence in their original
millisecond domain.

### Layer 3: action resolver

The action resolver converts device state into named logical actions. It must
support both the 28 vanilla actions and Atom-owned actions without modifying a
form or consuming a load-order slot.

Each implemented action exposes:

- `down`;
- `pressed`;
- `released`;
- held duration;
- source device;
- source binding;
- whether an edge came from the buffered keyboard bridge;
- per-source controller edges;
- native bindings plus frame context/focus epoch.

Simultaneous keyboard/mouse and controller input is allowed. "Last active
device" controls MCM/UI glyph presentation only; it never disables the other
device.

The currently proven context classifier publishes `Gameplay`, `Menu`, and
`Unfocused`. `Menu` reproduces native `MenuMode` from InterfaceManager active
byte `+0x00` and mode `+0x0C`; it does not call the mutable shared helper entry.
Atom does not falsely infer a more specific console, dialogue, VATS, Pip-Boy,
or remapping identity from that coarse result. Those native consumers remain
authoritative. A focus epoch or coarse-context change invalidates action edges
and suppresses physically held controls until release.

### Layer 4: player-consumer bridge

FNV does not have one complete high-level action queue. Atom therefore needs
two kinds of bridge:

1. a shared bound-control adapter for consumers that use `0x00A24660`;
2. focused adapters for proven exceptional consumers such as attack,
   remembered automatic fire, run, aim, reload, wait, and camera look.

The implemented shared adapter chains `0x00A24660` and supplements only
ordered buffered-key edges or processed controller direction/edge results.
Native nonzero results always win, control 14 retains its native menu side
effect, and non-gameplay contexts pass through. Exceptional attack, automatic
fire, reload, wait, and other remembered-state consumers are not suppressed or
buffered. Disabling Atom Input returns keyboard/action handling immediately and
controller output at the next neutral frame.

The xNVSE prevented-automatic-attack fix is the model: rejecting an early query
is insufficient if a downstream consumer remembers an attack. Each buffered or
suppressed action must define how its consumer state is cleared.

## Fallout 4-inspired mouse profile

The desired result is not a cosmetic sensitivity preset. It is a direct,
predictable camera response with early visible motion and no added history.

### Required behavior

- Consume the native relative X/Y delta exactly once.
- Apply no moving average, interpolation, low-pass filter, acceleration, or
  frame-time multiplication.
- Preserve small one-count movement; no artificial mouse deadzone.
- Use independent horizontal and vertical scales.
- Support independent X and Y inversion.
- Keep a stable base degrees-per-count relationship across frame rates.
- Apply explicit camera-context multipliers for hip, aim, scope, first person,
  and third person rather than accepting undocumented native variation.
- Keep interface cursor behavior native. `fForegroundMouse*` and Control Panel
  sensitivity remain menu-cursor concerns.
- Clamp only pathological accumulated deltas after a stall/focus transition;
  normal high-speed flicks must not be flattened.

### Proposed transform

For an ordinary gameplay frame:

```text
heading_x = delta_x * base_sensitivity * x_scale * context_x
heading_y = delta_y * base_sensitivity * y_scale * context_y * invert_y
```

There is deliberately no `delta_time` term. Relative mouse counts already
represent motion accumulated over the interval.

The transform should operate in documented camera-angle units. MCM can expose
a familiar sensitivity slider, but internally Atom should also support a
calibrated degrees-per-count value so the same mouse DPI produces a repeatable
cm/360.

### Fallout 4 calibrated preset

The preset is named `Fallout 4 Direct`, not `Exact Fallout 4`.

Its qualitative contract is:

- direct relative motion;
- independent `XScale` and `YScale` with a 1:1 default;
- no smoothing or acceleration;
- matching horizontal and vertical response after aspect/FOV-independent
  angular conversion;
- conservative per-context multipliers close to Fallout 4's observed feel.

The current Fallout 4 binary proves that
`fMouseHeadingSensitivity`, `fMouseHeadingXScale`,
`fMouseHeadingYScale`, and `fMouseHeadingNormalizeMax` exist. It does not yet
prove the exact normalize formula. The shipped installation's 0.0300
sensitivity and equal 0.021 axis scales provide the nominal 0.00063 product now
used at FNV's final float boundary. Atom does not copy a guessed normalize
formula. Behavioral camera-context equivalence still requires an A/B trace.

### Stall and focus protection

An unfocused, loading, or severely stalled frame can accumulate an abnormally
large relative delta. Atom should discard input across a focus epoch and may
cap only a delta classified as discontinuous by an explicit focus/loading/stall
rule. A simple maximum-count clamp on every frame would damage deliberate fast
mouse flicks and is rejected.

## Eliminating avoidable delay

### Delay class A: lost or collapsed digital transitions

FNV configures a 32-event DirectInput keyboard buffer but normally drives
gameplay from current/previous snapshots. Atom now drains the current chained
keyboard capability after each enabled normal sample and mirrors it for later
native/xNVSE `GetDeviceData` callers.

The live keyboard object's `GetDeviceData` vtable slot is chained by
capability, without identifying its owning module. Calls for every other COM
object go directly to the captured predecessor. The fixed mirror preserves:

- real and xNVSE-injected events;
- `DIGDD_PEEK` without consumption;
- event order, timestamp, sequence, and caller-requested count;
- `DI_BUFFEROVERFLOW` propagation;
- focus loss and reacquisition;
- menu/console drains after Atom already captured an event.

The newest 32 events are retained, matching FNV's configured bound. A non-NULL
peek is answered from the mirror after a non-peek predecessor drain because
xNVSE's current injected queue explicitly halts on that peek shape. Short
`try_lock` contention falls through to the predecessor and increments a bounded
health counter; the hook never blocks or logs in the input path.

The native mouse has no configured DirectInput event buffer. Phase one retains
snapshot button edges and accumulated relative motion. Adding a mouse buffer
or authoritative Raw Input backend is a separate compatibility project, not a
hidden part of the mouse-feel preset.

### Delay class B: sample phase within the game frame

FNV samples at `0x0086F39E` and later reaches player, world, render, and Present
work. The safe initial implementation records exact QPC markers but leaves the
sample in place.

The completed normal-frame audit considered **Late Gameplay Sample**:

1. suppress only the normal call at `0x0086F39E`;
2. invoke the native sampler exactly once at the latest proven point before the
   first normal player/action/camera consumer;
3. leave movie, blocking, focus, and other sampler call sites unchanged;
4. publish the Atom snapshot immediately after that deferred native call.

Admission failed safely. `0x0086F390` couples the sampler with `0x00A257C0` and
conditional `0x00A253D0` work. The main loop then crosses menu/interface and
world calls before the candidate `0x0086EC98` boundary. Moving only the sampler
reorders coupled maintenance; moving the helper crosses unproven consumers.
Atom retains `0x0086F39E` and does not expose a nonfunctional MCM toggle.

### Delay class C: camera feedback after action acceptance

Atom applies its heading transform at the latest proven camera/aim consumer
which remains before aim direction and camera matrices are finalized. It must
not late-latch only the rendered camera while leaving weapon aim, projectiles,
interaction ray, crosshair, or first-person body one frame behind.

Pure render-only late latching is rejected unless every dependent view/aim
consumer is updated coherently. A visually responsive camera with stale aim is
not correct input.

### Delay class D: action acceptance windows

Optional action buffering improves responsiveness around gameplay state
boundaries but also deliberately retains an action. It is not a global latency
fix and must never be silently enabled for every control.

Recommended initial policy:

| Action | Default buffer | Reason |
|---|---:|---|
| attack/fire | 0 ms | prevents unexpected delayed shots |
| aim/block | 0 ms | state should track the physical hold |
| activate | 0 ms | avoid interacting with a new target after turning |
| reload | 0 ms | consumer state needs separate proof |
| jump | 0 ms initially | enable only after movement/landing contract research |
| weapon hotkeys | 0 ms | avoid post-menu or post-animation surprise |

MCM may expose a per-action value only after its consumer behavior is proven.
Hardcore gameplay does not justify surprising queued combat inputs.

### Delay class E: frame pacing and presentation

Atom records sample-to-`OnFramePresent` time but does not own the remaining
queue. The supplied FNV installation currently has a custom DXVK configuration
with a 120 FPS D3D9 limit, presentation interval zero,
`dxvk.latencySleep = False`, low-latency frame pacing, and CPU-frame overlap
disabled. The Fallout 4 preferences use interval one and borderless mode. These
are not equivalent comparison conditions.

Current DXVK documents `d3d9.maxFrameLatency`, `d3d9.presentInterval`, and
`dxvk.latencySleep`, including the assumption that a game's input sample occurs
after the preceding Present returns:
[DXVK configuration](https://github.com/doitsujin/dxvk/blob/master/dxvk.conf).

Atom must not edit those values or stack a second limiter. It should expose a
diagnostic statement such as "presentation latency is externally owned" and
report its own measured sample-to-Present interval. OMV/runtime work can then
be evaluated independently.

## Controller behavior included in the wrapper

Although the immediate request is mouse feel, a high-quality input wrapper must
not preserve known controller defects.

### Sticks

Process stick vectors in this order:

1. normalize signed raw axes to a symmetric range;
2. apply center calibration;
3. compute vector magnitude;
4. apply a radial deadzone;
5. rescale the remaining magnitude to `[0, 1]`;
6. apply a continuous monotonic response exponent;
7. apply optional anti-deadzone/output saturation;
8. apply independent X/Y scale and inversion.

Microsoft's XInput guidance uses vector magnitude and circular deadzones rather
than FNV's independent 8689 threshold:
[XInput deadzone guidance](https://learn.microsoft.com/en-us/windows/win32/xinput/getting-started-with-xinput).

### Triggers

Use independent left/right press and release thresholds. The release threshold
must be below the press threshold to provide hysteresis. FNV's native
greater-than-zero rule is used only when Atom Input is disabled.

### Mixed input

Keyboard/mouse and controller state merge into logical actions. Device changes
do not zero movement or suppress valid actions. The most recent meaningful
input updates glyph ownership after a short anti-flicker interval; tiny stick
drift cannot steal glyph ownership.

## Focus and failure state machine

Input state must have explicit epochs:

```text
Uninitialized -> Neutral -> Active
                      |        |
                      v        v
                  FocusLost <- DeviceLost
                      |
                      v
                ReacquireNeutral -> Active
```

Rules:

- focus loss increments the epoch, clears action buffers, and publishes neutral
  state without emitting gameplay release actions;
- no background gameplay input is accepted by default;
- reacquisition snapshots physical state into the baseline without generating
  presses for keys already held;
- device failure disables only the affected Atom capability and leaves native
  input operational;
- repeated overflow or hook conflict is visible in diagnostics but never logged
  from the hot path;
- disabling the module performs the same neutral handoff.

## Hook and compatibility contract

Every engine patch must be a small transactional hook with a complete native
fingerprint, rollback, and local-unavailability failure mode.

Required boundaries:

- supported FNV executable SHA-256 remains
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`;
- normal sampler call is `0x0086F39E -> 0x00A23010`;
- player/camera behavior is rooted in `0x0093E860` and `0x009445B0`;
- bound actions use `0x00A24660` where applicable;
- final xNVSE presentation boundary remains `0x0087055E -> 0x00B6B730`.

Atom must account for xNVSE's `FakeDirectInputDevice` already wrapping keyboard
and mouse. The implemented buffered path is therefore:

```text
Atom live GetDeviceData capability mirror
    -> current predecessor (normally xNVSE FakeDirectInputDevice)
        -> real DirectInput device / Wine backend
```

Do not patch xNVSE, Wine, DXVK, another input mod, or a third-party vtable by
identity. If the expected capability or fingerprint is unavailable, Atom Input
falls back to native behavior while unrelated Atom modules continue.

No input hook belongs in DllMain, TLS, `NVSEPlugin_Query`, or
`NVSEPlugin_Load`. Installation and state allocation occur at DeferredInit or a
later proven lifecycle point. The first load-to-gameplay-tested Atom DLL remains
the startup baseline; any added imports, TLS, statics, or config layout require
the repository's pre-Deferred footprint review.

## MCM Extender configuration

All configuration belongs in Atom's MCM Extender menu. The implemented pages
and options are:

### Input / General

| Option | Initial default | Timing |
|---|---|---|
| Enable Atom Input | off pending acceptance | live; controller uses neutral handoff |

Mixed input and foreground-only gameplay input are fixed safety policies, not
toggles. Late sampling failed admission and is not shown.

### Input / Mouse

| Option | Initial default | Range/choices |
|---|---|---|
| Mouse profile | Fallout 4 Direct | Native, Direct, Fallout 4 Direct |
| Base sensitivity | 1.00 | 0.05-8.00 |
| Horizontal scale | 1.00 | 0.10-4.00 |
| Vertical scale | 1.00 | 0.10-4.00 |
| Invert X | off | boolean |
| Invert Y | preserve native preference | boolean |

No smoothing or acceleration slider should exist in the first version because
the desired profile deliberately has neither. A setting that reintroduces delay
without a proven use case would undermine the module.

### Input / Controller

- left and right radial deadzone;
- response exponent;
- anti-deadzone/output saturation;
- independent trigger press/release thresholds;
- independent stick X/Y scale and inversion;

MCM Extender owns ordinary reset/default behavior; Atom does not write the INI.

### Input / Diagnostics

MCM should show persisted diagnostic choices, not a custom live overlay. Useful
options are bounded telemetry enablement and a one-shot request to write the
next capture summary after leaving MCM. Continuous per-event logging is
prohibited.

Native defaults, MCM defaults, and saved defaults must be identical. Unknown
configuration data must be preserved according to MCM Extender's actual save
contract.

## Behavioral validation

No source-text, manifest-content, or textual call-order tests belong in this
subsystem. Tests must execute the public input behavior or validate the shipped
artifact where that artifact is itself the contract.

### Deterministic action tests

- replay press/release pairs within one frame and verify ordered edges once the
  buffered keyboard phase exists;
- replay duplicate and alternating transitions and verify no collapse in the
  Atom event layer;
- verify focus loss clears pending actions without a synthetic press/release;
- verify reacquisition of a physically held key does not create a press;
- verify mixed-device actions remain simultaneous and drift does not steal
  glyph ownership;
- verify runtime disable returns to native state on a neutral boundary.

### Mouse transform tests

- every signed delta in a representative range produces the exact documented
  angular result;
- zero maps to zero and one count is not discarded;
- output is odd-symmetric when inversion is disabled;
- horizontal and vertical scales are independent;
- FPS and delta time do not change degrees-per-count;
- focus/stall discontinuities are discarded while deliberate high-count flicks
  remain unflattened;
- native profile is bit-for-bit equivalent to the established native output at
  the hook boundary.

### Controller tests

- sweep stick magnitude and angle across the deadzone boundary;
- require continuous direction-preserving output and bounded magnitude;
- verify trigger hysteresis emits one press and one release despite noise;
- verify opposing devices merge according to action policy.

### Compatibility behavior

- xNVSE tap, hold, disable, and buffered injection remain observable;
- console, menus, Pip-Boy, VATS, movies, focus changes, and overlays retain
  native control;
- another caller's `DIGDD_PEEK` and normal `GetDeviceData` results remain
  correct if the keyboard mirror phase is implemented;
- input buffer overflow is detected and reported without inventing events.

## Runtime A/B acceptance

The user's subjective comparison is part of acceptance, but it should be paired
with technical markers.

### Controlled setup

Capture both games with:

- the same mouse, DPI, USB polling rate, display, refresh/VRR state, compositor,
  window mode, and Proton version where possible;
- an explicit per-game DXVK version and effective configuration;
- matched stable FPS and separately matched frame-time variance;
- VSync/presentation settings recorded rather than assumed equivalent;
- overlays and external limiters listed.

The current installations are not matched: FNV's local DXVK config requests a
120 FPS D3D9 limit, presentation interval zero, custom low-latency pacing, and
no CPU-frame overlap, while Fallout 4 preferences request interval one in
borderless mode.

### Measurements

For FNV, record:

1. native sample completion;
2. Atom snapshot publication;
3. action/camera consumer application;
4. xNVSE `OnFramePresent`;
5. runtime Present return if available from the owning graphics subsystem;
6. externally visible response with a high-speed camera where practical.

For Fallout 4, at minimum record physical movement-to-visible response under
the same camera and presentation conditions. An exact Fallout 4 preset requires
raw-count-to-yaw/pitch calibration across hip, aim, and scoped contexts.

### Acceptance criteria

- Atom adds no frame of latency and no mandatory smoothing history.
- Normal mouse input is consumed exactly once per frame.
- median and 95th-percentile FNV sample-to-Present do not regress.
- Late Gameplay Sample, if admitted, measurably reduces sample-to-consumer time.
- high-rate mouse movement has no loss, duplication, stair-step, or periodic
  hitching.
- camera, projectile/aim direction, crosshair, activation ray, and first-person
  body agree in the same frame.
- the user prefers `Fallout 4 Direct` to native in blinded or rapidly switched
  A/B comparisons across representative indoor/outdoor combat.
- disabling Atom restores native behavior without restart where documented.
- at least three cold Proton load-to-gameplay runs with BaseObjectSwapper reach
  all DeferredInit markers and normal gameplay.

Subjective preference is valid evidence for a feel preset. It is not sufficient
evidence for claiming a particular low-level cause or an exact latency reduction.

## Delivery stages

### Stage 0: measurement-only

- add bounded sampler, consumer, and Present QPC markers;
- establish native sample-to-consumer and sample-to-Present distributions;
- record camera delta/angle behavior;
- no transformed input.

Implemented. Histograms remain bounded and opt-in.

### Stage 1: direct mouse and controller transforms

- publish the post-xNVSE native snapshot;
- implement Native, Direct, and Fallout 4 Direct mouse profiles;
- implement radial sticks, trigger hysteresis, and mixed-device state;
- apply only at proven camera/player consumers;
- retain the native sampler location.

Implemented at the final float heading and proven controller camera boundaries.

### Stage 2: coherent action layer

- named actions and explicit contexts;
- focused consumer bridges;
- neutral focus/device state machine;
- no action buffering by default.

Implemented for all 28 native bindings with coarse proven contexts. There is
no intentional time-based gameplay queue.

### Stage 3: buffered keyboard compatibility

- outer keyboard `GetDeviceData` mirror;
- consume the native 32-event buffer once while preserving all caller semantics;
- timestamped short-tap preservation and overflow diagnostics.

Implemented through the current live `GetDeviceData` capability and the shared
bound-action provider. Native menu/text consumers keep their established
ownership.

### Stage 4: late gameplay sample

- complete intervening-consumer research;
- defer only the normal sampler call;
- demonstrate a latency reduction with no compatibility loss.

Research completed; implementation rejected for this executable because the
safe deferral preconditions are not met. Native sample placement is retained.

### Stage 5: optional authoritative modern backend

Consider only if stages 1-4 cannot meet acceptance. It would own Raw Input and
fully emulate native/xNVSE DirectInput behavior. It requires a separate design,
startup review, and broad mod-stack test matrix. It is not implied by this
proposal.

Not required and not implemented.

## Recommendation

Retain the implemented stages 0 through 3 and complete runtime acceptance before
expanding the input surface. The resulting architecture is:

1. direct no-history mouse heading with independent axes and calibrated camera
   context scales;
2. one coherent post-xNVSE action snapshot;
3. radial controller output with neutral live handoff;
4. bounded keyboard edge preservation behind native/xNVSE ownership;
5. presentation latency measured and handled by OMV/DXVK rather than Atom.

This combination reproduces the parts of Fallout 4's input architecture which
are relevant to feel without pretending FNV is Fallout 4 or breaking the
existing input stack. Raw Input takeover, universal time-based action buffering,
and render-only late latching remain outside the admitted design because the
current executable evidence does not establish safe ownership boundaries for
them.

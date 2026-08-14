# FNV Native Sky Replacement

## Purpose and Scope

OMV replaces the proven native Fallout NV sky draw family with shader-model-3
atmosphere, celestial, cloud, and star shaders. The feature owns only the
draw-scoped replacement pair, its compiled resources, and pixel constants
`c21..c31`. It preserves the engine's meshes, textures, blend/depth state, draw
ordering, and native shader pair outside each admitted draw.

Configuration is owned by `[graphics.native_sky]` in `omv/config/omv.toml` and
the OMV runtime menu. `graphics.screen_space_shaders` is the master presentation
switch. The feature supports both forward and reversed depth and keeps cloud
normal lighting as the existing explicit option; it is not disabled or reduced
as a performance shortcut.

## Ownership and Draw Flow

`omv/src/effects/sky.rs` owns installation, compilation, D3D resources, draw
classification, constants, binding, and restoration. At `DeferredInit`, OMV
resolves the live selector-index-10 object cached at `0x011F9570` and chains
its current vtable slot `+0x7C` with an ownership-aware compare-exchange hook.
The captured predecessor runs first; OMV then observes the current property
object type and native vertex/pixel wrapper identities after the engine updates
its constants.
Only the atmosphere `(0,0)`, celestial `(1,1)`, moon-mask `(2,1)`, stars `(4,4)`,
and clouds `(6,1)` pairs are admitted. Missing shader resources, textures, frame
data, or current-pair identity leave that draw native.

Compilation runs on the existing worker and creation remains budgeted at three
resources per Present frame. Resources are device-owned and reset with the D3D
device. The replacement is bound immediately before the native draw and the
exact native pair is restored at the draw boundary. No engine shader wrapper is
rewritten.

The selector-slot and renderer-geometry hooks are installed once at
`DeferredInit`, including when native sky starts disabled, and remain resident
for process lifetime. Runtime enable/disable changes passive atomics and
resources only; it never rewrites a live engine entry or slot. Disabling native
sky restores any draw-scoped replacement pair, releases sky D3D shader objects
and pending state, and leaves the resident routes inert. Compiled bytecode is
retained and device objects are recreated incrementally after re-enable.

Frame colors and sun values come from the copied `NativeSkyFrame` backend
snapshot. OMV now linearizes colors, evaluates sun/sunset values, and prepares
the common `c21..c31` payload once per frame rather than once per sky object.
Only `c31.x`, the object kind, changes per draw. A monotonically increasing frame
epoch invalidates the cached payload without taking a blocking render lock; draw
access uses `try_lock` and fails closed to the native shader if configuration or
frame state is concurrently busy.

## GPU Performance Contract

The original celestial pixel shader evaluated both sun and non-sun equations
and selected the result from uniform `ObjectData.x`. OMV now compiles exact sun,
moon, and other-celestial variants and selects the variant from the already
proven object type. The equations and exact extended-sRGB transfer are unchanged:
sun keeps its daylight alpha and sunset color, moon keeps unit celestial
brightness, and other objects keep `SunData.y` brightness. The common celestial
shader measured 104 compiled instruction tokens; the specialized variants are
65-66 with the same one texture sample.

The star shader previously evaluated two independent 3D value-noise fields and
multiplied them by two. It now evaluates the animated field once and uses
`1.5 * noise^2`. For a uniform noise distribution both expressions have mean
0.5, while the new expression reduces the pathological peak from 2.0 to 1.5 and
remains spatially and temporally smooth. The compiled star shader falls from 282
to 188 instruction tokens with the same texture sample, horizon fade, tint,
strength, alpha, and exact sRGB transfer.

Atmosphere and both cloud variants deliberately retain their equations and
sample counts. In particular, OMV does not replace exact sRGB conversion with a
visible approximation, remove dither, lower sky coverage, drop either weather
texture, or force cloud normals off. Current static ceilings are:

| Pixel variant | Instructions | Texture samples | Bytecode bytes |
|---|---:|---:|---:|
| Atmosphere | 81 | 0 | 1,660 |
| Celestial sun | 65 | 1 | 1,276 |
| Celestial moon | 65 | 1 | 1,228 |
| Other celestial | 66 | 1 | 1,288 |
| Clouds | 193 | 2 | 3,484 |
| Cloud normals | 254 | 2 | 4,524 |
| Stars | 188 | 1 | 3,204 |

Every vertex and pixel variant has a named bytecode, instruction, and exact
texture-sample budget. The suite also compiles every variant, proves the
celestial specialization against the former uniform equation, verifies the star
mean/peak contract, and proves that common frame constants differ only in the
per-draw object-kind scalar.

## Failure, Compatibility, and Runtime Acceptance

All failures are per draw and fail closed to the engine's native sky pair.
Normal runtime performs no readback or diagnostics beyond the pre-existing
native-pair and required-texture validation. The two additional celestial pixel
resources add small one-time compile/device memory cost and no additional draw;
the prepared frame payload is eleven `float4` values.

Static shader metrics prove bounded work and equation coverage, not delivered
FPS or final pixels. Runtime acceptance must use the same save, resolution,
weather, time, and camera path with native sky off/on. Check sunrise/sunset sun
color and alpha, moon masks and phases, other celestial objects, both weather
textures during a blend, cloud normals both off and on, star brightness and
twinkle over time, forward/reversed depth, and device reset. Capture repeatable
frame times before claiming a performance delta.

Repository validation on 2026-07-22 passed all 254 OMV tests and the supported
release build for `i686-pc-windows-gnu`. Shader compilation and the static GPU
budgets are therefore proven; visual parity and delivered frame time remain an
in-game acceptance step.

## Mod-Agnostic Slot Migration Contract (2026-08-14)

Status: implemented and focused-test accepted in source on 2026-08-14; runtime
startup, visual, compatibility, and performance acceptance remain open.

The supported executable is PE32 x86 with image base `0x00400000` and SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Focused radare2 inspection closes the object, dispatch, ABI, and lifetime
contract needed to stop claiming the shared `0x00B89D80` function entry:

- generic shader lookup `0x00B55560` uses the cache at `0x011F9548`; case 10
  constructs the sky selector through `0x00B8A390`, so its cache slot is
  `0x011F9548 + 10 * 4 = 0x011F9570`;
- `0x00B8A390` allocates the `0xF0`-byte object and calls constructor
  `0x00B8A1F0`;
- `0x00B8A1F0` calls the shader-selector base constructor and then writes the
  derived vptr `0x010AFE18` before constructing the vertex/pixel wrapper arrays
  at `+0x98/+0xC4`;
- vtable address `0x010AFE18 + 0x7C = 0x010AFE94` contains
  `SkyShader::UpdateConstants @ 0x00B89D80`;
- generic draw dispatcher `0x00B98E80` loads the current selector into `ESI`.
  At `0x00B98FD9..0x00B98FE1` it loads virtual slot `+0x7C`, pushes the
  property-state pointer, restores the selector in `ECX`, and calls the slot.
  This proves the current OMV type
  `unsafe extern "thiscall" fn(*mut c_void, *const c_void)`;
- shader teardown `0x00B54280` decrements and nulls all cached selector objects
  at engine shutdown. The slot hook must therefore be process-retained and may
  not inspect the object during teardown.

At `DeferredInit`, the implementation reads the live selector pointer from
`0x011F9570`, validates its current vptr and executable `+0x7C` target, and uses
an ownership-aware compare-exchange slot hook. The predecessor actually found
in the live slot is authoritative; a cloned vtable installed by another plugin
is chainable when it remains live and ABI-compatible. A missing object,
unreadable slot, null/non-executable predecessor, or compare-exchange mismatch
disables native sky only.

The hook keeps the existing call order: invoke the captured predecessor first,
then classify the completed native constants and publish a pending sky draw.
It must never inspect another module to decide admission and must never fall
back to the shared function entry or a live D3D9 device vtable.

The diagnostics UI reports selector-slot, geometry, and shared texture-mirror
availability separately. A configured sky feature is reported as
dependency-blocked when its own selector route exists but geometry or texture
observation does not. Captured predecessor module/address labels are
presentation-only evidence and never influence admission.

The source-level migration removes the production `0x00B89D80` shared-entry
detour, keeps the established predecessor-first constant classification, and
adds no render-time scan, allocation, module lookup, or blocking lock. The
required BaseObjectSwapper cold starts, special sky-path captures, reset tests,
and NVIDIA/AMD timing comparison have not yet been performed for this artifact.

The containing 2026-08-14 source state passes all 643 explicit-target OMV
tests and the supported optimized OMV build. This proves compilation, static
slot ownership, and established shader contracts only; the runtime gates above
remain open.

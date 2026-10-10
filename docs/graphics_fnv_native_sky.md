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
proven object type. The exact extended-sRGB transfer is retained. The solar
coverage correction below intentionally changes the sun branch; moon keeps
unit celestial brightness and other objects keep `SunData.y` brightness. The common celestial
shader measured 104 compiled instruction tokens; the specialized variants are
65-66 with the same one texture sample.

The star shader previously evaluated two independent 3D value-noise fields and
multiplied them by two. It now evaluates the animated field once and uses
`1.5 * noise^2`. For a uniform noise distribution both expressions have mean
0.5, while the new expression reduces the pathological peak from 2.0 to 1.5 and
remains spatially and temporally smooth. The compiled star shader falls from 282
to 188 instruction tokens with the same texture sample, horizon fade, tint,
strength, alpha, and exact sRGB transfer.

Atmosphere and both cloud variants retain texture sample counts. The solar
haze correction below replaces their broad angular glow and sky addition. In particular, OMV does not replace exact sRGB conversion with a
visible approximation, remove dither, lower sky coverage, drop either weather
texture, or force cloud normals off. Current static ceilings are:

| Pixel variant | Instructions | Texture samples | Bytecode bytes |
|---|---:|---:|---:|
| Atmosphere | 101 | 0 | 1,964 |
| Celestial sun | 60 | 1 | 1,196 |
| Celestial moon | 65 | 1 | 1,228 |
| Other celestial | 66 | 1 | 1,288 |
| Clouds | 207 | 2 | 3,692 |
| Cloud normals | 269 | 2 | 4,748 |
| Stars | 188 | 1 | 3,204 |

Every vertex and pixel variant has a named bytecode, instruction, and exact
texture-sample budget. The suite also compiles every variant, proves the
celestial variant selection, verifies the star
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

## Rejected shared material-boundary candidate (2026-08-17)

Native sky retains its released `UpdateConstants +0x7C` observer and
draw-scoped raw replacement/restoration. It does not own SkyShader
`SetShaders`, mutate FNV's global last-selector cache, or infer shader state
from an unrelated selector. A rejected 2026-08-16 candidate did all three and
could couple sky readiness to PBR and other shader families; that design is not
part of production.

The rejected candidate made renderer geometry hooks enter `effects::material`, the exclusive owner
of the shared PBR/sky submission boundary. A pending sky publication identifies
the exact geometry and receives first refusal. When sky claims the draw, PBR is
not evaluated and the paired sky restoration runs immediately after the native
submission. When sky does not claim it, the broker delegates once to PBR. This
preserves the established sky constants, texture-mirror admission, shader
equations, resources, and reset behavior while preventing cross-family device
state reconstruction.

The first form of this broker did not satisfy its own identity claim.
`SkyShader::UpdateConstants` published only shader indices, object type, and
native D3D handles. Whichever renderer geometry hook ran next consumed that
state. An unrelated PBR geometry could therefore be classified as sky, skip
PBR, and receive a transient sky pair; the real sky draw would then fall
through. The affected Atom playtest showed working shadow hooks alongside
missing PBR, native-sky blinking, and other visible effect failures. That
observation does not prove each final pixel's owner, but it rejects the
shader-only publication as a durable material transaction.

The candidate made `effects::material` own the only OMV read of FNV's authoritative current
geometry source at `0x011F91E0`. `FUN_00B994F0` publishes this draw slot before
selector setup and the later renderer submission supplies the same geometry
pointer. Deferred hook installation validates the fixed global once. Serialized
selector/draw callbacks then perform two bounded pointer loads with low/null
checks; they do not call `VirtualQuery`, ask D3D for state, allocate, or lock.
PBR consumes this same accessor instead of retaining a private duplicate.

The sky observer release-publishes one fixed atomic descriptor containing the
exact geometry identity, render epoch, generation, shader indices, object type,
and native pair. A low-bit state word is both the publication marker and a
non-spinning claim lock. The geometry consumer acquires and locks one stable
generation before copying the descriptor. A different geometry leaves the
publication available for its exact later submission; a different render epoch
expires it; a newer UpdateConstants publication supersedes it. Reset, disable,
and Present cleanup clear any unconsumed generation. No geometry pointer is
dereferenced after publication; it is compared only as an opaque identity.

Sky admission is explicitly three-way. `Unclaimed` delegates to PBR.
`OwnedVanilla` means the exact sky geometry was identified but replacement
resources, textures, constants, or binding were unavailable; the native draw
runs and PBR remains excluded. `OwnedReplacement` runs the sky pair and restores
the captured native pair after submission. This distinction is required:
binding failure must not make real sky geometry eligible for PBR, while a stale
or unrelated publication must never suppress a valid PBR draw.

Identity publication is independent of replacement enablement and pair
support. When native-sky replacement is disabled or the SkyShader pair is not
recognized, the resident observer publishes a classification-only descriptor
without replacement handles. Its exact geometry resolves to `OwnedVanilla`;
configuration state and third-party sky variants therefore cannot expose real
sky geometry to PBR. Deferred startup validates the shared geometry global
before either material observer becomes resident. Failure keeps both material
replacements passive without suppressing the rest of OMV.

The sky slot diagnostic now separates activation, current direct ownership,
and actual detour invocation. A later compatible pointer-slot owner may displace
OMV and still chain it; observed invocation is evidence of that reachability.
Neither ownership nor module identity changes sky admission after DeferredInit.
Invocation evidence is fresh per requested diagnostics generation rather than
a permanent hot-draw counter. The constants route writes at most once per
generation, and a stale observation cannot make a later displaced slot appear
healthy. Executable slot ownership is read only for bounded diagnostics, never
for sky selection or every-frame rendering.

Static material tests prove unrelated geometry cannot consume sky state, exact
single consumption, epoch expiry, generation supersession, claim exclusion,
native-fallback exclusion, classification-only ownership, and paired
restoration order. The native sky compile/budget suite and the complete OMV
gates remain required, followed by exterior sunrise/sunset, moon, stars,
weather blend, fast camera movement, forward/reversed depth, PBR coexistence,
and device-reset playtests.

The containing compatibility candidate passes all 702 explicit-target OMV
tests and doc tests and the supported optimized OMV build. This proves static
slot/material integration and shader budgets, not the reported fast-camera sky
blink on the installed Atom configuration.

## Runtime rejection and production rollback (2026-08-17)

The subsequent exact-geometry candidate also failed the installed test: native
sky moved with Atom head bob and PBR remained absent. The log proved that sky
constants and replacement draws executed, but execution did not make the
composed image correct. The shared material broker, generation descriptor, and
`0x011F91E0` geometry source described above are therefore rejected and are no
longer production code.

Native sky is restored to the accepted commit-`1dac8a2` path: the resident
SkyShader constants observer publishes its released draw-scoped state, the
renderer prepares PBR and then sky before the captured native geometry call,
and sky restores its native pair immediately afterward. Disable/reset and
resource behavior return with that path. No Atom name, module identity, hook
address owner, or camera snapshot participates in sky admission.

The visible head-bob defect had a separate native cause. World rendering reads
the SceneGraph camera at `+0xAC`, while `0x00872B00` centers finite Sky and
Weather from SceneGraph child zero. Atom previously posed only the first
object. Atom now scopes both transforms around the complete parent route and
restores Sky/Weather from child zero's original center. That fix preserves OMV
sky ownership rather than creating another OMV-side camera model.

Static shader budgets and hook tests cannot accept the correction. The required
playtest is native sky off/on with Atom camera off/on, rapid translation and
rotation, weather/time transitions, PBR objects and terrain, reset/alt-tab, and
measured frame pacing on the installed release artifacts.

The restored candidate passes all 699 explicit-target OMV tests and the
supported five-crate release build. Its `omv.dll` identity is 12,862,364 bytes,
SHA-256 `b158b52ba8e1e1606cf69b77c7277848a85351f1555f0ff35f69cf581ebbf77a`.
Visible sky stability remains an installed playtest gate.

## Delta-only sky anchor and exact draw ownership (2026-08-17)

The installed candidate above was rejected again: sky still followed Atom head
bob and PBR remained absent. Fresh executable inspection narrows both mistakes.

`0x00558310` is only `NiNode::GetAt(0)`. In native preparation,
`0x00872B00` reads child zero's local translation at `+0x58`, copies that
translation to Sky and Weather, and updates those two roots. It does not read
the child's local rotation or world transform. Applying the complete Atom pose
to child zero was therefore broader than the native contract. It also composed
the same camera-space pose through two potentially different rotation bases,
so the render camera and finite-sky center could receive different world
translation deltas.

Atom now composes the render camera once, subtracts its original local
translation from the posed local translation, and adds that exact finite delta
to child zero's local translation. Child-zero rotation and world transform are
never changed. The route restores the original anchor translation before
recentering Sky and Weather. Pointer aliasing still performs only the camera
transaction.

OMV independently retains the exact geometry identity already available when
SkyShader `UpdateConstants` runs. `0x00B994F0` publishes the current pass-entry
pointer at `0x011F91E0`; entry `+0x00` is the geometry later passed to
RenderTriShape/RenderTriStrips. Native sky may claim only that pointer. A
different geometry leaves the sky publication pending and proceeds through
PBR. An exact sky draw excludes PBR even when the sky replacement falls back
to vanilla. This is a small local atomic field and comparison, not the rejected
shared material module, epoch protocol, global selector invalidation, or
cross-effect broker.

The earlier exact-geometry broker did not fix the image because PBR had a
separate unreachable selector-instance hook. That runtime rejection remains
valid for the generalized broker but does not make cross-geometry shader-state
consumption correct. The current pair of changes addresses the two proven
faults independently.

Static tests cannot accept head-bob stability or final pixels. Required runtime
acceptance is stationary and rapid first-person motion with Atom camera off/on,
native sky off/on, PBR objects and all terrain families, weather/time changes,
reset/alt-tab, and the repository startup matrix.

## Rejected local/world sky-anchor correction (2026-08-17)

The installed local-translation-only candidate was also rejected: stars still
moved with Atom head bob. The earlier contract covered native preparation at
`0x00872B00`, but omitted a second consumer in
`SkyShader::UpdateConstants @ 0x00B89D80`. That routine subtracts the world
translation of the pointer retained at `0x011F95D8` after copying the
geometry/model transform. The candidate incorrectly identified that pointer
as child zero and consequently wrote both the CameraNode local and world
translations. The installed result still moved stars with head bob and
rejected that ownership model.

## CameraNode/NiCamera sky correction (2026-08-17)

The executable keeps two distinct objects. `BSSceneGraph::BSSceneGraph @
0x00C517B0` constructs the CameraNode at child zero and stores a separate
NiCamera at `SceneGraph +0xAC`. `0x00872B00` copies only the CameraNode local
translation into Sky and Weather. In contrast, initialization at
`0x0086D873..0x0086D88A` publishes `SceneGraph +0xAC` to `0x011F95D8`, and
`SkyShader::UpdateConstants @ 0x00B89D80` subtracts that NiCamera's world
translation from the sky model transform.

Atom therefore composes the render NiCamera once, computes its resulting
world-translation delta, and adds that delta only to the distinct CameraNode's
local translation. Native preparation then gives finite sky geometry exactly
the same world displacement as the NiCamera subtraction. Atom never writes the
CameraNode world transform and restores its original local translation before
recentering Sky and Weather.

The behavioral regression models the distinct CameraNode and NiCamera, native
`0x00872B00` preparation, and the translation term from
`SkyShader::UpdateConstants`. With the rejected local-plus-world correction it
reports residual sky motion `[2, -2, 0]` under a rotated two-unit head-bob pose;
the corrected transaction keeps the relative sky matrix at zero. Installed
pixel quality remains an ordinary playtest concern, but the reported native
matrix jump is covered directly rather than inferred from restoration tests.

## Authored solar coverage contract

The owner's requirement is to retain the game disk while removing the oversized
OMV glow and recovering occluder-shaped rays. Geometry size alone is not proven
wrong. The sun branch previously added the same directional RGB to every texel
admitted by texture alpha and omitted native vertex visibility. Its added RGB
now follows texture RGB, preserving the former unit-texel peak and sunset tint;
alpha includes native vertex visibility, without OMV's additional daylight
cutoff. This is
an intentional OMV shading correction, not a claim of native pixel-shader parity.
Black weather-color candidates must not erase the texture itself.

`backend/fnv/sun_disk.rs` owns a draw-local retained texture and projective maps.
It adds no hook, static owner, startup preparation or configuration field. The
supported executable identity is the one recorded above. Focused raw evidence
is [solar disk coverage](../analysis/radare2/output/fnv_solar_disk_coverage_contract_20261006.txt).

- `Sun::Create @ 0x00640810` creates separate disk/glare shapes at `Sun +0x10`
  and `+0x14`, from distinct setting objects `0x011CCE7C` and `0x011CCE50`.
  The disk is a four-vertex parallelogram with complete square UVs and constant
  vertex alpha. Both shapes, their textures and native draw order remain owned
  by the engine.
- `Sun::Update @ 0x00641830` writes separate disk/glare RGBA through property
  `+0x60`; disk visibility is `+0x6C`. The retained texture setter
  `0x006348E0` writes property `+0x70`.
- `NiGeometry @ 0x00A804E0` stores geometry data at `+0xB8`, not the stale
  header's `+0xB4`. `NiGeometryData @ 0x00A67B20` stores count at `+0x08`,
  vertices at `+0x20`, colors at `+0x28`, and UVs at `+0x2C`. The geometry's
  property-state shade slot is `+0xA8`.
- `SkyShader::UpdateConstants @ 0x00B89D80` uses the geometry world transform
  at `+0x68`. When renderer `+0x164` is set, it subtracts the published camera
  `0x011F95D8` translation, then adds the renderer camera translation before
  view projection. `NiRenderer::GetRenderer @ 0x00B4F5D0` reads `0x011F95F0`.
  The source snapshot honors both branches and uses the captured depth camera's
  right/up/forward axes and frustum.
- The existing NiTexture renderer-data `+0x24`, D3D texture `+0x64` contract is
  also documented in `graphics_fnv_depth_resolve.md`. Native ownership remains
  live across serialized render-thread reads; a COM reference retains the 2D
  texture until the consuming draws finish. Range validation precedes reads.

Unavailable, nonfinite, singular, non-parallelogram, varying vertex-opacity or
non-square-UV data yields no source packet. Atmosphere then omits only disk
boost. Legacy shafts use native directional illumination and do not require
the disk packet, texture, or sprite opacity.
Base-level texture coverage uses the sun replacement's exact sRGB decode and
the product of texture, constant vertex and property alpha. It does not infer
radiance from a tone-mapped framebuffer or claim native mip-filter parity.
Textures are sampled only inside the projected authored quad. No fixed screen
radius or physical angular disk replaces the game's authored size.

Texture-shaped emission and native opacity add three instruction tokens, while
removing the duplicate daylight cutoff removes eight. The final sun variant
therefore uses 60 tokens and one texture fetch, below the former 65-token budget,
with no new draw. Retaining the uniform pedestal or discarding native alpha
would remove required behavior. Other native-sky shader budgets remain unchanged. Compilation and bytecode budgets
are static support evidence; final pixels, engine integration and startup were
not run. Gameplay validation remains solely the owner's decision.

## Solar haze and weather brightness ownership

The owner tested OMV Default 1.1.0 and reported a giant bright halo and weak
rays. The native sky's procedural solar term had a separate broad source:
`pow((1 + cos(theta))/2, 1/sun_influence)` multiplied additive solar RGB,
followed by a 2.043103 sky multiplier. This source was not the authored disk
texture and survived the disk coverage correction. Cloud scattering also used
an independent power lobe and positive solar addition.

Sky and cloud haze now use a peak-normalized Cornette-Shanks profile with
`g=0.8`, retaining the influence exponent as an artistic width control. The
profile follows [Bruneton's Mie phase function](https://ebruneton.github.io/precomputed_atmospheric_scattering/atmosphere/functions.glsl.html)
and the terrestrial asymmetry default in
[Hillaire's atmosphere model](https://diglib.eg.org/bitstream/handle/10.1111/cgf14050/v39i4pp013-022.pdf).
This is an angular shape for authored weather colors, not a new physical
transport solver or a replacement for the game's sun geometry.

The sky's solar haze blends its existing weather color toward the source color
with a bounded weight instead of adding a broad RGB pedestal. Cloud solar
scattering uses the same angular shape; cloud textures, opacity, normal mode,
weather tint and native state/order remain. Neutral defaults are one for sky
multiplier, solar strength, influence and cloud brightness. These are identity
settings, not perceptually playtested exposure values. Native sun/glare texture
coverage and geometry remain engine-owned. Directional/local atmosphere owns
the existing volumetric transport; legacy Sunshafts adds only ray contrast.

The solar haze shape and bounded blend cost 20 extra instruction tokens for sky,
14 for flat clouds and 15 for normal clouds, with no extra texture fetch or
pass. A larger power exponent would only narrow the old halo; it would retain
unbounded additive weather lighting and a less faithful angular shape. The
reference phase profile and source-color blend jointly address those contracts.
Celestial, moon, star and vertex budgets remain unchanged.

## Cloud lighting and brightness

Cloud brightness is a single linear RGB gain after lighting. It does not
change normal decoding, the ambient/direct-light balance, authored texture
detail, or opacity. Both cloud variants retain native texture blending,
black-texture fallback, vertex tint, sunset tint, and alpha shaping.

Flat clouds retain authored RGB as their detail source. At low sun angles,
a bounded blend between the existing upper-sky and sunlight colors supplies
the tint; the overhead-sun result retains its identity response. The previous
fifth-power dark tint, extrapolating blend weights, and amplified solar
addition are removed. The existing angular solar profile and coverage-dependent
scattering remain. If the evaluated optional sunlight color is black, the
flat-cloud tint retains the existing upper-sky color rather than blending
ambient detail toward black. This fallback does not add solar scattering or
manufacture sunlight; populated sunlight and sunset colors remain unchanged.
Normal clouds retain their brightness-one lighting shape,
but ambient luminance is bounded when computing the direct-light weight.
Over-white ambient light therefore cannot turn direct sunlight negative.
Source radiance retains headroom for the final display response.

This policy consumes the existing copied frame colors and sun direction. It
does not identify weather, inspect mods, change native artwork or coverage,
or introduce resources, texture fetches, passes, histories, or engine hooks.
Both variants fit their existing static ceilings. Offline D3D9 regressions
execute the production native vertex/pixel pairs, frame constants, authored
coverage blending, and the final tone mapper into UNORM output. These controlled
design inputs cover low/intermediate/overhead sun, shipped transparency,
colored populated texture blends, black sunlight, and final-tone bright detail.
They qualify the gain, coverage, and bright-detail contracts; native
game composition, image quality, startup, and delivered frame time are not run.

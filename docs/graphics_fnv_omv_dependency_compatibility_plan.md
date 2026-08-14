# OMV Mod-Agnostic Graphics Interoperability Plan

Status: source implementation complete through the interoperability-diagnostics
slice on 2026-08-14; release and runtime acceptance remain open.

Implementation evidence as of 2026-08-14:

- `Rel32CallHook` and `PointerSlotHook`, their static-friendly containers,
  ownership-aware transactions, and diagnostic predecessor addresses are
  implemented in `libpsycho`;
- the PPLighting and SkyShader vtable research gates below are closed;
- presentation is brokered by xNVSE `OnFramePresent`; reset and every proven
  scene/package/shadow transition use direct caller chains;
- renderer, render-state, PPLighting, and SkyShader dispatch use live
  engine-owned pointer slots; shader-creation and shared callee-entry hooks are
  removed from production ownership;
- terrain admission is functional rather than filename-based, and the menu
  exposes a read-only per-capability matrix with diagnostic predecessor owners;
- focused i686 tests passed for the new hook primitives, presentation decode,
  caller ABIs/groups, module-agnostic admission, and diagnostics; the complete
  suite and both required release builds also pass as recorded below.

No in-game startup, compatibility, visual, or performance claim follows from
this source state. In particular, the BaseObjectSwapper cold-start gate and
the affected NVIDIA/AMD matrix have not been run on this artifact. Commit
`9975b2e` remains the last documented accepted startup baseline.

This document is the implementation plan for making Oh My Vegas (`OMV`)
graphics effects coexist with unknown xNVSE graphics plugins, shader loaders,
and `d3d9.dll` proxies. The goal is to eliminate a class of ownership conflicts,
not to identify or special-case the mod currently associated with the NVIDIA
performance failure.

The strategy is:

- stop assuming ownership of shared engine function entries;
- chain the target that is present at each direct callsite or engine-owned
  vtable slot when OMV installs;
- publish independently installed graphics capabilities instead of a single
  global hooks-ready state;
- fail only the effect whose proven contract is unavailable;
- keep ENB and other `d3d9.dll` implementations opaque;
- preserve OMV's accepted rendering equations, phase order, coverage, and
  runtime configuration behavior.

The observed conflict at `CreateVertexShader @ 0x00BE0FE0` proves that the
current entry-detour strategy can collide with another graphics plugin. It
does not prove which installed mod causes the reported low performance. This
plan therefore does not use module names as behavior switches.

## Mandatory Constraints

The pre-`DeferredInit` compatibility contract in
[`nvse_startup_phase_safety.md`](nvse_startup_phase_safety.md) and
[`graphics_fnv_atmosphere_startup_crash_errata.md`](graphics_fnv_atmosphere_startup_crash_errata.md)
applies to every implementation slice in this plan.

- `NVSEPlugin_Load` must not publish or open a render route.
- Newly added engine-facing routes remain false until `DeferredInit`,
  immediately before their resident hook group becomes reachable.
- Do not add module-specific detection, patching, ordering, or disable paths.
- Do not hook a live `IDirect3DDevice9` vtable. ENB remains an opaque proxy.
- Do not install or remove executable hooks after `DeferredInit`. Runtime
  configuration changes only passive behavior atomics.
- Do not change the released schema-1 configuration shape, preset payload,
  manifest, migration, or `CONFIG_SCHEMA_VERSION`.
- Do not remove, reorder, or retype persisted compatibility fields.
- Render callbacks remain allocation-free and nonblocking. Diagnostics and
  ownership discovery happen outside hot paths.
- Preserve the existing immutable per-phase plans, `D3DSBT_ALL` isolation,
  and separate render-target/depth attachment restoration.
- Do not disable an unrelated OMV feature merely because one interception
  contract is unavailable.
- Static tests and release builds cannot establish startup or graphics runtime
  safety. The required Proton playtests remain release gates.

The last documented load-to-gameplay startup baseline is commit `9975b2e`
from 2026-08-10. Before implementation, confirm whether a newer accepted
artifact, including the in-progress shadow/depth work, supersedes it.

## Evidence Boundary

The following direct `CALL` sites were verified against the current supported
`FalloutNV.exe` during this planning pass:

| Engine operation | Current target | Direct callsites |
|---|---:|---|
| Device recreation | `0x00E73EB0` | `0x004DC41F` |
| Process image space | `0x00B55AC0` | `0x00876136` |
| Water | `0x004E2120` | `0x004E1D7C`, `0x004E1DB1`, `0x008728AE` |
| World | `0x00873200` | `0x00870AE8`, `0x00870E18` |
| First person | `0x00875110` | `0x0087093D`, `0x00870B21`, `0x00870F74` |
| Pre-alpha/depth | `0x00B65AE0` | `0x00B6653D`, `0x00B665A6` |
| Set shader package | `0x00B4F710` | `0x004DB187`, `0x004DCB9D` |
| Common shadow operation | `0x00871290` | `0x00870851`, `0x00870A74`, `0x00870C3C` |
| Completed local shadow | `0x00B9F780` | `0x00B5B9DC` |

Existing durable research and the 2026-08-14 focused radare2 closure establish:

- the renderer geometry slots are TriShape method 109 at `+0x1B4` and
  TriStrips method 110 at `+0x1B8`;
- the renderer owns the render-state object at `renderer + 0x8B8`;
- render-state method 55 at `+0xDC` currently targets `0x00E88A20` and is the
  texture observation route;
- the PPLighting derived selector is shader selector index 4, cached at
  `0x011F9558`; constructor `0x00BD44C0` writes vptr `0x010BC070`, and the
  virtual dispatch at `0x00B99479..0x00B99482` invokes
  `SetShaders @ 0x00BE1F90` through slot `+0xF4` (method 61);
- the SkyShader selector is shader selector index 10, cached at `0x011F9570`;
  constructor `0x00B8A1F0` writes vptr `0x010AFE18`, and the generic draw
  dispatcher at `0x00B98FD9..0x00B98FE1` invokes
  `UpdateConstants @ 0x00B89D80` through slot `+0x7C` (method 31);
- selector cache teardown `0x00B54280` releases and nulls the selector array at
  engine shutdown. OMV must therefore retain committed slot hooks for process
  lifetime and must not dereference the selector object during teardown.

The supported executable for these facts is PE32 x86, image base `0x00400000`,
SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The PPLighting and SkyShader migrations may now use these exact slots, but the
runtime owner must still validate the live cached object, its current vptr,
and the callable predecessor at `DeferredInit` before installing either
capability.

## Target Lifecycle

### `NVSEPlugin_Load`

OMV keeps its existing xNVSE message-listener registration. It may perform the
already accepted startup work, but it does not install or publish a graphics
route. No new listener or early D3D interception is required.

### `DeferredInit`

For each capability group:

1. Resolve the current callsite or live engine vtable slot.
2. Validate the instruction, pointer, ABI, object lifetime, and executable
   predecessor.
3. Preflight every member of the group before mutating any member.
4. Install the complete group in an ownership-aware transaction.
5. Commit the group and retain its predecessor targets for process lifetime.
6. Publish the capability bit only after the complete group succeeds.
7. Record a diagnostic reason and continue when an optional group fails.

Global initialization fails only when OMV cannot establish an essential
device/reset/presentation contract. Optional failures remain feature-local.

### Render time

Render callbacks consult only immutable plans and atomic capability/config
state. They do not scan modules, inspect code, construct diagnostic strings,
compile shaders, perform file I/O, allocate routinely, or block on a lock.

### Runtime configuration

Configuration enables or disables behavior behind already installed routes.
It never installs, removes, or transfers ownership of executable code.

## Cooperative Hook Primitives

Add two general ownership-aware primitives under
`libpsycho/src/os/windows/hook/`. They are shared infrastructure, but their
implementation must not change the behavior of existing hook types.

### `Rel32CallHook<F>`

The direct-callsite primitive must:

- accept exactly a five-byte `E8 rel32` instruction;
- resolve the call's current target as OMV's predecessor;
- validate that the predecessor is executable;
- reject jumps, unknown instructions, invalid ranges, and truncated calls;
- install only when the captured five bytes remain unchanged after preflight;
- encode a new `E8 rel32` to the OMV wrapper, flush instruction state, and
  verify the installed bytes;
- restore only when the callsite still contains OMV's exact call bytes;
- leave a later owner's bytes untouched when rollback has lost ownership;
- expose the predecessor without a hot-path lock.

It must not follow an arbitrary `E9` chain. Distinct callsites retain distinct
predecessors even when they originally targeted the same engine function.

### `PointerSlotHook<F>`

The engine-pointer primitive must:

- capture the pointer currently stored in a proven engine vtable or function
  slot;
- validate the captured predecessor as executable;
- install with compare-and-exchange from predecessor to OMV;
- restore with compare-and-exchange from OMV to predecessor;
- never blind-write a slot that changed after capture or installation;
- retain committed predecessor storage for process lifetime;
- expose the predecessor without a hot-path lock.

Resolve the actual live object's vtable at `DeferredInit` where the object
contract permits it. This chains a cooperative predecessor even when it uses
a cloned vtable.

### Transaction integration

Extend `ModificationTransaction` with callsite and pointer-slot operations.
Do not change the existing `VmtHook` contract for unrelated consumers. Every
multi-site feature group rolls back in reverse order and publishes nothing
until the whole group commits.

## Capability Ownership

Add `omv/src/interop.rs` or an equivalently focused module that owns:

- one atomic capability bitmask for hot paths;
- a post-Deferred diagnostic report containing failure reasons and captured
  predecessor addresses;
- a `DeferredHookOwner` retaining committed hook objects for process lifetime;
- pure dependency helpers used by feature admission.

A process-lifetime owner published only from `DeferredInit` avoids graphics
hook destructors and avoids spreading large hook statics across effect
modules. The exact storage type must be reviewed against the frozen startup
footprint before selection.

| Capability | Primary consumers | Failure result |
|---|---|---|
| Present | UI, resource servicing, final fallback | OMV rendering remains closed |
| Reset | Every D3D resource owner | All graphics routes remain closed |
| ImageSpace | Screen-space phase injection | Only safe presentation/menu fallback remains |
| Water | Underwater classification | Underwater-sensitive behavior is unavailable |
| World | World-phase effects | Only dependent world effects are unavailable |
| FirstPerson | First-person motion blur | First-person motion blur is unavailable |
| PreAlpha | Atmosphere and shadow consumption | Those consumers are unavailable |
| Geometry | PBR, native sky, native shadows | Only those geometry consumers are unavailable |
| TextureMirror | PBR and sky texture observation | PBR/sky admission fails closed |
| PbrSelection | PBR shader selection | PBR is unavailable |
| PbrPackage | PBR package replacement | PBR is unavailable |
| SkyConstants | Native sky | Native sky is unavailable |
| LocalLightEpoch | Local volumetric/terrain lights | Local light enrichment is unavailable |
| NativeShadowSlot | Completed-shadow observation | Shadow enrichment is unavailable |
| NativeShadowReplacement | OMV shadow production | Native rendering continues without OMV replacement |

State and rendering behavior depend on capability bits, never a module name.
Module/address ownership may be reported as diagnostic evidence only.

## Presentation And Device Lifecycle

### Presentation broker

Handle `NVSEMessage::OnFramePresent` in `omv/src/nvse_plugin.rs` through the
listener OMV already registers. xNVSE dispatches this message immediately
before the engine's final display call.

The message data points to a stack `int loadingScreen`. Decode it locally as a
checked, unaligned `i32` after validating the payload length. Do not use
`NVSEMessage::data_as_bool()`, which interprets the data pointer value rather
than the pointed-to integer.

The handler performs the current end-of-frame responsibilities:

- return immediately until deferred graphics publication is complete;
- use the published device, with only a checked singleton republish if it is
  absent rather than querying every frame;
- close outstanding PBR and sky scopes;
- service prepared shader and resource work;
- apply the safe final/menu fallback phases;
- never run gameplay world fallback during a loading screen;
- record presentation timing at callback arrival;
- complete diagnostics and finish the current world epoch;
- advance the render epoch before returning to xNVSE's final display path.

The production `DisplayScene` function-entry detour is removed. Presentation
uses the xNVSE message and does not replace it with a D3D device vtable hook.

### Device recreation

Replace the `0x00E73EB0` function-entry hook with the direct callsite at
`0x004DC41F`.

The wrapper preserves this order:

1. Release OMV device resources.
2. Invoke the captured predecessor exactly once.
3. Republish the device only after successful recreation.
4. Recreate effect resources through their existing owners.

Reset is an essential lifecycle capability and must not share a transaction
with optional geometry interception.

## Scene-Phase Migration

Replace the five shared function-entry hooks in `omv/src/fnv_render.rs` with
the direct callsites listed in the evidence table. Use a distinct wrapper for
each callsite unless a proven lock-free dispatcher preserves a separate
predecessor for every site.

Install independent complete groups:

- ImageSpace: `0x00876136`;
- Water: `0x004E1D7C`, `0x004E1DB1`, `0x008728AE`;
- World: `0x00870AE8`, `0x00870E18`;
- FirstPerson: `0x0087093D`, `0x00870B21`, `0x00870F74`;
- PreAlpha: `0x00B6653D`, `0x00B665A6`.

Preserve exact ABIs and predecessor ordering. A group with multiple callsites
publishes only if every callsite needed for correct phase classification
commits.

Preserve the accepted effect order:

1. Shadows and atmosphere before alpha.
2. World and post-world AO/motion blur at their established phases.
3. Scene-pre, native image-space, scene-post, then final.
4. Presentation only for fallback, menu, servicing, and epoch completion.

Feature dependencies replace the current monolithic scene-ready assumption.
Depth-independent present effects may survive a missing world hook;
first-person motion blur requires both World and FirstPerson; atmosphere and
shadow consumption require PreAlpha; underwater-sensitive classification
requires the complete Water group.

## Geometry, PBR, And Sky

### Geometry submission

At `DeferredInit`, resolve the live renderer vtable and chain:

- TriShape method 109 at `+0x1B4`;
- TriStrips method 110 at `+0x1B8`.

The two slots form one Geometry transaction. Preserve the existing
`render_geometry`, shadow submission, and predecessor semantics. PBR, native
sky, and native shadows depend on the complete Geometry capability.

### Texture observation

Resolve the live render-state object at `renderer + 0x8B8` and chain method 55
at `+0xDC`, currently `SetTexture @ 0x00E88A20`. Keep the observer shared by
PBR and sky. Do not use D3D getter calls or a live device vtable as an
alternative.

### Shader selection

Using the proven PPLighting selector index-4 object and slot `+0xF4`, replace the shared
`SetShaders @ 0x00BE1F90` entry hook with a pointer-slot chain on only the
proven PPLighting selector slot. Preserve the current temporary wrapper-handle
scope and selection behavior. Failure blocks PBR only.

### Shader creation

Remove the `CreateVertexShader @ 0x00BE0FE0` and
`CreatePixelShader @ 0x00BE1750` hooks and remove `CREATION_HOOKS_READY`.

Rely on the existing mechanisms instead:

- adopt engine shader wrappers already present when PBR becomes available;
- lazily adopt a wrapper on first observed use;
- adopt newly created or reloaded FSL wrappers through the same first-use
  contract.

No FSL-specific adapter is required for correctness. Tests must cover startup
enablement, startup-disabled then runtime-enabled PBR, and shader reload/new
wrapper adoption.

### Shader package

Replace the `SetShaderPackage @ 0x00B4F710` entry hook with direct-call hooks
at `0x004DB187` and `0x004DCB9D`.

Preflight both callsites, package tables, wrapper ranges, and lifetime patch
locations before changing SLS or global engine state. Commit the hook group
first, then perform validated, effectively infallible table/SLS publication
last. A failure must not leave a partial package install.

The existing lifetime `OwnedCodePatch` may keep its same-value/idempotent
behavior, subject to the same ownership and rollback audit.

### Terrain contract

Remove `GraphicsCompatibility::has_vpt_terrain_contract()` and any filename or
version test from terrain behavior admission.

Add a functional `pbr::engine_contracts::probe_terrain_contract()` after
package/wrapper adoption. It validates the exact shader tables, wrapper
vtables, pass rows, material ABI, constants, and required resources. A DLL
name may appear in diagnostics, but it never enables or disables terrain.

DepthResolve remains an explicitly documented provider adapter because its
legacy API lacks generic discovery. That adapter must not affect core hook
ownership or admission for unrelated effects.

### Native sky

Using the proven SkyShader selector index-10 object and slot `+0x7C`, replace the
`UpdateConstants @ 0x00B89D80` entry hook with a pointer-slot chain on the
current live target. Preserve the existing classification, constants, and
draw gate. A missing or changed slot disables native sky only.

## Shadows And Local Lights

The implementation must integrate the current in-progress shadow/world-context
changes rather than reverting or duplicating them.

Replace the common shadow entry interception with separate direct-call
wrappers at:

- `0x00870851`;
- `0x00870A74`;
- `0x00870C3C`.

Each wrapper statically identifies its main, special, or screenshot variant
and preserves the required `ECX`/`EBP` ABI. This should replace return-address
inference where the callsite itself proves the variant.

Separate shadow behavior into two capabilities:

1. Observer mode invokes the captured predecessor and may publish scalar-light
   context around any cooperative producer.
2. Native replacement is available only when the common engine implementation
   remains the exact proven vanilla contract and Geometry plus PreAlpha are
   available.

If another owner has replaced the common shadow implementation, observer
chaining can remain active while OMV native replacement fails closed. Local
volumetric lights may continue without an OMV-produced shadow map.

Replace the completed-shadow entry hook at `0x00B9F780` with its unique direct
callsite at `0x00B5B9DC`. Invoke the captured predecessor first, then validate
and retain the completed output.

Preserve special/screenshot native pass-through, the current main-context
guard, and at-most-once publication for each epoch/device combination.

## Diagnostics

Add a read-only Interoperability section to the OMV diagnostics UI containing:

- capability name;
- active, unavailable, or dependency-blocked state;
- concise functional reason;
- captured predecessor module and address when available.

Emit one concise startup capability matrix. Do not emit per-frame ownership
logs. The UI is diagnostic state, not configuration, and therefore adds no
schema or preset field.

Diagnostics must distinguish:

- disabled by user configuration;
- unavailable because its engine contract could not be chained safely;
- dependency-blocked by another unavailable OMV capability.

It must not assert that a particular external mod is incompatible without
direct evidence.

## Implementation Slices

Do not implement this redesign as one large diff. Each slice has its own
source, test, build, startup-footprint, and runtime acceptance gate.

1. **Stabilize the baseline.** Finish or isolate the in-progress shadow/depth
   slice and identify the latest cold-load-to-gameplay accepted artifact.
2. **Close static research.** Completed 2026-08-14 for the PPLighting selector
   and SkyShader slots, object lifetimes, family coverage, and ABIs.
3. **Add hook primitives.** Implemented and focused-test accepted 2026-08-14;
   startup/runtime acceptance remains part of the first consuming OMV slice.
4. **Migrate presentation and reset.** Source-complete 2026-08-14: xNVSE owns
   presentation and the unique Recreate caller is chained independently.
5. **Migrate scene phases.** Source-complete 2026-08-14: ImageSpace, Water,
   World, FirstPerson, and PreAlpha are independent all-or-nothing groups.
6. **Migrate geometry and texture observation.** Source-complete 2026-08-14:
   live renderer/render-state slots replace shared entries; essential reset is
   independent of optional geometry.
7. **Migrate PBR.** Source-complete 2026-08-14: selector/package routes chain,
   shader-creation hooks are absent, and terrain uses a functional probe.
8. **Migrate native sky.** Source-complete 2026-08-14 through the proven
   SkyShader selector slot.
9. **Migrate shadows and local lights.** Source-complete 2026-08-14 in
   `fnv_local_lights.rs`: caller variants and completed-output observation are
   independent from exact-native replacement admission. This statement does
   not modify or supersede the separately in-progress shadow shader/pipeline
   work.
10. **Finish diagnostics and documentation.** Source-complete 2026-08-14:
    the startup/UI capability matrix and durable ownership documentation are
    implemented. Full release validation and the compatibility/performance
    playtest matrix remain open.

No slice becomes the next startup baseline until the required
BaseObjectSwapper Proton load-to-gameplay playtest accepts it.

## Automated Validation

Focused and final gates are:

```bash
cargo test --target i686-pc-windows-gnu -p libpsycho --lib
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes \
  -p psycho-engine-fixes-helper -p omv
git diff --check
```

The focused suites must prove:

- i686 wrapper ABI correctness;
- every predecessor is invoked exactly once;
- a changed instruction or pointer is never overwritten;
- rollback is ownership-aware and reverse ordered;
- capability routes remain false before `DeferredInit`;
- a group never publishes partially;
- optional failure is feature-local;
- loading-screen presentation does not run gameplay fallback;
- reset releases before and republishes after its predecessor;
- accepted effect phase and ordering invariants remain unchanged;
- production installation no longer targets the removed shared entries;
- shader-creation hook addresses are absent;
- module names cannot control behavior;
- schema-1 config and preset round trips remain exact.

Synthetic compatibility tests must cover:

- a predecessor installed at the common callee entry before OMV;
- a predecessor already installed at a direct callsite;
- a predecessor already installed in an engine vtable slot;
- a well-behaved later owner chaining OMV;
- an unknown or non-`E8` callsite blocking only its dependent capability;
- a modified common shadow implementation allowing observation but rejecting
  exclusive OMV native replacement.

Run `git diff --check` and inspect the complete final diff for unrelated
changes. Because `libpsycho` is shared, its final release validation includes
all supported FNV DLLs, not only OMV.

### Source validation evidence (2026-08-14)

The implemented source passed:

```text
cargo test --target i686-pc-windows-gnu -p libpsycho --lib
  37 passed
cargo test --target i686-pc-windows-gnu -p omv
  644 passed; 0 failed; 0 ignored
cargo build --release --target i686-pc-windows-gnu -p omv
  passed
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes \
  -p psycho-engine-fixes-helper -p omv
  passed
git diff --check
  passed
```

The full build emitted the existing mimalloc C unused-parameter/pragma and
MinGW stdcall-fixup warnings. One intermediate focused build also observed a
dead-code warning in the simultaneously edited world-pipeline slice; that
warning was absent from the final supported build after the parallel edit
advanced. `cargo fmt --all -- --check` passed for this compatibility slice,
then the final combined-worktree check reported only an indentation delta in
the parallel depth edit at `backend/fnv.rs:2641`; it was deliberately not
modified here. Final whitespace and diff-scope inspection otherwise passed.
The shadow test/world-pipeline slice and its camera selection hunk in
`fnv_render.rs` remain outside this work's ownership.

The release artifact at this source state is 12,826,970 bytes with SHA-256
`fbde3b26ca7243a6734d5821f9cbaa151cba2bc8bd2986080c8e6e388e47dc69`.
It has nine sections, `SizeOfImage 0x8CF000`, `.text 0x5533A8`,
`.data 0x15B04`, `.rdata 0x2A1434`, `.eh_fram 0x7CF6C`, `.bss 0x6B10`,
`.idata 0x340C`, `.tls 0x8`, `.reloc 0x37D08`, a `0x18` TLS directory,
IAT size `0x6BC`, and no delay-import directory.

The last accepted startup baseline `9975b2e` is documented as a 12,432,517-byte
DLL with SHA-256
`4243c87d1f8cf288e9194c68358f8365dc1b1a4e1099852860ef65f8b187ba60`.
That baseline binary is not retained in the current workspace, so a new
symbol-by-symbol comparison could not be rerun; the current PE facts above are
compared against the durable baseline evidence rather than an assumed local
artifact. The 394,453-byte file delta includes all concurrent work visible in
the shared worktree and cannot be attributed only to interoperability.

The current source deliberately adds no pre-Deferred first touch: new hook
objects are first forced from the established `DeferredInit` installers, the
interoperability snapshot/log runs only after the complete gate is published,
and module-owner formatting runs only in the visible Diagnostics tab. It does
change the final DLL's code/static footprint and therefore is not startup-safe
until the required BaseObjectSwapper Proton load-to-gameplay playtest accepts
this exact artifact.

## Runtime Acceptance Matrix

Test at minimum:

- OMV alone;
- OMV with Fallout Shader Loader;
- VPT/FSL/LODFF/DepthResolve combinations;
- ENB or another `d3d9.dll` proxy;
- the full affected mod list;
- reset, alt-tab, resolution changes, loading screens, menus, screenshots,
  and special render paths;
- the affected NVIDIA GPU and an AMD sanity configuration.

Acceptance is separated into four independent claims:

1. **Startup safety:** a cold Proton launch with BaseObjectSwapper reaches
   gameplay and logs the deferred-hook marker. Record the accepted artifact
   as the new startup baseline.
2. **Compatibility:** OMV never overwrites an unknown owner, every predecessor
   runs exactly once, failures remain feature-local, and no partial group is
   published.
3. **Visual correctness:** the accepted effect equations, order, coverage,
   state restoration, screenshots, and special passes show no regression.
4. **Performance:** no new routine allocation, draw, copy, shader compilation,
   state capture, blocking lock, or per-frame diagnostic work is introduced;
   the affected NVIDIA full-modlist playtest no longer reaches the reported
   pathological performance.

Passing static tests or a release build does not prove any of these runtime
claims. The NVIDIA issue must not be called resolved until the affected
configuration passes the runtime matrix.

## Documentation Updates During Implementation

Update existing subsystem documents rather than creating redundant plans:

- this document remains the authoritative capability and chaining contract;
- [`graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md`](graphics_fnv_omv_nvr_hook_d3d9_nvidia_research.md)
  owns address, xref, vtable, and external-hook evidence;
- [`graphics_fnv_omv_nvidia_remediation_implementation.md`](graphics_fnv_omv_nvidia_remediation_implementation.md)
  records implemented slices and measured performance results;
- [`graphics_fnv_native_sky.md`](graphics_fnv_native_sky.md) owns the proven
  sky slot and lifecycle;
- [`graphics_fnv_pbr_errata.md`](graphics_fnv_pbr_errata.md) owns PBR ABI and
  prohibited-pattern updates;
- [`graphics_fnv_nvr_shadows_engine_contract.md`](graphics_fnv_nvr_shadows_engine_contract.md)
  owns shadow caller, ownership, lifetime, and replacement evidence;
- [`graphics_fnv_depth_resolve.md`](graphics_fnv_depth_resolve.md) owns the
  explicit DepthResolve provider boundary;
- the startup erratum is updated only after the required user playtest and
  records the artifact, baseline comparison, and observed result.

Implementation and documentation changes remain uncommitted unless the user
separately authorizes a specific commit.

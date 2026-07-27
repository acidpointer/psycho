# FNV atmosphere startup crash errata

Status: fixed and playtested on 2026-07-18.

The original atmosphere incident is closed. A separate PBR cache regression on
2026-07-27 reproduced the same pre-DeferredInit crash class and is awaiting the
load-to-gameplay A/B test described below.

## Incident

The first Phase 2 reliability build crashed while Fallout NV was loading game
data. Disabling OMV removed the crash. The crashing OMV build was
`unix=1784392287`.

The OMV log stopped after `NVSEPlugin_Load` and the xNVSE `PostLoad`
compatibility report. It did not contain:

- `[INIT] Deferred OMV graphics hooks initialized`;
- any FNV scene-hook installation;
- any Direct3D Present/Reset hook installation;
- any world-transaction telemetry.

Therefore no atmosphere shader, D3D resource, scene callback, or render-time
`try_lock` path had executed. Shader and render-hook debugging cannot explain
this class of failure.

## Resolved OMV trigger

The new reliability implementation published its initial
`GraphicsMenuConfig` to `fnv_world_pipeline` from `runtime::configure`, which is
called by `NVSEPlugin_Load`. That publication was also the first initialization
of the focused world's `LazyLock<Mutex<PublishedConfig>>` owner.

The fix was deliberately narrow:

1. `runtime::configure` continues to run during plugin load and continues to
   use its normal blocking configuration lock.
2. Plugin load copies the menu config into `DeferredHookSettings` without
   touching `fnv_world_pipeline`.
3. `install_deferred_hooks`, called for xNVSE `DeferredInit`, performs the first
   world-config publication immediately before graphics hooks are installed.
4. Render callbacks and render-owned depth/world owners remain
   `try_lock`-only. This incident does not justify using `try_lock` for ordinary
   startup configuration.

The passing build was `unix=1784395226`. Its log reached DeferredInit, installed
all four FNV scene hooks and the Direct3D hooks, entered the game, and reported
more than 21,600 Presents without repeating the loading crash.

This A/B result proves the unsafe phase placement of the first world-owner
publication as the OMV-side trigger. It does not prove the lower-level memory
corruption mechanism.

## External fault site

CrashLogger reported `EXCEPTION_ACCESS_VIOLATION` in BaseObjectSwapper:

- `ConditionalInput::IsValid + 0x88`;
- `ConditionalData.cpp:95`;
- failure inside `std::variant` visitation;
- corrupt stack/heap entries after the top two BaseObjectSwapper frames.

The available BaseObjectSwapper source also leaves `currentWorldspace` and
`currentRegionList` raw members uninitialized on some constructor paths in
`.research/BaseObjectSwapperNV-master/src/ConditionalData.h`. That is genuine
undefined behavior in the external plugin, but it is not evidence that OMV
wrote into BaseObjectSwapper memory. The defensible conclusion is:

- OMV's premature world-owner publication was a necessary trigger in this
  modpack and was fixed;
- BaseObjectSwapper was the observed fault site and contains an independent UB
  hazard;
- the exact timing/allocation path connecting them is not proven.

Do not rewrite this incident as either "BaseObjectSwapper alone caused it" or
"OMV directly corrupted BaseObjectSwapper." Neither claim is established.

## Do not repeat

- Never call `fnv_world_pipeline::publish_config` from
  `NVSEPlugin_Load`, `runtime::configure`, preload/query callbacks, a DLL entry
  point, or another earlier startup phase.
- Keep `DeferredHookSettings.menu_config`; it is the phase handoff that lets the
  world owner remain dormant during data/plugin loading.
- The first world-config publication belongs in `install_deferred_hooks` before
  scene and D3D hooks become reachable.
- Do not replace working startup/configuration locks with `try_lock` in response
  to a render-lock rule. Blocking is forbidden on render callbacks, not on
  serialized startup configuration.
- When a crash log stops before `[INIT] Deferred OMV graphics hooks initialized`,
  first audit load-time initialization and message phases. Do not tune shaders
  or render-stage selection for a callback that never ran.
- Every future world-owner/startup change needs a load-to-gameplay smoke test.
  The log must show the DeferredInit publication, hook installation, and live
  Present telemetry.
- Do not add Rust `thread_local!`, a TLS destructor, or another new DLL TLS
  owner for an OMV render cache without explicit startup-phase proof and a
  load-to-gameplay smoke test. Prefer statically initialized POD/atomic state
  whose first operational access remains behind DeferredInit.

The source comments in `omv/src/runtime.rs` and `omv/src/startup.rs`, this
erratum, and the root `AGENTS.md` rule are all intentional safeguards. Do not
remove them without replacing the phase contract with stronger evidence.

## 2026-07-27 PBR TLS regression

The first close-terrain draw-scope correction added a
`thread_local! Cell<TerrainLightDrawCache>` to `terrain_lights.rs`. Although the
cache was intended for render callbacks, this changed the injected DLL's TLS
startup footprint before any render callback ran.

The deployed OMV DLL exactly matched the local release artifact and reported
`unix=1785178325`. The fresh OMV log stopped after startup configuration,
compatibility discovery, and the first screen-space shader load. It did not
reach `[INIT] Deferred OMV graphics hooks initialized`, PBR hook installation,
or Present telemetry. CrashLogger then reported:

- `EXCEPTION_ACCESS_VIOLATION`;
- BaseObjectSwapper `ConditionalInput::IsValid +0x88`;
- corrupt stack/heap entries;
- about ten seconds of playtime while game data was still loading.

This is the same phase boundary and external fault signature as the 2026-07-18
incident. It proves that the terrain draw algorithm had not executed. The new
TLS owner is the only load-time construct introduced by the close-terrain fix
and is therefore the strongest OMV-side trigger candidate, but only a passing
replacement build can close that attribution. Do not investigate or patch
BaseObjectSwapper as the response to this OMV regression.

The correction removes the TLS owner entirely. The light cache now consists of
fixed zero-initialized atomics: a geometry key, an even/odd publication version,
a bounded light count, and packed float words. Readers accept a snapshot only
when its version and geometry remain stable. A concurrent publisher uses one
compare-exchange; contention bypasses caching instead of spinning or blocking.
There is no lazy initialization, destructor, lock, allocation, `UnsafeCell`, or
plugin-load function call.

Repository tests reject `thread_local!` in the production terrain-light module
and verify that atomic publication reproduces the shader constant payload
exactly. The required runtime closure is unchanged: the replacement build must
load into gameplay and log DeferredInit, installed graphics hooks, and live
Present telemetry before terrain visuals are evaluated.

Static validation passed all 339 OMV tests and the supported release build. The
corrected DLL SHA-256 is
`80d82b781e1575b76cc1d5ca183d37fc5519bc888931b24a42c4e20a49ffea2b`.
Symbol inspection places `DRAW_CACHE_VERSION`, `DRAW_CACHE_GEOMETRY`,
`DRAW_CACHE_COUNT`, `DRAW_CACHE_IDENTITIES`, and `DRAW_CACHE_COMPONENTS` in
`.bss`; the removed `TerrainLightDrawCache` TLS symbol is absent.

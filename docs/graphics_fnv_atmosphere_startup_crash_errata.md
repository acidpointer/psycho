# FNV atmosphere startup crash errata

Status: fixed and playtested on 2026-07-18.

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

The source comments in `omv/src/runtime.rs` and `omv/src/startup.rs`, this
erratum, and the root `AGENTS.md` rule are all intentional safeguards. Do not
remove them without replacing the phase contract with stronger evidence.

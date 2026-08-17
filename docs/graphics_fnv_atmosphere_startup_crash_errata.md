# FNV atmosphere startup crash errata

Status: fixed and playtested on 2026-07-18.

The original atmosphere incident is closed. A separate PBR cache regression on
2026-07-27 reproduced the same pre-DeferredInit crash class and is awaiting the
load-to-gameplay A/B test described below.

The authoritative repository-wide account of the external defect, compiled
binary evidence, attribution limits, prohibited mod-specific responses, and
future-change protocol is `docs/nvse_startup_phase_safety.md`. This erratum
retains OMV's incident chronology and local startup invariants.

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
- Keep an explicit staged-config handoff into DeferredInit. The original fix
  stored `menu_config` directly in `DeferredHookSettings`; the current depth
  fallback path stores it in the dormant runtime model and returns the
  effective menu config from `apply_initial_depth_activation`. Neither form may
  publish the world owner or a newly added hook admission early.
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

## 2026-08-03 CPU-only PBR prewarm boundary

Native PBR preparation now begins earlier when the settings staged by
`NVSEPlugin_Load` enable it. This is a deliberately narrower startup operation
than the world-owner and TLS regressions above:

- `startup::initialize_for_nvse` first stores the complete
  `DeferredHookSettings` handoff, then calls
  `pbr::start_cpu_preparation(native_pbr)`;
- the public PBR boundary only tests the immutable enabled bit and enters the
  process-owned compiler module;
- that module may read embedded source, inventory the reconstructible shader
  cache, load `D3DCompile`, allocate worker-owned memory, and compile bytecode;
- it cannot inspect an engine object or D3D device, create a D3D shader, install
  a hook, configure PBR runtime state, or touch `fnv_world_pipeline`.

DeferredInit remains the first world-config publication and the only initial
owner of PBR installation, engine contracts, and graphics hooks. Present
remains the D3D-resource creation owner. A source-order regression rejects an
early `fnv_world_pipeline::publish_config` or `pbr::install` call and requires
the settings handoff to precede CPU prewarm.

Static tests prove the source boundary but cannot prove compatibility with the
known load-time external allocator/timing sensitivity. Required runtime
acceptance is a normal cold-cache load into gameplay. The log must show PBR
inventory or compilation beginning before DeferredInit, followed by the
unchanged DeferredInit world publication, hook installation, preparation
completion, and live Present telemetry without the BaseObjectSwapper startup
crash signature.

## 2026-08-10 motion-blur config ABI regression

The first-person motion-blur correction produced another OMV-dependent crash
at the established BaseObjectSwapper-sensitive startup boundary. The deployed
release artifact reported `unix=1786366301`, source commit `cf600745` with a
dirty worktree, and a build time corresponding to the implementation under
test. The captured OMV log is
`.reports/omv-2026-08-10-155159-motion-blur-startup-crash.log`.

### Proven phase evidence

The log reached `NVSEPlugin_Load`, compatibility discovery, native-sky cache
reads, native-PBR cache inventory, and one external screen-shader cache read.
It did not contain:

- `[FNV WORLD] Initial config published at DeferredInit`;
- `[INIT] Deferred OMV graphics hooks initialized`;
- resident FNV scene-hook installation;
- any Present or scene transaction.

Consequently the new `RenderWorldSceneGraph`/`RenderFirstPerson` logic, D3D9
transaction, world-only shader, and retry token had not executed. The user
observed the BaseObjectSwapper fault. The corresponding full CrashLogger trace
was overwritten by the next launch, so the current incident does not provide a
new durable call-stack artifact; the earlier exact fault evidence remains in
`.reports/CrashLogger-2026-08-04-194321-pbr-startup-crash.log` and the incident
sections above.

### Exact new load-time path

The first-person rendering change did not add a `LazyLock`, TLS owner, engine
call, D3D call, or hook installation to `NVSEPlugin_Load`. It did make an
unnecessary configuration ABI transition there:

1. `MotionBlurConfig.first_person_strength` was removed, changing the nested
   `EmbeddedEffectsConfig`/`GraphicsMenuConfig` value layout copied through
   startup.
2. `CONFIG_SCHEMA_VERSION` was changed from 1 to 2, the shipped working config
   changed shape, and a second frozen preset manifest was added.
3. The built-in preset payload/version changed and schema-1 presets acquired a
   new migration that removed the field.
4. `ScreenShaderRuntime::configure`, which is called by `NVSEPlugin_Load`,
   starts `PresetService`. Its worker immediately constructs the built-in
   preset, scans installed presets, validates frozen shapes, and runs registered
   migrations. This is before DeferredInit and was the newly introduced
   allocation/serialization path in the known BaseObjectSwapper-sensitive
   interval.

By contrast, config-enabled screen-effect preparation, native sky preparation,
native PBR preparation, asset scanning, and existing scene-input publication
were all present in the accepted parent build. Moving those established
operations to DeferredInit was an over-broad attempted fix: it changed shader
readiness and loading latency without isolating the new owner. The captured log
does not record motion-blur compilation before the crash.

### Surgical correction

The correction preserves the complete world-only first-person implementation:

1. Configuration and presets remain schema 1. The preset manifest, built-in
   version `1.0.0`, and payload revision remain unchanged.
2. `first_person_strength` remains present in Rust, shipped TOML, saved TOML,
   and presets as a deprecated compatibility value, restoring the accepted
   nested value layout and eliminating the new startup migration path.
3. The field is absent from the menu and from `MotionBlurSettings`, temporal
   sequence comparison, shader constants, and HLSL. Its value has no rendering
   effect.
4. `service_enabled_effect_preparation` remains in `runtime::configure`; the
   prior process-owned worker lifecycle is unchanged.
5. Existing scene requirements retain their prior publication behavior. Only
   the new first-person-motion-blur admission is false during plugin load and
   is published by `apply_initial_depth_activation` at DeferredInit before the
   resident scene-hook group becomes reachable. A failed deferred attempt
   clears only that new admission before retry.

The phase boundary and newly introduced OMV path are established by source and
the captured log. The exact allocator/timing interaction with
BaseObjectSwapper's independent undefined behavior remains inference, just as
in the earlier incidents.

Runtime acceptance passed on 2026-08-10: the replacement DLL completed an
ordinary load-to-gameplay playtest through the previously failing startup
interval, motion blur worked in game, and the BaseObjectSwapper crash did not
recur. This is a runtime observation, not proof of the lower-level external UB
mechanism.

## 2026-08-10 rejected phase-capability experiment

An uncommitted experiment attempted to protect the startup boundary by adding
phase capabilities throughout `libnvse` and moving the dashboard from the
helper to the early core. It changed shared APIs, final DLL ownership, imports,
layout, and startup behavior far beyond the new delta which needed review.

The supported-target tests and complete release build passed, but the user's
Proton playtest crashed at the same BaseObjectSwapper RVA `0x4990` before
DeferredInit. The latest traces carried `eax = 1`, another small indeterminate
`currentWorldspace` value. Static success therefore did not establish runtime
compatibility, and the experiment is not an accepted startup baseline.

This crash does not justify a broader phase framework or intervention in
BaseObjectSwapper. Preserve the established source-order boundary and follow
the surgical, mod-agnostic procedure in
`docs/nvse_startup_phase_safety.md`.

## 2026-08-11 adaptive-response corrections awaiting playtest

The automatic exposure/tone follow-up changes embedded HLSL payload, the
final-color shader catalog, post-device response resources, and one D3D9
capability-wrapper body. It preserves schema 1, every persisted field and
preset payload, the existing final-color preparation worker and its start
order, the DeferredInit timing admission, hook groups, world publication, TLS,
and static-owner set. The new capability method is called only while creating
the device-owned final-color effect; no plugin-load or pre-Deferred caller was
added.

The later visibility/performance correction stays within the same runtime-only
owners. It changes the embedded response and compose payloads, reduces the two
post-device response textures from 256x1 to 128x1, and adds a plain two-scalar
update clock to the device-owned `BloomingHdrEffect`. It does not add or
first-touch a static, lock, TLS value, worker, parser, config value, preset
payload, publication atomic, hook, or admission path before DeferredInit. The
shader preparation worker, catalog publication, device creation, and hook
ordering remain unchanged.

The 2026-08-12 visible-tone follow-up changes only the equations in those same
embedded shaders, finite bounds for the three existing numeric schema-one
controls, the post-Deferred Present-clock condition, and one success log
emitted after the first render-time FP16 response allocation. Removing Color
Grade strength from adaptive gating does not open a new admission route: the
timing publication is still absent from `runtime::configure` and first runs in
`apply_initial_depth_activation` at DeferredInit. No field was added, removed,
reordered, or retyped; the schema, preset payload, worker/static set, hook
groups, and preparation order remain unchanged.

Those source-order facts keep the correction inside the established runtime
architecture, but changed code and embedded data still change the final OMV
DLL footprint. Commit `9975b2e` therefore remains the last documented
load-to-gameplay startup baseline. Static shader tests, strict config/preset
round trips, the full OMV suite, and the supported release build are necessary
but cannot accept this artifact. Acceptance requires at least three cold
Proton load-to-gameplay runs with BaseObjectSwapper installed, followed by
normal gameplay and live Present telemetry without the known `+0x4990` fault.
Record the tested commit/artifact hashes and logs here only after that runtime
evidence exists.

## 2026-08-12 native Shadows startup rejection and correction

The initial native Shadows implementation changed the final OMV DLL and the
load-to-Deferred configuration footprint. Commit `9975b2e` remains the
last documented load-to-gameplay startup baseline; the concurrent
adaptive-response work and this shadow route are both later, statically validated deltas
and are not an accepted startup baseline.

The exact rejected pre-Deferred footprint was:

- `GraphicsConfig` and its menu handoff contain one new
  `NativeShadowsConfig` with master/location toggles and bounded appearance or
  work controls. This is the explicit persisted control surface required by
  the feature. Schema 1, every earlier field, the preset manifest/version, and
  the built-in preset payload remain unchanged; missing shadow values default
  compatibly to modern NVR's high/custom profile.
- `DeferredHookSettings` carries the sanitized settings to `DeferredInit`.
  `NVSEPlugin_Load` publishes them through zero-initialized `AtomicU8`/`AtomicU32`
  fields guarded by a sequence counter. It does not touch an engine pointer,
  D3D device, lock, or shader compiler through the shadow module.
- The final DLL adds the settings atomics, `ROUTE_READY`, and the
  `LazyLock<Mutex<ShadowPipeline>>` static owner plus eleven embedded SM3 shader
  sources. The lazy pipeline, route atomic, shader-preparation worker, engine
  validation, and every COM resource are first touched at or after
  `DeferredInit`; only plain settings atomics are accessed earlier. The reader
  is bounded and fail-safe, so neither load nor a render callback waits on a
  configuration lock.
- The existing engine-hook group still owns the already-established common
  entry `0x00871290`. Shadow admission opens at `DeferredInit` immediately
  before that group becomes resident. The existing scene-pre and renderer
  recreate hooks gain runtime-only consumer and reset calls; neither executes
  during plugin/data loading.
- New D3D9 helpers are COM vtable wrappers and add no intended Windows DLL
  import. No shadow TLS value, destructor, early file scan, early allocation
  worker, hook, or world publication was added.

That atomic-only argument was insufficient. The subsequent Proton run failed
at BaseObjectSwapper's already-documented uninitialized `ConditionalInput`
path before OMV logged `[INIT] Deferred OMV graphics hooks initialized`. The
failure does not prove that an individual shadow atomic store corrupted engine
state; it rejects the complete changed plugin/data-loading footprint. In
particular, the larger `GraphicsConfig`, `GraphicsMenuConfig`,
`RuntimeSettings`, Current Look snapshot/event graph, and
`DeferredHookSettings` were all constructed or copied before `DeferredInit`.

The surgical correction preserves the entire Shadows implementation and
restores that ownership boundary:

- `NativeShadowsConfig` and the schema-one `[graphics.native_shadows]` table
  remain unchanged, including all fourteen controls and their defaults. A
  dedicated parser reads and sanitizes only this table after xNVSE enters
  `DeferredInit`; the ordinary plugin-load typed deserializer ignores it.
- `GraphicsConfig`, `GraphicsMenuConfig`, `RuntimeSettings`, Current Look
  snapshot/event values, and `DeferredHookSettings` no longer carry shadow
  state. `NVSEPlugin_Load` neither deserializes shadow settings into that value
  graph nor calls the shadow atomic publisher. Regression tests enumerate
  every one of these owners and reject reintroduction of shadow state.
- Deferred startup loads the table before engine hook installation, then
  validates the engine contract, initializes the existing lazy pipeline,
  starts the existing shader preparation, and opens the existing route at the
  same point immediately before the common hook becomes resident. No shader,
  resource, quality setting, hook, admission bit, or render ordering was
  removed or postponed beyond its established deferred boundary.
- ImGui reads a coherent copy directly from the shadow settings atomics and
  publishes edits back through the same sequence counter. The graphics master
  masks only render admission, so disabling it cannot overwrite the persisted
  per-effect switch. Current Look autosave writes that coherent post-Deferred
  snapshot on its existing worker; external reload parses and publishes the
  table on that same worker without changing its pre-Deferred command, event,
  or snapshot layouts.

This correction is statically bounded but is not a new accepted startup
baseline. It requires the same cold Proton load-to-gameplay evidence with
BaseObjectSwapper installed; only a run that reaches the deferred marker can
exercise any shadow hook or shader path.

The captured crashing worktree artifact was 12,843,405 bytes with SHA-256
`2f163362698c6a54d608a701e483d851fced448c9219855d05c4b084e0dd238b`.
The corrected supported release build is 12,822,605 bytes with SHA-256
`8c5b55dcac328ad5f5f6fc96a2e06f442f285dfd84b7af2e9050645bd4971c`.
The import table remains `0x340c`, the import-address table remains `0x6bc`,
the imported DLL/function set is identical, `.tls` remains `0x8` with the same
`0x18` thread-storage directory, and `.bss` remains `0x6b10`; no shadow owner
or render resource was removed. Restoring the smaller pre-Deferred value graph
reduces initialized `.data` from `0x15964` to `0x158c4`. All 571 supported-target
OMV tests pass, including 78 focused shadow tests and the new startup/config
negative controls, and the explicit supported release build completes without
warnings. These facts prove only the intended static correction and artifact
footprint; they do not replace the required Proton playtest.

An isolated same-toolchain build of source baseline `9975b2e` produced a
12,432,517-byte DLL with SHA-256
`4243c87d1f8cf288e9194c68358f8365dc1b1a4e1099852860ef65f8b187ba60`.
The current combined worktree artifact is 12,672,660 bytes with SHA-256
`a9f12aadaabc9fcac516794dddf24b4a3b9d6ff90fd8fcafeee50b2851a9b6b2`.
PE inspection reports an identical imported-DLL/function set, unchanged
`.idata` size `0x33fc`, and unchanged `.tls` size `0x8`. The combined artifact
increases `.text` by 119,552 bytes, `.rdata` by 41,312, `.data` by 5,920,
`.bss` by 3,072, `.eh_fram` by 6,264, and `.reloc` by 3,660. Those section
deltas include the concurrent adaptive-response work present in the worktree and
therefore are the complete current footprint comparison, not shadow-only size
attribution.

The compiler-corrected shadow build produced a 12,712,012-byte `omv.dll` with
SHA-256
`9c9b2ef0082be074d55f7b5301a9f0a860e8446634069193b99b3f7c1de648a3`.
PE inspection still reports the documented imported-DLL set, `.idata` size
`0x33fc`, and `.tls` size `0x8`. Its current relevant sections are `.text`
`0x557e68`, `.rdata` `0x294474`, `.data` `0x15484`, `.bss` `0x6b10`,
`.eh_fram` `0x7cdd4`, and `.reloc` `0x37774`. The cube shader correction changes
only embedded post-Deferred source bytes and its regression test; it adds no
new import, static owner, TLS value, or pre-Deferred operation. The larger
static settings/config shape and code/data movement are not an accepted startup
baseline; commit `9975b2e` remains the last load-to-gameplay evidence.

The bounded-producer correction produced a 12,710,264-byte `omv.dll` with
SHA-256
`441d212ae7b494d0e7c691b16f3a2dc5a80afaee945b63fc7c2d334dce70c586`.
Its relevant sections are `.text` `0x557ee8`, `.rdata` `0x2944b4`, `.data`
`0x15484`, `.bss` `0x6b10`, `.eh_fram` `0x7ce70`, `.idata` `0x33fc`, `.tls`
`0x8`, and `.reloc` `0x377ac`. The imported-DLL set remains unchanged. This
correction adds only post-Deferred cascade scheduling, traversal policy, and
tests plus static documentation/evidence; it adds no static owner, TLS value,
import, configuration field, load-phase operation, or hook-admission change.
It therefore does not widen the pre-Deferred call graph, but it is still part
of the unaccepted combined artifact rather than a new startup baseline.

Source-order tests now require that every pre-Deferred config, menu, runtime,
persistence, and startup-handoff owner exclude shadow state; that
`NVSEPlugin_Load` neither loads nor publishes it; and that the isolated parser
runs at DeferredInit before engine hook installation. Engine hooks must precede
shadow admission, shadow admission must precede common-hook residency, and
scene-pre composition must precede the ordinary screen stack; resource release
must precede native device recreation. The original 2026-08-12 route passed 32
focused shadow tests and all 519 then-current OMV tests. The corrective pass
adds strict config round trips/bounds and source-order coverage for the
multi-field atomic publication. The bounded-producer pass adds exact tests for
neutral-atlas progressive bootstrap, projected caster thresholds, per-cascade
LOD admission, and modern-NVR form profiles. All 525 current OMV tests pass,
including 38 focused shadow tests, and the explicit supported release build
completes without warnings.

Those checks cannot accept this changed startup artifact. No load-to-gameplay
claim was made during this implementation run. Startup compatibility remains
unproven until a cold Proton load reaches gameplay with BaseObjectSwapper
installed and the log reaches `[INIT] Deferred OMV graphics hooks initialized`
without the known `+0x4990` fault. This is an acceptance boundary, not evidence
that any other mod should be detected, reordered, patched, or disabled.

### 2026-08-13 inline Shadows owner regression and correction

The next deployed artifact reproduced the exact known startup failure. The
local and deployed `omv.dll` files both measured 12,840,091 bytes and had
SHA-256
`08f5c84686f3e31a47e72ca710ecec7bcf0cc5c5cf69ab5a663cc40551efafe9`.
The OMV log identified source commit `8655505` with a dirty worktree and build
`unix=1786577934`. It stopped after plugin-load configuration, compatibility
discovery, existing sky/PBR preparation, and a LUT warning. It did not reach
`[FNV WORLD] Initial config published at DeferredInit` or
`[INIT] Deferred OMV graphics hooks initialized`. CrashLogger reports the
established BaseObjectSwapper RVA `0x4990` fault with `eax = 6`. These are
runtime facts; no shadow hook, pipeline initializer, compiler, or shader ran.

The tenth shadow pass preserved the documented call order and config boundary,
but violated the broader frozen-footprint warning in `omv/src/startup.rs`.
`PIPELINE` was a `LazyLock<Mutex<ShadowPipeline>>`; `LazyLock<T>` reserves `T`
inline in initialized PE storage even before it is forced. Removing temporal
contact resources while adding directional-cache state changed that exported
static from the last gameplay-reaching shadow build's `0xA28` bytes to
`0x9D0` bytes. Symbol sizes from same-toolchain supported release builds prove
the exact layout delta. This does not prove a byte-level causal link to the
external uninitialized pointer, but it is the only newly changed static owner
and is a direct violation of the repository's accepted startup rule.

The surgical correction keeps the complete new `ShadowPipeline` and every
shadow shader, setting, hook, and test. The `0xA28` loader-visible owner is now
a fixed-size compatibility slot containing a boxed pipeline. Its one heap
allocation occurs only when the existing `shadows::install` path explicitly
forces the owner at DeferredInit; plugin load neither allocates nor accesses
it. A 32-bit compile-time assertion and a runtime regression test both require
the exact `0xA28` owner size. `startup.rs` now explicitly documents that a
lazy value's inline payload is part of the frozen footprint even if its
initializer runs later.

This correction restores the identified static-owner shape but remains
statically accepted only. A cold Proton load with BaseObjectSwapper installed
must reach both deferred markers and gameplay before the corrected artifact
becomes a new startup baseline. No BaseObjectSwapper detection, patch, hook,
ordering change, or feature disablement was introduced.

Supported-target validation passes all 594 OMV tests, including 101 focused
shadow tests and the new exact owner-size guard, plus doc tests. The release
build produces a 12,846,995-byte `omv.dll` with SHA-256
`baa5aac1919d14a62357aeca5151057e2052385a9a640972969d6c55806afd3c`.
PE inspection reports the restored `PIPELINE` symbol at `0xA28`, unchanged
`.bss` size `0x6B10`, `.idata` size `0x340C`, `.tls` size `0x8`, thread-storage
directory size `0x18`, import-address-table size `0x6BC`, and the same imported
DLL/function set as the rejected artifact. These results prove the bounded
source and binary correction, not the required Proton startup result.

### 2026-08-15 detached dynamic-shadow quality field

The shared dynamic-shadow quality implementation appends
`dynamic_shadow_quality` after `sun_shadows` in the detached
`[graphics.native_shadows]` table. This intentionally preserves schema one,
all released field names/types/order, and the built-in preset payload. Missing
values select `high`, the released 512-square cube profile. The dedicated
shadow parser remains first called at DeferredInit; neither `GraphicsConfig`
nor `GraphicsMenuConfig` gains this value, and plugin-load staging continues to
ignore the whole shadow table.

The render-thread tier is encoded in two previously unused bits of the existing
`SETTINGS: AtomicU8` seqlock publication. The implementation adds no static
atomic, `LazyLock`, mutex, TLS value, thread, worker request, file scan, hook
admission bit, or plugin-load operation. Point resource profile and failure
state live only inside the boxed `ShadowPipeline`, after its established
DeferredInit force. The loader-visible `PIPELINE` owner remains guarded at
exactly `0xA28`.

This is nevertheless a shipped configuration-shape and final-binary change,
so source reasoning does not make it startup-safe. The accepted comparison
baseline remains commit `9975b2e`. Required closure is the focused startup and
round-trip suite, the complete supported-target OMV suite and release build,
PE owner/section/import comparison, followed by a cold Proton
load-to-gameplay run with BaseObjectSwapper installed. Until that runtime run
reaches both DeferredInit markers and gameplay, this section records design and
static evidence only; it is not a new accepted startup baseline.

Static closure passes all 670 supported-target OMV tests and doc tests, and the
explicit release build completes without warnings. The resulting DLL is
12,851,496 bytes with SHA-256
`1e7217f3b78ea346eb3461468e576f7a9948012a7ce58034e3194eacb2e3e6f8`.
Inspection proves that `PIPELINE` remains `0xA28`; `.bss` remains `0x6B10`,
`.idata` remains `0x340C`, `.tls` remains `0x8`, the thread-storage directory
remains `0x18`, and the import-address table remains `0x6BC`. The current
`.data` is `0x15744` and `.reloc` is `0x37BF8`; those changed final-image
sections reinforce, rather than remove, the load-to-gameplay requirement.

### 2026-08-15 detached dynamic-shadow fade field

The configurable point-shadow transition appends
`dynamic_shadow_fade_seconds` after `dynamic_shadow_quality` in the same
detached `[graphics.native_shadows]` table. The dedicated parser remains first
called at DeferredInit. `GraphicsConfig`, `GraphicsMenuConfig`,
`RuntimeSettings`, Current Look startup snapshots, preset manifests/payloads,
and `DeferredHookSettings` do not gain the field. Schema version one and every
released field name, type, and relative order remain unchanged; a missing value
selects the 0.75-second default without migration work.

The post-Deferred settings publisher stores the sanitized millisecond value in
unused bits of the established light-count `AtomicU32`. This intentionally adds
no static atomic and does not change `.bss`, the `PIPELINE` compatibility owner,
TLS, a lazy owner, lock, thread, worker request, parser phase, hook admission,
or world publication order. The wall-transport correction changes only
post-Deferred shader payload, boxed pipeline/resource code, and render-time
binding. It retains the two existing cube families and adds no persistent D3D
resource.

These source facts bound the new startup delta but do not accept the final
image. The final OMV binary and detached table shape still differ from commit
`9975b2e`, which remains the last documented load-to-gameplay baseline. Closure
requires strict config/startup tests, the full supported-target suite and
release build, exact `PIPELINE`/PE footprint comparison, and repeated cold
Proton load-to-gameplay runs with BaseObjectSwapper installed. Record hashes,
section/import results, and runtime evidence here only after those gates pass.

Static closure passes all 676 explicit supported-target OMV tests plus doc
tests, including 166 focused Shadows tests, and the release build completes
without warnings. The artifact is 12,933,163 bytes with SHA-256
`3df20252d7c5be54b390514fa2f0f8b127e9a8882d815f79efde7ba5461f3f87`.
The owner-size test retains `PIPELINE = 0xA28`; PE inspection retains
`.bss = 0x6B10`, `.idata = 0x340C`, `.tls = 0x8`, thread-storage directory
`0x18`, IAT `0x6BC`, and the documented imported-DLL/function set. The D3D9
execution test resolves its desktop-window fallback dynamically, so it adds no
static USER32 import. Current changed sections are `.text = 0x5620A8`,
`.rdata = 0x2A3F14`, `.data = 0x15C24`, `.eh_fram = 0x7DD90`, and
`.reloc = 0x381C0`. These are static footprint facts, not load-to-gameplay
acceptance.

### 2026-08-17 accepted-boundary restoration candidate

An installed Atom/OMV playtest rejected the generalized render-transaction and
material-broker candidate: native sky followed Atom head bob and PBR remained
visually absent although OMV logged every relevant hook and resource as active.
Production removes that candidate completely. OMV's PBR, native sky, depth,
atmosphere, motion blur, bloom, image-space, reset, interoperability, and shared
hook code are restored to commit `1dac8a2`. Only the separately requested
dynamic-shadow files remain changed.

The restoration removes the candidate's new `LazyLock` hook containers,
transaction mutexes, camera mailboxes, material descriptor, invocation probes,
and publication atomics. It adds no configuration value, schema/preset change,
TLS value or destructor, import, worker, thread, file scan, parser, or
pre-Deferred operation. Atom's follow-up changes only post-Deferred camera
route code and one fixed function fingerprint; it adds no static lazy owner or
new import.

The complete explicit-target Atom and OMV test suites pass with 104 and 699
tests respectively. The supported five-crate optimized build also completes.
The candidate artifacts are:

- `atom.dll`: 6,814,953 bytes, SHA-256
  `9da56cc6e2cc12e8e21f14a235f967e781b6d75323ee47406967fd2963d9eaca`;
- `omv.dll`: 12,862,364 bytes, SHA-256
  `b158b52ba8e1e1606cf69b77c7277848a85351f1555f0ff35f69cf581ebbf77a`.

Atom's normalized import signature remains exactly 320 rows and its 29 DLL
table rows match the runtime-rejected deployed artifact. Import, export, TLS,
and IAT directory sizes remain `0x2B04`, `0x8C`, `0x18`, and `0x574`; delay
imports remain absent and `.tls` remains eight zero bytes. Its changed sections
are `.text = 0x2A6930`, `.data = 0x1F90`, `.rdata = 0x122A18`,
`.eh_fram = 0x4F5E0`, `.bss = 0x1AE0`, and `.reloc = 0x224CC`.

OMV's normalized import signature remains exactly 395 rows and all 36 DLL table
rows match `.release/omv-nvse-atom-foundation-check.zip` (SHA-256
`3d40c9c8391358b6da6ddccdfc2e2b113975bd4155afb0f5a4ef0c61782970a7`).
Import, export, TLS, and IAT sizes remain `0x340C`, `0x82`, `0x18`, and
`0x6BC`; delay imports remain absent, `.tls` remains eight zero bytes, and
`.bss` remains `0x6B10`. Current changed sections are `.text = 0x5603A8`,
`.data = 0x15444`, `.rdata = 0x2A3214`, `.eh_fram = 0x7D900`, and
`.reloc = 0x3790C`.

These static facts prove removal of the rejected startup footprint and a
bounded shadow/Atom code delta; they do not accept runtime startup or pixels.
The baseline remains unchanged until three cold Proton launches with
BaseObjectSwapper reach gameplay and the full Atom camera off/on graphics
matrix passes on these exact hashes.

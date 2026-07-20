# psycho

A Rust modding toolchain and family of native modifications for **Fallout: New
Vegas** and **Tale of Two Wastelands**.

`psycho` is the project name. It is not another name for Psycho Engine Fixes,
and this repository is not one mod with several optional modules. It is one
workspace where several concrete modifications are built together on a common
foundation:

- **psycho-engine-fixes** is an early-loaded engine, memory and performance mod.
- **psycho-engine-fixes-helper** is a companion xNVSE modification with console
  commands and event forwarding for Psycho Engine Fixes.
- **Oh My Vegas! (OMV)** is a separate, full graphics modification.
- **libpsycho** is the shared Rust library which makes these projects possible.

The practical goal is larger than one release: prove that complex New Vegas
mods can be written almost entirely in Rust, built completely on Linux, and
developed and tested through Wine/Proton without depending on a Windows IDE.

> [!IMPORTANT]
> Fallout: New Vegas is a 32-bit game. More RAM in your computer does not remove
> its virtual-address-space limit. No allocator can make this limit disappear.

## Workspace at a glance

| Project | Kind | Purpose |
|---|---|---|
| **psycho-engine-fixes** | Modification | Memory, loading, display, performance and targeted engine fixes |
| **psycho-engine-fixes-helper** | Companion modification | `PsychoInfo` console command and xNVSE event bridge |
| **Oh My Vegas!** | Modification | Screen-space effects and optimized native PBR/Sky shader ports |
| **libpsycho** | Shared library | WinAPI, D3D9, hooks, patching, PE inspection, logging and FFI |
| **psycho-imgui** | Shared library | Rust-facing ImGui integration used by complex in-game interfaces |
| **Syringe** | Loader/tool | Generic pre-CRT loader for early native DLLs |
| **libnvse** | Shared bindings | Rust access to xNVSE APIs |

The modifications are packaged separately because they have different runtime
jobs and installation boundaries. They still build as one project and exercise
the same libraries in production.

## Why the shared toolchain matters

`libpsycho` is not a helper written around one mod. Psycho Engine Fixes and OMV
put it under very different kinds of pressure:

- Psycho Engine Fixes uses early process startup, inline and IAT hooks,
  ownership-aware patches, allocator hot paths, threading and crash telemetry.
- OMV uses Direct3D 9 resource ownership, shader compilation, render-stage
  boundaries, runtime configuration and a large interactive graphics menu.
- The companion mod uses xNVSE registration and a narrow cross-DLL ABI without
  taking ownership of the early Engine Fixes DLL.

Having all of this on one library is useful proof: the abstractions are not only
nice on paper, they are reliable enough to support more than one complicated
native mod. There is still C in mimalloc, generated xNVSE bindings and HLSL in
the graphics work, but application and engine integration code is overwhelmingly
Rust.

## Modification highlights

### Psycho Engine Fixes

- Replaces selected game allocation paths with `gheap` and `scrap_heap`.
- Accelerates zlib decompression and the frequently used RNG path.
- Repairs native-fullscreen startup and Alt-Tab window placement.
- Makes save commits durable and rejects several malformed changed records.
- Provides targeted crash fixes for audited Havok, ragdoll, navmesh, linked
  reference, queued-task and inventory cases.
- Records memory pressure, allocator state and engine-fix diagnostics.
- Loads before normal xNVSE plugins through the Syringe startup barrier.

#### Engine and crash-fix reference

Each switch solves a concrete engine failure. These are narrow fixes, not a
generic exception handler which hides every crash. Every option below lives in
`[engine_fixes]`, is enabled in the packaged config, and can be controlled
independently:

```toml
[engine_fixes]
ragdoll_detached_phantom_guard = true
```

Set an option to `false` only when checking a compatibility problem or comparing
the original engine behavior. Changes require a game restart.

| Config option | Engine failure | What the enabled fix does |
|---|---|---|
| `display_alt_tab = true` | Native fullscreen starts from New Vegas' visible `320x240` bootstrap window. Later reset and focus paths can also request invalid placement or raise the game during Alt-Tab. | Creates the bootstrap window at the configured render size, repairs the known placement calls, and suppresses the unsafe focus-loss move. Ordinary windowed calls and an existing borderless owner keep their normal behavior. |
| `save_integrity_fix = true` | The game can report success after a partial temporary save, failed flush/close, or failed replacement. Malformed changed records can also run past their buffers, while records from missing plugins can publish partial state. | Flushes and closes the completed temporary save, rotates backups, and replaces the final save atomically. Loading bounds-checks changed records and skips unavailable content through the engine's own paths. It does not rewrite valid save data. |
| `navmesh_low_pointer_guard = true` | Pathfinding receives a very small invalid address where a real `NavMeshInfo` pointer is required, then dereferences it. | Rejects the impossible low pointer at the audited pathfinding boundary instead of letting it become a navigation object. |
| `entrydata_invalid_form_guard = true` | Corrupted container `EntryData` contains an invalid item-form pointer which vanilla save/load code later dereferences. | Drops only the broken inventory entry before serialization reaches the invalid form. Other entries remain untouched. |
| `extraownership_invalid_owner_guard = true` | `ExtraOwnership.owner` points at invalid memory and ownership checks in the game or xNVSE dereference it. | Converts the invalid value to the engine's valid “no owner” state. Valid faction and NPC ownership continues normally. |
| `linked_ref_children_stale_list_guard = true` | A deleted or unloading reference keeps a stale linked-reference child list across a save transition. Cleanup follows the dead list and crashes. | Treats that corrupt list like the already-supported missing-list case, only in the audited cleanup path. |
| `linked_ref_target_base_form_guard = true` | `ExtraLinkedRef` still points at a reference, but that target has a missing or invalid base form. Vanilla checks only the outer pointer before calling through the base form. | Validates the base form and skips the optional linked-reference or activation path when the target cannot satisfy its contract. |
| `ragdoll_null_bone_guard = true` | Havok starts a `bhkRagdollController` update before every slot in its bone table is populated. Vanilla reads through a null bone entry. | Skips only the incomplete ragdoll update. A later frame can update it once the skeleton is ready. |
| `ragdoll_detached_phantom_guard = true` | A penetration raycast is scheduled for an `hkpAabbPhantom` which has already detached from its Havok world. Walking its cached overlaps can crash. | Returns “no hit” for that best-effort query frame instead of using detached world state. It does not disable ragdoll collision or penetration handling globally. |
| `havok_add_entity_batch_null_guard = true` | `hkpWorld::addEntityBatch` receives null entity slots and the vanilla batch loop writes through them. | Compacts the batch so only valid entities reach the original add loop. |
| `havok_pending_add_null_guard = true` | The Havok pending-add array contains null slots after broadphase work; its later flush assumes every slot is valid. | Removes null slots before the original pending-add flush consumes the array. |
| `havok_narrowphase_invalid_pair_guard = true` | A broken narrowphase collision pair reaches collision-agent dispatch with invalid entity or agent state. | Rejects the invalid pair at the audited dispatch boundary while valid collision pairs continue through Havok. |
| `havok_post_add_null_entity_guard = true` | Vanilla tries to dispatch the `AddedToWorld` callback for a null entity after batch insertion. | Skips only the impossible null callback; normal post-add callbacks are unchanged. |
| `havok_remove_agent_null_reread_guard = true` | An AI linear-task path rereads a broadphase entity slot after agent work. The slot may become null, although the value is only a dead argument to the unlock wrapper. | Keeps the required unlock call but removes the unnecessary and unsafe second entity read. |
| `memset_null_dst_guard = true` | Two engine allocation consumers immediately write an alignment marker or call `memset` without checking for allocation failure. | Adds checks at those two consumers, outside the global `memset` and allocator hot paths. |
| `lowprocess_generic_locations_fix = true` | Mods can replace cleanup vtable slots or corrupt `LowProcess::genericLocationsList`, confusing ownership of list nodes and their non-owned reference payloads. | Enforces the engine's ownership rule regardless of vtable ownership: matching nodes are removed without freeing borrowed references, and an already-corrupt serializer entry becomes null at its exact callsite. |
| `queued_task_lifetime_guard = true` | A texture or background task reaches a virtual callback or final-release path after its intrusive reference count already became zero. | Stops the dead task at the audited dispatch/release boundaries. This guard works in allocator modes `0`, `1`, and `2`. |

The guards reject a bad record or object at the smallest safe boundary, while
normal game behavior continues through the original code. Disabling a guard
restores that original behavior; it is a diagnostic comparison, not a general
stability recommendation.

#### Performance paths beyond the heap

- The RNG replacement reduces the cost of a very frequently called engine
  service while preserving its expected output contract.
- The zlib replacement accelerates decompression during startup, save loading
  and cell transitions without changing resource contents or quality.
- The radio scan cache avoids repeated connected-interior and path checks from
  the periodic nearby-station worker, reducing camera and movement hitches in
  radio-heavy TTW worldspaces. Direct Pip-Boy and station-selection calls stay
  on the original path.

### Oh My Vegas!

- Provides an in-game graphics menu, opened with `Insert` by default.
- Includes depth-aware AO, contact AO, bloom/HDR, sunshafts and depth of field.
- Supports loose D3D9 shaders for AA, sharpening, grading and experiments.
- Ports the native PBR and Sky shaders from New Vegas Reloaded.
- Refactors the NVR shader design for OMV ownership and compatibility, with a
  large focus on reducing runtime overhead.
- Uses the complete Fallout Shader Loader, Vanilla Plus Terrain and LOD Flicker
  Fix stack as its renderer foundation.

## Requirements

- Fallout: New Vegas `1.4.0.525` or a TTW installation using this executable.
- [xNVSE](https://github.com/xNVSE/NVSE) installed in the real game directory.
- A mod manager such as Mod Organizer 2 for the conventional `Data` archives.

A 4 GB-aware executable is strongly recommended for any modern modlist, but it
does not expand New Vegas beyond the normal 32-bit address-space ceiling.

Oh My Vegas! additionally requires:

- Direct3D 9 with Shader Model 3.0 support.
- Fallout Shader Loader, plugin version `131` or newer.
- Vanilla Plus Terrain.
- LOD Flicker Fix.
- One D3DCompiler library visible to the game process: version `47`, `46`,
  `43`, `42` or `41`.

Do not download a random compiler DLL from a DLL mirror. Install a trusted
Microsoft runtime or use a known-good copy already supplied by your system or
modding environment.

## Choose the release files

Every release is split into three modification archives on purpose:

| Archive | Contents | How to install |
|---|---|---|
| `psycho-engine-fixes-<version>.zip` | Syringe loader, Engine Fixes DLL and config | Extract into the real game root |
| `psycho-engine-fixes-nvse-helper-<version>.zip` | Companion xNVSE modification | Install as a normal mod |
| `omv-nvse-<version>.zip` | OMV graphics modification, config and loose shaders | Install as a normal mod |

The Psycho Engine Fixes archive is not a regular `Data` mod. Mod Organizer 2
cannot place its root files unless you use a correctly configured root-file
plugin. Manual installation is simple and usually less confusing.

## Installation

### 1. Install xNVSE

Install xNVSE so `nvse_loader.exe` and its DLLs are beside `FalloutNV.exe`.
Launch the game through xNVSE, also when using Mod Organizer 2.

### 2. Install Psycho Engine Fixes

Open `psycho-engine-fixes-<version>.zip` and extract it into the directory that
contains `FalloutNV.exe`.

The result must look like this:

```text
Fallout New Vegas/
├── FalloutNV.exe
├── dinput8.dll
└── syringe/
    ├── psycho_engine_fixes.dll
    └── psycho_engine_fixes.toml
```

`psycho_engine_fixes.dll` belongs in `syringe/`. Do not move it into
`Data/NVSE/plugins/`; Engine Fixes must load earlier than a normal plugin.

> [!WARNING]
> Check an existing `dinput8.dll` before overwriting it. Windows loads only one
> proxy with this name. Keep a backup if another mod already owns the file.

### 3. Install the Psycho Engine Fixes companion

Install `psycho-engine-fixes-nvse-helper-<version>.zip` through your mod manager,
or extract it manually into the game directory. Its final path is:

```text
Data/NVSE/plugins/psycho_engine_fixes_helper.dll
```

The companion does not load or initialize Psycho Engine Fixes. It connects only
after Syringe has already activated the engine mod. Open the console and run
`PsychoInfo` to print a detailed status report.

### 4. Start the game

On a successful startup, the game root receives:

```text
psycho-engine-fixes-latest.log
```

Search the beginning of this file for the activation summary. If the file is
missing, verify the real game-root layout before changing allocator settings.

## OMV setup guide

OMV is its own conventional xNVSE modification. It shares `libpsycho` and the
Linux build workflow with the rest of the project, but it is not a graphics
module inside Psycho Engine Fixes. Install it at its own runtime boundary.

### Install with Mod Organizer 2

1. Select **Install a new mod from archive**.
2. Choose `omv-nvse-<version>.zip`.
3. Confirm that MO2 sees `Data` as the archive root.
4. Enable the new OMV mod in the left pane.
5. Disable or remove older OMV versions. If files still conflict, make sure the
   new archive wins them.
6. Launch `nvse_loader.exe` through MO2.

The virtual filesystem should produce this layout:

```text
Data/NVSE/plugins/
├── omv.dll
└── omv/
    ├── omv.toml
    └── shaders/
        ├── 01_depth_aware_cas.hlsl
        ├── 01_depth_aware_cas.toml
        ├── 03_fast_fxaa.hlsl
        └── 03_fast_fxaa.toml
```

For a manual installation, extract the same archive into the game directory;
do not extract it directly into `Data`, because the archive already contains
that folder.

### First launch

1. Start the game through xNVSE.
2. Wait until the main menu is fully visible.
3. Press `Insert` to open the OMV menu.
4. Change one effect at a time and confirm the image still looks correct.
5. Close the menu and check `omv-latest.log` in the game root.

The menu edits `Data/NVSE/plugins/omv/omv.toml`. Most settings are applied at a
safe frame boundary, and loose shader changes are detected while the game is
running.

### Native PBR and Sky

OMV's PBR and Sky shaders began as ports of the corresponding **New Vegas
Reloaded** work. The NVR shaders provided the proven rendering ideas and much of
the original visual model, but OMV is not simply loading NVR code under another
name.

The ports were adapted and significantly improved for the OMV renderer:

- Shader ownership follows OMV's own D3D9 resource and frame-boundary model.
- PBR replacements are selected from explicit object and terrain shader
  contracts instead of installing one broad replacement over unrelated draws.
- Unsupported shader families keep the original game path instead of receiving
  a half-compatible effect.
- Shaders are compiled, cached and prepared outside the draw hot path.
- Per-draw work is kept small, resource changes are batched at safe boundaries
  and expensive diagnostics remain disabled during normal play.
- Sky and material tuning were adjusted for the OMV effect stack rather than
  assuming the complete NVR runtime is present.

Performance received especially large focus. The purpose was to preserve the
NVR-derived look without importing its entire renderer or paying avoidable work
for every object and terrain draw. The packaged configuration currently enables
both ports.

Fallout Shader Loader `131+`, Vanilla Plus Terrain and LOD Flicker Fix are direct
OMV dependencies. Together they provide the shader and terrain contracts which
the current OMV implementation expects.

**New Vegas Reloaded is not an OMV dependency and is not a supported
co-installation target.** Both projects can own native renderer hooks, so using
them together is not a sensible baseline for bug reports.

### OMV troubleshooting

| Symptom | What to check |
|---|---|
| No OMV menu | Verify `omv.dll`, xNVSE launch and `omv-latest.log` |
| Shader compilation failure | Verify a supported D3DCompiler DLL is visible |
| AO or depth effects look inverted | Restore the packaged depth settings and remove old shader overrides |
| OMV reports a missing renderer dependency | Verify Fallout Shader Loader `131+`, Vanilla Plus Terrain and LOD Flicker Fix are all installed and winning conflicts |
| Visual corruption starts with PBR or Sky | Disable only the affected feature as a diagnostic, restart and attach the complete log |
| A loose shader behaves incorrectly | Disable its sidecar TOML or remove that shader pair temporarily |

Do not report an OMV graphics problem only with screenshot. The log says which
hooks, shader families and dependencies were active, and this is usually the
most important part.

## Configuration

### Psycho Engine Fixes

The Psycho Engine Fixes config is:

```text
syringe/psycho_engine_fixes.toml
```

It is fully commented. The main sections are:

- `[memory]` — allocator selection and memory behavior.
- `[engine_fixes]` — independent display and crash-containment fixes.
- `[performance]` — RNG, zlib and other measured hot paths.
- `[diagnostics]` — console output, logging and probes.

Restart the game after changing the Engine Fixes config.

#### Config option summary

Engine and performance switches use `true` for the Psycho implementation and
`false` for the original game path. Diagnostic booleans simply enable or
disable the named telemetry. The full `[engine_fixes]` list is explained in the
[engine and crash-fix reference](#engine-and-crash-fix-reference) above.

| Option | Packaged default | What it controls | When a user may change it |
|---|---:|---|---|
| `memory.allocator` | `2` | Selects vanilla heaps (`0`), `scrap_heap` only (`1`), or `gheap + scrap_heap` (`2`). | Use `1` when full gheap has compatibility or address-space problems; use `0` for an allocator-free comparison. |
| `performance.rng` | `true` | Replaces the heavily used game RNG with the faster compatible path. | Set `false` when comparing RNG behavior or another plugin patches the same function. |
| `performance.zlib` | `true` | Uses the faster decompression path for compressed game data. It does not change asset quality or save contents. | Set `false` when isolating a startup, resource-load, or decompression conflict. |
| `performance.post_load_reconciliation_prepass` | `true` | Runs the engine's guarded process reconciliation once before a successful load returns, moving backlog work out of the first rendered frame. | Set `false` to retain the vanilla reconciliation schedule. |
| `diagnostics.console` | `false` | Opens a Windows console and mirrors live log output. | Enable for startup research or when early loader messages are needed. |
| `diagnostics.debug_log` | `true` | Writes detailed startup, allocator, memory-pressure, OOM, and guard diagnostics. | Keep enabled for bug reports; disable only for a deliberately quieter log. |
| `diagnostics.hitch_profiling` | `false` | Adds high-resolution timing around engine spans and emits `[HITCH]` reports plus detailed `[RADIO_SCAN]` attribution for slow periodic scans. | Enable only during a focused hitch reproduction because it adds timing work to hot hooks. |
| `diagnostics.task_lifetime_trace` | `false` | Records queued-task retain, release, and dispatch provenance in a fixed ring. | Enable only for focused queued-task crash research. Production lifetime guards do not require it. |

### Allocator modes

#### Why replace the New Vegas heaps?

New Vegas allocates and frees enormous numbers of small objects while loading
assets, building cells, updating AI, running scripts and preparing render work.
The original allocators were designed for the hardware and workloads of their
time. On a modern, heavily modded game they can become a CPU bottleneck:

- many threads compete for old allocator synchronization;
- small allocations carry repeated lookup and bookkeeping cost;
- poor reuse and fragmentation scatter related objects through memory;
- temporary allocations create heavy churn during loading and frame updates;
- fragmentation wastes parts of the game's already limited 32-bit address
  space.

A heap replacer cannot make scripts, meshes or AI cheaper by itself. What it can
do is make the allocation work underneath them faster and more predictable. A
few microseconds repeated hundreds of thousands of times becomes real loading
time and frame-time cost.

Psycho Engine Fixes uses two specialized replacements because temporary data
and persistent game objects do not have the same lifetime rules.

#### Mode `1`: `scrap_heap` only

`scrap_heap` replaces the temporary allocation heaps used for short-lived work.
The game's main object heap remains vanilla.

This mode removes part of the allocation overhead while touching much less of
the engine's object-lifetime behavior. It is the simpler and safer practical
choice for very large or unfamiliar modlists, and it is also the first fallback
when diagnosing a location-specific crash.

The tradeoff is straightforward: temporary allocation becomes faster, but
long-lived game objects still use the original main heap. Performance gains are
therefore smaller than with the complete mode.

#### Mode `2`: `gheap + scrap_heap`

This is the complete heap-replacement solution and gives the best performance.
`scrap_heap` handles temporary work while `gheap` replaces the game's main SBM
object allocator. Exact small-object pools serve requests through 3584 bytes,
independent 16 MB blocks serve medium allocations, and larger requests use
exact page-rounded `VirtualAlloc` reservations. The small-object path avoids
one global allocator bottleneck during busy loading, AI and gameplay work.

It is also the most complex mode because New Vegas does not always respect
normal object lifetimes. IO, AI and Havok code can read pointers after an object
was logically freed. Reusing that address immediately may turn a harmless stale
read into corruption or a crash. `gheap` therefore includes:

- out-of-band pool and block metadata so freeing does not overwrite object
  bytes before the address is reused;
- Havok and IO coordination around cleanup;
- targeted guards for statically proven stale-reader families;
- process-VAS and largest-hole monitoring, progressive commit, and one
  empty-block retirement retry after a huge direct allocation fails;
- a lock-free common small-allocation path and bounded cold-path reservation
  work.

These protections are exactly why full `gheap` is not just “use another malloc”.
They also create its main tradeoff: independently reserved pools and blocks use
finite 32-bit address space, while immediate reuse still exposes engine code
that retained an invalid pointer. Huge modlists can reach VAS exhaustion even
when the computer has plenty of physical RAM and VRAM.

Use mode `2` when maximum performance is the priority and the modlist is stable
with it. Use mode `1` when broad compatibility and lower address-space pressure
matter more than the final amount of allocator speed. If one mode crashes and
the other does not, keep both logs; this difference is valuable diagnostic
information.

#### Mode `0`: vanilla allocators

Mode `0` disables both heap replacements. It is intended for compatibility and
diagnostic comparisons. It provides no heap-related performance improvement,
but it is useful for proving whether a problem belongs to the Psycho Engine
Fixes allocator path or exists in the original engine/mod stack.

| Mode | Replaced heaps | Performance | Complexity | Best use |
|---:|---|---|---|---|
| `0` | None | Vanilla | Lowest | Compatibility testing |
| `1` | Temporary `scrap_heap` | Moderate improvement | Lower | Heavy or unfamiliar modlists |
| `2` | Main `gheap` and temporary `scrap_heap` | Best improvement | Highest | Maximum performance on a validated setup |

The packaged config selects mode `2`: it is the performance-first default and
the main technical feature of Psycho Engine Fixes. Full `gheap` is necessarily
more sensitive to extreme VAS pressure and unusual lifetime conflicts, so it is
not claimed as universal for every huge modlist. Mode `1` exists as a clean,
useful fallback rather than a disguised “off” switch.

The [large-modlist gheap compatibility contract](docs/gheap_large_modlist_compatibility.md)
documents the texture path, hard limits, allocator evidence, and required
stress matrix.

### Oh My Vegas!

OMV uses:

```text
Data/NVSE/plugins/omv/omv.toml
```

The file documents every effect, shader phase and debug option. OMV also loads
loose shaders only from:

```text
Data/NVSE/plugins/omv/shaders/
```

Embedded effects are compiled into `omv.dll`; loose shader files are for the
packaged final passes and user experiments.

## Updating

1. Exit the game.
2. Replace `dinput8.dll` and `syringe/psycho_engine_fixes.dll` from the new
   Engine Fixes archive.
3. Compare your Engine Fixes config with the newly packaged file. New releases
   may add options with important defaults.
4. Update the companion modification and OMV from their separate archives.
5. Remove old loose OMV shader files if they are no longer present in the new
   archive; mod managers sometimes leave deleted files behind after a manual
   overwrite.

Keep personal configuration backups, but do not blindly copy a very old config
over a new release. Read new comments first.

## Uninstalling

Remove only the modification files which you installed.

### Psycho Engine Fixes

```text
dinput8.dll
syringe/psycho_engine_fixes.dll
syringe/psycho_engine_fixes.toml
```

Delete `dinput8.dll` only if it belongs to Syringe. Leave other DLLs inside
`syringe/` alone if another early-loaded mod placed them there.

### Psycho Engine Fixes companion

```text
Data/NVSE/plugins/psycho_engine_fixes_helper.dll
```

### OMV

```text
Data/NVSE/plugins/omv.dll
Data/NVSE/plugins/omv/
```

Psycho Engine Fixes and OMV do not add persistent gameplay forms. Removing them
does not require a save-cleaning tool.

## Logs and bug reports

For an engine-fixes problem, include:

- `psycho-engine-fixes-latest.log`.
- `CrashLogger.log` or the complete timestamped CrashLogger file.
- `syringe/psycho_engine_fixes.toml`.
- The action, cell and save used immediately before the crash.
- Whether allocator modes `0`, `1` and `2` change the result.

For an OMV problem, include:

- `omv-latest.log`.
- `Data/NVSE/plugins/omv/omv.toml`.
- A screenshot for visible corruption.
- Resolution, display mode, weather/interior context and relevant graphics
  dependencies.
- Whether disabling only the affected feature changes the result.

Please do not crop logs to the final ten lines. Startup ownership and dependency
messages are often more useful than the last error.

## Compatibility notes

Psycho Engine Fixes chains several existing IAT hooks and refuses some unknown
patch-site owners, but two mods changing the same engine instruction can still
conflict. Always test with logs; plugin count alone tells almost nothing.

The display fix recognizes the visible bootstrap window and six audited
placement paths. Native fullscreen and existing borderless windows receive
narrow transition handling. Ordinary windowed or unrecognized calls pass
through unchanged.

OMV expects ownership of its graphics hooks. Co-installation with another native
renderer overhaul is not supported unless documented explicitly.

## Syringe for developers

Syringe is the generic, mod-agnostic `dinput8.dll` shipped in the Psycho Engine
Fixes archive. It loads every DLL from:

```text
syringe/*.dll
```

After loading completes, Syringe calls two optional exports:

```text
Syringe_ModInit
Syringe_ModActivate
```

All `Syringe_ModInit` callbacks finish before any `Syringe_ModActivate` callback
runs. Both phases execute outside `DllMain`, avoiding Windows loader-lock work.
The activation phase lets early mods make final ownership decisions after all
participants are present.

An early-loaded DLL should keep `DllMain` minimal, initialize through
`Syringe_ModInit`, and use `Syringe_ModActivate` only for work that requires the
complete early-mod set. Use a separate xNVSE helper only for services which
actually require xNVSE.

## Building from source

Only the 32-bit Windows GNU target is supported:

```text
i686-pc-windows-gnu
```

Install the Rust target, MinGW-w64 and initialize both submodules:

```bash
rustup target add i686-pc-windows-gnu
git submodule update --init --recursive
```

Build the complete modification set with the target written explicitly:

```bash
cargo build --release --target i686-pc-windows-gnu \
  -p syringe \
  -p psycho-engine-fixes \
  -p psycho-engine-fixes-helper \
  -p omv
```

Do not rely on `.cargo/config.toml`; its default target is intentionally not the
supported FNV target. `i686-w64-mingw32-gcc` must be available on `PATH`.

For the repository owner's local FNV/TTW layout, edit `TARGET_DIR` at the top of
`build_fnv.sh`, then run:

```bash
./build_fnv.sh
```

Create the three release archives with:

```bash
cd psycho-engine-fixes
./release.sh v0.1.0
```

Archives are written into `.release/`.

## Repository layout

| Path | Purpose |
|---|---|
| `psycho-engine-fixes/` | Early-loaded engine-fixes modification and config |
| `psycho-engine-fixes-helper/` | Companion xNVSE modification for Engine Fixes |
| `syringe/` | Generic pre-CRT `dinput8.dll` loader |
| `syringe-api/` | Small callback ABI shared with early DLLs |
| `omv/` | Separate Oh My Vegas! graphics modification, config and shaders |
| `libpsycho/` | Shared production library used across the modifications |
| `libnvse/` | Rust bindings for xNVSE |
| `libmimalloc/` | Local mimalloc C build used for third-party CRT allocation |
| `libf4se/` | Deprecated Fallout 4 bindings; not maintained |

## Source

Project repository: <https://github.com/acidpointer/psycho>

Detailed OMV developer notes: [`omv/README.md`](omv/README.md)

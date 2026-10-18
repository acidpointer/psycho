# Repository map

## Crate ownership

| Area | Responsibility |
|---|---|
| `psycho-engine-fixes` | Early-loaded core DLL. Engine patches, allocator, IO/LOD, diagnostics, command ABI. |
| `psycho-engine-fixes-helper` | Late xNVSE dashboard and command forwarder. Never loads or initializes the core. |
| `syringe` | Generic `no_std` `dinput8.dll` proxy. No `libpsycho`, no NVSE, no game knowledge. |
| `syringe-api` | Small callback ABI for early-loaded DLLs. |
| `omv` | xNVSE graphics plugin. Owns D3D9 stages, resources, shaders, presets, and graphics tests. |
| `atom` | ESP-less xNVSE gameplay overhaul. Input, cameras, ballistics, and MCM Extender config. |
| `libpsycho` | Shared WinAPI, hooking, patching, logging, config, FFI, hardware, D3D9 test/device helpers. |
| `libnvse` | xNVSE bindings, plugin context, events, commands, serialization. |
| `libmimalloc` | CRT-only mimalloc build. |
| `libf4se` | Deprecated. Do not extend without an explicit request. |
| `psycho-imgui` | Reusable Dear ImGui Win32/DX9 bridge. |
| `libpsycho-foundation` | Not a workspace member. Ignore unless the user explicitly asks. |

## Startup order

1. Windows loads `dinput8.dll` (Syringe).
2. Syringe installs its executable startup barrier from `DllMain`.
3. The barrier runs outside loader lock after xNVSE preload callbacks.
4. Syringe loads the real system `dinput8.dll` and every `syringe/*.dll`.
5. It calls all `Syringe_ModInit`, then all `Syringe_ModActivate`.
6. The core requires `SYRINGE_INFO_PRE_CRT_BARRIER`; the worker fallback cannot
   safely patch live code.
7. OMV `NVSEPlugin_Load` performs config and process-owned preparation only.
8. OMV installs engine, D3D, and render hooks at xNVSE `DeferredInit`.

Read `docs/nvse_startup_phase_safety.md` before changing anything reachable
before `DeferredInit`.

## Core file map

| Path | Owns |
|---|---|
| `psycho-engine-fixes/src/entry.rs` | Loader exports, Syringe validation, activation state. |
| `psycho-engine-fixes/src/startup.rs` | Config load, logging, allocator, fix and hook installation order. |
| `psycho-engine-fixes/src/config.rs` | Immutable core config, raw migration, defaults, validation. |
| `psycho-engine-fixes/src/events.rs` | Numeric host event ABI. |
| `psycho-engine-fixes/src/command_api.rs` | Command and dashboard ABI shared with the helper. |
| `psycho-engine-fixes/src/mods/engine_fixes/mod.rs` | Install order, dashboard feature bits, counters. |
| `psycho-engine-fixes/src/mods/engine_fixes/statics.rs` | Hook containers and fixed game addresses. |
| `psycho-engine-fixes/src/mods/engine_fixes/types.rs` | Native function signatures and calling conventions. |
| `psycho-engine-fixes/src/mods/engine_fixes/patching.rs` | Fingerprint and direct-call patch helpers. |
| `psycho-engine-fixes/src/mods/perf/` | Performance hooks, signatures, and scene/light/occlusion work. |
| `psycho-engine-fixes/src/mods/heap_replacer/` | Allocator modes, gheap, scrap heap, mimalloc, manifests. |
| `psycho-engine-fixes/src/mods/zlib/` | zlib replacement and ownership. |
| `psycho-engine-fixes/src/mods/diagnostics.rs` | Hitch profiling and diagnostics. |

## OMV file map

| Path | Owns |
|---|---|
| `omv/src/nvse_plugin.rs` | xNVSE exports and message routing. |
| `omv/src/startup.rs` | Load-time preparation, DeferredInit installation, frozen footprint. |
| `omv/src/runtime.rs` | Render graph, phase admission, workbench, runtime state. |
| `omv/src/hooks.rs` | D3D9 and engine hook installation/lifecycle. |
| `omv/src/config.rs` | Loaded TOML schema, defaults, validation, save paths. |
| `omv/src/presets.rs`, `current_look.rs` | Versioned presets and Current Look persistence. |
| `omv/src/shaders.rs` | Shader discovery, compilation, cache, embedded sources, budgets. |
| `omv/src/effects/` | AO, AA, atmosphere, bloom/color, DOF, grass, motion blur, PBR, shadows, sky, sunshafts, TAA. |
| `omv/src/backend/` | Depth providers, owned depth, snapshots, sun disk. |
| `omv/src/fnv_render.rs`, `fnv_world_pipeline.rs`, `fnv_local_lights.rs` | Native render/world/light boundaries. |
| `omv/src/effects/ambient_occlusion_image_tests.rs` | Reference offline D3D9 image-test pattern. |
| `omv/src/runtime_performance_tests.rs` | Offline phase and work-budget execution. |

## Atom file map

| Path | Owns |
|---|---|
| `atom/src/lib.rs` | xNVSE exports, runtime version gate, event routing. |
| `atom/src/config.rs` | Read-only `Atom.ini` snapshot. |
| `atom/src/runtime.rs` | Deferred installation and event lifecycle. |
| `atom/src/input/` | Input pipeline, native hooks, buffering, telemetry. |
| `atom/src/camera/` | First-person and third-person camera, motion, hooks. |
| `atom/src/ballistics/` | Physical rounds, flight, ricochet, pool, telemetry. |
| `atom/src/integrity.rs` | Capability/ownership diagnostics. |
| `atom/mcm/Atom.json` | MCM Extender menu and persistence contract. |
| `atom/tests/` | Public behavioral acceptance tests. |

## Helper file map

| Path | Owns |
|---|---|
| `psycho-engine-fixes-helper/src/engine_fixes.rs` | Late-bound core exports, event and dashboard ABI mirrors. |
| `psycho-engine-fixes-helper/src/commands.rs` | xNVSE commands. |
| `psycho-engine-fixes-helper/src/dashboard.rs` | ImGui dashboard pages and runtime view. |
| `psycho-engine-fixes-helper/src/dashboard_config.rs` | Restart-only TOML editing. |
| `psycho-engine-fixes-helper/src/events.rs` | xNVSE message translation. |
| `psycho-engine-fixes-helper/src/input.rs` | Win32 input bridge and DirectInput suppression. |

## libpsycho file map

| Path | Owns |
|---|---|
| `libpsycho/src/logger/` | Asynchronous process-wide logger and deferred start. |
| `libpsycho/src/config/` | TOML load/save/migrate helpers. |
| `libpsycho/src/ffi/` | `FnPtr`, function traits, pointer helpers. |
| `libpsycho/src/hook/` | Hook trait. |
| `libpsycho/src/os/windows/hook/inline/` | Inline hook and trampoline. |
| `libpsycho/src/os/windows/hook/callsite.rs` | Ownership-aware `E8 rel32` callsite hook. |
| `libpsycho/src/os/windows/hook/pointer.rs` | CAS-based function-pointer slot hook. |
| `libpsycho/src/os/windows/hook/replacement.rs` | Provider replacement without a trampoline. |
| `libpsycho/src/os/windows/hook/transaction.rs` | Rollback transaction for related modifications. |
| `libpsycho/src/os/windows/patch.rs` | `CodeSignature`, `OwnedCodePatch`, restoration. |
| `libpsycho/src/os/windows/memory.rs` | Range/access validation, protection, readback. |
| `libpsycho/src/os/windows/winapi.rs` | Shared Win32 wrappers. Use these instead of direct WinAPI. |
| `libpsycho/src/os/windows/directx9.rs` | D3D9 device/surface/texture/test helpers. |
| `libpsycho/src/hardware/` | CPU/GPU/memory detection. |

## Key symbols

- Hook installation: `ModificationTransaction`, `InlineHookContainer`,
  `Rel32CallHookContainer`, `PointerSlotHookContainer`,
  `ReplacementHookContainer`.
- Patch verification: `CodeSignature::verify`, `OwnedCodePatch`.
- Native calls: `FnPtr::from_address_unchecked` only after signature proof.
- Logging: `libpsycho::logger::Logger` plus the `log` facade.
- Config: `libpsycho::config::Config`.
- xNVSE: `libnvse::plugin::PluginContext`, `NVSEInterfaceFFI`,
  `NVSEMessageType`, `SaveWriter`/`LoadReader`.
- D3D tests: `create_direct3d9`, `create_windowed_device`,
  `create_system_memory_surface`, `begin_scene`/`end_scene`.
- Dashboard ABI: `DASHBOARD_ABI_VERSION`, `DASHBOARD_FEATURE_*`, and the exact
  mirror in `psycho-engine-fixes-helper/src/engine_fixes.rs`.

## Test locations

- Inline `#[cfg(test)] mod tests` in production modules.
- External test modules via `#[path = "..._tests.rs"] mod ...` (common in OMV).
- Integration tests under `atom/tests/`.
- Ignored explicit benchmarks use `#[ignore = "..."]`; run them only when the
  task needs the measurement and run them explicitly.
- List tests without guessing counts:

```bash
cargo test --target i686-pc-windows-gnu -p <crate> -- --list
cargo test --target i686-pc-windows-gnu -p omv effects::shadows:: -- --list
```

## Search hygiene

```bash
rg -n 'symbol' --glob '!target/**' --glob '!node_modules/**'
rg --files -g '*.rs' -g '!target/**' -g '!node_modules/**'
```

- `rg` respects `.gitignore`, so `.reports/`, `.research/`, and `fnv_reverse/`
  are skipped by default. Add `--no-ignore` only when those inputs exist and
  are relevant.
- Do not run recursive `find` or `grep` from the repository root; stale nested
  `target/` directories can be gigabytes.
- `Cargo.lock` is tracked even though `.gitignore` lists it. Expect lockfile
  changes when dependencies change.
- `libnvse/xnvse` is a submodule and its build script edits headers. Never
  commit submodule content or a pointer change unless explicitly intended.

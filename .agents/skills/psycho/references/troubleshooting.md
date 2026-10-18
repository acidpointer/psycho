# Troubleshooting

## Read the whole log

Crash Logger's own header warns that the topmost stack module is not always the
crash reason. Read the complete log, the phase markers, and the caller chain
before forming a hypothesis.

## Phase markers

| Log | Marker | Meaning |
|---|---|---|
| Psycho | `[INIT] Psycho engine fixes starting` | Core startup began. |
| Psycho | `[INIT] Psycho engine fixes ready` | Core startup completed. |
| Psycho | `[MEMORY] Allocator mode ... selected` | Allocator mode accepted. |
| Psycho | `[MEMORY] ... rejected ... Vanilla allocator retained` | Fallible allocator setup failed; other fixes continue. |
| OMV | `[INIT] Oh My Vegas graphics initialized through xNVSE` | `NVSEPlugin_Load` reached OMV setup. |
| OMV | `[INIT] Deferred OMV graphics hooks initialized` | Deferred engine/D3D hooks installed. |
| OMV | `[XNVSE] Deferred graphics hook install failed` | Deferred installation failed. |
| Atom | `[INIT] Atom initialized successfully` | Atom deferred initialization completed. |

If a crash occurs before the OMV `DeferredInit` marker, do not tune shaders,
render stages, or depth policy. Audit load-time initialization and message
phases first. Read `docs/nvse_startup_phase_safety.md`.

## Symptom routing

| Symptom | Read first | Do not |
|---|---|---|
| Crash before `DeferredInit` | `docs/nvse_startup_phase_safety.md`, atmosphere startup errata | Blame a shader or render callback that never ran. |
| Visible PBR artifact | `docs/graphics_fnv_pbr_errata.md` | Broaden a selector or add a shader guess. |
| AO/bloom/TAA blink or ghost | owning effect doc, `docs/graphics_fnv_omv_ao_blink_research_plan.md`, `docs/graphics_fnv_temporal_aa_contract.md` | Clamp or epsilon over an unknown state bug. |
| Depth unavailable or wrong | `docs/graphics_fnv_depth_resolve.md`, `docs/graphics_fnv_driver_owned_d3d_nvidia_depth.md`, `docs/graphics_fnv_portable_depth_transport.md` | Borrow an unversioned external surface. |
| Shadow cost or holes | `docs/graphics_fnv_nvr_shadows_engine_contract.md`, shadow performance plan | Loosen a budget to make a test pass. |
| Stutter or low FPS | `docs/graphics_fnv_omv_runtime_performance.md`, `docs/fnv_location_performance_static_audit.md` | Claim an FPS result from static counts. |
| Allocator/OOM/UAF | `gheap/AGENTS.md`, `docs/gheap_large_modlist_compatibility.md` | Pick VAS exhaustion or UAF without direct evidence. |
| Save or load failure | `docs/save_integrity.md`, owning `docs/crash_*` | Bypass the transaction or narrow the supported path. |
| Input/camera mismatch | `docs/atom.md`, `docs/fnv_actor_input_contract.md` | Poll pause state or parse config every frame. |
| Hook conflict | `docs/graphics_fnv_pbr_errata.md`, `libpsycho` hook ownership docs | Overwrite a provider another mod installed. |
| Config ignored | owning config doc, `docs/psycho_dashboard.md` | Assume live reload where the contract is restart-only. |

## Attribution discipline

Keep these categories separate in every report:

- **Runtime evidence**: an executed game or device run with a captured result.
- **Binary proof**: exact instructions, bytes, callers, layouts, and ABI from
  the supported executable.
- **Static inference**: a conclusion that follows from code but was not
  executed.
- **Unresolved**: the owner, race, allocation, or mod attribution that direct
  evidence does not prove.

Do not rewrite an unresolved fact into a confident cause. Do not attribute an
external mod's fault to Psycho without a direct A/B or write proof.

## Common failure modes

| Failure | Evidence | Prevention |
|---|---|---|
| Wrong architecture | 64-bit target or 64-bit test binary | Always pass `--target i686-pc-windows-gnu`. |
| Missing toolchain | `i686-w64-mingw32-gcc` not found | Install the mingw i686 compiler and Rust target. |
| GPU test cannot create a device | `create_windowed_device` fails under Wine | Check `DISPLAY`, Wine D3D support, and report not run. |
| Stale nested build trees | Old `target/` directories of several GB | Use `rg`, prune `target/`, do not recursive `find`. |
| Submodule noise | `libnvse/xnvse` modified by build | Do not commit submodule content or pointer changes. |
| Source-text test | `include_str!("*.rs")` plus string assertions | Replace with the actual shipped path where it can execute. |
| Logging violation | `println!`/`eprintln!` in production | Use `libpsycho::logger::Logger` and `log`. |
| Hot-path I/O | file scan/read, shader compile, or blocking lock in render | Move work to preparation or a worker. |
| Hook ownership loss | provider or callsite changed after capture | Use the ownership-aware container and chain the current target. |
| Address reuse | an old address used on a different binary | Reverify identity and exact bytes before any write. |
| Config/ABI drift | core field without helper mirror or version bump | Update both sides, preserve the published prefix, bump the version. |
| MCM defaults drift | JSON default differs from native default | Test shipped JSON against native defaults. |
| Startup footprint change | new TLS, import, static, or config layout before `DeferredInit` | Read the startup contract and keep the accepted baseline. |
| Unproven runtime claim | static build or compile reported as gameplay proof | Label it offline-qualified and list what was not run. |

## Crash report checklist

Ask for or locate:

- the complete Crash Logger log;
- the complete Psycho, OMV, or Atom log;
- the exact game/executable path and hash when the incident is native;
- the active configuration file;
- the action, cell, and save used immediately before the fault;
- whether allocator modes `0`, `1`, and `2` change the result;
- the graphics dependencies and display mode for visual faults.

Never require a game run under the OMV no-game-runtime exception. Report the
game-only behavior as not run.

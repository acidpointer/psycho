# AGENTS.md

## Build

Only supported target: `i686-pc-windows-gnu` (32-bit, FNV/xNVSE requirement).

```
cargo build --release --target i686-pc-windows-gnu -p psycho-loader -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Requires `mingw-w64` (`i686-w64-mingw32-gcc`) on `$PATH` and `rustup target add i686-pc-windows-gnu`.

**Warning:** `.cargo/config.toml` sets `target = "x86_64-pc-windows-gnu"` which is wrong. Always pass `--target i686-pc-windows-gnu` explicitly. The `libnvse/build.rs` will `panic!` if compiled for a non-i686 target.

## Git submodules

Two submodules must be initialized before building:

```
git submodule update --init --recursive
```

- `libmimalloc/c_src/mimalloc` -- upstream mimalloc C source
- `libnvse/xnvse` -- xNVSE C++ headers (bindgen input)

`libnvse/build.rs` patches `xnvse/nvse/nvse/PluginAPI.h` at build time (strips `[[nodiscard]]`). Don't commit submodule changes unless intentional.

## Workspace structure

| Crate | Role |
|---|---|
| `psycho-engine-fixes` | Core DLL (`psycho_engine_fixes.dll`). Loaded early by `psycho-loader` from `<game root>/mods/psycho_engine_fixes.dll`; owns engine patches and shared state. |
| `psycho-engine-fixes-helper` | Thin xNVSE plugin (`psycho_engine_fixes_helper.dll`, plugin name `psycho-nvse-helper`). Registers console commands/messages and lazily resolves exact named exports from `psycho_engine_fixes.dll` only if it is already loaded. It must never load or initialize the core DLL. |
| `psycho-loader` | Generic early `dinput8.dll` proxy. Loads every `<game root>/mods/*.dll` before xNVSE plugin load. Must stay mod/plugin agnostic, `no_std`, and independent of `libpsycho`. |
| `psycho-loader-api` | Tiny generic ABI for DLLs loaded by `psycho-loader`. Loaded DLLs should export `PsychoLoader_ModInit` and do real startup there, not in DllMain/TLS callbacks. |
| `libpsycho` | WinAPI wrappers, IAT/inline/VMT hooking, logging. |
| `libnvse` | Rust bindings to xNVSE via `bindgen`. |
| `libmimalloc` | Fork of mimalloc sys crate. Builds C source via `cc`. |
| `libf4se` | Deprecated F4SE bindings. Not maintained. |

Plugin entry flow: `dinput8.dll` attach callback (`DllMain` or TLS) -> loader thread loads every `<game root>/mods/*.dll` -> loader calls each optional `PsychoLoader_ModInit` export outside the loaded DLL's loader-lock callback -> `psycho_engine_fixes.dll` completes all setup from that single entrypoint -> `psycho_engine_fixes_helper.dll` `NVSEPlugin_*` only registers helper services and forwards optional messages/commands through `PsychoEngineFixes_RunCommand` / `PsychoEngineFixes_NotifyEvent` if the core DLL is already available.

## WinAPI usage

Do not call WinAPI directly outside allocator hot paths. Use `libpsycho::os::windows::winapi` wrappers instead.

If a wrapper is missing, add it to `libpsycho` and make it as safe/idiomatic as practical. Direct WinAPI calls are allowed only in allocator code where per-allocation performance is critical and wrapper checks would be too expensive.

## Testing

No test suite exists. No `tests/` directories. Verify changes by building: `cargo build --release --target i686-pc-windows-gnu`. Linting: check for `cargo clippy` or `rustfmt` if needed (no CI config found).

## Graphics feature rule

Do not implement graphics effects as shader-only guesses when the effect needs engine data, intermediate buffers, masks, or render-stage control. Implement and prove the engine-side contract first: required textures, depth/color sources, constants, phase ownership, lifetime, compatibility behavior, and failure fallback. If the engine-side contract is missing or unproven, the correct next step is engine research/instrumentation or runtime buffer implementation, not another shader tweak.

Do not "fix" a broken graphics feature by globally disabling that target feature, removing it from the default runtime path, or narrowing user-facing coverage just to avoid the bug. Temporary disables are allowed only as explicitly labeled diagnostics or emergency safety switches, and must not be presented as the fix. The fix must preserve the intended feature and correct its engine contract, draw selection, resource binding, shader ABI, or performance behavior.

Before changing Fallout NV native PBR, read `docs/graphics_fnv_pbr_errata.md`. It records known PBR terrain/object/light regressions, including the close-terrain `-40 FPS` failure, broken terrain colors, interior wall/floor corruption, and light/shadow blinking. Do not repeat any "do not repeat" pattern from that document.

## Config

Plugin runtime config: `psycho-engine-fixes/config/psycho_engine_fixes.toml`, deployed beside the core DLL as `<game root>/mods/psycho_engine_fixes.toml`. Important memory setting: `memory.allocator` (`0` = off, `1` = scrap_heap, `2` = gheap + scrap_heap). It also controls zlib, display tweaks, logging, and debug probes.

## Key subsystem: gheap

`psycho-engine-fixes/src/mods/heap_replacer/gheap/` replaces the game's SBM allocator with a zombie-safe slab allocator.

Current project state:
- The project works and all features have been tested.
- `memory.allocator = 1` runs scrap_heap only. It gives less performance improvement than gheap + scrap_heap and can still have some random-user stability issues, but it is the safest practical allocator mode today.
- Full gheap can run on lightweight modpacks, but huge modpacks usually hit instant crashes or delayed VAS exhaustion/OOM crashes.
- Full gheap has location-specific crashes whose root cause is still unknown. Treat OOM/VAS exhaustion and UAF/reuse races as both plausible until proven otherwise.
- Full gheap is not broadly stable for other users. It is only known to be stable-ish on the user's own modpack.
- Potential rendering/texture memory issue: Fallout NV may duplicate textures or GPU-related data in both VRAM and RAM. This could explain some VAS/OOM behavior, but it is unproven and needs Ghidra/source/log-based research before relying on it.

Critical constraints:
- Mimalloc is CRT-only (third-party libs). Game objects go through slab.
- Havok Lock MUST be acquired before cleanup stages 0-6. AI threads access freed Havok objects without it.
- IO barrier wired into all OOM stage paths (stages 0, 4, 5).

## Research: `.research` directory

`.research/` is optional -- it may be empty or contain source code of other NVSE plugins (CrashLogger, JohnnyGuitar, JIP-LN, Tick Fix, etc.). When present, check it during crash investigation if a plugin involved in the crash has source here. Compare their hooking patterns, crash sites, and interactions with gheap to find conflicts.

## Research: Ghidra is ground truth

When investigating any game behavior, crash, or engine mechanism, Ghidra output is the authoritative reference. Pre-existing research lives in `analysis/ghidra/output/` (subdirs: `crash/`, `disasm/`, `memory/`, `perf/`). Each `.txt` file there maps to a source Ghidra script in `analysis/ghidra/scripts/`. Ignore `.md` files in `analysis/` -- they are outdated prose. Only trust the `.txt` Ghidra output unless user explicitly requests otherwise.

If a knowledge gap exists (unknown function behavior, unclear call paths, missing data flow), immediately prepare a Ghidra script to investigate and fill the gap with correct knowledge. Do not guess or reason from assumptions when a script can give a concrete answer.

No guessing rule: never implement a crash fix from an inferred model when the exact game contract is still unknown. If the current Ghidra output does not explain the failing function, caller ownership, data layout, lifetime, and safe intervention point, the next action is more research scripts -- not a patch. Partial research is not enough.

Architecture rule: do not place engine-fix crash patches in `psycho-engine-fixes-helper`. The helper exists for xNVSE commands/messages and optional access to data exported by the core DLL. Engine behavior fixes belong in `psycho-engine-fixes`, loaded by `psycho-loader`, unless the user explicitly asks for a helper-side compatibility shim.

Operational rule: do not run Ghidra, `analyzeHeadless`, or `ghidraRun` yourself. Prepare scripts in `analysis/ghidra/scripts/`, ask the user to run them, and analyze the resulting `.txt` output after the user provides it.

## Runtime debugging constraints

The user runs the game on Linux through Proton/Wine and cannot use native Windows debuggers such as WinDbg, x32dbg, or Visual Studio debugger. Do not propose debugger-dependent workflows as primary solutions. Prefer static Ghidra research, instrumented plugin logging, crash logs, minidumps if available, Wine/Proton logs, and targeted in-game repro telemetry.

## Ghidra scripts: mandatory rules

All Ghidra scripts live in `analysis/ghidra/scripts/`. Rules are in `analysis/ghidra/scripts/SCRIPT_RULES.md`. Every rule is critical -- Jython (Python 2.7) has quirks that silently break standard patterns.

Key constraints (non-negotiable):
- **TABS ONLY.** No spaces indentation, no mixed tabs/spaces.
- **No top-level loops.** Any `for` or `while` loop at module scope breaks the Jython parser. Wrap all loops in helper functions.
- **No top-level tuple unpacking.** `for src, tgt in calls:` breaks at top level. Use `item[0]`, `item[1]` or wrap in a function.
- **No top-level `while hasNext/next`.** Same parser bug. Wrap in function.
- **Always `decomp.dispose()`** at script end. Ghidra leaks memory otherwise.
- **Output to `analysis/ghidra/output/`** subdirectory matching the topic.
- **Copy the standard helpers** (`decompile_at`, `find_refs_to`, `find_and_print_calls_from`) into every script. Do not reinvent.
- **Standard script header:** `# @category Analysis` / `# @description ...`

## Engineering balance: OOM vs UAF vs performance

Every gheap decision lives in a permanent three-way tension. All three requirements are critical and non-negotiable, but they conflict:

1. **OOM recovery** -- the game must not crash from out-of-memory. Requires cleanup stages, commit tracking, pressure monitoring, quarantine.
2. **UAF protection** -- freed memory must remain readable ("zombie-safe") because the game accesses freed pointers on IO threads, AI threads, and after cell transitions. Requires slab reuse cooldown, Havok lock, IO barrier.
3. **Performance** -- this replaces the game's allocator in every hot path. Cannot add overhead per-allocation. Requires sharded size classes, bitmap free tracking, minimal synchronization.

When a change touches gheap, explicitly state which of the three it optimizes for and how it affects the others. Example: "This adds a 15s reuse cooldown to slab blocks (costs memory, helps UAF)."

## Honesty

Never tell the user what they want to hear if it is wrong. If an idea, assumption, or instruction is incorrect, say so directly. Explain the reason and reference sources (code, Ghidra output, docs) so the user can verify. Polite lies waste time; blunt correctness builds trust.

## Style

- KISS principle. No over-engineering, no clever tricks. Simple, direct solutions.
- Clean code. Clear naming that explains intent without comments. A developer unfamiliar with the code should understand context within minutes, not hours.
- Self-documenting code over docstrings. Names carry meaning; comments explain why, not what.
- No non-ASCII in comments/docstrings.
- Comments should read like a human wrote them, not LLM.
- Prefer editing existing files over rewriting.
- Code uses edition 2024.

## Logs

- **Fresh logs** -- symlinks created by `ln_logs.sh` in `psycho-engine-fixes/`: `psycho-engine-fixes-latest.log`, `CrashLogger.log`. Always point to the game directory.
- **User reports** -- put problem report logs into `.reports/` for analysis.

## Shell scripts

- `build_fnv.sh` -- builds and installs the full FNV set: `FalloutNV/dinput8.dll`, `FalloutNV/mods/psycho_engine_fixes.dll`, `FalloutNV/mods/psycho_engine_fixes.toml`, and helper DLL to the legacy xNVSE mod path `mods/psycho_nvse/nvse/plugins/psycho_engine_fixes_helper.dll` (edit `TARGET_DIR` at top). It also removes exact stale Psycho configs/DLLs from old install layouts.
- `psycho-engine-fixes/build.sh` -- compatibility wrapper that calls `../build_fnv.sh`
- `psycho-engine-fixes/release.sh` -- builds release and packages zips in `.release/`
- `psycho-engine-fixes/ln_logs.sh` -- symlinks game log files into repo for inspection

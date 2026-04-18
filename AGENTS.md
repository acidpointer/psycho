# AGENTS.md

## Build

Only supported target: `i686-pc-windows-gnu` (32-bit, FNV/xNVSE requirement).

```
cargo build --release --target i686-pc-windows-gnu -p psycho-nvse
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
| `psycho-nvse` | Main plugin (`cdylib`). Entry points in `src/entry.rs`. |
| `libpsycho` | WinAPI wrappers, IAT/inline/VMT hooking, logging. |
| `libnvse` | Rust bindings to xNVSE via `bindgen`. |
| `libmimalloc` | Fork of mimalloc sys crate. Builds C source via `cc`. |
| `libf4se` | Deprecated F4SE bindings. Not maintained. |

Plugin entry flow: `DllMain` (empty) -> `NVSEPlugin_Preload` (config, logger, trampolines) -> `NVSEPlugin_Query` (version info) -> `NVSEPlugin_Load` (activate hooks).

## Testing

No test suite exists. No `tests/` directories. Verify changes by building: `cargo build --release --target i686-pc-windows-gnu`. Linting: check for `cargo clippy` or `rustfmt` if needed (no CI config found).

## Config

Plugin runtime config: `psycho-nvse/config/psycho-nvse.toml`. Controls heap replacer, zlib, display tweaks, logging, debug probes.

## Key subsystem: gheap

`psycho-nvse/src/mods/heap_replacer/gheap/` replaces the game's SBM allocator with a zombie-safe slab allocator.

Critical constraints:
- Mimalloc is CRT-only (third-party libs). Game objects go through slab.
- Havok Lock MUST be acquired before cleanup stages 0-6. AI threads access freed Havok objects without it.
- IO barrier wired into all OOM stage paths (stages 0, 4, 5).

## Research: `.research` directory

`.research/` is optional -- it may be empty or contain source code of other NVSE plugins (CrashLogger, JohnnyGuitar, JIP-LN, Tick Fix, etc.). When present, check it during crash investigation if a plugin involved in the crash has source here. Compare their hooking patterns, crash sites, and interactions with gheap to find conflicts.

## Research: Ghidra is ground truth

When investigating any game behavior, crash, or engine mechanism, Ghidra output is the authoritative reference. Pre-existing research lives in `analysis/ghidra/output/` (subdirs: `crash/`, `disasm/`, `memory/`, `perf/`). Each `.txt` file there maps to a source Ghidra script in `analysis/ghidra/scripts/`. Ignore `.md` files in `analysis/` -- they are outdated prose. Only trust the `.txt` Ghidra output unless user explicitly requests otherwise.

If a knowledge gap exists (unknown function behavior, unclear call paths, missing data flow), immediately prepare a Ghidra script to investigate and fill the gap with correct knowledge. Do not guess or reason from assumptions when a script can give a concrete answer.

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

- **Fresh logs** -- symlinks created by `ln_logs.sh` in `psycho-nvse/`: `psycho-nvse-latest.log`, `CrashLogger.log`. Always point to the game directory.
- **User reports** -- put problem report logs into `.reports/` for analysis.

## Shell scripts

- `psycho-nvse/build.sh` -- builds and copies DLL to game directory (edit `TARGET_DIR` at top)
- `psycho-nvse/release.sh` -- builds release and packages zips in `.release/`
- `psycho-nvse/ln_logs.sh` -- symlinks game log files into repo for inspection

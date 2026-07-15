# Psycho Engine Fixes

Performance and engine fixes for Fallout: New Vegas.

This mod is made for heavy setups. It loads early, patches engine code directly,
and tries to remove some of the old bottlenecks that hurt New Vegas today:
memory allocation, loading, decompression, fullscreen focus, and several known
crash paths.

## What It Does

- Replaces hot heap paths with `gheap` and `scrap_heap`.
- Speeds up zlib decompression for compressed resources.
- Replaces the old RNG path with a faster compatible one.
- Fixes native-fullscreen startup and safe fullscreen Alt-Tab placement.
- Adds small crash guards for known broken engine states.
- Writes useful diagnostics for crash reports and memory pressure.
- Includes Syringe, an early `dinput8.dll` loader for DLLs in `FalloutNV/syringe`.

## Requirements

- Fallout: New Vegas
- xNVSE
- A mod manager, or manual install if you know what you are doing

The mod is built for the normal 32-bit Fallout: New Vegas executable.

## Installation

Install the release archive into the Fallout: New Vegas game folder, where
`FalloutNV.exe` is located.

Expected layout:

```text
FalloutNV/
  dinput8.dll
  syringe/
    psycho_engine_fixes.dll
    psycho_engine_fixes.toml
  Data/
    NVSE/
      plugins/
        psycho_engine_fixes_helper.dll
```

Do not move `psycho_engine_fixes.dll` to `Data/NVSE/plugins`. It belongs in
`FalloutNV/syringe` and is loaded by `dinput8.dll`.

The xNVSE helper belongs in `Data/NVSE/plugins`. It is only a helper for console
commands and runtime messages.

## Updating

Replace the old files with the new archive.

Check `syringe/psycho_engine_fixes.toml` after updating. New versions can add new
options, and the config file has comments for them.

## Uninstalling

Remove these files:

```text
FalloutNV/dinput8.dll
FalloutNV/syringe/psycho_engine_fixes.dll
FalloutNV/syringe/psycho_engine_fixes.toml
FalloutNV/Data/NVSE/plugins/psycho_engine_fixes_helper.dll
```

Only remove `dinput8.dll` if it is the Psycho loader. If another mod installed
its own `dinput8.dll`, check before deleting.

## Configuration

Config file:

```text
FalloutNV/syringe/psycho_engine_fixes.toml
```

The config is documented in place. Read comments in the file. Main sections:

- `memory` - choose vanilla allocator, `scrap_heap`, or `gheap + scrap_heap`
- `engine_fixes` - individual crash and display fixes
- `performance` - zlib and RNG patches
- `diagnostics` - console and debug log

Most users should start with defaults.

For crash reports, keep `debug_log` enabled and include the config file.

## Allocator Modes

This is the main feature of the mod.

`gheap` replaces the main game heap. It can give the strongest performance
improvement, but it has to deal with ugly engine behavior: stale pointers,
worker threads, Havok, loading, and cell transitions.

`scrap_heap` replaces temporary allocation heaps. It is usually safer for very
large modlists and is useful for troubleshooting.

If full allocator mode crashes for you, try the safer allocator mode in the
config and keep logs. That information is useful.

## Logs And Crash Reports

Main log:

```text
FalloutNV/psycho-engine-fixes-latest.log
```

When reporting a crash, include:

- `psycho-engine-fixes-latest.log`
- `CrashLogger.log`, if installed
- `psycho_engine_fixes.toml`
- what you were doing before the crash
- whether changing allocator mode changes the crash

Without logs, most memory and engine crashes are impossible to understand.

## Compatibility

Psycho should work with normal xNVSE setups.

It is also designed to be compatible with common engine/plugin stacks, but any
mod that patches the same engine code can conflict. If something breaks, report
it with logs and your mod list.

The display fix recognizes the visible bootstrap creation plus six audited
window-placement paths. Native fullscreen and live borderless windows receive
narrow transition policies; ordinary windowed and unrecognized calls pass
through unchanged. Existing `CreateWindowExA` and `SetWindowPos` IAT hooks are
chained, while directly modified callsites remain under their current owner's
control.

## Syringe

`syringe` is the generic `dinput8.dll` shipped with this mod.

It is a generic early loader, not an xNVSE plugin. It loads DLLs from:

```text
FalloutNV/syringe/*.dll
```

After loading every DLL, it runs two optional callback phases:

```text
Syringe_ModInit
Syringe_ModActivate
```

All `Syringe_ModInit` callbacks finish before any `Syringe_ModActivate`
callback runs. Both execute after `LoadLibraryW` returns and outside `DllMain`,
which avoids Windows loader-lock deadlocks. The second phase lets mods make a
final ownership decision after every early mod has initialized. A zero return
is reported as that mod's failure but does not stop callbacks for other mods.

For other developers:

- put your early DLL in `FalloutNV/syringe`
- export `Syringe_ModInit`
- initialize from that function
- optionally export `Syringe_ModActivate` for work that must run after every
  early mod has initialized
- keep `DllMain` minimal
- use a separate xNVSE plugin only when you need xNVSE services

The loader is intentionally small, `no_std`, and mod-agnostic.

## Building From Source

This project builds fully from Linux by cross-compiling to Windows.

Target:

```text
i686-pc-windows-gnu
```

Setup:

```sh
rustup target add i686-pc-windows-gnu
git submodule update --init --recursive
```

Build:

```sh
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv
```

Requires `mingw-w64` with `i686-w64-mingw32-gcc` on `PATH`.

Local test install:

```sh
./build_fnv.sh
```

Release archives:

```sh
cd psycho-engine-fixes
./release.sh
```

This produces the core, xNVSE helper, and `omv-nvse-*` archives in `.release/`.

## Developer Notes

`libpsycho` is the low-level Rust modding library used by this project. It
contains WinAPI wrappers, IAT hooks, inline hooks with trampolines, VMT hooks,
memory patching helpers, PE/module inspection, FFI helpers, executable version
checks, and threaded logging.

The workspace also has a local `libmimalloc` fork. It builds mimalloc C sources
directly in the workspace, so Psycho can control build flags and allocator
features for this 32-bit target.

## Workspace

- `syringe` - generic early `dinput8.dll` loader
- `syringe-api` - ABI for early-loaded DLLs
- `psycho-engine-fixes` - core engine fix DLL
- `psycho-engine-fixes-helper` - xNVSE helper plugin
- `libpsycho` - shared modding infrastructure
- `libnvse` - Rust bindings for xNVSE
- `libmimalloc` - local mimalloc build
- `libf4se` - old Fallout 4 bindings, not maintained

## Source

```text
https://github.com/acidpointer/psycho
```

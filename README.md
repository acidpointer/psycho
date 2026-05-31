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
- Fixes fullscreen and borderless alt-tab/focus problems.
- Adds small crash guards for known broken engine states.
- Writes useful diagnostics for crash reports and memory pressure.
- Includes an early `dinput8.dll` loader for DLLs in `FalloutNV/mods`.

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
  mods/
    psycho_engine_fixes.dll
    psycho_engine_fixes.toml
  Data/
    NVSE/
      plugins/
        psycho_engine_fixes_helper.dll
```

Do not move `psycho_engine_fixes.dll` to `Data/NVSE/plugins`. It belongs in
`FalloutNV/mods` and is loaded by `dinput8.dll`.

The xNVSE helper belongs in `Data/NVSE/plugins`. It is only a helper for console
commands and runtime messages.

## Updating

Replace the old files with the new archive.

Check `mods/psycho_engine_fixes.toml` after updating. New versions can add new
options, and the config file has comments for them.

## Uninstalling

Remove these files:

```text
FalloutNV/dinput8.dll
FalloutNV/mods/psycho_engine_fixes.dll
FalloutNV/mods/psycho_engine_fixes.toml
FalloutNV/Data/NVSE/plugins/psycho_engine_fixes_helper.dll
```

Only remove `dinput8.dll` if it is the Psycho loader. If another mod installed
its own `dinput8.dll`, check before deleting.

## Configuration

Config file:

```text
FalloutNV/mods/psycho_engine_fixes.toml
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

The alt-tab fix is meant for fullscreen and borderless-window users. It was
tested with Proton/Wine and should also help with related Windows focus issues.

## Psycho Loader

`psycho-loader` is the `dinput8.dll` shipped with this mod.

It is a generic early loader, not an xNVSE plugin. It loads DLLs from:

```text
FalloutNV/mods/*.dll
```

After loading a DLL, it looks for this optional export:

```text
PsychoLoader_ModInit
```

If present, it calls that function after `LoadLibraryW` returns. This gives mods
a clean startup point outside `DllMain`, which is important because doing real
work from `DllMain` can deadlock on Windows loader lock.

For other developers:

- put your early DLL in `FalloutNV/mods`
- export `PsychoLoader_ModInit`
- initialize from that function
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
cargo build --release --target i686-pc-windows-gnu -p psycho-loader -p psycho-engine-fixes -p psycho-engine-fixes-helper
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

## Developer Notes

`libpsycho` is the low-level Rust modding library used by this project. It
contains WinAPI wrappers, IAT hooks, inline hooks with trampolines, VMT hooks,
memory patching helpers, PE/module inspection, FFI helpers, executable version
checks, and threaded logging.

The workspace also has a local `libmimalloc` fork. It builds mimalloc C sources
directly in the workspace, so Psycho can control build flags and allocator
features for this 32-bit target.

## Workspace

- `psycho-loader` - generic early `dinput8.dll` loader
- `psycho-loader-api` - ABI for early-loaded DLLs
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


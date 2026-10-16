<div align="center">

# PSYCHO

**New Vegas is 32-bit. Your modlist is not.**

Engine fixes, free performance, modern graphics, and a full gameplay overhaul
for **Fallout: New Vegas** and **Tale of Two Wastelands** - written in Rust,
built on Linux.

</div>

---

## What is Psycho?

A toolbox, not a single mod. Four independent modifications share one
foundation, so you install only the parts you want.

| Mod | What it gives you | How you feel it |
|---|---|---|
| **Psycho Engine Fixes** | Faster memory, loading and IO, plus targeted crash fixes | Smoother frames, fewer crashes |
| **Oh My Vegas! (OMV)** | A modern graphics stack: PBR, atmosphere, depth of field, motion blur, AA | Press `Insert` and watch the Mojave change |
| **Atom** | An ESP-less gameplay overhaul: input, cameras, physical ballistics | Bullets finally fly for real |
| **Engine Fixes Helper** | An in-game telemetry and config dashboard | Press `F10` to look under the hood |

Underneath all of it: **libpsycho** (the shared Rust engine toolkit), **Syringe**
(a tiny early loader), and **psycho-imgui**.

> [!NOTE]
> New Vegas is 32-bit and always will be. No mod can give it more address space
> than it was built for. Psycho pushes that limit hard - it just will not
> pretend the limit is gone.

## What you get

**Psycho Engine Fixes**

- Replaces the game allocators with modern, multithreaded ones.
- Moves loading, LOD and streaming work off the critical path.
- Repairs fullscreen, Alt-Tab, cursor confinement and system/media keys.
- Makes saves durable and guards audited crash paths in Havok, AI, navmesh,
  inventory and save code.
- Accelerates zlib decompression and the engine RNG.

**Oh My Vegas!**

- Native PBR and Sky shaders, ported from New Vegas Reloaded and rebuilt for
  performance.
- Ambient occlusion, bloom/HDR, volumetric atmosphere, depth of field, camera
  motion blur, temporal and spatial anti-aliasing.
- Loose HLSL shader loading for your own experiments.

**Atom**

- A rebuilt input path and first/third-person cameras.
- Native physical ballistics with per-material ricochet.
- No ESP, no ESL, no load-order slot.

Every switch is independent and documented - nothing is an all-or-nothing
gamble.

## Install

**You need:** Fallout: New Vegas `1.4.0.525` (TTW works through the normal
`FalloutNV.exe`), [xNVSE](https://github.com/xNVSE/NVSE), and a mod manager such
as Mod Organizer 2. A 4 GB-aware executable is strongly recommended.

Download only the parts you want:

| Archive | Where it goes |
|---|---|
| `psycho-engine-fixes-<version>.zip` | Extract into the folder containing `FalloutNV.exe` |
| `psycho-engine-fixes-nvse-helper-<version>.zip` | Install as a normal mod |
| `omv-nvse-<version>.zip` | Install as a normal mod |
| `atom-nvse-<version>.zip` | Install as a normal mod |

Then launch the game through **xNVSE**. A healthy start writes
`psycho-engine-fixes-latest.log` into the game root.

> [!IMPORTANT]
> Engine Fixes loads early through `dinput8.dll`, so it must sit beside
> `FalloutNV.exe`. Dropping it into `Data` does nothing. If another mod already
> owns `dinput8.dll`, back it up first - Windows loads only one.

> [!WARNING]
> Oh My Vegas! needs Direct3D 9 with Shader Model 3.0, plus one D3DCompiler DLL
> (`47`, `46`, `43`, `42` or `41`) visible to the game, so it can compile its
> shaders. Use a trusted Microsoft runtime, not a random DLL mirror.
> **New Vegas Reloaded is not supported alongside OMV** - both drive the
> renderer, so pick one.

> [!NOTE]
> OMV is standalone. Fallout Shader Loader, Vanilla Plus Terrain and LOD
> Flicker Fix are not required - OMV checks the engine's own shader and terrain
> contracts and works with or without them.

## Configure

| Mod | File |
|---|---|
| Engine Fixes | `syringe/psycho_engine_fixes.toml` (fully commented) |
| Oh My Vegas! | `Data/NVSE/plugins/omv/omv.toml` |
| Atom | `Data/MCM/Atom.json` (MCM Extender menu) |

The Engine Fixes config is grouped into memory, engine fixes, IO/LOD streaming,
performance and diagnostics. Change one thing at a time and restart the game
after saving.

## When something breaks

Attach the **whole** log, not the last ten lines - the startup messages explain
far more than the final error.

- **Engine Fixes:** `psycho-engine-fixes-latest.log`, `CrashLogger.log`, your
  `syringe/psycho_engine_fixes.toml`, and the action, cell and save used just
  before the crash. Note whether allocator modes `0`, `1` and `2` change the
  result.
- **Oh My Vegas!:** `omv-latest.log`, `omv.toml`, a screenshot for visible
  corruption, and your resolution, display mode and graphics dependencies.

## Good to know

- Two mods can patch the same instruction. Test with logs; a plugin count tells
  you nothing.
- OMV expects to own its graphics hooks - do not stack it under another native
  renderer overhaul.
- These mods add no permanent gameplay records, so uninstalling needs no save
  cleaner. Remove only the files you installed.
- `bFull Screen` selects fullscreen; borderless windowed is the windowed default.

## On AI

Skeptical of "AI mods"? Fair. Here is the honest version.

AI is a tool here, not the engineer. It handles the tedious work - reverse
engineering, digging through engine logic, triaging crashes, and mapping faults
back to the subsystem that owns them. The judgment, the design and the
responsibility stay human.

- Design, code quality, behavior and stability belong to the developer
  (acidpointer). Every change is reviewed and playtested before it ships.
- AI helps prototype; that code is usually refactored hard before release.
- The automated tests are AI-written, purely to save the developer's time.

This is not a prompt-and-publish mod. It is engineered, tested, and owned.

## On documentation

There is a reason `docs/` is full of dated files. AI is made to write
documentation in depth while the work happens - engine contracts, crash
post-mortems, design decisions, and the notes behind each change - and that
record is kept instead of thrown away.

It looks like clutter until the day a regression appears months later. Then
those notes are what tell you what changed, why it changed, and what the code
was supposed to do. What would otherwise be a day of guessing becomes a quick
answer.

## Build from source

Only the 32-bit Windows GNU target is supported.

```bash
rustup target add i686-pc-windows-gnu
git submodule update --init --recursive
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper -p omv -p atom
```

This needs `i686-w64-mingw32-gcc` on `PATH`; tests run through Wine.
`./build_fnv.sh` builds and installs the full set, and
`psycho-engine-fixes/release.sh <version>` packages the archives.

## Repository map

| Path | Purpose |
|---|---|
| `psycho-engine-fixes/` | Early-loaded engine fixes, allocators and config |
| `psycho-engine-fixes-helper/` | Companion xNVSE dashboard |
| `omv/` | Oh My Vegas! graphics mod, shaders and config |
| `atom/` | Atom gameplay overhaul |
| `syringe/` | Generic early `dinput8.dll` loader |
| `libpsycho/` | Shared Rust engine toolkit |
| `docs/` | Engine contracts, research and design notes |

- Oh My Vegas! deep dive: [`omv/README.md`](omv/README.md)
- Atom contracts: [`docs/atom.md`](docs/atom.md)
- Early loader: [`syringe/README.md`](syringe/README.md)

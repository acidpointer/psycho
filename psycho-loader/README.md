# psycho-loader

Early `dinput8.dll` proxy for Fallout New Vegas.

This crate is intentionally mod-agnostic. It is not an NVSE plugin, does not
know about `psycho_engine_fixes.dll`, and must not call NVSE APIs. Its job is to
load before later plugin systems run, proxy the real system `dinput8.dll`, and
load every `*.dll` from `<game root>/mods`.

The proxy is deliberately `no_std` and does not depend on `libpsycho`. Keep it
limited to tiny Kernel32-only startup code; richer modding infrastructure belongs
in loaded mods after `PsychoLoader_ModInit`.

DLLs are loaded in case-insensitive filename order. Other developers can place
their own early-load DLLs in the same directory without changing this loader.

The proxy starts a tiny loader thread from `DllMain` and from its TLS callback.
Both callbacks use the same guarded attach path. That keeps `LoadLibraryW` out
of the loader-lock callback itself, while still loading the mods before normal
dinput8 forwarding in most startup paths.

Loaded DLLs should not perform real initialization from `DllMain` or TLS
callbacks. Instead, export this optional entrypoint:

```text
PsychoLoader_ModInit(const PsychoLoaderInfo* info) -> i32
```

`psycho-loader` calls it after `LoadLibraryW` returns, so the mod has a clear
startup point outside the loaded DLL's loader-lock callback.

Build:

```text
cargo build --release --target i686-pc-windows-gnu -p psycho-loader -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Deploy `dinput8.dll` next to the game executable. Any early-load DLL, including
`psycho_engine_fixes.dll`, belongs in `<game root>/mods/`. Host-specific helper
DLLs remain wherever that host plugin manager expects them.

# Syringe

Early `dinput8.dll` proxy for Fallout New Vegas.

This crate is intentionally mod-agnostic. It is not an NVSE plugin, does not
know about `psycho_engine_fixes.dll`, and must not call NVSE APIs. Its job is to
load before later plugin systems run, proxy the real system `dinput8.dll`, and
load every `*.dll` from `<game root>/syringe`.

The proxy is deliberately `no_std` and does not depend on `libpsycho`. Keep it
limited to tiny Kernel32-only startup code; richer modding infrastructure belongs
in loaded mods after `Syringe_ModInit`.

DLLs are loaded in Windows ordinal case-insensitive filename order. Other
developers can place their own early-load DLLs in the same directory without
changing this loader.

The proxy starts one loader thread from `DllMain` without waiting for it. That
worker loads the real system `dinput8.dll`, then discovers and initializes
Syringe DLLs. Proxy exports always forward independently of this work: they
never wait for, or start, mod loading. This avoids loading arbitrary mods while
another DLL may hold the Windows loader lock.

Loaded DLLs should not perform real initialization from `DllMain` or TLS
callbacks. Instead, export this optional entrypoint:

```text
Syringe_ModInit(const SyringeInfo* info) -> i32
```

`syringe` calls it after `LoadLibraryExW` returns, so the mod has a clear
startup point outside the loaded DLL's loader-lock callback. The export name
must be exactly undecorated `Syringe_ModInit`; an i686 stdcall DLL should use a
module definition file to guarantee that spelling. `info` is borrowed only for
the callback and must not be retained.

Build:

```text
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Deploy `dinput8.dll` next to the game executable. Any early-load DLL, including
`psycho_engine_fixes.dll`, belongs in `<game root>/syringe/`. Host-specific helper
DLLs remain wherever that host plugin manager expects them.

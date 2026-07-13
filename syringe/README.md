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

The proxy installs a small main-executable startup barrier from `DllMain`. The
barrier runs outside loader lock, loads the real system `dinput8.dll`, and then
discovers and initializes Syringe DLLs. A non-blocking worker is retained only
as a compatibility fallback when the executable has no supported startup
import. Proxy exports never wait for an active loader pass, avoiding a loader-
lock deadlock. They also never start mod loading themselves.

The worker does not claim the pre-CRT capability flag. A mod that rewrites
executable code must require the barrier flag and reject worker activation.

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

Mods that need to inspect the final early-mod state may also export:

```text
Syringe_ModActivate(const SyringeInfo* info) -> i32
```

Syringe loads every DLL first, calls every `Syringe_ModInit`, and only then
calls every `Syringe_ModActivate`, using the same deterministic filename order
for each phase. A zero return is reported for diagnostics but does not stop the
remaining callbacks.

Build:

```text
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Deploy `dinput8.dll` next to the game executable. Any early-load DLL, including
`psycho_engine_fixes.dll`, belongs in `<game root>/syringe/`. Host-specific helper
DLLs remain wherever that host plugin manager expects them.

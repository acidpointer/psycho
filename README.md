# Project PSYCHO

> *Psycho was always in the Wasteland. Now it's in your engine.*

An experimental NVSE plugin written entirely in **Rust** that replaces core Fallout: New Vegas engine subsystems with modern, high-performance alternatives. Started as a fun attempt to write a memory allocator replacement, grew into a full Rust modding infrastructure for Bethesda-engine games.

Source: [https://github.com/acidpointer/psycho](https://github.com/acidpointer/psycho)

---

## Why Rust?

Rust is a natural fit for game modding. Modding inherently involves unsafe low-level memory manipulation, hooking, and patching — exactly the domain where memory safety bugs are most destructive and hardest to debug. Rust lets you write unsafe code where necessary while keeping the rest of the codebase honest. The compiler catches entire categories of bugs before they become a 3-hour debugging session in x64dbg.

---

## Workspace Structure

### `psycho-nvse`
The main plugin. A `cdylib` loaded by xNVSE at startup. Performs all engine patches:
- CRT allocator replacement via IAT hooks (mimalloc)
- Scrap heap replacement (custom region bump allocator)
- zlib reimplementation (zlib-rs backend)

### `libpsycho`
Core library providing the low-level infrastructure everything else is built on.

- **WinAPI wrappers** — safe abstractions over `VirtualProtect`, memory patching, NOP/CALL writing, PE parsing, and related Win32 operations
- **IAT hooking** — rewrites Import Address Table entries at runtime to redirect function calls
- **Inline hooking** — JMP-trampoline hooks with disassembly-aware trampoline generation via `iced-x86`. Handles cases where patching overwrites partial instructions correctly
- **VMT hooking** — Virtual Method Table hooking, implemented but not yet battle-tested in production
- **Logging** — a forked `simplelog` with a threaded writer backend. Log calls return immediately; a dedicated thread handles the actual I/O. Suitable for high-frequency logging scenarios without stalling the game thread

### `libnvse`
Rust bindings to **xNVSE**, auto-generated from official C++ headers via `bindgen` at build time. Provides safe(r) Rust wrappers around the raw FFI types. Work in progress — not all of the xNVSE API surface is covered, but enough to write functional plugins without touching C++.

Uses `closure-ffi` for safely passing Rust closures across FFI boundaries.

### `libmimalloc`
A fork of the `mimalloc` Rust crate tracking the upstream mimalloc C library directly rather than waiting on crates.io releases. Exposes:
- A global allocator interface (implements `GlobalAlloc`)
- A per-heap `MiHeap` API used internally by the scrap heap replacer

### `libf4se`
⚠️ **Deprecated.** Early-stage Rust bindings to **F4SE** for Fallout 4. Supports only old-gen (1.10.163) and a small subset of the F4SE C API. Not actively maintained.

Still usable as a starting point or reference for anyone wanting to build Fallout 4 tooling in Rust. The infrastructure in `libpsycho` is fully compatible.

---

## Dependencies

Key third-party crates used across the workspace:

| Crate | Purpose |
|---|---|
| `parking_lot` | Fast synchronization primitives — `Mutex`, `RwLock`, `Once`. Significantly faster than `std::sync` equivalents |
| `clashmap` | Concurrent hashmap (fork of DashMap). Used for the scrap heap registry and other shared concurrent state |
| `rustc-hash` (`FxHash`) | Extremely fast non-cryptographic hasher. Used where key distribution is trusted and speed matters |
| `ahash` | Fast, DoS-resistant non-cryptographic hasher. Used where slightly more hash quality is needed |
| `crossbeam-queue` | Lock-free MPMC queue used in the GC and thread communication |
| `iced-x86` | x86/x64 disassembler and assembler. Used by the inline hook engine for instruction-aware trampoline generation |
| `goblin` | PE32/PE64 binary parsing. Used for IAT resolution and module inspection |
| `windows` | Official Microsoft Rust bindings to the Windows API |
| `libz-rs-sys` | Rust-native zlib reimplementation (zlib-rs). Drop-in replacement for the C zlib ABI |
| `closure-ffi` | Safely pass Rust closures across FFI boundaries |
| `anyhow` / `thiserror` | Error handling |
| `bindgen` | Auto-generate Rust FFI bindings from C/C++ headers (build dependency for `libnvse`) |

---

## Cross-Compilation

The project is developed on **Linux** and **cross-compiled to Windows targets**. This is a deliberate design constraint, not an afterthought.

### Supported Targets

| Target | Toolchain | Notes |
|---|---|---|
| `i686-pc-windows-gnu` | `mingw-w64` | Only supported target. 32-bit, required for FNV/xNVSE compatibility. Full `rust-analyzer` support |

The codebase is written with 32-bit in mind throughout. All pointer arithmetic and struct layouts account for 32-bit targets. Other targets are not supported.

---

## Building

```sh
# Install the target
rustup target add i686-pc-windows-gnu

# Build the plugin
cargo build --release --target i686-pc-windows-gnu -p psycho-nvse
```

Requires `mingw-w64` (`i686-w64-mingw32-gcc`) on `$PATH`.

---

## Contributing

Contributions are welcome — especially on the library side (`libpsycho`, `libnvse`). The more complete and robust these become, the more useful the infrastructure is for the broader Rust modding community.

If you want to write your own NVSE plugin in Rust, this repository is a working starting point. The libraries are designed to be reusable independently of `psycho-nvse` itself.

Bug reports, API improvements, new hook types, better test coverage — all appreciated. Open an issue or a PR on GitHub.

---

## Inspiration

This project started after reading the source code of **NVHR (New Vegas Heap Replacer)**. NVHR is a well-engineered mod and worth reading. Psycho asks what the same problem space looks like approached entirely in Rust.

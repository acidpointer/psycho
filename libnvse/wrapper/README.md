# xNVSE C++ Wrapper

Wrapper infrastructure for generating Rust FFI bindings to xNVSE via bindgen.

## Supported targets

| Rust target | Host OS | Status |
|---|---|---|
| `i686-pc-windows-gnu` | Linux (cross-compile) | Primary |
| `i686-pc-windows-gnu` | Windows (MSYS2/MinGW) | Supported |
| `i686-pc-windows-msvc` | Windows | Supported |

All targets use the same stub headers and produce identical bindings.
No Windows SDK required for bindgen -- the stubs satisfy all type declarations.

## How it works

1. `build.rs` patches xNVSE headers (removes `[[nodiscard]]` for older clang)
2. Clang parses `nvse_wrapper.h` with `-nostdinc++` using our stubs
3. bindgen generates Rust FFI bindings from the parsed AST
4. The clang target is always `i686-pc-windows-msvc` because the game and xNVSE
   are MSVC-compiled binaries -- our plugin must match their ABI

## Why custom C++ headers?

We provide minimal C++ stdlib stubs because:

- Cross-compilation from Linux has no Windows headers
- Avoids Windows SDK dependency for bindgen
- Guarantees reproducible bindings regardless of host environment
- Only declares types that xNVSE headers reference (no full implementations needed)

## Modifying

- To support new xNVSE headers, add stub headers in `include/`
- To change what xNVSE APIs are exposed, edit `nvse_wrapper.h`
- All changes trigger rebuild via `cargo:rerun-if-changed`

## AI Warning

This wrapper was built with significant AI assistance. If you see issues
or know a better approach, pull requests are welcome.

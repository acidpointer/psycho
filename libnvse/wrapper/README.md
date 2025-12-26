# xNVSE C++ Wrapper

This directory contains the wrapper infrastructure for generating Rust FFI bindings to xNVSE (Extended New Vegas Script Extender).

# AI Warning

C++ wrapper, stubs, build.rs and this README.md was done with significant help of AI tools, as im not C++ developer at all. If you hate the way it done - please, feel free to provide pull request with better solution, i'll appreciate any help.

## Structure

```
wrapper/
├── nvse_wrapper.h          # Main wrapper header that includes xNVSE headers
└── include/                # Minimal C++ standard library stubs for cross-compilation
    ├── cstddef
    ├── cstdarg
    ├── cstdint
    ├── type_traits
    ├── string
    ├── string_view
    ├── vector
    ├── map
    ├── unordered_map
    ├── list
    ├── functional
    ├── memory
    ├── tuple
    ├── utility
    ├── algorithm
    ├── cmath
    ├── initializer_list
    ├── span
    └── bit
```

## Why Custom C++ Headers?

We provide minimal C++ standard library stubs because:

1. **Cross-compilation**: Building Windows binaries from Linux without Windows SDK
2. **i686 (32-bit) target**: xNVSE is 32-bit only (Fallout New Vegas is a 32-bit game)
3. **Avoiding system headers**: Linux C++ headers aren't compatible with Windows MSVC target
4. **Minimal dependencies**: Only include what's actually needed by xNVSE headers

## How It Works

1. `build.rs` downloads xNVSE source from GitHub
2. Clang uses these stubs instead of system C++ headers (`-nostdinc++`)
3. bindgen generates Rust FFI bindings from `nvse_wrapper.h`
4. C++ stdlib types are marked as opaque (not fully generated) in Rust

## Modifying

- To add new types, create stub headers in `include/`
- To change what's included, edit `nvse_wrapper.h`
- All changes automatically trigger rebuild via `cargo:rerun-if-changed`

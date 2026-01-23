# libnvse

Library to work with xNVSE.

## About

This crate provides automatically generated Rust bindings to the xNVSE plugin API, enabling you to write Fallout New Vegas NVSE plugins in Rust.

- **xNVSE Version**: 6.4.4 (pinned via git submodule)
- **Target**: i686-pc-windows-gnu (32-bit only)
- **Bindings**: Auto-generated using bindgen

## Building

### Prerequisites

1. **Initialize the xNVSE submodule** (first time only):
   ```bash
   git submodule update --init --recursive
   ```

2. **Install i686 Windows target**:
   ```bash
   rustup target add i686-pc-windows-gnu
   ```

3. **Install required tools**:
   - `mingw-w64` (for cross-compilation from Linux)
   - `bindgen` dependencies (clang/libclang)

### Build

```bash
cargo build --target i686-pc-windows-gnu
```

The build process will:
1. Verify the xNVSE submodule is present
2. Patch xNVSE headers for bindgen compatibility
3. Generate Rust bindings to `src/bindings/nvse.rs`
4. Compile the crate

## Project Structure

```
libnvse/
├── xnvse/                      # Git submodule (xNVSE 6.4.4 source)
├── wrapper/                    # C++ wrapper infrastructure
│   ├── nvse_wrapper.h          # Main wrapper header
│   └── include/                # Minimal C++ stdlib stubs for cross-compilation
├── src/
│   ├── lib.rs                  # Main library file
│   └── bindings/               # Auto-generated bindings (gitignored)
│       └── nvse.rs
└── build.rs                    # Build script (runs bindgen)
```

## Updating xNVSE Version

To update to a newer xNVSE version:

```bash
cd libnvse/xnvse
git fetch --tags
git checkout <new-version>  # e.g., 6.4.5
cd ../..
git add libnvse/xnvse
git commit -m "Update xNVSE to version X.Y.Z"
```

## Notes

- Bindings are generated at build time and placed in `src/bindings/nvse.rs`
- The bindings file is gitignored (auto-generated)
- xNVSE source is vendored via git submodule (version controlled)
- No network access required during build (unlike previous download approach)

# Project PSYCHO

Something that started as fun attempt to write F4SE mod which replace Fallout 4 memory allocator with `MiMalloc`.

Rust - is perfect choice for game modding as it can protect developer from large amount of errors. For game modding it's actually critical, because it involves low-level memory manipulation and other hacks which may break game or introduce hard to debug errors.

Why psycho? In Fallout 4 modding we have good tradition to name some core plugin with chem:
- (Buffout 4 NG)[https://google.com]

# Project structure

- `libpsycho` - core hacking library and winapi wrapper
- `libmimalloc` - fork of `mimalloc` crate. It uses more recent c library sources and may contain other changes.
- `libf4se` - in-progress bindings to F4SE. Support ONLY Fallout 4 1.10.163 (old-gen) and small subset of F4SE C API. Also introduce various abstractions to make modding even easier.
- `drifter` - runtime testing utility which is main tool for `libpsycho` testing
- `psycho-fo4` - experimental in-progress plugin for Fallout 4. All project started from here :D

# Cross compilation

I know, it's strange to have supported cross-compilation for game hacking project. But why not? Lots of developers use Linux for coding and gaming, so we will support them!

## Supported targets

- `x86_64-pc-windows-gnu` - Windows cross-compilation with `mingw-w64`. Works fine, `rust-analyzer` support it out of the box. Produce large binaries which may be inacceptable for some cases

- `x86_64-pc-windows-msvc` - Windows cross-compilation with LLVM and `cargo-xwin`. produce small binaries, but not supported by `rust-analyzer`. 

Support for `i686-pc-windows-gnu` and `i686-pc-windows-msvc` planned too, but it's low priority task. While code developed with 32 bit support in mind, it's absolutely not tested.

# Help needed!

I appreciate any help. Development of such project is complex task. I absolute beginner in unsafe Rust and so low level programming, so my approaches may not be the best. Any help is investment in large community of game moders. Let's build something cool!
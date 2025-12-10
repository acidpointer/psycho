# libpsycho

Library which provides basic building blocks for game modding or hacking.  

## Features

- Import address table(aka IAT) hooking
- Virtual method table(aka VMT) hooking
- Inline hooking via JMP instruction and trampoline
- Wrappers for common WinAPI calls (better safety and easier to use)
- `EventEmitter` inspired by Node.Js
- Various utilities for FFI: `FFIRef<T>`, `FnPtr<T>`, etc.
- Bethesda like executable verioning helpers (see `common/exe_version.rs`)
- No unexpected panics! All abstractions propagates result.

## TODO

- Memory patching. Direct patching of memory regions with `NOOP` or other instructions. Should be revertable
- Memory search by pattern. Feature which exists in all mature hacking libraries
- Support for Rust closures as detours instead function pointers. It's much better if hook can accept closure and own it. It's much better type-checking and more possibilities for business logic.

## Why?

World lacks of pure Rust all-in-one game hacking library. 
# libpsycho

This is core library crate for all project.

## Why?

Project "PSYCHO" aims to be not only some plugin for Fallout 4 game, it tries to be complete solution for modding various games.

Main issue which blocks Rust in modding is bad tooling. While we have great language, it lacks of many ready tools to perform
basic modding operations, like hooking and memory patching. That's why "libpsycho" exist.

## Features
1. Safe wrapper for couple of common WinAPI functions and types
2. IAT hook library
3. VMT hook library
4. JMP (trampoline) hook library
5. Utility FFI types and abstractions
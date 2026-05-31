//! Core `psycho_engine_fixes.dll` engine patches.
//!
//! This DLL is loaded early by `psycho-loader` and owns all engine patches.
//! The xNVSE helper is only a late command/event adapter.

// use libmimalloc::MiMalloc;

// #[global_allocator]
// static GLOBAL: MiMalloc = MiMalloc;

mod command_api;
mod config;
mod entry;
mod events;
mod host_events;
mod mods;
mod startup;

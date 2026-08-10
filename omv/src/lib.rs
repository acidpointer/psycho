//! Loader-hosted graphics module.
//!
//! This crate is intentionally separate from `psycho-engine-fixes`: graphics
//! hooks and Direct3D state management should be developed and tested without
//! increasing the blast radius of allocator or engine-fix changes.

mod asset_scanner;
mod backend;
mod compat;
mod config;
mod current_look;
mod effects;
mod file_io;
mod fnv_local_lights;
mod fnv_render;
mod fnv_world_pipeline;
mod graphics_diagnostics;
mod hooks;
mod input;
mod luts;
mod nvse_plugin;
mod plugininfo;
mod presets;
mod render_state;
mod runtime;
mod shaders;
mod startup;

//! Loader-hosted graphics module.
//!
//! This crate is intentionally separate from `psycho-engine-fixes`: graphics
//! hooks and Direct3D state management should be developed and tested without
//! increasing the blast radius of allocator or engine-fix changes.

mod backend;
mod compat;
mod config;
mod effects;
mod fnv_local_lights;
mod fnv_render;
mod fnv_world_pipeline;
mod hooks;
mod input;
mod luts;
mod nvse_plugin;
mod plugininfo;
mod runtime;
mod shaders;
mod startup;

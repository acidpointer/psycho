//! Loader-hosted graphics module.
//!
//! This crate is intentionally separate from `psycho-engine-fixes`: graphics
//! hooks and Direct3D state management should be developed and tested without
//! increasing the blast radius of allocator or engine-fix changes.

mod ambient_occlusion;
mod backend;
mod blooming_hdr;
mod config;
mod entry;
mod fnv_render;
mod hooks;
mod input;
mod runtime;
mod shaders;
mod startup;
mod sunshafts;

//! This is experimental NVSE plugin which brings various patches to game.
//!
//! First of all, this plugin is testing polygon for `libpsycho`, but meantime
//! it tries to be safe and useful for gamers.
//!
//! At the moment, arhitecture of this plugin is unstable and may significantly change.

// use libmimalloc::MiMalloc;

// #[global_allocator]
// static GLOBAL: MiMalloc = MiMalloc;

mod config;
mod entry;
mod mods;
pub(crate) mod nvse_services;
mod plugininfo;

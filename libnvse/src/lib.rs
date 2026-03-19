//! # libnvse -- Safe Rust bindings for xNVSE 6.4.4
//!
//! Provides idiomatic Rust wrappers around the xNVSE plugin API, enabling
//! developers to write full-featured Fallout: New Vegas script extender
//! plugins entirely in Rust.
//!
//! # Quick start
//!
//! A minimal NVSE plugin in Rust:
//!
//! ```no_run
//! use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
//! use libnvse::api::interface::NVSEInterface;
//! use libnvse::api::messaging::NVSEMessageType;
//!
//! // NVSE calls this first -- fill in plugin info and do version checks.
//! #[unsafe(no_mangle)]
//! pub unsafe extern "C" fn NVSEPlugin_Query(
//!     _nvse: *const NVSEInterfaceFFI,
//!     info: *mut PluginInfoFFI,
//! ) -> bool {
//!     let info = unsafe { &mut *info };
//!     info.name = c"my-rust-plugin".as_ptr();
//!     info.version = 1;
//!     true
//! }
//!
//! // NVSE calls this after Query succeeds -- register everything here.
//! #[unsafe(no_mangle)]
//! pub unsafe extern "C" fn NVSEPlugin_Load(
//!     nvse: *const NVSEInterfaceFFI,
//! ) -> bool {
//!     let mut nvse = match NVSEInterface::from_raw(nvse) {
//!         Ok(n) => n,
//!         Err(e) => {
//!             log::error!("Init failed: {}", e);
//!             return false;
//!         }
//!     };
//!
//!     // Register a message listener
//!     nvse.messaging_interface_mut()
//!         .register_listener("NVSE", |msg| {
//!             match msg.get_type() {
//!                 NVSEMessageType::PostLoad => {
//!                     log::info!("All plugins loaded!");
//!                 }
//!                 NVSEMessageType::DeferredInit => {
//!                     log::info!("Game is ready!");
//!                 }
//!                 _ => {}
//!             }
//!         })
//!         .ok();
//!
//!     // Query other interfaces as needed
//!     if let Ok(console) = nvse.query_console() {
//!         console.run("player.additem f 100").ok();
//!     }
//!
//!     true
//! }
//! ```
//!
//! # Target
//!
//! This crate ONLY compiles for `i686-pc-windows-gnu` (32-bit).
//! Fallout: New Vegas is a 32-bit x86 application.
//!
//! ```sh
//! cargo build --target i686-pc-windows-gnu
//! ```

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// Currently we can support only x86/x86_64 architectures
#[cfg(not(target_arch = "x86"))]
compile_error!("Unsupported architecture - only x86/x64 supported");

// Include the auto-generated bindings from a fixed location
// This allows rust-analyzer to find them without needing OUT_DIR
#[allow(clippy::all)]
#[path = "bindings/nvse.rs"]
mod nvse_bindings;

// Re-export bindings at the crate root for easier access
pub(crate) use nvse_bindings::root::*;

pub use nvse_bindings::root::{NVSEInterface as NVSEInterfaceFFI, PluginInfo as PluginInfoFFI};

pub mod api;
pub mod plugin;

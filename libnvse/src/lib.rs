//! NVSE bindings for Rust
//!
//! Very experimental and early stage of development.

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
pub use nvse_bindings::*;

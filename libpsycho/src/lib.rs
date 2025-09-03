//! libpsycho
//! Library with all necessary functionality for plugin development.

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("Unsupported architecture - only x86/x64 supported");

pub mod common;
pub mod ffi;
pub mod hook;
pub mod patch;
pub mod os;
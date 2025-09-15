//! libpsycho
//! Library with all necessary functionality for plugin development.

// Currently we can support only x86/x86_64 architectures
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("Unsupported architecture - only x86/x64 supported");

// Currently Windows is only possible target OS
#[cfg(not(target_os = "windows"))]
compile_error!("Unsupported OS - Windows is only supported target OS for now");

pub mod common;
pub mod ffi;
pub mod hook;
pub mod os;
// TODO: Patch module needs updating to use new winapi paths
// pub mod patch;

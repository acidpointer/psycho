pub mod traits;
pub mod builder;
pub mod examples;

// Re-export core traits and builder
pub use traits::*;
pub use builder::*;

// Hook implementations are platform-specific and live in os modules
// This allows for clean separation of concerns and platform-specific optimizations

#[cfg(target_os = "windows")]
pub use crate::os::windows::hooks::*;

// Future platforms can be added here:
// #[cfg(target_os = "linux")]
// pub use crate::os::linux::hooks::*;
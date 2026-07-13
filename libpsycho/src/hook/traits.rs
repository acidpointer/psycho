use std::fmt::Debug;

use crate::ffi::fnptr::Function;

/// Core trait for all hook types providing common functionality
pub trait Hook<F: Function>: Send + Sync + Debug {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Enable the hook, redirecting calls to the detour function
    fn enable(&self) -> Result<(), Self::Error>;

    /// Disable the hook, restoring original behavior
    fn disable(&self) -> Result<(), Self::Error>;

    /// Check if the hook is currently enabled
    fn is_enabled(&self) -> bool;

    /// Get a descriptive name for this hook (for debugging/logging)
    fn name(&self) -> &str;

    /// Get the original function that was hooked.
    fn original(&self) -> F;
}

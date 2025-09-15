use std::fmt::Debug;

/// Core trait for all hook types providing common functionality
pub trait Hook: Send + Sync + Debug {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Enable the hook, redirecting calls to the detour function
    fn enable(&self) -> Result<(), Self::Error>;

    /// Disable the hook, restoring original behavior
    fn disable(&self) -> Result<(), Self::Error>;

    /// Check if the hook is currently enabled
    fn is_enabled(&self) -> bool;

    /// Get a descriptive name for this hook (for debugging/logging)
    fn name(&self) -> &str;
}

/// Trait for hooks that can provide access to the original function
pub trait OriginAccess<T>: Hook {
    /// Get the original function that was hooked
    ///
    /// # Safety
    /// The caller must ensure that calling this function is safe in the current context
    unsafe fn original(&self) -> T;
}

/// Trait for hooks that intercept function calls with trampolines
pub trait TrampolineHook<T>: Hook + OriginAccess<T> {
    /// Get the trampoline function that calls the original with proper stack setup
    ///
    /// # Safety
    /// The caller must ensure that calling this function is safe in the current context
    unsafe fn trampoline(&self) -> T;
}

/// Trait for hooks that modify import/virtual tables
pub trait TableHook<T>: Hook + OriginAccess<T> {
    /// Get the table entry index that was modified
    fn table_index(&self) -> usize;

    /// Get the table base address
    fn table_base(&self) -> *mut std::ffi::c_void;
}
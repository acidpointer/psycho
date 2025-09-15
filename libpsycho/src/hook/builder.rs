//! Hook builder API for convenient hook creation
//!
//! This module provides a fluent API for creating hooks with sensible defaults
//! and validation.

use std::ffi::c_void;
use crate::hook::traits::*;

/// Hook type selector
#[derive(Debug, Clone, Copy)]
pub enum HookType {
    /// Jump hook with trampoline
    Jump,
    /// Import Address Table hook
    Iat,
    /// Virtual Method Table hook
    Vmt,
}

/// Builder for creating hooks with a fluent API
#[derive(Debug)]
pub struct HookBuilder<F: Copy + 'static> {
    hook_type: HookType,
    name: Option<String>,
    target: Option<F>,
    target_ptr: Option<*mut c_void>,
    detour: Option<F>,

    // IAT-specific fields
    module_base: Option<*mut c_void>,
    library_name: Option<String>,
    function_name: Option<String>,

    // VMT-specific fields
    object_ptr: Option<*mut c_void>,
    method_index: Option<usize>,
}

impl<F: Copy + 'static> HookBuilder<F> {
    /// Create a new hook builder for the specified hook type
    pub fn new(hook_type: HookType) -> Self {
        Self {
            hook_type,
            name: None,
            target: None,
            target_ptr: None,
            detour: None,
            module_base: None,
            library_name: None,
            function_name: None,
            object_ptr: None,
            method_index: None,
        }
    }

    /// Set the hook name (for debugging/logging)
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the target function to hook
    pub fn target(mut self, target: F) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the target function from a raw pointer
    ///
    /// # Safety
    /// The pointer must be a valid function pointer
    pub unsafe fn target_ptr(mut self, target_ptr: *mut c_void) -> Self {
        self.target_ptr = Some(target_ptr);
        self
    }

    /// Set the detour function
    pub fn detour(mut self, detour: F) -> Self {
        self.detour = Some(detour);
        self
    }

    /// Set module base for IAT hooks
    ///
    /// # Safety
    /// The module base must be valid
    pub unsafe fn module_base(mut self, module_base: *mut c_void) -> Self {
        self.module_base = Some(module_base);
        self
    }

    /// Set library name for IAT hooks
    pub fn library_name(mut self, library_name: impl Into<String>) -> Self {
        self.library_name = Some(library_name.into());
        self
    }

    /// Set function name for IAT hooks
    pub fn function_name(mut self, function_name: impl Into<String>) -> Self {
        self.function_name = Some(function_name.into());
        self
    }

    /// Set object pointer for VMT hooks
    ///
    /// # Safety
    /// The object pointer must be valid and have a VMT
    pub unsafe fn object_ptr(mut self, object_ptr: *mut c_void) -> Self {
        self.object_ptr = Some(object_ptr);
        self
    }

    /// Set method index for VMT hooks
    pub fn method_index(mut self, method_index: usize) -> Self {
        self.method_index = Some(method_index);
        self
    }

    /// Build the hook
    ///
    /// # Safety
    /// All provided pointers must be valid and the hook configuration must be correct
    pub unsafe fn build(self) -> Result<Box<dyn Hook<Error = crate::os::windows::hooks::WindowsHookError>>, BuildError> {
        use crate::os::windows::hooks::{JmpHook, IatHook, VmtHook};

        let name = self.name.unwrap_or_else(|| format!("{:?}_hook", self.hook_type));
        let detour = self.detour.ok_or(BuildError::MissingDetour)?;

        match self.hook_type {
            HookType::Jump => {
                if let Some(target) = self.target {
                    Ok(Box::new(JmpHook::new(name, target, detour)?))
                } else if let Some(target_ptr) = self.target_ptr {
                    let detour_ptr = std::ptr::null_mut(); // TODO: Convert detour to pointer
                    Ok(Box::new(unsafe { JmpHook::<F>::from_raw_ptrs(name, target_ptr, detour_ptr)? }))
                } else {
                    Err(BuildError::MissingTarget)
                }
            }

            HookType::Iat => {
                let module_base = self.module_base.ok_or(BuildError::MissingModuleBase)?;
                let library_name = self.library_name.ok_or(BuildError::MissingLibraryName)?;
                let function_name = self.function_name.ok_or(BuildError::MissingFunctionName)?;

                Ok(Box::new(unsafe { IatHook::new(
                    name,
                    module_base,
                    library_name,
                    function_name,
                    detour,
                )? }))
            }

            HookType::Vmt => {
                let object_ptr = self.object_ptr.ok_or(BuildError::MissingObjectPtr)?;
                let method_index = self.method_index.ok_or(BuildError::MissingMethodIndex)?;

                Ok(Box::new(unsafe { VmtHook::new(name, object_ptr, method_index, detour)? }))
            }
        }
    }
}

/// Builder API convenience functions
impl<F: Copy + 'static> HookBuilder<F> {
    /// Create a jump hook builder
    pub fn jump() -> Self {
        Self::new(HookType::Jump)
    }

    /// Create an IAT hook builder
    pub fn iat() -> Self {
        Self::new(HookType::Iat)
    }

    /// Create a VMT hook builder
    pub fn vmt() -> Self {
        Self::new(HookType::Vmt)
    }
}

/// Errors that can occur during hook building
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("Missing target function or target pointer")]
    MissingTarget,

    #[error("Missing detour function")]
    MissingDetour,

    #[error("Missing module base (required for IAT hooks)")]
    MissingModuleBase,

    #[error("Missing library name (required for IAT hooks)")]
    MissingLibraryName,

    #[error("Missing function name (required for IAT hooks)")]
    MissingFunctionName,

    #[error("Missing object pointer (required for VMT hooks)")]
    MissingObjectPtr,

    #[error("Missing method index (required for VMT hooks)")]
    MissingMethodIndex,

    #[error("Windows hook error: {0}")]
    WindowsHookError(#[from] crate::os::windows::hooks::WindowsHookError),
}
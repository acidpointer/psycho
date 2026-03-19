//! Safe wrapper for the NVSE script interface.
//!
//! Allows plugins to compile and execute scripts, call user-defined
//! functions, and interact with the scripting engine.
//!
//! # Usage
//!
//! ```no_run
//! // Compile and run a script expression
//! let compiled = scripts.compile_expression("player.GetAV Health")?;
//!
//! // Call a user-defined function script
//! let result = scripts.call_function(func_script, calling_ref, None)?;
//! ```
//!
//! # Important notes
//!
//! - Scripts compiled at runtime should be cleaned up when no longer needed
//! - Function calls support up to 15 arguments
//! - Float arguments passed via variadic must be bit-cast to void*

use std::ptr::NonNull;

use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

use crate::{
    NVSEArrayVarInterface_Element as ElementFFI, NVSEScriptInterface as NVSEScriptInterfaceFFI,
    Script as ScriptFFI, TESObjectREFR,
};

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("NVSEScriptInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("CompileScript function pointer is NULL")]
    CompileScriptIsNull,

    #[error("CompileExpression function pointer is NULL")]
    CompileExpressionIsNull,

    #[error("CallFunction function pointer is NULL")]
    CallFunctionIsNull,

    #[error("Script compilation failed")]
    CompileFailed,

    #[error("Function call failed")]
    CallFailed,

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type ScriptResult<T> = Result<T, ScriptError>;

/// Handle to a compiled script.
///
/// Scripts created via `compile()` or `compile_expression()` are managed
/// by the game engine. This handle provides safe access to the raw pointer.
#[derive(Debug)]
pub struct CompiledScript {
    ptr: *mut ScriptFFI,
}

impl CompiledScript {
    /// Get the raw Script pointer (for passing to other NVSE interfaces).
    pub fn as_raw(&self) -> *mut ScriptFFI {
        self.ptr
    }

    /// Check if this handle is valid.
    pub fn is_valid(&self) -> bool {
        !self.ptr.is_null()
    }
}

/// Safe wrapper around NVSEScriptInterface.
///
/// Provides script compilation, function calling, and argument extraction.
pub struct Scripts {
    ptr: NonNull<NVSEScriptInterfaceFFI>,
}

impl Scripts {
    /// Create a Scripts wrapper from a raw FFI pointer.
    pub fn from_raw(raw: *mut NVSEScriptInterfaceFFI) -> ScriptResult<Self> {
        let ptr = NonNull::new(raw).ok_or(ScriptError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Compile a script from text.
    ///
    /// The script text should be a complete script block.
    /// Returns a handle to the compiled script, or an error if compilation fails.
    pub fn compile(&self, script_text: &str) -> ScriptResult<CompiledScript> {
        let iface = unsafe { self.ptr.as_ref() };
        let compile_fn = iface
            .CompileScript
            .ok_or(ScriptError::CompileScriptIsNull)?;

        let win_str = WinString::new(script_text)?;
        let ptr = win_str.with_ansi(|text| unsafe { compile_fn(text) });

        if ptr.is_null() {
            Err(ScriptError::CompileFailed)
        } else {
            Ok(CompiledScript { ptr })
        }
    }

    /// Compile a single expression that returns a value.
    ///
    /// Simpler than `compile()` - evaluates a single expression.
    /// Example: `"player.GetAV Health"` or `"1 + 2"`
    pub fn compile_expression(&self, expression: &str) -> ScriptResult<CompiledScript> {
        let iface = unsafe { self.ptr.as_ref() };
        let compile_fn = iface
            .CompileExpression
            .ok_or(ScriptError::CompileExpressionIsNull)?;

        let win_str = WinString::new(expression)?;
        let ptr = win_str.with_ansi(|text| unsafe { compile_fn(text) });

        if ptr.is_null() {
            Err(ScriptError::CompileFailed)
        } else {
            Ok(CompiledScript { ptr })
        }
    }

    /// Call a user-defined function script with no arguments.
    ///
    /// Returns the function's result as a raw Element, or an error if the call fails.
    ///
    /// # Safety contract
    ///
    /// - `func_script` must point to a valid user-defined function Script
    /// - `calling_obj` may be NULL if the function does not require a reference
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn call_function_no_args(
        &self,
        func_script: *mut ScriptFFI,
        calling_obj: *mut TESObjectREFR,
    ) -> ScriptResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let call_fn = iface
            .CallFunctionAlt
            .ok_or(ScriptError::CallFunctionIsNull)?;

        let success = unsafe { call_fn(func_script, calling_obj, 0) };

        if success {
            Ok(())
        } else {
            Err(ScriptError::CallFailed)
        }
    }

    /// Get the raw CallFunction function pointer for variadic calls.
    ///
    /// Since Rust cannot express C variadic calls through a safe API,
    /// this returns the raw function pointer. The caller is responsible
    /// for passing correct argument types matching the function's parameters.
    ///
    /// # Arguments to CallFunction
    ///
    /// - Float args must be bit-cast: `*(u32*)&myFloat`
    /// - Form args are passed as their UInt32 refID
    /// - String args are passed as `*const c_char`
    /// - Maximum 15 arguments
    pub fn raw_call_function_fn(
        &self,
    ) -> ScriptResult<
        unsafe extern "C" fn(
            *mut ScriptFFI,
            *mut TESObjectREFR,
            *mut TESObjectREFR,
            *mut ElementFFI,
            u8,
            ...
        ) -> bool,
    > {
        let iface = unsafe { self.ptr.as_ref() };
        iface.CallFunction.ok_or(ScriptError::CallFunctionIsNull)
    }

    /// Get the number of parameters a function script expects.
    ///
    /// Also fills `param_types_out` with the type of each parameter.
    /// The buffer must be at least 15 bytes (max function params).
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn get_function_params(
        &self,
        func_script: *mut ScriptFFI,
        param_types_out: &mut [u8; 15],
    ) -> Option<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetFunctionParams?;
        Some(unsafe { get_fn(func_script, param_types_out.as_mut_ptr()) })
    }
}

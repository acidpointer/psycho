//! Safe wrapper for the NVSE string variable interface.
//!
//! NVSE extends Fallout's scripting engine with string variables.
//! Strings are represented internally by integer IDs. This interface
//! lets plugins create, read, and modify these string variables.
//!
//! # Usage
//!
//! ```no_run
//! // Get a string value by its variable ID
//! let value = string_vars.get(string_id)?;
//! log::info!("String value: {}", value);
//!
//! // Set a string variable's value
//! string_vars.set(string_id, "new value")?;
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

use crate::NVSEStringVarInterface as NVSEStringVarInterfaceFFI;

#[derive(Debug, Error)]
pub enum StringVarError {
    #[error("NVSEStringVarInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("GetString function pointer is NULL")]
    GetStringIsNull,

    #[error("SetString function pointer is NULL")]
    SetStringIsNull,

    #[error("CreateString function pointer is NULL")]
    CreateStringIsNull,

    #[error("Register function pointer is NULL")]
    RegisterIsNull,

    #[error("Assign function pointer is NULL")]
    AssignIsNull,

    #[error("GetString returned NULL for ID {0}")]
    StringNotFound(u32),

    #[error("String contains invalid UTF-8")]
    InvalidUtf8,

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type StringVarResult<T> = Result<T, StringVarError>;

/// Safe wrapper around NVSEStringVarInterface.
///
/// Provides access to NVSE's string variable system, allowing plugins
/// to create, read, and modify string variables used by the script engine.
pub struct StringVars {
    ptr: NonNull<NVSEStringVarInterfaceFFI>,
}

impl StringVars {
    /// Create a StringVars wrapper from a raw FFI pointer.
    pub fn from_raw(raw: *mut NVSEStringVarInterfaceFFI) -> StringVarResult<Self> {
        let ptr = NonNull::new(raw).ok_or(StringVarError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Get the string value for a given string variable ID.
    ///
    /// Returns the string content, or an error if the ID is invalid.
    pub fn get(&self, string_id: u32) -> StringVarResult<&str> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetString.ok_or(StringVarError::GetStringIsNull)?;

        let ptr = unsafe { get_fn(string_id) };
        if ptr.is_null() {
            return Err(StringVarError::StringNotFound(string_id));
        }

        let cstr = unsafe { CStr::from_ptr(ptr) };
        cstr.to_str().map_err(|_| StringVarError::InvalidUtf8)
    }

    /// Set the value of an existing string variable.
    pub fn set(&self, string_id: u32, value: &str) -> StringVarResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface.SetString.ok_or(StringVarError::SetStringIsNull)?;

        let win_str = WinString::new(value)?;
        win_str.with_ansi(|ptr| unsafe { set_fn(string_id, ptr) });

        Ok(())
    }

    /// Create a new string variable with the given initial value.
    ///
    /// Returns the integer ID of the newly created string variable.
    /// The `owning_script` parameter ties the variable's lifetime to
    /// a script; pass `std::ptr::null_mut()` for persistent strings.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn create(
        &self,
        value: &str,
        owning_script: *mut libc::c_void,
    ) -> StringVarResult<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let create_fn = iface
            .CreateString
            .ok_or(StringVarError::CreateStringIsNull)?;

        let win_str = WinString::new(value)?;
        let id = win_str.with_ansi(|ptr| unsafe { create_fn(ptr, owning_script) });

        Ok(id)
    }

    /// Register this interface for %z format specifier support.
    ///
    /// Call this once during plugin load if your commands use the %z
    /// format specifier to insert string variable contents into strings.
    /// Only needs to be called once per game session.
    pub fn register_format_specifier(&self) -> StringVarResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let register_fn = iface.Register.ok_or(StringVarError::RegisterIsNull)?;
        unsafe { register_fn(self.ptr.as_ptr()) };
        Ok(())
    }

    /// Assign a string as the result of a command execution.
    ///
    /// Call this inside a `Cmd_Execute` handler to return a string value.
    /// The COMMAND_ARGS are forwarded directly from the handler signature.
    ///
    /// # Safety contract
    ///
    /// All pointer parameters must be the exact values received in the
    /// command handler's COMMAND_ARGS. Do not fabricate these.
    #[allow(clippy::too_many_arguments, clippy::not_unsafe_ptr_arg_deref)]
    pub fn assign_string(
        &self,
        param_info: *mut crate::ParamInfo,
        script_data: *mut libc::c_void,
        this_obj: *mut crate::TESObjectREFR,
        containing_obj: *mut crate::TESObjectREFR,
        script_obj: *mut crate::Script,
        event_list: *mut crate::ScriptEventList,
        result: *mut f64,
        opcode_offset: *mut u32,
        value: &str,
    ) -> StringVarResult<bool> {
        let iface = unsafe { self.ptr.as_ref() };
        let assign_fn = iface.Assign.ok_or(StringVarError::AssignIsNull)?;

        let win_str = WinString::new(value)?;
        let success = win_str.with_ansi(|val_ptr| unsafe {
            assign_fn(
                param_info,
                script_data,
                this_obj,
                containing_obj,
                script_obj,
                event_list,
                result,
                opcode_offset,
                val_ptr,
            )
        });

        Ok(success)
    }

    /// Get a raw pointer to the underlying FFI interface.
    pub fn as_raw_ptr(&self) -> *mut NVSEStringVarInterfaceFFI {
        self.ptr.as_ptr()
    }
}

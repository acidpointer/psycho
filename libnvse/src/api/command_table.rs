//! Safe wrapper for the NVSE command table interface.
//!
//! Provides read-only access to xNVSE's internal command registry,
//! allowing plugins to look up command metadata, check return types,
//! and discover commands from other plugins.
//!
//! # Usage
//!
//! ```no_run
//! // Look up a command by name
//! if let Some(cmd) = cmd_table.get_by_name("player.additem") {
//!     log::info!("Found command: opcode={:#X}", cmd.opcode());
//! }
//!
//! // Check which plugin registered a command
//! if let Some(info) = cmd_table.get_plugin_info("MyPlugin") {
//!     log::info!("Plugin version: {}", info.version());
//! }
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

use crate::{
    CommandInfo as CommandInfoFFI, NVSECommandTableInterface as NVSECommandTableInterfaceFFI,
    PluginInfo as PluginInfoFFI,
};

#[derive(Debug, Error)]
pub enum CommandTableError {
    #[error("NVSECommandTableInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type CommandTableResult<T> = Result<T, CommandTableError>;

/// Read-only view of a registered command.
#[derive(Debug)]
pub struct CommandRef {
    ptr: *const CommandInfoFFI,
}

impl CommandRef {
    fn new(ptr: *const CommandInfoFFI) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Get the command's opcode.
    pub fn opcode(&self) -> u32 {
        unsafe { (*self.ptr).opcode }
    }

    /// Get the command's long name.
    pub fn name(&self) -> Option<&str> {
        let name_ptr = unsafe { (*self.ptr).longName };
        if name_ptr.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(name_ptr) }.to_str().ok()
    }

    /// Get the command's short name (alias).
    pub fn short_name(&self) -> Option<&str> {
        let name_ptr = unsafe { (*self.ptr).shortName };
        if name_ptr.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(name_ptr) }.to_str().ok()
    }

    /// Get the command's help text.
    pub fn help_text(&self) -> Option<&str> {
        let help_ptr = unsafe { (*self.ptr).helpText };
        if help_ptr.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(help_ptr) }.to_str().ok()
    }

    /// Get the number of parameters this command accepts.
    pub fn num_params(&self) -> u16 {
        unsafe { (*self.ptr).numParams }
    }

    /// Whether this command requires a calling reference.
    pub fn needs_parent(&self) -> bool {
        unsafe { (*self.ptr).needsParent != 0 }
    }

    /// Get the raw CommandInfo pointer (for advanced use).
    pub fn as_raw(&self) -> *const CommandInfoFFI {
        self.ptr
    }
}

/// Read-only view of a plugin's info.
#[derive(Debug)]
pub struct PluginInfoRef {
    ptr: *const PluginInfoFFI,
}

impl PluginInfoRef {
    fn new(ptr: *const PluginInfoFFI) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Get the plugin's name.
    pub fn name(&self) -> Option<&str> {
        let name_ptr = unsafe { (*self.ptr).name };
        if name_ptr.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(name_ptr) }.to_str().ok()
    }

    /// Get the plugin's version number.
    pub fn version(&self) -> u32 {
        unsafe { (*self.ptr).version }
    }
}

/// Safe wrapper around NVSECommandTableInterface.
///
/// Provides read-only access to xNVSE's internal command table for
/// looking up registered commands and plugin information.
pub struct CommandTable {
    ptr: NonNull<NVSECommandTableInterfaceFFI>,
}

impl CommandTable {
    /// Create a CommandTable wrapper from a raw FFI pointer.
    pub fn from_raw(raw: *mut NVSECommandTableInterfaceFFI) -> CommandTableResult<Self> {
        let ptr = NonNull::new(raw).ok_or(CommandTableError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Look up a command by its opcode.
    pub fn get_by_opcode(&self, opcode: u32) -> Option<CommandRef> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetByOpcode?;
        CommandRef::new(unsafe { get_fn(opcode) })
    }

    /// Look up a command by its name.
    pub fn get_by_name(&self, name: &str) -> Option<CommandRef> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetByName?;
        let win_str = WinString::new(name).ok()?;
        let result = win_str.with_ansi(|ptr| unsafe { get_fn(ptr) });
        CommandRef::new(result)
    }

    /// Get the return type of a command (0=numeric, 1=form, 2=string, 3=array).
    pub fn get_return_type(&self, cmd: &CommandRef) -> Option<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetReturnType?;
        Some(unsafe { get_fn(cmd.ptr) })
    }

    /// Get the minimum xNVSE version required by a command.
    ///
    /// Returns 0 for vanilla commands, u32::MAX for plugin commands.
    pub fn get_required_nvse_version(&self, cmd: &CommandRef) -> Option<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetRequiredNVSEVersion?;
        Some(unsafe { get_fn(cmd.ptr) })
    }

    /// Get the plugin that registered a command.
    pub fn get_parent_plugin(&self, cmd: &CommandRef) -> Option<PluginInfoRef> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetParentPlugin?;
        PluginInfoRef::new(unsafe { get_fn(cmd.ptr) })
    }

    /// Look up a plugin's info by plugin name.
    pub fn get_plugin_info(&self, plugin_name: &str) -> Option<PluginInfoRef> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetPluginInfoByName?;
        let win_str = WinString::new(plugin_name).ok()?;
        let result = win_str.with_ansi(|ptr| unsafe { get_fn(ptr) });
        PluginInfoRef::new(result)
    }

    /// Look up a plugin's info by DLL filename.
    pub fn get_plugin_info_by_dll(&self, dll_name: &str) -> Option<PluginInfoRef> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetPluginInfoByDLLName?;
        let win_str = WinString::new(dll_name).ok()?;
        let result = win_str.with_ansi(|ptr| unsafe { get_fn(ptr) });
        PluginInfoRef::new(result)
    }
}

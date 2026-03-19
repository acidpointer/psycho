//! Core NVSE interface wrapper.
//!
//! `NVSEInterface` is the main entry point for all NVSE plugin APIs.
//! It wraps the raw `NVSEInterface*` pointer received in `NVSEPlugin_Load`
//! and provides safe access to all sub-interfaces.
//!
//! # Lifecycle
//!
//! 1. NVSE calls your `NVSEPlugin_Load(nvse: *const NVSEInterface)` export
//! 2. Create a safe wrapper: `let nvse = NVSEInterface::from_raw(nvse_ptr)?;`
//! 3. Query sub-interfaces as needed: `nvse.query_console()?`, etc.
//! 4. Register commands, listeners, and callbacks
//!
//! # Example
//!
//! ```no_run
//! use libnvse::api::interface::NVSEInterface;
//!
//! unsafe extern "C" fn plugin_load(nvse_ptr: *const NVSEInterfaceFFI) -> bool {
//!     let mut nvse = match NVSEInterface::from_raw(nvse_ptr) {
//!         Ok(n) => n,
//!         Err(e) => {
//!             log::error!("Failed to init NVSE: {}", e);
//!             return false;
//!         }
//!     };
//!
//!     // Get the messaging interface (eagerly loaded)
//!     nvse.messaging_interface_mut().register_listener("NVSE", |msg| {
//!         log::info!("Got message: {}", msg.get_type());
//!     }).ok();
//!
//!     // Query other interfaces on demand
//!     if let Ok(console) = nvse.query_console() {
//!         console.run("player.additem f 100").ok();
//!     }
//!
//!     true
//! }
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use crate::api::messaging::{NVSEMessagingInterface, NVSEMessagingInterfaceError};
use crate::{
    NVSEArrayVarInterface as NVSEArrayVarInterfaceFFI,
    NVSECommandTableInterface as NVSECommandTableInterfaceFFI,
    NVSEConsoleInterface as NVSEConsoleInterfaceFFI,
    NVSEDataInterface as NVSEDataInterfaceFFI,
    NVSEEventManagerInterface as NVSEEventManagerInterfaceFFI,
    NVSEInterface as NVSEInterfaceFFI,
    NVSELoggingInterface as NVSELoggingInterfaceFFI,
    NVSEMessagingInterface as NVSEMessagingInterfaceFFI,
    NVSEScriptInterface as NVSEScriptInterfaceFFI,
    NVSESerializationInterface as NVSESerializationInterfaceFFI,
    NVSEStringVarInterface as NVSEStringVarInterfaceFFI,
    NVSETogglePlayerControlsInterface as NVSETogglePlayerControlsInterfaceFFI,
    kInterface_ArrayVar, kInterface_CommandTable, kInterface_Console, kInterface_Data,
    kInterface_EventManager, kInterface_Logging, kInterface_Messaging, kInterface_PlayerControls,
    kInterface_Script, kInterface_Serialization, kInterface_StringVar,
};
use crate::api::array_var::{ArrayVarError, ArrayVars};
use crate::api::command::{CommandBuilder, CommandError};
use crate::api::command_table::{CommandTable, CommandTableError};
use crate::api::console::{Console, ConsoleError};
use crate::api::data::{Data, DataError};
use crate::api::event_manager::{EventManager, EventManagerError};
use crate::api::logging::{Logging, LoggingError};
use crate::api::player_controls::{PlayerControls, PlayerControlsError};
use crate::api::script::{ScriptError, Scripts};
use crate::api::serialization::{Serialization, SerializationError};
use crate::api::string_var::{StringVarError, StringVars};

use libpsycho::common::exe_version::ExeVersion;
use thiserror::Error;

// -- Errors -----------------------------------------------------------------

#[derive(Debug, Error)]
pub enum NVSEInterfaceError {
    #[error("Interface pointer is NULL")]
    InterfaceIsNull,

    #[error("GetPluginHandle() from NVSEInterface is NULL")]
    GetPluginHandleIsNull,

    #[error("QueryInterface() from NVSEInterface is NULL")]
    QueryInterfaceIsNull,

    #[error("QueryInterface() from NVSEInterface returned NULL")]
    QueryResultIsNull,

    #[error("GetRuntimeDirectory() returned NULL")]
    RuntimeDirectoryIsNull,

    #[error("NVSEMessagingInterface error: {0}")]
    NVSEMessagingInterfaceError(#[from] NVSEMessagingInterfaceError),

    #[error("Console interface error: {0}")]
    ConsoleError(#[from] ConsoleError),

    #[error("Logging interface error: {0}")]
    LoggingError(#[from] LoggingError),

    #[error("Command error: {0}")]
    CommandError(#[from] CommandError),

    #[error("StringVar interface error: {0}")]
    StringVarError(#[from] StringVarError),

    #[error("Serialization interface error: {0}")]
    SerializationError(#[from] SerializationError),

    #[error("CommandTable interface error: {0}")]
    CommandTableError(#[from] CommandTableError),

    #[error("PlayerControls interface error: {0}")]
    PlayerControlsError(#[from] PlayerControlsError),

    #[error("ArrayVar interface error: {0}")]
    ArrayVarError(#[from] ArrayVarError),

    #[error("Script interface error: {0}")]
    ScriptError(#[from] ScriptError),

    #[error("EventManager interface error: {0}")]
    EventManagerError(#[from] EventManagerError),

    #[error("Data interface error: {0}")]
    DataError(#[from] DataError),
}

pub type NVSEInterfaceResult<T> = std::result::Result<T, NVSEInterfaceError>;

// -- Plugin handle ----------------------------------------------------------

/// Unique handle identifying this plugin to NVSE.
///
/// Obtained during plugin load and used when registering callbacks,
/// dispatching messages, and other operations that need plugin identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NVSEPluginHandle {
    handle: u32,
}

impl NVSEPluginHandle {
    /// Get the raw u32 handle value.
    pub fn get_handle(&self) -> u32 {
        self.handle
    }
}

// -- Internal helpers -------------------------------------------------------

fn get_plugin_handle(
    nvse_ptr: NonNull<NVSEInterfaceFFI>,
) -> NVSEInterfaceResult<NVSEPluginHandle> {
    let nvse = unsafe { nvse_ptr.as_ref() };
    let get_plugin_handle = nvse
        .GetPluginHandle
        .ok_or(NVSEInterfaceError::GetPluginHandleIsNull)?;

    let plugin_handle_val = unsafe { get_plugin_handle() };

    Ok(NVSEPluginHandle {
        handle: plugin_handle_val,
    })
}

/// Generic interface query - returns a typed raw pointer.
fn query_interface<T>(
    nvse_ptr: NonNull<NVSEInterfaceFFI>,
    interface_id: u32,
) -> NVSEInterfaceResult<*mut T> {
    let nvse_ref = unsafe { nvse_ptr.as_ref() };

    let query_interface_fn = nvse_ref
        .QueryInterface
        .ok_or(NVSEInterfaceError::QueryInterfaceIsNull)?;

    let result = unsafe { query_interface_fn(interface_id) } as *mut T;

    if result.is_null() {
        return Err(NVSEInterfaceError::QueryResultIsNull);
    }

    Ok(result)
}

fn query_messaging_interface<'a>(
    plugin_handle: NVSEPluginHandle,
    nvse_ptr: NonNull<NVSEInterfaceFFI>,
) -> NVSEInterfaceResult<NVSEMessagingInterface<'a>> {
    let raw_ptr =
        query_interface::<NVSEMessagingInterfaceFFI>(nvse_ptr, kInterface_Messaging as u32)?;

    let msg_interface = NVSEMessagingInterface::from_raw(raw_ptr, plugin_handle)?;

    Ok(msg_interface)
}

// -- Main interface ---------------------------------------------------------

/// Safe wrapper around the root NVSEInterface.
///
/// This is the primary entry point for NVSE plugin development.
/// Created from the raw pointer received in `NVSEPlugin_Load`, it provides:
///
/// - Version information (NVSE, runtime, editor)
/// - Plugin handle for identification
/// - Messaging interface (eagerly loaded)
/// - Query methods for all other sub-interfaces (loaded on demand)
///
/// # Sub-interfaces
///
/// | Method | Interface | Purpose |
/// |--------|-----------|---------|
/// | `messaging_interface_*()` | Messaging | Plugin-to-plugin communication |
/// | `query_console()` | Console | Execute console commands |
/// | `query_logging()` | Logging | Get plugin log directory path |
/// | `query_command_table()` | CommandTable | Look up registered commands |
/// | `query_string_vars()` | StringVar | Read/write NVSE string variables |
/// | `query_array_vars()` | ArrayVar | Create/manipulate NVSE arrays |
/// | `query_scripts()` | Script | Compile/call scripts |
/// | `query_serialization()` | Serialization | Persist data with game saves |
/// | `query_event_manager()` | EventManager | Register/dispatch events |
/// | `query_data()` | Data | Access NVSE internals |
/// | `query_player_controls()` | PlayerControls | Toggle player input |
/// | `command_builder()` | Commands | Register custom script commands |
pub struct NVSEInterface<'a> {
    nvse_version: ExeVersion,
    runtime_version: ExeVersion,
    editor_version: Option<ExeVersion>,
    is_editor: bool,
    nvse_ptr: NonNull<NVSEInterfaceFFI>,

    msg_interface: NVSEMessagingInterface<'a>,
    plugin_handle: NVSEPluginHandle,
}

impl<'a> NVSEInterface<'a> {
    /// Create a safe NVSEInterface from the raw pointer received in NVSEPlugin_Load.
    ///
    /// This validates the pointer, obtains the plugin handle, and eagerly
    /// initializes the messaging interface (since nearly all plugins need it).
    ///
    /// Returns an error if the pointer is NULL or essential function pointers
    /// are missing.
    pub fn from_raw(nvse_ptr: *const NVSEInterfaceFFI) -> NVSEInterfaceResult<Self> {
        let nvse_ptr = NonNull::new(nvse_ptr as *mut NVSEInterfaceFFI)
            .ok_or(NVSEInterfaceError::InterfaceIsNull)?;

        let plugin_handle = get_plugin_handle(nvse_ptr)?;

        let msg_interface = query_messaging_interface(plugin_handle, nvse_ptr)?;

        let nvse_ref = unsafe { nvse_ptr.as_ref() };

        Ok(Self {
            nvse_version: ExeVersion::from_u32(nvse_ref.nvseVersion),
            runtime_version: ExeVersion::from_u32(nvse_ref.runtimeVersion),
            is_editor: nvse_ref.isEditor != 0,
            editor_version: if nvse_ref.isEditor != 0 {
                Some(ExeVersion::from_u32(nvse_ref.editorVersion))
            } else {
                None
            },
            nvse_ptr,
            plugin_handle,
            msg_interface,
        })
    }

    // -- Version info -------------------------------------------------------

    /// Get the xNVSE version.
    pub fn nvse_version(&self) -> ExeVersion {
        self.nvse_version
    }

    /// Get the Fallout New Vegas runtime version.
    pub fn runtime_version(&self) -> ExeVersion {
        self.runtime_version
    }

    /// Get the GECK editor version (None if running in-game).
    pub fn editor_version(&self) -> Option<ExeVersion> {
        self.editor_version
    }

    /// Check if running inside the GECK editor.
    pub fn is_editor(&self) -> bool {
        self.is_editor
    }

    /// Check if this is the "no gore" version of the game.
    pub fn is_nogore(&self) -> bool {
        let nvse = unsafe { self.nvse_ptr.as_ref() };
        nvse.isNogore != 0
    }

    /// Get the game's runtime directory (e.g. "C:\Games\Fallout New Vegas\").
    pub fn runtime_directory(&self) -> NVSEInterfaceResult<&str> {
        let nvse = unsafe { self.nvse_ptr.as_ref() };
        let get_dir = nvse
            .GetRuntimeDirectory
            .ok_or(NVSEInterfaceError::RuntimeDirectoryIsNull)?;

        let ptr = unsafe { get_dir() };
        if ptr.is_null() {
            return Err(NVSEInterfaceError::RuntimeDirectoryIsNull);
        }

        let cstr = unsafe { CStr::from_ptr(ptr) };
        Ok(cstr.to_str().unwrap_or(""))
    }

    // -- Plugin handle ------------------------------------------------------

    /// Get this plugin's handle (used for registering callbacks, dispatching, etc.).
    pub fn get_plugin_handle(&self) -> NVSEPluginHandle {
        self.plugin_handle
    }

    /// Get the raw NVSEInterface pointer (for advanced/interop use).
    pub fn as_raw_ptr(&self) -> *const NVSEInterfaceFFI {
        self.nvse_ptr.as_ptr()
    }

    // -- Messaging (eagerly loaded) -----------------------------------------

    /// Get a shared reference to the messaging interface.
    pub fn messaging_interface_ref(&self) -> &NVSEMessagingInterface<'a> {
        &self.msg_interface
    }

    /// Get a mutable reference to the messaging interface.
    ///
    /// Needed for registering listeners (which mutates internal state).
    pub fn messaging_interface_mut(&mut self) -> &mut NVSEMessagingInterface<'a> {
        &mut self.msg_interface
    }

    // -- On-demand interface queries ----------------------------------------

    /// Query the console interface for executing console commands.
    pub fn query_console(&self) -> NVSEInterfaceResult<Console> {
        let raw =
            query_interface::<NVSEConsoleInterfaceFFI>(self.nvse_ptr, kInterface_Console as u32)?;
        Ok(Console::from_raw(raw)?)
    }

    /// Query the logging interface for plugin log file paths.
    pub fn query_logging(&self) -> NVSEInterfaceResult<Logging> {
        let raw =
            query_interface::<NVSELoggingInterfaceFFI>(self.nvse_ptr, kInterface_Logging as u32)?;
        Ok(Logging::from_raw(raw)?)
    }

    /// Query the command table interface for looking up registered commands.
    pub fn query_command_table(&self) -> NVSEInterfaceResult<CommandTable> {
        let raw = query_interface::<NVSECommandTableInterfaceFFI>(
            self.nvse_ptr,
            kInterface_CommandTable as u32,
        )?;
        Ok(CommandTable::from_raw(raw)?)
    }

    /// Query the string variable interface for NVSE string operations.
    pub fn query_string_vars(&self) -> NVSEInterfaceResult<StringVars> {
        let raw = query_interface::<NVSEStringVarInterfaceFFI>(
            self.nvse_ptr,
            kInterface_StringVar as u32,
        )?;
        Ok(StringVars::from_raw(raw)?)
    }

    /// Query the array variable interface for NVSE array operations.
    pub fn query_array_vars(&self) -> NVSEInterfaceResult<ArrayVars> {
        let raw = query_interface::<NVSEArrayVarInterfaceFFI>(
            self.nvse_ptr,
            kInterface_ArrayVar as u32,
        )?;
        Ok(ArrayVars::from_raw(raw)?)
    }

    /// Query the script interface for compiling and calling scripts.
    pub fn query_scripts(&self) -> NVSEInterfaceResult<Scripts> {
        let raw =
            query_interface::<NVSEScriptInterfaceFFI>(self.nvse_ptr, kInterface_Script as u32)?;
        Ok(Scripts::from_raw(raw)?)
    }

    /// Query the serialization interface for co-save operations.
    pub fn query_serialization(&self) -> NVSEInterfaceResult<Serialization<'a>> {
        let raw = query_interface::<NVSESerializationInterfaceFFI>(
            self.nvse_ptr,
            kInterface_Serialization as u32,
        )?;
        Ok(Serialization::from_raw(raw)?)
    }

    /// Query the event manager interface for event registration and dispatch.
    pub fn query_event_manager(&self) -> NVSEInterfaceResult<EventManager> {
        let raw = query_interface::<NVSEEventManagerInterfaceFFI>(
            self.nvse_ptr,
            kInterface_EventManager as u32,
        )?;
        Ok(EventManager::from_raw(raw)?)
    }

    /// Query the data interface for NVSE internals access.
    pub fn query_data(&self) -> NVSEInterfaceResult<Data> {
        let raw =
            query_interface::<NVSEDataInterfaceFFI>(self.nvse_ptr, kInterface_Data as u32)?;
        Ok(Data::from_raw(raw)?)
    }

    /// Query the player controls interface.
    ///
    /// `mod_name` is a static string identifying your mod for per-mod
    /// control tracking. Must remain valid for the entire game session.
    pub fn query_player_controls(
        &self,
        mod_name: &'static CStr,
    ) -> NVSEInterfaceResult<PlayerControls> {
        let raw = query_interface::<NVSETogglePlayerControlsInterfaceFFI>(
            self.nvse_ptr,
            kInterface_PlayerControls as u32,
        )?;
        Ok(PlayerControls::from_raw(raw, mod_name)?)
    }

    /// Create a command builder for registering custom script commands.
    ///
    /// Use this to register new console/script commands during plugin load.
    pub fn command_builder(&self) -> NVSEInterfaceResult<CommandBuilder> {
        Ok(CommandBuilder::from_raw(self.nvse_ptr.as_ptr())?)
    }
}

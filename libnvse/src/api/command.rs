//! Command registration API for NVSE plugins.
//!
//! Provides safe builders for registering new script commands that can be
//! called from the game's scripting engine (GECK scripts or console).
//!
//! # Overview
//!
//! NVSE plugins can register custom commands (opcodes) that scripts can call.
//! Each command has:
//! - A name (and optional short alias)
//! - Help text describing what it does
//! - Parameter definitions (what arguments it accepts)
//! - An execute handler (the Rust function that runs when the command is called)
//! - A return type (number, string, array, or form)
//!
//! # Usage
//!
//! ```no_run
//! use libnvse::api::command::{CommandBuilder, ParamType, ReturnType};
//!
//! // Register a simple command with no parameters
//! let mut builder = CommandBuilder::new(&nvse_interface);
//! builder.set_opcode_base(0x3000)?;
//!
//! builder.register("MyCommand", "mc", "Does something cool", false,
//!     my_command_execute)?;
//!
//! // Register a typed command that returns a string
//! builder.register_typed("MyStringCmd", "", "Returns a string",
//!     false, my_string_execute, ReturnType::String)?;
//! ```
//!
//! # Opcode allocation
//!
//! Each plugin gets a unique opcode range assigned by the xNVSE team.
//! Call `set_opcode_base()` before registering any commands.
//! Opcodes are auto-incremented for each registered command.

use std::ffi::CStr;
use std::ptr::NonNull;

use thiserror::Error;

use crate::{
    CommandInfo as CommandInfoFFI, CommandReturnType, Cmd_Execute,
    NVSEInterface as NVSEInterfaceFFI, ParamInfo as ParamInfoFFI,
};

// -- Parameter types --------------------------------------------------------

/// Script command parameter types.
///
/// These correspond to the kParamType_* constants in CommandTable.h.
/// Each variant describes the type of argument a script command expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ParamType {
    String = 0,
    Integer = 1,
    Float = 2,
    ObjectID = 3,
    ObjectRef = 4,
    ActorValue = 5,
    Actor = 6,
    SpellItem = 7,
    Axis = 8,
    Cell = 9,
    AnimationGroup = 10,
    MagicItem = 11,
    Sound = 12,
    Topic = 13,
    Quest = 14,
    Race = 15,
    Class = 16,
    Faction = 17,
    Sex = 18,
    Global = 19,
    Furniture = 20,
    TESObject = 21,
    VariableName = 22,
    QuestStage = 23,
    MapMarker = 24,
    ActorBase = 25,
    Container = 26,
    WorldSpace = 27,
    CrimeType = 28,
    AcousticSpace = 29,
    Package = 30,
    CombatStyle = 31,
    MagicEffect = 32,
    FormType = 33,
    WeatherID = 34,
    NPC = 35,
    Owner = 36,
    EffectShader = 37,
    FormList = 38,
    MenuIcon = 39,
    Perk = 40,
    Note = 41,
    MiscStat = 42,
    ImageSpaceModifier = 43,
    ImageSpace = 44,
    Double = 45,
    Unassigned = 46,
    ObjectType = 47,
    EncounterZone = 48,
    IdleForm = 49,
    Message = 50,
    InvObjOrFormList = 51,
    Alignment = 52,
    EquipType = 53,
    NonFormList = 54,
    SoundFile = 55,
    CriticalStage = 56,
    LeveledOrBaseChar = 57,
    LeveledOrBaseCreature = 58,
    LeveledChar = 59,
    LeveledCreature = 60,
    LeveledItem = 61,
    Reputation = 62,
    Casino = 63,
    CasinoChip = 64,
    Challenge = 65,
    CaravanMoney = 66,
    CaravanCard = 67,
    CaravanDeck = 68,
    Region = 69,
    AnyForm = 70,
    // NVSE extensions
    StringVar = 71,
    Array = 72,
}

impl ParamType {
    /// Get the display name for this parameter type (used in help text).
    pub fn type_str(&self) -> &'static CStr {
        match self {
            Self::String => c"String",
            Self::Integer => c"Integer",
            Self::Float => c"Float",
            Self::ObjectID => c"ObjectID",
            Self::ObjectRef => c"ObjectRef",
            Self::ActorValue => c"ActorValue",
            Self::Actor => c"Actor",
            Self::Quest => c"Quest",
            Self::AnyForm => c"AnyForm",
            Self::StringVar => c"StringVar",
            Self::Array => c"Array",
            _ => c"Unknown",
        }
    }
}

/// Command return type for typed command registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReturnType {
    Default = 0,
    Form = 1,
    String = 2,
    Array = 3,
    ArrayIndex = 4,
    Ambiguous = 5,
}

// -- Parameter definition ---------------------------------------------------

/// A single parameter definition for a command.
///
/// Use `Param::required()` or `Param::optional()` to create instances,
/// then collect them into a slice for command registration.
#[derive(Debug, Clone)]
pub struct Param {
    type_str: &'static CStr,
    type_id: ParamType,
    optional: bool,
}

impl Param {
    /// Create a required parameter.
    pub fn required(param_type: ParamType) -> Self {
        Self {
            type_str: param_type.type_str(),
            type_id: param_type,
            optional: false,
        }
    }

    /// Create an optional parameter.
    pub fn optional(param_type: ParamType) -> Self {
        Self {
            type_str: param_type.type_str(),
            type_id: param_type,
            optional: true,
        }
    }
}

// -- Errors -----------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("NVSEInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("RegisterCommand function pointer is NULL")]
    RegisterCommandIsNull,

    #[error("RegisterTypedCommand function pointer is NULL")]
    RegisterTypedCommandIsNull,

    #[error("SetOpcodeBase function pointer is NULL")]
    SetOpcodeBaseIsNull,

    #[error("Command registration failed for: {0}")]
    RegistrationFailed(String),

    #[error("Too many parameters (max 16): {0}")]
    TooManyParams(usize),

    #[error("Command name must not be empty")]
    EmptyName,
}

pub type CommandResult<T> = Result<T, CommandError>;

// -- Builder ----------------------------------------------------------------

/// Maximum number of parameters per command (xNVSE limitation).
const MAX_PARAMS: usize = 16;

/// Builder for registering NVSE script commands.
///
/// Holds a reference to the NVSEInterface and provides methods to
/// set the opcode base and register commands.
pub struct CommandBuilder {
    nvse_ptr: NonNull<NVSEInterfaceFFI>,
    /// Heap-allocated ParamInfo arrays that must outlive the game session.
    /// NVSE keeps raw pointers to these, so they must never be freed.
    _param_storage: Vec<Box<[ParamInfoFFI]>>,
    /// Heap-allocated C string pairs (longName, shortName, helpText) that
    /// must outlive the game session.
    _string_storage: Vec<Box<CStr>>,
}

impl CommandBuilder {
    /// Create a new CommandBuilder from a raw NVSEInterface pointer.
    pub fn from_raw(nvse_ptr: *const NVSEInterfaceFFI) -> CommandResult<Self> {
        let nvse_ptr = NonNull::new(nvse_ptr as *mut NVSEInterfaceFFI)
            .ok_or(CommandError::InterfaceIsNull)?;
        Ok(Self {
            nvse_ptr,
            _param_storage: Vec::new(),
            _string_storage: Vec::new(),
        })
    }

    /// Set the opcode base for subsequent command registrations.
    ///
    /// Must be called before registering any commands.
    /// The base must be your assigned opcode range from the xNVSE team.
    pub fn set_opcode_base(&self, opcode: u32) -> CommandResult<()> {
        let nvse = unsafe { self.nvse_ptr.as_ref() };
        let set_base = nvse
            .SetOpcodeBase
            .ok_or(CommandError::SetOpcodeBaseIsNull)?;
        unsafe { set_base(opcode) };
        Ok(())
    }

    /// Register a command with default return type (numeric).
    ///
    /// # Arguments
    /// - `name` - Command name (used in scripts, e.g. "MyCommand")
    /// - `short_name` - Short alias (e.g. "mc"), pass "" for none
    /// - `help` - Help text shown in console
    /// - `needs_ref` - Whether command requires a reference (called on an object)
    /// - `params` - Slice of parameter definitions
    /// - `execute` - The command handler function pointer
    pub fn register(
        &mut self,
        name: &str,
        short_name: &str,
        help: &str,
        needs_ref: bool,
        params: &[Param],
        execute: Cmd_Execute,
    ) -> CommandResult<()> {
        if name.is_empty() {
            return Err(CommandError::EmptyName);
        }
        if params.len() > MAX_PARAMS {
            return Err(CommandError::TooManyParams(params.len()));
        }

        let nvse = unsafe { self.nvse_ptr.as_ref() };
        let register_fn = nvse
            .RegisterCommand
            .ok_or(CommandError::RegisterCommandIsNull)?;

        let mut cmd = self.build_command_info(name, short_name, help, needs_ref, params, execute)?;

        let success = unsafe { register_fn(&mut cmd) };
        if !success {
            return Err(CommandError::RegistrationFailed(name.to_string()));
        }

        Ok(())
    }

    /// Register a typed command (returns String, Array, Form, etc.).
    ///
    /// Same as `register()` but specifies the return type for the script engine.
    #[allow(clippy::too_many_arguments)]
    pub fn register_typed(
        &mut self,
        name: &str,
        short_name: &str,
        help: &str,
        needs_ref: bool,
        params: &[Param],
        execute: Cmd_Execute,
        return_type: ReturnType,
    ) -> CommandResult<()> {
        if name.is_empty() {
            return Err(CommandError::EmptyName);
        }
        if params.len() > MAX_PARAMS {
            return Err(CommandError::TooManyParams(params.len()));
        }

        let nvse = unsafe { self.nvse_ptr.as_ref() };
        let register_fn = nvse
            .RegisterTypedCommand
            .ok_or(CommandError::RegisterTypedCommandIsNull)?;

        let mut cmd = self.build_command_info(name, short_name, help, needs_ref, params, execute)?;

        let ffi_return_type = match return_type {
            ReturnType::Default => CommandReturnType::kRetnType_Default,
            ReturnType::Form => CommandReturnType::kRetnType_Form,
            ReturnType::String => CommandReturnType::kRetnType_String,
            ReturnType::Array => CommandReturnType::kRetnType_Array,
            ReturnType::ArrayIndex => CommandReturnType::kRetnType_ArrayIndex,
            ReturnType::Ambiguous => CommandReturnType::kRetnType_Ambiguous,
        };
        let success = unsafe { register_fn(&mut cmd, ffi_return_type) };
        if !success {
            return Err(CommandError::RegistrationFailed(name.to_string()));
        }

        Ok(())
    }

    /// Register a typed command with a minimum required plugin version.
    ///
    /// Same as `register_typed()` but additionally specifies the minimum
    /// NVSE version needed to use this command.
    #[allow(clippy::too_many_arguments)]
    pub fn register_typed_version(
        &mut self,
        name: &str,
        short_name: &str,
        help: &str,
        needs_ref: bool,
        params: &[Param],
        execute: Cmd_Execute,
        return_type: ReturnType,
        required_version: u32,
    ) -> CommandResult<()> {
        if name.is_empty() {
            return Err(CommandError::EmptyName);
        }
        if params.len() > MAX_PARAMS {
            return Err(CommandError::TooManyParams(params.len()));
        }

        let nvse = unsafe { self.nvse_ptr.as_ref() };
        let register_fn = nvse
            .RegisterTypedCommandVersion
            .ok_or(CommandError::RegisterTypedCommandIsNull)?;

        let mut cmd =
            self.build_command_info(name, short_name, help, needs_ref, params, execute)?;

        let ffi_return_type = match return_type {
            ReturnType::Default => CommandReturnType::kRetnType_Default,
            ReturnType::Form => CommandReturnType::kRetnType_Form,
            ReturnType::String => CommandReturnType::kRetnType_String,
            ReturnType::Array => CommandReturnType::kRetnType_Array,
            ReturnType::ArrayIndex => CommandReturnType::kRetnType_ArrayIndex,
            ReturnType::Ambiguous => CommandReturnType::kRetnType_Ambiguous,
        };
        let success = unsafe { register_fn(&mut cmd, ffi_return_type, required_version) };
        if !success {
            return Err(CommandError::RegistrationFailed(name.to_string()));
        }

        Ok(())
    }

    /// Build a CommandInfo struct from the given parameters.
    ///
    /// Allocates strings and param arrays on the heap and leaks them
    /// intentionally - NVSE holds raw pointers to these for the entire
    /// game session.
    fn build_command_info(
        &mut self,
        name: &str,
        short_name: &str,
        help: &str,
        needs_ref: bool,
        params: &[Param],
        execute: Cmd_Execute,
    ) -> CommandResult<CommandInfoFFI> {
        // Allocate and leak C strings (NVSE keeps pointers to them)
        let name_cstr = self.leak_cstring(name);
        let short_cstr = self.leak_cstring(short_name);
        let help_cstr = self.leak_cstring(help);

        // Build ParamInfo array
        let (params_ptr, num_params) = if params.is_empty() {
            (std::ptr::null_mut(), 0u16)
        } else {
            let param_infos: Vec<ParamInfoFFI> = params
                .iter()
                .map(|p| ParamInfoFFI {
                    typeStr: p.type_str.as_ptr(),
                    typeID: p.type_id as u32,
                    isOptional: if p.optional { 1 } else { 0 },
                })
                .collect();

            let boxed: Box<[ParamInfoFFI]> = param_infos.into_boxed_slice();
            let ptr = boxed.as_ptr() as *mut ParamInfoFFI;
            self._param_storage.push(boxed);
            (ptr, params.len() as u16)
        };

        Ok(CommandInfoFFI {
            longName: name_cstr,
            shortName: short_cstr,
            opcode: 0, // Filled in by NVSE based on SetOpcodeBase
            helpText: help_cstr,
            needsParent: if needs_ref { 1 } else { 0 },
            numParams: num_params,
            params: params_ptr,
            execute,
            parse: None, // NVSE fills in default
            eval: None,  // NVSE fills in default
            flags: 0,
        })
    }

    /// Convert a Rust string to a C string, store it, and return
    /// a pointer that remains valid for the game session.
    fn leak_cstring(&mut self, s: &str) -> *const i8 {
        let mut bytes = Vec::with_capacity(s.len() + 1);
        // Strip interior NUL bytes -- they would truncate the C string
        bytes.extend(s.bytes().filter(|&b| b != 0));
        bytes.push(0);

        let cstr: Box<CStr> = Box::from(
            CStr::from_bytes_with_nul(&bytes).unwrap_or(c""),
        );
        let ptr = cstr.as_ptr();
        self._string_storage.push(cstr);
        ptr
    }
}

/// Command execute handler signature.
///
/// When writing a command handler, implement this signature:
///
/// ```no_run
/// unsafe extern "C" fn my_command(
///     param_info: *mut ParamInfo,     // parameter definitions
///     script_data: *mut c_void,       // raw script bytecode
///     this_obj: *mut TESObjectREFR,   // calling reference (if needs_ref)
///     containing_obj: *mut TESObjectREFR, // container reference
///     script_obj: *mut Script,        // the calling script
///     event_list: *mut ScriptEventList,   // script variables
///     result: *mut f64,               // write your numeric result here
///     opcode_offset: *mut u32,        // bytecode offset
/// ) -> bool // return true on success
/// ```
///
/// Access raw FFI types via `crate::` (they are `pub(crate)`):
/// `Cmd_Execute`, `Cmd_Eval`, `Cmd_Parse`, `CommandInfo`, `ParamInfo`,
/// `Script`, `ScriptEventList`, `TESObjectREFR`.
pub type ExecuteHandler = Cmd_Execute;

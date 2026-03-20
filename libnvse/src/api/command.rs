//! Command registration API for NVSE plugins.
//!
//! # Usage
//!
//! ```no_run
//! use libnvse::nvse_command;
//!
//! // Define a command with the macro -- generates the extern "C" handler
//! nvse_command!(PsychoMem, cmd, {
//!     cmd.print("Hello from Rust!");
//!     cmd.set_result(42.0);
//!     true
//! });
//!
//! // Register it
//! cmds.register("PsychoMem", "pmem", "Show memory info",
//!     false, &[], PSYCHO_MEM_EXECUTE)?;
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use thiserror::Error;

use crate::{
    Cmd_Execute, CommandInfo as CommandInfoFFI, CommandReturnType,
    NVSEInterface as NVSEInterfaceFFI, ParamInfo as ParamInfoFFI,
};

// ---------------------------------------------------------------------------
// CommandContext
// ---------------------------------------------------------------------------

/// Safe context passed to command handlers.
///
/// Created by the `nvse_command!` macro trampoline from raw COMMAND_ARGS.
pub struct CommandContext {
    /// Pointer to the numeric result slot.
    pub result: *mut f64,
    /// Calling reference (NULL if command not called on a ref).
    pub this_obj: *mut libc::c_void,
}

impl CommandContext {
    /// Set the numeric result returned to the script engine.
    pub fn set_result(&self, value: f64) {
        if !self.result.is_null() {
            unsafe { *self.result = value };
        }
    }

    /// Get the current result value.
    pub fn get_result(&self) -> f64 {
        if self.result.is_null() {
            0.0
        } else {
            unsafe { *self.result }
        }
    }

    /// Check if this command was called on a reference.
    pub fn has_this_ref(&self) -> bool {
        !self.this_obj.is_null()
    }

    /// Get the calling reference's form ID (0 if none).
    pub fn this_ref_id(&self) -> u32 {
        if self.this_obj.is_null() {
            0
        } else {
            unsafe { (*(self.this_obj as *const crate::TESForm)).refID }
        }
    }

    /// Print a line to the in-game console.
    pub fn print(&self, message: &str) {
        let _ = crate::api::console::console_print(message);
    }
}

/// Macro that generates a `Cmd_Execute`-compatible `extern "C"` function
/// wrapping a safe Rust body.
///
/// Produces a constant `{NAME}_EXECUTE` of type `Cmd_Execute` that can be
/// passed directly to `CommandBuilder::register`.
///
/// # Syntax
///
/// ```no_run
/// nvse_command!(CommandName, ctx_ident, {
///     // safe Rust code here
///     // ctx_ident is a &CommandContext
///     ctx_ident.print("hello");
///     ctx_ident.set_result(1.0);
///     true // return bool
/// });
/// ```
///
/// # Example
///
/// ```no_run
/// use libnvse::nvse_command;
///
/// nvse_command!(PsychoMem, cmd, {
///     cmd.print("=== Memory Report ===");
///     cmd.set_result(42.0);
///     true
/// });
///
/// // Register:
/// builder.register("PsychoMem", "pmem", "Memory report",
///     false, &[], PSYCHO_MEM_EXECUTE)?;
/// ```
#[macro_export]
macro_rules! nvse_command {
    ($name:ident, $ctx:ident, $body:expr) => {
        $crate::paste::paste! {
            #[allow(non_snake_case)]
            unsafe extern "C" fn [<__nvse_cmd_ $name>](
                _param_info: *mut ::libc::c_void,
                _script_data: *mut ::libc::c_void,
                this_obj: *mut ::libc::c_void,
                _containing_obj: *mut ::libc::c_void,
                _script_obj: *mut ::libc::c_void,
                _event_list: *mut ::libc::c_void,
                result: *mut f64,
                _opcode_offset: *mut u32,
            ) -> bool {
                let $ctx = $crate::api::command::CommandContext {
                    result,
                    this_obj,
                };
                $body
            }

            #[allow(non_upper_case_globals)]
            pub const [<$name:upper _EXECUTE>]: $crate::Cmd_Execute = {
                // SAFETY: All pointer params are *mut c_void which has
                // identical ABI to the specific NVSE pointer types on i686.
                // The transmute converts between fn pointer types that
                // differ only in the pointee types of their parameters.
                unsafe {
                    ::core::mem::transmute::<
                        unsafe extern "C" fn(
                            *mut ::libc::c_void, *mut ::libc::c_void,
                            *mut ::libc::c_void, *mut ::libc::c_void,
                            *mut ::libc::c_void, *mut ::libc::c_void,
                            *mut f64, *mut u32,
                        ) -> bool,
                        $crate::Cmd_Execute,
                    >([<__nvse_cmd_ $name>])
                }
            };
        }
    };
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
    StringVar = 71,
    Array = 72,
}

impl ParamType {
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

#[derive(Debug, Clone)]
pub struct Param {
    type_str: &'static CStr,
    type_id: ParamType,
    optional: bool,
}

impl Param {
    pub fn required(param_type: ParamType) -> Self {
        Self {
            type_str: param_type.type_str(),
            type_id: param_type,
            optional: false,
        }
    }
    pub fn optional(param_type: ParamType) -> Self {
        Self {
            type_str: param_type.type_str(),
            type_id: param_type,
            optional: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// CommandBuilder
// ---------------------------------------------------------------------------

const MAX_PARAMS: usize = 16;

/// Builder for registering NVSE script commands.
pub struct CommandBuilder {
    nvse_ptr: NonNull<NVSEInterfaceFFI>,
    _param_storage: Vec<Box<[ParamInfoFFI]>>,
    _string_storage: Vec<Box<CStr>>,
}

impl CommandBuilder {
    pub fn from_raw(nvse_ptr: *const NVSEInterfaceFFI) -> CommandResult<Self> {
        let nvse_ptr =
            NonNull::new(nvse_ptr as *mut NVSEInterfaceFFI).ok_or(CommandError::InterfaceIsNull)?;
        Ok(Self {
            nvse_ptr,
            _param_storage: Vec::new(),
            _string_storage: Vec::new(),
        })
    }

    pub fn set_opcode_base(&self, opcode: u32) -> CommandResult<()> {
        let nvse = unsafe { self.nvse_ptr.as_ref() };
        let f = nvse
            .SetOpcodeBase
            .ok_or(CommandError::SetOpcodeBaseIsNull)?;
        unsafe { f(opcode) };
        Ok(())
    }

    /// Register a command. Use `nvse_command!` macro to create the execute handler.
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
        let f = nvse
            .RegisterCommand
            .ok_or(CommandError::RegisterCommandIsNull)?;
        let mut cmd =
            self.build_command_info(name, short_name, help, needs_ref, params, execute)?;
        if !unsafe { f(&mut cmd) } {
            return Err(CommandError::RegistrationFailed(name.to_string()));
        }
        Ok(())
    }

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
        let f = nvse
            .RegisterTypedCommand
            .ok_or(CommandError::RegisterTypedCommandIsNull)?;
        let mut cmd =
            self.build_command_info(name, short_name, help, needs_ref, params, execute)?;
        if !unsafe { f(&mut cmd, Self::to_ffi_rt(return_type)) } {
            return Err(CommandError::RegistrationFailed(name.to_string()));
        }
        Ok(())
    }

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
        let f = nvse
            .RegisterTypedCommandVersion
            .ok_or(CommandError::RegisterTypedCommandIsNull)?;
        let mut cmd =
            self.build_command_info(name, short_name, help, needs_ref, params, execute)?;
        if !unsafe { f(&mut cmd, Self::to_ffi_rt(return_type), required_version) } {
            return Err(CommandError::RegistrationFailed(name.to_string()));
        }
        Ok(())
    }

    fn to_ffi_rt(rt: ReturnType) -> CommandReturnType {
        match rt {
            ReturnType::Default => CommandReturnType::kRetnType_Default,
            ReturnType::Form => CommandReturnType::kRetnType_Form,
            ReturnType::String => CommandReturnType::kRetnType_String,
            ReturnType::Array => CommandReturnType::kRetnType_Array,
            ReturnType::ArrayIndex => CommandReturnType::kRetnType_ArrayIndex,
            ReturnType::Ambiguous => CommandReturnType::kRetnType_Ambiguous,
        }
    }

    fn build_command_info(
        &mut self,
        name: &str,
        short_name: &str,
        help: &str,
        needs_ref: bool,
        params: &[Param],
        execute: Cmd_Execute,
    ) -> CommandResult<CommandInfoFFI> {
        let name_cstr = self.leak_cstring(name);
        let short_cstr = self.leak_cstring(short_name);
        let help_cstr = self.leak_cstring(help);

        let (params_ptr, num_params) = if params.is_empty() {
            (std::ptr::null_mut(), 0u16)
        } else {
            let pi: Vec<ParamInfoFFI> = params
                .iter()
                .map(|p| ParamInfoFFI {
                    typeStr: p.type_str.as_ptr(),
                    typeID: p.type_id as u32,
                    isOptional: if p.optional { 1 } else { 0 },
                })
                .collect();
            let boxed: Box<[ParamInfoFFI]> = pi.into_boxed_slice();
            let ptr = boxed.as_ptr() as *mut ParamInfoFFI;
            self._param_storage.push(boxed);
            (ptr, params.len() as u16)
        };

        Ok(CommandInfoFFI {
            longName: name_cstr,
            shortName: short_cstr,
            opcode: 0,
            helpText: help_cstr,
            needsParent: if needs_ref { 1 } else { 0 },
            numParams: num_params,
            params: params_ptr,
            execute,
            parse: None, // NVSE fills Cmd_Default_Parse
            eval: None,
            flags: 0,
        })
    }

    fn leak_cstring(&mut self, s: &str) -> *const i8 {
        let mut bytes = Vec::with_capacity(s.len() + 1);
        bytes.extend(s.bytes().filter(|&b| b != 0));
        bytes.push(0);
        let cstr: Box<CStr> = Box::from(CStr::from_bytes_with_nul(&bytes).unwrap_or(c""));
        let ptr = cstr.as_ptr();
        self._string_storage.push(cstr);
        ptr
    }
}

pub type ExecuteHandler = Cmd_Execute;

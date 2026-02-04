//!
//! 
//! You can do something like this:
//! ```
//!    // See, you can use closures for registering listeners for NVSEMessagingInterface!
//!    msg_interface.register_listener("NVSE", |msg| {
//!        let msg_type = msg.get_type();
//!
//!        if msg_type == NVSEMessageType::MainGameLoop
//!            || msg_type == NVSEMessageType::OnFramePresent
//!            || msg_type == NVSEMessageType::ScriptCompile
//!            || msg_type == NVSEMessageType::EventListDestroyed
//!            || msg_type == NVSEMessageType::ScriptPrecompile
//!        {
//!            return;
//!        }
//!
//!        log::debug!("Message received: {}", msg.get_type());
//!
//!        if msg.get_type() == NVSEMessageType::DeferredInit {
//!            match show_message_box("psycho-nvse loaded! Have FUN!", "YUP", || {
//!                log::info!("YES! BUTTON PRESSED!!!!")
//!            }) {
//!                Ok(_) => {}
//!                Err(err) => {
//!                    log::error!("show_message_box error: {:?}", err);
//!                }
//!            }
//!        }
//!    })?;
//! ```

use crate::{
    NVSEMessagingInterface as NVSEMessagingInterfaceFFI, api::interface::NVSEPluginHandle
};
use ahash::AHashMap;
use closure_ffi::BareFn;
use libpsycho::os::windows::winapi::{WinString, WinapiError};
use parking_lot::RwLock;
use std::{ffi::CStr, fmt::Display, ptr::NonNull};
use thiserror::Error;

use libc::c_void;

use crate::{
    NVSEMessagingInterface_Message, NVSEMessagingInterface_kMessage_ClearScriptDataCache,
    NVSEMessagingInterface_kMessage_DeferredInit, NVSEMessagingInterface_kMessage_DeleteGame,
    NVSEMessagingInterface_kMessage_DeleteGameName,
    NVSEMessagingInterface_kMessage_EventListDestroyed, NVSEMessagingInterface_kMessage_ExitGame,
    NVSEMessagingInterface_kMessage_ExitGame_Console,
    NVSEMessagingInterface_kMessage_ExitToMainMenu, NVSEMessagingInterface_kMessage_LoadGame,
    NVSEMessagingInterface_kMessage_MainGameLoop, NVSEMessagingInterface_kMessage_NewGame,
    NVSEMessagingInterface_kMessage_OnFramePresent, NVSEMessagingInterface_kMessage_PostLoad,
    NVSEMessagingInterface_kMessage_PostLoadGame, NVSEMessagingInterface_kMessage_PostPostLoad,
    NVSEMessagingInterface_kMessage_PostQueryPlugins, NVSEMessagingInterface_kMessage_PreLoadGame,
    NVSEMessagingInterface_kMessage_RenameGame, NVSEMessagingInterface_kMessage_RenameGameName,
    NVSEMessagingInterface_kMessage_RenameNewGame,
    NVSEMessagingInterface_kMessage_RenameNewGameName,
    NVSEMessagingInterface_kMessage_RuntimeScriptError, NVSEMessagingInterface_kMessage_SaveGame,
    NVSEMessagingInterface_kMessage_ScriptCompile,
    NVSEMessagingInterface_kMessage_ScriptPrecompile,
};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum NVSEMessageType {
    PostLoad,
    ExitGame,
    ExitToMainMenu,
    LoadGame,
    SaveGame,
    ScriptPrecompile,
    PreLoadGame,
    ExitGame_Console,
    PostLoadGame,
    PostPostLoad,
    RuntimeScriptError,
    DeleteGame,
    RenameGame,
    RenameNewGame,
    NewGame,
    DeleteGameName,
    RenameGameName,
    RenameNewGameName,
    DeferredInit,
    ClearScriptDataCache,
    MainGameLoop,
    ScriptCompile,
    EventListDestroyed,
    PostQueryPlugins,
    OnFramePresent,
    Unknown(u32),
}

const kMessage_PostLoad: u32 = NVSEMessagingInterface_kMessage_PostLoad as u32;
const kMessage_ExitGame: u32 = NVSEMessagingInterface_kMessage_ExitGame as u32;
pub const kMessage_ExitToMainMenu: u32 = NVSEMessagingInterface_kMessage_ExitToMainMenu as u32;
pub const kMessage_LoadGame: u32 = NVSEMessagingInterface_kMessage_LoadGame as u32;
pub const kMessage_SaveGame: u32 = NVSEMessagingInterface_kMessage_SaveGame as u32;
pub const kMessage_ScriptPrecompile: u32 = NVSEMessagingInterface_kMessage_ScriptPrecompile as u32;
pub const kMessage_PreLoadGame: u32 = NVSEMessagingInterface_kMessage_PreLoadGame as u32;
pub const kMessage_ExitGame_Console: u32 = NVSEMessagingInterface_kMessage_ExitGame_Console as u32;
pub const kMessage_PostLoadGame: u32 = NVSEMessagingInterface_kMessage_PostLoadGame as u32;
pub const kMessage_PostPostLoad: u32 = NVSEMessagingInterface_kMessage_PostPostLoad as u32;
pub const kMessage_RuntimeScriptError: u32 =
    NVSEMessagingInterface_kMessage_RuntimeScriptError as u32;
pub const kMessage_DeleteGame: u32 = NVSEMessagingInterface_kMessage_DeleteGame as u32;
pub const kMessage_RenameGame: u32 = NVSEMessagingInterface_kMessage_RenameGame as u32;
pub const kMessage_RenameNewGame: u32 = NVSEMessagingInterface_kMessage_RenameNewGame as u32;
pub const kMessage_NewGame: u32 = NVSEMessagingInterface_kMessage_NewGame as u32;
pub const kMessage_DeleteGameName: u32 = NVSEMessagingInterface_kMessage_DeleteGameName as u32;
pub const kMessage_RenameGameName: u32 = NVSEMessagingInterface_kMessage_RenameGameName as u32;
pub const kMessage_RenameNewGameName: u32 =
    NVSEMessagingInterface_kMessage_RenameNewGameName as u32;
pub const kMessage_DeferredInit: u32 = NVSEMessagingInterface_kMessage_DeferredInit as u32;
pub const kMessage_ClearScriptDataCache: u32 =
    NVSEMessagingInterface_kMessage_ClearScriptDataCache as u32;
pub const kMessage_MainGameLoop: u32 = NVSEMessagingInterface_kMessage_MainGameLoop as u32;
pub const kMessage_ScriptCompile: u32 = NVSEMessagingInterface_kMessage_ScriptCompile as u32;
pub const kMessage_EventListDestroyed: u32 =
    NVSEMessagingInterface_kMessage_EventListDestroyed as u32;
pub const kMessage_PostQueryPlugins: u32 = NVSEMessagingInterface_kMessage_PostQueryPlugins as u32;
pub const kMessage_OnFramePresent: u32 = NVSEMessagingInterface_kMessage_OnFramePresent as u32;

impl Display for NVSEMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string_form = match self {
            NVSEMessageType::PostLoad => "PostLoad",
            NVSEMessageType::ExitGame => "ExitGame",
            NVSEMessageType::ExitToMainMenu => "ExitToMainMenu",
            NVSEMessageType::LoadGame => "LoadGame",
            NVSEMessageType::SaveGame => "SaveGame",
            NVSEMessageType::ScriptPrecompile => "ScriptPrecompile",
            NVSEMessageType::PreLoadGame => "PreLoadGame",
            NVSEMessageType::ExitGame_Console => "ExitGame_Console",
            NVSEMessageType::PostLoadGame => "PostLoadGame",
            NVSEMessageType::PostPostLoad => "PostPostLoad",
            NVSEMessageType::RuntimeScriptError => "RuntimeScriptError",
            NVSEMessageType::DeleteGame => "DeleteGame",
            NVSEMessageType::RenameGame => "RenameGame",
            NVSEMessageType::RenameNewGame => "RenameNewGame",
            NVSEMessageType::NewGame => "NewGame",
            NVSEMessageType::DeleteGameName => "DeleteGameName",
            NVSEMessageType::RenameGameName => "RenameGameName",
            NVSEMessageType::RenameNewGameName => "RenameNewGameName",
            NVSEMessageType::DeferredInit => "DeferredInit",
            NVSEMessageType::ClearScriptDataCache => "ClearScriptDataCache",
            NVSEMessageType::MainGameLoop => "MainGameLoop",
            NVSEMessageType::ScriptCompile => "ScriptCompile",
            NVSEMessageType::EventListDestroyed => "EventListDestroyed",
            NVSEMessageType::PostQueryPlugins => "PostQueryPlugins",
            NVSEMessageType::OnFramePresent => "OnFramePresent",
            NVSEMessageType::Unknown(v) => &format!("Unknown({})", v),
        };

        write!(f, "{}", string_form)
    }
}

impl From<&NVSEMessagingInterface_Message> for NVSEMessageType {
    fn from(msg: &NVSEMessagingInterface_Message) -> Self {
        match msg.type_ {
            kMessage_PostLoad => Self::PostLoad,
            kMessage_ExitGame => Self::ExitGame,
            kMessage_ExitToMainMenu => Self::ExitToMainMenu,
            kMessage_LoadGame => Self::LoadGame,
            kMessage_SaveGame => Self::SaveGame,
            kMessage_ScriptPrecompile => Self::ScriptPrecompile,
            kMessage_PreLoadGame => Self::PreLoadGame,
            kMessage_ExitGame_Console => Self::ExitGame_Console,
            kMessage_PostLoadGame => Self::PostLoadGame,
            kMessage_PostPostLoad => Self::PostPostLoad,
            kMessage_RuntimeScriptError => Self::RuntimeScriptError,
            kMessage_DeleteGame => Self::DeleteGame,
            kMessage_RenameGame => Self::RenameGame,
            kMessage_RenameNewGame => Self::RenameNewGame,
            kMessage_NewGame => Self::NewGame,
            kMessage_DeleteGameName => Self::DeleteGameName,
            kMessage_RenameGameName => Self::RenameGameName,
            kMessage_RenameNewGameName => Self::RenameNewGameName,
            kMessage_DeferredInit => Self::DeferredInit,
            kMessage_ClearScriptDataCache => Self::ClearScriptDataCache,
            kMessage_MainGameLoop => Self::MainGameLoop,
            kMessage_ScriptCompile => Self::ScriptCompile,
            kMessage_EventListDestroyed => Self::EventListDestroyed,
            kMessage_PostQueryPlugins => Self::PostQueryPlugins,
            kMessage_OnFramePresent => Self::OnFramePresent,
            _ => Self::Unknown(msg.type_),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NVSEMessage {
    data: *mut c_void,
    data_len: u32,
    sender: String,
    msg_type: NVSEMessageType,
}

impl From<&NVSEMessagingInterface_Message> for NVSEMessage {
    fn from(val: &NVSEMessagingInterface_Message) -> Self {
        let msg_type: NVSEMessageType = val.into();
        let sender = unsafe { CStr::from_ptr(val.sender) }
            .to_str()
            .unwrap_or("UNKNOWN")
            .to_string();

        Self {
            data: val.data,
            data_len: val.dataLen,
            msg_type,
            sender,
        }
    }
}

impl NVSEMessage {
    pub fn get_type(&self) -> NVSEMessageType {
        self.msg_type
    }
}

#[derive(Debug, Error)]
pub enum NVSEMessagingInterfaceError {
    #[error("RegisterListener from NVSEMessagingInterface is NULL")]
    RegisterListenerIsNull,

    #[error("NVSEMessagingInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),

    #[error("Message listener already registered for sender: {0}")]
    ListenerAlreadyRegistered(String),
}

pub type NVSEMessagingInterfaceResult<T> = std::result::Result<T, NVSEMessagingInterfaceError>;

pub struct NVSEMessagingInterface<'a> {
    version: u32,
    msg_ptr: NonNull<NVSEMessagingInterfaceFFI>,

    listeners:
        AHashMap<String, BareFn<'a, unsafe extern "C" fn(*mut NVSEMessagingInterface_Message)>>,

    plugin_handle: NVSEPluginHandle,

    _guard: RwLock<()>,
}

impl<'a> NVSEMessagingInterface<'a> {
    pub fn from_raw(
        msg_interface: *mut NVSEMessagingInterfaceFFI,
        plugin_handle: NVSEPluginHandle,
    ) -> NVSEMessagingInterfaceResult<Self> {
        let msg_ptr =
            NonNull::new(msg_interface).ok_or(NVSEMessagingInterfaceError::InterfaceIsNull)?;

        let msg_ref = unsafe { msg_ptr.as_ref() };

        let version = msg_ref.version;

        Ok(Self {
            version,
            msg_ptr,
            plugin_handle,
            listeners: AHashMap::new(),
            _guard: RwLock::new(()),
        })
    }

    pub fn register_listener<F: Fn(&NVSEMessage) + 'a>(
        &mut self,
        sender: &str,
        cb: F,
    ) -> NVSEMessagingInterfaceResult<()> {
        let _lock = self._guard.write();

        if self.listeners.contains_key(sender) {
            return Err(NVSEMessagingInterfaceError::ListenerAlreadyRegistered(
                sender.to_string(),
            ));
        }

        let msg_ref = unsafe { self.msg_ptr.as_ref() };

        let register_listener_fn = msg_ref
            .RegisterListener
            .ok_or(NVSEMessagingInterfaceError::RegisterListenerIsNull)?;

        // Okay okay, what this thing will do for us?
        // First of all, we want to give NVSE raw pointer to our closure.
        // This task achiavable through `closure-ffi` with `BareFn` type.
        // BareFn will own our closure and can safely return pointer to it.
        // But we all know about Rust's lifetimes, so we save BareFn to hashmap.
        // That means NVSE always have pointer to VALID function, while developer
        // use nice high level API in little cost of RAM
        let bare_fn = BareFn::new(move |msg: *mut NVSEMessagingInterface_Message| {
            let message: NVSEMessage = unsafe { &*msg }.into();

            cb(&message)
        });

        let sender_winstr = WinString::new(sender)?;

        sender_winstr.with_ansi(|sender| unsafe {
            register_listener_fn(self.plugin_handle.get_handle(), sender, Some(bare_fn.bare()))
        });

        // This is closure lifetime preservation program
        // Input closure was chosen to exclusively participate in program
        // of preserving it's lifetime in our specialy designed vault(hashmap)
        self.listeners.insert(sender.to_string(), bare_fn);

        Ok(())
    }

    pub fn is_listener_registered(&self, sender: &str) -> bool {
        let _lock = self._guard.read();

        self.listeners.contains_key(sender)
    }
}

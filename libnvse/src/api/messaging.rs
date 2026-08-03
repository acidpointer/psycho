//! Messaging NVSE API wrapper
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
//!            match show_message_box("NVSE plugin loaded", "OK", || {
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
    NVSEMessagingInterface as NVSEMessagingInterfaceFFI, api::interface::NVSEPluginHandle,
};
use ahash::AHashMap;
use closure_ffi::BareFn;
use libpsycho::os::windows::winapi::{WinString, WinapiError};
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

#[derive(Debug)]
pub struct NVSEMessage {
    data: *mut c_void,
    data_len: u32,
    sender: String,
    msg_type: NVSEMessageType,
}

impl From<&NVSEMessagingInterface_Message> for NVSEMessage {
    fn from(val: &NVSEMessagingInterface_Message) -> Self {
        let msg_type: NVSEMessageType = val.into();
        let sender = if val.sender.is_null() {
            "UNKNOWN".to_string()
        } else {
            unsafe { CStr::from_ptr(val.sender) }
                .to_str()
                .unwrap_or("UNKNOWN")
                .to_string()
        };

        Self {
            data: val.data,
            data_len: val.dataLen,
            msg_type,
            sender,
        }
    }
}

impl NVSEMessage {
    /// Get the message type.
    pub fn get_type(&self) -> NVSEMessageType {
        self.msg_type
    }

    /// Get the sender plugin name.
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// Get the raw data pointer and length.
    pub fn raw_data(&self) -> (*mut c_void, u32) {
        (self.data, self.data_len)
    }

    /// Interpret the message data as a file path string.
    ///
    /// Many NVSE messages (LoadGame, SaveGame, DeleteGame, etc.) pass
    /// a C string path as their data. Returns None if data is NULL or
    /// not valid UTF-8.
    pub fn data_as_path(&self) -> Option<&str> {
        if self.data.is_null() || self.data_len == 0 {
            return None;
        }
        let cstr = unsafe { CStr::from_ptr(self.data as *const i8) };
        cstr.to_str().ok()
    }

    /// Interpret the message data as a bool (used by PostLoadGame).
    ///
    /// xNVSE passes this as a pointer-sized boolean value, not a pointer to bool.
    /// Returns None if the message has no boolean payload or uses an unexpected value.
    pub fn data_as_bool(&self) -> Option<bool> {
        if self.data_len < 1 {
            return None;
        }

        match self.data as usize {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
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

    #[error(
        "NVSE rejected message listener registration for sender {sender} with plugin handle {plugin_handle}"
    )]
    ListenerRegistrationRejected { sender: String, plugin_handle: u32 },
}

pub type NVSEMessagingInterfaceResult<T> = std::result::Result<T, NVSEMessagingInterfaceError>;

pub struct NVSEMessagingInterface<'a> {
    version: u32,
    msg_ptr: NonNull<NVSEMessagingInterfaceFFI>,

    listeners:
        AHashMap<String, BareFn<'a, unsafe extern "C" fn(*mut NVSEMessagingInterface_Message)>>,

    plugin_handle: NVSEPluginHandle,
}

fn register_listener_handle(
    reported_handle: u32,
    recover_gapful_nvse_handle: bool,
    mut register: impl FnMut(u32) -> bool,
) -> Option<u32> {
    if register(reported_handle) {
        return Some(reported_handle);
    }

    if !recover_gapful_nvse_handle || reported_handle <= 1 {
        return None;
    }

    // xNVSE's load-pass index advances before Load succeeds, but its accepted
    // listener range counts only successful plugins plus the current plugin.
    // A prior Load failure therefore leaves GetPluginHandle() too high. The
    // first accepted descending handle is the current plugin's eventual slot;
    // stop there so an already-loaded plugin's handle is never reached.
    (1..reported_handle).rev().find(|handle| register(*handle))
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
        })
    }

    pub fn register_listener<F: Fn(&NVSEMessage) + 'a>(
        &mut self,
        sender: &str,
        cb: F,
    ) -> NVSEMessagingInterfaceResult<()> {
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

        let reported_handle = self.plugin_handle.get_handle();
        let registered_handle = sender_winstr.with_ansi(|sender_ptr| {
            // Only the built-in NVSE sender is guaranteed to exist during the
            // load pass. For another sender, false can mean "not loaded", so
            // probing lower handles would risk assuming another plugin's ID.
            register_listener_handle(reported_handle, sender == "NVSE", |handle| unsafe {
                register_listener_fn(handle, sender_ptr, Some(bare_fn.bare()))
            })
        });

        let Some(registered_handle) = registered_handle else {
            return Err(NVSEMessagingInterfaceError::ListenerRegistrationRejected {
                sender: sender.to_string(),
                plugin_handle: reported_handle,
            });
        };

        self.plugin_handle = NVSEPluginHandle::from_raw(registered_handle);

        // This is closure lifetime preservation program
        // Input closure was chosen to exclusively participate in program
        // of preserving it's lifetime in our specialy designed vault(hashmap)
        self.listeners.insert(sender.to_string(), bare_fn);

        Ok(())
    }

    pub fn is_listener_registered(&self, sender: &str) -> bool {
        self.listeners.contains_key(sender)
    }

    pub(crate) fn plugin_handle(&self) -> NVSEPluginHandle {
        self.plugin_handle
    }

    /// Dispatch a message to a specific plugin or all plugins.
    ///
    /// - `message_type` - Your plugin-defined message type ID
    /// - `data` - Raw data bytes to send (receiver must know the format)
    /// - `receiver` - Target plugin name, or None to broadcast to all
    ///
    /// Returns true if any listeners received the message.
    pub fn dispatch(
        &self,
        message_type: u32,
        data: &[u8],
        receiver: Option<&str>,
    ) -> NVSEMessagingInterfaceResult<bool> {
        let msg_ref = unsafe { self.msg_ptr.as_ref() };

        let dispatch_fn = msg_ref
            .Dispatch
            .ok_or(NVSEMessagingInterfaceError::InterfaceIsNull)?;

        let data_ptr = if data.is_empty() {
            std::ptr::null_mut()
        } else {
            data.as_ptr() as *mut c_void
        };

        let result = match receiver {
            Some(name) => {
                let win_name = WinString::new(name)?;
                win_name.with_ansi(|name_ptr| unsafe {
                    dispatch_fn(
                        self.plugin_handle.get_handle(),
                        message_type,
                        data_ptr,
                        data.len() as u32,
                        name_ptr,
                    )
                })
            }
            None => unsafe {
                dispatch_fn(
                    self.plugin_handle.get_handle(),
                    message_type,
                    data_ptr,
                    data.len() as u32,
                    std::ptr::null(),
                )
            },
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::CStr,
        sync::{
            Mutex,
            atomic::{AtomicU32, Ordering},
        },
    };

    use super::{
        NVSEMessagingInterface, NVSEMessagingInterfaceFFI, NVSEPluginHandle,
        register_listener_handle,
    };

    static MOCK_MAX_HANDLE: AtomicU32 = AtomicU32::new(0);
    static MOCK_ATTEMPTS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    unsafe extern "C" fn mock_register_listener(
        listener: u32,
        sender: *const i8,
        handler: crate::NVSEMessagingInterface_EventCallback,
    ) -> bool {
        MOCK_ATTEMPTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(listener);

        !sender.is_null()
            && handler.is_some()
            && unsafe { CStr::from_ptr(sender) }.to_bytes() == b"NVSE"
            && listener <= MOCK_MAX_HANDLE.load(Ordering::Acquire)
    }

    #[test]
    fn accepted_reported_handle_is_used_without_probing() {
        let mut attempts = Vec::new();
        let handle = register_listener_handle(7, true, |candidate| {
            attempts.push(candidate);
            candidate == 7
        });

        assert_eq!(handle, Some(7));
        assert_eq!(attempts, [7]);
    }

    #[test]
    fn messaging_interface_retains_the_recovered_handle() {
        MOCK_MAX_HANDLE.store(9, Ordering::Release);
        MOCK_ATTEMPTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let mut raw = NVSEMessagingInterfaceFFI {
            version: 4,
            RegisterListener: Some(mock_register_listener),
            Dispatch: None,
        };
        let mut messaging =
            NVSEMessagingInterface::from_raw(&mut raw, NVSEPluginHandle::from_raw(12))
                .expect("mock messaging interface");

        messaging
            .register_listener("NVSE", |_| {})
            .expect("gapful handle recovery");

        assert_eq!(messaging.plugin_handle().get_handle(), 9);
        assert!(messaging.is_listener_registered("NVSE"));
        assert_eq!(
            *MOCK_ATTEMPTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            [12, 11, 10, 9]
        );
    }

    #[test]
    fn gapful_nvse_handle_recovers_to_current_plugin_slot() {
        for current_handle in 1..=32 {
            for earlier_load_failures in 1..=32 {
                let reported_handle = current_handle + earlier_load_failures;
                let mut attempts = Vec::new();
                let handle = register_listener_handle(reported_handle, true, |candidate| {
                    attempts.push(candidate);
                    candidate <= current_handle
                });

                assert_eq!(handle, Some(current_handle));
                assert_eq!(attempts.first(), Some(&reported_handle));
                assert_eq!(attempts.last(), Some(&current_handle));
                assert!(
                    attempts
                        .iter()
                        .all(|candidate| *candidate >= current_handle)
                );
            }
        }
    }

    #[test]
    fn third_party_sender_failure_does_not_probe_other_plugin_handles() {
        let mut attempts = Vec::new();
        let handle = register_listener_handle(12, false, |candidate| {
            attempts.push(candidate);
            false
        });

        assert_eq!(handle, None);
        assert_eq!(attempts, [12]);
    }

    #[test]
    fn complete_nvse_rejection_is_reported_after_bounded_probe() {
        let mut attempts = Vec::new();
        let handle = register_listener_handle(3, true, |candidate| {
            attempts.push(candidate);
            false
        });

        assert_eq!(handle, None);
        assert_eq!(attempts, [3, 2, 1]);
    }
}

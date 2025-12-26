use std::{ffi::CStr, str::Utf8Error};

use crate::sys::f4se::{F4SEMessagingInterface, F4SEMessagingInterface_Message, UInt32};
use libc::c_void;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum F4SEMessageError {
    #[error("Message pointer is NULL")]
    MsgPtrIsNull,

    #[error("UTF-8 coding error: {0}")]
    Utf8Error(#[from] Utf8Error),
}


pub type F4SEMessageResult<T> = std::result::Result<T, F4SEMessageError>;


#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum F4SEMessageType {
    PostLoad,
    PostPostLoad,
    PreLoadGame,
    PostLoadGame,
    PreSaveGame,
    PostSaveGame,
    DeleteGame,
    InputLoaded,
    NewGame,
    GameLoaded,
    GameDataReady,
    Unknown,
}

impl From<&F4SEMessagingInterface_Message> for F4SEMessageType {
    fn from(msg: &F4SEMessagingInterface_Message) -> Self {
        match msg.r#type {
            F4SEMessagingInterface::kMessage_PostLoad => F4SEMessageType::PostLoad,
            F4SEMessagingInterface::kMessage_PostPostLoad => F4SEMessageType::PostPostLoad,
            F4SEMessagingInterface::kMessage_PreLoadGame => F4SEMessageType::PreLoadGame,
            F4SEMessagingInterface::kMessage_PostLoadGame => F4SEMessageType::PostLoadGame,
            F4SEMessagingInterface::kMessage_PreSaveGame => F4SEMessageType::PreSaveGame,
            F4SEMessagingInterface::kMessage_PostSaveGame => F4SEMessageType::PostSaveGame,
            F4SEMessagingInterface::kMessage_DeleteGame => F4SEMessageType::DeleteGame,
            F4SEMessagingInterface::kMessage_InputLoaded => F4SEMessageType::InputLoaded,
            F4SEMessagingInterface::kMessage_NewGame => F4SEMessageType::NewGame,
            F4SEMessagingInterface::kMessage_GameLoaded => F4SEMessageType::GameLoaded,
            F4SEMessagingInterface::kMessage_GameDataReady => F4SEMessageType::GameDataReady,
            _ => F4SEMessageType::Unknown,
        }
    }
}

impl From<F4SEMessageType> for UInt32 {
    fn from(value: F4SEMessageType) -> Self {
        match value {
            F4SEMessageType::PostLoad => F4SEMessagingInterface::kMessage_PostLoad,
            F4SEMessageType::PostPostLoad => F4SEMessagingInterface::kMessage_PostPostLoad,
            F4SEMessageType::PreLoadGame => F4SEMessagingInterface::kMessage_PreLoadGame,
            F4SEMessageType::PostLoadGame => F4SEMessagingInterface::kMessage_PostLoadGame,
            F4SEMessageType::PreSaveGame => F4SEMessagingInterface::kMessage_PreSaveGame,
            F4SEMessageType::PostSaveGame => F4SEMessagingInterface::kMessage_PostSaveGame,
            F4SEMessageType::DeleteGame => F4SEMessagingInterface::kMessage_DeleteGame,
            F4SEMessageType::InputLoaded => F4SEMessagingInterface::kMessage_InputLoaded,
            F4SEMessageType::NewGame => F4SEMessagingInterface::kMessage_NewGame,
            F4SEMessageType::GameLoaded => F4SEMessagingInterface::kMessage_GameLoaded,
            F4SEMessageType::GameDataReady => F4SEMessagingInterface::kMessage_GameDataReady,
            F4SEMessageType::Unknown => 999,
        }
    }
}

/// Rust native representation of `F4SEMessagingInterface_Message`
/// 
/// # Explanation
/// Usually, it's much more complex to work with FFI types in Rust.
/// This struct designed to avoid as much as possible safety issues and
/// can be constructed from `*mut F4SEMessagingInterface_Message`.
#[derive(Debug, Clone)]
pub struct F4SEMessage {
    sender: String,
    message_type: F4SEMessageType,
    data_len: u32,
    data_ptr: *mut c_void,
}

// Safety: no safety issues
unsafe impl Send for F4SEMessage {}

// Safety: no safety issues
unsafe impl Sync for F4SEMessage {}

impl F4SEMessage {
    /// Create owned message struct from message ptr
    /// 
    /// # Safety
    /// - `msg_ptr` is NULL-checked
    /// - inner C string(s) converted to Rust native `String`
    pub unsafe fn from_ptr(msg_ptr: *mut F4SEMessagingInterface_Message) -> F4SEMessageResult<Self> {
        if msg_ptr.is_null() {
            return Err(F4SEMessageError::MsgPtrIsNull);
        }

        // Best way to work with raw pointers - not use raw pointers.
        // So, here we quickly convert it to reference
        let msg_ref = unsafe { &*msg_ptr };

        let sender_str = unsafe { CStr::from_ptr(msg_ref.sender) }.to_str()?;

        Ok(Self {
            sender: sender_str.to_string(),
            message_type: msg_ref.into(),
            data_len: msg_ref.dataLen,
            data_ptr: msg_ref.data,
        })
    }

    pub fn get_sender(&self) -> &String {
        &self.sender
    }

    pub fn get_message_type(&self) -> F4SEMessageType {
        self.message_type
    }

    pub fn get_data_len(&self) -> UInt32 {
        self.data_len
    }

    pub fn get_data_ptr(&self) -> *mut libc::c_void {
        self.data_ptr
    }
}
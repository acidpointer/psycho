use std::{
    ffi::CStr,
    str::Utf8Error,
    sync::{Arc, OnceLock},
};

use crate::sys::f4se::{
    F4SEInterface, F4SEMessagingInterface, F4SEMessagingInterface_Message,
    F4SESerializationInterface, PluginHandle, UInt32, kInterface_Messaging,
    kInterface_Serialization,
};
use libpsycho::{
    common::{
        emitter::{EventEmitter, ListenerId},
        exe_version::ExeVersion,
    },
    ffi::r#ref::{FFIRef, FFIRefError},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum F4SEContextError {
    #[error("FFIRef error: {0}")]
    FFIRef(#[from] FFIRefError),

    #[error("QueryInterface is NULL")]
    QueryInterfaceIsNull(),

    #[error("GetPluginHandle is NULL")]
    GetPluginHandleIsNull(),

    #[error("F4SEContext already initialized")]
    AlreadyInitialized(),

    #[error("F4SEContext is not initialized")]
    NotInitialized(),
}

type F4SEContextResult<T> = std::result::Result<T, F4SEContextError>;

static G_F4SE_CTX: OnceLock<Arc<F4SEContext>> = OnceLock::new();

/// F4SEContext
pub struct F4SEContext {
    interface: FFIRef<F4SEInterface>,
}

// Safety: Safe (maybe) because F4SEInterface is read-only interface
unsafe impl Send for F4SEContext {}

// Safety: Safe (maybe) because F4SEInterface is read-only interface
unsafe impl Sync for F4SEContext {}

impl F4SEContext {
    /// Initialize static F4SEContext with F4SEInterface
    pub fn init(f4se: *mut F4SEInterface) -> F4SEContextResult<()> {
        if G_F4SE_CTX.get().is_none() {
            let f4se_ref = FFIRef::new(f4se)?;

            let instance = Arc::new(Self {
                interface: f4se_ref,
            });

            G_F4SE_CTX
                .set(instance.clone())
                .map_err(|_| F4SEContextError::AlreadyInitialized())?;
        }

        Ok(())
    }

    pub fn instance() -> F4SEContextResult<Arc<Self>> {
        let instance = G_F4SE_CTX
            .get()
            .ok_or_else(F4SEContextError::NotInitialized)?;

        Ok(instance.clone())
    }

    fn query<Q>(&self, interface_id: u32) -> F4SEContextResult<FFIRef<Q>> {
        let query_fn = self
            .interface
            .QueryInterface
            .ok_or_else(F4SEContextError::QueryInterfaceIsNull)?;

        let interface_ptr = unsafe { query_fn(interface_id) as *mut Q };
        let interface_ref = FFIRef::new(interface_ptr)?;

        Ok(interface_ref)
    }

    /// Query F4SEInterface for F4SEMessagingInterface
    pub fn query_messanging_interface(&self) -> F4SEContextResult<FFIRef<F4SEMessagingInterface>> {
        self.query::<F4SEMessagingInterface>(kInterface_Messaging)
    }

    /// Query F4SEInterface for F4SESerializationInterface
    pub fn query_serialization_interface(
        &self,
    ) -> F4SEContextResult<FFIRef<F4SESerializationInterface>> {
        self.query::<F4SESerializationInterface>(kInterface_Serialization)
    }

    /// Return current F4SE version
    pub fn f4se_version(&self) -> ExeVersion {
        ExeVersion::from_u32(self.interface.f4seVersion)
    }

    /// Return current runtime(game) version
    pub fn runtime_version(&self) -> ExeVersion {
        ExeVersion::from_u32(self.interface.runtimeVersion)
    }

    /// Return plugin handle
    pub fn plugin_handle(&self) -> F4SEContextResult<PluginHandle> {
        let plugin_handle_fn = self
            .interface
            .GetPluginHandle
            .ok_or_else(F4SEContextError::GetPluginHandleIsNull)?;

        let plugin_handle = unsafe { plugin_handle_fn() };
        Ok(plugin_handle)
    }
}

// Messanging

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

#[derive(Debug, Clone)]
pub struct F4SEMessage {
    sender: String,
    message_type: F4SEMessageType,
    data_len: u32,
    data_ptr: *mut libc::c_void,
}

unsafe impl Send for F4SEMessage {}
unsafe impl Sync for F4SEMessage {}

impl F4SEMessage {
    /// Create owned message struct from message ptr
    /// 
    /// # Safety
    /// Safe, because copy content of message and not owns message ptr.
    pub unsafe fn from_ptr(msg_ptr: *mut F4SEMessagingInterface_Message) -> Result<Self, Utf8Error> {
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

static G_F4SE_MESSAGE_BROKER: OnceLock<Arc<F4SEMessageBroker>> = OnceLock::new();

pub struct F4SEMessageBroker {
    emitter: EventEmitter<'static, F4SEMessageType, F4SEMessage>,
}

impl F4SEMessageBroker {
    fn new() -> Self {
        Self {
            emitter: EventEmitter::default(),
        }
    }

    /// Initializes or returns singleton of F4SEMessageBroker
    ///
    /// # Safety
    /// 'static lifetime is safe here, because instance of struct
    /// stored in global static variable, in OnceLock and never drop.
    pub fn instance() -> Arc<Self> {
        G_F4SE_MESSAGE_BROKER
            .get_or_init(|| Arc::new(Self::new()))
            .clone()
    }

    pub fn on<F: Fn(&F4SEMessage) + Send + Sync + 'static>(
        &self,
        msg_type: F4SEMessageType,
        callback: F,
    ) -> ListenerId {
        self.emitter.on(msg_type, callback)
    }

    unsafe extern "C" fn listener_topic_f4se(msg_ptr: *mut F4SEMessagingInterface_Message) {
        // It is highly important to check if pointer to message is not NULL
        if msg_ptr.is_null() {
            return;
        }

        // TODO: Check if it is really required here
        if !msg_ptr.is_aligned() {
            return;
        }

        match unsafe { F4SEMessage::from_ptr(msg_ptr) } {
            Ok(msg) => {
                let broker = Self::instance();

                broker.emitter.emit(msg.get_message_type(), msg);
            }

            Err(err) => {
                log::error!("Error converting message sender to Rust string: {err}")
            }
        }
    }
}

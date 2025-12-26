use std::sync::OnceLock;

use crate::sys::f4se::{
    F4SEInterface, F4SEMessagingInterface, F4SEMessagingInterface_Message,
    F4SESerializationInterface, PluginHandle, kInterface_Messaging, kInterface_Serialization,
};

use super::message::*;
use libpsycho::{
    common::{emitter::EventEmitter, exe_version::ExeVersion},
    ffi::r#ref::{FFIRef, FFIRefError},
};
use parking_lot::RwLock;
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

    #[error("Function 'RegisterListener' from 'F4SEMessagingInterface' is NULL")]
    MsgInterfaceRegisterListenerIsNull(),
}

type F4SEContextResult<T> = std::result::Result<T, F4SEContextError>;

static G_F4SE_CTX: OnceLock<F4SEContext> = OnceLock::new();

/// F4SEContext
pub struct F4SEContext {
    interface: RwLock<FFIRef<F4SEInterface>>,
    emitter: EventEmitter<'static, F4SEMessageType, F4SEMessage>,
}

// Safety: Synchronized with RwLock
unsafe impl Send for F4SEContext {}

// Safety: Synchronized with RwLock
unsafe impl Sync for F4SEContext {}

impl F4SEContext {
    unsafe extern "C" fn listener_topic_f4se(msg_ptr: *mut F4SEMessagingInterface_Message) {
        // It is highly important to check if pointer to message is not NULL
        if msg_ptr.is_null() {
            return;
        }

        let f4se_ctx = match Self::instance() {
            Ok(instance) => instance,
            Err(err) => {
                log::error!(
                    "Failed to get F4SEContext instance in 'listener_topic_f4se'. Error: {:?}",
                    err
                );
                return;
            }
        };

        let message = match unsafe { F4SEMessage::from_ptr(msg_ptr) } {
            Ok(msg) => msg,
            Err(err) => {
                log::error!(
                    "Failed to convert F4SEMessage from raw in 'listener_topic_f4se'. Error: {:?}",
                    err
                );
                return;
            }
        };

        let emitter = f4se_ctx.emitter();

        emitter.emit(message.get_message_type(), message);
    }

    /// Initialize static F4SEContext with F4SEInterface
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn init(f4se: *mut F4SEInterface) -> F4SEContextResult<()> {
        if G_F4SE_CTX.get().is_none() {
            let f4se_ref = unsafe { FFIRef::new(f4se) }?;

            let instance = Self {
                interface: RwLock::new(f4se_ref),
                emitter: EventEmitter::new(),
            };

            // At this point, we have enougth input to initialize message listener
            let messanging_interface = instance.query_messanging_interface()?;

            // Null-check for register listener function
            let register_listener = messanging_interface
                .RegisterListener
                .ok_or(F4SEContextError::MsgInterfaceRegisterListenerIsNull())?;

            let is_registered = unsafe {
                register_listener(
                    instance.plugin_handle()?,
                    c"F4SE".as_ptr(),
                    Some(Self::listener_topic_f4se),
                )
            };

            G_F4SE_CTX
                .set(instance)
                .map_err(|_| F4SEContextError::AlreadyInitialized())?;
        }

        Ok(())
    }

    pub fn emitter(&'_ self) -> &'static EventEmitter<'_, F4SEMessageType, F4SEMessage> {
        &self.emitter
    }

    pub fn instance() -> F4SEContextResult<&'static Self> {
        let instance = G_F4SE_CTX
            .get()
            .ok_or_else(F4SEContextError::NotInitialized)?;

        Ok(instance)
    }

    fn query<Q>(&self, interface_id: u32) -> F4SEContextResult<FFIRef<Q>> {
        let query_fn = self
            .interface
            .read()
            .QueryInterface
            .ok_or_else(F4SEContextError::QueryInterfaceIsNull)?;

        let interface_ptr = unsafe { query_fn(interface_id) as *mut Q };
        let interface_ref = unsafe { FFIRef::new(interface_ptr) }?;

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
        ExeVersion::from_u32(self.interface.read().f4seVersion)
    }

    /// Return current runtime(game) version
    pub fn runtime_version(&self) -> ExeVersion {
        ExeVersion::from_u32(self.interface.read().runtimeVersion)
    }

    /// Return plugin handle
    pub fn plugin_handle(&self) -> F4SEContextResult<PluginHandle> {
        let plugin_handle_fn = self
            .interface
            .read()
            .GetPluginHandle
            .ok_or(F4SEContextError::GetPluginHandleIsNull())?;

        let plugin_handle = unsafe { plugin_handle_fn() };
        Ok(plugin_handle)
    }
}

// Messanging

use std::{
    ffi::{CStr, CString}, ptr::NonNull, sync::{Arc, OnceLock}
};

use dashmap::DashMap;
use parking_lot::Mutex;
use thiserror::Error;

use crate::{
    context::F4SEContext,
    sys::f4se::{F4SEMessagingInterface, F4SEMessagingInterface_Message},
};

static G_F4SE_MESSAGE_BROKER: OnceLock<F4SEMessageBroker> = OnceLock::new();

#[derive(Debug, Error)]
pub enum F4SEMessageBrokerError {
    #[error("RegisterListener is NULL in F4SEInterface")]
    RegListenerFnIsNull,

    #[error("GetPluginHandle() is NULL on F4SEInterface")]
    PluginHandleIsNull,

    #[error("F4SEMessagingInterface Cant register listener callback")]
    RegListener,
}

type F4SEMessageBrokerResult<T> = core::result::Result<T, F4SEMessageBrokerError>;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
enum F4SEMessageType {
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

impl F4SEMessageType {
    pub fn from_message(msg: &mut F4SEMessagingInterface_Message) -> Self {
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


pub struct F4SEMessage<'a> {
    sender: &'a str,
    message_type: F4SEMessageType,
    inner: &'a mut F4SEMessagingInterface_Message,
}


impl<'a> F4SEMessage<'a> {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn from_raw(raw_message: *mut F4SEMessagingInterface_Message) -> anyhow::Result<Self> {
        let message = unsafe { &mut *raw_message };
        
        let sender_cstr = unsafe { CStr::from_ptr(message.sender) };
        
        let sender = sender_cstr.to_str()?;

        let message_type = F4SEMessageType::from_message(message);        

        Ok(Self {
            sender,
            message_type,
            inner: message,
        })
    }
}


type F4SEMsgBrokerCb = Mutex<Box<dyn FnMut(&mut F4SEMessagingInterface_Message) + Send + Sync>>;

pub struct F4SEMessageBroker {
    subs: Arc<DashMap<F4SEMessageType, Vec<F4SEMsgBrokerCb>>>,
}

impl F4SEMessageBroker {
    pub fn instantiate(
        msg_interface: NonNull<F4SEMessagingInterface>,
        ctx: &F4SEContext,
    ) -> F4SEMessageBrokerResult<&'static Self> {
        if ctx.plugin_handle().is_none() {
            return Err(F4SEMessageBrokerError::PluginHandleIsNull);
        }

        let interface = unsafe { &mut *msg_interface.as_ptr() };

        if interface.RegisterListener.is_none() {
            return Err(F4SEMessageBrokerError::RegListenerFnIsNull);
        }

        if let Some(reg_listener_fn) = interface.RegisterListener {
            if let Some(handle) = ctx.plugin_handle() {
                let is_ok = unsafe {
                    reg_listener_fn(
                        handle,
                        c"F4SE".as_ptr(),
                        Some(F4SEMessageBroker::topic_f4se_cb),
                    )
                };

                if !is_ok {
                    return Err(F4SEMessageBrokerError::RegListener);
                }
            }
        }

        let result = G_F4SE_MESSAGE_BROKER.get_or_init(move || F4SEMessageBroker {
            subs: Arc::new(DashMap::new()),
        });

        Ok(result)
    }

    pub fn instance() -> Option<&'static Self> {
        G_F4SE_MESSAGE_BROKER.get()
    }

    unsafe extern "C" fn topic_f4se_cb(msg_raw: *mut F4SEMessagingInterface_Message) {
        let msg = unsafe { &mut *msg_raw };

        
        let msg_type = F4SEMessageType::from_message(msg);

        if let Some(broker) = F4SEMessageBroker::instance() {
            let found_cbs = broker.subs.get(&msg_type);

            if let Some(callbacks) = found_cbs {
                for callback in callbacks.iter() {
                    callback.lock()(msg);
                }
            }
        }
    }
}

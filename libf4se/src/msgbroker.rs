use std::sync::{Arc, OnceLock};

use libpsycho::common::emitter::{EventEmitter, ListenerId};

use crate::{message::{F4SEMessage, F4SEMessageType}, sys::f4se::F4SEMessagingInterface_Message};

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

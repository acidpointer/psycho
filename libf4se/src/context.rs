use std::{
    ptr::NonNull, sync::OnceLock
};

use libpsycho::common::exe_version::ExeVersion;

use crate::sys::f4se::{
    kInterface_Messaging, kInterface_Serialization, F4SEInterface, F4SEMessagingInterface, F4SESerializationInterface, PluginHandle
};

/// Global state is required
static G_F4SE_CTX: OnceLock<F4SEContext> = OnceLock::new();

/// Available interfaces to query
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F4SEQueryInterface {
    Messanging = 1,
    Scaleform = 2,
    Papyrus = 3,
    Serialization = 4,
    Task = 5,
    Object = 6,
    Trampoline = 7,
    Max = 8,
    Invalid = 0,
}


/// F4SEContext
pub struct F4SEContext {
    inner: &'static F4SEInterface,
}


// Safety: Safe because F4SEInterface is readonly interface itself.
unsafe impl Send for F4SEContext {}

// Safety: Safe because F4SEInterface is readonly interface itself.
unsafe impl Sync for F4SEContext {}


impl<'a> F4SEContext {
    /// Initialize static F4SEContext with F4SEInterface
    pub fn instantiate(f4se: NonNull<F4SEInterface>) -> &'a Self {
        let interface = unsafe { &*(f4se.as_ptr()) };

        G_F4SE_CTX.get_or_init(move || Self { inner: interface })
    }

    /// Query F4SEInterface for F4SEMessagingInterface
    /// Return Option with mutable reference to queried interface.
    /// If Option is None - interface is NULL
    /// 
    /// Note: Under the hood it converts raw pointer to mut ref
    pub fn query_messanging_interface(&self) -> Option<&mut F4SEMessagingInterface> {
        if let Some(query_fn) = self.inner.QueryInterface {
            let ptr = unsafe { query_fn(kInterface_Messaging) as *mut F4SEMessagingInterface };

            let ptr: &mut F4SEMessagingInterface = unsafe { &mut *ptr };

            return Some(ptr);
        }

        None
    }

    /// Query F4SEInterface for F4SESerializationInterface
    /// Return Option with mutable reference to queried interface.
    /// If Option is None - interface is NULL
    /// 
    /// Note: Under the hood it converts raw pointer to mut ref
    pub fn query_serialization_interface(&self) -> Option<&mut F4SESerializationInterface> {
        if let Some(query_fn) = self.inner.QueryInterface {
            let ptr = unsafe { query_fn(kInterface_Serialization) };

            let ptr: &mut F4SESerializationInterface =
                unsafe { &mut *(ptr as *mut F4SESerializationInterface) };

            return Some(ptr);
        }

        None
    }

    /// Returns reference to global instance
    pub fn instance() -> Option<&'a Self> {
        G_F4SE_CTX.get()
    }

    /// Return current F4SE version
    pub fn f4se_version(&self) -> ExeVersion {
        ExeVersion::from_u32(self.inner.f4seVersion)
    }

    /// Return current runtime(game) version
    pub fn runtime_version(&self) -> ExeVersion {
        ExeVersion::from_u32(self.inner.runtimeVersion)
    }

    /// Return plugin handle
    pub fn plugin_handle(&self) -> Option<PluginHandle> {
        if let Some(plugin_handle_fn) = self.inner.GetPluginHandle {
            let plugin_handle = unsafe { plugin_handle_fn() };

            return Some(plugin_handle);
        }

        None
    }
}

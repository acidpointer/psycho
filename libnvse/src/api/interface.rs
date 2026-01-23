use std::ptr::NonNull;

use crate::api::messaging::{NVSEMessagingInterface, NVSEMessagingInterfaceError};
use crate::{
    NVSEInterface as NVSEInterfaceFFI, NVSEMessagingInterface as NVSEMessagingInterfaceFFI,
    kInterface_Messaging,
};
use libpsycho::common::exe_version::ExeVersion;
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NVSEInterfaceError {
    #[error("Interface pointer is NULL")]
    InterfaceIsNull,

    #[error("GetPluginHandle() from NVSEInterface is NULL")]
    GetPluginHandleIsNull,

    #[error("QueryInterface() from NVSEInterface is NULL")]
    QueryInterfaceIsNull,

    #[error("QueryInterface() from NVSEInterface returned NULL")]
    QueryResultIsNull,

    #[error("NVSEMessagingInterface error: {0}")]
    NVSEMessagingInterfaceError(#[from] NVSEMessagingInterfaceError),
}

pub type NVSEInterfaceResult<T> = std::result::Result<T, NVSEInterfaceError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NVSEPluginHandle {
    handle: u32,
}

impl NVSEPluginHandle {
    pub fn get_handle(&self) -> u32 {
        self.handle
    }
}

fn get_plugin_handle(nvse_ptr: NonNull<NVSEInterfaceFFI>) -> NVSEInterfaceResult<NVSEPluginHandle> {
    let nvse = unsafe { nvse_ptr.as_ref() };
    let get_plugin_handle = nvse
        .GetPluginHandle
        .ok_or(NVSEInterfaceError::GetPluginHandleIsNull)?;

    let plugin_handle_val = unsafe { get_plugin_handle() };

    Ok(NVSEPluginHandle {
        handle: plugin_handle_val,
    })
}

fn query_interface<T>(
    nvse_ptr: NonNull<NVSEInterfaceFFI>,
    interface_id: u32,
) -> NVSEInterfaceResult<*mut T> {
    let nvse_ref = unsafe { nvse_ptr.as_ref() };

    let query_interface_fn = nvse_ref
        .QueryInterface
        .ok_or(NVSEInterfaceError::QueryInterfaceIsNull)?;

    let result = unsafe { query_interface_fn(interface_id) } as *mut T;

    if result.is_null() {
        return Err(NVSEInterfaceError::QueryResultIsNull);
    }

    Ok(result)
}

fn query_messaging_interface<'a>(
    plugin_handle: NVSEPluginHandle,
    nvse_ptr: NonNull<NVSEInterfaceFFI>,
) -> NVSEInterfaceResult<NVSEMessagingInterface<'a>> {
    let raw_ptr =
        query_interface::<NVSEMessagingInterfaceFFI>(nvse_ptr, kInterface_Messaging as u32)?;

    let msg_interface = NVSEMessagingInterface::from_raw(raw_ptr, plugin_handle)?;

    Ok(msg_interface)
}

pub struct NVSEInterface<'a> {
    nvse_version: ExeVersion,
    runtime_version: ExeVersion,
    editor_version: Option<ExeVersion>,
    is_editor: bool,
    nvse_ptr: NonNull<NVSEInterfaceFFI>,

    msg_interface: NVSEMessagingInterface<'a>,
    plugin_handle: NVSEPluginHandle,

    _guard: RwLock<()>,
}

impl<'a> NVSEInterface<'a> {
    pub fn from_raw(nvse_ptr: *const NVSEInterfaceFFI) -> NVSEInterfaceResult<Self> {
        let nvse_ptr = NonNull::new(nvse_ptr as *mut NVSEInterfaceFFI)
            .ok_or(NVSEInterfaceError::InterfaceIsNull)?;

        let plugin_handle = get_plugin_handle(nvse_ptr)?;

        let msg_interface = query_messaging_interface(plugin_handle, nvse_ptr)?;

        let nvse_ref = unsafe { nvse_ptr.as_ref() };

        Ok(Self {
            nvse_version: ExeVersion::from_u32(nvse_ref.nvseVersion),
            runtime_version: ExeVersion::from_u32(nvse_ref.runtimeVersion),
            is_editor: nvse_ref.isEditor != 0,
            editor_version: if nvse_ref.isEditor != 0 {
                Some(ExeVersion::from_u32(nvse_ref.editorVersion))
            } else {
                None
            },
            nvse_ptr,
            plugin_handle,
            msg_interface,

            _guard: RwLock::new(()),
        })
    }

    pub fn is_editor(&self) -> bool {
        self.is_editor
    }

    pub fn messaging_interface_ref(&self) -> &NVSEMessagingInterface<'a> {
        let _lock = self._guard.read();

        &self.msg_interface
    }

    pub fn messaging_interface_mut(&mut self) -> &mut NVSEMessagingInterface<'a> {
        let _lock = self._guard.write();

        &mut self.msg_interface
    }

    pub fn get_plugin_handle(&self) -> NVSEPluginHandle {
        self.plugin_handle
    }
}

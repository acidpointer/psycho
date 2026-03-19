//! Safe wrapper for the NVSE data interface.
//!
//! Provides access to internal NVSE singletons, functions, and data.
//! This is a lower-level interface used for advanced operations like
//! inventory reference manipulation, lambda management, and form extra data.
//!
//! # Usage
//!
//! ```no_run
//! // Clear the script data cache
//! data.clear_script_data_cache();
//!
//! // Get a raw function pointer by ID
//! let func_ptr = data.get_func(DataFunc::DecompileScript);
//! ```

use std::ptr::NonNull;

use thiserror::Error;

use crate::NVSEDataInterface as NVSEDataInterfaceFFI;

// -- Singleton IDs ----------------------------------------------------------

/// IDs for NVSE internal singletons accessible via `get_singleton()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DataSingleton {
    /// DirectInput hook control.
    DIHookControl = 1,
    /// Internal array variable map.
    ArrayMap = 2,
    /// Internal string variable map.
    StringMap = 3,
    /// Inventory reference map.
    InventoryReferenceMap = 4,
}

/// IDs for NVSE internal functions accessible via `get_func()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DataFunc {
    InventoryReferenceCreate = 1,
    InventoryReferenceGetForRefID = 2,
    InventoryReferenceGetRefBySelf = 3,
    ArrayVarMapDeleteBySelf = 4,
    StringVarMapDeleteBySelf = 5,
    LambdaDeleteAllForScript = 6,
    InventoryReferenceCreateEntry = 7,
    LambdaSaveVariableList = 8,
    LambdaUnsaveVariableList = 9,
    IsScriptLambda = 10,
    HasScriptCommand = 11,
    DecompileScript = 12,
    FormExtraDataGet = 13,
    FormExtraDataGetAll = 14,
    FormExtraDataAdd = 15,
    FormExtraDataRemoveByName = 16,
    FormExtraDataRemoveByPtr = 17,
}

/// IDs for NVSE data values accessible via `get_data()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DataValue {
    /// Number of preloaded mods.
    NumPreloadMods = 1,
}

// -- Error ------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum DataError {
    #[error("NVSEDataInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("GetSingleton function pointer is NULL")]
    GetSingletonIsNull,

    #[error("GetFunc function pointer is NULL")]
    GetFuncIsNull,

    #[error("GetData function pointer is NULL")]
    GetDataIsNull,

    #[error("Requested item returned NULL")]
    ResultIsNull,
}

pub type DataResult<T> = Result<T, DataError>;

// -- Wrapper ----------------------------------------------------------------

/// Safe wrapper around NVSEDataInterface.
///
/// Provides access to NVSE internal singletons, function pointers, and data.
/// Most plugin developers will not need this interface directly.
pub struct Data {
    ptr: NonNull<NVSEDataInterfaceFFI>,
}

impl Data {
    /// Create a Data wrapper from a raw FFI pointer.
    pub fn from_raw(raw: *mut NVSEDataInterfaceFFI) -> DataResult<Self> {
        let ptr = NonNull::new(raw).ok_or(DataError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Get a raw pointer to an internal NVSE singleton.
    ///
    /// The returned pointer must be cast to the appropriate type.
    /// Returns NULL if the singleton ID is invalid.
    pub fn get_singleton(&self, id: DataSingleton) -> DataResult<*mut libc::c_void> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface
            .GetSingleton
            .ok_or(DataError::GetSingletonIsNull)?;

        let ptr = unsafe { get_fn(id as u32) };
        if ptr.is_null() {
            Err(DataError::ResultIsNull)
        } else {
            Ok(ptr)
        }
    }

    /// Get a raw function pointer from NVSE's internal function table.
    ///
    /// The returned pointer must be cast to the appropriate function type.
    /// See `_InventoryReferenceCreate`, `_DecompileScript`, etc. in the
    /// generated bindings for the expected signatures.
    pub fn get_func(&self, id: DataFunc) -> DataResult<*mut libc::c_void> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetFunc.ok_or(DataError::GetFuncIsNull)?;

        let ptr = unsafe { get_fn(id as u32) };
        if ptr.is_null() {
            Err(DataError::ResultIsNull)
        } else {
            Ok(ptr)
        }
    }

    /// Get a raw data value from NVSE.
    pub fn get_data(&self, id: DataValue) -> DataResult<*mut libc::c_void> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetData.ok_or(DataError::GetDataIsNull)?;

        let ptr = unsafe { get_fn(id as u32) };
        if ptr.is_null() {
            Err(DataError::ResultIsNull)
        } else {
            Ok(ptr)
        }
    }

    /// Clear the internal script data cache.
    ///
    /// Called internally by NVSE during certain operations.
    /// Most plugins should not need to call this.
    pub fn clear_script_data_cache(&self) {
        let iface = unsafe { self.ptr.as_ref() };
        if let Some(clear_fn) = iface.ClearScriptDataCache {
            unsafe { clear_fn() };
        }
    }
}

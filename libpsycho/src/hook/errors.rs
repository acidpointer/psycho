#![allow(dead_code)]

use thiserror::Error;

use crate::{common::func::FnPtrError, patch::PatchError, winapi::WindowsError};

#[derive(Debug, Error)]
pub enum HookError {
    #[error("Base module handle is NULL")]
    BaseModuleIsNull,

    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("WinAPI error: {0}")]
    WinError(#[from] WindowsError),

    #[error("FnPtr error: {0}")]
    FnPtrError(#[from] FnPtrError),

    #[error("WinAPI(bindings from Microsoft) error: {0}")]
    WindowsError(#[from] windows::core::Error),

    #[error("Size mismatch: *mut c_void ({0} bytes) vs T ({1} bytes)")]
    TransmuteError(usize, usize),

    #[error("Null pointer encountered: {0}")]
    NullPointerError(String),

    #[error("Index out of bounds: {index} (max: {max})")]
    IndexOutOfBoundsError { index: usize, max: usize },

    #[error("VTable size exceeded safety limit")]
    VTableSizeExceededError,

    #[error("Feature not implemented: {0}")]
    NotImplementedError(String),

    #[error("Memory access error: {0}")]
    MemoryAccessError(String),

    #[error("Invalid argument: {0}")]
    InvalidArgumentError(String),

    #[error("Validation failed: {0}")]
    ValidationError(String),

    #[error("Function signature mismatch")]
    FunctionSignatureMismatchError,

    #[error("Module '{0}' function '{1}' reached invalid scan size")]
    InvalidScanSizeError(String, String),

    #[error("Misaligned base address for module '{0}' function '{1}'")]
    MisalignedBaseAddressError(String, String),

    #[error("Module '{0}' miss function '{1}' in import address table (IAT)")]
    OriginFuncNotFoundInRegionError(String, String),

    #[error("Unknown error(anyhow): {0}")]
    UnknownError(#[from] anyhow::Error),

    #[error("Memory patch error: {0}")]
    MemoryPatchError(#[from] PatchError),

    #[error("Hook already enabled")]
    HookAlreadyEnabledError,

    #[error("Hook not enabled")]
    HookNotEnabledError,
}
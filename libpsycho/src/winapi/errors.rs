//! errors.rs
#![allow(dead_code)]

use std::ffi::NulError;

use windows::core::HRESULT;
use thiserror::Error;

//use crate::{hooking::HookError, types::UniStringError};

/// Custom error type for Windows API operations
#[derive(Error, Debug)]
pub enum WindowsError {
    #[error("Windows API error: {0}")]
    WinAPIError(#[from] windows::core::Error),

    #[error("API call failed with HRESULT: {0:?}")]
    HResultError(HRESULT),
    
    #[error("API call returned false")]
    BooleanError,
    
    #[error("Unexpected null pointer")]
    NullPointerError,

    #[error("Function address not found: {0}")]
    FunctionNotFound(String),

    #[error("PE parser error: {0}")]
    PeParserError(#[from] goblin::error::Error),

    #[error("Utf8 raw string conversion error: {0}")]
    Utf8ConvError(#[from] std::str::Utf8Error),

    #[error("Invalid DOS signature")]
    InvalidPEFormatError,

    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Nul bytes found error: {0}")]
    NulError(#[from] NulError),

    #[error("RVA not found for function name: '{0}' in dll: '{1}'")]
    RvaNotFoundError(String, String),

    #[error("RVA not found for function name: '{0}' in dll: '{1}'")]
    ProcAddressError(String, String),

    #[error("Function not found or GetProcAddress returned NULLPTR")]
    ProcAddressNullError,

    #[error("Failed to get module HANDLE for: {0}")]
    HandleError(String),

    #[error("Cant get current HANDLE")]
    CurrentHandleError,

    #[error("Process HANDLE is NULL")]
    ProcessHandleNullError,

    #[error("Module HANDLE is NULL")]
    ModuleHandleNullError,

    #[error("Failed to load dll: {0} error: {1}")]
    DllLoadError(String, String),

    #[error("NULLPTR on loading dll: {0}")]
    DllLoadNullError(String),

    #[error("Untyped windows error: {0}")]
    UnknownError(String),

    #[error("Size mismatch: *mut c_void ({0} bytes) vs T ({1} bytes)")]
    TransmuteError(usize, usize),

    #[error("T must be a function pointer type (size mismatch)")]
    PointerSizeError,

    #[error("Memory query failed with error {0}")]
    MemoryQueryFailed(u32),

    #[error("Invalid size parameter")]
    InvalidSize,

    #[error("Memory not committed at address 0x{0:X}")]
    MemoryNotCommitted(usize),

    #[error("Invalid memory range: base=0x{0:X}, size={1}")]
    InvalidMemoryRange(usize, usize),

    #[error("Unaligned memory access: address 0x{0:X} not aligned to {1}-byte boundary")]
    UnalignedMemoryAccess(usize, usize),
}

#[derive(Error, Debug)]
pub enum D3DError {
    #[error("Windows API error: {0}")]
    WindowsError(#[from] windows::core::Error),

    #[error("API call failed with HRESULT: {0:?}")]
    HResultError(HRESULT),
    
    #[error("DirectX function not found: {0}")]
    FunctionNotFound(String),
    
    #[error("Failed to hook DirectX function: {0}")]
    HookError(String),
    
    #[error("VTable access error: {0}")]
    VTableError(String),
}

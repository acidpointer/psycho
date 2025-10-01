use thiserror::Error;

use crate::{ffi::fnptr::FnPtrError, os::windows::{memory::MemoryError, winapi::WinapiError}};

#[derive(Debug, Error)]
pub enum VmtHookError {
    #[error("WinAPI error: {0}")]
    Winapi(#[from] WinapiError),

    #[error("FnPtr error: {0}")]
    FnPtr(#[from] FnPtrError),

    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),

    #[error("Invalid or NULL pointer")]
    InvalidPointer,

    #[error("VMT hook already enabled")]
    AlreadyEnabled,

    #[error("VMT hook not enabled")]
    NotEnabled,
}

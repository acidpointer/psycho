use thiserror::Error;

use crate::{
    ffi::fnptr::FnPtrError,
    os::windows::{pe::PeError, winapi::WinapiError},
};

#[derive(Debug, Error)]
pub enum IatHookError {
    #[error("FnPtr error: {0}")]
    FnPtrError(#[from] FnPtrError),

    #[error("PE parser error: {0}")]
    PeError(#[from] PeError),

    #[error("WinAPI error: {0}")]
    Winapi(#[from] WinapiError),

    #[error("IAT Hook already enabled")]
    AlreadyEnabled,

    #[error("IAT entry is NULL")]
    IatEntryNull,

    #[error("Hook is not enabled")]
    NotEnabled,
}

use libc::c_void;
use thiserror::Error;
use windows::Win32::System::ProcessStatus::MODULEINFO;

use crate::os::windows::winapi::{HModule, ModuleInfo};

use super::winapi::{WinapiError, get_current_process};

#[derive(Debug, Error)]
pub enum WinProcessError {

    #[error("Winapi error: {0}")]
    WinapiError(#[from] WinapiError)
}

pub type WinProcessResult<T> = std::result::Result<T, WinProcessError>;

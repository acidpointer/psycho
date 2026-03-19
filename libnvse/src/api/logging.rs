//! Safe wrapper for the NVSE logging interface.
//!
//! Provides the path where plugin log files should be written.
//! Default path: `Data/NVSE/Plugins/Logs/` (configurable in nvse_config.ini).
//!
//! # Usage
//!
//! ```no_run
//! let log_path = logging.plugin_log_path()?;
//! println!("Logs go to: {}", log_path);
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use thiserror::Error;

use crate::NVSELoggingInterface as NVSELoggingInterfaceFFI;

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("NVSELoggingInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("GetPluginLogPath function pointer is NULL")]
    GetPluginLogPathIsNull,

    #[error("GetPluginLogPath returned a NULL string")]
    PathIsNull,

    #[error("Log path contains invalid UTF-8")]
    InvalidUtf8,
}

pub type LoggingResult<T> = Result<T, LoggingError>;

/// Safe wrapper around NVSELoggingInterface.
///
/// Provides access to the configured plugin log directory path.
pub struct Logging {
    ptr: NonNull<NVSELoggingInterfaceFFI>,
}

impl Logging {
    /// Create a Logging wrapper from a raw FFI pointer.
    pub fn from_raw(raw: *mut NVSELoggingInterfaceFFI) -> LoggingResult<Self> {
        let ptr = NonNull::new(raw).ok_or(LoggingError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Get the configured plugin log directory path.
    ///
    /// Returns the path with a trailing slash (e.g. "Data/NVSE/Plugins/Logs/").
    /// This path is configurable via nvse_config.ini under [Logging] sPluginLogPath.
    pub fn plugin_log_path(&self) -> LoggingResult<&str> {
        let iface = unsafe { self.ptr.as_ref() };

        let get_path = iface
            .GetPluginLogPath
            .ok_or(LoggingError::GetPluginLogPathIsNull)?;

        let path_ptr = unsafe { get_path() };

        if path_ptr.is_null() {
            return Err(LoggingError::PathIsNull);
        }

        let cstr = unsafe { CStr::from_ptr(path_ptr) };
        cstr.to_str().map_err(|_| LoggingError::InvalidUtf8)
    }
}

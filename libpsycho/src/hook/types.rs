use std::ffi::c_void;

pub type Result<T> = std::result::Result<T, super::errors::HookError>;

/// Type which represent IAT entry pointer
pub type IatEntryPtr = *mut *mut c_void;
pub type VtablePtr = *mut *mut c_void;
pub type ObjectPtr = *mut *mut *mut c_void;
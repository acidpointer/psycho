use crate::os::windows::hook::vmt::errors::VmtHookError;

pub mod errors;
pub mod vmthook;

pub type VmtHookResult<T> = std::result::Result<T, VmtHookError>;

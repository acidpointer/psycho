use crate::os::windows::hook::vmt::errors::VmtHookError;

pub mod vmthook;
pub mod errors;
pub mod utils;

pub type VmtHookResult<T> = std::result::Result<T, VmtHookError>;

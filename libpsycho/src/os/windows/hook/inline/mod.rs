pub mod inlinehook;
pub mod utils;
pub mod errors;
pub mod trampoline;

pub type InlineHookResult<T> = std::result::Result<T, errors::InlineHookError>;



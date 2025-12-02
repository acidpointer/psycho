pub mod inlinehook;
pub mod errors;
pub mod trampoline;

mod disasm;

pub type InlineHookResult<T> = std::result::Result<T, errors::InlineHookError>;



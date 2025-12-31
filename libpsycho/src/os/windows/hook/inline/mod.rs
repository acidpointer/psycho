pub mod inlinehook;
pub mod errors;
pub mod trampoline;

mod disasm;
mod thunk;

pub type InlineHookResult<T> = std::result::Result<T, errors::InlineHookError>;



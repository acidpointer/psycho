pub mod errors;
pub mod inlinehook;
pub mod trampoline;

pub(crate) mod disasm;
mod thunk;

pub(crate) use disasm::{create_jump_bytes, verify_jump_bytes};
pub type InlineHookResult<T> = std::result::Result<T, errors::InlineHookError>;

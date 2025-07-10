mod memory;
mod errors;
mod helpers;

pub use errors::*;
pub use memory::*;
pub use helpers::*;


pub type Result<T> = core::result::Result<T, errors::PatchError>;
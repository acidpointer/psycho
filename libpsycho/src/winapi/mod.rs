mod win;
mod helpers;
mod errors;
mod types;
mod constants;

pub use win::*;
pub use helpers::*;
pub use errors::*;
pub use types::*;
pub use constants::*;

type Result<T> = core::result::Result<T, WindowsError>;

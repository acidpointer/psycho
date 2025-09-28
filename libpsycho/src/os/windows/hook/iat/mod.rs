pub mod iathook;
pub mod errors;
pub mod utils;

pub type IatHookResult<T> = std::result::Result<T, errors::IatHookError>;

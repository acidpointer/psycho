pub mod errors;
pub mod iathook;

pub type IatHookResult<T> = std::result::Result<T, errors::IatHookError>;

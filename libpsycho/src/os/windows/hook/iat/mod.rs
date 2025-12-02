pub mod iathook;
pub mod errors;

pub type IatHookResult<T> = std::result::Result<T, errors::IatHookError>;

use thiserror::Error;

use crate::os::windows::winapi::WinapiError;

/// Error types for memory patching operations
#[derive(Error, Debug)]
pub enum PatchError {
    #[error("Invalid size parameter")]
    InvalidSize,

    #[error("Memory not committed at address 0x{0:X}")]
    MemoryNotCommitted(usize),

    #[error("Invalid memory range: base=0x{0:X}, size={1}")]
    InvalidMemoryRange(usize, usize),

    #[error("Unaligned memory access: address 0x{0:X} not aligned to {1}-byte boundary")]
    UnalignedMemoryAccess(usize, usize),

    #[error("Jump/call exceeds 2GB range limit")]
    JumpRangeTooLarge,

    #[error("Memory query failed with error {0}")]
    MemoryQueryFailed(u32),

    #[error("Memory protection change failed")]
    ProtectionChangeFailed,

    #[error("Patch already applied")]
    AlreadyApplied,

    #[error("Patch not applied")]
    NotApplied,

    #[error("MemoryPatch already disabled")]
    PatchAlreadyDisabled,

    #[error("Memory access violation")]
    AccessViolation,

    #[error("Memory patch verification failed")]
    PatchVerificationFailed,

    #[error("Memory range exceeds 2GB limit")]
    RangeTooLarge,
    
    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError)
}

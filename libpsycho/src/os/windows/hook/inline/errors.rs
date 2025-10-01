use libc::c_void;
use iced_x86::{IcedError, Mnemonic};
use thiserror::Error;

use crate::ffi::fnptr::FnPtrError;
use crate::os::windows::winapi::WinapiError;

#[derive(Debug, Error)]
pub enum InlineHookError {
    #[error("WinAPI error: {0}")]
    Winapi(#[from] WinapiError),
    
    #[error("FnPtr error: {0}")]
    FnPtr(#[from] FnPtrError),

    #[error("Iced error: {0}")]
    IcedError(#[from] IcedError),
    
    #[error("Target function is too small for hook (need {needed} bytes, got {available})")]
    InsufficientSpace { needed: usize, available: usize },
    
    #[error("Failed to disassemble instructions at target")]
    DisassemblyFailed,
    
    #[error("Failed to allocate trampoline memory")]
    TrampolineAllocationFailed,
    
    #[error("Failed to encode jump instruction")]
    JumpEncodingFailed,
    
    #[error("Memory range too far for relative jump")]
    MemoryRangeTooFar,
    
    #[error("Hook is already enabled")]
    AlreadyEnabled,
    
    #[error("Hook is not enabled")]
    NotEnabled,
    
    #[error("Cannot relocate instruction: {0:?}")]
    NonRelocatableInstruction(Mnemonic),
    
    #[error("Encoding error: {0}")]
    EncodingError(String),
    
    #[error("Target memory is not executable")]
    NonExecutableMemory,
    
    #[error("Target memory is not accessible")]
    InaccessibleMemory,
    
    #[error("Hook is in failed state and cannot be used")]
    HookFailed,
    
    #[error("Architecture mismatch: expected {expected}, got {detected}")]
    ArchitectureMismatch { expected: u32, detected: u32 },
    
    #[error("Jump verification failed: expected target {expected:x}, got {actual:x}")]
    JumpVerificationFailed { expected: usize, actual: usize },
    
    #[error("Unsafe memory region: can only read {safe} bytes, need {requested}")]
    UnsafeMemoryRegion { safe: usize, requested: usize },
    
    #[error("Detected recursive hook call")]
    RecursiveHook,
    
    #[error("RIP-relative instruction cannot be relocated: {0:?}")]
    RipRelativeInstruction(Mnemonic),
    
    #[error("Target function too small: {size} bytes")]
    FunctionTooSmall { size: usize },
}

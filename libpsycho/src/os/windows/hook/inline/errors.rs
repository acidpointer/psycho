use iced_x86::{IcedError, Mnemonic};
use thiserror::Error;

use crate::ffi::fnptr::FnPtrError;
use crate::os::windows::memory::MemoryError;
use crate::os::windows::winapi::WinapiError;

#[derive(Debug, Error)]
pub enum InlineHookError {
    #[error("Target pointer is NULL")]
    TargetIsNull,

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
    
    #[error("Hook is already enabled")]
    AlreadyEnabled,
    
    #[error("Hook is not enabled")]
    NotEnabled,
    
    #[error("Cannot relocate instruction: {0:?}")]
    NonRelocatableInstruction(Mnemonic),
    
    #[error("Encoding error: {0}")]
    EncodingError(String),
    
    #[error("Hook is in failed state and cannot be used")]
    HookFailed,
    
    #[error("Unsafe memory region: can only read {safe} bytes, need {requested}")]
    UnsafeMemoryRegion { safe: usize, requested: usize },
    
    #[error("RIP-relative instruction cannot be relocated: {0:?}")]
    RipRelativeInstruction(Mnemonic),
    
    #[error("Target function too small: {size} bytes")]
    FunctionTooSmall { size: usize },

    #[error("Memory error: {0}")]
    MemoryError(#[from] MemoryError),

    #[error("Disassembler error: {0}")]
    DisasmError(#[from] DisasmError),

    #[error("Inline hook container already initialized")]
    HookContainerInitialized,

    #[error("Inline hook cotainer not initialized")]
    HookContainerNotInitialized,
}

#[derive(Debug, Error)]
pub enum DisasmError {
    #[error("Source pointer is NULL")]
    SrcNullPtr,

    #[error("Function pointer container error: {0}")]
    FnPtrError(#[from] FnPtrError),

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),

    #[error("Iced_x86 error: {0}")]
    IcedError(#[from] IcedError),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Target function is too short to hook it")]
    ShortTarget,

    #[error("Invalid instruction found during disassembly")]
    InvalidInstruction,

    #[error("Trampoline pointer is NULL")]
    TrampolineIsNull,

    #[error("Absolute jump supported only on x86_64 architecture")]
    AbsJumpNotSupportedOnArch,

    #[error("Incorrect minimum bytes value for jump instruction")]
    WrongMinJumpSize,

    #[error("Jump verification failed! Expected target: {0:X}, actual: {1:X}")]
    JumpVerificationFailed(usize, usize),
}

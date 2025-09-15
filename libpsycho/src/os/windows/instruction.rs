//! Instruction analysis and code generation for Windows hooking
//!
//! This module provides safe instruction analysis using iced-x86 disassembler
//! for creating trampolines and analyzing function prologs for safe hooking.

use std::ffi::c_void;
use thiserror::Error;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic,
    code_asm::{CodeAssembler, CodeAssemblerResult},
    IcedError,
};

use super::memory::read_bytes;

#[derive(Debug, Error)]
pub enum InstructionError {
    #[error("Invalid instruction at address 0x{0:X}")]
    InvalidInstruction(usize),

    #[error("Insufficient bytes to analyze (need at least {0} bytes)")]
    InsufficientBytes(usize),

    #[error("Cannot safely hook at this location: {0}")]
    UnsafeHookLocation(String),

    #[error("Assembly error: {0}")]
    AssemblyError(String),

    #[error("Memory error: {0}")]
    MemoryError(#[from] super::memory::MemoryError),

    #[error("Iced assembler error: {0}")]
    IcedError(#[from] IcedError),
}

pub type InstructionResult<T> = Result<T, InstructionError>;

/// Information about analyzed instructions
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    pub instruction: Instruction,
    pub address: u64,
    pub bytes: Vec<u8>,
}

/// Analysis result for a function prolog
#[derive(Debug)]
pub struct PrologAnalysis {
    pub instructions: Vec<InstructionInfo>,
    pub total_length: usize,
    pub safe_patch_size: usize,
    pub has_relocations: bool,
}

/// Architecture-specific constants
pub struct ArchConstants {
    pub pointer_size: usize,
    pub jump_instruction_size: usize,
    pub min_hook_size: usize,
}

impl ArchConstants {
    /// Get constants for current architecture
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                pointer_size: 8,
                jump_instruction_size: 5, // JMP rel32
                min_hook_size: 5,
            }
        }
        #[cfg(target_arch = "x86")]
        {
            Self {
                pointer_size: 4,
                jump_instruction_size: 5, // JMP rel32
                min_hook_size: 5,
            }
        }
    }
}

/// Analyze function prolog for safe hooking
pub fn analyze_function_prolog(
    function_address: *const c_void,
    min_bytes: usize,
) -> InstructionResult<PrologAnalysis> {
    let arch = ArchConstants::current();
    let required_bytes = min_bytes.max(arch.min_hook_size);

    // Read enough bytes for analysis (typically 32-64 bytes should be sufficient)
    let analysis_size = required_bytes.max(64);
    let bytes = read_bytes(function_address, analysis_size)?;

    // Determine architecture for decoder
    #[cfg(target_arch = "x86_64")]
    let bitness = 64;
    #[cfg(target_arch = "x86")]
    let bitness = 32;

    let mut decoder = Decoder::with_ip(
        bitness,
        &bytes,
        function_address as u64,
        DecoderOptions::NONE,
    );

    let mut instructions = Vec::new();
    let mut total_length = 0usize;
    let mut has_relocations = false;

    // Analyze instructions until we have enough bytes for hooking
    while total_length < required_bytes {
        let instruction = decoder.decode();

        if instruction.is_invalid() {
            return Err(InstructionError::InvalidInstruction(
                (function_address as usize) + total_length
            ));
        }

        // Check for problematic instructions that make hooking unsafe
        if is_problematic_instruction(&instruction) {
            return Err(InstructionError::UnsafeHookLocation(
                format!("Problematic instruction: {:?}", instruction.mnemonic())
            ));
        }

        // Check for instructions that need relocation
        if needs_relocation(&instruction) {
            has_relocations = true;
        }

        let inst_bytes = bytes[total_length..total_length + instruction.len()].to_vec();

        instructions.push(InstructionInfo {
            instruction,
            address: function_address as u64 + total_length as u64,
            bytes: inst_bytes,
        });

        total_length += instruction.len();

        // Safety check: don't analyze too many instructions
        if instructions.len() > 20 {
            break;
        }
    }

    if total_length < required_bytes {
        return Err(InstructionError::InsufficientBytes(required_bytes));
    }

    Ok(PrologAnalysis {
        instructions,
        total_length,
        safe_patch_size: total_length,
        has_relocations,
    })
}

/// Generate a trampoline that executes original instructions and jumps back
pub fn generate_trampoline(
    analysis: &PrologAnalysis,
    original_function: *const c_void,
    return_address: *const c_void,
) -> InstructionResult<Vec<u8>> {
    #[cfg(target_arch = "x86_64")]
    let mut assembler = CodeAssembler::new(64)?;
    #[cfg(target_arch = "x86")]
    let mut assembler = CodeAssembler::new(32)?;

    // Copy original instructions, relocating as needed
    for inst_info in &analysis.instructions {
        if needs_relocation(&inst_info.instruction) {
            // Generate relocated instruction
            generate_relocated_instruction(&mut assembler, &inst_info.instruction, inst_info.address)?;
        } else {
            // Copy instruction bytes directly
            assembler.db(&inst_info.bytes)?;
        }
    }

    // Generate jump back to original function + patch size
    let jump_target = original_function as u64 + analysis.safe_patch_size as u64;

    #[cfg(target_arch = "x86_64")]
    {
        // For x64, we might need absolute jump if distance > 2GB
        let current_addr = return_address as u64;

        // TODO: Clarify logic
        let distance = jump_target.wrapping_sub(current_addr + 5);

        if distance > 0x7FFF_FFFF && distance < 0xFFFF_FFFF_8000_0000 {
            // Use absolute jump
            assembler.mov(iced_x86::code_asm::rax, jump_target)?;
            assembler.jmp(iced_x86::code_asm::rax)?;
        } else {
            // Use relative jump
            assembler.jmp(jump_target)?;
        }
    }

    #[cfg(target_arch = "x86")]
    {
        // x86 can always use relative jump
        assembler.jmp(jump_target)?;
    }

    let result = assembler.assemble(return_address as u64)
        .map_err(|e| InstructionError::AssemblyError(format!("{:?}", e)))?;

    Ok(result.into_iter().collect())
}

/// Generate a jump instruction to the detour function
pub fn generate_jump_to_detour(
    detour_address: *const c_void,
    patch_size: usize,
) -> InstructionResult<Vec<u8>> {
    let arch = ArchConstants::current();

    if patch_size < arch.jump_instruction_size {
        return Err(InstructionError::InsufficientBytes(arch.jump_instruction_size));
    }

    #[cfg(target_arch = "x86_64")]
    let mut assembler = CodeAssembler::new(64)?;
    #[cfg(target_arch = "x86")]
    let mut assembler = CodeAssembler::new(32)?;

    // Generate jump to detour
    assembler.jmp(detour_address as u64)?;

    // Pad with NOPs if needed
    let nop_count = patch_size - arch.jump_instruction_size;
    for _ in 0..nop_count {
        assembler.nop()?;
    }

    let result = assembler.assemble(0)
        .map_err(|e| InstructionError::AssemblyError(format!("{:?}", e)))?;

    Ok(result.into_iter().collect())
}

/// Check if an instruction is problematic for hooking
fn is_problematic_instruction(instruction: &Instruction) -> bool {
    match instruction.mnemonic() {
        // Jump/call instructions in the middle of our patch area are problematic
        Mnemonic::Jmp | Mnemonic::Call if instruction.len() < 5 => true,

        // Conditional jumps that might be partially overwritten
        Mnemonic::Jo | Mnemonic::Jno | Mnemonic::Jb | Mnemonic::Jae |
        Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jbe | Mnemonic::Ja |
        Mnemonic::Js | Mnemonic::Jns | Mnemonic::Jp | Mnemonic::Jnp |
        Mnemonic::Jl | Mnemonic::Jge | Mnemonic::Jle | Mnemonic::Jg => true,

        // Loop instructions
        Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne => true,

        // Return instructions
        Mnemonic::Ret | Mnemonic::Retf => true,

        // Interrupt/system instructions
        Mnemonic::Int | Mnemonic::Into | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => true,

        _ => false,
    }
}

/// Check if an instruction needs relocation when moved
fn needs_relocation(instruction: &Instruction) -> bool {
    // Instructions with IP-relative addressing need relocation
    instruction.is_ip_rel_memory_operand() ||
    // RIP-relative instructions
    (instruction.memory_base() == iced_x86::Register::RIP) ||
    // Relative jumps/calls
    (matches!(instruction.flow_control(),
        FlowControl::ConditionalBranch |
        FlowControl::UnconditionalBranch |
        FlowControl::Call))
}

/// Generate a relocated version of an instruction
fn generate_relocated_instruction(
    assembler: &mut CodeAssembler,
    instruction: &Instruction,
    _original_address: u64,
) -> InstructionResult<()> {
    // This is a complex operation that depends on the specific instruction
    // For now, we'll handle the most common cases

    match instruction.mnemonic() {
        Mnemonic::Call => {
            // Convert relative call to absolute
            let target = instruction.near_branch_target();
            assembler.call(target)
                .map_err(|e| InstructionError::AssemblyError(format!("{:?}", e)))?;
        }

        Mnemonic::Jmp => {
            // Convert relative jump to absolute
            let target = instruction.near_branch_target();
            assembler.jmp(target)
                .map_err(|e| InstructionError::AssemblyError(format!("{:?}", e)))?;
        }

        _ => {
            // For other instructions, we need more complex relocation logic
            // This would require analyzing operands and generating equivalent code
            return Err(InstructionError::UnsafeHookLocation(
                format!("Cannot relocate instruction: {:?}", instruction.mnemonic())
            ));
        }
    }

    Ok(())
}

impl From<CodeAssemblerResult> for InstructionError {
    fn from(err: CodeAssemblerResult) -> Self {
        InstructionError::AssemblyError(format!("{:?}", err))
    }
}